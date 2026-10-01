use std::io::{self, Read, Write};
use std::path::PathBuf;

pub fn encrypt_stream_age_recipients<'b, R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    recipients: impl Iterator<Item = &'b (dyn age::Recipient + 'b)>,
    original_name: &str,
) -> io::Result<()> {
    let encryptor = age::Encryptor::with_recipients(recipients)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
    let mut age_writer = encryptor.wrap_output(writer)?;
    super::types::write_metadata_prefix(&mut age_writer, original_name)?;
    io::copy(reader, &mut age_writer)?;
    age_writer.finish()?;
    Ok(())
}

pub struct AgeStreamReader<R> {
    reader: R,
    finished: bool,
}

impl<R: Read> AgeStreamReader<R> {
    pub fn new(reader: R) -> Self {
        Self {
            reader,
            finished: false,
        }
    }
}

impl<R: Read> Read for AgeStreamReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.finished {
            return Ok(0);
        }
        match self.reader.read(buf) {
            Ok(0) => {
                self.finished = true;
                Ok(0)
            }
            Ok(n) => Ok(n),
            Err(e) => {
                if e.to_string().contains("last chunk has been processed") {
                    self.finished = true;
                    Ok(0)
                } else {
                    Err(e)
                }
            }
        }
    }
}

pub fn encrypt_stream_age_passphrase<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    passphrase: &str,
    original_name: &str,
) -> io::Result<()> {
    let secret = age::secrecy::SecretString::from(passphrase.to_string());
    let encryptor = age::Encryptor::with_user_passphrase(secret);
    let mut age_writer = encryptor.wrap_output(writer)?;
    super::types::write_metadata_prefix(&mut age_writer, original_name)?;
    io::copy(reader, &mut age_writer)?;
    age_writer.finish()?;
    Ok(())
}

pub fn load_identities(paths: &[PathBuf]) -> io::Result<Vec<Box<dyn age::Identity>>> {
    if paths.is_empty() {
        return Ok(Vec::new());
    }
    let filenames: Vec<String> = paths
        .iter()
        .map(|p| p.to_string_lossy().into_owned())
        .collect();
    let mut stdin_guard = age::cli_common::StdinGuard::new(false);
    age::cli_common::read_identities(filenames, None, &mut stdin_guard).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Failed reading identities: {}", e),
        )
    })
}

pub fn load_recipients(
    recipients: &[String],
    files: &[PathBuf],
) -> io::Result<Vec<Box<dyn age::Recipient + Send>>> {
    let recipient_files: Vec<String> =
        files.iter().map(|p| p.to_string_lossy().into_owned()).collect();
    let mut stdin_guard = age::cli_common::StdinGuard::new(false);
    age::cli_common::read_recipients(
        recipients.to_vec(),
        recipient_files,
        vec![],
        None,
        &mut stdin_guard,
    )
    .map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Failed reading recipients: {}", e),
        )
    })
}

pub fn extract_recipients_from_identity_file(path: &std::path::Path) -> Vec<String> {
    use std::str::FromStr;
    let mut recipients = Vec::new();

    let expanded_path = crate::config::expand_tilde(path);
    let mut files_to_check = vec![expanded_path.clone()];
    let file_name = expanded_path.file_name().unwrap_or_default().to_string_lossy();
    if !file_name.ends_with(".pub") {
        let mut pub_file = expanded_path.clone();
        pub_file.set_file_name(format!("{}.pub", file_name));
        if pub_file.is_file() {
            files_to_check.push(pub_file);
        }
    }

    for file_path in files_to_check {
        if let Ok(content) = std::fs::read_to_string(&file_path) {
            for line in content.lines() {
                let trimmed = line.trim();
                let lower = trimmed.to_ascii_lowercase();

                let prefix_match = [
                    "# public key:",
                    "# public-key:",
                    "# public_key:",
                    "# recipient:",
                    "# recipient key:",
                    "# recipient-key:",
                ];

                let mut matched = false;
                for prefix in prefix_match {
                    if lower.starts_with(prefix) {
                        let pk = trimmed[prefix.len()..].trim().to_string();
                        if !pk.is_empty() && !recipients.contains(&pk) {
                            recipients.push(pk);
                        }
                        matched = true;
                        break;
                    }
                }
                if matched {
                    continue;
                }

                if trimmed.starts_with("AGE-SECRET-KEY-1")
                    && let Ok(identity) = age::x25519::Identity::from_str(trimmed)
                {
                    let pk = identity.to_public().to_string();
                    if !recipients.contains(&pk) {
                        recipients.push(pk);
                    }
                    continue;
                }

                if trimmed.starts_with("age1")
                    || trimmed.starts_with("ssh-ed25519 ")
                    || trimmed.starts_with("ssh-rsa ")
                    || trimmed.starts_with("ecdsa-sha2-")
                {
                    let pk = trimmed.to_string();
                    if !recipients.contains(&pk) {
                        recipients.push(pk);
                    }
                }
            }
        }
    }

    recipients
}
