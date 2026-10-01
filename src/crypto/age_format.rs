use std::io::{self, Read, Write};
use std::path::PathBuf;

use super::types::ValvMetadata;

pub fn encrypt_stream_age_recipients<'b, R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    recipients: impl Iterator<Item = &'b (dyn age::Recipient + 'b)>,
    original_name: &str,
) -> io::Result<()> {
    let encryptor = age::Encryptor::with_recipients(recipients)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
    let mut age_writer = encryptor.wrap_output(writer)?;

    let meta = serde_json::to_string(&ValvMetadata {
        original_name: original_name.to_string(),
    })
    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    let mut prefix_bytes = Vec::with_capacity(meta.len() + 2);
    prefix_bytes.push(b'\n');
    prefix_bytes.extend_from_slice(meta.as_bytes());
    prefix_bytes.push(b'\n');

    age_writer.write_all(&prefix_bytes)?;
    io::copy(reader, &mut age_writer)?;
    age_writer.finish()?;
    Ok(())
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

    let meta = serde_json::to_string(&ValvMetadata {
        original_name: original_name.to_string(),
    })
    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    let mut prefix_bytes = Vec::with_capacity(meta.len() + 2);
    prefix_bytes.push(b'\n');
    prefix_bytes.extend_from_slice(meta.as_bytes());
    prefix_bytes.push(b'\n');

    age_writer.write_all(&prefix_bytes)?;
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
