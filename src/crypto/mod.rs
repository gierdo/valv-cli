pub mod age_format;
pub mod types;
pub mod valv_format;

use std::fs::File;
use std::io::{self, BufReader, Cursor, Read, Write};
use std::path::Path;

pub use age_format::{
    encrypt_stream_age_passphrase, encrypt_stream_age_recipients,
    extract_recipients_from_identity_file, load_identities, load_recipients,
};
pub use types::{
    zeroize, Credentials, DecryptError, DecryptedHeader, DecryptedPayload, EncryptionMethod,
    VaultFormat, BUFFER_SIZE, DEFAULT_ITERATIONS, MAX_ITERATIONS, MIN_ITERATIONS, VALV_V2,
};
pub use valv_format::{derive_key, encrypt_file, encrypt_stream, transform_stream};

pub fn encrypt_stream_unified<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    original_name: &str,
    method: &EncryptionMethod,
) -> io::Result<()> {
    match method {
        EncryptionMethod::ValvPassphrase {
            password,
            iterations,
        } => encrypt_stream(reader, writer, password, original_name, *iterations),
        EncryptionMethod::AgePassphrase(passphrase) => {
            encrypt_stream_age_passphrase(reader, writer, passphrase, original_name)
        }
        EncryptionMethod::AgeRecipients(recipients) => {
            let iter = recipients.iter().map(|r| &**r as &dyn age::Recipient);
            encrypt_stream_age_recipients(reader, writer, iter, original_name)
        }
    }
}

pub fn decrypt_header_with_credentials<'a, R: Read + Send + 'a>(
    mut reader: R,
    credentials: &Credentials,
) -> Result<DecryptedHeader<'a>, DecryptError> {
    let mut first4 = [0u8; 4];
    let n = match reader.read(&mut first4) {
        Ok(n) => n,
        Err(e) => return Err(DecryptError::Io(e)),
    };

    if n == 4 && first4 == VALV_V2.to_be_bytes() {
        let password = credentials
            .password
            .as_deref()
            .ok_or(DecryptError::InvalidPassword)?;

        let chained = Cursor::new(first4).chain(reader);
        return valv_format::decrypt_valv_v2_header(chained, password);
    }

    let chained = Cursor::new(first4[..n].to_vec()).chain(reader);
    let decryptor = match age::Decryptor::new(chained) {
        Ok(d) => d,
        Err(_) => return Err(DecryptError::CorruptHeader("Unsupported file version")),
    };

    let mut scrypt_id = None;
    if let Some(ref pwd) = credentials.password
        && !pwd.is_empty()
        && let Ok(pwd_str) = std::str::from_utf8(pwd)
    {
        scrypt_id = Some(age::scrypt::Identity::new(age::secrecy::SecretString::from(
            pwd_str.to_string(),
        )));
    }

    let mut id_refs: Vec<&dyn age::Identity> = credentials
        .identities
        .iter()
        .map(|i| &**i as &dyn age::Identity)
        .collect();
    if let Some(ref sid) = scrypt_id {
        id_refs.push(sid as &dyn age::Identity);
    }

    if id_refs.is_empty() {
        return Err(DecryptError::InvalidPassword);
    }

    let mut stream_reader = match decryptor.decrypt(id_refs.into_iter()) {
        Ok(r) => r,
        Err(_) => return Err(DecryptError::InvalidPassword),
    };

    let mut first_byte = [0u8; 1];
    let read_res = stream_reader.read(&mut first_byte);
    if let Ok(1) = read_res {
        if first_byte[0] == b'\n' {
            let mut buf = Vec::new();
            let mut byte = [0u8; 1];
            let mut found_newline = false;
            while buf.len() < 4096 {
                match stream_reader.read(&mut byte) {
                    Ok(1) => {
                        if byte[0] == b'\n' {
                            found_newline = true;
                            break;
                        }
                        buf.push(byte[0]);
                    }
                    _ => break,
                }
            }

            if found_newline
                && let Ok(meta_str) = std::str::from_utf8(&buf)
                && let Ok(meta) = serde_json::from_str::<types::ValvMetadata>(meta_str)
            {
                return Ok(DecryptedHeader {
                    original_name: meta.original_name,
                    payload: DecryptedPayload::Age(Box::new(stream_reader)),
                });
            } else {
                let mut full_buf = Vec::with_capacity(1 + buf.len() + 1);
                full_buf.push(b'\n');
                full_buf.extend_from_slice(&buf);
                if found_newline {
                    full_buf.push(b'\n');
                }
                let chained = Cursor::new(full_buf).chain(stream_reader);
                return Ok(DecryptedHeader {
                    original_name: "decrypted_file".to_string(),
                    payload: DecryptedPayload::Age(Box::new(chained)),
                });
            }
        } else {
            let chained = Cursor::new(vec![first_byte[0]]).chain(stream_reader);
            return Ok(DecryptedHeader {
                original_name: "decrypted_file".to_string(),
                payload: DecryptedPayload::Age(Box::new(chained)),
            });
        }
    }

    Ok(DecryptedHeader {
        original_name: "decrypted_file".to_string(),
        payload: DecryptedPayload::Age(Box::new(stream_reader)),
    })
}

pub fn decrypt_header<'a, R: Read + Send + 'a>(
    reader: R,
    password: &[u8],
) -> Result<DecryptedHeader<'a>, DecryptError> {
    let creds = Credentials::new().with_password(password.to_vec());
    decrypt_header_with_credentials(reader, &creds)
}

pub fn decrypt_file_with_credentials_to<W: Write>(
    file_path: &Path,
    credentials: &Credentials,
    writer: &mut W,
) -> Result<String, DecryptError> {
    let file = File::open(file_path)?;
    let reader = BufReader::with_capacity(BUFFER_SIZE, file);
    let mut header = decrypt_header_with_credentials(reader, credentials)?;
    header.decrypt_payload(writer)?;
    Ok(header.original_name)
}

pub fn decrypt_file_to<W: Write>(
    file_path: &Path,
    password: &[u8],
    writer: &mut W,
) -> Result<String, DecryptError> {
    let creds = Credentials::new().with_password(password.to_vec());
    decrypt_file_with_credentials_to(file_path, &creds, writer)
}

pub fn decrypt_file(source: &Path, dest: &Path, password: &[u8]) -> Result<String, DecryptError> {
    #[cfg(unix)]
    let out_file = {
        use std::os::unix::fs::OpenOptionsExt;
        File::options()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(dest)?
    };
    #[cfg(not(unix))]
    let out_file = File::create(dest)?;

    let mut out_writer = io::BufWriter::with_capacity(BUFFER_SIZE, out_file);
    decrypt_file_to(source, password, &mut out_writer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_v2_encrypt_decrypt_roundtrip() {
        let password = b"TestPassphrase123!";
        let original_name = "vacation_photo.jpg";
        let payload = b"Simulated JPEG raw image content binary data \x00\xff\xfe\x01\x02";

        let mut input = Cursor::new(payload);
        let mut encrypted = Vec::new();

        encrypt_stream(&mut input, &mut encrypted, password, original_name, 1000)
            .expect("Encryption failed");

        assert!(encrypted.len() > payload.len());
        assert_eq!(&encrypted[..4], &VALV_V2.to_be_bytes());

        let enc_cursor = Cursor::new(&encrypted);
        let mut header =
            decrypt_header(enc_cursor, password).expect("Decryption header failed");
        assert_eq!(header.original_name, original_name);

        let mut decrypted_payload = Vec::new();
        header
            .decrypt_payload(&mut decrypted_payload)
            .expect("Payload decryption failed");

        assert_eq!(decrypted_payload, payload);
    }

    #[test]
    fn test_v2_wrong_password() {
        let password = b"CorrectPassword";
        let wrong_password = b"WrongPassword";
        let original_name = "secret.txt";
        let payload = b"Top secret contents";

        let mut input = Cursor::new(payload);
        let mut encrypted = Vec::new();

        encrypt_stream(&mut input, &mut encrypted, password, original_name, 1000).unwrap();

        let enc_cursor = Cursor::new(&encrypted);
        let res = decrypt_header(enc_cursor, wrong_password);
        assert!(matches!(res, Err(DecryptError::InvalidPassword)));
    }

    #[test]
    fn test_unsupported_version_rejected() {
        let bad_version_bytes = [0u8, 0u8, 0u8, 1u8, 0u8, 0u8];
        let cursor = Cursor::new(&bad_version_bytes);
        let res = decrypt_header(cursor, b"password");
        assert!(matches!(
            res,
            Err(DecryptError::CorruptHeader("Unsupported file version") | DecryptError::CorruptHeader("Unsupported version"))
        ));
    }

    #[test]
    fn test_out_of_bounds_iterations_rejected() {
        let password = b"TestPassword";
        let payload = b"test";

        let mut encrypted = Vec::new();
        let res = encrypt_stream(
            &mut Cursor::new(payload),
            &mut encrypted,
            password,
            "test.txt",
            0,
        );
        assert!(res.is_err());

        let mut valid = Vec::new();
        encrypt_stream(
            &mut Cursor::new(payload),
            &mut valid,
            password,
            "test.txt",
            1000,
        )
        .unwrap();
        valid[32..36].copy_from_slice(&0u32.to_be_bytes());
        let res = decrypt_header(Cursor::new(&valid), password);
        assert!(matches!(
            res,
            Err(DecryptError::CorruptHeader(
                "PBKDF2 iterations out of bounds" | "Invalid iterations"
            ))
        ));
    }

    #[test]
    fn test_zeroize() {
        let mut data = [42u8; 32];
        zeroize(&mut data);
        assert_eq!(data, [0u8; 32]);
    }

    #[test]
    fn test_age_passphrase_roundtrip() {
        let passphrase = "MySecureAgePassphrase123!";
        let original_name = "document.pdf";
        let payload = b"Secret PDF Binary Content 123456789";

        let mut input = Cursor::new(payload);
        let mut encrypted = Vec::new();
        encrypt_stream_age_passphrase(&mut input, &mut encrypted, passphrase, original_name)
            .expect("Age encryption failed");

        let enc_cursor = Cursor::new(&encrypted);
        let mut header = decrypt_header(enc_cursor, passphrase.as_bytes())
            .expect("Age decryption failed");
        assert_eq!(header.original_name, original_name);

        let mut decrypted_payload = Vec::new();
        header
            .decrypt_payload(&mut decrypted_payload)
            .expect("Age payload decryption failed");
        assert_eq!(decrypted_payload, payload);
    }

    #[test]
    fn test_age_key_based_roundtrip() {
        let key = age::x25519::Identity::generate();
        let pubkey = key.to_public();
        let original_name = "notes.md";
        let payload = b"# Top Secret Notes\n- item 1\n- item 2";

        let mut input = Cursor::new(payload);
        let mut encrypted = Vec::new();
        let recipients = vec![Box::new(pubkey) as Box<dyn age::Recipient + Send>];
        encrypt_stream_unified(
            &mut input,
            &mut encrypted,
            original_name,
            &EncryptionMethod::AgeRecipients(&recipients),
        )
        .expect("Key encryption failed");

        let creds = Credentials::new().with_identities(vec![Box::new(key)]);
        let enc_cursor = Cursor::new(&encrypted);
        let mut header = decrypt_header_with_credentials(enc_cursor, &creds)
            .expect("Key decryption header failed");
        assert_eq!(header.original_name, original_name);

        let mut decrypted_payload = Vec::new();
        header
            .decrypt_payload(&mut decrypted_payload)
            .expect("Key payload decryption failed");
        assert_eq!(decrypted_payload, payload);
    }

    #[test]
    fn test_extract_recipients_from_identity_file() {
        use age::secrecy::ExposeSecret;
        let key = age::x25519::Identity::generate();
        let pubkey = key.to_public();

        let temp_dir = std::env::temp_dir().join(format!("valv_id_test_{}", rand::random::<u32>()));
        let _ = std::fs::create_dir_all(&temp_dir);
        let key_file = temp_dir.join("keys.txt");

        // Format 1: With "# public key:" header
        let content = format!(
            "# created: 2026-01-01\n# public key: {}\n{}\n",
            pubkey,
            key.to_string().expose_secret()
        );
        std::fs::write(&key_file, &content).unwrap();
        let extracted = extract_recipients_from_identity_file(&key_file);
        assert_eq!(extracted, vec![pubkey.to_string()]);

        // Format 2: Just the secret key
        let content_raw = format!("{}\n", key.to_string().expose_secret());
        std::fs::write(&key_file, &content_raw).unwrap();
        let extracted_raw = extract_recipients_from_identity_file(&key_file);
        assert_eq!(extracted_raw, vec![pubkey.to_string()]);

        // Format 3: With "# Recipient: " (e.g. age-plugin-tpm or sops keys.txt)
        let content_recipient_hdr = format!(
            "# Created: 2026-09-30 11:51:01\n# Recipient: {}\nAGE-PLUGIN-TPM-1XYZ\n",
            pubkey
        );
        std::fs::write(&key_file, &content_recipient_hdr).unwrap();
        let extracted_recip = extract_recipients_from_identity_file(&key_file);
        assert_eq!(extracted_recip, vec![pubkey.to_string()]);

        // Format 4: Companion .pub file
        let private_key_file = temp_dir.join("id_test");
        let pub_key_file = temp_dir.join("id_test.pub");
        std::fs::write(&private_key_file, b"-----BEGIN OPENSSH PRIVATE KEY-----\n...").unwrap();
        std::fs::write(&pub_key_file, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... user@host\n").unwrap();
        let extracted_ssh = extract_recipients_from_identity_file(&private_key_file);
        assert_eq!(extracted_ssh, vec!["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... user@host"]);

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
