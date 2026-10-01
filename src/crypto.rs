use std::fs::File;
use std::io::{self, BufReader, Cursor, Read, Write};
use std::path::{Path, PathBuf};

use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use pbkdf2::pbkdf2_hmac;
use rand::RngExt;
use serde::{Deserialize, Serialize};
use sha2::Sha512;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

pub const VALV_V2: u32 = 2;
pub const DEFAULT_ITERATIONS: u32 = 50_000;
pub const MIN_ITERATIONS: u32 = 1_000;
pub const MAX_ITERATIONS: u32 = 1_000_000;
pub const BUFFER_SIZE: usize = 64 * 1024;

pub fn zeroize(bytes: &mut [u8]) {
    bytes.zeroize();
}

const SALT_LEN: usize = 16;
const IV_LEN: usize = 12;
const CHECK_LEN: usize = 12;

#[derive(Serialize, Deserialize)]
struct ValvMetadata {
    #[serde(rename = "originalName")]
    original_name: String,
}

#[derive(Debug)]
pub enum DecryptError {
    InvalidPassword,
    CorruptHeader(&'static str),
    Io(io::Error),
}

impl std::fmt::Display for DecryptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecryptError::InvalidPassword => write!(f, "Invalid password"),
            DecryptError::CorruptHeader(msg) => write!(f, "Corrupt file header: {}", msg),
            DecryptError::Io(e) => write!(f, "I/O error: {}", e),
        }
    }
}

impl std::error::Error for DecryptError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            DecryptError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for DecryptError {
    fn from(e: io::Error) -> Self {
        DecryptError::Io(e)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultFormat {
    Age,
    Valv,
}

#[derive(Default)]
pub struct Credentials {
    pub password: Option<Vec<u8>>,
    pub identities: Vec<Box<dyn age::Identity>>,
}

impl Credentials {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_password(mut self, password: Vec<u8>) -> Self {
        self.password = Some(password);
        self
    }

    pub fn with_identities(mut self, identities: Vec<Box<dyn age::Identity>>) -> Self {
        self.identities = identities;
        self
    }

    pub fn is_empty(&self) -> bool {
        self.password.as_ref().map(|p| p.is_empty()).unwrap_or(true) && self.identities.is_empty()
    }
}

impl Drop for Credentials {
    fn drop(&mut self) {
        if let Some(ref mut pwd) = self.password {
            pwd.zeroize();
        }
    }
}

pub enum EncryptionMethod<'a> {
    AgeRecipients(&'a [Box<dyn age::Recipient + Send>]),
    AgePassphrase(&'a str),
    ValvPassphrase {
        password: &'a [u8],
        iterations: u32,
    },
}

pub enum DecryptedPayload<'a> {
    Valv {
        cipher: ChaCha20,
        reader: Box<dyn Read + Send + 'a>,
    },
    Age(Box<dyn Read + Send + 'a>),
}

pub struct DecryptedHeader<'a> {
    pub original_name: String,
    pub payload: DecryptedPayload<'a>,
}

pub fn transform_stream<R: Read, W: Write>(
    cipher: &mut ChaCha20,
    reader: &mut R,
    writer: &mut W,
) -> io::Result<()> {
    let mut buffer = vec![0u8; BUFFER_SIZE];
    loop {
        let n = reader.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        cipher.apply_keystream(&mut buffer[..n]);
        writer.write_all(&buffer[..n])?;
    }
    writer.flush()?;
    Ok(())
}

impl<'a> DecryptedHeader<'a> {
    pub fn decrypt_payload<W: Write>(&mut self, writer: &mut W) -> io::Result<()> {
        match &mut self.payload {
            DecryptedPayload::Valv { cipher, reader } => transform_stream(cipher, reader, writer),
            DecryptedPayload::Age(age_reader) => {
                io::copy(age_reader, writer)?;
                writer.flush()?;
                Ok(())
            }
        }
    }
}

pub fn derive_key(password: &[u8], salt: &[u8], iterations: u32) -> [u8; 32] {
    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha512>(password, salt, iterations, &mut key);
    key
}

pub fn encrypt_stream<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    password: &[u8],
    original_name: &str,
    iterations: u32,
) -> io::Result<()> {
    if !(MIN_ITERATIONS..=MAX_ITERATIONS).contains(&iterations) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "Iterations must be between {} and {}",
                MIN_ITERATIONS, MAX_ITERATIONS
            ),
        ));
    }

    let mut rng = rand::rng();
    let mut salt = [0u8; SALT_LEN];
    let mut iv = [0u8; IV_LEN];
    let mut check_bytes = [0u8; CHECK_LEN];
    rng.fill(&mut salt);
    rng.fill(&mut iv);
    rng.fill(&mut check_bytes);

    writer.write_all(&VALV_V2.to_be_bytes())?;
    writer.write_all(&salt)?;
    writer.write_all(&iv)?;
    writer.write_all(&iterations.to_be_bytes())?;
    writer.write_all(&check_bytes)?;

    let mut key = derive_key(password, &salt, iterations);
    let mut cipher = ChaCha20::new(&key.into(), &iv.into());
    zeroize(&mut key);

    let mut encrypted_check = check_bytes;
    cipher.apply_keystream(&mut encrypted_check);
    writer.write_all(&encrypted_check)?;

    let meta = serde_json::to_string(&ValvMetadata {
        original_name: original_name.to_string(),
    })
    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    let mut prefix_bytes = Vec::with_capacity(meta.len() + 2);
    prefix_bytes.push(b'\n');
    prefix_bytes.extend_from_slice(meta.as_bytes());
    prefix_bytes.push(b'\n');

    cipher.apply_keystream(&mut prefix_bytes);
    writer.write_all(&prefix_bytes)?;

    transform_stream(&mut cipher, reader, writer)
}

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

        let mut salt = [0u8; SALT_LEN];
        let mut iv = [0u8; IV_LEN];
        let mut iters_bytes = [0u8; 4];
        let mut check_bytes = [0u8; CHECK_LEN];

        reader.read_exact(&mut salt)?;
        reader.read_exact(&mut iv)?;
        reader.read_exact(&mut iters_bytes)?;
        reader.read_exact(&mut check_bytes)?;

        let iterations = u32::from_be_bytes(iters_bytes);
        if !(MIN_ITERATIONS..=MAX_ITERATIONS).contains(&iterations) {
            return Err(DecryptError::CorruptHeader(
                "PBKDF2 iterations out of bounds",
            ));
        }

        let mut key = derive_key(password, &salt, iterations);
        let mut cipher = ChaCha20::new(&key.into(), &iv.into());
        zeroize(&mut key);

        let mut dec_check = [0u8; CHECK_LEN];
        reader.read_exact(&mut dec_check)?;
        cipher.apply_keystream(&mut dec_check);

        if !bool::from(dec_check.ct_eq(&check_bytes)) {
            return Err(DecryptError::InvalidPassword);
        }

        let mut nl = [0u8; 1];
        reader.read_exact(&mut nl)?;
        cipher.apply_keystream(&mut nl);
        if nl[0] != b'\n' {
            return Err(DecryptError::CorruptHeader("Missing initial newline"));
        }

        let mut json_bytes = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            reader.read_exact(&mut byte)?;
            cipher.apply_keystream(&mut byte);
            if byte[0] == b'\n' {
                break;
            }
            json_bytes.push(byte[0]);
            if json_bytes.len() > 4096 {
                return Err(DecryptError::CorruptHeader("Metadata exceeds 4KB"));
            }
        }

        let meta_str = std::str::from_utf8(&json_bytes)
            .map_err(|_| DecryptError::CorruptHeader("Invalid UTF-8 in metadata"))?;
        let meta: ValvMetadata = serde_json::from_str(meta_str)
            .map_err(|_| DecryptError::CorruptHeader("Invalid JSON metadata"))?;

        Ok(DecryptedHeader {
            original_name: meta.original_name,
            payload: DecryptedPayload::Valv {
                cipher,
                reader: Box::new(reader),
            },
        })
    } else {
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
                    && let Ok(meta) = serde_json::from_str::<ValvMetadata>(meta_str)
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

pub fn encrypt_file(
    source: &Path,
    dest: &Path,
    password: &[u8],
    original_name: &str,
    iterations: u32,
) -> io::Result<()> {
    let mut in_file = BufReader::with_capacity(BUFFER_SIZE, File::open(source)?);
    let out_file = File::create(dest)?;
    let mut out_writer = std::io::BufWriter::with_capacity(BUFFER_SIZE, out_file);
    encrypt_stream(
        &mut in_file,
        &mut out_writer,
        password,
        original_name,
        iterations,
    )
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

    let mut out_writer = std::io::BufWriter::with_capacity(BUFFER_SIZE, out_file);
    decrypt_file_to(source, password, &mut out_writer)
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
            Err(DecryptError::CorruptHeader("Unsupported file version"))
        ));
    }

    #[test]
    fn test_out_of_bounds_iterations_rejected() {
        let password = b"TestPassword";
        let payload = b"test";

        // iterations = 0 (below MIN_ITERATIONS)
        let mut encrypted = Vec::new();
        let res = encrypt_stream(
            &mut Cursor::new(payload),
            &mut encrypted,
            password,
            "test.txt",
            0,
        );
        assert!(res.is_err());

        // Construct header with iterations = 0
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
                "PBKDF2 iterations out of bounds"
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
}
