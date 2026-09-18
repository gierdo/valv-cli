use std::fs::File;
use std::io::{self, BufReader, Read, Write};
use std::path::Path;

use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use pbkdf2::pbkdf2_hmac;
use rand::RngExt;
use serde::{Deserialize, Serialize};
use sha2::Sha512;

pub const VALV_V2: u32 = 2;
pub const DEFAULT_ITERATIONS: u32 = 50_000;
pub const V1_ITERATIONS: u32 = 20_000;
pub const BUFFER_SIZE: usize = 64 * 1024;

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

pub struct DecryptedHeader {
    pub original_name: String,
    pub cipher: ChaCha20,
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

impl DecryptedHeader {
    pub fn decrypt_payload<R: Read, W: Write>(
        &mut self,
        reader: &mut R,
        writer: &mut W,
    ) -> io::Result<()> {
        transform_stream(&mut self.cipher, reader, writer)
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

    let key = derive_key(password, &salt, iterations);
    let mut cipher = ChaCha20::new(&key.into(), &iv.into());

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

pub fn decrypt_header<R: Read>(
    reader: &mut R,
    password: &[u8],
    is_v1_hint: bool,
) -> Result<DecryptedHeader, DecryptError> {
    let mut first4 = [0u8; 4];
    reader.read_exact(&mut first4)?;
    let version = u32::from_be_bytes(first4);

    if version == VALV_V2 && !is_v1_hint {
        let mut salt = [0u8; SALT_LEN];
        let mut iv = [0u8; IV_LEN];
        let mut iters_bytes = [0u8; 4];
        let mut check_bytes = [0u8; CHECK_LEN];

        reader.read_exact(&mut salt)?;
        reader.read_exact(&mut iv)?;
        reader.read_exact(&mut iters_bytes)?;
        reader.read_exact(&mut check_bytes)?;

        let iterations = u32::from_be_bytes(iters_bytes);
        let key = derive_key(password, &salt, iterations);
        let mut cipher = ChaCha20::new(&key.into(), &iv.into());

        let mut dec_check = [0u8; CHECK_LEN];
        reader.read_exact(&mut dec_check)?;
        cipher.apply_keystream(&mut dec_check);

        let mut diff = 0u8;
        for (a, b) in dec_check.iter().zip(check_bytes.iter()) {
            diff |= a ^ b;
        }
        if diff != 0 {
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
            cipher,
        })
    } else {
        let mut salt = [0u8; SALT_LEN];
        salt[..4].copy_from_slice(&first4);
        reader.read_exact(&mut salt[4..])?;

        let mut iv = [0u8; IV_LEN];
        reader.read_exact(&mut iv)?;

        let key = derive_key(password, &salt, V1_ITERATIONS);
        let mut cipher = ChaCha20::new(&key.into(), &iv.into());

        let mut first_enc = [0u8; 1];
        reader.read_exact(&mut first_enc)?;
        cipher.apply_keystream(&mut first_enc);

        let mut name_bytes = Vec::new();
        if first_enc[0] == b'\n' {
            let mut byte = [0u8; 1];
            loop {
                reader.read_exact(&mut byte)?;
                cipher.apply_keystream(&mut byte);
                if byte[0] == b'\n' {
                    break;
                }
                name_bytes.push(byte[0]);
                if name_bytes.len() > 1024 {
                    return Err(DecryptError::InvalidPassword);
                }
            }
        } else {
            return Err(DecryptError::InvalidPassword);
        }

        let original_name =
            String::from_utf8(name_bytes).map_err(|_| DecryptError::InvalidPassword)?;

        Ok(DecryptedHeader {
            original_name,
            cipher,
        })
    }
}

pub fn decrypt_file_to<W: Write>(
    file_path: &Path,
    password: &[u8],
    writer: &mut W,
) -> Result<String, DecryptError> {
    let file = File::open(file_path)?;
    let mut reader = BufReader::with_capacity(BUFFER_SIZE, file);

    let is_v1_hint = file_path
        .file_name()
        .and_then(|n| n.to_str())
        .map(|n| n.starts_with(".valv."))
        .unwrap_or(false);

    let mut header = decrypt_header(&mut reader, password, is_v1_hint)?;
    header.decrypt_payload(&mut reader, writer)?;
    Ok(header.original_name)
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
    let out_file = File::create(dest)?;
    let mut out_writer = std::io::BufWriter::with_capacity(BUFFER_SIZE, out_file);
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

        let mut enc_cursor = Cursor::new(&encrypted);
        let mut header =
            decrypt_header(&mut enc_cursor, password, false).expect("Decryption header failed");
        assert_eq!(header.original_name, original_name);

        let mut decrypted_payload = Vec::new();
        header
            .decrypt_payload(&mut enc_cursor, &mut decrypted_payload)
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

        let mut enc_cursor = Cursor::new(&encrypted);
        let res = decrypt_header(&mut enc_cursor, wrong_password, false);
        assert!(matches!(res, Err(DecryptError::InvalidPassword)));
    }
}
