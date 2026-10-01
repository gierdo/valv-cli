use std::io::{self, Read, Write};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

pub const VALV_V2: u32 = 2;
pub const DEFAULT_ITERATIONS: u32 = 50_000;
pub const MIN_ITERATIONS: u32 = 1_000;
pub const MAX_ITERATIONS: u32 = 1_000_000;
pub const BUFFER_SIZE: usize = 64 * 1024;

pub const SALT_LEN: usize = 16;
pub const IV_LEN: usize = 12;
pub const CHECK_LEN: usize = 12;

pub fn zeroize(bytes: &mut [u8]) {
    bytes.zeroize();
}

#[derive(Serialize, Deserialize)]
pub struct ValvMetadata {
    #[serde(rename = "originalName")]
    pub original_name: String,
}

#[derive(Debug)]
pub enum DecryptError {
    InvalidPassword,
    ExcessiveWork,
    CorruptHeader(&'static str),
    Io(io::Error),
}

impl std::fmt::Display for DecryptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecryptError::InvalidPassword => write!(f, "Invalid password or key"),
            DecryptError::ExcessiveWork => write!(f, "Decryption requires excessive work"),
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

impl From<age::DecryptError> for DecryptError {
    fn from(err: age::DecryptError) -> Self {
        match err {
            age::DecryptError::ExcessiveWork { .. } => DecryptError::ExcessiveWork,
            age::DecryptError::InvalidHeader => DecryptError::CorruptHeader("Invalid age header"),
            age::DecryptError::InvalidMac => DecryptError::CorruptHeader("Invalid age header MAC"),
            age::DecryptError::UnknownFormat => {
                DecryptError::CorruptHeader("Unsupported file version")
            }
            age::DecryptError::Io(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                DecryptError::CorruptHeader("Invalid or truncated header")
            }
            age::DecryptError::Io(e) => DecryptError::Io(e),
            _ => DecryptError::InvalidPassword,
        }
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

pub fn write_metadata_prefix<W: Write>(writer: &mut W, original_name: &str) -> io::Result<()> {
    let meta = serde_json::to_string(&ValvMetadata {
        original_name: original_name.to_string(),
    })
    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    let mut prefix_bytes = Vec::with_capacity(meta.len() + 2);
    prefix_bytes.push(b'\n');
    prefix_bytes.extend_from_slice(meta.as_bytes());
    prefix_bytes.push(b'\n');
    writer.write_all(&prefix_bytes)?;
    Ok(())
}

pub fn extract_metadata_from_stream<'a, R: Read + Send + 'a>(
    mut reader: R,
) -> (String, Box<dyn Read + Send + 'a>) {
    let mut first_byte = [0u8; 1];
    if let Ok(1) = reader.read(&mut first_byte) {
        if first_byte[0] == b'\n' {
            let mut buf = Vec::new();
            let mut byte = [0u8; 1];
            let mut found_newline = false;
            while buf.len() < 4096 {
                match reader.read(&mut byte) {
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
                return (meta.original_name, Box::new(reader));
            } else {
                let mut full_buf =
                    Vec::with_capacity(1 + buf.len() + if found_newline { 1 } else { 0 });
                full_buf.push(b'\n');
                full_buf.extend_from_slice(&buf);
                if found_newline {
                    full_buf.push(b'\n');
                }
                let chained = std::io::Cursor::new(full_buf).chain(reader);
                return ("decrypted_file".to_string(), Box::new(chained));
            }
        } else {
            let chained = std::io::Cursor::new(vec![first_byte[0]]).chain(reader);
            return ("decrypted_file".to_string(), Box::new(chained));
        }
    }

    ("decrypted_file".to_string(), Box::new(reader))
}

pub struct DecryptedHeader<'a> {
    pub original_name: String,
    pub payload: Box<dyn Read + Send + 'a>,
}

impl<'a> DecryptedHeader<'a> {
    pub fn decrypt_payload<W: Write>(&mut self, writer: &mut W) -> io::Result<()> {
        io::copy(&mut self.payload, writer)?;
        writer.flush()?;
        Ok(())
    }
}
