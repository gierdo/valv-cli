use std::io::{self, Read, Write};
use chacha20::ChaCha20;
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

impl<'a> DecryptedHeader<'a> {
    pub fn decrypt_payload<W: Write>(&mut self, writer: &mut W) -> io::Result<()> {
        match &mut self.payload {
            DecryptedPayload::Valv { cipher, reader } => {
                crate::crypto::valv_format::transform_stream(cipher, reader, writer)
            }
            DecryptedPayload::Age(age_reader) => {
                io::copy(age_reader, writer)?;
                writer.flush()?;
                Ok(())
            }
        }
    }
}
