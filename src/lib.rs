pub mod cli;
pub mod crypto;
pub mod vault;

use std::io;

#[derive(Debug)]
pub enum ValvError {
    InvalidPassword,
    Io(io::Error),
    Decrypt(crypto::DecryptError),
    Message(String, u8),
}

impl ValvError {
    pub fn exit_code(&self) -> u8 {
        match self {
            ValvError::InvalidPassword => 2,
            ValvError::Io(_) => 1,
            ValvError::Decrypt(crypto::DecryptError::InvalidPassword) => 2,
            ValvError::Decrypt(_) => 1,
            ValvError::Message(_, code) => *code,
        }
    }
}

impl std::fmt::Display for ValvError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ValvError::InvalidPassword => write!(f, "Incorrect password"),
            ValvError::Io(e) => write!(f, "{}", e),
            ValvError::Decrypt(e) => write!(f, "{}", e),
            ValvError::Message(msg, _) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for ValvError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ValvError::Io(e) => Some(e),
            ValvError::Decrypt(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for ValvError {
    fn from(e: io::Error) -> Self {
        ValvError::Io(e)
    }
}

impl From<crypto::DecryptError> for ValvError {
    fn from(e: crypto::DecryptError) -> Self {
        match e {
            crypto::DecryptError::InvalidPassword => ValvError::InvalidPassword,
            crypto::DecryptError::Io(io_err) => ValvError::Io(io_err),
            other => ValvError::Decrypt(other),
        }
    }
}
