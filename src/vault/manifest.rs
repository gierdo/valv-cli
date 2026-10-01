use std::fs::{self, File};
use std::io::{BufWriter, Cursor, Write};
use std::path::Path;

use crate::ValvError;
use crate::crypto::{encrypt_stream_unified, Credentials, EncryptionMethod, VaultFormat};

pub fn save_encrypted_manifest(
    mount_manifest_path: &Path,
    vault_dir: &Path,
    format: VaultFormat,
    recipients: &[Box<dyn age::Recipient + Send>],
    credentials: &Credentials,
    iterations: u32,
) -> Result<(), ValvError> {
    if !mount_manifest_path.is_file() {
        return Ok(());
    }

    let plaintext = fs::read(mount_manifest_path)?;
    let orig_name = mount_manifest_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(".age_vault.toml");

    let method = if format == VaultFormat::Age || !recipients.is_empty() {
        if !recipients.is_empty() {
            Some(EncryptionMethod::AgeRecipients(recipients))
        } else if let Some(ref pwd) = credentials.password
            && let Ok(pwd_str) = std::str::from_utf8(pwd)
        {
            Some(EncryptionMethod::AgePassphrase(pwd_str))
        } else {
            None
        }
    } else {
        credentials
            .password
            .as_ref()
            .map(|pwd| EncryptionMethod::ValvPassphrase {
                password: pwd,
                iterations,
            })
    };

    let method = match method {
        Some(m) => m,
        None => return Ok(()),
    };

    let target_name = if orig_name.starts_with('.') {
        if format == VaultFormat::Age || !recipients.is_empty() {
            ".age_vault.toml.age"
        } else {
            ".age_vault.toml.valv"
        }
    } else if format == VaultFormat::Age || !recipients.is_empty() {
        "age_vault.toml.age"
    } else {
        "age_vault.toml.valv"
    };

    let target_path = vault_dir.join(target_name);
    let mut out_file = BufWriter::new(File::create(&target_path)?);
    encrypt_stream_unified(
        &mut Cursor::new(&plaintext),
        &mut out_file,
        orig_name,
        &method,
    )
    .map_err(|e| ValvError::Message(format!("Failed to encrypt manifest: {}", e), 1))?;
    out_file.flush()?;

    // Remove any unencrypted plaintext manifest in vault_dir if present
    let plain_name = if orig_name.starts_with('.') {
        ".age_vault.toml"
    } else {
        "age_vault.toml"
    };
    let unencrypted_in_vault = vault_dir.join(plain_name);
    if unencrypted_in_vault.is_file() && unencrypted_in_vault != target_path {
        let _ = fs::remove_file(unencrypted_in_vault);
    }

    Ok(())
}
