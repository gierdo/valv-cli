use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use crate::ValvError;
use crate::crypto::{
    BUFFER_SIZE, Credentials, DecryptError, EncryptionMethod, VaultFormat,
    decrypt_header_with_credentials,
};

use super::manifest::save_encrypted_manifest;
use super::paths::{collect_vault_files, get_thumbnail_valv_name, sanitize_filename};
use super::session::{SessionFileEntry, ValvSession};
use super::sync::run_sync_daemon_with_credentials;
use super::thumbnail::create_thumbnail_file_unified;

pub fn mount_vault(
    vault_dir: &Path,
    mount_dir: &Path,
    password_bytes: &[u8],
    watch_pid: Option<u32>,
    foreground: bool,
    iterations: u32,
) -> Result<(), ValvError> {
    let creds = Credentials::new().with_password(password_bytes.to_vec());
    mount_vault_with_credentials(
        vault_dir,
        mount_dir,
        &creds,
        watch_pid,
        foreground,
        iterations,
        VaultFormat::Valv,
        &[],
        &[],
        &[],
    )
}

#[allow(clippy::too_many_arguments)]
pub fn mount_vault_with_credentials(
    vault_dir: &Path,
    mount_dir: &Path,
    credentials: &Credentials,
    watch_pid: Option<u32>,
    foreground: bool,
    iterations: u32,
    default_format: VaultFormat,
    recipients: &[Box<dyn age::Recipient + Send>],
    identity_paths: &[PathBuf],
    recipient_strings: &[String],
) -> Result<(), ValvError> {
    if !vault_dir.is_dir() {
        return Err(ValvError::Message(
            format!("Cannot read vault directory {}", vault_dir.display()),
            1,
        ));
    }

    // 1. Decrypt manifest first if present. Abort immediately if manifest cannot be decrypted.
    let manifest_info = if let Some(manifest_path) =
        crate::config::AgeVaultManifest::find_in_dir(vault_dir)
    {
        let (manifest, content) = crate::config::AgeVaultManifest::load_from_file_with_credentials(
            &manifest_path,
            credentials,
        )
        .map_err(|e| ValvError::Message(format!("Failed to decrypt vault manifest: {}", e), 1))?;
        Some((manifest, manifest_path, content))
    } else {
        None
    };

    let valv_files = collect_vault_files(vault_dir);

    // Verify credentials on first file if any exist
    if let Some(first_file) = valv_files.first() {
        let f = File::open(first_file)?;
        let r = BufReader::new(f);
        if let Err(DecryptError::InvalidPassword) = decrypt_header_with_credentials(r, credentials)
        {
            return Err(ValvError::InvalidPassword);
        }
    }

    fs::create_dir_all(mount_dir).map_err(|e| {
        ValvError::Message(
            format!(
                "Failed to create mount directory {}: {}",
                mount_dir.display(),
                e
            ),
            1,
        )
    })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(mount_dir, fs::Permissions::from_mode(0o700));
    }

    // Prevent desktop thumbnailers from caching decrypted media in ~/.cache/thumbnails
    let _ = fs::write(mount_dir.join(".nomedia"), b"");
    #[cfg(unix)]
    {
        let thumb_symlink = mount_dir.join(".thumbnails");
        if !thumb_symlink.exists() {
            let _ = std::os::unix::fs::symlink("/dev/null", &thumb_symlink);
        }
    }

    let mut manifest_recip_list = Vec::new();
    if let Some((manifest, manifest_path, content)) = manifest_info {
        let (resolved_manifest_recips, resolved_manifest_files) = manifest.resolve_recipients();
        manifest_recip_list = resolved_manifest_recips;

        let mount_manifest_name = if manifest_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .starts_with("age_vault")
        {
            "age_vault.toml"
        } else {
            ".age_vault.toml"
        };
        let mount_manifest_file = mount_dir.join(mount_manifest_name);
        fs::write(&mount_manifest_file, content)?;

        let fallback_recips;
        let recips_for_init = if !recipients.is_empty() {
            recipients
        } else if let Ok(loaded) =
            crate::crypto::load_recipients(&manifest_recip_list, &resolved_manifest_files)
            && !loaded.is_empty()
        {
            fallback_recips = loaded;
            &fallback_recips[..]
        } else {
            &[]
        };

        let _ = save_encrypted_manifest(
            &mount_manifest_file,
            vault_dir,
            default_format,
            recips_for_init,
            credentials,
            iterations,
        );
    }

    if manifest_recip_list.is_empty() && !recipient_strings.is_empty() {
        manifest_recip_list = recipient_strings.to_vec();
    }

    let mut session = ValvSession {
        vault_dir: fs::canonicalize(vault_dir).unwrap_or_else(|_| vault_dir.to_path_buf()),
        watch_pid,
        daemon_pid: std::process::id(),
        files: HashMap::new(),
        format: Some(match default_format {
            VaultFormat::Age => "age".to_string(),
            VaultFormat::Valv => "valv".to_string(),
        }),
        manifest_recipients: manifest_recip_list.clone(),
    };

    // Decrypt all existing files (including nested subdirectories) into mount_dir via streaming
    for valv_path in &valv_files {
        let rel_valv_path = match valv_path.strip_prefix(vault_dir) {
            Ok(p) => p,
            Err(_) => valv_path.as_path(),
        };
        let rel_dir = rel_valv_path.parent().unwrap_or(Path::new(""));

        let in_file = match File::open(valv_path) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("Warning: skipping {}: {}", valv_path.display(), e);
                continue;
            }
        };
        let reader = BufReader::with_capacity(BUFFER_SIZE, in_file);

        let mut header = match decrypt_header_with_credentials(reader, credentials) {
            Ok(h) => h,
            Err(DecryptError::InvalidPassword) => {
                eprintln!(
                    "Warning: failed decrypting {}: invalid password or key",
                    valv_path.display()
                );
                continue;
            }
            Err(e) => {
                eprintln!("Warning: skipping {}: {}", valv_path.display(), e);
                continue;
            }
        };

        let orig_name = sanitize_filename(&header.original_name).to_string();
        let rel_dest_path = if rel_dir.as_os_str().is_empty() {
            PathBuf::from(&orig_name)
        } else {
            rel_dir.join(&orig_name)
        };
        let dest_path = mount_dir.join(&rel_dest_path);

        if let Some(parent) = dest_path.parent() {
            let _ = fs::create_dir_all(parent);
        }

        #[cfg(unix)]
        let out_file = {
            use std::os::unix::fs::OpenOptionsExt;
            match File::options()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&dest_path)
            {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("Warning: skipping {}: {}", dest_path.display(), e);
                    continue;
                }
            }
        };
        #[cfg(not(unix))]
        let out_file = match File::create(&dest_path) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("Warning: skipping {}: {}", dest_path.display(), e);
                continue;
            }
        };
        let mut writer = BufWriter::with_capacity(BUFFER_SIZE, out_file);

        if let Err(e) = header.decrypt_payload(&mut writer) {
            eprintln!(
                "Warning: failed decrypting payload {}: {}",
                valv_path.display(),
                e
            );
            let _ = fs::remove_file(&dest_path);
            continue;
        }
        let _ = writer.flush();

        let meta = fs::metadata(&dest_path).ok();
        let mtime = meta
            .as_ref()
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let size = meta.map(|m| m.len()).unwrap_or(0);
        session.files.insert(
            rel_dest_path.to_string_lossy().to_string(),
            SessionFileEntry {
                valv_name: rel_valv_path.to_string_lossy().to_string(),
                mtime_secs: mtime,
                size,
            },
        );

        if let Some(thumb_name) = get_thumbnail_valv_name(&rel_valv_path.to_string_lossy()) {
            let thumb_valv = vault_dir.join(&thumb_name);
            if !thumb_valv.exists() {
                let method = if rel_valv_path.to_string_lossy().ends_with(".age") {
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

                if let Some(m) = method {
                    let _ = create_thumbnail_file_unified(&dest_path, &thumb_valv, &orig_name, &m);
                }
            }
        }
    }

    let session_json = serde_json::to_string(&session)
        .map_err(|e| ValvError::Message(format!("Session serialization failed: {}", e), 1))?;
    fs::write(mount_dir.join(".valv_session.json"), session_json)?;

    if foreground {
        println!("READY {}", mount_dir.display());
        run_sync_daemon_with_credentials(
            &session.vault_dir,
            mount_dir,
            credentials,
            watch_pid,
            iterations,
            default_format,
            recipients,
        )?;
    } else {
        let current_exe = std::env::current_exe()?;

        let mut cmd = std::process::Command::new(current_exe);
        cmd.arg("sync-daemon")
            .arg(&session.vault_dir)
            .arg(mount_dir)
            .arg("-i")
            .arg(iterations.to_string());

        if default_format == VaultFormat::Age {
            cmd.arg("--age");
        } else if default_format == VaultFormat::Valv {
            cmd.arg("--valv");
        }

        for path in identity_paths {
            cmd.arg("-k").arg(path);
        }

        for recip in &manifest_recip_list {
            cmd.arg("-r").arg(recip);
        }

        for recip in recipient_strings {
            if !manifest_recip_list.contains(recip) {
                cmd.arg("-r").arg(recip);
            }
        }

        if let Some(pid) = watch_pid {
            cmd.arg("--watch-pid").arg(pid.to_string());
        }

        if credentials.password.is_some() {
            cmd.arg("--stdin-password");
            cmd.stdin(std::process::Stdio::piped());
        }

        cmd.stdout(std::process::Stdio::null());
        cmd.stderr(std::process::Stdio::null());

        let mut child = cmd.spawn()?;
        if let Some(ref pwd) = credentials.password
            && let Some(mut stdin) = child.stdin.take()
        {
            let _ = stdin.write_all(pwd);
            let _ = stdin.write_all(b"\n");
        }

        println!("READY {}", mount_dir.display());
    }

    Ok(())
}
