use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Write};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, UNIX_EPOCH};

use crate::ValvError;
use crate::crypto::{
    BUFFER_SIZE, Credentials, EncryptionMethod, VaultFormat, encrypt_stream_unified,
};

use super::manifest::save_encrypted_manifest;
use super::paths::{
    clean_empty_dirs_up_to, collect_plain_files, generate_random_filename,
    get_suffix_for_path_and_format, get_thumbnail_valv_name,
};
use super::session::{SessionFileEntry, ValvSession, is_process_alive, list_mounts};
use super::thumbnail::create_thumbnail_file_unified;

pub static TERMINATE: AtomicBool = AtomicBool::new(false);

#[cfg(unix)]
pub extern "C" fn sig_handler(_: libc::c_int) {
    TERMINATE.store(true, Ordering::SeqCst);
}

pub fn sync_file_to_vault(
    src_path: &Path,
    vault_dir: &Path,
    valv_name: &str,
    orig_name: &str,
    credentials: &Credentials,
    iterations: u32,
    recipients: &[Box<dyn age::Recipient + Send>],
) -> Result<(), ValvError> {
    let dest_path = vault_dir.join(valv_name);
    if let Some(parent) = dest_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let in_file = File::open(src_path)?;
    let mut in_reader = BufReader::with_capacity(BUFFER_SIZE, in_file);

    let out_file = File::create(&dest_path)?;
    let mut out_writer = BufWriter::with_capacity(BUFFER_SIZE, out_file);

    let method = if valv_name.ends_with(".age") {
        if !recipients.is_empty() {
            EncryptionMethod::AgeRecipients(recipients)
        } else if let Some(ref pwd) = credentials.password
            && let Ok(pwd_str) = std::str::from_utf8(pwd)
        {
            EncryptionMethod::AgePassphrase(pwd_str)
        } else {
            return Err(ValvError::Message(
                "No recipients or passphrase available for age encryption".to_string(),
                1,
            ));
        }
    } else if let Some(ref pwd) = credentials.password {
        EncryptionMethod::ValvPassphrase {
            password: pwd,
            iterations,
        }
    } else {
        return Err(ValvError::Message(
            "No password available for valv encryption".to_string(),
            1,
        ));
    };

    encrypt_stream_unified(&mut in_reader, &mut out_writer, orig_name, &method)?;
    out_writer.flush()?;

    if let Some(thumb_name) = get_thumbnail_valv_name(valv_name) {
        let thumb_path = vault_dir.join(&thumb_name);
        let _ = create_thumbnail_file_unified(src_path, &thumb_path, orig_name, &method);
    }

    Ok(())
}

pub fn preserve_unsynced_dirs(mount_dir: &Path, vault_dir: &Path) {
    if let Ok(entries) = fs::read_dir(mount_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name.starts_with('.') || crate::config::is_manifest_file(&path) {
                continue;
            }
            if path.is_dir() {
                let target_dir = vault_dir.join(name);
                if !target_dir.exists() {
                    let _ = fs::rename(&path, &target_dir);
                }
            }
        }
    }
}

pub fn run_sync_daemon_with_credentials(
    vault_dir: &Path,
    mount_dir: &Path,
    credentials: &Credentials,
    watch_pid: Option<u32>,
    iterations: u32,
    default_format: VaultFormat,
    recipients: &[Box<dyn age::Recipient + Send>],
) -> Result<(), ValvError> {
    let session_file = mount_dir.join(".valv_session.json");
    let mut session: ValvSession = match fs::read_to_string(&session_file) {
        Ok(data) => serde_json::from_str(&data).unwrap_or_default(),
        Err(_) => ValvSession::default(),
    };
    session.vault_dir = vault_dir.to_path_buf();
    session.daemon_pid = std::process::id();

    #[cfg(unix)]
    unsafe {
        libc::signal(libc::SIGINT, sig_handler as *const () as libc::sighandler_t);
        libc::signal(
            libc::SIGTERM,
            sig_handler as *const () as libc::sighandler_t,
        );
        libc::signal(libc::SIGHUP, sig_handler as *const () as libc::sighandler_t);
    }

    let close_trigger = mount_dir.join(".valv_close");
    let mut current_recipients: Vec<Box<dyn age::Recipient + Send>> =
        if let Some(mount_manifest_path) = crate::config::AgeVaultManifest::find_in_dir(mount_dir)
            && let Ok((manifest, _)) =
                crate::config::AgeVaultManifest::load_from_file_with_credentials(
                    &mount_manifest_path,
                    credentials,
                )
        {
            let (r_strs, r_files) = manifest.resolve_recipients();
            crate::crypto::load_recipients(&r_strs, &r_files).unwrap_or_default()
        } else if let Ok(Some((manifest, _, _))) =
            crate::config::AgeVaultManifest::load_from_dir_with_credentials(vault_dir, credentials)
        {
            let (r_strs, r_files) = manifest.resolve_recipients();
            crate::crypto::load_recipients(&r_strs, &r_files).unwrap_or_default()
        } else {
            Vec::new()
        };

    loop {
        if TERMINATE.load(Ordering::SeqCst) {
            break;
        }

        // 1. Check if watched process (e.g. Yazi) is still running
        if let Some(pid) = watch_pid
            && !is_process_alive(pid)
        {
            break;
        }

        // 2. Check if close/unmount requested
        if close_trigger.exists() {
            break;
        }

        // 3. Sync manifest file between mount_dir and vault_dir and re-encrypt if recipients changed
        let mount_manifest_path = crate::config::AgeVaultManifest::find_in_dir(mount_dir);
        let active_manifest_info = if let Some(ref p_mount) = mount_manifest_path {
            crate::config::AgeVaultManifest::load_from_file_with_credentials(p_mount, credentials)
                .ok()
        } else {
            None
        };

        let effective_recipients: &[Box<dyn age::Recipient + Send>] =
            if let Some((ref manifest, _)) = active_manifest_info {
                let (new_recip_strs, new_recip_files) = manifest.resolve_recipients();
                let recipients_changed = (!new_recip_strs.is_empty()
                    || !new_recip_files.is_empty())
                    && new_recip_strs != session.manifest_recipients;
                if recipients_changed
                    && let Ok(new_recips) =
                        crate::crypto::load_recipients(&new_recip_strs, &new_recip_files)
                    && !new_recips.is_empty()
                {
                    current_recipients = new_recips;
                    session.manifest_recipients = new_recip_strs.clone();

                    // Re-encrypt all existing files in session.files with updated recipients
                    for (rel_dest_path, item) in &session.files {
                        let src_path = mount_dir.join(rel_dest_path);
                        let filename = src_path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                        if src_path.exists() {
                            let _ = sync_file_to_vault(
                                &src_path,
                                vault_dir,
                                &item.valv_name,
                                filename,
                                credentials,
                                iterations,
                                &current_recipients,
                            );
                        }
                    }
                }

                if current_recipients.is_empty()
                    && (!new_recip_strs.is_empty() || !new_recip_files.is_empty())
                    && let Ok(loaded) =
                        crate::crypto::load_recipients(&new_recip_strs, &new_recip_files)
                {
                    current_recipients = loaded;
                }

                let recips_for_manifest = if !current_recipients.is_empty() {
                    &current_recipients[..]
                } else {
                    recipients
                };

                if let Some(ref p_mount) = mount_manifest_path {
                    let _ = save_encrypted_manifest(
                        p_mount,
                        vault_dir,
                        default_format,
                        recips_for_manifest,
                        credentials,
                        iterations,
                    );
                }

                if !current_recipients.is_empty() {
                    &current_recipients
                } else {
                    recipients
                }
            } else if !current_recipients.is_empty() {
                &current_recipients
            } else {
                recipients
            };

        // 4. Scan mount_dir recursively for changes (supports pasting subdirectories)
        let plain_files = collect_plain_files(mount_dir);
        for path in plain_files {
            let rel_path = match path.strip_prefix(mount_dir) {
                Ok(p) => p,
                Err(_) => continue,
            };
            let rel_str = rel_path.to_string_lossy().to_string();

            let meta = match fs::metadata(&path) {
                Ok(m) => m,
                Err(_) => continue,
            };
            let mtime = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let size = meta.len();

            let needs_sync = match session.files.get(&rel_str) {
                Some(entry) => entry.mtime_secs != mtime || entry.size != size,
                None => true,
            };

            if needs_sync {
                let suffix = get_suffix_for_path_and_format(&path, default_format);
                let valv_name = match session.files.get(&rel_str) {
                    Some(entry) => entry.valv_name.clone(),
                    None => {
                        let rel_dir = rel_path.parent().unwrap_or(Path::new(""));
                        let random_valv = generate_random_filename(suffix);
                        if rel_dir.as_os_str().is_empty() {
                            random_valv
                        } else {
                            rel_dir.join(random_valv).to_string_lossy().to_string()
                        }
                    }
                };

                let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if sync_file_to_vault(
                    &path,
                    vault_dir,
                    &valv_name,
                    filename,
                    credentials,
                    iterations,
                    effective_recipients,
                )
                .is_ok()
                {
                    session.files.insert(
                        rel_str,
                        SessionFileEntry {
                            valv_name,
                            mtime_secs: mtime,
                            size,
                        },
                    );
                }
            }
        }

        // Check for deletions
        let mut deleted = Vec::new();
        for (rel_path_str, item) in &session.files {
            let p = mount_dir.join(rel_path_str);
            if !p.exists() {
                let target_valv = vault_dir.join(&item.valv_name);
                let _ = fs::remove_file(&target_valv);

                // Also remove associated thumbnail file if present
                if let Some(thumb_name) = get_thumbnail_valv_name(&item.valv_name) {
                    let thumb_valv = vault_dir.join(&thumb_name);
                    let _ = fs::remove_file(thumb_valv);
                }

                if let Some(parent) = target_valv.parent() {
                    clean_empty_dirs_up_to(vault_dir, parent);
                }

                deleted.push(rel_path_str.clone());
            }
        }
        for d in deleted {
            session.files.remove(&d);
        }

        if let Ok(json) = serde_json::to_string(&session) {
            let _ = fs::write(&session_file, json);
        }

        thread::sleep(Duration::from_millis(500));
    }

    // Cleanup: preserve any unsynced subdirectories and remove mount directory
    preserve_unsynced_dirs(mount_dir, vault_dir);
    let _ = fs::remove_dir_all(mount_dir);
    Ok(())
}

pub fn unmount_vault(target_path: &Path) -> Result<(), ValvError> {
    let (mount_dir, daemon_pid, vault_dir) = if target_path.join(".valv_session.json").exists() {
        let session_file = target_path.join(".valv_session.json");
        let session = fs::read_to_string(&session_file)
            .ok()
            .and_then(|d| serde_json::from_str::<ValvSession>(&d).ok());
        let daemon_pid = session.as_ref().map(|s| s.daemon_pid);
        let vault_dir = session.map(|s| s.vault_dir);
        (target_path.to_path_buf(), daemon_pid, vault_dir)
    } else {
        let target_canon =
            fs::canonicalize(target_path).unwrap_or_else(|_| target_path.to_path_buf());
        let mounts = list_mounts();
        let matched = mounts.into_iter().find(|m| {
            let v_canon = fs::canonicalize(&m.vault_dir).unwrap_or_else(|_| m.vault_dir.clone());
            let m_canon = fs::canonicalize(&m.mount_dir).unwrap_or_else(|_| m.mount_dir.clone());
            v_canon == target_canon || m_canon == target_canon
        });

        if let Some(m) = matched {
            (m.mount_dir, Some(m.daemon_pid), Some(m.vault_dir))
        } else {
            return Err(ValvError::Message(
                format!("No active Valv mount found for {}", target_path.display()),
                1,
            ));
        }
    };

    let close_file = mount_dir.join(".valv_close");
    let _ = fs::write(&close_file, b"close");

    // Wait for daemon to clean up and exit cleanly
    for _ in 0..50 {
        if !mount_dir.exists() {
            println!("Unmounted: {}", mount_dir.display());
            return Ok(());
        }
        if let Some(pid) = daemon_pid
            && !is_process_alive(pid)
        {
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }

    if let Some(ref v_dir) = vault_dir {
        preserve_unsynced_dirs(&mount_dir, v_dir);
    }
    #[cfg(feature = "fuse")]
    {
        let _ = crate::vault::fuse_fs::fs::unmount_fuse_target(&mount_dir);
    }
    let _ = fs::remove_dir_all(&mount_dir);
    println!("Unmounted: {}", mount_dir.display());
    Ok(())
}
