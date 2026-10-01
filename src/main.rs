use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use valv::ValvError;
use valv::cli::{CliArgs, Mode, print_help, read_password};
use valv::crypto::{
    BUFFER_SIZE, Credentials, DEFAULT_ITERATIONS, DecryptError, EncryptionMethod, VaultFormat,
    decrypt_file_with_credentials_to, decrypt_header_with_credentials, encrypt_stream_unified,
    load_identities, load_recipients,
};
use valv::vault::{
    collect_plain_files, collect_vault_files, create_thumbnail_file_unified,
    generate_random_filename, get_mount_dir, get_suffix_for_path_and_format,
    get_thumbnail_valv_name, is_thumbnail_valv_file, is_valv_file, list_mounts,
    mount_vault_with_credentials, run_sync_daemon_with_credentials, sanitize_filename,
    unmount_vault,
};

fn resolve_output_path(
    output: Option<&Path>,
    default_dir: &Path,
    rel_parent: &Path,
    filename: &str,
    is_batch: bool,
) -> Result<PathBuf, ValvError> {
    if let Some(out) = output {
        let is_dir_target = out.is_dir()
            || out.to_string_lossy().ends_with('/')
            || out.to_string_lossy().ends_with('\\')
            || is_batch
            || !rel_parent.as_os_str().is_empty();

        if is_dir_target {
            let target_dir = out.join(rel_parent);
            fs::create_dir_all(&target_dir).map_err(|e| {
                ValvError::Message(
                    format!("Failed to create directory {}: {}", target_dir.display(), e),
                    1,
                )
            })?;
            Ok(target_dir.join(filename))
        } else {
            if let Some(parent) = out.parent()
                && !parent.as_os_str().is_empty()
            {
                let _ = fs::create_dir_all(parent);
            }
            Ok(out.to_path_buf())
        }
    } else {
        let target_dir = default_dir.join(rel_parent);
        if !rel_parent.as_os_str().is_empty() {
            let _ = fs::create_dir_all(&target_dir);
        }
        Ok(target_dir.join(filename))
    }
}

fn run_encrypt(cli: &CliArgs, files: &[PathBuf]) -> Result<(), ValvError> {
    if files.is_empty() {
        print_help();
        return Err(ValvError::Message(
            "No input files specified.".to_string(),
            1,
        ));
    }

    let recipients = load_recipients(&cli.recipients, &cli.recipients_files)
        .map_err(|e| ValvError::Message(e.to_string(), 1))?;

    let format = if !recipients.is_empty() || cli.age {
        VaultFormat::Age
    } else {
        VaultFormat::Valv
    };

    let mut password = if recipients.is_empty() {
        let pwd = read_password(cli)
            .map_err(|e| ValvError::Message(format!("Failed to read password: {}", e), 1))?
            .into_bytes();
        if pwd.is_empty() {
            return Err(ValvError::Message(
                "Password cannot be empty when encrypting without recipients.".to_string(),
                1,
            ));
        }
        Some(pwd)
    } else {
        None
    };

    let iterations = cli.iterations.unwrap_or(DEFAULT_ITERATIONS);

    let res = (|| -> Result<(), ValvError> {
        let mut items_to_encrypt: Vec<(PathBuf, PathBuf)> = Vec::new();
        for file_path in files {
            if !file_path.exists() {
                eprintln!("File not found: {}", file_path.display());
                continue;
            }
            if file_path.is_dir() {
                let plain_files = collect_plain_files(file_path);
                for pf in plain_files {
                    let rel = pf.strip_prefix(file_path).unwrap_or(&pf).to_path_buf();
                    items_to_encrypt.push((pf, rel));
                }
            } else {
                let name = file_path
                    .file_name()
                    .map(PathBuf::from)
                    .unwrap_or_else(|| PathBuf::from("file"));
                items_to_encrypt.push((file_path.clone(), name));
            }
        }

        let is_batch = items_to_encrypt.len() > 1;

        for (source_path, rel_sub_path) in &items_to_encrypt {
            let orig_filename = source_path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("file");

            let suffix = get_suffix_for_path_and_format(source_path, format);
            let dest_filename = generate_random_filename(suffix);
            let rel_parent = rel_sub_path.parent().unwrap_or_else(|| Path::new(""));

            let default_dir = source_path.parent().unwrap_or_else(|| Path::new("."));
            let dest_path = resolve_output_path(
                cli.output.as_deref(),
                default_dir,
                rel_parent,
                &dest_filename,
                is_batch,
            )?;

            if dest_path.exists() && !cli.force {
                eprintln!(
                    "Destination already exists, skipping: {} (use -f to overwrite)",
                    dest_path.display()
                );
                continue;
            }

            let method = if !recipients.is_empty() {
                EncryptionMethod::AgeRecipients(&recipients)
            } else if let Some(ref pwd) = password {
                if format == VaultFormat::Age {
                    let pwd_str = std::str::from_utf8(pwd).map_err(|_| {
                        ValvError::Message("Passphrase must be valid UTF-8 for age.".to_string(), 1)
                    })?;
                    EncryptionMethod::AgePassphrase(pwd_str)
                } else {
                    EncryptionMethod::ValvPassphrase {
                        password: pwd,
                        iterations,
                    }
                }
            } else {
                return Err(ValvError::Message(
                    "No encryption key or password provided.".to_string(),
                    1,
                ));
            };

            let mut in_file = BufReader::with_capacity(BUFFER_SIZE, File::open(source_path)?);
            let out_file = File::create(&dest_path)?;
            let mut out_writer = BufWriter::with_capacity(BUFFER_SIZE, out_file);

            if let Err(e) = encrypt_stream_unified(
                &mut in_file,
                &mut out_writer,
                orig_filename,
                &method,
            ) {
                let _ = fs::remove_file(&dest_path);
                return Err(ValvError::Message(
                    format!("Encryption failed for {}: {}", source_path.display(), e),
                    1,
                ));
            }

            println!(
                "Encrypted: {} -> {}",
                source_path.display(),
                dest_path.display()
            );

            if let Some(thumb_name) = get_thumbnail_valv_name(&dest_filename) {
                let thumb_parent = dest_path.parent().unwrap_or_else(|| Path::new("."));
                let thumb_path = thumb_parent.join(&thumb_name);

                if (!thumb_path.exists() || cli.force)
                    && let Ok(true) = create_thumbnail_file_unified(
                        source_path,
                        &thumb_path,
                        orig_filename,
                        &method,
                    )
                {
                    println!(
                        "Thumbnail: {} -> {}",
                        source_path.display(),
                        thumb_path.display()
                    );
                }
            }
        }
        Ok(())
    })();

    if let Some(ref mut pwd) = password {
        valv::crypto::zeroize(pwd);
    }
    res
}

fn run_decrypt(cli: &CliArgs, files: &[PathBuf]) -> Result<(), ValvError> {
    if files.is_empty() {
        print_help();
        return Err(ValvError::Message(
            "No input files specified.".to_string(),
            1,
        ));
    }

    let identities = load_identities(&cli.identities)
        .map_err(|e| ValvError::Message(e.to_string(), 1))?;

    let mut password = if identities.is_empty()
        || cli.password.is_some()
        || cli.stdin_password
    {
        let pwd = read_password(cli)
            .map_err(|e| ValvError::Message(format!("Failed to read password: {}", e), 1))?
            .into_bytes();
        Some(pwd)
    } else {
        None
    };

    let mut credentials = Credentials::new().with_identities(identities);
    if let Some(ref pwd) = password {
        credentials.password = Some(pwd.clone());
    }

    let res = (|| -> Result<(), ValvError> {
        let mut items_to_decrypt: Vec<(PathBuf, PathBuf)> = Vec::new();
        for file_path in files {
            if !file_path.exists() {
                eprintln!("File not found: {}", file_path.display());
                continue;
            }
            if file_path.is_dir() {
                let vault_files = collect_vault_files(file_path);
                for vf in vault_files {
                    let rel = vf.strip_prefix(file_path).unwrap_or(&vf).to_path_buf();
                    items_to_decrypt.push((vf, rel));
                }
            } else {
                let name = file_path
                    .file_name()
                    .map(PathBuf::from)
                    .unwrap_or_else(|| PathBuf::from("file"));
                items_to_decrypt.push((file_path.clone(), name));
            }
        }

        let is_batch = items_to_decrypt.len() > 1;

        for (file_path, rel_sub_path) in &items_to_decrypt {
            if is_batch
                && is_thumbnail_valv_file(file_path)
                && let Some(name_str) = file_path.file_name().and_then(|n| n.to_str())
                && let Some(prefix) = name_str
                    .strip_suffix("-t.valv")
                    .or_else(|| name_str.strip_suffix("-t.age"))
            {
                let has_companion = items_to_decrypt.iter().any(|(f, _)| {
                    f.file_name()
                        .and_then(|n| n.to_str())
                        .map(|n| n.starts_with(prefix) && n != name_str)
                        .unwrap_or(false)
                });
                if has_companion {
                    continue;
                }
            }

            if cli.to_stdout {
                let mut stdout = io::stdout().lock();
                if let Err(e) =
                    decrypt_file_with_credentials_to(file_path, &credentials, &mut stdout)
                {
                    if !is_batch {
                        return Err(match e {
                            DecryptError::InvalidPassword => ValvError::InvalidPassword,
                            other => ValvError::Message(
                                format!("Decryption failed for {}: {}", file_path.display(), other),
                                1,
                            ),
                        });
                    } else {
                        eprintln!("Warning: skipping {}: {}", file_path.display(), e);
                        continue;
                    }
                }
            } else {
                let file = match File::open(file_path) {
                    Ok(f) => f,
                    Err(e) => {
                        if is_batch {
                            eprintln!("Warning: skipping {}: {}", file_path.display(), e);
                            continue;
                        } else {
                            return Err(e.into());
                        }
                    }
                };
                let reader = BufReader::with_capacity(BUFFER_SIZE, file);

                let mut header = match decrypt_header_with_credentials(reader, &credentials) {
                    Ok(h) => h,
                    Err(e) => {
                        if !is_batch {
                            return Err(match e {
                                DecryptError::InvalidPassword => ValvError::InvalidPassword,
                                other => ValvError::Message(
                                    format!("Failed to read {}: {}", file_path.display(), other),
                                    1,
                                ),
                            });
                        } else {
                            eprintln!("Warning: skipping {}: {}", file_path.display(), e);
                            continue;
                        }
                    }
                };

                let orig_name = sanitize_filename(&header.original_name);
                let rel_parent = rel_sub_path.parent().unwrap_or_else(|| Path::new(""));

                let default_dir = file_path.parent().unwrap_or_else(|| Path::new("."));
                let dest_path = resolve_output_path(
                    cli.output.as_deref(),
                    default_dir,
                    rel_parent,
                    orig_name,
                    is_batch,
                )?;

                if dest_path.exists() && !cli.force {
                    eprintln!(
                        "Destination already exists, skipping: {} (use -f to overwrite)",
                        dest_path.display()
                    );
                    continue;
                }

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
                            if is_batch {
                                eprintln!("Warning: skipping {}: {}", dest_path.display(), e);
                                continue;
                            } else {
                                return Err(e.into());
                            }
                        }
                    }
                };
                #[cfg(not(unix))]
                let out_file = match File::create(&dest_path) {
                    Ok(f) => f,
                    Err(e) => {
                        if is_batch {
                            eprintln!("Warning: skipping {}: {}", dest_path.display(), e);
                            continue;
                        } else {
                            return Err(e.into());
                        }
                    }
                };

                let mut out_writer = BufWriter::with_capacity(BUFFER_SIZE, out_file);

                if let Err(e) = header.decrypt_payload(&mut out_writer) {
                    let _ = fs::remove_file(&dest_path);
                    if is_batch {
                        eprintln!(
                            "Warning: failed decrypting payload {}: {}",
                            file_path.display(),
                            e
                        );
                        continue;
                    } else {
                        return Err(ValvError::Message(
                            format!("Write error for {}: {}", dest_path.display(), e),
                            1,
                        ));
                    }
                }

                println!(
                    "Decrypted: {} -> {}",
                    file_path.display(),
                    dest_path.display()
                );
            }
        }
        Ok(())
    })();

    if let Some(ref mut pwd) = password {
        valv::crypto::zeroize(pwd);
    }
    if let Some(ref mut pwd) = credentials.password {
        valv::crypto::zeroize(pwd);
    }
    res
}

fn run() -> Result<(), ValvError> {
    let cli = CliArgs::parse();
    let (mode, files) = cli.resolve_mode_and_files(is_valv_file);

    match mode {
        Mode::Mount => {
            let vault_dir = files.first().cloned().unwrap_or_else(|| PathBuf::from("."));
            if !vault_dir.is_dir() {
                return Err(ValvError::Message(
                    format!("Not a directory: {}", vault_dir.display()),
                    1,
                ));
            }

            let identities = load_identities(&cli.identities)
                .map_err(|e| ValvError::Message(e.to_string(), 1))?;
            let recipients = load_recipients(&cli.recipients, &cli.recipients_files)
                .map_err(|e| ValvError::Message(e.to_string(), 1))?;

            let mut password = if identities.is_empty()
                || cli.password.is_some()
                || cli.stdin_password
            {
                let pwd = read_password(&cli)
                    .map_err(|e| ValvError::Message(format!("Failed to read password: {}", e), 1))?
                    .into_bytes();
                if pwd.is_empty() && identities.is_empty() {
                    return Err(ValvError::Message(
                        "Password or identity required to mount vault.".to_string(),
                        1,
                    ));
                }
                Some(pwd)
            } else {
                None
            };

            let mut credentials = Credentials::new().with_identities(identities);
            if let Some(ref pwd) = password {
                credentials.password = Some(pwd.clone());
            }

            let watch_pid = if cli.no_watch {
                None
            } else {
                cli.watch_pid.or_else(|| {
                    #[cfg(unix)]
                    {
                        Some(std::os::unix::process::parent_id())
                    }
                    #[cfg(not(unix))]
                    {
                        None
                    }
                })
            };
            let mount_dir = get_mount_dir(&vault_dir, watch_pid, cli.output.as_deref());
            let iterations = cli.iterations.unwrap_or(DEFAULT_ITERATIONS);
            let format = if cli.age || !recipients.is_empty() {
                VaultFormat::Age
            } else {
                VaultFormat::Valv
            };

            let res = mount_vault_with_credentials(
                &vault_dir,
                &mount_dir,
                &credentials,
                watch_pid,
                cli.foreground,
                iterations,
                format,
                &recipients,
                &cli.identities,
                &cli.recipients,
            );
            if let Some(ref mut pwd) = password {
                valv::crypto::zeroize(pwd);
            }
            if let Some(ref mut pwd) = credentials.password {
                valv::crypto::zeroize(pwd);
            }
            res?;
        }
        Mode::Unmount => {
            let target = files.first().cloned().unwrap_or_else(|| PathBuf::from("."));
            unmount_vault(&target)?;
        }
        Mode::Mounts => {
            let mounts = list_mounts();
            if mounts.is_empty() {
                println!("No active Valv mounts found.");
            } else {
                for m in mounts {
                    let watch_info = match m.watch_pid {
                        Some(w) => format!("daemon PID: {}, watch PID: {}", m.daemon_pid, w),
                        None => format!("daemon PID: {}", m.daemon_pid),
                    };
                    println!(
                        "{} -> {} ({} files, {})",
                        m.mount_dir.display(),
                        m.vault_dir.display(),
                        m.file_count,
                        watch_info
                    );
                }
            }
        }
        Mode::SyncDaemon => {
            if files.len() < 2 {
                return Err(ValvError::Message(
                    "sync-daemon requires <vault_dir> <mount_dir>".to_string(),
                    1,
                ));
            }
            let vault_dir = &files[0];
            let mount_dir = &files[1];

            let identities = load_identities(&cli.identities)
                .map_err(|e| ValvError::Message(e.to_string(), 1))?;
            let recipients = load_recipients(&cli.recipients, &cli.recipients_files)
                .map_err(|e| ValvError::Message(e.to_string(), 1))?;

            let mut password_str = String::new();
            let _ = io::stdin().read_line(&mut password_str);
            let mut password = password_str
                .trim_end_matches(&['\r', '\n'][..])
                .as_bytes()
                .to_vec();
            valv::crypto::zeroize(unsafe { password_str.as_bytes_mut() });

            let mut credentials = Credentials::new().with_identities(identities);
            if !password.is_empty() {
                credentials.password = Some(password.clone());
            }

            let iterations = cli.iterations.unwrap_or(DEFAULT_ITERATIONS);
            let format = if cli.age || !recipients.is_empty() {
                VaultFormat::Age
            } else {
                VaultFormat::Valv
            };

            let res = run_sync_daemon_with_credentials(
                vault_dir,
                mount_dir,
                &credentials,
                cli.watch_pid,
                iterations,
                format,
                &recipients,
            );
            valv::crypto::zeroize(&mut password);
            if let Some(ref mut pwd) = credentials.password {
                valv::crypto::zeroize(pwd);
            }
            res?;
        }
        Mode::Encrypt => run_encrypt(&cli, &files)?,
        Mode::Decrypt => run_decrypt(&cli, &files)?,
    }

    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("Error: {}", e);
            ExitCode::from(e.exit_code())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use age::secrecy::ExposeSecret;
    use clap::Parser;

    #[test]
    fn test_resolve_output_path_single_file() {
        let default_dir = Path::new("/tmp");
        let path = resolve_output_path(None, default_dir, Path::new(""), "foo.txt", false).unwrap();
        assert_eq!(path, PathBuf::from("/tmp/foo.txt"));
    }

    #[test]
    fn test_resolve_output_path_custom_dir() {
        let temp_dir =
            std::env::temp_dir().join(format!("valv_out_test_{}", rand::random::<u32>()));
        let default_dir = Path::new("/tmp");
        let path =
            resolve_output_path(Some(&temp_dir), default_dir, Path::new(""), "foo.txt", true)
                .unwrap();
        assert_eq!(path, temp_dir.join("foo.txt"));
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[cfg(unix)]
    #[test]
    fn test_decrypted_file_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let temp_dir =
            std::env::temp_dir().join(format!("valv_perm_test_{}", rand::random::<u32>()));
        fs::create_dir_all(&temp_dir).unwrap();

        let src_file = temp_dir.join("secret.txt");
        fs::write(&src_file, b"super confidential").unwrap();

        let enc_file = temp_dir.join("secret-x.valv");
        let password = b"StrongPassword123";
        valv::crypto::encrypt_file(&src_file, &enc_file, password, "secret.txt", 1000).unwrap();

        let dec_file = temp_dir.join("decrypted.txt");
        valv::crypto::decrypt_file(&enc_file, &dec_file, password).unwrap();

        let meta = fs::metadata(&dec_file).unwrap();
        let permissions = meta.permissions();
        assert_eq!(permissions.mode() & 0o777, 0o600);

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_age_encrypt_decrypt_cli_roundtrip() {
        let temp_dir =
            std::env::temp_dir().join(format!("valv_age_cli_test_{}", rand::random::<u32>()));
        fs::create_dir_all(&temp_dir).unwrap();

        let src_file = temp_dir.join("cli_secret.txt");
        fs::write(&src_file, b"secret text content").unwrap();

        let key = age::x25519::Identity::generate();
        let pubkey = key.to_public().to_string();
        let key_file = temp_dir.join("key.txt");
        fs::write(&key_file, key.to_string().expose_secret().as_bytes()).unwrap();

        let enc_args = vec![
            "valv",
            "encrypt",
            "-r",
            &pubkey,
            "-o",
            temp_dir.to_str().unwrap(),
            src_file.to_str().unwrap(),
        ];
        let cli_enc = CliArgs::try_parse_from(enc_args).unwrap();
        let (mode, files) = cli_enc.resolve_mode_and_files(is_valv_file);
        assert_eq!(mode, Mode::Encrypt);
        run_encrypt(&cli_enc, &files).expect("CLI encrypt with age pubkey should succeed");

        // Find created encrypted file
        let mut enc_files = Vec::new();
        for entry in fs::read_dir(&temp_dir).unwrap().flatten() {
            let p = entry.path();
            if is_valv_file(&p) && !is_thumbnail_valv_file(&p) {
                enc_files.push(p);
            }
        }
        assert_eq!(enc_files.len(), 1);
        let enc_file = &enc_files[0];
        assert!(enc_file.to_string_lossy().ends_with(".age"));

        // Decrypt using key file
        let dec_dir = temp_dir.join("decrypted");
        fs::create_dir_all(&dec_dir).unwrap();
        let dec_args = vec![
            "valv",
            "decrypt",
            "-k",
            key_file.to_str().unwrap(),
            "-o",
            dec_dir.to_str().unwrap(),
            enc_file.to_str().unwrap(),
        ];
        let cli_dec = CliArgs::try_parse_from(dec_args).unwrap();
        let (mode_dec, files_dec) = cli_dec.resolve_mode_and_files(is_valv_file);
        assert_eq!(mode_dec, Mode::Decrypt);
        run_decrypt(&cli_dec, &files_dec).expect("CLI decrypt with age key should succeed");

        let decrypted_content = fs::read_to_string(dec_dir.join("cli_secret.txt")).unwrap();
        assert_eq!(decrypted_content, "secret text content");

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_cli_directory_encrypt_decrypt_roundtrip() {
        let temp_dir =
            std::env::temp_dir().join(format!("valv_dir_cli_test_{}", rand::random::<u32>()));
        fs::create_dir_all(&temp_dir).unwrap();

        let src_dir = temp_dir.join("source");
        let nested_dir = src_dir.join("nested").join("deep");
        fs::create_dir_all(&nested_dir).unwrap();

        fs::write(src_dir.join("root.txt"), b"root content").unwrap();
        fs::write(nested_dir.join("deep.txt"), b"deep content").unwrap();

        let vault_dir = temp_dir.join("vault");
        let enc_args = vec![
            "valv",
            "encrypt",
            "-p",
            "DirPassword123",
            "--age",
            "-o",
            vault_dir.to_str().unwrap(),
            src_dir.to_str().unwrap(),
        ];
        let cli_enc = CliArgs::try_parse_from(enc_args).unwrap();
        let (mode, files) = cli_enc.resolve_mode_and_files(is_valv_file);
        assert_eq!(mode, Mode::Encrypt);
        run_encrypt(&cli_enc, &files).expect("Encrypting directory should succeed");

        let vault_files = collect_vault_files(&vault_dir);
        assert_eq!(vault_files.len(), 2);

        let dec_dir = temp_dir.join("decrypted");
        let dec_args = vec![
            "valv",
            "decrypt",
            "-p",
            "DirPassword123",
            "-o",
            dec_dir.to_str().unwrap(),
            vault_dir.to_str().unwrap(),
        ];
        let cli_dec = CliArgs::try_parse_from(dec_args).unwrap();
        let (mode_dec, files_dec) = cli_dec.resolve_mode_and_files(is_valv_file);
        assert_eq!(mode_dec, Mode::Decrypt);
        run_decrypt(&cli_dec, &files_dec).expect("Decrypting directory should succeed");

        assert_eq!(
            fs::read_to_string(dec_dir.join("root.txt")).unwrap(),
            "root content"
        );
        assert_eq!(
            fs::read_to_string(dec_dir.join("nested").join("deep").join("deep.txt")).unwrap(),
            "deep content"
        );

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_cli_directory_decrypt_partial_failure_skips_corrupt() {
        let temp_dir =
            std::env::temp_dir().join(format!("valv_partial_test_{}", rand::random::<u32>()));
        fs::create_dir_all(&temp_dir).unwrap();

        let src_dir = temp_dir.join("source");
        let nested_dir = src_dir.join("nested");
        fs::create_dir_all(&nested_dir).unwrap();

        fs::write(src_dir.join("valid1.txt"), b"valid 1").unwrap();
        fs::write(nested_dir.join("valid2.txt"), b"valid 2").unwrap();

        let vault_dir = temp_dir.join("vault");
        let enc_args = vec![
            "valv",
            "encrypt",
            "-p",
            "TestPass123",
            "-o",
            vault_dir.to_str().unwrap(),
            src_dir.to_str().unwrap(),
        ];
        let cli_enc = CliArgs::try_parse_from(enc_args).unwrap();
        let (_mode, files) = cli_enc.resolve_mode_and_files(is_valv_file);
        run_encrypt(&cli_enc, &files).unwrap();

        // Inject corrupt .valv file
        let corrupt_dir = vault_dir.join("nested");
        fs::write(corrupt_dir.join("corrupt-x.valv"), b"GARBAGE_HEADER_DATA").unwrap();

        let dec_dir = temp_dir.join("decrypted");
        let dec_args = vec![
            "valv",
            "decrypt",
            "-p",
            "TestPass123",
            "-o",
            dec_dir.to_str().unwrap(),
            vault_dir.to_str().unwrap(),
        ];
        let cli_dec = CliArgs::try_parse_from(dec_args).unwrap();
        let (_mode_dec, files_dec) = cli_dec.resolve_mode_and_files(is_valv_file);
        // Decrypt should skip corrupt file gracefully and not fail overall
        run_decrypt(&cli_dec, &files_dec).expect("Directory decrypt with corrupt file should succeed for valid files");

        assert_eq!(
            fs::read_to_string(dec_dir.join("valid1.txt")).unwrap(),
            "valid 1"
        );
        assert_eq!(
            fs::read_to_string(dec_dir.join("nested").join("valid2.txt")).unwrap(),
            "valid 2"
        );

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
