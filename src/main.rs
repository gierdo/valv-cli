use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use valv::ValvError;
use valv::cli::{CliArgs, Mode, print_help, read_password};
use valv::crypto::{
    BUFFER_SIZE, DEFAULT_ITERATIONS, DecryptError, decrypt_file_to, decrypt_header, encrypt_stream,
};
use valv::vault::{
    create_thumbnail_file, generate_random_filename, get_mount_dir, get_suffix_for_path,
    get_thumbnail_valv_name, is_thumbnail_valv_file, is_valv_file, list_mounts, mount_vault,
    run_sync_daemon, unmount_vault,
};

fn resolve_output_path(
    output: Option<&Path>,
    default_dir: &Path,
    filename: &str,
    multiple_inputs: bool,
) -> Result<PathBuf, ValvError> {
    if let Some(out) = output {
        let is_dir_target = out.is_dir()
            || out.to_string_lossy().ends_with('/')
            || out.to_string_lossy().ends_with('\\')
            || multiple_inputs;

        if is_dir_target {
            fs::create_dir_all(out).map_err(|e| {
                ValvError::Message(
                    format!("Failed to create directory {}: {}", out.display(), e),
                    1,
                )
            })?;
            Ok(out.join(filename))
        } else {
            if let Some(parent) = out.parent()
                && !parent.as_os_str().is_empty()
            {
                let _ = fs::create_dir_all(parent);
            }
            Ok(out.to_path_buf())
        }
    } else {
        Ok(default_dir.join(filename))
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

    let password = read_password(cli)
        .map_err(|e| ValvError::Message(format!("Failed to read password: {}", e), 1))?;
    if password.is_empty() {
        return Err(ValvError::Message(
            "Password cannot be empty.".to_string(),
            1,
        ));
    }
    let password_bytes = password.as_bytes();
    let iterations = cli.iterations.unwrap_or(DEFAULT_ITERATIONS);

    for file_path in files {
        if !file_path.exists() {
            eprintln!("File not found: {}", file_path.display());
            continue;
        }

        let orig_filename = file_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("file");

        let suffix = get_suffix_for_path(file_path);
        let dest_filename = generate_random_filename(suffix);
        let default_dir = file_path.parent().unwrap_or_else(|| Path::new("."));
        let dest_path = resolve_output_path(
            cli.output.as_deref(),
            default_dir,
            &dest_filename,
            files.len() > 1,
        )?;

        if dest_path.exists() && !cli.force {
            eprintln!(
                "Destination already exists, skipping: {} (use -f to overwrite)",
                dest_path.display()
            );
            continue;
        }

        // simplification: write directly with cleanup on failure
        let mut in_file = BufReader::with_capacity(BUFFER_SIZE, File::open(file_path)?);
        let out_file = File::create(&dest_path)?;
        let mut out_writer = BufWriter::with_capacity(BUFFER_SIZE, out_file);

        if let Err(e) = encrypt_stream(
            &mut in_file,
            &mut out_writer,
            password_bytes,
            orig_filename,
            iterations,
        ) {
            let _ = fs::remove_file(&dest_path);
            return Err(ValvError::Message(
                format!("Encryption failed for {}: {}", file_path.display(), e),
                1,
            ));
        }

        println!(
            "Encrypted: {} -> {}",
            file_path.display(),
            dest_path.display()
        );

        if let Some(thumb_name) = get_thumbnail_valv_name(&dest_filename) {
            let thumb_path = if let Some(out) = cli.output.as_deref() {
                if out.is_dir() || files.len() > 1 {
                    out.join(&thumb_name)
                } else {
                    let parent = out.parent().unwrap_or_else(|| Path::new("."));
                    parent.join(&thumb_name)
                }
            } else {
                default_dir.join(&thumb_name)
            };

            if (!thumb_path.exists() || cli.force)
                && let Ok(true) = create_thumbnail_file(
                    file_path,
                    &thumb_path,
                    password_bytes,
                    orig_filename,
                    iterations,
                )
            {
                println!(
                    "Thumbnail: {} -> {}",
                    file_path.display(),
                    thumb_path.display()
                );
            }
        }
    }

    Ok(())
}

fn run_decrypt(cli: &CliArgs, files: &[PathBuf]) -> Result<(), ValvError> {
    if files.is_empty() {
        print_help();
        return Err(ValvError::Message(
            "No input files specified.".to_string(),
            1,
        ));
    }

    let password = read_password(cli)
        .map_err(|e| ValvError::Message(format!("Failed to read password: {}", e), 1))?;
    if password.is_empty() {
        return Err(ValvError::Message(
            "Password cannot be empty.".to_string(),
            1,
        ));
    }
    let password_bytes = password.as_bytes();

    for file_path in files {
        if !file_path.exists() {
            eprintln!("File not found: {}", file_path.display());
            continue;
        }

        if files.len() > 1
            && is_thumbnail_valv_file(file_path)
            && let Some(name_str) = file_path.file_name().and_then(|n| n.to_str())
            && let Some(prefix) = name_str.strip_suffix("-t.valv")
        {
            let has_companion = files.iter().any(|f| {
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
            if let Err(e) = decrypt_file_to(file_path, password_bytes, &mut stdout) {
                return Err(match e {
                    DecryptError::InvalidPassword => ValvError::InvalidPassword,
                    other => ValvError::Message(
                        format!("Decryption failed for {}: {}", file_path.display(), other),
                        1,
                    ),
                });
            }
        } else {
            let file = File::open(file_path)?;
            let mut reader = BufReader::with_capacity(BUFFER_SIZE, file);
            let is_v1_hint = file_path
                .file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.starts_with(".valv."))
                .unwrap_or(false);

            let mut header = match decrypt_header(&mut reader, password_bytes, is_v1_hint) {
                Ok(h) => h,
                Err(DecryptError::InvalidPassword) => return Err(ValvError::InvalidPassword),
                Err(e) => {
                    return Err(ValvError::Message(
                        format!("Failed to read {}: {}", file_path.display(), e),
                        1,
                    ));
                }
            };

            let orig_name = if header.original_name.is_empty() {
                "decrypted_file"
            } else {
                header.original_name.as_str()
            };

            let default_dir = file_path.parent().unwrap_or_else(|| Path::new("."));
            let dest_path = resolve_output_path(
                cli.output.as_deref(),
                default_dir,
                orig_name,
                files.len() > 1,
            )?;

            if dest_path.exists() && !cli.force {
                eprintln!(
                    "Destination already exists, skipping: {} (use -f to overwrite)",
                    dest_path.display()
                );
                continue;
            }

            let out_file = File::create(&dest_path)?;
            let mut out_writer = BufWriter::with_capacity(BUFFER_SIZE, out_file);

            if let Err(e) = header.decrypt_payload(&mut reader, &mut out_writer) {
                let _ = fs::remove_file(&dest_path);
                return Err(ValvError::Message(
                    format!("Write error for {}: {}", dest_path.display(), e),
                    1,
                ));
            }

            println!(
                "Decrypted: {} -> {}",
                file_path.display(),
                dest_path.display()
            );
        }
    }

    Ok(())
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

            let password = read_password(&cli)
                .map_err(|e| ValvError::Message(format!("Failed to read password: {}", e), 1))?;
            if password.is_empty() {
                return Err(ValvError::Message(
                    "Password cannot be empty.".to_string(),
                    1,
                ));
            }

            let watch_pid = cli
                .watch_pid
                .unwrap_or_else(std::os::unix::process::parent_id);
            let mount_dir = get_mount_dir(&vault_dir, watch_pid, cli.output.as_deref());
            let iterations = cli.iterations.unwrap_or(DEFAULT_ITERATIONS);

            mount_vault(
                &vault_dir,
                &mount_dir,
                password.as_bytes(),
                watch_pid,
                cli.foreground,
                iterations,
            )?;
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
            let watch_pid = cli
                .watch_pid
                .ok_or_else(|| ValvError::Message("Missing --watch-pid".to_string(), 1))?;

            let mut password = String::new();
            io::stdin().read_line(&mut password)?;
            let password = password.trim_end_matches(&['\r', '\n'][..]);
            let iterations = cli.iterations.unwrap_or(DEFAULT_ITERATIONS);

            run_sync_daemon(
                vault_dir,
                mount_dir,
                password.as_bytes(),
                watch_pid,
                iterations,
            )?;
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

    #[test]
    fn test_resolve_output_path_single_file() {
        let default_dir = Path::new("/tmp");
        let path = resolve_output_path(None, default_dir, "foo.txt", false).unwrap();
        assert_eq!(path, PathBuf::from("/tmp/foo.txt"));
    }

    #[test]
    fn test_resolve_output_path_custom_dir() {
        let temp_dir =
            std::env::temp_dir().join(format!("valv_out_test_{}", rand::random::<u32>()));
        let default_dir = Path::new("/tmp");
        let path = resolve_output_path(Some(&temp_dir), default_dir, "foo.txt", true).unwrap();
        assert_eq!(path, temp_dir.join("foo.txt"));
        let _ = fs::remove_dir_all(&temp_dir);
    }
}
