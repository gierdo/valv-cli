use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter, Cursor, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::{Duration, UNIX_EPOCH};

use rand::RngExt;
use serde::{Deserialize, Serialize};

use crate::crypto::{BUFFER_SIZE, DecryptError, decrypt_header, encrypt_stream};

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct ValvSession {
    pub vault_dir: PathBuf,
    pub watch_pid: Option<u32>,
    pub daemon_pid: u32,
    pub files: HashMap<String, SessionFileEntry>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SessionFileEntry {
    pub valv_name: String,
    pub mtime_secs: u64,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveMount {
    pub mount_dir: PathBuf,
    pub vault_dir: PathBuf,
    pub daemon_pid: u32,
    pub watch_pid: Option<u32>,
    pub file_count: usize,
}

pub fn is_valv_file(path: &Path) -> bool {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    name.ends_with(".valv") || name.starts_with(".valv.")
}

pub fn is_thumbnail_valv_file(path: &Path) -> bool {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    name.ends_with("-t.valv")
}

pub fn get_thumbnail_valv_name(valv_name: &str) -> Option<String> {
    let prefix = valv_name
        .strip_suffix("-i.valv")
        .or_else(|| valv_name.strip_suffix("-g.valv"))
        .or_else(|| valv_name.strip_suffix("-v.valv"))?;
    Some(format!("{}-t.valv", prefix))
}

// simplification: calls ffmpeg (primary) or imagemagick (fallback) to generate a 512x512
// center-cropped JPEG thumbnail. Ceiling: requires system ffmpeg or convert; upgrade path:
// embed pure Rust decoders if external tools cannot be assumed.
pub fn generate_thumbnail(path: &Path) -> Option<Vec<u8>> {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase())
        .unwrap_or_default();

    let is_media = matches!(
        ext.as_str(),
        "jpg"
            | "jpeg"
            | "png"
            | "webp"
            | "bmp"
            | "gif"
            | "svg"
            | "heic"
            | "heif"
            | "avif"
            | "ico"
            | "mp4"
            | "mkv"
            | "mov"
            | "avi"
            | "webm"
            | "flv"
            | "3gp"
            | "wmv"
            | "m4v"
    );
    if !is_media {
        return None;
    }

    if let Ok(out) = Command::new("ffmpeg")
        .args(["-y", "-loglevel", "error", "-ss", "00:00:00", "-i"])
        .arg(path)
        .args([
            "-frames:v",
            "1",
            "-vf",
            "scale=512:512:force_original_aspect_ratio=increase,crop=512:512",
            "-q:v",
            "5",
            "-f",
            "image2",
            "pipe:1",
        ])
        .output()
        && out.status.success()
        && !out.stdout.is_empty()
    {
        return Some(out.stdout);
    }

    for cmd in &["magick", "convert"] {
        if let Ok(out) = Command::new(cmd)
            .arg(format!("{}[0]", path.display()))
            .args([
                "-auto-orient",
                "-resize",
                "512x512^",
                "-gravity",
                "center",
                "-extent",
                "512x512",
                "-quality",
                "75",
                "jpeg:-",
            ])
            .output()
            && out.status.success()
            && !out.stdout.is_empty()
        {
            return Some(out.stdout);
        }
    }

    None
}

pub fn create_thumbnail_file(
    source_file: &Path,
    thumb_valv_path: &Path,
    password_bytes: &[u8],
    orig_filename: &str,
    iterations: u32,
) -> io::Result<bool> {
    if let Some(thumb_bytes) = generate_thumbnail(source_file) {
        let mut reader = Cursor::new(thumb_bytes);
        let out_file = File::create(thumb_valv_path)?;
        let mut writer = BufWriter::new(out_file);
        encrypt_stream(
            &mut reader,
            &mut writer,
            password_bytes,
            orig_filename,
            iterations,
        )?;
        Ok(true)
    } else {
        Ok(false)
    }
}

pub fn get_suffix_for_path(path: &Path) -> &'static str {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase())
        .unwrap_or_default();

    match ext.as_str() {
        "gif" => "-g.valv",
        "jpg" | "jpeg" | "png" | "webp" | "bmp" | "svg" | "heic" | "heif" | "avif" | "ico" => {
            "-i.valv"
        }
        "mp4" | "mkv" | "mov" | "avi" | "webm" | "flv" | "3gp" | "wmv" | "m4v" => "-v.valv",
        "txt" | "md" | "json" | "csv" | "xml" | "log" | "pdf" | "html" | "css" | "js" | "py"
        | "rs" => "-x.valv",
        _ => "-i.valv",
    }
}

pub fn generate_random_filename(suffix: &str) -> String {
    const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut rng = rand::rng();
    let prefix: String = (0..32)
        .map(|_| {
            let idx = rng.random_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect();
    format!("{}{}", prefix, suffix)
}

pub fn get_mount_dir(vault_dir: &Path, watch_pid: u32, custom_output: Option<&Path>) -> PathBuf {
    if let Some(out) = custom_output {
        return out.to_path_buf();
    }
    let uid = unsafe { libc::getuid() };
    let shm = Path::new("/dev/shm");
    let base = if shm.exists() {
        shm.to_path_buf()
    } else {
        std::env::temp_dir()
    };
    let vault_name = vault_dir
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("vault");
    base.join(format!("valv-{}/{}-{}", uid, vault_name, watch_pid))
}

pub fn list_mounts() -> Vec<ActiveMount> {
    let uid = unsafe { libc::getuid() };
    let shm = Path::new("/dev/shm");
    let base = if shm.exists() {
        shm.to_path_buf()
    } else {
        std::env::temp_dir()
    };
    let user_mount_base = base.join(format!("valv-{}", uid));
    let mut mounts = Vec::new();

    if let Ok(entries) = fs::read_dir(user_mount_base) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                let session_file = path.join(".valv_session.json");
                if let Ok(data) = fs::read_to_string(&session_file)
                    && let Ok(session) = serde_json::from_str::<ValvSession>(&data)
                {
                    mounts.push(ActiveMount {
                        mount_dir: path,
                        vault_dir: session.vault_dir,
                        daemon_pid: session.daemon_pid,
                        watch_pid: session.watch_pid,
                        file_count: session.files.len(),
                    });
                }
            }
        }
    }
    mounts
}

pub fn mount_vault(
    vault_dir: &Path,
    mount_dir: &Path,
    password_bytes: &[u8],
    watch_pid: u32,
    foreground: bool,
    iterations: u32,
) -> Result<(), (String, u8)> {
    let entries = fs::read_dir(vault_dir).map_err(|e| {
        (
            format!("Cannot read vault directory {}: {}", vault_dir.display(), e),
            1,
        )
    })?;

    let mut valv_files = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        // Ignore thumbnail (-t.valv) files so real files are mounted instead of previews
        if path.is_file() && is_valv_file(&path) && !is_thumbnail_valv_file(&path) {
            valv_files.push(path);
        }
    }

    // Verify password on first file if any exist
    if let Some(first_file) = valv_files.first() {
        let f = File::open(first_file).map_err(|e| (e.to_string(), 1))?;
        let mut r = BufReader::new(f);
        let is_v1 = first_file
            .file_name()
            .and_then(|n| n.to_str())
            .map(|n| n.starts_with(".valv."))
            .unwrap_or(false);
        if let Err(DecryptError::InvalidPassword) = decrypt_header(&mut r, password_bytes, is_v1) {
            return Err(("Incorrect password for vault".to_string(), 2));
        }
    }

    fs::create_dir_all(mount_dir).map_err(|e| {
        (
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

    let mut session = ValvSession {
        vault_dir: fs::canonicalize(vault_dir).unwrap_or_else(|_| vault_dir.to_path_buf()),
        watch_pid: Some(watch_pid),
        daemon_pid: std::process::id(),
        files: HashMap::new(),
    };

    // Decrypt all existing files into mount_dir via streaming
    for valv_path in &valv_files {
        let valv_name = valv_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
            .to_string();

        let in_file = match File::open(valv_path) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("Warning: skipping {}: {}", valv_path.display(), e);
                continue;
            }
        };
        let mut reader = BufReader::with_capacity(BUFFER_SIZE, in_file);
        let is_v1 = valv_path
            .file_name()
            .and_then(|n| n.to_str())
            .map(|n| n.starts_with(".valv."))
            .unwrap_or(false);

        let mut header = match decrypt_header(&mut reader, password_bytes, is_v1) {
            Ok(h) => h,
            Err(DecryptError::InvalidPassword) => {
                let _ = fs::remove_dir_all(mount_dir);
                return Err(("Incorrect password for vault".to_string(), 2));
            }
            Err(e) => {
                eprintln!("Warning: skipping {}: {}", valv_path.display(), e);
                continue;
            }
        };

        let orig_name = if header.original_name.is_empty() {
            "decrypted_file".to_string()
        } else {
            header.original_name.clone()
        };

        let dest_path = mount_dir.join(&orig_name);
        let out_file = match File::create(&dest_path) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("Warning: skipping {}: {}", dest_path.display(), e);
                continue;
            }
        };
        let mut writer = BufWriter::with_capacity(BUFFER_SIZE, out_file);

        if let Err(e) = header.decrypt_payload(&mut reader, &mut writer) {
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
            orig_name.clone(),
            SessionFileEntry {
                valv_name: valv_name.clone(),
                mtime_secs: mtime,
                size,
            },
        );

        if let Some(thumb_name) = get_thumbnail_valv_name(&valv_name) {
            let thumb_valv = vault_dir.join(&thumb_name);
            if !thumb_valv.exists() {
                let _ = create_thumbnail_file(
                    &dest_path,
                    &thumb_valv,
                    password_bytes,
                    &orig_name,
                    iterations,
                );
            }
        }
    }

    let session_json = serde_json::to_string(&session)
        .map_err(|e| (format!("Session serialization failed: {}", e), 1))?;
    fs::write(mount_dir.join(".valv_session.json"), session_json)
        .map_err(|e| (format!("Failed to write session file: {}", e), 1))?;

    if foreground {
        println!("READY {}", mount_dir.display());
        run_sync_daemon(
            &session.vault_dir,
            mount_dir,
            password_bytes,
            watch_pid,
            iterations,
        )?;
    } else {
        let current_exe = std::env::current_exe()
            .map_err(|e| (format!("Failed to determine binary path: {}", e), 1))?;

        let mut child = std::process::Command::new(current_exe)
            .arg("sync-daemon")
            .arg(&session.vault_dir)
            .arg(mount_dir)
            .arg("--watch-pid")
            .arg(watch_pid.to_string())
            .arg("-i")
            .arg(iterations.to_string())
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map_err(|e| (format!("Failed to spawn background daemon: {}", e), 1))?;

        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(password_bytes);
            let _ = stdin.write_all(b"\n");
        }

        println!("READY {}", mount_dir.display());
    }

    Ok(())
}

pub fn run_sync_daemon(
    vault_dir: &Path,
    mount_dir: &Path,
    password_bytes: &[u8],
    watch_pid: u32,
    iterations: u32,
) -> Result<(), (String, u8)> {
    let session_file = mount_dir.join(".valv_session.json");
    let mut session: ValvSession = if session_file.exists() {
        let data = fs::read_to_string(&session_file).unwrap_or_default();
        serde_json::from_str(&data).unwrap_or_default()
    } else {
        ValvSession::default()
    };
    session.vault_dir = vault_dir.to_path_buf();
    session.daemon_pid = std::process::id();

    let close_trigger = mount_dir.join(".valv_close");

    loop {
        // 1. Check if watched process (e.g. Yazi) is still running
        if !Path::new(&format!("/proc/{}", watch_pid)).exists() {
            break;
        }

        // 2. Check if close/unmount requested
        if close_trigger.exists() {
            break;
        }

        // 3. Scan mount_dir for changes
        if let Ok(entries) = fs::read_dir(mount_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if filename.starts_with('.') || !path.is_file() {
                    continue;
                }

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

                if let Some(item) = session.files.get_mut(filename) {
                    if item.mtime_secs != mtime || item.size != size {
                        // File modified: re-encrypt to same valv_name
                        let target_valv = vault_dir.join(&item.valv_name);
                        if let Ok(mut in_file) = File::open(&path)
                            && let Ok(out_file) = File::create(&target_valv)
                        {
                            let mut writer = BufWriter::new(out_file);
                            if encrypt_stream(
                                &mut in_file,
                                &mut writer,
                                password_bytes,
                                filename,
                                iterations,
                            )
                            .is_ok()
                            {
                                item.mtime_secs = mtime;
                                item.size = size;

                                if let Some(thumb_name) = get_thumbnail_valv_name(&item.valv_name) {
                                    let thumb_valv = vault_dir.join(&thumb_name);
                                    if let Ok(true) = create_thumbnail_file(
                                        &path,
                                        &thumb_valv,
                                        password_bytes,
                                        filename,
                                        iterations,
                                    ) {
                                        // Thumbnail updated
                                    } else {
                                        let _ = fs::remove_file(thumb_valv);
                                    }
                                }
                            }
                        }
                    }
                } else {
                    // New file added: encrypt to new valv file
                    let suffix = get_suffix_for_path(&path);
                    let new_valv_name = generate_random_filename(suffix);
                    let target_valv = vault_dir.join(&new_valv_name);
                    if let Ok(mut in_file) = File::open(&path)
                        && let Ok(out_file) = File::create(&target_valv)
                    {
                        let mut writer = BufWriter::new(out_file);
                        if encrypt_stream(
                            &mut in_file,
                            &mut writer,
                            password_bytes,
                            filename,
                            iterations,
                        )
                        .is_ok()
                        {
                            if let Some(thumb_name) = get_thumbnail_valv_name(&new_valv_name) {
                                let thumb_valv = vault_dir.join(&thumb_name);
                                let _ = create_thumbnail_file(
                                    &path,
                                    &thumb_valv,
                                    password_bytes,
                                    filename,
                                    iterations,
                                );
                            }

                            session.files.insert(
                                filename.to_string(),
                                SessionFileEntry {
                                    valv_name: new_valv_name,
                                    mtime_secs: mtime,
                                    size,
                                },
                            );
                        }
                    }
                }
            }

            // Check for deletions
            let mut deleted = Vec::new();
            for (orig_name, item) in &session.files {
                let p = mount_dir.join(orig_name);
                if !p.exists() {
                    let target_valv = vault_dir.join(&item.valv_name);
                    let _ = fs::remove_file(&target_valv);

                    // Also remove associated thumbnail file if present
                    if let Some(thumb_name) = get_thumbnail_valv_name(&item.valv_name) {
                        let thumb_valv = vault_dir.join(&thumb_name);
                        let _ = fs::remove_file(thumb_valv);
                    }

                    deleted.push(orig_name.clone());
                }
            }
            for d in deleted {
                session.files.remove(&d);
            }

            if let Ok(json) = serde_json::to_string(&session) {
                let _ = fs::write(&session_file, json);
            }
        }

        thread::sleep(Duration::from_millis(500));
    }

    // Cleanup: remove mount directory on session end
    let _ = fs::remove_dir_all(mount_dir);
    Ok(())
}

pub fn unmount_vault(target_path: &Path) -> Result<(), (String, u8)> {
    let mount_dir = if target_path.join(".valv_session.json").exists() {
        target_path.to_path_buf()
    } else {
        let uid = unsafe { libc::getuid() };
        let shm = Path::new("/dev/shm");
        let base = if shm.exists() {
            shm.to_path_buf()
        } else {
            std::env::temp_dir()
        };
        let mut found = None;
        if let Ok(entries) = fs::read_dir(base.join(format!("valv-{}", uid))) {
            for e in entries.flatten() {
                if e.path().is_dir() {
                    found = Some(e.path());
                    break;
                }
            }
        }
        found.ok_or_else(|| {
            (
                format!("No active Valv mount found at {}", target_path.display()),
                1,
            )
        })?
    };

    let close_file = mount_dir.join(".valv_close");
    let _ = fs::write(&close_file, b"close");

    // Wait for daemon to clean up (up to 1.5 seconds)
    for _ in 0..15 {
        if !mount_dir.exists() {
            println!("Unmounted: {}", mount_dir.display());
            return Ok(());
        }
        thread::sleep(Duration::from_millis(100));
    }

    let _ = fs::remove_dir_all(&mount_dir);
    println!("Unmounted: {}", mount_dir.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_filename_suffixes() {
        assert_eq!(get_suffix_for_path(Path::new("test.jpg")), "-i.valv");
        assert_eq!(get_suffix_for_path(Path::new("anim.gif")), "-g.valv");
        assert_eq!(get_suffix_for_path(Path::new("video.mp4")), "-v.valv");
        assert_eq!(get_suffix_for_path(Path::new("doc.txt")), "-x.valv");
        assert_eq!(get_suffix_for_path(Path::new("unknown.xyz")), "-i.valv");
    }

    #[test]
    fn test_thumbnail_suffix_detection() {
        assert!(is_thumbnail_valv_file(Path::new("abc123xyz-t.valv")));
        assert!(!is_thumbnail_valv_file(Path::new("abc123xyz-i.valv")));
        assert!(!is_thumbnail_valv_file(Path::new("abc123xyz-v.valv")));
    }

    #[test]
    fn test_list_mounts() {
        let mounts = list_mounts();
        let _ = mounts;
    }

    #[test]
    fn test_mount_unmount_lifecycle() {
        let temp_dir =
            std::env::temp_dir().join(format!("valv_test_{}", rand::rng().random::<u32>()));
        let vault_dir = temp_dir.join("vault");
        let mount_dir = temp_dir.join("mount");
        fs::create_dir_all(&vault_dir).unwrap();

        let password = b"VaultPass123";
        // Create an encrypted file in vault
        let file_path = vault_dir.join("testfile-x.valv");
        let mut out = BufWriter::new(File::create(&file_path).unwrap());
        encrypt_stream(
            &mut Cursor::new(b"Hello from vault"),
            &mut out,
            password,
            "hello.txt",
            1000,
        )
        .unwrap();

        // Mount
        let current_pid = std::process::id();
        mount_vault(&vault_dir, &mount_dir, password, current_pid, false, 1000)
            .expect("Mount should succeed");

        assert!(mount_dir.join("hello.txt").exists());
        let decrypted_content = fs::read_to_string(mount_dir.join("hello.txt")).unwrap();
        assert_eq!(decrypted_content, "Hello from vault");

        // Verify session data
        let session_data = fs::read_to_string(mount_dir.join(".valv_session.json")).unwrap();
        let session: ValvSession = serde_json::from_str(&session_data).unwrap();
        assert_eq!(session.files.len(), 1);

        // Unmount
        unmount_vault(&mount_dir).expect("Unmount should succeed");
        assert!(!mount_dir.exists());

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_mount_ignores_thumbnails() {
        let temp_dir =
            std::env::temp_dir().join(format!("valv_test_thumb_{}", rand::rng().random::<u32>()));
        let vault_dir = temp_dir.join("vault");
        let mount_dir = temp_dir.join("mount");
        fs::create_dir_all(&vault_dir).unwrap();

        let password = b"VaultPass123";
        // Create real image file
        let img_valv = vault_dir.join("abc123-i.valv");
        let mut out_img = BufWriter::new(File::create(&img_valv).unwrap());
        encrypt_stream(
            &mut Cursor::new(b"FULL_RESOLUTION_IMAGE_DATA_12345"),
            &mut out_img,
            password,
            "photo.jpg",
            1000,
        )
        .unwrap();

        // Create thumbnail file with same originalName
        let thumb_valv = vault_dir.join("abc123-t.valv");
        let mut out_thumb = BufWriter::new(File::create(&thumb_valv).unwrap());
        encrypt_stream(
            &mut Cursor::new(b"THUMBNAIL_PREVIEW"),
            &mut out_thumb,
            password,
            "photo.jpg",
            1000,
        )
        .unwrap();

        // Mount
        let current_pid = std::process::id();
        mount_vault(&vault_dir, &mount_dir, password, current_pid, false, 1000)
            .expect("Mount should succeed");

        assert!(mount_dir.join("photo.jpg").exists());
        let decrypted = fs::read_to_string(mount_dir.join("photo.jpg")).unwrap();
        // Crucial check: photo.jpg MUST be the full resolution image, NOT the thumbnail preview!
        assert_eq!(decrypted, "FULL_RESOLUTION_IMAGE_DATA_12345");

        // Unmount
        unmount_vault(&mount_dir).expect("Unmount should succeed");
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_get_thumbnail_valv_name() {
        assert_eq!(
            get_thumbnail_valv_name("12345678901234567890123456789012-i.valv"),
            Some("12345678901234567890123456789012-t.valv".to_string())
        );
        assert_eq!(
            get_thumbnail_valv_name("12345678901234567890123456789012-v.valv"),
            Some("12345678901234567890123456789012-t.valv".to_string())
        );
        assert_eq!(
            get_thumbnail_valv_name("12345678901234567890123456789012-g.valv"),
            Some("12345678901234567890123456789012-t.valv".to_string())
        );
        assert_eq!(
            get_thumbnail_valv_name("12345678901234567890123456789012-x.valv"),
            None
        );
    }

    #[test]
    fn test_thumbnail_generation_and_auto_mount() {
        let temp_dir = std::env::temp_dir().join(format!(
            "valv_test_thumb_gen_{}",
            rand::rng().random::<u32>()
        ));
        let vault_dir = temp_dir.join("vault");
        let mount_dir = temp_dir.join("mount");
        fs::create_dir_all(&vault_dir).unwrap();

        let ppm_data = b"P6\n2 2\n255\n\xff\x00\x00\x00\xff\x00\x00\x00\xff\xff\xff\xff";
        let src_img = temp_dir.join("test.png");
        let converted = Command::new("ffmpeg")
            .args([
                "-y",
                "-loglevel",
                "error",
                "-f",
                "image2pipe",
                "-vcodec",
                "ppm",
                "-i",
                "-",
                src_img.to_str().unwrap(),
            ])
            .stdin(std::process::Stdio::piped())
            .spawn()
            .and_then(|mut child| {
                if let Some(mut stdin) = child.stdin.take() {
                    let _ = stdin.write_all(ppm_data);
                }
                child.wait()
            });

        if converted.is_err() || !src_img.exists() {
            let _ = fs::remove_dir_all(&temp_dir);
            return;
        }

        let thumb_bytes = generate_thumbnail(&src_img);
        assert!(thumb_bytes.is_some());
        let bytes = thumb_bytes.unwrap();
        assert!(bytes.len() > 100);
        assert_eq!(&bytes[..2], &[0xff, 0xd8]);

        let password = b"VaultPass123";
        let img_valv = vault_dir.join("abc123xyz-i.valv");
        let mut out_img = BufWriter::new(File::create(&img_valv).unwrap());
        encrypt_stream(
            &mut BufReader::new(File::open(&src_img).unwrap()),
            &mut out_img,
            password,
            "test.png",
            1000,
        )
        .unwrap();

        let expected_thumb_valv = vault_dir.join("abc123xyz-t.valv");
        assert!(!expected_thumb_valv.exists());

        let current_pid = std::process::id();
        mount_vault(&vault_dir, &mount_dir, password, current_pid, false, 1000)
            .expect("Mount should succeed");

        assert!(expected_thumb_valv.exists());

        let mut decrypted_thumb = Vec::new();
        crate::crypto::decrypt_file_to(&expected_thumb_valv, password, &mut decrypted_thumb)
            .expect("Decrypt thumbnail");
        assert_eq!(&decrypted_thumb[..2], &[0xff, 0xd8]);

        unmount_vault(&mount_dir).expect("Unmount should succeed");
        let _ = fs::remove_dir_all(&temp_dir);
    }
}
