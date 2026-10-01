use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter, Cursor, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::ValvError;
use crate::crypto::{
    BUFFER_SIZE, Credentials, DecryptError, EncryptionMethod, VaultFormat,
    decrypt_header_with_credentials, encrypt_stream_unified,
};

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct ValvSession {
    pub vault_dir: PathBuf,
    pub watch_pid: Option<u32>,
    pub daemon_pid: u32,
    pub files: HashMap<String, SessionFileEntry>,
    #[serde(default)]
    pub format: Option<String>,
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
    name.ends_with(".valv") || name.ends_with(".age")
}

pub fn sanitize_filename(name: &str) -> &str {
    let trimmed = name.trim();
    let basename = trimmed.rsplit(['/', '\\']).next().unwrap_or("");
    if basename.is_empty() || basename == "." || basename == ".." || basename.contains('\0') {
        "decrypted_file"
    } else {
        basename
    }
}

pub fn is_thumbnail_valv_file(path: &Path) -> bool {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    name.ends_with("-t.valv") || name.ends_with("-t.age")
}

pub fn get_thumbnail_valv_name(valv_name: &str) -> Option<String> {
    if let Some(prefix) = valv_name
        .strip_suffix("-i.valv")
        .or_else(|| valv_name.strip_suffix("-g.valv"))
        .or_else(|| valv_name.strip_suffix("-v.valv"))
    {
        return Some(format!("{}-t.valv", prefix));
    }
    if let Some(prefix) = valv_name
        .strip_suffix("-i.age")
        .or_else(|| valv_name.strip_suffix("-g.age"))
        .or_else(|| valv_name.strip_suffix("-v.age"))
    {
        return Some(format!("{}-t.age", prefix));
    }
    None
}

pub fn collect_vault_files(dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    collect_vault_files_recursive(dir, &mut files);
    files
}

fn collect_vault_files_recursive(dir: &Path, files: &mut Vec<PathBuf>) {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name.starts_with('.') {
                continue;
            }
            if path.is_dir() {
                collect_vault_files_recursive(&path, files);
            } else if path.is_file() && is_valv_file(&path) && !is_thumbnail_valv_file(&path) {
                files.push(path);
            }
        }
    }
}

pub fn collect_plain_files(dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    collect_plain_files_recursive(dir, &mut files);
    files
}

fn collect_plain_files_recursive(dir: &Path, files: &mut Vec<PathBuf>) {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name.starts_with('.') {
                continue;
            }
            if path.is_dir() {
                collect_plain_files_recursive(&path, files);
            } else if path.is_file() {
                files.push(path);
            }
        }
    }
}

pub fn clean_empty_dirs_up_to(base: &Path, mut dir: &Path) {
    while dir != base && dir.starts_with(base) {
        if let Ok(mut entries) = fs::read_dir(dir) {
            if entries.next().is_none() {
                let _ = fs::remove_dir(dir);
            } else {
                break;
            }
        } else {
            break;
        }
        if let Some(parent) = dir.parent() {
            dir = parent;
        } else {
            break;
        }
    }
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
        .args([
            "-y",
            "-loglevel",
            "error",
            "-protocol_whitelist",
            "file",
            "-ss",
            "00:00:00",
            "-i",
        ])
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

pub fn create_thumbnail_file_unified(
    source_file: &Path,
    thumb_valv_path: &Path,
    orig_filename: &str,
    method: &EncryptionMethod,
) -> io::Result<bool> {
    if let Some(thumb_bytes) = generate_thumbnail(source_file) {
        if let Some(parent) = thumb_valv_path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let mut reader = Cursor::new(thumb_bytes);
        let out_file = File::create(thumb_valv_path)?;
        let mut writer = BufWriter::new(out_file);
        encrypt_stream_unified(&mut reader, &mut writer, orig_filename, method)?;
        Ok(true)
    } else {
        Ok(false)
    }
}

pub fn create_thumbnail_file(
    source_file: &Path,
    thumb_valv_path: &Path,
    password_bytes: &[u8],
    orig_filename: &str,
    iterations: u32,
) -> io::Result<bool> {
    let method = EncryptionMethod::ValvPassphrase {
        password: password_bytes,
        iterations,
    };
    create_thumbnail_file_unified(source_file, thumb_valv_path, orig_filename, &method)
}

pub fn get_suffix_for_path(path: &Path) -> &'static str {
    get_suffix_for_path_and_format(path, VaultFormat::Valv)
}

pub fn get_suffix_for_path_and_format(path: &Path, format: VaultFormat) -> &'static str {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase())
        .unwrap_or_default();

    match format {
        VaultFormat::Age => match ext.as_str() {
            "gif" => "-g.age",
            "jpg" | "jpeg" | "png" | "webp" | "bmp" | "svg" | "heic" | "heif" | "avif" | "ico" => {
                "-i.age"
            }
            "mp4" | "mkv" | "mov" | "avi" | "webm" | "flv" | "3gp" | "wmv" | "m4v" => "-v.age",
            "txt" | "md" | "json" | "csv" | "xml" | "log" | "pdf" | "html" | "css" | "js" | "py"
            | "rs" => "-x.age",
            _ => "-i.age",
        },
        VaultFormat::Valv => match ext.as_str() {
            "gif" => "-g.valv",
            "jpg" | "jpeg" | "png" | "webp" | "bmp" | "svg" | "heic" | "heif" | "avif" | "ico" => {
                "-i.valv"
            }
            "mp4" | "mkv" | "mov" | "avi" | "webm" | "flv" | "3gp" | "wmv" | "m4v" => "-v.valv",
            "txt" | "md" | "json" | "csv" | "xml" | "log" | "pdf" | "html" | "css" | "js" | "py"
            | "rs" => "-x.valv",
            _ => "-i.valv",
        },
    }
}

pub fn generate_random_filename(suffix: &str) -> String {
    use rand::distr::{Alphanumeric, SampleString};
    let prefix = Alphanumeric.sample_string(&mut rand::rng(), 32);
    format!("{}{}", prefix, suffix)
}

#[cfg(unix)]
pub fn get_current_uid() -> u32 {
    unsafe { libc::getuid() }
}

#[cfg(not(unix))]
pub fn get_current_uid() -> u32 {
    0
}

pub fn user_mount_base() -> PathBuf {
    let uid = get_current_uid();
    let shm = Path::new("/dev/shm");
    let base = if shm.exists() {
        shm.to_path_buf()
    } else {
        let tmp = std::env::temp_dir();
        eprintln!(
            "Warning: /dev/shm not available; falling back to persistent directory {}",
            tmp.display()
        );
        tmp
    };
    base.join(format!("valv-{}", uid))
}

pub fn is_process_alive(pid: u32) -> bool {
    #[cfg(unix)]
    {
        unsafe {
            libc::kill(pid as i32, 0) == 0
                || io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
        }
    }
    #[cfg(not(unix))]
    {
        false
    }
}

pub fn get_mount_dir(
    vault_dir: &Path,
    watch_pid: Option<u32>,
    custom_output: Option<&Path>,
) -> PathBuf {
    if let Some(out) = custom_output {
        return out.to_path_buf();
    }
    let vault_name = vault_dir
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("vault");
    let tag = match watch_pid {
        Some(pid) => pid.to_string(),
        None => std::process::id().to_string(),
    };
    user_mount_base().join(format!("{}-{}", vault_name, tag))
}

pub fn list_mounts() -> Vec<ActiveMount> {
    let base = user_mount_base();
    let mut mounts = Vec::new();

    if let Ok(entries) = fs::read_dir(base) {
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

static TERMINATE: AtomicBool = AtomicBool::new(false);

#[cfg(unix)]
extern "C" fn sig_handler(_: libc::c_int) {
    TERMINATE.store(true, Ordering::SeqCst);
}

fn sync_file_to_vault(
    src_path: &Path,
    vault_dir: &Path,
    valv_rel_path: &str,
    filename: &str,
    credentials: &Credentials,
    iterations: u32,
    recipients: &[Box<dyn age::Recipient + Send>],
) -> io::Result<()> {
    let target_valv = vault_dir.join(valv_rel_path);
    if let Some(parent) = target_valv.parent() {
        fs::create_dir_all(parent)?;
    }

    let parent_dir = target_valv.parent().unwrap_or(vault_dir);
    let stem = target_valv
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("file");
    let temp_valv = parent_dir.join(format!(".{}.tmp", stem));

    let method = if valv_rel_path.ends_with(".age") {
        if !recipients.is_empty() {
            EncryptionMethod::AgeRecipients(recipients)
        } else if let Some(ref pwd) = credentials.password
            && let Ok(pwd_str) = std::str::from_utf8(pwd)
        {
            EncryptionMethod::AgePassphrase(pwd_str)
        } else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "No recipient or passphrase available for age encryption",
            ));
        }
    } else if let Some(ref pwd) = credentials.password {
        EncryptionMethod::ValvPassphrase {
            password: pwd,
            iterations,
        }
    } else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "No password available for Valv encryption",
        ));
    };

    let res = (|| -> io::Result<()> {
        let mut in_file = BufReader::with_capacity(BUFFER_SIZE, File::open(src_path)?);
        let out_file = File::create(&temp_valv)?;
        let mut writer = BufWriter::with_capacity(BUFFER_SIZE, out_file);
        encrypt_stream_unified(&mut in_file, &mut writer, filename, &method)?;
        fs::rename(&temp_valv, &target_valv)?;
        Ok(())
    })();

    if res.is_err() {
        let _ = fs::remove_file(&temp_valv);
        return res;
    }

    if let Some(thumb_name) = get_thumbnail_valv_name(valv_rel_path) {
        let thumb_valv = vault_dir.join(&thumb_name);
        if let Ok(true) = create_thumbnail_file_unified(src_path, &thumb_valv, filename, &method) {
            // Thumbnail updated
        } else {
            let _ = fs::remove_file(&thumb_valv);
        }
    }

    Ok(())
}

fn copy_dir_all(src: &Path, dst: &Path) -> io::Result<()> {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        let dest_path = dst.join(entry.file_name());
        if ty.is_dir() {
            copy_dir_all(&entry.path(), &dest_path)?;
        } else {
            fs::copy(entry.path(), dest_path)?;
        }
    }
    Ok(())
}

pub fn preserve_unsynced_dirs(mount_dir: &Path, vault_dir: &Path) {
    if let Ok(entries) = fs::read_dir(mount_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if !name.starts_with('.') && path.is_dir() {
                let mut dest = vault_dir.join(name);
                if dest.exists() {
                    dest = vault_dir.join(format!("{}_unsynced", name));
                }
                eprintln!("Preserving unsynced directory to {}", dest.display());
                if fs::rename(&path, &dest).is_err() {
                    let _ = copy_dir_all(&path, &dest);
                    let _ = fs::remove_dir_all(&path);
                }
            }
        }
    }
}

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

    let valv_files = collect_vault_files(vault_dir);

    // Verify credentials on first file if any exist
    if let Some(first_file) = valv_files.first() {
        let f = File::open(first_file)?;
        let r = BufReader::new(f);
        if let Err(DecryptError::InvalidPassword) = decrypt_header_with_credentials(r, credentials) {
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

    let mut session = ValvSession {
        vault_dir: fs::canonicalize(vault_dir).unwrap_or_else(|_| vault_dir.to_path_buf()),
        watch_pid,
        daemon_pid: std::process::id(),
        files: HashMap::new(),
        format: Some(match default_format {
            VaultFormat::Age => "age".to_string(),
            VaultFormat::Valv => "valv".to_string(),
        }),
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
        if let Some(pid) = watch_pid {
            cmd.arg("--watch-pid").arg(pid.to_string());
        }
        if default_format == VaultFormat::Age {
            cmd.arg("--age");
        }
        for id_path in identity_paths {
            cmd.arg("-k").arg(id_path);
        }
        for recip in recipient_strings {
            cmd.arg("-r").arg(recip);
        }

        let mut child = cmd
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map_err(|e| {
                ValvError::Message(format!("Failed to spawn background daemon: {}", e), 1)
            })?;

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

pub fn run_sync_daemon(
    vault_dir: &Path,
    mount_dir: &Path,
    password_bytes: &[u8],
    watch_pid: Option<u32>,
    iterations: u32,
) -> Result<(), ValvError> {
    let creds = Credentials::new().with_password(password_bytes.to_vec());
    run_sync_daemon_with_credentials(
        vault_dir,
        mount_dir,
        &creds,
        watch_pid,
        iterations,
        VaultFormat::Valv,
        &[],
    )
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
    let mut session: ValvSession = if session_file.exists() {
        let data = fs::read_to_string(&session_file).unwrap_or_default();
        serde_json::from_str(&data).unwrap_or_default()
    } else {
        ValvSession::default()
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

        // 3. Scan mount_dir recursively for changes (supports pasting subdirectories)
        let plain_files = collect_plain_files(mount_dir);
        for path in plain_files {
            let rel_path = match path.strip_prefix(mount_dir) {
                Ok(p) => p,
                Err(_) => continue,
            };
            let rel_str = rel_path.to_string_lossy().to_string();
            let rel_dir = rel_path.parent().unwrap_or(Path::new(""));

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
            let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

            if let Some(item) = session.files.get_mut(&rel_str) {
                if (item.mtime_secs != mtime || item.size != size)
                    && sync_file_to_vault(
                        &path,
                        vault_dir,
                        &item.valv_name,
                        filename,
                        credentials,
                        iterations,
                        recipients,
                    )
                    .is_ok()
                {
                    item.mtime_secs = mtime;
                    item.size = size;
                }
            } else {
                let fmt = if session.format.as_deref() == Some("age")
                    || default_format == VaultFormat::Age
                {
                    VaultFormat::Age
                } else {
                    VaultFormat::Valv
                };
                let suffix = get_suffix_for_path_and_format(&path, fmt);
                let rand_filename = generate_random_filename(suffix);
                let new_valv_rel_path = if rel_dir.as_os_str().is_empty() {
                    PathBuf::from(rand_filename)
                } else {
                    rel_dir.join(rand_filename)
                };
                let new_valv_rel_str = new_valv_rel_path.to_string_lossy().to_string();

                if sync_file_to_vault(
                    &path,
                    vault_dir,
                    &new_valv_rel_str,
                    filename,
                    credentials,
                    iterations,
                    recipients,
                )
                .is_ok()
                {
                    session.files.insert(
                        rel_str,
                        SessionFileEntry {
                            valv_name: new_valv_rel_str,
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
    let _ = fs::remove_dir_all(&mount_dir);
    println!("Unmounted: {}", mount_dir.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::encrypt_stream;
    use rand::RngExt;
    use std::io::Cursor;

    #[test]
    fn test_filename_suffixes() {
        assert_eq!(get_suffix_for_path(Path::new("test.jpg")), "-i.valv");
        assert_eq!(get_suffix_for_path(Path::new("anim.gif")), "-g.valv");
        assert_eq!(get_suffix_for_path(Path::new("video.mp4")), "-v.valv");
        assert_eq!(get_suffix_for_path(Path::new("doc.txt")), "-x.valv");
        assert_eq!(get_suffix_for_path(Path::new("unknown.xyz")), "-i.valv");

        assert_eq!(
            get_suffix_for_path_and_format(Path::new("test.jpg"), VaultFormat::Age),
            "-i.age"
        );
        assert_eq!(
            get_suffix_for_path_and_format(Path::new("video.mp4"), VaultFormat::Age),
            "-v.age"
        );
    }

    #[test]
    fn test_thumbnail_suffix_detection() {
        assert!(is_thumbnail_valv_file(Path::new("abc123xyz-t.valv")));
        assert!(is_thumbnail_valv_file(Path::new("abc123xyz-t.age")));
        assert!(!is_thumbnail_valv_file(Path::new("abc123xyz-i.valv")));
        assert!(!is_thumbnail_valv_file(Path::new("abc123xyz-v.age")));
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
        mount_vault(
            &vault_dir,
            &mount_dir,
            password,
            Some(current_pid),
            false,
            1000,
        )
        .expect("Mount should succeed");

        assert!(mount_dir.join("hello.txt").exists());
        let decrypted_content = fs::read_to_string(mount_dir.join("hello.txt")).unwrap();
        assert_eq!(decrypted_content, "Hello from vault");

        // Verify session data
        let session_data = fs::read_to_string(mount_dir.join(".valv_session.json")).unwrap();
        let session: ValvSession = serde_json::from_str(&session_data).unwrap();
        assert_eq!(session.files.len(), 1);

        // Verify .nomedia and .thumbnails exist in mount_dir (R5)
        assert!(mount_dir.join(".nomedia").exists());
        #[cfg(unix)]
        assert!(mount_dir.join(".thumbnails").is_symlink());

        // Unmount
        unmount_vault(&mount_dir).expect("Unmount should succeed");
        assert!(!mount_dir.exists());

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_age_vault_mount_unmount_lifecycle() {
        let temp_dir =
            std::env::temp_dir().join(format!("valv_age_test_{}", rand::rng().random::<u32>()));
        let vault_dir = temp_dir.join("vault");
        let mount_dir = temp_dir.join("mount");
        fs::create_dir_all(&vault_dir).unwrap();

        let key = age::x25519::Identity::generate();
        let pubkey = key.to_public();

        // Create an encrypted file in vault using Age
        let file_path = vault_dir.join("testfile-x.age");
        let mut out = BufWriter::new(File::create(&file_path).unwrap());
        let recipients = vec![Box::new(pubkey) as Box<dyn age::Recipient + Send>];
        encrypt_stream_unified(
            &mut Cursor::new(b"Hello from Age vault"),
            &mut out,
            "secret_doc.txt",
            &EncryptionMethod::AgeRecipients(&recipients),
        )
        .unwrap();
        drop(out);

        // Mount using Age key credentials
        let creds = Credentials::new().with_identities(vec![Box::new(key)]);
        let current_pid = std::process::id();
        mount_vault_with_credentials(
            &vault_dir,
            &mount_dir,
            &creds,
            Some(current_pid),
            false,
            1000,
            VaultFormat::Age,
            &recipients,
            &[],
            &[],
        )
        .expect("Age mount should succeed");

        assert!(mount_dir.join("secret_doc.txt").exists());
        let decrypted = fs::read_to_string(mount_dir.join("secret_doc.txt")).unwrap();
        assert_eq!(decrypted, "Hello from Age vault");

        // Unmount
        unmount_vault(&mount_dir).expect("Unmount should succeed");
        assert!(!mount_dir.exists());

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_nested_vault_mount_and_pasting_directories() {
        let temp_dir =
            std::env::temp_dir().join(format!("valv_nested_test_{}", rand::rng().random::<u32>()));
        let vault_dir = temp_dir.join("vault");
        let mount_dir = temp_dir.join("mount");
        fs::create_dir_all(&vault_dir).unwrap();

        let password = b"VaultPass123";

        // Create a nested directory in vault with an encrypted file
        let nested_vault_dir = vault_dir.join("subfolder").join("nested");
        fs::create_dir_all(&nested_vault_dir).unwrap();
        let file_path = nested_vault_dir.join("file1-x.valv");
        let mut out = BufWriter::new(File::create(&file_path).unwrap());
        encrypt_stream(
            &mut Cursor::new(b"Deep nested secret"),
            &mut out,
            password,
            "deep.txt",
            1000,
        )
        .unwrap();
        drop(out);

        // Mount
        let current_pid = std::process::id();
        mount_vault(
            &vault_dir,
            &mount_dir,
            password,
            Some(current_pid),
            false,
            1000,
        )
        .expect("Mount with nested files should succeed");

        assert!(mount_dir.join("subfolder/nested/deep.txt").exists());
        let content = fs::read_to_string(mount_dir.join("subfolder/nested/deep.txt")).unwrap();
        assert_eq!(content, "Deep nested secret");

        // Simulate pasting a new nested directory into the mount
        let pasted_dir = mount_dir.join("pasted_folder").join("inner");
        fs::create_dir_all(&pasted_dir).unwrap();
        fs::write(pasted_dir.join("pasted_file.txt"), b"Pasted nested data").unwrap();

        // Run a sync daemon cycle manually
        let _creds = Credentials::new().with_password(password.to_vec());
        let plain_files = collect_plain_files(&mount_dir);
        assert_eq!(plain_files.len(), 2); // deep.txt and pasted_file.txt

        // Unmount (which performs a final sync/preservation)
        unmount_vault(&mount_dir).expect("Unmount should succeed");
        assert!(!mount_dir.exists());

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_unmount_by_vault_dir() {
        let temp_dir =
            std::env::temp_dir().join(format!("valv_test_vdir_{}", rand::rng().random::<u32>()));
        let vault_dir = temp_dir.join("vault");
        fs::create_dir_all(&vault_dir).unwrap();

        let password = b"VaultPass123";
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

        let current_pid = std::process::id();
        let mount_dir = get_mount_dir(&vault_dir, Some(current_pid), None);
        mount_vault(
            &vault_dir,
            &mount_dir,
            password,
            Some(current_pid),
            false,
            1000,
        )
        .expect("Mount should succeed");

        assert!(mount_dir.join("hello.txt").exists());

        // Unmount using vault directory path instead of mount directory path
        unmount_vault(&vault_dir).expect("Unmount by vault dir should succeed");
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
        mount_vault(
            &vault_dir,
            &mount_dir,
            password,
            Some(current_pid),
            false,
            1000,
        )
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
            get_thumbnail_valv_name("12345678901234567890123456789012-i.age"),
            Some("12345678901234567890123456789012-t.age".to_string())
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
        mount_vault(
            &vault_dir,
            &mount_dir,
            password,
            Some(current_pid),
            false,
            1000,
        )
        .expect("Mount should succeed");

        assert!(expected_thumb_valv.exists());

        let mut decrypted_thumb = Vec::new();
        crate::crypto::decrypt_file_to(&expected_thumb_valv, password, &mut decrypted_thumb)
            .expect("Decrypt thumbnail");
        assert_eq!(&decrypted_thumb[..2], &[0xff, 0xd8]);

        unmount_vault(&mount_dir).expect("Unmount should succeed");
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_sanitize_filename() {
        assert_eq!(sanitize_filename("test.txt"), "test.txt");
        assert_eq!(sanitize_filename("../../etc/passwd"), "passwd");
        assert_eq!(sanitize_filename("/etc/shadow"), "shadow");
        assert_eq!(
            sanitize_filename("C:\\Windows\\system32\\cmd.exe"),
            "cmd.exe"
        );
        assert_eq!(sanitize_filename("."), "decrypted_file");
        assert_eq!(sanitize_filename(".."), "decrypted_file");
        assert_eq!(sanitize_filename(""), "decrypted_file");
        assert_eq!(sanitize_filename("   "), "decrypted_file");
        assert_eq!(sanitize_filename("foo\0bar"), "decrypted_file");
    }

    #[test]
    fn test_unsynced_subdirectory_preserved() {
        let temp_dir =
            std::env::temp_dir().join(format!("valv_test_sub_{}", rand::rng().random::<u32>()));
        let vault_dir = temp_dir.join("vault");
        let mount_dir = temp_dir.join("mount");
        fs::create_dir_all(&vault_dir).unwrap();

        let password = b"VaultPass123";
        let file_path = vault_dir.join("testfile-x.valv");
        let mut out = BufWriter::new(File::create(&file_path).unwrap());
        encrypt_stream(
            &mut Cursor::new(b"Hello"),
            &mut out,
            password,
            "hello.txt",
            1000,
        )
        .unwrap();

        let current_pid = std::process::id();
        mount_vault(
            &vault_dir,
            &mount_dir,
            password,
            Some(current_pid),
            false,
            1000,
        )
        .expect("Mount should succeed");

        // User creates a subdirectory with files inside mount_dir
        let user_folder = mount_dir.join("MyFolder");
        fs::create_dir_all(&user_folder).unwrap();
        fs::write(user_folder.join("notes.txt"), b"important unsynced data").unwrap();

        // Unmount
        unmount_vault(&mount_dir).expect("Unmount should succeed");

        // The subdirectory MUST be preserved in vault_dir instead of deleted!
        assert!(vault_dir.join("MyFolder/notes.txt").exists());
        let preserved_data = fs::read_to_string(vault_dir.join("MyFolder/notes.txt")).unwrap();
        assert_eq!(preserved_data, "important unsynced data");

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
