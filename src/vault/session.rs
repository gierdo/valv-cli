use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct ValvSession {
    pub vault_dir: PathBuf,
    pub watch_pid: Option<u32>,
    pub daemon_pid: u32,
    pub files: HashMap<String, SessionFileEntry>,
    #[serde(default)]
    pub format: Option<String>,
    #[serde(default)]
    pub manifest_recipients: Vec<String>,
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

pub fn get_mount_dir(
    vault_dir: &Path,
    watch_pid: Option<u32>,
    custom_output: Option<&Path>,
) -> PathBuf {
    if let Some(custom) = custom_output {
        return custom.to_path_buf();
    }

    let canon = fs::canonicalize(vault_dir).unwrap_or_else(|_| vault_dir.to_path_buf());
    let vault_name = canon
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("vault");

    let mut base_runtime = None;
    if let Ok(runtime_dir) = std::env::var("XDG_RUNTIME_DIR") {
        let p = PathBuf::from(runtime_dir).join("valv");
        if fs::create_dir_all(&p).is_ok() {
            base_runtime = Some(p);
        }
    }
    if base_runtime.is_none() {
        let p = std::env::temp_dir().join("valv");
        let _ = fs::create_dir_all(&p);
        base_runtime = Some(p);
    }
    let base = base_runtime.unwrap();

    if let Some(pid) = watch_pid {
        base.join(format!("{}-{}-{}", vault_name, std::process::id(), pid))
    } else {
        base.join(format!("{}-{}", vault_name, std::process::id()))
    }
}

pub fn is_process_alive(pid: u32) -> bool {
    #[cfg(unix)]
    {
        // kill(pid, 0) returns 0 if process exists, -1 with ESRCH if not
        unsafe { libc::kill(pid as i32, 0) == 0 }
    }
    #[cfg(not(unix))]
    {
        // simplification: on Windows / non-unix platforms fallback to true.
        // Ceiling: does not auto-close on Windows when parent terminates. Upgrade path: OpenProcess.
        let _ = pid;
        true
    }
}

pub fn list_mounts() -> Vec<ActiveMount> {
    let mut mounts = Vec::new();

    let mut search_dirs = Vec::new();
    if let Ok(runtime_dir) = std::env::var("XDG_RUNTIME_DIR") {
        search_dirs.push(PathBuf::from(runtime_dir).join("valv"));
    }
    search_dirs.push(std::env::temp_dir().join("valv"));
    search_dirs.push(std::env::temp_dir());

    for dir in search_dirs {
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                let session_file = path.join(".valv_session.json");
                if session_file.exists()
                    && let Ok(data) = fs::read_to_string(&session_file)
                    && let Ok(session) = serde_json::from_str::<ValvSession>(&data)
                {
                    if is_process_alive(session.daemon_pid) {
                        let file_count = session.files.len();
                        let active = ActiveMount {
                            mount_dir: path,
                            vault_dir: session.vault_dir,
                            daemon_pid: session.daemon_pid,
                            watch_pid: session.watch_pid,
                            file_count,
                        };
                        if !mounts
                            .iter()
                            .any(|m: &ActiveMount| m.mount_dir == active.mount_dir)
                        {
                            mounts.push(active);
                        }
                    } else {
                        // Stale mount folder where daemon died
                        let _ = fs::remove_dir_all(&path);
                    }
                }
            }
        }
    }

    mounts
}
