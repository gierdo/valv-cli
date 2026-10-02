#[cfg(feature = "fuse")]
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

#[cfg(feature = "fuse")]
use fuser::MountOption;

#[cfg(feature = "fuse")]
use crate::ValvError;
#[cfg(feature = "fuse")]
use crate::crypto::VaultFormat;
#[cfg(feature = "fuse")]
use crate::vault::session::is_process_alive;

#[cfg(feature = "fuse")]
use super::driver::ValvFuseFs;

#[cfg(feature = "fuse")]
pub fn has_fuse_support() -> bool {
    Path::new("/dev/fuse").exists()
        && fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/fuse")
            .is_ok()
}

#[cfg(feature = "fuse")]
#[allow(clippy::too_many_arguments)]
pub fn mount_fuse_vault(
    vault_dir: &Path,
    mount_dir: &Path,
    password: Option<Vec<u8>>,
    watch_pid: Option<u32>,
    foreground: bool,
    iterations: u32,
    default_format: VaultFormat,
    recipient_strings: &[String],
    recipient_files: &[PathBuf],
    identity_paths: &[PathBuf],
) -> Result<(), ValvError> {
    if foreground {
        let fs = ValvFuseFs::new(
            vault_dir,
            password,
            default_format,
            iterations,
            recipient_strings.to_vec(),
            recipient_files.to_vec(),
            identity_paths.to_vec(),
            watch_pid,
        )?;

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

        let options = vec![
            MountOption::FSName("valv".to_string()),
            MountOption::DefaultPermissions,
        ];

        if let Some(pid) = watch_pid {
            let m_dir = mount_dir.to_path_buf();
            std::thread::spawn(move || {
                let close_trigger = m_dir.join(".valv_close");
                loop {
                    if !is_process_alive(pid) || close_trigger.exists() {
                        let _ = unmount_fuse_target(&m_dir);
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(500));
                }
            });
        }

        println!("READY {}", mount_dir.display());
        let _ = std::io::stdout().flush();

        let res = fuser::mount2(fs, mount_dir, &options);
        let _ = unmount_fuse_target(mount_dir);
        res.map_err(|e| ValvError::Message(format!("FUSE mount failed: {}", e), 1))
    } else {
        let current_exe = std::env::current_exe()?;
        let mut cmd = std::process::Command::new(current_exe);
        cmd.arg("mount")
            .arg(vault_dir)
            .arg("-o")
            .arg(mount_dir)
            .arg("--foreground")
            .arg("--driver")
            .arg("fuse")
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
        for recip in recipient_strings {
            cmd.arg("-r").arg(recip);
        }
        for rfile in recipient_files {
            cmd.arg("-R").arg(rfile);
        }

        if let Some(pid) = watch_pid {
            cmd.arg("--watch-pid").arg(pid.to_string());
        }

        if password.is_some() {
            cmd.arg("--stdin-password");
            cmd.stdin(std::process::Stdio::piped());
        } else {
            cmd.stdin(std::process::Stdio::null());
        }

        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());

        let mut child = cmd.spawn().map_err(|e| {
            ValvError::Message(format!("Failed to spawn background FUSE daemon: {}", e), 1)
        })?;

        if let Some(ref pwd) = password
            && let Some(mut stdin) = child.stdin.take()
        {
            let _ = stdin.write_all(pwd);
            let _ = stdin.write_all(b"\n");
        }

        let mut stdout_reader = BufReader::new(child.stdout.take().unwrap());
        let mut line = String::new();
        match stdout_reader.read_line(&mut line) {
            Ok(n) if n > 0 && line.starts_with("READY") => {
                print!("{}", line);
                let _ = std::io::stdout().flush();
                Ok(())
            }
            _ => {
                let mut stderr_content = String::new();
                if let Some(mut stderr) = child.stderr.take() {
                    let _ = std::io::Read::read_to_string(&mut stderr, &mut stderr_content);
                }
                let status = child.wait().ok();
                let code = status.and_then(|s| s.code()).unwrap_or(1);
                if code == 2 {
                    Err(ValvError::InvalidPassword)
                } else {
                    let err_msg = if !stderr_content.trim().is_empty() {
                        stderr_content.trim().to_string()
                    } else {
                        format!("FUSE daemon exited unexpectedly with code {}", code)
                    };
                    Err(ValvError::Message(err_msg, code as u8))
                }
            }
        }
    }
}

#[cfg(feature = "fuse")]
pub fn unmount_fuse_target(mount_dir: &Path) -> Result<(), ValvError> {
    let cmd = std::process::Command::new("fusermount3")
        .arg("-u")
        .arg(mount_dir)
        .output();

    if let Ok(out) = cmd
        && out.status.success()
    {
        return Ok(());
    }

    let cmd2 = std::process::Command::new("fusermount")
        .arg("-u")
        .arg(mount_dir)
        .output();

    if let Ok(out) = cmd2
        && out.status.success()
    {
        return Ok(());
    }

    #[cfg(unix)]
    unsafe {
        use std::ffi::CString;
        let c_path = CString::new(mount_dir.to_string_lossy().as_bytes()).unwrap();
        libc::umount2(c_path.as_ptr(), libc::MNT_FORCE);
    }

    let _ = fs::remove_dir(mount_dir);
    Ok(())
}
