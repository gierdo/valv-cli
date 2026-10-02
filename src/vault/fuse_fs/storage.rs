#[cfg(feature = "fuse")]
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Cursor, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

#[cfg(feature = "fuse")]
use fuser::FUSE_ROOT_ID;

#[cfg(feature = "fuse")]
use crate::ValvError;
#[cfg(feature = "fuse")]
use crate::config::AgeVaultManifest;
#[cfg(feature = "fuse")]
use crate::crypto::{
    BUFFER_SIZE, Credentials, EncryptionMethod, VaultFormat, decrypt_file_with_credentials_to,
    decrypt_header_with_credentials, encrypt_stream_unified, load_identities, load_recipients,
};
#[cfg(feature = "fuse")]
use crate::vault::paths::{
    clean_empty_dirs_up_to, collect_vault_files, generate_random_filename,
    get_suffix_for_path_and_format, get_thumbnail_valv_name, sanitize_filename,
};
#[cfg(feature = "fuse")]
use crate::vault::session::{SessionFileEntry, ValvSession};
#[cfg(feature = "fuse")]
use crate::vault::thumbnail::create_thumbnail_file_unified;

#[cfg(feature = "fuse")]
use super::handles::HandleTable;
#[cfg(feature = "fuse")]
use super::inodes::{InodeEntry, InodeTree};

#[cfg(feature = "fuse")]
#[derive(Debug, Clone)]
pub struct VaultStorage {
    pub vault_dir: PathBuf,
    pub password: Option<Vec<u8>>,
    pub default_format: VaultFormat,
    pub iterations: u32,
    pub recipient_strings: Vec<String>,
    pub recipient_files: Vec<PathBuf>,
    pub identity_paths: Vec<PathBuf>,
    pub watch_pid: Option<u32>,
}

#[cfg(feature = "fuse")]
impl VaultStorage {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        vault_dir: &Path,
        password: Option<Vec<u8>>,
        default_format: VaultFormat,
        iterations: u32,
        recipient_strings: Vec<String>,
        recipient_files: Vec<PathBuf>,
        identity_paths: Vec<PathBuf>,
        watch_pid: Option<u32>,
    ) -> Self {
        Self {
            vault_dir: fs::canonicalize(vault_dir).unwrap_or_else(|_| vault_dir.to_path_buf()),
            password,
            default_format,
            iterations,
            recipient_strings,
            recipient_files,
            identity_paths,
            watch_pid,
        }
    }

    pub fn get_credentials(&self) -> Credentials {
        let identities = load_identities(&self.identity_paths).unwrap_or_default();
        let mut creds = Credentials::new().with_identities(identities);
        if let Some(ref pwd) = self.password {
            creds.password = Some(pwd.clone());
        }
        creds
    }

    pub fn resolve_encryption_method<'a>(
        &'a self,
        recipients: &'a [Box<dyn age::Recipient + Send>],
        format: VaultFormat,
    ) -> Result<EncryptionMethod<'a>, libc::c_int> {
        if format == VaultFormat::Age || !recipients.is_empty() {
            if !recipients.is_empty() {
                Ok(EncryptionMethod::AgeRecipients(recipients))
            } else if let Some(ref pwd) = self.password
                && let Ok(pwd_str) = std::str::from_utf8(pwd)
            {
                Ok(EncryptionMethod::AgePassphrase(pwd_str))
            } else {
                Err(libc::EACCES)
            }
        } else if let Some(ref pwd) = self.password {
            Ok(EncryptionMethod::ValvPassphrase {
                password: pwd,
                iterations: self.iterations,
            })
        } else {
            Err(libc::EACCES)
        }
    }

    pub fn scan_vault(
        &mut self,
        tree: &mut InodeTree,
        handles: &mut HandleTable,
    ) -> Result<(), ValvError> {
        let creds = self.get_credentials();

        // 1. Check for manifest
        if let Some(manifest_path) = AgeVaultManifest::find_in_dir(&self.vault_dir) {
            let (_, content) =
                AgeVaultManifest::load_from_file_with_credentials(&manifest_path, &creds).map_err(
                    |e| ValvError::Message(format!("Failed to decrypt vault manifest: {}", e), 1),
                )?;

            let orig_name = if manifest_path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("")
                .starts_with("age_vault")
            {
                "age_vault.toml"
            } else {
                ".age_vault.toml"
            };

            let rel_path = manifest_path
                .strip_prefix(&self.vault_dir)
                .unwrap_or(&manifest_path)
                .to_path_buf();

            let manifest_ino = tree.allocate_ino();
            let mtime = fs::metadata(&manifest_path)
                .and_then(|m| m.modified())
                .unwrap_or_else(|_| SystemTime::now());

            tree.insert(InodeEntry {
                ino: manifest_ino,
                parent: FUSE_ROOT_ID,
                name: orig_name.to_string(),
                is_dir: false,
                vault_rel_path: Some(rel_path),
                size: content.len() as u64,
                mtime,
                format: self.default_format,
                children: Vec::new(),
            });

            tree.add_child(FUSE_ROOT_ID, manifest_ino);
            handles.set_cache(manifest_ino, content.into_bytes(), mtime);
        }

        // 2. Scan vault files
        let vault_files = collect_vault_files(&self.vault_dir);
        let mut session_file_entries = HashMap::new();

        for file_path in &vault_files {
            let rel_path = match file_path.strip_prefix(&self.vault_dir) {
                Ok(p) => p.to_path_buf(),
                Err(_) => continue,
            };
            let rel_dir = rel_path.parent().unwrap_or_else(|| Path::new(""));

            let f = match File::open(file_path) {
                Ok(f) => f,
                Err(_) => continue,
            };
            let reader = BufReader::with_capacity(BUFFER_SIZE, f);

            let header = match decrypt_header_with_credentials(reader, &creds) {
                Ok(h) => h,
                Err(_) => continue,
            };

            let orig_name = sanitize_filename(&header.original_name).to_string();
            let parent_ino = tree.ensure_dir_path(rel_dir, self.default_format);

            let meta = fs::metadata(file_path).ok();
            let mtime = meta
                .as_ref()
                .and_then(|m| m.modified().ok())
                .unwrap_or_else(SystemTime::now);

            let file_format = if file_path.to_string_lossy().ends_with(".age") {
                VaultFormat::Age
            } else {
                VaultFormat::Valv
            };

            let mut content = Vec::new();
            let mut h = header;
            let size = if h.decrypt_payload(&mut content).is_ok() {
                content.len() as u64
            } else {
                meta.map(|m| m.len()).unwrap_or(0)
            };

            let ino = tree.allocate_ino();
            tree.insert(InodeEntry {
                ino,
                parent: parent_ino,
                name: orig_name.clone(),
                is_dir: false,
                vault_rel_path: Some(rel_path.clone()),
                size,
                mtime,
                format: file_format,
                children: Vec::new(),
            });

            session_file_entries.insert(
                orig_name,
                SessionFileEntry {
                    valv_name: rel_path.to_string_lossy().to_string(),
                    mtime_secs: mtime
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0),
                    size,
                },
            );

            if !content.is_empty() {
                handles.set_cache(ino, content, mtime);
            }

            tree.add_child(parent_ino, ino);
        }

        // 3. Insert virtual .valv_session.json file for Yazi / session management
        let session_info = ValvSession {
            vault_dir: self.vault_dir.clone(),
            watch_pid: self.watch_pid,
            daemon_pid: std::process::id(),
            files: session_file_entries,
            format: Some(match self.default_format {
                VaultFormat::Age => "age".to_string(),
                VaultFormat::Valv => "valv".to_string(),
            }),
            manifest_recipients: self.recipient_strings.clone(),
        };

        if let Ok(session_json) = serde_json::to_string(&session_info) {
            let session_ino = tree.allocate_ino();
            let session_bytes = session_json.into_bytes();
            let now = SystemTime::now();
            tree.insert(InodeEntry {
                ino: session_ino,
                parent: FUSE_ROOT_ID,
                name: ".valv_session.json".to_string(),
                is_dir: false,
                vault_rel_path: None,
                size: session_bytes.len() as u64,
                mtime: now,
                format: self.default_format,
                children: Vec::new(),
            });
            handles.set_cache(session_ino, session_bytes, now);
            tree.add_child(FUSE_ROOT_ID, session_ino);
        }

        Ok(())
    }

    pub fn read_file_content(
        &self,
        vault_rel_path: Option<&Path>,
        is_manifest: bool,
    ) -> Result<Vec<u8>, libc::c_int> {
        let rel_path = match vault_rel_path {
            Some(p) => p,
            None => return Ok(Vec::new()),
        };
        let full_path = self.vault_dir.join(rel_path);
        let creds = self.get_credentials();

        let mut out = Vec::new();
        if is_manifest || crate::config::is_manifest_file(&full_path) {
            if let Ok((_, content)) =
                AgeVaultManifest::load_from_file_with_credentials(&full_path, &creds)
            {
                out = content.into_bytes();
            }
        } else if decrypt_file_with_credentials_to(&full_path, &creds, &mut out).is_err() {
            return Err(libc::EIO);
        }

        Ok(out)
    }

    pub fn save_file(
        &mut self,
        name: &str,
        parent_rel: &Path,
        existing_rel: Option<&Path>,
        format: VaultFormat,
        buffer: &[u8],
    ) -> Result<PathBuf, libc::c_int> {
        let is_manifest = name == ".age_vault.toml" || name == "age_vault.toml";
        let recipients =
            load_recipients(&self.recipient_strings, &self.recipient_files).unwrap_or_default();
        let method = self.resolve_encryption_method(&recipients, format)?;

        let vault_rel = match existing_rel {
            Some(p) => p.to_path_buf(),
            None => {
                let suffix = get_suffix_for_path_and_format(Path::new(name), format);
                let random_name = generate_random_filename(suffix);
                parent_rel.join(random_name)
            }
        };

        let dest_path = self.vault_dir.join(&vault_rel);
        if let Some(parent) = dest_path.parent() {
            let _ = fs::create_dir_all(parent);
        }

        let out_file = File::create(&dest_path).map_err(|_| libc::EIO)?;
        let mut out_writer = BufWriter::with_capacity(BUFFER_SIZE, out_file);

        if encrypt_stream_unified(&mut Cursor::new(buffer), &mut out_writer, name, &method).is_err()
        {
            let _ = fs::remove_file(&dest_path);
            return Err(libc::EIO);
        }
        let _ = out_writer.flush();

        if let Some(thumb_name) = get_thumbnail_valv_name(&vault_rel.to_string_lossy()) {
            let thumb_path = self.vault_dir.join(&thumb_name);
            let _ = create_thumbnail_file_unified(&dest_path, &thumb_path, name, &method);
        }

        if is_manifest
            && let Ok(content_str) = std::str::from_utf8(buffer)
            && let Ok(manifest) = toml::from_str::<AgeVaultManifest>(content_str)
        {
            let (r_strs, r_files) = manifest.resolve_recipients();
            self.recipient_strings = r_strs;
            self.recipient_files = r_files;
        }

        Ok(vault_rel)
    }

    pub fn remove_vault_file(&self, vault_rel_path: &Path) {
        let target_file = self.vault_dir.join(vault_rel_path);
        let _ = fs::remove_file(&target_file);

        if let Some(thumb_name) = get_thumbnail_valv_name(&vault_rel_path.to_string_lossy()) {
            let _ = fs::remove_file(self.vault_dir.join(thumb_name));
        }

        if let Some(parent_dir) = target_file.parent() {
            clean_empty_dirs_up_to(&self.vault_dir, parent_dir);
        }
    }

    pub fn remove_vault_dir(&self, vault_rel_path: &Path) {
        let _ = fs::remove_dir(self.vault_dir.join(vault_rel_path));
    }

    pub fn create_vault_dir(&self, vault_rel_path: &Path) {
        let _ = fs::create_dir_all(self.vault_dir.join(vault_rel_path));
    }
}
