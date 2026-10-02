#[cfg(feature = "fuse")]
pub mod fs {
    use std::collections::HashMap;
    use std::ffi::OsStr;
    use std::fs::{self, File};
    use std::io::{BufRead, BufReader, BufWriter, Cursor, Write};
    use std::path::{Path, PathBuf};
    use std::time::{Duration, SystemTime};

    use fuser::{
        FileAttr, FileType, Filesystem, MountOption, ReplyAttr, ReplyCreate, ReplyData,
        ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyOpen, ReplyStatfs, ReplyWrite, Request,
        TimeOrNow, FUSE_ROOT_ID,
    };

    use crate::ValvError;
    use crate::config::AgeVaultManifest;
    use crate::crypto::{
        decrypt_file_with_credentials_to, decrypt_header_with_credentials, encrypt_stream_unified,
        load_identities, load_recipients, Credentials, EncryptionMethod, VaultFormat, BUFFER_SIZE,
    };
    use crate::vault::paths::{
        clean_empty_dirs_up_to, collect_vault_files, generate_random_filename,
        get_suffix_for_path_and_format, get_thumbnail_valv_name, sanitize_filename,
    };
    use crate::vault::session::{is_process_alive, SessionFileEntry, ValvSession};
    use crate::vault::thumbnail::create_thumbnail_file_unified;

    const TTL: Duration = Duration::from_secs(1);

    #[derive(Debug, Clone)]
    pub struct InodeEntry {
        pub ino: u64,
        pub parent: u64,
        pub name: String,
        pub is_dir: bool,
        pub vault_rel_path: Option<PathBuf>,
        pub size: u64,
        pub mtime: SystemTime,
        pub format: VaultFormat,
        pub children: Vec<u64>,
    }

    pub struct OpenHandle {
        pub ino: u64,
        pub is_write: bool,
        pub buffer: Option<Vec<u8>>,
        pub modified: bool,
    }

    pub struct ValvFuseFs {
        pub vault_dir: PathBuf,
        pub password: Option<Vec<u8>>,
        pub default_format: VaultFormat,
        pub iterations: u32,
        pub recipient_strings: Vec<String>,
        pub recipient_files: Vec<PathBuf>,
        pub identity_paths: Vec<PathBuf>,
        pub watch_pid: Option<u32>,
        pub next_ino: u64,
        pub next_fh: u64,
        pub inodes: HashMap<u64, InodeEntry>,
        pub open_handles: HashMap<u64, OpenHandle>,
        pub read_cache: HashMap<u64, (Vec<u8>, SystemTime)>,
    }

    impl ValvFuseFs {
        pub fn new(
            vault_dir: &Path,
            password: Option<Vec<u8>>,
            default_format: VaultFormat,
            iterations: u32,
            recipient_strings: Vec<String>,
            recipient_files: Vec<PathBuf>,
            identity_paths: Vec<PathBuf>,
            watch_pid: Option<u32>,
        ) -> Result<Self, ValvError> {
            let mut fs = Self {
                vault_dir: fs::canonicalize(vault_dir).unwrap_or_else(|_| vault_dir.to_path_buf()),
                password,
                default_format,
                iterations,
                recipient_strings,
                recipient_files,
                identity_paths,
                watch_pid,
                next_ino: FUSE_ROOT_ID + 1,
                next_fh: 1,
                inodes: HashMap::new(),
                open_handles: HashMap::new(),
                read_cache: HashMap::new(),
            };

            // Root inode
            fs.inodes.insert(
                FUSE_ROOT_ID,
                InodeEntry {
                    ino: FUSE_ROOT_ID,
                    parent: FUSE_ROOT_ID,
                    name: "".to_string(),
                    is_dir: true,
                    vault_rel_path: Some(PathBuf::new()),
                    size: 0,
                    mtime: SystemTime::now(),
                    format: default_format,
                    children: Vec::new(),
                },
            );

            fs.scan_vault()?;
            Ok(fs)
        }

        pub fn get_credentials(&self) -> Credentials {
            let identities = load_identities(&self.identity_paths).unwrap_or_default();
            let mut creds = Credentials::new().with_identities(identities);
            if let Some(ref pwd) = self.password {
                creds.password = Some(pwd.clone());
            }
            creds
        }

        fn allocate_ino(&mut self) -> u64 {
            let ino = self.next_ino;
            self.next_ino += 1;
            ino
        }

        fn allocate_fh(&mut self) -> u64 {
            let fh = self.next_fh;
            self.next_fh += 1;
            fh
        }

        fn find_child_ino(&self, parent: u64, name: &str) -> Option<u64> {
            let parent_entry = self.inodes.get(&parent)?;
            for &child_ino in &parent_entry.children {
                if let Some(child) = self.inodes.get(&child_ino) {
                    if child.name == name {
                        return Some(child_ino);
                    }
                }
            }
            None
        }

        fn ensure_dir_path(&mut self, rel_dir: &Path) -> u64 {
            if rel_dir.as_os_str().is_empty() {
                return FUSE_ROOT_ID;
            }

            let mut current_ino = FUSE_ROOT_ID;
            for component in rel_dir.iter() {
                let name = component.to_string_lossy().to_string();
                if let Some(child_ino) = self.find_child_ino(current_ino, &name) {
                    current_ino = child_ino;
                } else {
                    let new_ino = self.allocate_ino();
                    let parent_rel = self
                        .inodes
                        .get(&current_ino)
                        .and_then(|p| p.vault_rel_path.clone())
                        .unwrap_or_default();
                    let vault_rel = parent_rel.join(&name);

                    self.inodes.insert(
                        new_ino,
                        InodeEntry {
                            ino: new_ino,
                            parent: current_ino,
                            name: name.clone(),
                            is_dir: true,
                            vault_rel_path: Some(vault_rel),
                            size: 0,
                            mtime: SystemTime::now(),
                            format: self.default_format,
                            children: Vec::new(),
                        },
                    );

                    if let Some(parent_entry) = self.inodes.get_mut(&current_ino) {
                        parent_entry.children.push(new_ino);
                    }
                    current_ino = new_ino;
                }
            }

            current_ino
        }

        pub fn scan_vault(&mut self) -> Result<(), ValvError> {
            let creds = self.get_credentials();

            // 1. Check for manifest
            if let Some(manifest_path) = AgeVaultManifest::find_in_dir(&self.vault_dir) {
                let (_, content) = AgeVaultManifest::load_from_file_with_credentials(
                    &manifest_path,
                    &creds,
                )
                .map_err(|e| {
                    ValvError::Message(format!("Failed to decrypt vault manifest: {}", e), 1)
                })?;

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

                let manifest_ino = self.allocate_ino();
                self.inodes.insert(
                    manifest_ino,
                    InodeEntry {
                        ino: manifest_ino,
                        parent: FUSE_ROOT_ID,
                        name: orig_name.to_string(),
                        is_dir: false,
                        vault_rel_path: Some(rel_path),
                        size: content.len() as u64,
                        mtime: fs::metadata(&manifest_path)
                            .and_then(|m| m.modified())
                            .unwrap_or_else(|_| SystemTime::now()),
                        format: self.default_format,
                        children: Vec::new(),
                    },
                );

                if let Some(root) = self.inodes.get_mut(&FUSE_ROOT_ID) {
                    root.children.push(manifest_ino);
                }
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
                let parent_ino = self.ensure_dir_path(rel_dir);

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

                let ino = self.allocate_ino();
                self.inodes.insert(
                    ino,
                    InodeEntry {
                        ino,
                        parent: parent_ino,
                        name: orig_name.clone(),
                        is_dir: false,
                        vault_rel_path: Some(rel_path.clone()),
                        size,
                        mtime,
                        format: file_format,
                        children: Vec::new(),
                    },
                );

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
                    self.read_cache.insert(ino, (content, mtime));
                }

                if let Some(parent_entry) = self.inodes.get_mut(&parent_ino) {
                    parent_entry.children.push(ino);
                }
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
                let session_ino = self.allocate_ino();
                let session_bytes = session_json.into_bytes();
                let now = SystemTime::now();
                self.inodes.insert(
                    session_ino,
                    InodeEntry {
                        ino: session_ino,
                        parent: FUSE_ROOT_ID,
                        name: ".valv_session.json".to_string(),
                        is_dir: false,
                        vault_rel_path: None,
                        size: session_bytes.len() as u64,
                        mtime: now,
                        format: self.default_format,
                        children: Vec::new(),
                    },
                );
                self.read_cache.insert(session_ino, (session_bytes, now));
                if let Some(root) = self.inodes.get_mut(&FUSE_ROOT_ID) {
                    root.children.push(session_ino);
                }
            }

            Ok(())
        }

        fn get_attr_for_inode(&self, ino: u64) -> Option<FileAttr> {
            let entry = self.inodes.get(&ino)?;
            let kind = if entry.is_dir {
                FileType::Directory
            } else {
                FileType::RegularFile
            };
            let perm = if entry.is_dir { 0o700 } else { 0o600 };
            let blocks = (entry.size + 511) / 512;

            #[cfg(unix)]
            let (uid, gid) = (unsafe { libc::getuid() }, unsafe { libc::getgid() });
            #[cfg(not(unix))]
            let (uid, gid) = (1000, 1000);

            Some(FileAttr {
                ino,
                size: entry.size,
                blocks,
                atime: entry.mtime,
                mtime: entry.mtime,
                ctime: entry.mtime,
                crtime: entry.mtime,
                kind,
                perm,
                nlink: if entry.is_dir { 2 } else { 1 },
                uid,
                gid,
                rdev: 0,
                flags: 0,
                blksize: 4096,
            })
        }

        fn read_file_content(&mut self, ino: u64) -> Result<Vec<u8>, libc::c_int> {
            for handle in self.open_handles.values() {
                if handle.ino == ino {
                    if let Some(ref buf) = handle.buffer {
                        return Ok(buf.clone());
                    }
                }
            }

            if let Some((cached, _)) = self.read_cache.get(&ino) {
                return Ok(cached.clone());
            }

            let entry = match self.inodes.get(&ino) {
                Some(e) => e.clone(),
                None => return Err(libc::ENOENT),
            };

            let rel_path = match entry.vault_rel_path {
                Some(ref p) => p,
                None => return Ok(Vec::new()),
            };
            let full_path = self.vault_dir.join(rel_path);

            let creds = self.get_credentials();
            let mut out = Vec::new();
            if crate::config::is_manifest_file(&full_path) {
                if let Ok((_, content)) =
                    AgeVaultManifest::load_from_file_with_credentials(&full_path, &creds)
                {
                    out = content.into_bytes();
                }
            } else if decrypt_file_with_credentials_to(&full_path, &creds, &mut out).is_err() {
                return Err(libc::EIO);
            }

            self.read_cache.insert(ino, (out.clone(), entry.mtime));
            Ok(out)
        }

        fn save_file_to_vault(&mut self, ino: u64, buffer: &[u8]) -> Result<(), libc::c_int> {
            let entry = match self.inodes.get(&ino) {
                Some(e) => e.clone(),
                None => return Err(libc::ENOENT),
            };

            let is_manifest = entry.name == ".age_vault.toml" || entry.name == "age_vault.toml";
            let format = entry.format;

            let recipients = load_recipients(&self.recipient_strings, &self.recipient_files)
                .unwrap_or_default();
            let method = if format == VaultFormat::Age || !recipients.is_empty() {
                if !recipients.is_empty() {
                    EncryptionMethod::AgeRecipients(&recipients)
                } else if let Some(ref pwd) = self.password
                    && let Ok(pwd_str) = std::str::from_utf8(pwd)
                {
                    EncryptionMethod::AgePassphrase(pwd_str)
                } else {
                    return Err(libc::EACCES);
                }
            } else if let Some(ref pwd) = self.password {
                EncryptionMethod::ValvPassphrase {
                    password: pwd,
                    iterations: self.iterations,
                }
            } else {
                return Err(libc::EACCES);
            };

            let vault_rel = match entry.vault_rel_path {
                Some(p) => p,
                None => {
                    let suffix = get_suffix_for_path_and_format(Path::new(&entry.name), format);
                    let random_name = generate_random_filename(suffix);
                    let parent_rel = self
                        .inodes
                        .get(&entry.parent)
                        .and_then(|p| p.vault_rel_path.clone())
                        .unwrap_or_default();
                    parent_rel.join(random_name)
                }
            };

            let dest_path = self.vault_dir.join(&vault_rel);
            if let Some(parent) = dest_path.parent() {
                let _ = fs::create_dir_all(parent);
            }

            let out_file = match File::create(&dest_path) {
                Ok(f) => f,
                Err(_) => return Err(libc::EIO),
            };
            let mut out_writer = BufWriter::with_capacity(BUFFER_SIZE, out_file);

            if encrypt_stream_unified(
                &mut Cursor::new(buffer),
                &mut out_writer,
                &entry.name,
                &method,
            )
            .is_err()
            {
                let _ = fs::remove_file(&dest_path);
                return Err(libc::EIO);
            }
            let _ = out_writer.flush();

            if let Some(thumb_name) =
                get_thumbnail_valv_name(&vault_rel.to_string_lossy())
            {
                let thumb_path = self.vault_dir.join(&thumb_name);
                let _ = create_thumbnail_file_unified(
                    &dest_path,
                    &thumb_path,
                    &entry.name,
                    &method,
                );
            }

            let now = SystemTime::now();
            if let Some(inode_entry) = self.inodes.get_mut(&ino) {
                inode_entry.vault_rel_path = Some(vault_rel);
                inode_entry.size = buffer.len() as u64;
                inode_entry.mtime = now;
            }

            self.read_cache.insert(ino, (buffer.to_vec(), now));

            if is_manifest {
                if let Ok(content_str) = std::str::from_utf8(buffer)
                    && let Ok(manifest) = toml::from_str::<AgeVaultManifest>(content_str)
                {
                    let (r_strs, r_files) = manifest.resolve_recipients();
                    self.recipient_strings = r_strs;
                    self.recipient_files = r_files;
                }
            }

            Ok(())
        }
    }

    impl Filesystem for ValvFuseFs {
        fn init(
            &mut self,
            _req: &Request<'_>,
            _config: &mut fuser::KernelConfig,
        ) -> Result<(), libc::c_int> {
            Ok(())
        }

        fn lookup(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEntry) {
            let name_str = name.to_string_lossy().to_string();
            if let Some(child_ino) = self.find_child_ino(parent, &name_str) {
                if let Some(attr) = self.get_attr_for_inode(child_ino) {
                    reply.entry(&TTL, &attr, 0);
                    return;
                }
            }
            reply.error(libc::ENOENT);
        }

        fn getattr(&mut self, _req: &Request<'_>, ino: u64, _fh: Option<u64>, reply: ReplyAttr) {
            if let Some(attr) = self.get_attr_for_inode(ino) {
                reply.attr(&TTL, &attr);
            } else {
                reply.error(libc::ENOENT);
            }
        }

        fn setattr(
            &mut self,
            _req: &Request<'_>,
            ino: u64,
            _mode: Option<u32>,
            _uid: Option<u32>,
            _gid: Option<u32>,
            size: Option<u64>,
            _atime: Option<TimeOrNow>,
            _mtime: Option<TimeOrNow>,
            _ctime: Option<SystemTime>,
            fh: Option<u64>,
            _crtime: Option<SystemTime>,
            _chgtime: Option<SystemTime>,
            _bkuptime: Option<SystemTime>,
            _flags: Option<u32>,
            reply: ReplyAttr,
        ) {
            if let Some(new_size) = size {
                let mut content = None;
                if let Some(handle_id) = fh
                    && let Some(handle) = self.open_handles.get_mut(&handle_id)
                {
                    if let Some(ref mut buf) = handle.buffer {
                        buf.resize(new_size as usize, 0);
                        handle.modified = true;
                        content = Some(buf.clone());
                    }
                } else {
                    let mut found_handle = false;
                    for handle in self.open_handles.values_mut() {
                        if handle.ino == ino {
                            if let Some(ref mut buf) = handle.buffer {
                                buf.resize(new_size as usize, 0);
                                handle.modified = true;
                                content = Some(buf.clone());
                                found_handle = true;
                                break;
                            }
                        }
                    }
                    if !found_handle {
                        if let Ok(mut c) = self.read_file_content(ino) {
                            c.resize(new_size as usize, 0);
                            content = Some(c);
                        }
                    }
                }

                if let Some(c) = content {
                    let _ = self.save_file_to_vault(ino, &c);
                }

                if let Some(entry) = self.inodes.get_mut(&ino) {
                    entry.size = new_size;
                    entry.mtime = SystemTime::now();
                }
            }

            if let Some(attr) = self.get_attr_for_inode(ino) {
                reply.attr(&TTL, &attr);
            } else {
                reply.error(libc::ENOENT);
            }
        }

        fn readdir(
            &mut self,
            _req: &Request<'_>,
            ino: u64,
            _fh: u64,
            offset: i64,
            mut reply: ReplyDirectory,
        ) {
            let entry = match self.inodes.get(&ino) {
                Some(e) if e.is_dir => e.clone(),
                _ => {
                    reply.error(libc::ENOTDIR);
                    return;
                }
            };

            let mut entries: Vec<(u64, FileType, String)> = Vec::new();
            entries.push((ino, FileType::Directory, ".".to_string()));
            entries.push((entry.parent, FileType::Directory, "..".to_string()));

            for &child_ino in &entry.children {
                if let Some(child) = self.inodes.get(&child_ino) {
                    let kind = if child.is_dir {
                        FileType::Directory
                    } else {
                        FileType::RegularFile
                    };
                    entries.push((child_ino, kind, child.name.clone()));
                }
            }

            for (i, (child_ino, kind, name)) in entries.into_iter().enumerate().skip(offset as usize)
            {
                if reply.add(child_ino, (i + 1) as i64, kind, name) {
                    break;
                }
            }
            reply.ok();
        }

        fn open(&mut self, _req: &Request<'_>, ino: u64, flags: i32, reply: ReplyOpen) {
            let is_write = (flags & libc::O_ACCMODE) == libc::O_WRONLY
                || (flags & libc::O_ACCMODE) == libc::O_RDWR
                || (flags & libc::O_APPEND) != 0;

            let buffer = if is_write {
                if (flags & libc::O_TRUNC) != 0 {
                    Some(Vec::new())
                } else {
                    Some(self.read_file_content(ino).unwrap_or_default())
                }
            } else {
                None
            };

            let fh = self.allocate_fh();
            self.open_handles.insert(
                fh,
                OpenHandle {
                    ino,
                    is_write,
                    buffer,
                    modified: (flags & libc::O_TRUNC) != 0,
                },
            );

            reply.opened(fh, 0);
        }

        fn read(
            &mut self,
            _req: &Request<'_>,
            ino: u64,
            fh: u64,
            offset: i64,
            size: u32,
            _flags: i32,
            _lock_owner: Option<u64>,
            reply: ReplyData,
        ) {
            let content = if let Some(handle) = self.open_handles.get(&fh)
                && let Some(ref buf) = handle.buffer
            {
                buf.clone()
            } else {
                match self.read_file_content(ino) {
                    Ok(c) => c,
                    Err(err) => {
                        reply.error(err);
                        return;
                    }
                }
            };

            let offset = offset as usize;
            if offset >= content.len() {
                reply.data(&[]);
            } else {
                let end = (offset + size as usize).min(content.len());
                reply.data(&content[offset..end]);
            }
        }

        fn write(
            &mut self,
            _req: &Request<'_>,
            ino: u64,
            fh: u64,
            offset: i64,
            data: &[u8],
            _write_flags: u32,
            _flags: i32,
            _lock_owner: Option<u64>,
            reply: ReplyWrite,
        ) {
            let handle = match self.open_handles.get_mut(&fh) {
                Some(h) => h,
                None => {
                    reply.error(libc::EBADF);
                    return;
                }
            };

            let buf = match handle.buffer.as_mut() {
                Some(b) => b,
                None => {
                    reply.error(libc::EBADF);
                    return;
                }
            };

            let offset = offset as usize;
            if offset + data.len() > buf.len() {
                buf.resize(offset + data.len(), 0);
            }

            buf[offset..offset + data.len()].copy_from_slice(data);
            handle.modified = true;

            let new_size = buf.len() as u64;
            if let Some(entry) = self.inodes.get_mut(&ino) {
                entry.size = new_size;
                entry.mtime = SystemTime::now();
            }

            reply.written(data.len() as u32);
        }

        fn flush(
            &mut self,
            _req: &Request<'_>,
            ino: u64,
            fh: u64,
            _lock_owner: u64,
            reply: ReplyEmpty,
        ) {
            let buf_to_save = if let Some(handle) = self.open_handles.get_mut(&fh) {
                if handle.is_write && handle.modified {
                    handle.modified = false;
                    handle.buffer.clone()
                } else {
                    None
                }
            } else {
                None
            };

            if let Some(buf) = buf_to_save {
                if let Err(err) = self.save_file_to_vault(ino, &buf) {
                    reply.error(err);
                    return;
                }
            }
            reply.ok();
        }

        fn release(
            &mut self,
            _req: &Request<'_>,
            ino: u64,
            fh: u64,
            _flags: i32,
            _lock_owner: Option<u64>,
            _flush: bool,
            reply: ReplyEmpty,
        ) {
            if let Some(handle) = self.open_handles.remove(&fh) {
                if handle.is_write && handle.modified {
                    if let Some(ref buf) = handle.buffer {
                        let _ = self.save_file_to_vault(ino, buf);
                    }
                }
            }
            reply.ok();
        }

        fn create(
            &mut self,
            _req: &Request<'_>,
            parent: u64,
            name: &OsStr,
            _mode: u32,
            _umask: u32,
            _flags: i32,
            reply: ReplyCreate,
        ) {
            let name_str = name.to_string_lossy().to_string();

            let ino = if let Some(existing_ino) = self.find_child_ino(parent, &name_str) {
                if let Some(entry) = self.inodes.get_mut(&existing_ino) {
                    entry.size = 0;
                    entry.mtime = SystemTime::now();
                }
                self.read_cache.insert(existing_ino, (Vec::new(), SystemTime::now()));
                existing_ino
            } else {
                let new_ino = self.allocate_ino();
                self.inodes.insert(
                    new_ino,
                    InodeEntry {
                        ino: new_ino,
                        parent,
                        name: name_str,
                        is_dir: false,
                        vault_rel_path: None,
                        size: 0,
                        mtime: SystemTime::now(),
                        format: self.default_format,
                        children: Vec::new(),
                    },
                );

                if let Some(parent_entry) = self.inodes.get_mut(&parent) {
                    parent_entry.children.push(new_ino);
                }
                new_ino
            };

            let fh = self.allocate_fh();
            self.open_handles.insert(
                fh,
                OpenHandle {
                    ino,
                    is_write: true,
                    buffer: Some(Vec::new()),
                    modified: true,
                },
            );

            if let Some(attr) = self.get_attr_for_inode(ino) {
                reply.created(&TTL, &attr, 0, fh, 0);
            } else {
                reply.error(libc::EIO);
            }
        }

        fn mkdir(
            &mut self,
            _req: &Request<'_>,
            parent: u64,
            name: &OsStr,
            _mode: u32,
            _umask: u32,
            reply: ReplyEntry,
        ) {
            let name_str = name.to_string_lossy().to_string();
            let ino = self.allocate_ino();

            let parent_rel = self
                .inodes
                .get(&parent)
                .and_then(|p| p.vault_rel_path.clone())
                .unwrap_or_default();
            let vault_rel = parent_rel.join(&name_str);
            let _ = fs::create_dir_all(self.vault_dir.join(&vault_rel));

            self.inodes.insert(
                ino,
                InodeEntry {
                    ino,
                    parent,
                    name: name_str,
                    is_dir: true,
                    vault_rel_path: Some(vault_rel),
                    size: 0,
                    mtime: SystemTime::now(),
                    format: self.default_format,
                    children: Vec::new(),
                },
            );

            if let Some(parent_entry) = self.inodes.get_mut(&parent) {
                parent_entry.children.push(ino);
            }

            if let Some(attr) = self.get_attr_for_inode(ino) {
                reply.entry(&TTL, &attr, 0);
            } else {
                reply.error(libc::EIO);
            }
        }

        fn rmdir(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
            let name_str = name.to_string_lossy().to_string();
            let child_ino = match self.find_child_ino(parent, &name_str) {
                Some(i) => i,
                None => {
                    reply.error(libc::ENOENT);
                    return;
                }
            };

            let entry = match self.inodes.get(&child_ino) {
                Some(e) if e.is_dir => e.clone(),
                Some(_) => {
                    reply.error(libc::ENOTDIR);
                    return;
                }
                None => {
                    reply.error(libc::ENOENT);
                    return;
                }
            };

            if !entry.children.is_empty() {
                reply.error(libc::ENOTEMPTY);
                return;
            }

            if let Some(ref rel_p) = entry.vault_rel_path {
                let _ = fs::remove_dir(self.vault_dir.join(rel_p));
            }

            if let Some(parent_entry) = self.inodes.get_mut(&parent) {
                parent_entry.children.retain(|&i| i != child_ino);
            }
            self.inodes.remove(&child_ino);

            reply.ok();
        }

        fn unlink(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
            let name_str = name.to_string_lossy().to_string();
            let child_ino = match self.find_child_ino(parent, &name_str) {
                Some(i) => i,
                None => {
                    reply.error(libc::ENOENT);
                    return;
                }
            };

            let entry = match self.inodes.get(&child_ino) {
                Some(e) if !e.is_dir => e.clone(),
                Some(_) => {
                    reply.error(libc::EISDIR);
                    return;
                }
                None => {
                    reply.error(libc::ENOENT);
                    return;
                }
            };

            if let Some(ref rel_p) = entry.vault_rel_path {
                let target_file = self.vault_dir.join(rel_p);
                let _ = fs::remove_file(&target_file);

                if let Some(thumb_name) =
                    get_thumbnail_valv_name(&rel_p.to_string_lossy())
                {
                    let _ = fs::remove_file(self.vault_dir.join(thumb_name));
                }

                if let Some(parent_dir) = target_file.parent() {
                    clean_empty_dirs_up_to(&self.vault_dir, parent_dir);
                }
            }

            if let Some(parent_entry) = self.inodes.get_mut(&parent) {
                parent_entry.children.retain(|&i| i != child_ino);
            }
            self.inodes.remove(&child_ino);
            self.read_cache.remove(&child_ino);

            reply.ok();
        }

        fn rename(
            &mut self,
            _req: &Request<'_>,
            parent: u64,
            name: &OsStr,
            newparent: u64,
            newname: &OsStr,
            _flags: u32,
            reply: ReplyEmpty,
        ) {
            let name_str = name.to_string_lossy().to_string();
            let newname_str = newname.to_string_lossy().to_string();

            let child_ino = match self.find_child_ino(parent, &name_str) {
                Some(i) => i,
                None => {
                    reply.error(libc::ENOENT);
                    return;
                }
            };

            if let Some(existing_dest_ino) = self.find_child_ino(newparent, &newname_str) {
                if let Some(parent_entry) = self.inodes.get_mut(&newparent) {
                    parent_entry.children.retain(|&i| i != existing_dest_ino);
                }
                if let Some(existing_entry) = self.inodes.remove(&existing_dest_ino) {
                    if let Some(ref rel_p) = existing_entry.vault_rel_path {
                        let target_file = self.vault_dir.join(rel_p);
                        let _ = fs::remove_file(&target_file);
                        if let Some(thumb_name) =
                            get_thumbnail_valv_name(&rel_p.to_string_lossy())
                        {
                            let _ = fs::remove_file(self.vault_dir.join(thumb_name));
                        }
                        if let Some(p_dir) = target_file.parent() {
                            clean_empty_dirs_up_to(&self.vault_dir, p_dir);
                        }
                    }
                }
                self.read_cache.remove(&existing_dest_ino);
            }

            if parent != newparent {
                if let Some(parent_entry) = self.inodes.get_mut(&parent) {
                    parent_entry.children.retain(|&i| i != child_ino);
                }
                if let Some(newparent_entry) = self.inodes.get_mut(&newparent) {
                    newparent_entry.children.push(child_ino);
                }
            }

            let is_dir = self.inodes.get(&child_ino).map(|e| e.is_dir).unwrap_or(false);

            if let Some(entry) = self.inodes.get_mut(&child_ino) {
                entry.parent = newparent;
                entry.name = newname_str.clone();
                entry.mtime = SystemTime::now();
            }

            if !is_dir {
                if let Ok(content) = self.read_file_content(child_ino) {
                    let _ = self.save_file_to_vault(child_ino, &content);
                }
            }

            reply.ok();
        }

        fn statfs(&mut self, _req: &Request<'_>, _ino: u64, reply: ReplyStatfs) {
            reply.statfs(1_000_000, 1_000_000, 1_000_000, 1_000_000, 1_000_000, 512, 255, 0);
        }
    }

    pub fn has_fuse_support() -> bool {
        Path::new("/dev/fuse").exists()
            && fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open("/dev/fuse")
                .is_ok()
    }

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

    #[cfg(test)]
    mod tests {
        use age::secrecy::ExposeSecret;
        use super::*;
        use crate::crypto::{encrypt_stream, encrypt_stream_unified, EncryptionMethod};
        use rand::RngExt;
        use std::io::Cursor;

        #[test]
        fn test_has_fuse_support() {
            let _ = has_fuse_support();
        }

        #[test]
        fn test_fuse_mount_read_write_lifecycle() {
            if !has_fuse_support() {
                return;
            }

            let temp_dir = std::env::temp_dir().join(format!(
                "valv_fuse_test_{}",
                rand::rng().random::<u32>()
            ));
            let vault_dir = temp_dir.join("vault");
            let mount_dir = temp_dir.join("mount");
            fs::create_dir_all(&vault_dir).unwrap();
            fs::create_dir_all(&mount_dir).unwrap();

            let password = b"TestFusePass123";
            let file_path = vault_dir.join("hello-x.valv");
            let mut out = BufWriter::new(File::create(&file_path).unwrap());
            encrypt_stream(
                &mut Cursor::new(b"Hello from FUSE"),
                &mut out,
                password,
                "hello.txt",
                1000,
            )
            .unwrap();
            drop(out);

            let fs = ValvFuseFs::new(
                &vault_dir,
                Some(password.to_vec()),
                VaultFormat::Valv,
                1000,
                vec![],
                vec![],
                vec![],
                None,
            )
            .expect("ValvFuseFs creation");

            let options = vec![MountOption::FSName("valv_test".to_string())];

            let session = match fuser::spawn_mount2(fs, &mount_dir, &options) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("Skipping test: spawn_mount2 failed (maybe no /dev/fuse permissions): {}", e);
                    let _ = fs::remove_dir_all(&temp_dir);
                    return;
                }
            };

            // 1. Read existing file
            let mut read_success = false;
            for _ in 0..50 {
                if let Ok(content) = fs::read_to_string(mount_dir.join("hello.txt")) {
                    assert_eq!(content, "Hello from FUSE");
                    read_success = true;
                    break;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            assert!(read_success, "Should read hello.txt via FUSE");

            // 2. Read virtual .valv_session.json
            assert!(mount_dir.join(".valv_session.json").exists());
            let session_text = fs::read_to_string(mount_dir.join(".valv_session.json")).unwrap();
            assert!(session_text.contains("vault_dir"));

            // 3. Write new file
            let new_file = mount_dir.join("new_note.txt");
            fs::write(&new_file, b"brand new content in fuse").unwrap();

            // Verify readability through mount
            let read_back = fs::read_to_string(&new_file).unwrap();
            assert_eq!(read_back, "brand new content in fuse");

            // 4. Overwrite existing file in-place
            let hello_file = mount_dir.join("hello.txt");
            fs::write(&hello_file, b"Updated hello content").unwrap();
            let read_updated = fs::read_to_string(&hello_file).unwrap();
            assert_eq!(read_updated, "Updated hello content");

            // 5. Simulate editor atomic save (write to temp file then rename over target)
            let temp_edit = mount_dir.join("new_note.txt.tmp");
            fs::write(&temp_edit, b"Editor atomic save content").unwrap();
            fs::rename(&temp_edit, &new_file).unwrap();
            let read_renamed = fs::read_to_string(&new_file).unwrap();
            assert_eq!(read_renamed, "Editor atomic save content");

            // 6. Unmount
            drop(session);
            let _ = unmount_fuse_target(&mount_dir);

            // 7. Verify that vault_dir has exactly 2 files and decrypts to modified content
            let vault_files = collect_vault_files(&vault_dir);
            assert_eq!(vault_files.len(), 2, "Should have exactly 2 files (no orphans from rename/overwrite)");

            let creds = Credentials::new().with_password(password.to_vec());
            let mut decrypted_map = HashMap::new();
            for vf in &vault_files {
                let mut content = Vec::new();
                let f = File::open(vf).unwrap();
                let reader = BufReader::new(f);
                let header = decrypt_header_with_credentials(reader, &creds).unwrap();
                let orig_name = header.original_name.clone();
                let mut h = header;
                h.decrypt_payload(&mut content).unwrap();
                decrypted_map.insert(orig_name, String::from_utf8(content).unwrap());
            }

            assert_eq!(decrypted_map.get("hello.txt").unwrap(), "Updated hello content");
            assert_eq!(decrypted_map.get("new_note.txt").unwrap(), "Editor atomic save content");

            let _ = fs::remove_dir_all(&temp_dir);
        }

        #[test]
        fn test_fuse_age_vault_lifecycle() {
            if !has_fuse_support() {
                return;
            }

            let temp_dir = std::env::temp_dir().join(format!(
                "valv_fuse_age_test_{}",
                rand::rng().random::<u32>()
            ));
            let vault_dir = temp_dir.join("vault");
            let mount_dir = temp_dir.join("mount");
            fs::create_dir_all(&vault_dir).unwrap();
            fs::create_dir_all(&mount_dir).unwrap();

            let key = age::x25519::Identity::generate();
            let pubkey = key.to_public().to_string();
            let key_file = temp_dir.join("key.txt");
            fs::write(&key_file, format!("{}\n", key.to_string().expose_secret())).unwrap();

            let file_path = vault_dir.join("secret-x.age");
            let mut out = BufWriter::new(File::create(&file_path).unwrap());
            let recips = crate::crypto::load_recipients(&[pubkey.clone()], &[]).unwrap();
            encrypt_stream_unified(
                &mut Cursor::new(b"Age Secret Content"),
                &mut out,
                "secret.txt",
                &EncryptionMethod::AgeRecipients(&recips),
            )
            .unwrap();
            drop(out);

            let fs = ValvFuseFs::new(
                &vault_dir,
                None,
                VaultFormat::Age,
                1000,
                vec![pubkey],
                vec![],
                vec![key_file],
                None,
            )
            .expect("ValvFuseFs creation");

            let options = vec![MountOption::FSName("valv_age_test".to_string())];

            let session = match fuser::spawn_mount2(fs, &mount_dir, &options) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("Skipping test: spawn_mount2 failed: {}", e);
                    let _ = fs::remove_dir_all(&temp_dir);
                    return;
                }
            };

            let mut read_success = false;
            for _ in 0..50 {
                if let Ok(content) = fs::read_to_string(mount_dir.join("secret.txt")) {
                    assert_eq!(content, "Age Secret Content");
                    read_success = true;
                    break;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            assert!(read_success, "Should read secret.txt via Age FUSE");

            drop(session);
            let _ = unmount_fuse_target(&mount_dir);
            let _ = fs::remove_dir_all(&temp_dir);
        }
    }
}
