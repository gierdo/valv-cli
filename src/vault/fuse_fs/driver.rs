#[cfg(feature = "fuse")]
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

#[cfg(feature = "fuse")]
use fuser::{
    FileAttr, Filesystem, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory, ReplyEmpty,
    ReplyEntry, ReplyOpen, ReplyStatfs, ReplyWrite, Request, TimeOrNow,
};

#[cfg(feature = "fuse")]
use crate::ValvError;
#[cfg(feature = "fuse")]
use crate::crypto::{Credentials, VaultFormat};

#[cfg(feature = "fuse")]
use super::handles::{HandleTable, OpenHandle};
#[cfg(feature = "fuse")]
use super::inodes::{InodeEntry, InodeTree, TTL};
#[cfg(feature = "fuse")]
use super::storage::VaultStorage;
#[cfg(feature = "fuse")]
use crate::vault::paths::clean_empty_dirs_up_to;

#[cfg(feature = "fuse")]
pub struct ValvFuseFs {
    pub storage: VaultStorage,
    pub tree: InodeTree,
    pub handles: HandleTable,
}

#[cfg(feature = "fuse")]
impl ValvFuseFs {
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
    ) -> Result<Self, ValvError> {
        let mut storage = VaultStorage::new(
            vault_dir,
            password,
            default_format,
            iterations,
            recipient_strings,
            recipient_files,
            identity_paths,
            watch_pid,
        );
        let mut tree = InodeTree::new(default_format);
        let mut handles = HandleTable::new();

        storage.scan_vault(&mut tree, &mut handles)?;

        Ok(Self {
            storage,
            tree,
            handles,
        })
    }

    pub fn get_credentials(&self) -> Credentials {
        self.storage.get_credentials()
    }

    pub fn get_attr_for_inode(&self, ino: u64) -> Option<FileAttr> {
        self.tree.get_file_attr(ino)
    }

    pub fn scan_vault(&mut self) -> Result<(), ValvError> {
        self.storage.scan_vault(&mut self.tree, &mut self.handles)
    }

    pub fn read_file_content(&mut self, ino: u64) -> Result<Vec<u8>, libc::c_int> {
        if let Some(buf) = self.handles.get_active_buffer(None, ino) {
            return Ok(buf);
        }

        let entry = self.tree.get(ino).cloned().ok_or(libc::ENOENT)?;
        let is_manifest = entry.name == ".age_vault.toml" || entry.name == "age_vault.toml";
        let out = self
            .storage
            .read_file_content(entry.vault_rel_path.as_deref(), is_manifest)?;

        self.handles.set_cache(ino, out.clone(), entry.mtime);
        Ok(out)
    }

    pub fn save_file_to_vault(&mut self, ino: u64, buffer: &[u8]) -> Result<(), libc::c_int> {
        let entry = self.tree.get(ino).cloned().ok_or(libc::ENOENT)?;
        let parent_rel = self
            .tree
            .get(entry.parent)
            .and_then(|p| p.vault_rel_path.clone())
            .unwrap_or_default();

        let vault_rel = self.storage.save_file(
            &entry.name,
            &parent_rel,
            entry.vault_rel_path.as_deref(),
            entry.format,
            buffer,
        )?;

        let now = SystemTime::now();
        if let Some(inode_entry) = self.tree.get_mut(ino) {
            inode_entry.vault_rel_path = Some(vault_rel);
            inode_entry.size = buffer.len() as u64;
            inode_entry.mtime = now;
        }

        self.handles.set_cache(ino, buffer.to_vec(), now);
        Ok(())
    }
}

#[cfg(feature = "fuse")]
impl Filesystem for ValvFuseFs {
    fn init(
        &mut self,
        _req: &Request<'_>,
        _config: &mut fuser::KernelConfig,
    ) -> Result<(), libc::c_int> {
        Ok(())
    }

    fn lookup(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEntry) {
        let name_str = name.to_string_lossy();
        if let Some(child_ino) = self.tree.find_child(parent, &name_str)
            && let Some(attr) = self.tree.get_file_attr(child_ino)
        {
            reply.entry(&TTL, &attr, 0);
            return;
        }
        reply.error(libc::ENOENT);
    }

    fn getattr(&mut self, _req: &Request<'_>, ino: u64, _fh: Option<u64>, reply: ReplyAttr) {
        if let Some(attr) = self.tree.get_file_attr(ino) {
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
                && let Some(handle) = self.handles.get_handle_mut(handle_id)
            {
                if let Some(ref mut buf) = handle.buffer {
                    buf.resize(new_size as usize, 0);
                    handle.modified = true;
                    content = Some(buf.clone());
                }
            } else {
                let mut found_handle = false;
                for handle in self.handles.open_handles_map_mut().values_mut() {
                    if handle.ino == ino
                        && let Some(ref mut buf) = handle.buffer
                    {
                        buf.resize(new_size as usize, 0);
                        handle.modified = true;
                        content = Some(buf.clone());
                        found_handle = true;
                        break;
                    }
                }
                if !found_handle && let Ok(mut c) = self.read_file_content(ino) {
                    c.resize(new_size as usize, 0);
                    content = Some(c);
                }
            }

            if let Some(c) = content {
                let _ = self.save_file_to_vault(ino, &c);
            }

            if let Some(entry) = self.tree.get_mut(ino) {
                entry.size = new_size;
                entry.mtime = SystemTime::now();
            }
        }

        if let Some(attr) = self.tree.get_file_attr(ino) {
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
        let entries = match self.tree.read_dir_entries(ino) {
            Some(entries) => entries,
            None => {
                reply.error(libc::ENOTDIR);
                return;
            }
        };

        for (i, (child_ino, kind, name)) in entries.into_iter().enumerate().skip(offset as usize) {
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

        let fh = self.handles.insert_handle(OpenHandle {
            ino,
            is_write,
            buffer,
            modified: (flags & libc::O_TRUNC) != 0,
        });

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
        let content = match self.handles.get_active_buffer(Some(fh), ino) {
            Some(c) => c,
            None => match self.read_file_content(ino) {
                Ok(c) => c,
                Err(err) => {
                    reply.error(err);
                    return;
                }
            },
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
        let written = match self.handles.write_to_handle(fh, offset as usize, data) {
            Ok(n) => n,
            Err(err) => {
                reply.error(err);
                return;
            }
        };

        if let Some(entry) = self.tree.get_mut(ino)
            && let Some(handle) = self.handles.get_handle(fh)
            && let Some(ref buf) = handle.buffer
        {
            entry.size = buf.len() as u64;
            entry.mtime = SystemTime::now();
        }

        reply.written(written as u32);
    }

    fn flush(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        fh: u64,
        _lock_owner: u64,
        reply: ReplyEmpty,
    ) {
        if let Some((target_ino, buf)) = self.handles.flush_handle(fh)
            && let Err(err) = self.save_file_to_vault(target_ino, &buf)
        {
            reply.error(err);
            return;
        }
        reply.ok();
    }

    fn release(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        fh: u64,
        _flags: i32,
        _lock_owner: Option<u64>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        if let Some((target_ino, buf)) = self.handles.release_handle(fh) {
            let _ = self.save_file_to_vault(target_ino, &buf);
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

        let ino = if let Some(existing_ino) = self.tree.find_child(parent, &name_str) {
            if let Some(entry) = self.tree.get_mut(existing_ino) {
                entry.size = 0;
                entry.mtime = SystemTime::now();
            }
            self.handles
                .set_cache(existing_ino, Vec::new(), SystemTime::now());
            existing_ino
        } else {
            let new_ino = self.tree.allocate_ino();
            self.tree.insert(InodeEntry {
                ino: new_ino,
                parent,
                name: name_str,
                is_dir: false,
                vault_rel_path: None,
                size: 0,
                mtime: SystemTime::now(),
                format: self.storage.default_format,
                children: Vec::new(),
            });

            self.tree.add_child(parent, new_ino);
            new_ino
        };

        let fh = self.handles.create_handle(ino);

        if let Some(attr) = self.tree.get_file_attr(ino) {
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
        let ino = self.tree.allocate_ino();

        let parent_rel = self
            .tree
            .get(parent)
            .and_then(|p| p.vault_rel_path.clone())
            .unwrap_or_default();
        let vault_rel = parent_rel.join(&name_str);
        self.storage.create_vault_dir(&vault_rel);

        self.tree.insert(InodeEntry {
            ino,
            parent,
            name: name_str,
            is_dir: true,
            vault_rel_path: Some(vault_rel),
            size: 0,
            mtime: SystemTime::now(),
            format: self.storage.default_format,
            children: Vec::new(),
        });

        self.tree.add_child(parent, ino);

        if let Some(attr) = self.tree.get_file_attr(ino) {
            reply.entry(&TTL, &attr, 0);
        } else {
            reply.error(libc::EIO);
        }
    }

    fn rmdir(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        let name_str = name.to_string_lossy();
        let child_ino = match self.tree.find_child(parent, &name_str) {
            Some(i) => i,
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        let entry = match self.tree.get(child_ino) {
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
            self.storage.remove_vault_dir(rel_p);
        }

        self.tree.remove_child(parent, child_ino);
        self.tree.remove(child_ino);

        reply.ok();
    }

    fn unlink(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        let name_str = name.to_string_lossy();
        let child_ino = match self.tree.find_child(parent, &name_str) {
            Some(i) => i,
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        let entry = match self.tree.get(child_ino) {
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
            self.storage.remove_vault_file(rel_p);
        }

        self.tree.remove_child(parent, child_ino);
        self.tree.remove(child_ino);
        self.handles.invalidate_cache(child_ino);

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

        let child_ino = match self.tree.find_child(parent, &name_str) {
            Some(i) => i,
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        let is_dir = self.tree.get(child_ino).map(|e| e.is_dir).unwrap_or(false);

        // Check if destination exists
        if let Some(existing_dest_ino) = self.tree.find_child(newparent, &newname_str) {
            let dest_is_dir = self
                .tree
                .get(existing_dest_ino)
                .map(|e| e.is_dir)
                .unwrap_or(false);

            if is_dir && !dest_is_dir {
                reply.error(libc::ENOTDIR);
                return;
            }
            if !is_dir && dest_is_dir {
                reply.error(libc::EISDIR);
                return;
            }

            if dest_is_dir {
                let dest_entry = self.tree.get(existing_dest_ino).unwrap();
                if !dest_entry.children.is_empty() {
                    reply.error(libc::ENOTEMPTY);
                    return;
                }
                if let Some(ref rel_p) = dest_entry.vault_rel_path {
                    self.storage.remove_vault_dir(rel_p);
                }
            } else {
                let dest_entry = self.tree.get(existing_dest_ino).unwrap();
                if let Some(ref rel_p) = dest_entry.vault_rel_path {
                    self.storage.remove_vault_file(rel_p);
                }
            }

            self.tree.remove_child(newparent, existing_dest_ino);
            self.tree.remove(existing_dest_ino);
            self.handles.invalidate_cache(existing_dest_ino);
        }

        if is_dir {
            let old_vault_rel = self
                .tree
                .get(child_ino)
                .and_then(|e| e.vault_rel_path.clone())
                .unwrap_or_default();
            let new_parent_rel = self
                .tree
                .get(newparent)
                .and_then(|p| p.vault_rel_path.clone())
                .unwrap_or_default();
            let new_vault_rel = new_parent_rel.join(&newname_str);

            if old_vault_rel != new_vault_rel {
                let old_disk_path = self.storage.vault_dir.join(&old_vault_rel);
                let new_disk_path = self.storage.vault_dir.join(&new_vault_rel);
                if old_disk_path.exists() {
                    if let Some(parent_dir) = new_disk_path.parent() {
                        let _ = std::fs::create_dir_all(parent_dir);
                    }
                    if std::fs::rename(&old_disk_path, &new_disk_path).is_err() {
                        reply.error(libc::EIO);
                        return;
                    }
                    if let Some(parent_dir) = old_disk_path.parent() {
                        clean_empty_dirs_up_to(&self.storage.vault_dir, parent_dir);
                    }
                } else {
                    let _ = std::fs::create_dir_all(&new_disk_path);
                }

                self.tree
                    .update_descendant_paths(child_ino, &old_vault_rel, &new_vault_rel);
            }

            if parent != newparent {
                self.tree.remove_child(parent, child_ino);
                self.tree.add_child(newparent, child_ino);
            }

            if let Some(entry) = self.tree.get_mut(child_ino) {
                entry.parent = newparent;
                entry.name = newname_str;
                entry.vault_rel_path = Some(new_vault_rel);
                entry.mtime = SystemTime::now();
            }
        } else {
            let old_vault_rel = self
                .tree
                .get(child_ino)
                .and_then(|e| e.vault_rel_path.clone());
            let new_parent_rel = self
                .tree
                .get(newparent)
                .and_then(|p| p.vault_rel_path.clone())
                .unwrap_or_default();

            let content = match self.read_file_content(child_ino) {
                Ok(c) => c,
                Err(err) => {
                    reply.error(err);
                    return;
                }
            };

            if let Some(ref old_rel) = old_vault_rel {
                self.storage.remove_vault_file(old_rel);
            }

            let entry_format = self
                .tree
                .get(child_ino)
                .map(|e| e.format)
                .unwrap_or(self.storage.default_format);

            let new_vault_rel = match self.storage.save_file(
                &newname_str,
                &new_parent_rel,
                None,
                entry_format,
                &content,
            ) {
                Ok(p) => p,
                Err(err) => {
                    reply.error(err);
                    return;
                }
            };

            if parent != newparent {
                self.tree.remove_child(parent, child_ino);
                self.tree.add_child(newparent, child_ino);
            }

            let now = SystemTime::now();
            if let Some(entry) = self.tree.get_mut(child_ino) {
                entry.parent = newparent;
                entry.name = newname_str;
                entry.vault_rel_path = Some(new_vault_rel);
                entry.size = content.len() as u64;
                entry.mtime = now;
            }

            self.handles.set_cache(child_ino, content, now);
        }

        reply.ok();
    }

    fn statfs(&mut self, _req: &Request<'_>, _ino: u64, reply: ReplyStatfs) {
        reply.statfs(
            1_000_000, 1_000_000, 1_000_000, 1_000_000, 1_000_000, 512, 255, 0,
        );
    }
}
