#[cfg(feature = "fuse")]
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

#[cfg(feature = "fuse")]
use fuser::{FUSE_ROOT_ID, FileAttr, FileType};

#[cfg(feature = "fuse")]
use crate::crypto::VaultFormat;

#[cfg(feature = "fuse")]
pub const TTL: Duration = Duration::from_secs(1);

#[cfg(feature = "fuse")]
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

#[cfg(feature = "fuse")]
#[derive(Debug, Clone)]
pub struct InodeTree {
    next_ino: u64,
    inodes: HashMap<u64, InodeEntry>,
}

#[cfg(feature = "fuse")]
impl InodeTree {
    pub fn new(default_format: VaultFormat) -> Self {
        let mut tree = Self {
            next_ino: FUSE_ROOT_ID + 1,
            inodes: HashMap::new(),
        };

        // Initialize root directory inode
        tree.inodes.insert(
            FUSE_ROOT_ID,
            InodeEntry {
                ino: FUSE_ROOT_ID,
                parent: FUSE_ROOT_ID,
                name: String::new(),
                is_dir: true,
                vault_rel_path: Some(PathBuf::new()),
                size: 0,
                mtime: SystemTime::now(),
                format: default_format,
                children: Vec::new(),
            },
        );

        tree
    }

    pub fn allocate_ino(&mut self) -> u64 {
        let ino = self.next_ino;
        self.next_ino += 1;
        ino
    }

    pub fn get(&self, ino: u64) -> Option<&InodeEntry> {
        self.inodes.get(&ino)
    }

    pub fn get_mut(&mut self, ino: u64) -> Option<&mut InodeEntry> {
        self.inodes.get_mut(&ino)
    }

    pub fn insert(&mut self, entry: InodeEntry) {
        self.inodes.insert(entry.ino, entry);
    }

    pub fn remove(&mut self, ino: u64) -> Option<InodeEntry> {
        self.inodes.remove(&ino)
    }

    pub fn inodes_map(&self) -> &HashMap<u64, InodeEntry> {
        &self.inodes
    }

    pub fn inodes_map_mut(&mut self) -> &mut HashMap<u64, InodeEntry> {
        &mut self.inodes
    }

    pub fn find_child(&self, parent: u64, name: &str) -> Option<u64> {
        let parent_entry = self.inodes.get(&parent)?;
        for &child_ino in &parent_entry.children {
            if let Some(child) = self.inodes.get(&child_ino)
                && child.name == name
            {
                return Some(child_ino);
            }
        }
        None
    }

    pub fn add_child(&mut self, parent: u64, child: u64) {
        if let Some(parent_entry) = self.inodes.get_mut(&parent)
            && !parent_entry.children.contains(&child)
        {
            parent_entry.children.push(child);
        }
    }

    pub fn remove_child(&mut self, parent: u64, child: u64) {
        if let Some(parent_entry) = self.inodes.get_mut(&parent) {
            parent_entry.children.retain(|&i| i != child);
        }
    }

    pub fn ensure_dir_path(&mut self, rel_dir: &Path, default_format: VaultFormat) -> u64 {
        if rel_dir.as_os_str().is_empty() {
            return FUSE_ROOT_ID;
        }

        let mut current_ino = FUSE_ROOT_ID;
        for component in rel_dir.iter() {
            let name = component.to_string_lossy().to_string();
            if let Some(child_ino) = self.find_child(current_ino, &name) {
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
                        format: default_format,
                        children: Vec::new(),
                    },
                );

                self.add_child(current_ino, new_ino);
                current_ino = new_ino;
            }
        }

        current_ino
    }

    pub fn get_file_attr(&self, ino: u64) -> Option<FileAttr> {
        let entry = self.inodes.get(&ino)?;
        let kind = if entry.is_dir {
            FileType::Directory
        } else {
            FileType::RegularFile
        };
        let perm = if entry.is_dir { 0o700 } else { 0o600 };
        let blocks = entry.size.div_ceil(512);

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

    pub fn read_dir_entries(&self, dir_ino: u64) -> Option<Vec<(u64, FileType, String)>> {
        let entry = match self.inodes.get(&dir_ino) {
            Some(e) if e.is_dir => e.clone(),
            _ => return None,
        };

        let mut entries = Vec::new();
        entries.push((dir_ino, FileType::Directory, ".".to_string()));
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

        Some(entries)
    }

    pub fn update_descendant_paths(&mut self, root_ino: u64, old_prefix: &Path, new_prefix: &Path) {
        let mut stack = vec![root_ino];
        while let Some(current_ino) = stack.pop() {
            if let Some(entry) = self.inodes.get_mut(&current_ino) {
                if let Some(ref p) = entry.vault_rel_path
                    && let Ok(suffix) = p.strip_prefix(old_prefix)
                {
                    entry.vault_rel_path = Some(new_prefix.join(suffix));
                }
                stack.extend_from_slice(&entry.children);
            }
        }
    }
}
