#[cfg(feature = "fuse")]
use std::collections::HashMap;
use std::time::SystemTime;

#[cfg(feature = "fuse")]
#[derive(Debug, Clone)]
pub struct OpenHandle {
    pub ino: u64,
    pub is_write: bool,
    pub buffer: Option<Vec<u8>>,
    pub modified: bool,
}

#[cfg(feature = "fuse")]
#[derive(Debug)]
pub struct HandleTable {
    next_fh: u64,
    handles: HashMap<u64, OpenHandle>,
    read_cache: HashMap<u64, (Vec<u8>, SystemTime)>,
}

#[cfg(feature = "fuse")]
impl Default for HandleTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "fuse")]
impl HandleTable {
    pub fn new() -> Self {
        Self {
            next_fh: 1,
            handles: HashMap::new(),
            read_cache: HashMap::new(),
        }
    }

    pub fn allocate_fh(&mut self) -> u64 {
        let fh = self.next_fh;
        self.next_fh += 1;
        fh
    }

    pub fn insert_handle(&mut self, handle: OpenHandle) -> u64 {
        let fh = self.allocate_fh();
        self.handles.insert(fh, handle);
        fh
    }

    pub fn create_handle(&mut self, ino: u64) -> u64 {
        self.insert_handle(OpenHandle {
            ino,
            is_write: true,
            buffer: Some(Vec::new()),
            modified: true,
        })
    }

    pub fn get_handle(&self, fh: u64) -> Option<&OpenHandle> {
        self.handles.get(&fh)
    }

    pub fn get_handle_mut(&mut self, fh: u64) -> Option<&mut OpenHandle> {
        self.handles.get_mut(&fh)
    }

    pub fn open_handles_map(&self) -> &HashMap<u64, OpenHandle> {
        &self.handles
    }

    pub fn open_handles_map_mut(&mut self) -> &mut HashMap<u64, OpenHandle> {
        &mut self.handles
    }

    pub fn read_cache_map(&self) -> &HashMap<u64, (Vec<u8>, SystemTime)> {
        &self.read_cache
    }

    pub fn read_cache_map_mut(&mut self) -> &mut HashMap<u64, (Vec<u8>, SystemTime)> {
        &mut self.read_cache
    }

    pub fn get_active_buffer(&self, fh: Option<u64>, ino: u64) -> Option<Vec<u8>> {
        if let Some(handle_id) = fh
            && let Some(handle) = self.handles.get(&handle_id)
            && let Some(ref buf) = handle.buffer
        {
            return Some(buf.clone());
        }

        for handle in self.handles.values() {
            if handle.ino == ino
                && let Some(ref buf) = handle.buffer
            {
                return Some(buf.clone());
            }
        }

        if let Some((cached, _)) = self.read_cache.get(&ino) {
            return Some(cached.clone());
        }

        None
    }

    pub fn write_to_handle(
        &mut self,
        fh: u64,
        offset: usize,
        data: &[u8],
    ) -> Result<usize, libc::c_int> {
        let handle = self.handles.get_mut(&fh).ok_or(libc::EBADF)?;
        let buf = handle.buffer.as_mut().ok_or(libc::EBADF)?;

        if offset + data.len() > buf.len() {
            buf.resize(offset + data.len(), 0);
        }

        buf[offset..offset + data.len()].copy_from_slice(data);
        handle.modified = true;
        Ok(data.len())
    }

    pub fn flush_handle(&mut self, fh: u64) -> Option<(u64, Vec<u8>)> {
        let handle = self.handles.get_mut(&fh)?;
        if handle.is_write && handle.modified {
            handle.modified = false;
            handle.buffer.as_ref().map(|b| (handle.ino, b.clone()))
        } else {
            None
        }
    }

    pub fn release_handle(&mut self, fh: u64) -> Option<(u64, Vec<u8>)> {
        let handle = self.handles.remove(&fh)?;
        if handle.is_write && handle.modified {
            handle.buffer.map(|b| (handle.ino, b))
        } else {
            None
        }
    }

    pub fn set_cache(&mut self, ino: u64, content: Vec<u8>, mtime: SystemTime) {
        self.read_cache.insert(ino, (content, mtime));
    }

    pub fn get_cached(&self, ino: u64) -> Option<&(Vec<u8>, SystemTime)> {
        self.read_cache.get(&ino)
    }

    pub fn invalidate_cache(&mut self, ino: u64) {
        self.read_cache.remove(&ino);
    }
}
