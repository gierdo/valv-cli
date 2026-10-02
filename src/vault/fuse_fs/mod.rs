#[cfg(feature = "fuse")]
pub mod driver;
#[cfg(feature = "fuse")]
pub mod handles;
#[cfg(feature = "fuse")]
pub mod inodes;
#[cfg(feature = "fuse")]
pub mod lifecycle;
#[cfg(feature = "fuse")]
pub mod storage;

#[cfg(feature = "fuse")]
pub mod fs {
    pub use super::driver::ValvFuseFs;
    pub use super::handles::OpenHandle;
    pub use super::inodes::InodeEntry;
    pub use super::lifecycle::{has_fuse_support, mount_fuse_vault, unmount_fuse_target};

    #[cfg(test)]
    mod tests {
        include!("tests.rs");
    }
}
