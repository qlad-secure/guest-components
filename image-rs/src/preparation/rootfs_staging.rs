// SPDX-License-Identifier: Apache-2.0

//! Mutable, attempt-owned application of the strict checked TAR profile.
//!
//! The parent and this process must be trusted: mode 0700 and FD-relative I/O do
//! not isolate same-UID/root writers or hostile guest management. No root path or
//! FD is exported. This is not an immutable rootfs, builder result, mount, lease,
//! admission capability or permission to start a task.

use super::layer_content::{parse_ustar, CheckedLayerContent, TarEntry};
use nix::{
    errno::Errno,
    fcntl::{fcntl, openat, AtFlags, FcntlArg, FdFlag, OFlag},
    libc,
    sys::stat::{fchmod, fstat, fstatat, mkdirat, Mode},
    unistd::{unlinkat, UnlinkatFlags},
};
use std::{collections::BTreeMap, fs::File, os::fd::AsFd, os::unix::fs::FileExt};
use zeroize::Zeroizing;

#[cfg(feature = "launch-preparation-executable")]
use sha2::{Digest, Sha384};

#[cfg(feature = "launch-preparation-executable")]
#[path = "staging_executable.rs"]
mod executable;
#[cfg(feature = "launch-preparation-executable")]
pub use executable::{CheckedStagingExecutable, StagedExecutableError};

#[cfg(feature = "launch-preparation-erofs")]
#[path = "staging_builder.rs"]
mod builder;
#[cfg(feature = "launch-preparation-erofs")]
pub use builder::{BuilderInput, BuilderInputError, BuilderInputLimits};

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum RootfsStagingError {
    #[error("rootfs staging limits are invalid")]
    InvalidLimits,
    #[error("rootfs staging parent must be an owned private directory")]
    InvalidParent,
    #[error("rootfs staging exceeds its configured bounds")]
    TooLarge,
    #[error("rootfs staging requires consecutive original layer indices")]
    LayerOrder,
    #[error("rootfs staging rejected a checked archive")]
    ArchiveRejected,
    #[error("rootfs staging rejects file/directory replacement")]
    TypeCollision,
    #[error("rootfs staging filesystem operation failed")]
    FileOperation,
    #[error("rootfs staging cleanup failed")]
    CleanupFailed,
}

/// Trusted provisioning input, never a path selected by an image or host RPC.
/// The caller must exclude other writers to this directory and its children.
pub struct PrivateStagingParent(File);

impl PrivateStagingParent {
    pub fn new(directory: File) -> Result<Self, RootfsStagingError> {
        validate_parent(&directory)?;
        fcntl(&directory, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC))
            .map_err(|_| RootfsStagingError::FileOperation)?;
        Ok(Self(directory))
    }
}

/// Logical bounds, supplied by the trusted constructor without defaults. Inodes
/// include the root and implicit directories. Write bytes include overwritten
/// files; live bytes count the final file sizes. These are not disk-block quotas.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct RootfsStagingLimits {
    pub layers: usize,
    pub total_tar_bytes: usize,
    pub applied_entries: usize,
    pub inodes: usize,
    pub write_bytes: usize,
    pub live_file_bytes: usize,
    pub path_bytes: usize,
    pub path_components: usize,
}

impl RootfsStagingLimits {
    pub fn validate(self) -> Result<(), RootfsStagingError> {
        if [
            self.layers,
            self.total_tar_bytes,
            self.applied_entries,
            self.inodes,
            self.write_bytes,
            self.live_file_bytes,
            self.path_bytes,
            self.path_components,
        ]
        .iter()
        .any(|v| *v == 0 || *v > isize::MAX as usize)
        {
            return Err(RootfsStagingError::InvalidLimits);
        }
        Ok(())
    }
}

/// Desired archive metadata, not the mutable workspace's host metadata. Implicit
/// directories (including an unlisted root) use 0755/uid0/gid0/mtime0. A later
/// explicit directory entry replaces those desired values without chmod/chown.
pub struct StagedMetadata {
    is_dir: bool,
    mode: u32,
    uid: u64,
    gid: u64,
    mtime: u64,
}

impl StagedMetadata {
    pub fn is_dir(&self) -> bool {
        self.is_dir
    }
    pub fn mode(&self) -> u32 {
        self.mode
    }
    pub fn uid(&self) -> u64 {
        self.uid
    }
    pub fn gid(&self) -> u64 {
        self.gid
    }
    pub fn mtime(&self) -> u64 {
        self.mtime
    }

    fn implicit_directory() -> Self {
        Self {
            is_dir: true,
            mode: 0o755,
            uid: 0,
            gid: 0,
            mtime: 0,
        }
    }
}

struct StagedNode {
    metadata: StagedMetadata,
    size: usize,
    #[cfg(feature = "launch-preparation-executable")]
    identity: Option<(libc::dev_t, libc::ino_t)>,
    #[cfg(feature = "launch-preparation-executable")]
    payload_sha384: Option<[u8; 48]>,
}

#[derive(Debug, Eq, PartialEq)]
pub struct RootfsStagingSummary {
    layers: usize,
    total_tar_bytes: usize,
    applied_entries: usize,
    inodes: usize,
    write_bytes: usize,
    live_file_bytes: usize,
}

impl RootfsStagingSummary {
    pub fn layers(&self) -> usize {
        self.layers
    }
    pub fn total_tar_bytes(&self) -> usize {
        self.total_tar_bytes
    }
    pub fn applied_entries(&self) -> usize {
        self.applied_entries
    }
    pub fn inodes(&self) -> usize {
        self.inodes
    }
    pub fn write_bytes(&self) -> usize {
        self.write_bytes
    }
    pub fn live_file_bytes(&self) -> usize {
        self.live_file_bytes
    }
}

/// Sole owner of a fresh private mutable tree. Regular files replace regular
/// files; directories merge. Type changes and every unsupported TAR feature stay
/// rejected. Writers close before success, but directory contents remain mutable.
/// Drop attempts cleanup; explicit discard reports cleanup failures. A process
/// crash can leave an orphan: no restart/recovery or custody claim is made.
pub struct RootfsStaging {
    parent: File,
    name: String,
    root: File,
    nodes: BTreeMap<String, StagedNode>,
    summary: RootfsStagingSummary,
    cleaned: bool,
}

impl RootfsStaging {
    pub fn from_checked_layers(
        parent: PrivateStagingParent,
        layers: Vec<CheckedLayerContent>,
        limits: RootfsStagingLimits,
    ) -> Result<Self, RootfsStagingError> {
        limits.validate()?;
        validate_parent(&parent.0)?;
        if layers.is_empty() || layers.len() > limits.layers {
            return Err(RootfsStagingError::TooLarge);
        }
        let mut total_tar_bytes = 0usize;
        for (index, layer) in layers.iter().enumerate() {
            if usize::try_from(layer.original_index()).ok() != Some(index) {
                return Err(RootfsStagingError::LayerOrder);
            }
            let len =
                usize::try_from(layer.tar_byte_len()).map_err(|_| RootfsStagingError::TooLarge)?;
            total_tar_bytes = total_tar_bytes
                .checked_add(len)
                .filter(|v| *v <= limits.total_tar_bytes)
                .ok_or(RootfsStagingError::TooLarge)?;
        }
        let (name, root) = create_root(&parent.0)?;
        let mut staging = Self {
            parent: parent.0,
            name,
            root,
            nodes: BTreeMap::from([(
                ".".into(),
                StagedNode {
                    metadata: StagedMetadata::implicit_directory(),
                    size: 0,
                    #[cfg(feature = "launch-preparation-executable")]
                    identity: None,
                    #[cfg(feature = "launch-preparation-executable")]
                    payload_sha384: None,
                },
            )]),
            summary: RootfsStagingSummary {
                layers: layers.len(),
                total_tar_bytes,
                applied_entries: 0,
                inodes: 1,
                write_bytes: 0,
                live_file_bytes: 0,
            },
            cleaned: false,
        };
        #[cfg(feature = "launch-preparation-executable")]
        {
            let stat = fstat(&staging.root).map_err(|_| RootfsStagingError::FileOperation)?;
            staging
                .nodes
                .get_mut(".")
                .expect("root inventory exists")
                .identity = Some((stat.st_dev, stat.st_ino));
        }
        for layer in layers {
            // Bounds were checked before allocation; reads do not use shared FD
            // offsets. The original strict parser is reused, never a generic
            // unpacker. Only the immutable checked TAR capability reaches here.
            let len =
                usize::try_from(layer.tar_byte_len()).map_err(|_| RootfsStagingError::TooLarge)?;
            let mut tar = Zeroizing::new(vec![0; len]);
            let reader = File::from(
                layer
                    .sealed_tar()
                    .as_fd()
                    .try_clone_to_owned()
                    .map_err(|_| RootfsStagingError::FileOperation)?,
            );
            reader
                .read_exact_at(&mut tar, 0)
                .map_err(|_| RootfsStagingError::FileOperation)?;
            let entries = parse_ustar(&tar, layer.limits())
                .map_err(|_| RootfsStagingError::ArchiveRejected)?;
            for entry in entries {
                staging.apply_entry(entry, limits)?;
            }
        }
        Ok(staging)
    }

    pub fn summary(&self) -> &RootfsStagingSummary {
        &self.summary
    }

    /// Logical archive paths and desired metadata only; no workspace path/FD.
    pub fn metadata(&self) -> impl Iterator<Item = (&str, &StagedMetadata)> {
        self.nodes
            .iter()
            .map(|(path, node)| (path.as_str(), &node.metadata))
    }

    pub fn discard(mut self) -> Result<(), RootfsStagingError> {
        self.cleanup()
    }

    fn apply_entry(
        &mut self,
        entry: TarEntry<'_>,
        limits: RootfsStagingLimits,
    ) -> Result<(), RootfsStagingError> {
        if self.summary.applied_entries >= limits.applied_entries
            || entry.path.len() > limits.path_bytes
            || (entry.path != "." && entry.path.split('/').count() > limits.path_components)
            || entry.path.split('/').any(|part| part.len() > 255)
        {
            return Err(RootfsStagingError::TooLarge);
        }
        self.summary.applied_entries += 1;
        self.ensure_parents(&entry.path, limits)?;
        let old = self.nodes.get(&entry.path);
        if old.is_some_and(|node| node.metadata.is_dir != entry.is_dir) {
            return Err(RootfsStagingError::TypeCollision);
        }
        let metadata = StagedMetadata {
            is_dir: entry.is_dir,
            mode: entry.mode,
            uid: entry.uid,
            gid: entry.gid,
            mtime: entry.mtime,
        };
        if entry.is_dir {
            if old.is_none() {
                self.create_directory(&entry.path, limits)?;
            }
            self.nodes
                .get_mut(&entry.path)
                .expect("owned directory was inserted")
                .metadata = metadata;
            return Ok(());
        }
        let old_size = old.map_or(0, |node| node.size);
        let write_bytes = self
            .summary
            .write_bytes
            .checked_add(entry.payload.len())
            .filter(|v| *v <= limits.write_bytes)
            .ok_or(RootfsStagingError::TooLarge)?;
        let live_bytes = (self.summary.live_file_bytes - old_size)
            .checked_add(entry.payload.len())
            .filter(|v| *v <= limits.live_file_bytes)
            .ok_or(RootfsStagingError::TooLarge)?;
        if old.is_none() && self.nodes.len() >= limits.inodes {
            return Err(RootfsStagingError::TooLarge);
        }
        let (parent, name) = parent_and_name(&self.root, &entry.path)?;
        if old.is_some() {
            // Never truncate an existing inode or follow a leaf alias. No writer
            // FD or path was exported; replacement allocates a fresh file.
            unlinkat(&parent, name, UnlinkatFlags::NoRemoveDir)
                .map_err(|_| RootfsStagingError::FileOperation)?;
        }
        let file = File::from(
            openat(
                &parent,
                name,
                OFlag::O_WRONLY
                    | OFlag::O_CREAT
                    | OFlag::O_EXCL
                    | OFlag::O_NOFOLLOW
                    | OFlag::O_CLOEXEC,
                Mode::S_IRUSR | Mode::S_IWUSR,
            )
            .map_err(|_| RootfsStagingError::FileOperation)?,
        );
        // Register immediately, so a chmod/write failure removes partial output.
        #[cfg(feature = "launch-preparation-executable")]
        let registered_path = entry.path.clone();
        self.nodes.insert(
            entry.path,
            StagedNode {
                metadata,
                size: entry.payload.len(),
                #[cfg(feature = "launch-preparation-executable")]
                identity: None,
                #[cfg(feature = "launch-preparation-executable")]
                payload_sha384: Some(Sha384::digest(entry.payload).into()),
            },
        );
        fchmod(&file, Mode::S_IRUSR | Mode::S_IWUSR)
            .map_err(|_| RootfsStagingError::FileOperation)?;
        file.write_all_at(entry.payload, 0)
            .map_err(|_| RootfsStagingError::FileOperation)?;
        #[cfg(feature = "launch-preparation-executable")]
        {
            let stat = fstat(&file).map_err(|_| RootfsStagingError::FileOperation)?;
            self.nodes
                .get_mut(&registered_path)
                .expect("new file was registered")
                .identity = Some((stat.st_dev, stat.st_ino));
        }
        self.summary.write_bytes = write_bytes;
        self.summary.live_file_bytes = live_bytes;
        self.summary.inodes = self.nodes.len();
        Ok(())
    }

    fn ensure_parents(
        &mut self,
        path: &str,
        limits: RootfsStagingLimits,
    ) -> Result<(), RootfsStagingError> {
        let mut offset = 0;
        while let Some(index) = path[offset..].find('/') {
            offset += index;
            let parent = &path[..offset];
            match self.nodes.get(parent) {
                Some(node) if !node.metadata.is_dir => {
                    return Err(RootfsStagingError::TypeCollision)
                }
                Some(_) => (),
                None => self.create_directory(parent, limits)?,
            }
            offset += 1;
        }
        Ok(())
    }

    fn create_directory(
        &mut self,
        path: &str,
        limits: RootfsStagingLimits,
    ) -> Result<(), RootfsStagingError> {
        if self.nodes.len() >= limits.inodes {
            return Err(RootfsStagingError::TooLarge);
        }
        let (parent, name) = parent_and_name(&self.root, path)?;
        mkdirat(&parent, name, Mode::S_IRWXU).map_err(|_| RootfsStagingError::FileOperation)?;
        self.nodes.insert(
            path.into(),
            StagedNode {
                metadata: StagedMetadata::implicit_directory(),
                size: 0,
                #[cfg(feature = "launch-preparation-executable")]
                identity: None,
                #[cfg(feature = "launch-preparation-executable")]
                payload_sha384: None,
            },
        );
        self.summary.inodes = self.nodes.len();
        let directory = open_directory(&parent, name)?;
        fchmod(&directory, Mode::S_IRWXU).map_err(|_| RootfsStagingError::FileOperation)?;
        #[cfg(feature = "launch-preparation-executable")]
        {
            let stat = fstat(&directory).map_err(|_| RootfsStagingError::FileOperation)?;
            self.nodes
                .get_mut(path)
                .expect("new directory was registered")
                .identity = Some((stat.st_dev, stat.st_ino));
        }
        Ok(())
    }

    fn cleanup(&mut self) -> Result<(), RootfsStagingError> {
        if self.cleaned {
            return Ok(());
        }
        let mut failed = false;
        // Lexicographic reverse order places descendants before their parents.
        // Never use recursive pathname removal or follow a substituted directory.
        for (path, node) in self
            .nodes
            .iter()
            .rev()
            .filter(|(path, _)| path.as_str() != ".")
        {
            let result = parent_and_name(&self.root, path).and_then(|(parent, name)| {
                let flag = if node.metadata.is_dir {
                    UnlinkatFlags::RemoveDir
                } else {
                    UnlinkatFlags::NoRemoveDir
                };
                match unlinkat(&parent, name, flag) {
                    Ok(()) | Err(Errno::ENOENT) => Ok(()),
                    Err(_) => Err(RootfsStagingError::CleanupFailed),
                }
            });
            failed |= result.is_err();
        }
        let identity_matches = fstat(&self.root)
            .and_then(|held| {
                fstatat(
                    &self.parent,
                    self.name.as_str(),
                    AtFlags::AT_SYMLINK_NOFOLLOW,
                )
                .map(|named| named.st_dev == held.st_dev && named.st_ino == held.st_ino)
            })
            .unwrap_or(false);
        if !identity_matches
            || unlinkat(&self.parent, self.name.as_str(), UnlinkatFlags::RemoveDir).is_err()
        {
            failed = true;
        }
        self.cleaned = !failed;
        if failed {
            Err(RootfsStagingError::CleanupFailed)
        } else {
            Ok(())
        }
    }
}

impl Drop for RootfsStaging {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

fn validate_parent(parent: &File) -> Result<(), RootfsStagingError> {
    let stat = fstat(parent).map_err(|_| RootfsStagingError::InvalidParent)?;
    // SAFETY: geteuid has no arguments or memory-safety preconditions.
    if stat.st_mode & libc::S_IFMT != libc::S_IFDIR
        || stat.st_uid != unsafe { libc::geteuid() }
        || stat.st_mode & 0o7777 != 0o700
    {
        return Err(RootfsStagingError::InvalidParent);
    }
    Ok(())
}

fn create_root(parent: &File) -> Result<(String, File), RootfsStagingError> {
    for _ in 0..8 {
        let mut random = [0u8; 16];
        // SAFETY: the output buffer is valid for exactly random.len() bytes.
        if unsafe { libc::getrandom(random.as_mut_ptr().cast(), random.len(), 0) }
            != random.len() as isize
        {
            return Err(RootfsStagingError::FileOperation);
        }
        let name = format!(
            "onb17-staging-{}",
            random
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );
        match mkdirat(parent, name.as_str(), Mode::S_IRWXU) {
            Err(Errno::EEXIST) => continue,
            Err(_) => return Err(RootfsStagingError::FileOperation),
            Ok(()) => (),
        }
        let result = open_directory(parent, &name).and_then(|root| {
            fchmod(&root, Mode::S_IRWXU).map_err(|_| RootfsStagingError::FileOperation)?;
            Ok(root)
        });
        return match result {
            Ok(root) => Ok((name, root)),
            Err(error) => {
                let _ = unlinkat(parent, name.as_str(), UnlinkatFlags::RemoveDir);
                Err(error)
            }
        };
    }
    Err(RootfsStagingError::FileOperation)
}

fn open_directory(root: &File, path: &str) -> Result<File, RootfsStagingError> {
    let mut current = root
        .try_clone()
        .map_err(|_| RootfsStagingError::FileOperation)?;
    if path == "." {
        return Ok(current);
    }
    for part in path.split('/') {
        current = File::from(
            openat(
                &current,
                part,
                OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| RootfsStagingError::FileOperation)?,
        );
    }
    Ok(current)
}

fn parent_and_name<'a>(root: &File, path: &'a str) -> Result<(File, &'a str), RootfsStagingError> {
    let (parent, name) = path.rsplit_once('/').unwrap_or((".", path));
    Ok((open_directory(root, parent)?, name))
}

#[cfg(test)]
#[path = "rootfs_staging_tests.rs"]
mod tests;
