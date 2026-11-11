// SPDX-License-Identifier: Apache-2.0

//! Independent view validation of received immutable EROFS bytes.
//!
//! The expected size and digest must come from the receiver's authenticated
//! transcript. This module establishes byte agreement and the actual mounted
//! view; it does not reconstruct producer signature/decryption/builder lineage,
//! authenticate the transcript, issue a preparation record, or permit a start.

use super::{
    erofs_mount::{mount_sealed_origin, ErofsMountError, ErofsMountLimits, EROFS_BACKING_ADAPTER},
    erofs_reader::{ExpectedNode, Reader},
    launch_spec::BoundEffectiveSpec,
    mounted_view_check::{
        check_mounted_view, MountedExecutableSummary, MountedViewCheck, MountedViewError,
    },
    readonly_ramfs::ReadOnlyRamImage,
    static_elf::StaticElfLimits,
    SealedImageBytes,
};
use nix::libc;
use sha2::{Digest, Sha384};
#[cfg(feature = "launch-preparation-execution")]
use std::os::fd::BorrowedFd;
use std::{
    collections::BTreeSet,
    fs::File,
    io,
    os::fd::{AsFd, AsRawFd, OwnedFd},
    time::Instant,
};
use zeroize::Zeroizing;

const SUPER: usize = 1024;
const CHUNK: usize = 8192;
const DIRECTORY: u16 = 0o040000;
const REGULAR: u16 = 0o100000;

/// Expected byte identity, not evidence of how those bytes were produced.
#[derive(Clone, Copy)]
pub struct ReceivedOriginExpectation {
    pub image_sha384: [u8; 48],
    pub byte_len: u64,
}

#[derive(Clone, Copy)]
pub struct ReceivedViewLimits {
    pub mount: ErofsMountLimits,
    /// Aggregate decoded path bytes. Inode limits separately bound parser
    /// tables; this is not a quota for their allocator or kernel overhead.
    pub inventory_path_bytes: usize,
}

impl ReceivedViewLimits {
    pub fn validate(self) -> Result<(), ReceivedViewError> {
        self.mount
            .validate()
            .map_err(|_| ReceivedViewError::InvalidLimits)?;
        if self.inventory_path_bytes == 0 || self.inventory_path_bytes > isize::MAX as usize {
            return Err(ReceivedViewError::InvalidLimits);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ReceivedViewError {
    #[error("received-view limits are invalid")]
    InvalidLimits,
    #[error("received-view work was cancelled or its deadline expired")]
    Cancelled,
    #[error("received sealed origin differs from its expected identity or profile")]
    BackingRejected,
    #[error("received EROFS metadata uses an invalid or unsupported profile")]
    ImageRejected,
    #[error("received EROFS inventory exceeds configured limits")]
    TooLarge,
    #[error("received-view file operation failed")]
    Operation,
    #[error("received-view mount rejected: {0}")]
    MountRejected(ErofsMountError),
    #[error("received-view mounted tree rejected: {0}")]
    ViewRejected(MountedViewError),
}

/// A receiver-owned checked view with no producer provenance constructor.
/// Descriptors remain private, non-Clone, and close in dependency order.
pub struct ReceivedMountedView {
    _checked: MountedViewCheck,
    _root: File,
    _image: ReadOnlyRamImage,
    _backing: SealedImageBytes,
    summary: ReceivedRootfsSummary,
}

impl ReceivedMountedView {
    pub fn from_sealed_origin(
        descriptor: OwnedFd,
        expected: ReceivedOriginExpectation,
        spec: &BoundEffectiveSpec,
        elf_limits: StaticElfLimits,
        limits: ReceivedViewLimits,
        cancelled: &impl Fn() -> bool,
    ) -> Result<Self, ReceivedViewError> {
        limits.validate()?;
        elf_limits
            .validate()
            .map_err(|_| ReceivedViewError::InvalidLimits)?;
        let deadline = Instant::now()
            .checked_add(limits.mount.wall_time)
            .ok_or(ReceivedViewError::InvalidLimits)?;
        let stopped = || cancelled() || Instant::now() >= deadline;
        check_cancel(&stopped)?;
        if expected.byte_len == 0 || expected.byte_len > limits.mount.backing_bytes as u64 {
            return Err(ReceivedViewError::BackingRejected);
        }
        // This consuming boundary verifies inode seals and hashes actual bytes.
        // Its expectation must be independently bound by the receiver's caller.
        let backing = SealedImageBytes::from_received_fd(
            descriptor,
            limits.mount.backing_bytes as u64,
            expected.image_sha384,
        )
        .map_err(|_| ReceivedViewError::BackingRejected)?;
        if backing.byte_len() != expected.byte_len {
            return Err(ReceivedViewError::BackingRejected);
        }
        check_cancel(&stopped)?;
        let snapshot = read_snapshot(&backing, &stopped)?;
        let inventory = read_inventory(&snapshot, limits, &stopped)?;
        // Plaintext parsing storage is zeroized before allocating RAMFS data.
        drop(snapshot);
        check_cancel(&stopped)?;
        let (image, root) = mount_sealed_origin(&backing, limits.mount.ramfs_data_bytes, &stopped)
            .map_err(ReceivedViewError::MountRejected)?;
        if image.byte_len() != expected.byte_len || image.sha384() != &expected.image_sha384 {
            return Err(ReceivedViewError::BackingRejected);
        }
        let checked = check_mounted_view(
            &root,
            &inventory,
            spec,
            elf_limits,
            limits.mount.view,
            &stopped,
        )
        .map_err(ReceivedViewError::ViewRejected)?;
        check_cancel(&stopped)?;
        let summary = ReceivedRootfsSummary {
            image_sha384: expected.image_sha384,
            byte_len: expected.byte_len,
            executable: checked.summary.clone(),
        };
        Ok(Self {
            _checked: checked,
            _root: root,
            _image: image,
            _backing: backing,
            summary,
        })
    }

    pub fn summary(&self) -> &ReceivedRootfsSummary {
        &self.summary
    }

    pub fn discard(self) {
        drop(self);
    }

    /// Consume the checked view for trusted task creation. The returned owner
    /// retains all backing and mount resources while its execution FDs are used.
    #[cfg(feature = "launch-preparation-execution")]
    pub fn into_execution(self) -> ExecutionView {
        ExecutionView { owner: self }
    }
}

/// One checked root/cwd/executable association for the trusted runtime.
/// There is no path or descriptor adoption constructor. Child aliases require
/// their caller to retain this owner until the actual child has been reaped.
#[cfg(feature = "launch-preparation-execution")]
pub struct ExecutionView {
    owner: ReceivedMountedView,
}

#[cfg(feature = "launch-preparation-execution")]
impl ExecutionView {
    pub fn root_fd(&self) -> BorrowedFd<'_> {
        self.owner._root.as_fd()
    }
    pub fn cwd_fd(&self) -> BorrowedFd<'_> {
        self.owner._checked._cwd.as_fd()
    }
    pub fn executable_fd(&self) -> BorrowedFd<'_> {
        self.owner._checked._executable.as_fd()
    }
    pub fn summary(&self) -> &ReceivedRootfsSummary {
        self.owner.summary()
    }
}

/// Actual received-byte and mounted-view observations; no builder/tool claims.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceivedRootfsSummary {
    image_sha384: [u8; 48],
    byte_len: u64,
    executable: MountedExecutableSummary,
}

impl ReceivedRootfsSummary {
    pub fn image_sha384(&self) -> &[u8; 48] {
        &self.image_sha384
    }

    pub fn byte_len(&self) -> u64 {
        self.byte_len
    }

    pub fn backing_adapter(&self) -> &'static str {
        EROFS_BACKING_ADAPTER
    }

    pub fn executable(&self) -> &MountedExecutableSummary {
        &self.executable
    }

    pub fn mount_id(&self) -> u64 {
        self.executable.mount_id()
    }
}

fn read_snapshot(
    backing: &SealedImageBytes,
    cancelled: &impl Fn() -> bool,
) -> Result<Zeroizing<Vec<u8>>, ReceivedViewError> {
    check_cancel(cancelled)?;
    let length = usize::try_from(backing.byte_len()).map_err(|_| ReceivedViewError::TooLarge)?;
    let mut bytes = Zeroizing::new(Vec::new());
    bytes
        .try_reserve_exact(length)
        .map_err(|_| ReceivedViewError::Operation)?;
    bytes.resize(length, 0);
    let mut offset = 0;
    while offset < length {
        check_cancel(cancelled)?;
        let count = (length - offset).min(CHUNK);
        // SAFETY: backing is live and immutable; the checked snapshot allocation
        // covers this complete output range. Its bounded offset fits off_t.
        let received = unsafe {
            libc::pread(
                backing.as_fd().as_raw_fd(),
                bytes[offset..offset + count].as_mut_ptr().cast(),
                count,
                offset as libc::off_t,
            )
        };
        if received < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(ReceivedViewError::Operation);
        }
        if received == 0 {
            return Err(ReceivedViewError::Operation);
        }
        offset += received as usize;
    }
    check_cancel(cancelled)?;
    Ok(bytes)
}

fn read_inventory(
    bytes: &[u8],
    limits: ReceivedViewLimits,
    cancelled: &impl Fn() -> bool,
) -> Result<Vec<ExpectedNode>, ReceivedViewError> {
    limits.validate()?;
    check_cancel(cancelled)?;
    let count = bytes
        .get(SUPER + 16..SUPER + 24)
        .and_then(|field| field.try_into().ok())
        .map(u64::from_le_bytes)
        .and_then(|value| usize::try_from(value).ok())
        .filter(|count| *count > 0 && *count <= limits.mount.view.inodes)
        .ok_or(ReceivedViewError::TooLarge)?;
    let root = bytes
        .get(SUPER + 14..SUPER + 16)
        .and_then(|field| field.try_into().ok())
        .map(u16::from_le_bytes)
        .map(u64::from)
        .ok_or(ReceivedViewError::ImageRejected)?;
    let mut reader = Reader::new(bytes, count).map_err(|_| ReceivedViewError::ImageRejected)?;
    let mut pending = Vec::new();
    pending
        .try_reserve_exact(count)
        .map_err(|_| ReceivedViewError::Operation)?;
    pending.push((".".to_owned(), root, root, true, 0usize));
    let mut discovered = BTreeSet::from([root]);
    let mut nodes = Vec::new();
    nodes
        .try_reserve_exact(count)
        .map_err(|_| ReceivedViewError::Operation)?;
    let mut path_bytes = 1usize;
    let mut live_file_bytes = 0usize;
    while let Some((path, nid, parent_nid, expected_dir, depth)) = pending.pop() {
        check_cancel(cancelled)?;
        let inode = reader
            .inode(nid)
            .map_err(|_| ReceivedViewError::ImageRejected)?;
        let kind = inode.mode & 0o170000;
        let is_dir = kind == DIRECTORY;
        if !matches!(kind, DIRECTORY | REGULAR)
            || expected_dir != is_dir
            || inode.mode & 0o7000 != 0
            || inode.uid == u32::MAX
            || inode.gid == u32::MAX
            || inode.mtime > i64::MAX as u64
            || inode.nsec != 0
        {
            return Err(ReceivedViewError::ImageRejected);
        }
        let data = reader
            .data(&inode)
            .map_err(|_| ReceivedViewError::ImageRejected)?;
        let payload_sha384 = if is_dir {
            let children = reader
                .directory(data, nid, parent_nid)
                .map_err(|_| ReceivedViewError::ImageRejected)?;
            let subdirs = children.iter().filter(|child| child.is_dir).count();
            if usize::try_from(inode.nlink).ok() != subdirs.checked_add(2) {
                return Err(ReceivedViewError::ImageRejected);
            }
            for child in children {
                check_cancel(cancelled)?;
                if discovered.len() >= count || !discovered.insert(child.nid) {
                    return Err(ReceivedViewError::ImageRejected);
                }
                let child_depth = depth.checked_add(1).ok_or(ReceivedViewError::TooLarge)?;
                let length = if path == "." {
                    Some(child.name.len())
                } else {
                    path.len()
                        .checked_add(1)
                        .and_then(|n| n.checked_add(child.name.len()))
                }
                .filter(|length| *length <= limits.mount.view.path_bytes)
                .ok_or(ReceivedViewError::TooLarge)?;
                if child_depth > limits.mount.view.path_components {
                    return Err(ReceivedViewError::TooLarge);
                }
                path_bytes = path_bytes
                    .checked_add(length)
                    .filter(|total| *total <= limits.inventory_path_bytes)
                    .ok_or(ReceivedViewError::TooLarge)?;
                let mut child_path = String::new();
                child_path
                    .try_reserve_exact(length)
                    .map_err(|_| ReceivedViewError::Operation)?;
                if path != "." {
                    child_path.push_str(&path);
                    child_path.push('/');
                }
                child_path.push_str(child.name);
                pending.push((child_path, child.nid, nid, child.is_dir, child_depth));
            }
            None
        } else {
            if inode.nlink != 1 || !data.tail.is_empty() || data.prefix.len() != inode.size {
                return Err(ReceivedViewError::ImageRejected);
            }
            live_file_bytes = live_file_bytes
                .checked_add(inode.size)
                .filter(|total| *total <= limits.mount.view.live_file_bytes)
                .ok_or(ReceivedViewError::TooLarge)?;
            let mut digest = Sha384::new();
            for chunk in data.prefix.chunks(CHUNK) {
                check_cancel(cancelled)?;
                digest.update(chunk);
            }
            Some(digest.finalize().into())
        };
        nodes.push(ExpectedNode {
            path,
            is_dir,
            mode: u32::from(inode.mode & 0o777),
            uid: inode.uid,
            gid: inode.gid,
            mtime: inode.mtime,
            size: if is_dir { 0 } else { inode.size },
            payload_sha384,
        });
    }
    if nodes.len() != count {
        return Err(ReceivedViewError::ImageRejected);
    }
    check_cancel(cancelled)?;
    Ok(nodes)
}

fn check_cancel(cancelled: &impl Fn() -> bool) -> Result<(), ReceivedViewError> {
    if cancelled() {
        Err(ReceivedViewError::Cancelled)
    } else {
        Ok(())
    }
}

#[cfg(test)]
#[path = "received_view_tests.rs"]
mod tests;
