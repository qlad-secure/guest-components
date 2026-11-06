// SPDX-License-Identifier: Apache-2.0

//! Owned detached EROFS views from verified, sealed builder output.
//!
//! No mountpoint, namespace mutation, loop device, mount helper or root FD is
//! exported. A fresh private ramfs copy is frozen at superblock level before
//! EROFS opens it. The original sealed inode remains the lineage commitment.
//! The trusted caller supplies mount privilege and an already
//! registered EROFS implementation, kept registered by trusted startup. Missing
//! registration is rejected before fsopen; concurrent unregistration must be
//! excluded because the kernel may otherwise auto-load a filesystem module.
//! Detached mount destruction is reference based: descendant descriptors close
//! before the root descriptor and backing. No lease or start permit is issued.

use super::readonly_ramfs::ReadOnlyRamImage;
pub use super::readonly_ramfs::{RamImageError, RamImageStage};

pub use super::mounted_view_check::{
    MountedExecutableSummary, MountedViewError, MountedViewLimits,
};
use super::SealedImageBytes;
#[cfg(feature = "launch-preparation-erofs")]
use super::{
    erofs_builder::{VerifiedErofsBacking, VerifiedErofsSummary},
    launch_spec::BoundEffectiveSpec,
    mounted_view_check::{check_mounted_view, MountedViewCheck},
    static_elf::StaticElfLimits,
};
use nix::libc;
use std::{
    ffi::{CStr, CString},
    fs::File,
    io::{self, Read},
    os::fd::{AsFd, AsRawFd, FromRawFd},
    time::{Duration, Instant},
};

const FS_CLOEXEC: libc::c_uint = 1;
const SET_FLAG: libc::c_uint = 0;
const SET_STRING: libc::c_uint = 1;
const CREATE_EXCLUSIVE: libc::c_uint = 8;
const VIEW_ATTRS: libc::c_uint =
    (libc::MOUNT_ATTR_RDONLY | libc::MOUNT_ATTR_NOSUID | libc::MOUNT_ATTR_NODEV) as libc::c_uint;
const REGISTRY_BYTES: u64 = 65536;
pub const EROFS_BACKING_ADAPTER: &str = "private-ro-ramfs-v1";

#[cfg(feature = "launch-preparation-receive")]
pub(super) fn mount_sealed_origin(
    backing: &SealedImageBytes,
    ramfs_bytes: usize,
    cancelled: &impl Fn() -> bool,
) -> Result<(ReadOnlyRamImage, File), ErofsMountError> {
    check_cancel(cancelled)?;
    require_registered_erofs()?;
    let image = ReadOnlyRamImage::from_sealed(backing, ramfs_bytes, cancelled)
        .map_err(ErofsMountError::RamImageRejected)?;
    check_cancel(cancelled)?;
    let root = create_detached_root(image.as_file(), &NativeMountApi, cancelled)?;
    check_cancel(cancelled)?;
    Ok((image, root))
}

#[derive(Clone, Copy)]
pub struct ErofsMountLimits {
    pub view: MountedViewLimits,
    pub backing_bytes: usize,
    /// Page-rounded payload allocation for the one private RAMFS data file.
    /// This is not a quota for filesystem metadata or the EROFS page cache.
    pub ramfs_data_bytes: usize,
    /// Bounded reads and kernel calls are cooperative. Late completion is
    /// rejected; this is not preemption of a synchronous mount syscall.
    pub wall_time: Duration,
}
impl ErofsMountLimits {
    pub fn validate(self) -> Result<(), ErofsMountError> {
        self.view
            .validate()
            .map_err(|_| ErofsMountError::InvalidLimits)?;
        if self.ramfs_data_bytes == 0
            || self.ramfs_data_bytes > isize::MAX as usize
            || self.backing_bytes == 0
            || self.backing_bytes > isize::MAX as usize
            || self.wall_time.is_zero()
            || Instant::now().checked_add(self.wall_time).is_none()
        {
            return Err(ErofsMountError::InvalidLimits);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MountStep {
    Open,
    ReadOnly,
    Source,
    Create,
    Mount,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ErofsMountError {
    #[error("EROFS mount limits rejected")]
    InvalidLimits,
    #[error("EROFS mount cancelled or deadline exceeded")]
    Cancelled,
    #[error("EROFS must be registered by trusted startup before mounting")]
    ErofsUnavailable,
    #[error("EROFS sealed backing receiver checks failed")]
    BackingRejected,
    #[error("EROFS private read-only backing copy rejected: {0}")]
    RamImageRejected(RamImageError),
    #[error("EROFS kernel mount step {step:?} failed with errno {errno}")]
    KernelRejected { step: MountStep, errno: i32 },
    #[error("EROFS actual mounted view rejected: {0}")]
    ViewRejected(MountedViewError),
    #[error("EROFS mount file operation failed")]
    Operation,
}

#[cfg(feature = "launch-preparation-erofs")]
impl VerifiedErofsBacking {
    /// Consume builder lineage, recheck the actual sealed inode, instantiate a
    /// detached read-only mount and verify its actual tree/spec/executable.
    /// Only this constructor creates a verified view; there is no public
    /// conversion from a pathname, arbitrary descriptor or caller assertion.
    pub fn mount_checked(
        self,
        spec: &BoundEffectiveSpec,
        elf_limits: StaticElfLimits,
        limits: ErofsMountLimits,
        cancelled: &impl Fn() -> bool,
    ) -> Result<VerifiedMountedView, ErofsMountError> {
        limits.validate()?;
        elf_limits
            .validate()
            .map_err(|_| ErofsMountError::InvalidLimits)?;
        let deadline = Instant::now()
            .checked_add(limits.wall_time)
            .ok_or(ErofsMountError::InvalidLimits)?;
        let stopped = || cancelled() || Instant::now() >= deadline;
        check_cancel(&stopped)?;
        let (sealed, summary, inventory) = self.into_mount_parts();
        // This is a receiver boundary even for a local owner. The expected hash
        // comes from the retained builder result, never a received caller field.
        let alias = sealed
            .as_fd()
            .try_clone_to_owned()
            .map_err(|_| ErofsMountError::Operation)?;
        let backing = SealedImageBytes::from_received_fd(
            alias,
            limits.backing_bytes as u64,
            *summary.image_sha384(),
        )
        .map_err(|_| ErofsMountError::BackingRejected)?;
        if backing.byte_len() != summary.byte_len() {
            return Err(ErofsMountError::BackingRejected);
        }
        drop(sealed);
        check_cancel(&stopped)?;
        require_registered_erofs()?;
        check_cancel(&stopped)?;
        // EROFS's regular-file backend needs read_folio, which shmem memfd
        // lacks. Keep the sealed source and use only this private, frozen,
        // post-freeze hash-checked RAMFS copy as the kernel mount source.
        let image = ReadOnlyRamImage::from_sealed(&backing, limits.ramfs_data_bytes, &stopped)
            .map_err(ErofsMountError::RamImageRejected)?;
        if image.byte_len() != summary.byte_len() || image.sha384() != summary.image_sha384() {
            return Err(ErofsMountError::BackingRejected);
        }
        let root = create_detached_root(image.as_file(), &NativeMountApi, &stopped)?;
        let checked =
            check_mounted_view(&root, &inventory, spec, elf_limits, limits.view, &stopped)
                .map_err(ErofsMountError::ViewRejected)?;
        check_cancel(&stopped)?;
        let summary = MountedRootfsSummary {
            backing: summary,
            executable: checked.summary.clone(),
            backing_adapter: EROFS_BACKING_ADAPTER,
        };
        Ok(VerifiedMountedView {
            _checked: checked,
            _root: root,
            _image: image,
            _backing: backing,
            summary,
        })
    }
}

/// One non-Clone owner. Every root/cwd/executable reference remains private;
/// the optional offer API can duplicate only the sealed data origin. Closing
/// this detached owner is not an attached-mount unmount protocol or a final
/// preparation authorization.
#[cfg(feature = "launch-preparation-erofs")]
pub struct VerifiedMountedView {
    // Field drop order releases descendants, then the detached root, then data.
    _checked: MountedViewCheck,
    _root: File,
    _image: ReadOnlyRamImage,
    _backing: SealedImageBytes,
    summary: MountedRootfsSummary,
}
#[cfg(feature = "launch-preparation-erofs")]
impl VerifiedMountedView {
    pub fn summary(&self) -> &MountedRootfsSummary {
        &self.summary
    }
    /// Duplicate only the original immutable data inode for a non-authorizing
    /// offer. The RAMFS mount, EROFS root and executable FDs remain private.
    #[cfg(feature = "launch-preparation-offer")]
    pub fn duplicate_sealed_origin(&self) -> Result<std::os::fd::OwnedFd, ErofsMountError> {
        self._backing
            .as_fd()
            .try_clone_to_owned()
            .map_err(|_| ErofsMountError::Operation)
    }
    pub fn discard(self) {
        drop(self);
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg(feature = "launch-preparation-erofs")]
pub struct MountedRootfsSummary {
    backing: VerifiedErofsSummary,
    executable: MountedExecutableSummary,
    backing_adapter: &'static str,
}
#[cfg(feature = "launch-preparation-erofs")]
impl MountedRootfsSummary {
    pub fn backing_adapter(&self) -> &'static str {
        self.backing_adapter
    }
    pub fn backing(&self) -> &VerifiedErofsSummary {
        &self.backing
    }
    pub fn executable(&self) -> &MountedExecutableSummary {
        &self.executable
    }
    pub fn mount_id(&self) -> u64 {
        self.executable.mount_id()
    }
}

fn require_registered_erofs() -> Result<(), ErofsMountError> {
    let file = File::open("/proc/filesystems").map_err(|_| ErofsMountError::Operation)?;
    let mut bytes = Vec::new();
    file.take(REGISTRY_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ErofsMountError::Operation)?;
    if bytes.len() > REGISTRY_BYTES as usize {
        return Err(ErofsMountError::Operation);
    }
    let registry = std::str::from_utf8(&bytes).map_err(|_| ErofsMountError::Operation)?;
    if registry
        .lines()
        .any(|line| line.split_whitespace().last() == Some("erofs"))
    {
        Ok(())
    } else {
        Err(ErofsMountError::ErofsUnavailable)
    }
}
fn check_cancel(cancelled: &impl Fn() -> bool) -> Result<(), ErofsMountError> {
    if cancelled() {
        Err(ErofsMountError::Cancelled)
    } else {
        Ok(())
    }
}

// Private syscall seam permits deterministic failure/ownership tests. Neither
// callers nor image data can supply a different implementation or filesystem.
trait MountApi {
    fn open(&self) -> io::Result<File>;
    fn config(
        &self,
        context: &File,
        command: libc::c_uint,
        key: Option<&CStr>,
        value: Option<&CStr>,
    ) -> io::Result<()>;
    fn mount(&self, context: &File) -> io::Result<File>;
}
struct NativeMountApi;
impl MountApi for NativeMountApi {
    fn open(&self) -> io::Result<File> {
        // SAFETY: the filesystem string is static/NUL-terminated and flags are
        // from the Linux mount UAPI. A nonnegative result is a new owned FD.
        let fd = unsafe { libc::syscall(libc::SYS_fsopen, c"erofs".as_ptr(), FS_CLOEXEC) };
        owned_fd(fd)
    }
    fn config(
        &self,
        context: &File,
        command: libc::c_uint,
        key: Option<&CStr>,
        value: Option<&CStr>,
    ) -> io::Result<()> {
        let key = key.map_or(std::ptr::null(), CStr::as_ptr);
        let value = value.map_or(std::ptr::null(), CStr::as_ptr);
        // SAFETY: context is live, strings live through this call, and the
        // fixed commands accept these NUL-terminated strings or null pointers.
        let result = unsafe {
            libc::syscall(
                libc::SYS_fsconfig,
                context.as_raw_fd(),
                command,
                key,
                value,
                0,
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
    fn mount(&self, context: &File) -> io::Result<File> {
        // SAFETY: context is live in awaiting-mount state; fixed attributes do
        // not include NOEXEC, since this view is intended for future execution.
        let fd = unsafe {
            libc::syscall(
                libc::SYS_fsmount,
                context.as_raw_fd(),
                FS_CLOEXEC,
                VIEW_ATTRS,
            )
        };
        owned_fd(fd)
    }
}
fn owned_fd(fd: libc::c_long) -> io::Result<File> {
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        // SAFETY: successful syscalls returned a new, exclusively owned FD.
        Ok(unsafe { File::from_raw_fd(fd as i32) })
    }
}
fn kernel_error(step: MountStep, error: io::Error) -> ErofsMountError {
    ErofsMountError::KernelRejected {
        step,
        errno: error.raw_os_error().unwrap_or(libc::EIO),
    }
}
fn create_detached_root(
    backing: &impl AsFd,
    api: &impl MountApi,
    cancelled: &impl Fn() -> bool,
) -> Result<File, ErofsMountError> {
    check_cancel(cancelled)?;
    let context = api.open().map_err(|e| kernel_error(MountStep::Open, e))?;
    check_cancel(cancelled)?;
    api.config(&context, SET_FLAG, Some(c"ro"), None)
        .map_err(|e| kernel_error(MountStep::ReadOnly, e))?;
    check_cancel(cancelled)?;
    let source = CString::new(format!("/proc/self/fd/{}", backing.as_fd().as_raw_fd()))
        .map_err(|_| ErofsMountError::Operation)?;
    api.config(&context, SET_STRING, Some(c"source"), Some(&source))
        .map_err(|e| kernel_error(MountStep::Source, e))?;
    check_cancel(cancelled)?;
    api.config(&context, CREATE_EXCLUSIVE, None, None)
        .map_err(|e| kernel_error(MountStep::Create, e))?;
    check_cancel(cancelled)?;
    let root = api
        .mount(&context)
        .map_err(|e| kernel_error(MountStep::Mount, e))?;
    // fsmount leaves the fscontext as a reconfiguration handle; close it before
    // any success publication or checked-view readback can occur.
    drop(context);
    check_cancel(cancelled)?;
    Ok(root)
}

#[cfg(all(test, feature = "launch-preparation-erofs"))]
#[path = "erofs_mount_tests.rs"]
mod tests;
