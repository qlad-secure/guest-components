// SPDX-License-Identifier: Apache-2.0

//! Private, detached, unswappable file backing for file-backed filesystems.
//!
//! The copied file is hashed after a nonforced superblock read-only transition,
//! which rejects outstanding writers across every mount alias. The owner keeps
//! both the read-only file and its detached RAMFS root private. This requires
//! trusted process/descriptor custody; a privileged owner can reconfigure RAMFS.
//! The payload budget includes page rounding, but is not a filesystem quota or
//! an accounting of inode metadata, source bytes, or a consumer's page cache.

use super::SealedImageBytes;
use nix::libc;
use sha2::{Digest, Sha384};
use std::{
    ffi::CStr,
    fs::File,
    io::{self, Read},
    os::{
        fd::{AsFd, AsRawFd, FromRawFd},
        unix::fs::{FileExt, MetadataExt},
    },
};
use zeroize::Zeroizing;

const CLOEXEC: libc::c_uint = 1;
const SET_FLAG: libc::c_uint = 0;
const SET_STRING: libc::c_uint = 1;
const RECONFIGURE: libc::c_uint = 7;
const CREATE_EXCLUSIVE: libc::c_uint = 8;
const FSPICK_EMPTY_PATH: libc::c_uint = 8;
const RAMFS_MAGIC: libc::c_long = 0x8584_58f6u32 as libc::c_long;
const DATA_ATTRS: libc::c_uint =
    libc::MOUNT_ATTR_NOSUID as u32 | libc::MOUNT_ATTR_NODEV as u32 | libc::MOUNT_ATTR_NOEXEC as u32;
const REGISTRY_BYTES: usize = 64 * 1024;
const CHUNK_BYTES: usize = 8192;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RamImageStage {
    Open,
    Configure,
    Create,
    Mount,
    CreateFile,
    ReadFile,
    Pick,
    ReadOnly,
    Reconfigure,
    MountAttributes,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum RamImageError {
    #[error("RAMFS payload allocation limit must be nonzero and representable")]
    InvalidLimit,
    #[error("RAMFS page-rounded payload exceeds its allocation limit")]
    TooLarge,
    #[error("RAMFS backing creation was cancelled")]
    Cancelled,
    #[error("RAMFS kernel step {stage:?} failed with errno {errno}")]
    Kernel { stage: RamImageStage, errno: i32 },
    #[error("RAMFS backing file operation failed")]
    Operation,
    #[error("RAMFS backing profile rejected")]
    Profile,
    #[error("RAMFS backing digest differs from the sealed source")]
    ContentMismatch,
}

pub(crate) struct ReadOnlyRamImage {
    // Drop the file before the detached root. No writer, fscontext, public path,
    // writable mapping, or alternate mount is retained by a completed owner.
    file: File,
    _root: File,
    byte_len: u64,
    sha384: [u8; 48],
}

impl ReadOnlyRamImage {
    pub(crate) fn from_sealed(
        source: &SealedImageBytes,
        max_data_bytes: usize,
        cancelled: &impl Fn() -> bool,
    ) -> Result<Self, RamImageError> {
        check_cancel(cancelled)?;
        // SAFETY: sysconf has no pointer arguments or side effects for this key.
        let page_size = usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) })
            .map_err(|_| RamImageError::Operation)?;
        check_payload_budget(source.byte_len(), max_data_bytes, page_size)?;
        require_registered_ramfs()?;
        check_cancel(cancelled)?;
        let root = create_root(cancelled)?;
        let writer = open_data(
            &root,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            RamImageStage::CreateFile,
        )?;
        // A process umask must not change the fixed private-file profile.
        // SAFETY: writer is a live newly created private regular file.
        if unsafe { libc::fchmod(writer.as_raw_fd(), 0o600) } != 0 {
            return Err(RamImageError::Operation);
        }
        check_cancel(cancelled)?;
        copy_source(source, &writer, cancelled)?;
        // Keep the inode linked: an unlinked open inode would make the
        // nonforced transition fail with EBUSY through s_remove_count.
        let file = open_data(&root, libc::O_RDONLY, RamImageStage::ReadFile)?;
        drop(writer);
        check_cancel(cancelled)?;
        make_superblock_readonly(&root, cancelled)?;
        // Verify read-only state before adding the per-mount attribute. This
        // mount started writable, so that attribute cannot mask a failed SBRO.
        check_readonly(&root)?;
        set_mount_readonly(&root)?;
        check_cancel(cancelled)?;
        check_profile(&root, &file, source.byte_len())?;
        let sha384 = digest_file(&file, source.byte_len(), cancelled)?;
        if sha384 != *source.sha384() {
            return Err(RamImageError::ContentMismatch);
        }
        check_profile(&root, &file, source.byte_len())?;
        check_cancel(cancelled)?;
        Ok(Self {
            file,
            _root: root,
            byte_len: source.byte_len(),
            sha384,
        })
    }

    pub(crate) fn as_file(&self) -> &File {
        &self.file
    }

    pub(crate) fn byte_len(&self) -> u64 {
        self.byte_len
    }

    pub(crate) fn sha384(&self) -> &[u8; 48] {
        &self.sha384
    }
}

fn check_payload_budget(
    byte_len: u64,
    max_data_bytes: usize,
    page_size: usize,
) -> Result<(), RamImageError> {
    if max_data_bytes == 0 || max_data_bytes > isize::MAX as usize || page_size == 0 {
        return Err(RamImageError::InvalidLimit);
    }
    if byte_len == 0 {
        return Err(RamImageError::Profile);
    }
    let bytes = usize::try_from(byte_len).map_err(|_| RamImageError::TooLarge)?;
    let rounded = bytes
        .checked_add(page_size - 1)
        .map(|n| n / page_size)
        .and_then(|pages| pages.checked_mul(page_size))
        .ok_or(RamImageError::TooLarge)?;
    if rounded > max_data_bytes {
        Err(RamImageError::TooLarge)
    } else {
        Ok(())
    }
}

fn require_registered_ramfs() -> Result<(), RamImageError> {
    // Avoid fsopen's module-loading path when trusted startup has not registered
    // the filesystem. No caller or image pathname is inspected.
    let registry = File::open("/proc/filesystems").map_err(|_| RamImageError::Operation)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(REGISTRY_BYTES + 1)
        .map_err(|_| RamImageError::Operation)?;
    registry
        .take((REGISTRY_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| RamImageError::Operation)?;
    if bytes.len() > REGISTRY_BYTES {
        return Err(RamImageError::Operation);
    }
    let registry = std::str::from_utf8(&bytes).map_err(|_| RamImageError::Operation)?;
    if registry
        .lines()
        .any(|line| line.split_whitespace().last() == Some("ramfs"))
    {
        Ok(())
    } else {
        Err(RamImageError::Profile)
    }
}

fn create_root(cancelled: &impl Fn() -> bool) -> Result<File, RamImageError> {
    // SAFETY: static NUL-terminated filesystem name and Linux UAPI flags. On
    // success fsopen returns a new descriptor whose ownership is adopted below.
    let context = owned_fd(
        unsafe { libc::syscall(libc::SYS_fsopen, c"ramfs".as_ptr(), CLOEXEC) },
        RamImageStage::Open,
    )?;
    check_cancel(cancelled)?;
    config(
        &context,
        SET_STRING,
        Some(c"mode"),
        Some(c"0700"),
        RamImageStage::Configure,
    )?;
    check_cancel(cancelled)?;
    config(
        &context,
        CREATE_EXCLUSIVE,
        None,
        None,
        RamImageStage::Create,
    )?;
    check_cancel(cancelled)?;
    // SAFETY: the context is awaiting-mount; these fixed mount attributes make
    // the data-only root private and nonexecutable, without making it RO yet.
    let root = owned_fd(
        unsafe { libc::syscall(libc::SYS_fsmount, context.as_raw_fd(), CLOEXEC, DATA_ATTRS) },
        RamImageStage::Mount,
    )?;
    drop(context);
    check_cancel(cancelled)?;
    Ok(root)
}

fn open_data(root: &File, flags: libc::c_int, stage: RamImageStage) -> Result<File, RamImageError> {
    // SAFETY: root is live; the single-component fixed name cannot escape it.
    // O_EXCL prevents replacement at creation and NOFOLLOW rejects symlinks.
    let fd = unsafe {
        libc::openat(
            root.as_raw_fd(),
            c"image".as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
            0o600 as libc::mode_t,
        )
    };
    owned_fd(fd as libc::c_long, stage)
}

fn copy_source(
    source: &SealedImageBytes,
    destination: &File,
    cancelled: &impl Fn() -> bool,
) -> Result<(), RamImageError> {
    let mut buffer = Zeroizing::new([0u8; CHUNK_BYTES]);
    let mut offset = 0;
    while offset < source.byte_len() {
        check_cancel(cancelled)?;
        let count = (source.byte_len() - offset).min(CHUNK_BYTES as u64) as usize;
        let read = loop {
            // SAFETY: the sealed regular source is live; the buffer is writable
            // for count bytes and its bounded offset fits the configured limit.
            let read = unsafe {
                libc::pread(
                    source.as_fd().as_raw_fd(),
                    buffer.as_mut_ptr().cast(),
                    count,
                    offset as libc::off_t,
                )
            };
            if read >= 0 {
                break read as usize;
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(RamImageError::Operation);
            }
            check_cancel(cancelled)?;
        };
        if read == 0 {
            return Err(RamImageError::Operation);
        }
        let mut written = 0;
        while written < read {
            check_cancel(cancelled)?;
            match destination.write_at(&buffer[written..read], offset + written as u64) {
                Ok(0) => return Err(RamImageError::Operation),
                Ok(count) => written += count,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => return Err(RamImageError::Operation),
            }
        }
        offset += read as u64;
    }
    check_cancel(cancelled)
}

fn make_superblock_readonly(
    root: &File,
    cancelled: &impl Fn() -> bool,
) -> Result<(), RamImageError> {
    // SAFETY: EMPTY_PATH picks the exact retained detached mount root rather
    // than resolving a caller pathname. No mutable reconfiguration FD escapes.
    let context = owned_fd(
        unsafe {
            libc::syscall(
                libc::SYS_fspick,
                root.as_raw_fd(),
                c"".as_ptr(),
                CLOEXEC | FSPICK_EMPTY_PATH,
            )
        },
        RamImageStage::Pick,
    )?;
    check_cancel(cancelled)?;
    config(
        &context,
        SET_FLAG,
        Some(c"ro"),
        None,
        RamImageStage::ReadOnly,
    )?;
    check_cancel(cancelled)?;
    // No force flag: the VFS must reject every still-open writable file or
    // shared writable mapping, including references through mount aliases.
    config(
        &context,
        RECONFIGURE,
        None,
        None,
        RamImageStage::Reconfigure,
    )?;
    drop(context);
    check_cancel(cancelled)
}

#[repr(C)]
struct MountAttributes {
    attr_set: u64,
    attr_clr: u64,
    propagation: u64,
    userns_fd: u64,
}

fn set_mount_readonly(root: &File) -> Result<(), RamImageError> {
    let attributes = MountAttributes {
        attr_set: libc::MOUNT_ATTR_RDONLY | u64::from(DATA_ATTRS),
        attr_clr: 0,
        propagation: 0,
        userns_fd: 0,
    };
    // SAFETY: initialized Linux mount_attr ABI, exact live root, empty path,
    // fixed flags. This is additional hardening after the real SBRO transition.
    let result = unsafe {
        libc::syscall(
            libc::SYS_mount_setattr,
            root.as_raw_fd(),
            c"".as_ptr(),
            libc::AT_EMPTY_PATH,
            &attributes,
            std::mem::size_of::<MountAttributes>(),
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(kernel_error(RamImageStage::MountAttributes))
    }
}

fn check_readonly(root: &File) -> Result<(), RamImageError> {
    // SAFETY: initialized ABI output struct and a live descriptor.
    let mut mount = unsafe { std::mem::zeroed::<libc::statvfs>() };
    if unsafe { libc::fstatvfs(root.as_raw_fd(), &mut mount) } != 0 {
        return Err(RamImageError::Operation);
    }
    if mount.f_flag & libc::ST_RDONLY == 0 {
        return Err(RamImageError::Profile);
    }
    Ok(())
}

fn check_profile(root: &File, file: &File, byte_len: u64) -> Result<(), RamImageError> {
    let root_metadata = root.metadata().map_err(|_| RamImageError::Operation)?;
    let metadata = file.metadata().map_err(|_| RamImageError::Operation)?;
    let required = libc::ST_RDONLY | libc::ST_NOSUID | libc::ST_NODEV | libc::ST_NOEXEC;
    for descriptor in [root, file] {
        // SAFETY: initialized ABI output structs and live descriptors.
        let mut fs = unsafe { std::mem::zeroed::<libc::statfs>() };
        let mut mount = unsafe { std::mem::zeroed::<libc::statvfs>() };
        if unsafe { libc::fstatfs(descriptor.as_raw_fd(), &mut fs) } != 0
            || unsafe { libc::fstatvfs(descriptor.as_raw_fd(), &mut mount) } != 0
        {
            return Err(RamImageError::Operation);
        }
        if fs.f_type != RAMFS_MAGIC || mount.f_flag & required != required {
            return Err(RamImageError::Profile);
        }
    }
    if !root_metadata.is_dir()
        || root_metadata.mode() & 0o7777 != 0o700
        || !metadata.is_file()
        || metadata.mode() & 0o7777 != 0o600
        || metadata.nlink() != 1
        || metadata.len() != byte_len
        || metadata.dev() != root_metadata.dev()
    {
        return Err(RamImageError::Profile);
    }
    // SAFETY: fcntl GETFL/GETFD inspect a live descriptor, without pointer args.
    let mode = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
    let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFD) };
    if mode < 0 || flags < 0 {
        return Err(RamImageError::Operation);
    }
    if mode & libc::O_ACCMODE != libc::O_RDONLY || flags & libc::FD_CLOEXEC == 0 {
        return Err(RamImageError::Profile);
    }
    Ok(())
}

fn digest_file(
    file: &File,
    byte_len: u64,
    cancelled: &impl Fn() -> bool,
) -> Result<[u8; 48], RamImageError> {
    let mut digest = Sha384::new();
    let mut buffer = Zeroizing::new([0u8; CHUNK_BYTES]);
    let mut offset = 0;
    while offset < byte_len {
        check_cancel(cancelled)?;
        let count = (byte_len - offset).min(CHUNK_BYTES as u64) as usize;
        let read = match file.read_at(&mut buffer[..count], offset) {
            Ok(0) => return Err(RamImageError::Operation),
            Ok(read) => read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(RamImageError::Operation),
        };
        digest.update(&buffer[..read]);
        offset += read as u64;
    }
    check_cancel(cancelled)?;
    Ok(digest.finalize().into())
}

fn config(
    context: &File,
    command: libc::c_uint,
    key: Option<&CStr>,
    value: Option<&CStr>,
    stage: RamImageStage,
) -> Result<(), RamImageError> {
    let key = key.map_or(std::ptr::null(), CStr::as_ptr);
    let value = value.map_or(std::ptr::null(), CStr::as_ptr);
    // SAFETY: context is live and the fixed command's optional strings remain
    // NUL-terminated and valid for the duration of this call.
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
        Err(kernel_error(stage))
    }
}

fn owned_fd(fd: libc::c_long, stage: RamImageStage) -> Result<File, RamImageError> {
    if fd < 0 {
        Err(kernel_error(stage))
    } else {
        // SAFETY: the successful syscall returned a new, exclusively owned FD.
        Ok(unsafe { File::from_raw_fd(fd as libc::c_int) })
    }
}

fn kernel_error(stage: RamImageStage) -> RamImageError {
    RamImageError::Kernel {
        stage,
        errno: io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO),
    }
}

fn check_cancel(cancelled: &impl Fn() -> bool) -> Result<(), RamImageError> {
    if cancelled() {
        Err(RamImageError::Cancelled)
    } else {
        Ok(())
    }
}

#[cfg(test)]
#[path = "readonly_ramfs_tests.rs"]
mod tests;
