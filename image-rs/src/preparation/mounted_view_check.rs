// SPDX-License-Identifier: Apache-2.0

//! Bounded readback through an owned, immutable EROFS mount root.
//!
//! The caller must retain the detached mount and its sealed backing throughout
//! this check. Only the owned mount constructor calls this crate-private entry
//! point. A successful observation is not a lease, final spec or start permit.
//! openat2 resolution and statx mount identities keep every lookup on the held
//! mount; the trusted process must still exclude hostile privileged FD users.

use super::{
    erofs_reader::ExpectedNode,
    launch_spec::BoundEffectiveSpec,
    static_elf::{check_static_elf, StaticElfLimits, StaticElfSummary},
};
use nix::libc;
use sha2::{Digest, Sha384};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::CString,
    fs::File,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::FileExt,
    },
};
use zeroize::Zeroizing;

const EROFS_MAGIC: libc::c_long = 0xe0f5_e1e2;
const CHUNK: usize = 8192;
const DIRENT_HEADER: usize = 19;
const STAT_MASK: u32 = libc::STATX_TYPE
    | libc::STATX_MODE
    | libc::STATX_NLINK
    | libc::STATX_UID
    | libc::STATX_GID
    | libc::STATX_INO
    | libc::STATX_SIZE
    | libc::STATX_MTIME
    | libc::STATX_MNT_ID;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MountedViewLimits {
    pub inodes: usize,
    pub live_file_bytes: usize,
    pub path_bytes: usize,
    pub path_components: usize,
    /// Aggregate bytes returned by getdents64 during inventory traversal.
    pub directory_entry_bytes: usize,
}
impl MountedViewLimits {
    pub fn validate(self) -> Result<(), MountedViewError> {
        if [
            self.inodes,
            self.live_file_bytes,
            self.path_bytes,
            self.path_components,
            self.directory_entry_bytes,
        ]
        .iter()
        .any(|value| *value == 0 || *value > isize::MAX as usize)
        {
            return Err(MountedViewError::InvalidLimits);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum MountedViewError {
    #[error("mounted view limits are invalid")]
    InvalidLimits,
    #[error("mounted view exceeds configured bounds")]
    TooLarge,
    #[error("mounted view requires a read-only executable EROFS mount with nosuid and nodev")]
    MountProfileRejected,
    #[error("mounted view requires supported openat2 and statx mount identities")]
    UnsupportedKernel,
    #[error("mounted view inventory differs from checked backing")]
    InventoryMismatch,
    #[error("mounted view metadata differs from checked backing")]
    MetadataMismatch,
    #[error("mounted view lookup crossed or changed its owned mount or inode")]
    IdentityMismatch,
    #[error("mounted view file bytes differ from checked backing")]
    ContentMismatch,
    #[error("mounted view rejects the candidate launch permissions")]
    PermissionDenied,
    #[error("mounted view executable uses an unsupported ELF profile")]
    ElfRejected,
    #[error("mounted view check was cancelled")]
    Cancelled,
    #[error("mounted view file operation failed")]
    FileOperation,
}

/// Actual mounted-file and ELF observations, without an exported root or entry FD.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MountedExecutableSummary {
    spec_sha384: String,
    executable_sha384: String,
    executable: String,
    elf: StaticElfSummary,
    mount_id: u64,
    inodes: usize,
    live_file_bytes: usize,
}
impl MountedExecutableSummary {
    pub fn spec_sha384(&self) -> &str {
        &self.spec_sha384
    }
    pub fn executable_sha384(&self) -> &str {
        &self.executable_sha384
    }
    pub fn executable(&self) -> &str {
        &self.executable
    }
    pub fn elf(&self) -> &StaticElfSummary {
        &self.elf
    }
    pub fn mount_id(&self) -> u64 {
        self.mount_id
    }
    pub fn inodes(&self) -> usize {
        self.inodes
    }
    pub fn live_file_bytes(&self) -> usize {
        self.live_file_bytes
    }
}

pub(crate) struct MountedViewCheck {
    pub(crate) _executable: File,
    pub(crate) _cwd: File,
    pub(crate) summary: MountedExecutableSummary,
}

pub(crate) fn check_mounted_view(
    root: &File,
    expected: &[ExpectedNode],
    spec: &BoundEffectiveSpec,
    elf_limits: StaticElfLimits,
    limits: MountedViewLimits,
    cancelled: &impl Fn() -> bool,
) -> Result<MountedViewCheck, MountedViewError> {
    limits.validate()?;
    check_cancel(cancelled)?;
    check_mount_profile(root)?;
    let checked = check_tree(root, expected, spec, elf_limits, limits, cancelled)?;
    check_mount_profile(root)?;
    check_cancel(cancelled)?;
    Ok(checked)
}

fn check_mount_profile(root: &File) -> Result<(), MountedViewError> {
    // SAFETY: both output structs are initialized and writable for their ABI
    // sizes; fstatfs/fstatvfs only inspect the live owned descriptor.
    let mut fs = unsafe { std::mem::zeroed::<libc::statfs>() };
    let mut mount = unsafe { std::mem::zeroed::<libc::statvfs>() };
    if unsafe { libc::fstatfs(root.as_raw_fd(), &mut fs) } != 0
        || unsafe { libc::fstatvfs(root.as_raw_fd(), &mut mount) } != 0
    {
        return Err(MountedViewError::FileOperation);
    }
    let required = libc::ST_RDONLY | libc::ST_NOSUID | libc::ST_NODEV;
    if fs.f_type != EROFS_MAGIC
        || mount.f_flag & required != required
        || mount.f_flag & libc::ST_NOEXEC != 0
    {
        return Err(MountedViewError::MountProfileRejected);
    }
    Ok(())
}

type Inventory<'a> = BTreeMap<&'a str, &'a ExpectedNode>;
fn inventory(
    expected: &[ExpectedNode],
    limits: MountedViewLimits,
) -> Result<Inventory<'_>, MountedViewError> {
    limits.validate()?;
    if expected.is_empty() || expected.len() > limits.inodes {
        return Err(MountedViewError::TooLarge);
    }
    let mut result = BTreeMap::new();
    let mut bytes = 0usize;
    for node in expected {
        if !valid_path(&node.path, limits)
            || node.mode & !0o777 != 0
            || node.uid == u32::MAX
            || node.gid == u32::MAX
            || node.mtime > i64::MAX as u64
            || (node.is_dir && (node.size != 0 || node.payload_sha384.is_some()))
            || (!node.is_dir && node.payload_sha384.is_none())
            || result.insert(node.path.as_str(), node).is_some()
        {
            return Err(MountedViewError::InventoryMismatch);
        }
        if !node.is_dir {
            bytes = bytes
                .checked_add(node.size)
                .filter(|n| *n <= limits.live_file_bytes)
                .ok_or(MountedViewError::TooLarge)?;
        }
    }
    if !result.get(".").is_some_and(|node| node.is_dir) {
        return Err(MountedViewError::InventoryMismatch);
    }
    for node in expected.iter().filter(|node| node.path != ".") {
        if !result
            .get(parent(&node.path))
            .is_some_and(|node| node.is_dir)
        {
            return Err(MountedViewError::InventoryMismatch);
        }
    }
    Ok(result)
}
fn valid_path(path: &str, limits: MountedViewLimits) -> bool {
    path == "."
        || (!path.is_empty()
            && path.len() <= limits.path_bytes
            && path.split('/').count() <= limits.path_components
            && path
                .split('/')
                .all(|part| !part.is_empty() && !matches!(part, "." | "..") && part.len() <= 255)
            && !path.as_bytes().contains(&0))
}
fn parent(path: &str) -> &str {
    path.rsplit_once('/').map_or(".", |(value, _)| value)
}
fn relative(absolute: &str) -> Result<&str, MountedViewError> {
    let path = absolute
        .strip_prefix('/')
        .ok_or(MountedViewError::InventoryMismatch)?;
    Ok(if path.is_empty() { "." } else { path })
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct Snapshot {
    mount_id: u64,
    device: (u32, u32),
    ino: u64,
    mode: u16,
    uid: u32,
    gid: u32,
    nlink: u32,
    size: u64,
    mtime: i64,
    nsec: u32,
}
fn snapshot(file: &File) -> Result<Snapshot, MountedViewError> {
    // SAFETY: the kernel receives a valid zero-initialized statx output and the
    // empty C string with AT_EMPTY_PATH refers only to this live descriptor.
    let mut stat = unsafe { std::mem::zeroed::<libc::statx>() };
    if unsafe {
        libc::statx(
            file.as_raw_fd(),
            c"".as_ptr(),
            libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW | libc::AT_NO_AUTOMOUNT,
            STAT_MASK,
            &mut stat,
        )
    } != 0
    {
        return Err(
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOSYS) {
                MountedViewError::UnsupportedKernel
            } else {
                MountedViewError::FileOperation
            },
        );
    }
    if stat.stx_mask & STAT_MASK != STAT_MASK || stat.stx_mnt_id == 0 {
        return Err(MountedViewError::UnsupportedKernel);
    }
    Ok(Snapshot {
        mount_id: stat.stx_mnt_id,
        device: (stat.stx_dev_major, stat.stx_dev_minor),
        ino: stat.stx_ino,
        mode: stat.stx_mode,
        uid: stat.stx_uid,
        gid: stat.stx_gid,
        nlink: stat.stx_nlink,
        size: stat.stx_size,
        mtime: stat.stx_mtime.tv_sec,
        nsec: stat.stx_mtime.tv_nsec,
    })
}
fn check_node(
    stat: Snapshot,
    node: &ExpectedNode,
    mount_id: u64,
    directories: &Inventory<'_>,
) -> Result<(), MountedViewError> {
    if stat.mount_id != mount_id {
        return Err(MountedViewError::IdentityMismatch);
    }
    let file_type = if node.is_dir {
        libc::S_IFDIR
    } else {
        libc::S_IFREG
    };
    let nlink = if node.is_dir {
        directories
            .values()
            .filter(|entry| entry.is_dir && entry.path != "." && parent(&entry.path) == node.path)
            .count()
            .checked_add(2)
            .ok_or(MountedViewError::TooLarge)?
    } else {
        1
    };
    if u32::from(stat.mode) != file_type | node.mode
        || stat.uid != node.uid
        || stat.gid != node.gid
        || stat.mtime < 0
        || stat.mtime as u64 != node.mtime
        || stat.nsec != 0
        || usize::try_from(stat.nlink).ok() != Some(nlink)
        || (!node.is_dir && usize::try_from(stat.size).ok() != Some(node.size))
    {
        return Err(MountedViewError::MetadataMismatch);
    }
    Ok(())
}

fn open_beneath(
    root: &File,
    path: &str,
    directory: bool,
    path_only: bool,
) -> Result<File, MountedViewError> {
    let path = CString::new(path).map_err(|_| MountedViewError::InventoryMismatch)?;
    let flags = libc::O_CLOEXEC
        | libc::O_NOFOLLOW
        | if directory { libc::O_DIRECTORY } else { 0 }
        | if path_only {
            libc::O_PATH
        } else {
            libc::O_RDONLY | libc::O_NONBLOCK
        };
    // SAFETY: zero fills future-extension fields. The CString, descriptor and
    // sized input struct remain live for this synchronous syscall. A successful
    // syscall transfers exactly one new descriptor into File ownership.
    let mut how = unsafe { std::mem::zeroed::<libc::open_how>() };
    how.flags = flags as u64;
    how.resolve = libc::RESOLVE_BENEATH | libc::RESOLVE_NO_SYMLINKS | libc::RESOLVE_NO_XDEV;
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            root.as_raw_fd(),
            path.as_ptr(),
            &how,
            std::mem::size_of_val(&how),
        )
    };
    if fd < 0 {
        return Err(match std::io::Error::last_os_error().raw_os_error() {
            Some(libc::ENOSYS) => MountedViewError::UnsupportedKernel,
            Some(libc::EXDEV | libc::ELOOP) => MountedViewError::IdentityMismatch,
            _ => MountedViewError::FileOperation,
        });
    }
    Ok(unsafe { File::from_raw_fd(fd as i32) })
}

struct DirectoryLocation<'a> {
    root: &'a File,
    path: &'a str,
    file: &'a File,
    current: Snapshot,
    parent_inode: u64,
}
fn directory_entries(
    location: DirectoryLocation<'_>,
    inventory: &Inventory<'_>,
    limits: MountedViewLimits,
    budget: &mut usize,
    cancelled: &impl Fn() -> bool,
) -> Result<Vec<String>, MountedViewError> {
    let DirectoryLocation {
        root,
        path,
        file,
        current,
        parent_inode,
    } = location;
    let mut buffer = [0u8; CHUNK];
    let mut names = BTreeSet::new();
    let mut children = Vec::new();
    let mut dot = false;
    let mut dotdot = false;
    loop {
        check_cancel(cancelled)?;
        // SAFETY: getdents64 writes at most this writable buffer length. The
        // descriptor is an independently opened readable directory, not O_PATH.
        let count = unsafe {
            libc::syscall(
                libc::SYS_getdents64,
                file.as_raw_fd(),
                buffer.as_mut_ptr(),
                buffer.len(),
            )
        };
        if count < 0 {
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(MountedViewError::FileOperation);
        }
        let count = count as usize;
        if count == 0 {
            break;
        }
        *budget = budget
            .checked_add(count)
            .filter(|n| *n <= limits.directory_entry_bytes)
            .ok_or(MountedViewError::TooLarge)?;
        let bytes = buffer.get(..count).ok_or(MountedViewError::FileOperation)?;
        let mut offset = 0;
        while offset < count {
            check_cancel(cancelled)?;
            let entry = bytes
                .get(offset..)
                .filter(|entry| entry.len() > DIRENT_HEADER)
                .ok_or(MountedViewError::InventoryMismatch)?;
            let length = u16::from_ne_bytes([entry[16], entry[17]]) as usize;
            if length < DIRENT_HEADER + 1 || !length.is_multiple_of(8) || length > entry.len() {
                return Err(MountedViewError::InventoryMismatch);
            }
            let raw = &entry[DIRENT_HEADER..length];
            let end = raw
                .iter()
                .position(|b| *b == 0)
                .ok_or(MountedViewError::InventoryMismatch)?;
            let name = std::str::from_utf8(&raw[..end])
                .map_err(|_| MountedViewError::InventoryMismatch)?;
            let ino = u64::from_ne_bytes(entry[..8].try_into().expect("dirent header"));
            if name.is_empty()
                || name.len() > 255
                || name.contains('/')
                || !names.insert(name.to_owned())
            {
                return Err(MountedViewError::InventoryMismatch);
            }
            if matches!(name, "." | "..") {
                if entry[18] != libc::DT_DIR
                    || ino
                        != if name == "." {
                            current.ino
                        } else {
                            parent_inode
                        }
                {
                    return Err(MountedViewError::IdentityMismatch);
                }
                if name == "." {
                    dot = true;
                } else {
                    dotdot = true;
                }
            } else {
                let child = if path == "." {
                    name.to_owned()
                } else {
                    format!("{path}/{name}")
                };
                if !valid_path(&child, limits) || children.len() >= inventory.len() {
                    return Err(MountedViewError::TooLarge);
                }
                let wanted = inventory
                    .get(child.as_str())
                    .ok_or(MountedViewError::InventoryMismatch)?;
                if entry[18]
                    != if wanted.is_dir {
                        libc::DT_DIR
                    } else {
                        libc::DT_REG
                    }
                {
                    return Err(MountedViewError::MetadataMismatch);
                }
                let opened = open_beneath(root, &child, wanted.is_dir, true)?;
                let actual = snapshot(&opened)?;
                if actual.mount_id != current.mount_id || actual.ino != ino {
                    return Err(MountedViewError::IdentityMismatch);
                }
                children.push(child);
            }
            offset += length;
        }
    }
    if !dot || !dotdot || snapshot(file)? != current {
        return Err(MountedViewError::IdentityMismatch);
    }
    Ok(children)
}

fn check_tree(
    root: &File,
    expected: &[ExpectedNode],
    spec: &BoundEffectiveSpec,
    elf_limits: StaticElfLimits,
    limits: MountedViewLimits,
    cancelled: &impl Fn() -> bool,
) -> Result<MountedViewCheck, MountedViewError> {
    check_tree_at(
        RootLocation {
            file: root,
            parent_inode: None,
        },
        expected,
        spec,
        elf_limits,
        limits,
        cancelled,
    )
}
struct RootLocation<'a> {
    file: &'a File,
    // Production detached mount roots have their own inode as dot-dot. Only
    // ordinary-tree unit fixtures supply a containing directory's inode here.
    parent_inode: Option<u64>,
}
fn check_tree_at(
    location: RootLocation<'_>,
    expected: &[ExpectedNode],
    spec: &BoundEffectiveSpec,
    elf_limits: StaticElfLimits,
    limits: MountedViewLimits,
    cancelled: &impl Fn() -> bool,
) -> Result<MountedViewCheck, MountedViewError> {
    let root = location.file;
    let inventory = inventory(expected, limits)?;
    elf_limits
        .validate()
        .map_err(|_| MountedViewError::InvalidLimits)?;
    if spec.uid() == 0 || spec.gid() == 0 {
        return Err(MountedViewError::PermissionDenied);
    }
    let root_stat = snapshot(root)?;
    let mut pending = vec![".".to_owned()];
    let mut seen = BTreeSet::new();
    let mut identities = BTreeSet::new();
    let mut directory_bytes = 0usize;
    let mut live_bytes = 0usize;
    while let Some(path) = pending.pop() {
        check_cancel(cancelled)?;
        if !seen.insert(path.clone()) || seen.len() > inventory.len() {
            return Err(MountedViewError::InventoryMismatch);
        }
        let node = inventory
            .get(path.as_str())
            .ok_or(MountedViewError::InventoryMismatch)?;
        let file = open_beneath(root, &path, node.is_dir, false)?;
        let before = snapshot(&file)?;
        check_node(before, node, root_stat.mount_id, &inventory)?;
        if !identities.insert((before.device, before.ino)) {
            return Err(MountedViewError::IdentityMismatch);
        }
        if node.is_dir {
            let parent_file = open_beneath(root, parent(&path), true, true)?;
            let parent_stat = snapshot(&parent_file)?;
            if parent_stat.mount_id != root_stat.mount_id {
                return Err(MountedViewError::IdentityMismatch);
            }
            pending.extend(directory_entries(
                DirectoryLocation {
                    root,
                    path: &path,
                    file: &file,
                    current: before,
                    parent_inode: if path == "." {
                        location.parent_inode.unwrap_or(root_stat.ino)
                    } else {
                        parent_stat.ino
                    },
                },
                &inventory,
                limits,
                &mut directory_bytes,
                cancelled,
            )?);
        } else {
            live_bytes = live_bytes
                .checked_add(node.size)
                .filter(|n| *n <= limits.live_file_bytes)
                .ok_or(MountedViewError::TooLarge)?;
            let mut digest = Sha384::new();
            let mut buffer = Zeroizing::new([0u8; CHUNK]);
            let mut offset = 0;
            while offset < node.size {
                check_cancel(cancelled)?;
                let count = (node.size - offset).min(CHUNK);
                file.read_exact_at(&mut buffer[..count], offset as u64)
                    .map_err(|_| MountedViewError::FileOperation)?;
                digest.update(&buffer[..count]);
                offset += count;
            }
            if Some(digest.finalize().into()) != node.payload_sha384 {
                return Err(MountedViewError::ContentMismatch);
            }
        }
        let named = open_beneath(root, &path, node.is_dir, true)?;
        if snapshot(&file)? != before || snapshot(&named)? != before {
            return Err(MountedViewError::IdentityMismatch);
        }
    }
    if seen.len() != inventory.len() || snapshot(root)? != root_stat {
        return Err(MountedViewError::InventoryMismatch);
    }
    let executable_path = relative(spec.executable())?;
    let cwd_path = relative(spec.cwd())?;
    let entry = inventory
        .get(executable_path)
        .filter(|node| !node.is_dir)
        .ok_or(MountedViewError::InventoryMismatch)?;
    check_permissions(entry, spec)?;
    check_ancestors(
        root,
        parent(executable_path),
        spec,
        &inventory,
        root_stat.mount_id,
    )?;
    let cwd = check_ancestors(root, cwd_path, spec, &inventory, root_stat.mount_id)?;
    let executable = open_beneath(root, executable_path, false, false)?;
    let before = snapshot(&executable)?;
    check_node(before, entry, root_stat.mount_id, &inventory)?;
    if entry.size == 0 || entry.size > elf_limits.file_bytes {
        return Err(MountedViewError::TooLarge);
    }
    let mut bytes = Zeroizing::new(Vec::new());
    bytes
        .try_reserve_exact(entry.size)
        .map_err(|_| MountedViewError::TooLarge)?;
    bytes.resize(entry.size, 0);
    for (index, chunk) in bytes.chunks_mut(CHUNK).enumerate() {
        check_cancel(cancelled)?;
        executable
            .read_exact_at(chunk, (index * CHUNK) as u64)
            .map_err(|_| MountedViewError::FileOperation)?;
    }
    let hash: [u8; 48] = Sha384::digest(&bytes).into();
    if entry.payload_sha384 != Some(hash) {
        return Err(MountedViewError::ContentMismatch);
    }
    let elf = check_static_elf(&bytes, elf_limits).map_err(|_| MountedViewError::ElfRejected)?;
    let named = open_beneath(root, executable_path, false, true)?;
    if snapshot(&executable)? != before
        || snapshot(&named)? != before
        || snapshot(root)? != root_stat
    {
        return Err(MountedViewError::IdentityMismatch);
    }
    check_cancel(cancelled)?;
    Ok(MountedViewCheck {
        _executable: executable,
        _cwd: cwd,
        summary: MountedExecutableSummary {
            spec_sha384: spec.sha384().to_owned(),
            executable_sha384: hash.iter().map(|byte| format!("{byte:02x}")).collect(),
            executable: spec.executable().to_owned(),
            elf,
            mount_id: root_stat.mount_id,
            inodes: seen.len(),
            live_file_bytes: live_bytes,
        },
    })
}
fn check_ancestors(
    root: &File,
    path: &str,
    spec: &BoundEffectiveSpec,
    inventory: &Inventory<'_>,
    mount_id: u64,
) -> Result<File, MountedViewError> {
    let mut logical = ".".to_owned();
    let mut directory = open_beneath(root, ".", true, true)?;
    let node = inventory
        .get(".")
        .ok_or(MountedViewError::InventoryMismatch)?;
    check_node(snapshot(&directory)?, node, mount_id, inventory)?;
    check_permissions(node, spec)?;
    if path == "." {
        return Ok(directory);
    }
    for part in path.split('/') {
        logical = if logical == "." {
            part.to_owned()
        } else {
            format!("{logical}/{part}")
        };
        let node = inventory
            .get(logical.as_str())
            .filter(|node| node.is_dir)
            .ok_or(MountedViewError::InventoryMismatch)?;
        directory = open_beneath(root, &logical, true, true)?;
        check_node(snapshot(&directory)?, node, mount_id, inventory)?;
        check_permissions(node, spec)?;
    }
    Ok(directory)
}
fn check_permissions(
    node: &ExpectedNode,
    spec: &BoundEffectiveSpec,
) -> Result<(), MountedViewError> {
    let shift = if node.uid == spec.uid() {
        6
    } else if node.gid == spec.gid() {
        3
    } else {
        0
    };
    let bits = (node.mode >> shift) & 7;
    if bits & 1 == 0 || bits & 2 != 0 {
        return Err(MountedViewError::PermissionDenied);
    }
    Ok(())
}
fn check_cancel(cancelled: &impl Fn() -> bool) -> Result<(), MountedViewError> {
    if cancelled() {
        Err(MountedViewError::Cancelled)
    } else {
        Ok(())
    }
}

#[cfg(test)]
#[path = "mounted_view_check_tests.rs"]
mod tests;
