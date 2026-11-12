// SPDX-License-Identifier: Apache-2.0

//! Point-in-time executable/spec checks inside the private mutable workspace.
//! The verified TAR payload commitment detects content replacement. These checks
//! do not seal files, make a mount, bind a final Kata task or authorize execution.
//! An immutable final view must be checked again at the later custody boundary.

use super::*;
use crate::preparation::{
    launch_spec::BoundEffectiveSpec,
    static_elf::{check_static_elf, StaticElfLimits, StaticElfSummary},
};
use nix::sys::stat::FileStat;

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum StagedExecutableError {
    #[error("staged executable bounds rejected")]
    InvalidLimits,
    #[error("staged executable exceeds configured bounds")]
    TooLarge,
    #[error("staged executable or working directory is unavailable")]
    MissingNode,
    #[error("staged executable path or inode differs from the owned inventory")]
    IdentityMismatch,
    #[error("staged workspace file metadata differs from its private profile")]
    WorkspaceMismatch,
    #[error("staged executable or directory permissions reject the launch user")]
    PermissionDenied,
    #[error("staged executable bytes differ from the verified layer payload")]
    ContentMismatch,
    #[error("staged executable filesystem operation failed")]
    FileOperation,
    #[error("staged executable uses an unsupported ELF profile")]
    ElfRejected,
}

/// Commitments and ELF observations only, without a root or executable FD.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckedStagingExecutable {
    spec_sha384: String,
    executable_sha384: String,
    executable: String,
    elf: StaticElfSummary,
}

impl CheckedStagingExecutable {
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
}

impl RootfsStaging {
    /// Blocking, bounded positional read and ELF inspection of the same owned
    /// byte snapshot. Desired archive modes govern the target user; physical
    /// workspace modes stay 0700/0600 and are separately checked. No exec occurs.
    pub fn check_static_executable(
        &self,
        spec: &BoundEffectiveSpec,
        limits: StaticElfLimits,
    ) -> Result<CheckedStagingExecutable, StagedExecutableError> {
        limits
            .validate()
            .map_err(|_| StagedExecutableError::InvalidLimits)?;
        if spec.uid() == 0 || spec.gid() == 0 {
            return Err(StagedExecutableError::PermissionDenied);
        }
        let path = relative_path(spec.executable())?;
        let cwd = relative_path(spec.cwd())?;
        let node = self
            .nodes
            .get(path)
            .ok_or(StagedExecutableError::MissingNode)?;
        if node.metadata.is_dir {
            return Err(StagedExecutableError::MissingNode);
        }
        allowed_permissions(&node.metadata, spec)?;
        let (parent_path, name) = path.rsplit_once('/').unwrap_or((".", path));
        let parent = self.checked_directory(parent_path, spec)?;
        self.checked_directory(cwd, spec)?;
        let file = File::from(
            openat(
                &parent,
                name,
                OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK,
                Mode::empty(),
            )
            .map_err(|_| StagedExecutableError::FileOperation)?,
        );
        let before = fstat(&file).map_err(|_| StagedExecutableError::FileOperation)?;
        check_file(&before, node)?;
        if node.size == 0 || node.size > limits.file_bytes {
            return Err(StagedExecutableError::TooLarge);
        }
        let mut bytes = Zeroizing::new(Vec::new());
        bytes
            .try_reserve_exact(node.size)
            .map_err(|_| StagedExecutableError::TooLarge)?;
        bytes.resize(node.size, 0);
        file.read_exact_at(&mut bytes, 0)
            .map_err(|_| StagedExecutableError::FileOperation)?;
        let after = fstat(&file).map_err(|_| StagedExecutableError::FileOperation)?;
        check_file(&after, node)?;
        let named = fstatat(&parent, name, AtFlags::AT_SYMLINK_NOFOLLOW)
            .map_err(|_| StagedExecutableError::FileOperation)?;
        check_file(&named, node)?;
        // Catch an observed ancestor/cwd substitution as well as leaf changes.
        self.checked_directory(parent_path, spec)?;
        self.checked_directory(cwd, spec)?;
        let hash: [u8; 48] = Sha384::digest(bytes.as_slice()).into();
        if node.payload_sha384 != Some(hash) {
            return Err(StagedExecutableError::ContentMismatch);
        }
        let elf =
            check_static_elf(&bytes, limits).map_err(|_| StagedExecutableError::ElfRejected)?;
        Ok(CheckedStagingExecutable {
            spec_sha384: spec.sha384().to_owned(),
            executable_sha384: hash.iter().map(|byte| format!("{byte:02x}")).collect(),
            executable: spec.executable().to_owned(),
            elf,
        })
    }

    fn checked_directory(
        &self,
        path: &str,
        spec: &BoundEffectiveSpec,
    ) -> Result<File, StagedExecutableError> {
        let mut directory = self
            .root
            .try_clone()
            .map_err(|_| StagedExecutableError::FileOperation)?;
        let root = self
            .nodes
            .get(".")
            .ok_or(StagedExecutableError::MissingNode)?;
        check_directory(
            &fstat(&directory).map_err(|_| StagedExecutableError::FileOperation)?,
            root,
            spec,
        )?;
        let named_root = fstatat(
            &self.parent,
            self.name.as_str(),
            AtFlags::AT_SYMLINK_NOFOLLOW,
        )
        .map_err(|_| StagedExecutableError::FileOperation)?;
        check_directory(&named_root, root, spec)?;
        if path == "." {
            return Ok(directory);
        }
        let mut logical = String::new();
        for part in path.split('/') {
            if !logical.is_empty() {
                logical.push('/');
            }
            logical.push_str(part);
            let node = self
                .nodes
                .get(&logical)
                .ok_or(StagedExecutableError::MissingNode)?;
            directory = File::from(
                openat(
                    &directory,
                    part,
                    OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|_| StagedExecutableError::FileOperation)?,
            );
            check_directory(
                &fstat(&directory).map_err(|_| StagedExecutableError::FileOperation)?,
                node,
                spec,
            )?;
        }
        Ok(directory)
    }
}

fn relative_path(absolute: &str) -> Result<&str, StagedExecutableError> {
    let path = absolute
        .strip_prefix('/')
        .ok_or(StagedExecutableError::MissingNode)?;
    if path.is_empty() {
        return Ok(".");
    }
    if path
        .split('/')
        .any(|part| part.is_empty() || matches!(part, "." | ".."))
    {
        return Err(StagedExecutableError::MissingNode);
    }
    Ok(path)
}

fn allowed_permissions(
    metadata: &StagedMetadata,
    spec: &BoundEffectiveSpec,
) -> Result<(), StagedExecutableError> {
    // Unix owner class takes precedence over group/other; supplementary groups
    // are absent from this strict bound-spec profile.
    let shift = if metadata.uid == u64::from(spec.uid()) {
        6
    } else if metadata.gid == u64::from(spec.gid()) {
        3
    } else {
        0
    };
    let bits = (metadata.mode >> shift) & 0o7;
    if bits & 0o1 == 0 || bits & 0o2 != 0 {
        return Err(StagedExecutableError::PermissionDenied);
    }
    Ok(())
}

fn check_identity(stat: &FileStat, node: &StagedNode) -> Result<(), StagedExecutableError> {
    if node.identity != Some((stat.st_dev, stat.st_ino)) {
        return Err(StagedExecutableError::IdentityMismatch);
    }
    Ok(())
}

fn check_directory(
    stat: &FileStat,
    node: &StagedNode,
    spec: &BoundEffectiveSpec,
) -> Result<(), StagedExecutableError> {
    check_identity(stat, node)?;
    // SAFETY: geteuid takes no arguments and has no memory preconditions.
    if !node.metadata.is_dir
        || stat.st_mode & libc::S_IFMT != libc::S_IFDIR
        || stat.st_mode & 0o7777 != 0o700
        || stat.st_uid != unsafe { libc::geteuid() }
    {
        return Err(StagedExecutableError::WorkspaceMismatch);
    }
    allowed_permissions(&node.metadata, spec)
}

fn check_file(stat: &FileStat, node: &StagedNode) -> Result<(), StagedExecutableError> {
    check_identity(stat, node)?;
    // SAFETY: geteuid takes no arguments and has no memory preconditions.
    if stat.st_mode & libc::S_IFMT != libc::S_IFREG
        || stat.st_mode & 0o7777 != 0o600
        || stat.st_nlink != 1
        || stat.st_uid != unsafe { libc::geteuid() }
        || usize::try_from(stat.st_size).ok() != Some(node.size)
    {
        return Err(StagedExecutableError::WorkspaceMismatch);
    }
    Ok(())
}

#[cfg(test)]
#[path = "staging_executable_tests.rs"]
mod tests;
