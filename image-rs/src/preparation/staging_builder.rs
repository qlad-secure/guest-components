// SPDX-License-Identifier: Apache-2.0

//! Export only the owned final inventory and verified payloads. Desired archive
//! metadata is encoded separately from the private workspace's 0700/0600 modes.
//! No caller pathname, file list, digest assertion or workspace FD is accepted.

use super::*;
use crate::preparation::{erofs_reader::ExpectedNode, SealedImageBytes};
use nix::sys::stat::FileStat;

const BLOCK: usize = 512;
const CHUNK: usize = 8192;
const USTAR_ID_MAX: u64 = 0o7777777;
const USTAR_TIME_MAX: u64 = 0o77777777777;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuilderInputLimits {
    pub tar_bytes: usize,
    pub inodes: usize,
    pub live_file_bytes: usize,
}

impl BuilderInputLimits {
    pub fn validate(self) -> Result<(), BuilderInputError> {
        if [self.tar_bytes, self.inodes, self.live_file_bytes]
            .iter()
            .any(|value| *value == 0 || *value > isize::MAX as usize)
        {
            return Err(BuilderInputError::InvalidLimits);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum BuilderInputError {
    #[error("builder input bounds are invalid")]
    InvalidLimits,
    #[error("builder input exceeds configured bounds")]
    TooLarge,
    #[error("builder input metadata is not representable by the selected profile")]
    UnsupportedMetadata,
    #[error("builder input workspace differs from its owned inventory")]
    WorkspaceMismatch,
    #[error("builder input payload differs from the verified layer payload")]
    ContentMismatch,
    #[error("builder input filesystem operation failed")]
    FileOperation,
    #[error("builder input sealing failed")]
    SealingFailed,
    #[error("builder input export was cancelled")]
    Cancelled,
}

/// Immutable metadata-bearing builder input, constructible only from a staging
/// owner. This does not establish filesystem validity or authorize a task.
pub struct BuilderInput {
    pub(crate) tar: SealedImageBytes,
    pub(crate) nodes: Vec<ExpectedNode>,
}

impl RootfsStaging {
    /// Blocking export. The caller must retain exclusive writer custody and
    /// keep the cancellation predicate live until actual export completion.
    pub(crate) fn builder_input(
        &self,
        limits: BuilderInputLimits,
        cancelled: &impl Fn() -> bool,
    ) -> Result<BuilderInput, BuilderInputError> {
        limits.validate()?;
        check_cancel(cancelled)?;
        if self.cleaned
            || self.nodes.len() > limits.inodes
            || self.summary.live_file_bytes > limits.live_file_bytes
        {
            return Err(BuilderInputError::TooLarge);
        }
        let mut length = 2 * BLOCK;
        let mut nodes = Vec::with_capacity(self.nodes.len());
        for (path, node) in &self.nodes {
            check_cancel(cancelled)?;
            let metadata = &node.metadata;
            if metadata.uid > USTAR_ID_MAX
                || metadata.gid > USTAR_ID_MAX
                || metadata.mtime > USTAR_TIME_MAX
                || metadata.mode & !0o777 != 0
                || (metadata.is_dir && node.size != 0)
            {
                return Err(BuilderInputError::UnsupportedMetadata);
            }
            // Reject an unrepresentable name before reserving or reading bytes.
            header(path, node)?;
            length = length
                .checked_add(BLOCK)
                .and_then(|value| {
                    node.size
                        .checked_add(BLOCK - 1)
                        .map(|size| size / BLOCK * BLOCK)
                        .and_then(|size| value.checked_add(size))
                })
                .filter(|value| *value <= limits.tar_bytes)
                .ok_or(BuilderInputError::TooLarge)?;
            nodes.push(ExpectedNode {
                path: path.clone(),
                is_dir: metadata.is_dir,
                mode: metadata.mode,
                uid: metadata.uid as u32,
                gid: metadata.gid as u32,
                mtime: metadata.mtime,
                size: node.size,
                payload_sha384: node.payload_sha384,
            });
        }
        let mut tar = Zeroizing::new(Vec::with_capacity(length));
        for (path, node) in &self.nodes {
            check_cancel(cancelled)?;
            tar.extend_from_slice(&header(path, node)?);
            if node.metadata.is_dir {
                self.builder_directory(path)?;
                continue;
            }
            let (parent, name) = path.rsplit_once('/').unwrap_or((".", path));
            let directory = self.builder_directory(parent)?;
            let file = File::from(
                openat(
                    &directory,
                    name,
                    OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK,
                    Mode::empty(),
                )
                .map_err(|_| BuilderInputError::FileOperation)?,
            );
            check_file(
                &fstat(&file).map_err(|_| BuilderInputError::FileOperation)?,
                node,
            )?;
            let mut digest = Sha384::new();
            let mut offset = 0;
            let mut buffer = Zeroizing::new([0; CHUNK]);
            while offset < node.size {
                check_cancel(cancelled)?;
                let count = (node.size - offset).min(CHUNK);
                file.read_exact_at(&mut buffer[..count], offset as u64)
                    .map_err(|_| BuilderInputError::FileOperation)?;
                digest.update(&buffer[..count]);
                tar.extend_from_slice(&buffer[..count]);
                offset += count;
            }
            let actual: [u8; 48] = digest.finalize().into();
            if node.payload_sha384 != Some(actual) {
                return Err(BuilderInputError::ContentMismatch);
            }
            check_file(
                &fstat(&file).map_err(|_| BuilderInputError::FileOperation)?,
                node,
            )?;
            let parent = self.builder_directory(parent)?;
            check_file(
                &fstatat(&parent, name, AtFlags::AT_SYMLINK_NOFOLLOW)
                    .map_err(|_| BuilderInputError::FileOperation)?,
                node,
            )?;
            let padded = tar.len().div_ceil(BLOCK) * BLOCK;
            tar.resize(padded, 0);
        }
        // Recheck every directory after the complete snapshot, including the
        // held root's association with its private parent name.
        for (path, node) in &self.nodes {
            check_cancel(cancelled)?;
            if node.metadata.is_dir {
                self.builder_directory(path)?;
            }
        }
        tar.resize(length, 0);
        check_cancel(cancelled)?;
        let tar = SealedImageBytes::from_bytes(&tar, limits.tar_bytes as u64)
            .map_err(|_| BuilderInputError::SealingFailed)?;
        check_cancel(cancelled)?;
        Ok(BuilderInput { tar, nodes })
    }

    fn builder_directory(&self, path: &str) -> Result<File, BuilderInputError> {
        let root_node = self
            .nodes
            .get(".")
            .ok_or(BuilderInputError::WorkspaceMismatch)?;
        let mut directory = self
            .root
            .try_clone()
            .map_err(|_| BuilderInputError::FileOperation)?;
        check_directory(
            &fstat(&directory).map_err(|_| BuilderInputError::FileOperation)?,
            root_node,
        )?;
        check_directory(
            &fstatat(
                &self.parent,
                self.name.as_str(),
                AtFlags::AT_SYMLINK_NOFOLLOW,
            )
            .map_err(|_| BuilderInputError::FileOperation)?,
            root_node,
        )?;
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
                .ok_or(BuilderInputError::WorkspaceMismatch)?;
            directory = File::from(
                openat(
                    &directory,
                    part,
                    OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|_| BuilderInputError::FileOperation)?,
            );
            check_directory(
                &fstat(&directory).map_err(|_| BuilderInputError::FileOperation)?,
                node,
            )?;
        }
        Ok(directory)
    }
}

fn check_cancel(cancelled: &impl Fn() -> bool) -> Result<(), BuilderInputError> {
    if cancelled() {
        Err(BuilderInputError::Cancelled)
    } else {
        Ok(())
    }
}

fn check_identity(stat: &FileStat, node: &StagedNode) -> Result<(), BuilderInputError> {
    // SAFETY: geteuid has no arguments or memory preconditions.
    if node.identity != Some((stat.st_dev, stat.st_ino))
        || stat.st_uid != unsafe { libc::geteuid() }
    {
        return Err(BuilderInputError::WorkspaceMismatch);
    }
    Ok(())
}

fn check_directory(stat: &FileStat, node: &StagedNode) -> Result<(), BuilderInputError> {
    check_identity(stat, node)?;
    if !node.metadata.is_dir
        || stat.st_mode & libc::S_IFMT != libc::S_IFDIR
        || stat.st_mode & 0o7777 != 0o700
    {
        return Err(BuilderInputError::WorkspaceMismatch);
    }
    Ok(())
}

fn check_file(stat: &FileStat, node: &StagedNode) -> Result<(), BuilderInputError> {
    check_identity(stat, node)?;
    if node.metadata.is_dir
        || stat.st_mode & libc::S_IFMT != libc::S_IFREG
        || stat.st_mode & 0o7777 != 0o600
        || stat.st_nlink != 1
        || usize::try_from(stat.st_size).ok() != Some(node.size)
    {
        return Err(BuilderInputError::WorkspaceMismatch);
    }
    Ok(())
}

fn header(path: &str, node: &StagedNode) -> Result<[u8; BLOCK], BuilderInputError> {
    let mut header = [0; BLOCK];
    let (prefix, name) = if path.len() <= 100 {
        ("", path)
    } else {
        path.match_indices('/')
            .rev()
            .find_map(|(index, _)| {
                let (prefix, tail) = path.split_at(index);
                let name = &tail[1..];
                (prefix.len() <= 155 && name.len() <= 100).then_some((prefix, name))
            })
            .ok_or(BuilderInputError::UnsupportedMetadata)?
    };
    header[..name.len()].copy_from_slice(name.as_bytes());
    header[345..345 + prefix.len()].copy_from_slice(prefix.as_bytes());
    octal(&mut header[100..108], u64::from(node.metadata.mode))?;
    octal(&mut header[108..116], node.metadata.uid)?;
    octal(&mut header[116..124], node.metadata.gid)?;
    octal(&mut header[124..136], node.size as u64)?;
    octal(&mut header[136..148], node.metadata.mtime)?;
    header[148..156].fill(b' ');
    header[156] = if node.metadata.is_dir { b'5' } else { b'0' };
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");
    octal(&mut header[329..337], 0)?;
    octal(&mut header[337..345], 0)?;
    let checksum = header.iter().map(|byte| u64::from(*byte)).sum();
    octal(&mut header[148..155], checksum)?;
    header[155] = b' ';
    Ok(header)
}

fn octal(field: &mut [u8], value: u64) -> Result<(), BuilderInputError> {
    let text = format!("{value:o}");
    if text.len() >= field.len() {
        return Err(BuilderInputError::UnsupportedMetadata);
    }
    field.fill(b'0');
    let start = field.len() - 1 - text.len();
    field[start..start + text.len()].copy_from_slice(text.as_bytes());
    *field.last_mut().expect("nonempty fixed USTAR field") = 0;
    Ok(())
}

/// Separate private scratch directory for the native tool's immediately unlinked
/// disk buffer. A child killed between create/unlink can leave a regular file;
/// enumerate only this owned directory and unlink relative names on teardown.
pub(crate) struct BuilderScratch {
    pub(crate) root: File,
    parent: File,
    name: String,
    cleaned: bool,
}
impl RootfsStaging {
    pub(crate) fn builder_scratch(&self) -> Result<BuilderScratch, BuilderInputError> {
        let parent = self
            .parent
            .try_clone()
            .map_err(|_| BuilderInputError::FileOperation)?;
        let (name, root) = create_root(&parent).map_err(|_| BuilderInputError::FileOperation)?;
        Ok(BuilderScratch {
            root,
            parent,
            name,
            cleaned: false,
        })
    }
}
impl BuilderScratch {
    pub(crate) fn cleanup(&mut self) -> Result<(), BuilderInputError> {
        if self.cleaned {
            return Ok(());
        }
        use std::os::fd::AsRawFd;
        let entries = std::fs::read_dir(format!("/proc/self/fd/{}", self.root.as_raw_fd()))
            .map_err(|_| BuilderInputError::FileOperation)?;
        for entry in entries {
            let entry = entry.map_err(|_| BuilderInputError::FileOperation)?;
            unlinkat(
                &self.root,
                entry.file_name().as_os_str(),
                UnlinkatFlags::NoRemoveDir,
            )
            .map_err(|_| BuilderInputError::FileOperation)?;
        }
        let held = fstat(&self.root).map_err(|_| BuilderInputError::FileOperation)?;
        let named = fstatat(
            &self.parent,
            self.name.as_str(),
            AtFlags::AT_SYMLINK_NOFOLLOW,
        )
        .map_err(|_| BuilderInputError::FileOperation)?;
        if held.st_dev != named.st_dev || held.st_ino != named.st_ino {
            return Err(BuilderInputError::WorkspaceMismatch);
        }
        unlinkat(&self.parent, self.name.as_str(), UnlinkatFlags::RemoveDir)
            .map_err(|_| BuilderInputError::FileOperation)?;
        self.cleaned = true;
        Ok(())
    }
}
impl Drop for BuilderScratch {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::preparation::layer_content::LayerContentLimits;
    use std::{
        fs::{self, DirBuilder},
        os::unix::fs::{DirBuilderExt, PermissionsExt},
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    struct Parent(PathBuf);
    impl Parent {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "onb17-builder-input-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            DirBuilder::new().mode(0o700).create(&path).unwrap();
            Self(path)
        }
        fn staging(&self) -> RootfsStaging {
            let parent = File::open(&self.0).unwrap();
            let (name, root) = create_root(&parent).unwrap();
            let stat = fstat(&root).unwrap();
            RootfsStaging {
                parent,
                name,
                root,
                nodes: BTreeMap::from([(
                    ".".into(),
                    StagedNode {
                        metadata: StagedMetadata::implicit_directory(),
                        size: 0,
                        identity: Some((stat.st_dev, stat.st_ino)),
                        payload_sha384: None,
                    },
                )]),
                summary: RootfsStagingSummary {
                    layers: 1,
                    total_tar_bytes: 0,
                    applied_entries: 0,
                    inodes: 1,
                    write_bytes: 0,
                    live_file_bytes: 0,
                },
                cleaned: false,
            }
        }
    }
    impl Drop for Parent {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }
    fn limits() -> BuilderInputLimits {
        BuilderInputLimits {
            tar_bytes: 32 * 1024,
            inodes: 16,
            live_file_bytes: 16 * 1024,
        }
    }
    fn staging_limits() -> RootfsStagingLimits {
        RootfsStagingLimits {
            layers: 2,
            total_tar_bytes: 32 * 1024,
            applied_entries: 16,
            inodes: 16,
            write_bytes: 32 * 1024,
            live_file_bytes: 16 * 1024,
            path_bytes: 256,
            path_components: 16,
        }
    }
    fn entry<'a>(path: &'a str, payload: &'a [u8]) -> TarEntry<'a> {
        TarEntry {
            path: path.into(),
            is_dir: false,
            mode: 0o541,
            uid: 11,
            gid: 22,
            mtime: 33,
            payload,
        }
    }
    fn read_tar(input: &BuilderInput) -> Vec<u8> {
        let mut bytes = vec![0; input.tar.byte_len() as usize];
        File::from(input.tar.as_fd().try_clone_to_owned().unwrap())
            .read_exact_at(&mut bytes, 0)
            .unwrap();
        bytes
    }
    fn parse_tar(bytes: &[u8]) -> Vec<TarEntry<'_>> {
        parse_ustar(
            bytes,
            LayerContentLimits {
                ciphertext_bytes: 32 * 1024,
                private_options_bytes: 1024,
                public_options_bytes: 1024,
                plaintext_bytes: 32 * 1024,
                tar_bytes: 32 * 1024,
                tar_entries: 16,
                path_bytes: 256,
                file_bytes: 16 * 1024,
            },
        )
        .unwrap()
    }

    #[test]
    fn final_inventory_exports_overwrite_and_implicit_desired_metadata() {
        let parent = Parent::new();
        let mut staging = parent.staging();
        staging
            .apply_entry(entry("a/b/app", b"old-long"), staging_limits())
            .unwrap();
        let mut replacement = entry("a/b/app", b"new");
        replacement.mode = 0o500;
        replacement.uid = 44;
        replacement.gid = 55;
        replacement.mtime = 66;
        staging.apply_entry(replacement, staging_limits()).unwrap();
        let first = staging.builder_input(limits(), &|| false).unwrap();
        let second = staging.builder_input(limits(), &|| false).unwrap();
        let bytes = read_tar(&first);
        assert_eq!(bytes, read_tar(&second));
        let entries = parse_tar(&bytes);
        assert_eq!(
            entries.iter().map(|e| e.path.as_str()).collect::<Vec<_>>(),
            [".", "a", "a/b", "a/b/app"]
        );
        for directory in &entries[..3] {
            assert!(directory.is_dir);
            assert_eq!(
                (
                    directory.mode,
                    directory.uid,
                    directory.gid,
                    directory.mtime
                ),
                (0o755, 0, 0, 0)
            );
        }
        let app = &entries[3];
        assert_eq!(app.payload, b"new");
        assert_eq!((app.mode, app.uid, app.gid, app.mtime), (0o500, 44, 55, 66));
        assert_eq!(
            first.nodes[3].payload_sha384,
            Some(Sha384::digest(b"new").into())
        );
        assert_eq!(
            fs::metadata(parent.0.join(&staging.name).join("a/b/app"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        staging.discard().unwrap();
        assert_eq!(fs::read_dir(&parent.0).unwrap().count(), 0);
    }

    #[test]
    fn actual_payload_inode_mode_and_link_substitution_are_rejected() {
        for case in ["content", "inode", "mode", "hardlink", "ancestor"] {
            let parent = Parent::new();
            let mut staging = parent.staging();
            staging
                .apply_entry(entry("a/app", b"payload"), staging_limits())
                .unwrap();
            let root = parent.0.join(&staging.name);
            let path = root.join("a/app");
            // Keep the original inode alive so replacement cannot accidentally
            // reuse its number and make this identity test timing-dependent.
            let _original = (case == "inode").then(|| File::open(&path).unwrap());
            match case {
                "content" => fs::write(&path, b"PAYLOAD").unwrap(),
                "inode" => {
                    fs::remove_file(&path).unwrap();
                    fs::write(&path, b"payload").unwrap();
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
                }
                "mode" => fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap(),
                "hardlink" => fs::hard_link(&path, root.join("alias")).unwrap(),
                "ancestor" => {
                    fs::set_permissions(root.join("a"), fs::Permissions::from_mode(0o755)).unwrap()
                }
                _ => unreachable!(),
            }
            assert!(
                staging.builder_input(limits(), &|| false).is_err(),
                "{case}"
            );
            if case == "hardlink" {
                fs::remove_file(root.join("alias")).unwrap();
            }
            staging.discard().unwrap();
        }
    }

    #[test]
    fn export_bounds_cancel_and_unrepresentable_metadata_fail_closed() {
        let parent = Parent::new();
        let mut staging = parent.staging();
        staging
            .apply_entry(entry("a/app", b"payload"), staging_limits())
            .unwrap();
        for field in 0..3 {
            let mut cap = limits();
            match field {
                0 => cap.tar_bytes = 1024,
                1 => cap.inodes = 2,
                2 => cap.live_file_bytes = 6,
                _ => unreachable!(),
            }
            assert_eq!(
                staging.builder_input(cap, &|| false).err(),
                Some(BuilderInputError::TooLarge)
            );
        }
        assert_eq!(
            staging.builder_input(limits(), &|| true).err(),
            Some(BuilderInputError::Cancelled)
        );
        for field in 0..3 {
            let metadata = &mut staging.nodes.get_mut("a/app").unwrap().metadata;
            metadata.uid = 11;
            metadata.gid = 22;
            metadata.mtime = 33;
            match field {
                0 => metadata.uid = u64::from(u32::MAX),
                1 => metadata.gid = USTAR_ID_MAX + 1,
                2 => metadata.mtime = USTAR_TIME_MAX + 1,
                _ => unreachable!(),
            }
            assert_eq!(
                staging.builder_input(limits(), &|| false).err(),
                Some(BuilderInputError::UnsupportedMetadata)
            );
        }
        staging.discard().unwrap();
    }

    #[test]
    fn root_and_ancestor_names_must_still_refer_to_owned_directories() {
        for replace_root in [false, true] {
            let parent = Parent::new();
            let mut staging = parent.staging();
            staging
                .apply_entry(entry("a/app", b"payload"), staging_limits())
                .unwrap();
            let root = parent.0.join(&staging.name);
            let path = if replace_root {
                root.clone()
            } else {
                root.join("a")
            };
            let saved = parent.0.join("held-original");
            fs::rename(&path, &saved).unwrap();
            DirBuilder::new().mode(0o700).create(&path).unwrap();
            assert_eq!(
                staging.builder_input(limits(), &|| false).err(),
                Some(BuilderInputError::WorkspaceMismatch)
            );
            fs::remove_dir(&path).unwrap();
            fs::rename(saved, path).unwrap();
            staging.discard().unwrap();
        }
    }

    #[test]
    fn cancellation_during_export_and_non_ustar_basename_are_rejected() {
        use std::cell::Cell;
        let parent = Parent::new();
        let mut staging = parent.staging();
        staging
            .apply_entry(entry("a/app", &[b'x'; CHUNK + 1]), staging_limits())
            .unwrap();
        let polls = Cell::new(0);
        assert_eq!(
            staging
                .builder_input(limits(), &|| {
                    polls.set(polls.get() + 1);
                    polls.get() >= 9
                })
                .err(),
            Some(BuilderInputError::Cancelled)
        );
        assert!(polls.get() >= 9);
        let path = "b".repeat(101);
        staging
            .apply_entry(entry(&path, b"x"), staging_limits())
            .unwrap();
        assert_eq!(
            staging.builder_input(limits(), &|| false).err(),
            Some(BuilderInputError::UnsupportedMetadata)
        );
        staging.discard().unwrap();
    }

    #[test]
    fn ustar_prefix_and_exact_budget_preserve_long_paths() {
        let parent = Parent::new();
        let mut staging = parent.staging();
        let path = format!("{}/{}", "a".repeat(90), "b".repeat(90));
        staging
            .apply_entry(entry(&path, b"x"), staging_limits())
            .unwrap();
        let mut cap = limits();
        cap.tar_bytes = 3072;
        cap.inodes = 3;
        cap.live_file_bytes = 1;
        let input = staging.builder_input(cap, &|| false).unwrap();
        assert_eq!(input.tar.byte_len(), 3072);
        let bytes = read_tar(&input);
        assert_eq!(parse_tar(&bytes)[2].path, path);
        cap.tar_bytes -= 1;
        assert_eq!(
            staging.builder_input(cap, &|| false).err(),
            Some(BuilderInputError::TooLarge)
        );
        staging.discard().unwrap();
    }
}
