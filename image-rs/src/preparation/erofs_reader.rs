// SPDX-License-Identifier: Apache-2.0

//! Readback of a deliberately restricted EROFS format, without mounting it.
//!
//! The accepted profile uses 4096-byte blocks, complete 64-byte inodes and flat
//! uncompressed data. Directory tails may be inline; regular files, xattrs,
//! devices and external blobs cannot use alternative storage layouts.
//! Field layouts and directory/data mapping follow Linux v6.18 fs/erofs and
//! erofs-utils v1.8.10 include/erofs_fs.h. Native fsck validation remains a
//! separate check: agreement between this reader and a builder is not a kernel
//! mount or executable-view qualification.

#[cfg(any(feature = "launch-preparation-erofs", test))]
use sha2::{Digest, Sha384};
use std::collections::BTreeMap;
#[cfg(any(feature = "launch-preparation-erofs", test))]
use std::collections::BTreeSet;

const BLOCK: usize = 4096;
const SUPER: usize = 1024;
const INODE_BYTES: usize = 64;
const DIRENT_BYTES: usize = 12;
#[cfg(any(feature = "launch-preparation-erofs", test))]
const REGULAR: u16 = 0o100000;
const DIRECTORY: u16 = 0o040000;

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct ExpectedNode {
    pub path: String,
    pub is_dir: bool,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub mtime: u64,
    pub size: usize,
    pub payload_sha384: Option<[u8; 48]>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(super) enum ErofsReadError {
    #[error("EROFS expected inventory is invalid")]
    #[cfg(any(feature = "launch-preparation-erofs", test))]
    InvalidInventory,
    #[error("EROFS image uses an unsupported format profile")]
    UnsupportedProfile,
    #[error("EROFS image metadata or data range is invalid")]
    Malformed,
    #[error("EROFS image differs from the checked input inventory")]
    #[cfg(any(feature = "launch-preparation-erofs", test))]
    ParityMismatch,
}

#[cfg(any(feature = "launch-preparation-erofs", test))]
pub(super) fn verify_erofs(bytes: &[u8], expected: &[ExpectedNode]) -> Result<(), ErofsReadError> {
    let mut inventory = BTreeMap::new();
    for node in expected {
        if !valid_path(&node.path)
            || node.mode & !0o7777 != 0
            || node.mtime > i64::MAX as u64
            || (node.is_dir && (node.size != 0 || node.payload_sha384.is_some()))
            || (!node.is_dir && node.payload_sha384.is_none())
            || inventory.insert(node.path.as_str(), node).is_some()
        {
            return Err(ErofsReadError::InvalidInventory);
        }
    }
    if !inventory.get(".").is_some_and(|node| node.is_dir) {
        return Err(ErofsReadError::InvalidInventory);
    }
    for node in expected.iter().filter(|node| node.path != ".") {
        let parent = node.path.rsplit_once('/').map_or(".", |(path, _)| path);
        if !inventory.get(parent).is_some_and(|node| node.is_dir) {
            return Err(ErofsReadError::InvalidInventory);
        }
    }
    let max_path = expected
        .iter()
        .map(|node| node.path.len())
        .max()
        .unwrap_or(0);
    let mut reader = Reader::new(bytes, expected.len())?;
    let root = u64::from(le16(bytes, SUPER + 14)?);
    let mut pending = vec![(".".to_owned(), root, root)];
    let mut discovered = BTreeSet::from([root]);
    let mut seen = 0usize;
    while let Some((path, nid, parent_nid)) = pending.pop() {
        let expected = inventory
            .get(path.as_str())
            .ok_or(ErofsReadError::ParityMismatch)?;
        let inode = reader.inode(nid)?;
        let file_type = if expected.is_dir { DIRECTORY } else { REGULAR };
        if inode.mode != (file_type | expected.mode as u16)
            || inode.uid != expected.uid
            || inode.gid != expected.gid
            || inode.mtime != expected.mtime
            || inode.nsec != 0
        {
            return Err(ErofsReadError::ParityMismatch);
        }
        let data = reader.data(&inode)?;
        if expected.is_dir {
            let children = reader.directory(data, nid, parent_nid)?;
            let subdirs = children.iter().filter(|child| child.is_dir).count();
            if usize::try_from(inode.nlink).ok() != subdirs.checked_add(2) {
                return Err(ErofsReadError::ParityMismatch);
            }
            for child in children {
                if discovered.len() >= inventory.len() || !discovered.insert(child.nid) {
                    return Err(ErofsReadError::Malformed);
                }
                let child_path = if path == "." {
                    child.name.to_owned()
                } else {
                    // A malformed image cannot allocate a name chain deeper
                    // than any actual checked inventory path.
                    if path
                        .len()
                        .checked_add(child.name.len())
                        .and_then(|len| len.checked_add(1))
                        .is_none_or(|len| len > max_path)
                    {
                        return Err(ErofsReadError::ParityMismatch);
                    }
                    format!("{path}/{}", child.name)
                };
                let wanted = inventory
                    .get(child_path.as_str())
                    .ok_or(ErofsReadError::ParityMismatch)?;
                if wanted.is_dir != child.is_dir {
                    return Err(ErofsReadError::ParityMismatch);
                }
                pending.push((child_path, child.nid, nid));
            }
        } else if inode.nlink != 1
            || inode.size != expected.size
            || Some(Sha384::digest(data.prefix).into()) != expected.payload_sha384
        {
            return Err(ErofsReadError::ParityMismatch);
        }
        seen += 1;
    }
    if seen != inventory.len() {
        return Err(ErofsReadError::ParityMismatch);
    }
    Ok(())
}

#[cfg(any(feature = "launch-preparation-erofs", test))]
fn valid_path(path: &str) -> bool {
    path == "."
        || (!path.is_empty()
            && path
                .split('/')
                .all(|part| !part.is_empty() && part != "." && part != ".." && part.len() <= 255)
            && !path.as_bytes().contains(&0))
}

pub(super) struct Inode {
    pub(super) mode: u16,
    offset: usize,
    inline: bool,
    pub(super) size: usize,
    block: usize,
    pub(super) uid: u32,
    pub(super) gid: u32,
    pub(super) mtime: u64,
    pub(super) nsec: u32,
    pub(super) nlink: u32,
}
pub(super) struct Payload<'a> {
    pub(super) prefix: &'a [u8],
    pub(super) tail: &'a [u8],
}
pub(super) struct Child<'a> {
    pub(super) name: &'a str,
    pub(super) nid: u64,
    pub(super) is_dir: bool,
}
pub(super) struct Reader<'a> {
    bytes: &'a [u8],
    metadata_base: usize,
    node_limit: usize,
    // Exact byte ranges catch aliased payloads, overlapping inodes and data
    // redirected onto metadata. Allocated data blocks include their padding.
    ranges: BTreeMap<usize, usize>,
}
impl<'a> Reader<'a> {
    pub(super) fn new(bytes: &'a [u8], node_limit: usize) -> Result<Self, ErofsReadError> {
        if bytes.len() < BLOCK || !bytes.len().is_multiple_of(BLOCK) {
            return Err(ErofsReadError::Malformed);
        }
        let sb = range(bytes, SUPER, 128)?;
        if le32(sb, 0)? != 0xe0f5_e1e2
            || le32(sb, 8)? != 3 // SB_CHKSUM | MTIME
            || sb[12] != 12
            || sb[13] != 0
            || le32(sb, 80)? != 0 // no incompatible feature bits
            || sb[24..36].iter().any(|byte| *byte != 0)
            || sb[44..80].iter().any(|byte| *byte != 0)
            || sb[84..128].iter().any(|byte| *byte != 0)
            || bytes[..SUPER].iter().any(|byte| *byte != 0)
        {
            return Err(ErofsReadError::UnsupportedProfile);
        }
        if le64(sb, 16)? != node_limit as u64
            || usize::try_from(le32(sb, 36)?)
                .ok()
                .and_then(|blocks| blocks.checked_mul(BLOCK))
                != Some(bytes.len())
            || le32(sb, 4)? != checksum(bytes)?
        {
            return Err(ErofsReadError::Malformed);
        }
        let metadata_base = usize::try_from(le32(sb, 40)?)
            .ok()
            .and_then(|block| block.checked_mul(BLOCK))
            .filter(|base| *base < bytes.len())
            .ok_or(ErofsReadError::Malformed)?;
        Ok(Self {
            bytes,
            metadata_base,
            node_limit,
            ranges: BTreeMap::from([(0, SUPER + 128)]),
        })
    }

    pub(super) fn inode(&mut self, nid: u64) -> Result<Inode, ErofsReadError> {
        let offset = usize::try_from(nid)
            .ok()
            .and_then(|nid| nid.checked_mul(32))
            .and_then(|offset| self.metadata_base.checked_add(offset))
            .ok_or(ErofsReadError::Malformed)?;
        self.claim(offset, INODE_BYTES)?;
        let inode = range(self.bytes, offset, INODE_BYTES)?;
        if !matches!(le16(inode, 0)?, 1 | 5) // extended, FLAT_PLAIN or FLAT_INLINE
            || le16(inode, 2)? != 0
            || le16(inode, 6)? != 0
            || inode[48..64].iter().any(|byte| *byte != 0)
        {
            return Err(ErofsReadError::UnsupportedProfile);
        }
        let mode = le16(inode, 4)?;
        let inline = le16(inode, 0)? == 5;
        if inline && mode & 0o170000 != DIRECTORY {
            return Err(ErofsReadError::UnsupportedProfile);
        }
        let size = usize::try_from(le64(inode, 8)?).map_err(|_| ErofsReadError::Malformed)?;
        if size > self.bytes.len() {
            return Err(ErofsReadError::Malformed);
        }
        let block = usize::try_from(le32(inode, 16)?).map_err(|_| ErofsReadError::Malformed)?;
        Ok(Inode {
            mode,
            offset,
            inline,
            size,
            block,
            uid: le32(inode, 24)?,
            gid: le32(inode, 28)?,
            mtime: le64(inode, 32)?,
            nsec: le32(inode, 40)?,
            nlink: le32(inode, 44)?,
        })
    }

    pub(super) fn data(&mut self, inode: &Inode) -> Result<Payload<'a>, ErofsReadError> {
        let prefix_len = if inode.inline {
            if inode.size.is_multiple_of(BLOCK) {
                return Err(ErofsReadError::Malformed);
            }
            inode.size / BLOCK * BLOCK
        } else {
            inode.size
        };
        let prefix = if prefix_len == 0 {
            &[][..]
        } else {
            let offset = inode
                .block
                .checked_mul(BLOCK)
                .ok_or(ErofsReadError::Malformed)?;
            let allocated = prefix_len
                .checked_add(BLOCK - 1)
                .map(|size| size / BLOCK * BLOCK)
                .ok_or(ErofsReadError::Malformed)?;
            self.claim(offset, allocated)?;
            range(self.bytes, offset, prefix_len)?
        };
        let tail = if inode.inline {
            let len = inode.size - prefix_len;
            let offset = inode
                .offset
                .checked_add(INODE_BYTES)
                .ok_or(ErofsReadError::Malformed)?;
            if offset % BLOCK + len > BLOCK {
                return Err(ErofsReadError::Malformed);
            }
            self.claim(offset, len)?;
            range(self.bytes, offset, len)?
        } else {
            &[][..]
        };
        Ok(Payload { prefix, tail })
    }

    fn claim(&mut self, offset: usize, size: usize) -> Result<(), ErofsReadError> {
        let end = offset
            .checked_add(size)
            .filter(|end| *end <= self.bytes.len())
            .ok_or(ErofsReadError::Malformed)?;
        if self
            .ranges
            .range(..end)
            .next_back()
            .is_some_and(|(_, previous_end)| *previous_end > offset)
        {
            return Err(ErofsReadError::Malformed);
        }
        self.ranges.insert(offset, end);
        Ok(())
    }

    pub(super) fn directory(
        &self,
        bytes: Payload<'a>,
        nid: u64,
        parent_nid: u64,
    ) -> Result<Vec<Child<'a>>, ErofsReadError> {
        let mut children = Vec::new();
        let mut dot = false;
        let mut dotdot = false;
        let mut previous: Option<&[u8]> = None;
        for block in bytes
            .prefix
            .chunks(BLOCK)
            .chain(std::iter::once(bytes.tail).filter(|tail| !tail.is_empty()))
        {
            let table_bytes = usize::from(le16(block, 8)?);
            if table_bytes == 0
                || !table_bytes.is_multiple_of(DIRENT_BYTES)
                || table_bytes >= block.len()
            {
                return Err(ErofsReadError::Malformed);
            }
            let count = table_bytes / DIRENT_BYTES;
            for index in 0..count {
                let entry = range(block, index * DIRENT_BYTES, DIRENT_BYTES)?;
                let name_start = usize::from(le16(entry, 8)?);
                let name_end = if index + 1 == count {
                    block.len()
                } else {
                    usize::from(le16(block, (index + 1) * DIRENT_BYTES + 8)?)
                };
                if name_start < table_bytes || name_end <= name_start || entry[11] != 0 {
                    return Err(ErofsReadError::Malformed);
                }
                let raw_name = range(block, name_start, name_end - name_start)?;
                let name_bytes = if index + 1 == count {
                    let len = raw_name
                        .iter()
                        .position(|byte| *byte == 0)
                        .unwrap_or(raw_name.len());
                    if raw_name[len..].iter().any(|byte| *byte != 0) {
                        return Err(ErofsReadError::Malformed);
                    }
                    &raw_name[..len]
                } else {
                    raw_name
                };
                if name_bytes.is_empty()
                    || name_bytes.len() > 255
                    || name_bytes.contains(&0)
                    || name_bytes.contains(&b'/')
                    || previous.is_some_and(|last| last >= name_bytes)
                    || !matches!(entry[10], 1 | 2)
                {
                    return Err(ErofsReadError::Malformed);
                }
                let name =
                    std::str::from_utf8(name_bytes).map_err(|_| ErofsReadError::Malformed)?;
                let child_nid = le64(entry, 0)?;
                if name == "." {
                    if dot || child_nid != nid || entry[10] != 2 {
                        return Err(ErofsReadError::Malformed);
                    }
                    dot = true;
                } else if name == ".." {
                    if dotdot || child_nid != parent_nid || entry[10] != 2 {
                        return Err(ErofsReadError::Malformed);
                    }
                    dotdot = true;
                } else {
                    if children.len() >= self.node_limit {
                        return Err(ErofsReadError::Malformed);
                    }
                    children.push(Child {
                        name,
                        nid: child_nid,
                        is_dir: entry[10] == 2,
                    });
                }
                previous = Some(name_bytes);
            }
        }
        if !dot || !dotdot {
            return Err(ErofsReadError::Malformed);
        }
        Ok(children)
    }
}

fn range(bytes: &[u8], offset: usize, size: usize) -> Result<&[u8], ErofsReadError> {
    let end = offset.checked_add(size).ok_or(ErofsReadError::Malformed)?;
    bytes.get(offset..end).ok_or(ErofsReadError::Malformed)
}
fn le16(bytes: &[u8], offset: usize) -> Result<u16, ErofsReadError> {
    Ok(u16::from_le_bytes(
        range(bytes, offset, 2)?
            .try_into()
            .map_err(|_| ErofsReadError::Malformed)?,
    ))
}
fn le32(bytes: &[u8], offset: usize) -> Result<u32, ErofsReadError> {
    Ok(u32::from_le_bytes(
        range(bytes, offset, 4)?
            .try_into()
            .map_err(|_| ErofsReadError::Malformed)?,
    ))
}
fn le64(bytes: &[u8], offset: usize) -> Result<u64, ErofsReadError> {
    Ok(u64::from_le_bytes(
        range(bytes, offset, 8)?
            .try_into()
            .map_err(|_| ErofsReadError::Malformed)?,
    ))
}
fn checksum(bytes: &[u8]) -> Result<u32, ErofsReadError> {
    let mut crc = !0u32;
    for (index, byte) in range(bytes, SUPER, BLOCK - SUPER)?.iter().enumerate() {
        crc ^= if (4..8).contains(&index) {
            0
        } else {
            u32::from(*byte)
        };
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0x82f6_3b78 & 0u32.wrapping_sub(crc & 1));
        }
    }
    Ok(crc)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Generated by upstream erofs-utils v1.8.10, not by a local EROFS writer.
    // mkfs.erofs --tar=f --sort=none -b4096
    //   -Eforce-inode-extended,^inline_data,^xattr-name-filter -x-1 -T0
    //   --mkfs-time --preserve-mtime -U00000000-0000-0000-0000-000000000000
    // Native fsck.erofs --extract validated the complete image without mounting.
    // SHA384: 89930ec0dc93cf3a834bc2a7e5354154cd62d6b1311d66864e711ab91af97a387ebed478c06f0708e53e574c3691be6a
    const IMAGE: &[u8] = include_bytes!("testdata/erofs-flat-v1.8.10.img");
    const ROOT: usize = 36 * 32;
    const APP: usize = 50 * 32;

    fn expected() -> Vec<ExpectedNode> {
        [
            (".", true, 0o755, 0, 0, 0, &b""[..]),
            ("bin", true, 0o555, 70000, 80000, 123, &b""[..]),
            ("bin/app", false, 0o555, 70000, 80000, 456, &b"payload"[..]),
            ("empty", true, 0o750, 123, 456, 789, &b""[..]),
            ("zero", false, 0o444, 1, 2, 0, &b""[..]),
        ]
        .into_iter()
        .map(
            |(path, is_dir, mode, uid, gid, mtime, payload)| ExpectedNode {
                path: path.to_owned(),
                is_dir,
                mode,
                uid,
                gid,
                mtime,
                size: payload.len(),
                payload_sha384: (!is_dir).then(|| Sha384::digest(payload).into()),
            },
        )
        .collect()
    }

    fn repair_checksum(image: &mut [u8]) {
        let crc = checksum(image).unwrap();
        image[SUPER + 4..SUPER + 8].copy_from_slice(&crc.to_le_bytes());
    }

    #[test]
    fn native_extended_directory_tails_and_plain_files_match() {
        assert_eq!(verify_erofs(IMAGE, &expected()), Ok(()));
    }

    // Same pinned native profile as IMAGE. This fixture contains a directory
    // with one full external block plus an inline tail, and a 5003-byte file.
    // Native fsck.erofs --extract accepted it. SHA384:
    // 59a38f9173ddc0d75e0611496b7124ca032590e26e7018a4055d382b4aa2b57d5a5ed782233ffdbf3db9c47caf50f18c
    const MULTIBLOCK: &[u8] = include_bytes!("testdata/erofs-flat-multiblock-v1.8.10.img");

    fn multiblock_expected() -> Vec<ExpectedNode> {
        let mut expected = vec![ExpectedNode {
            path: ".".into(),
            is_dir: true,
            mode: 0o755,
            uid: 0,
            gid: 0,
            mtime: 0,
            size: 0,
            payload_sha384: None,
        }];
        expected.extend((0..160).map(|index| ExpectedNode {
            path: format!("node-{index:04}-empty"),
            is_dir: false,
            mode: 0o444,
            uid: 1000 + index,
            gid: 2000 + index,
            mtime: u64::from(index),
            size: 0,
            payload_sha384: Some(Sha384::digest(b"").into()),
        }));
        let payload: Vec<_> = (0..5003).map(|index| (index % 251) as u8).collect();
        expected.push(ExpectedNode {
            path: "large".into(),
            is_dir: false,
            mode: 0o544,
            uid: 70000,
            gid: 80000,
            mtime: 321,
            size: payload.len(),
            payload_sha384: Some(Sha384::digest(&payload).into()),
        });
        expected
    }

    #[test]
    fn native_directory_block_boundary_and_multiblock_payload_match() {
        assert_eq!(verify_erofs(MULTIBLOCK, &multiblock_expected()), Ok(()));
        let root = usize::from(le16(MULTIBLOCK, SUPER + 14).unwrap()) * 32;
        assert_eq!(le16(MULTIBLOCK, root).unwrap(), 5);
        assert!(le64(MULTIBLOCK, root + 8).unwrap() > BLOCK as u64);
        let prefix_offset = le32(MULTIBLOCK, root + 16).unwrap() as usize * BLOCK;
        let mut corrupted = MULTIBLOCK.to_vec();
        // A malformed final entry in the full block cannot be hidden by an
        // otherwise correct inline tail or by valid file bytes.
        corrupted[prefix_offset + BLOCK - 1] ^= 1;
        repair_checksum(&mut corrupted);
        assert!(verify_erofs(&corrupted, &multiblock_expected()).is_err());
        let large_nid = le64(MULTIBLOCK, prefix_offset + 2 * DIRENT_BYTES).unwrap();
        let large_inode = usize::try_from(large_nid).unwrap() * 32;
        let large_data = le32(MULTIBLOCK, large_inode + 16).unwrap() as usize * BLOCK;
        let mut corrupted = MULTIBLOCK.to_vec();
        corrupted[large_data + BLOCK] ^= 1;
        assert_eq!(
            verify_erofs(&corrupted, &multiblock_expected()),
            Err(ErofsReadError::ParityMismatch)
        );
        let mut corrupted = MULTIBLOCK.to_vec();
        let tail_length = le64(MULTIBLOCK, root + 8).unwrap() as usize % BLOCK;
        corrupted[root + INODE_BYTES + tail_length - 1] ^= 1;
        repair_checksum(&mut corrupted);
        assert!(verify_erofs(&corrupted, &multiblock_expected()).is_err());
    }

    #[test]
    fn truncated_expanded_and_corrupted_superblock_fail() {
        for len in [0, 1024, 4095, 4096, IMAGE.len() - 1] {
            assert!(verify_erofs(&IMAGE[..len], &expected()).is_err());
        }
        let mut expanded = IMAGE.to_vec();
        expanded.resize(IMAGE.len() + BLOCK, 0);
        assert_eq!(
            verify_erofs(&expanded, &expected()),
            Err(ErofsReadError::Malformed)
        );
        let mut changed = IMAGE.to_vec();
        changed[SUPER + 4] ^= 1;
        assert_eq!(
            verify_erofs(&changed, &expected()),
            Err(ErofsReadError::Malformed)
        );
    }

    #[test]
    fn extensions_and_storage_profiles_fail_even_with_valid_checksum() {
        for (offset, value) in [
            (SUPER + 12, 11), // different block size
            (SUPER + 13, 1),  // superblock extension slots
            (SUPER + 8, 7),   // xattr filter compatibility bit
            (SUPER + 80, 8),  // external device feature
            (SUPER + 86, 1),  // extra device
            (SUPER + 91, 1),  // xattr prefixes
            (ROOT, 7),        // compressed inode
            (ROOT + 2, 1),    // xattrs
            (APP, 5),         // inline regular file
        ] {
            let mut changed = IMAGE.to_vec();
            changed[offset] = value;
            repair_checksum(&mut changed);
            assert_eq!(
                verify_erofs(&changed, &expected()),
                Err(ErofsReadError::UnsupportedProfile)
            );
        }
    }

    #[test]
    fn desired_mode_identity_time_type_and_actual_payload_are_compared() {
        for offset in [
            APP + 4,
            APP + 24,
            APP + 28,
            APP + 32,
            APP + 40,
            APP + 44,
            4096,
        ] {
            let mut changed = IMAGE.to_vec();
            changed[offset] ^= 1;
            repair_checksum(&mut changed);
            assert_eq!(
                verify_erofs(&changed, &expected()),
                Err(ErofsReadError::ParityMismatch)
            );
        }
        let mut expected = expected();
        expected[2].is_dir = true;
        expected[2].size = 0;
        expected[2].payload_sha384 = None;
        assert_eq!(
            verify_erofs(IMAGE, &expected),
            Err(ErofsReadError::ParityMismatch)
        );
    }

    #[test]
    fn missing_extra_and_changed_paths_are_rejected() {
        let mut missing = expected();
        missing.pop();
        assert!(verify_erofs(IMAGE, &missing).is_err());
        let mut extra = expected();
        let mut node = extra[4].clone();
        node.path = "additional".into();
        extra.push(node);
        assert!(verify_erofs(IMAGE, &extra).is_err());
        let mut renamed = expected();
        renamed[2].path = "bin/other".into();
        assert_eq!(
            verify_erofs(IMAGE, &renamed),
            Err(ErofsReadError::ParityMismatch)
        );
    }

    #[test]
    fn directory_loops_wrong_parents_names_and_types_fail() {
        for (offset, value) in [
            (ROOT + INODE_BYTES, 50),          // dot points elsewhere
            (ROOT + INODE_BYTES + 12, 50),     // dotdot points elsewhere
            (ROOT + INODE_BYTES + 24, 36),     // bin points to root
            (ROOT + INODE_BYTES + 24 + 10, 1), // bin claims regular type
            (ROOT + INODE_BYTES + 8, 0),       // empty entry table
            (ROOT + INODE_BYTES + 60, b'/'),   // invalid child name
        ] {
            let mut changed = IMAGE.to_vec();
            changed[offset] = value;
            repair_checksum(&mut changed);
            assert!(verify_erofs(&changed, &expected()).is_err());
        }
    }

    #[test]
    fn aliased_and_out_of_bounds_data_and_inodes_fail() {
        for (offset, value) in [
            (APP + 16, 0),                  // payload points into inode/superblock area
            (APP + 16, 2),                  // payload is beyond the image
            (APP + 8, 255),                 // payload length differs
            (ROOT + INODE_BYTES + 24, 255), // bin inode out of bounds
        ] {
            let mut changed = IMAGE.to_vec();
            changed[offset] = value;
            repair_checksum(&mut changed);
            assert!(verify_erofs(&changed, &expected()).is_err());
        }
    }

    #[test]
    fn malformed_expected_inventory_is_not_a_parity_authority() {
        let mut invalid = expected();
        invalid.push(invalid[0].clone());
        assert_eq!(
            verify_erofs(IMAGE, &invalid),
            Err(ErofsReadError::InvalidInventory)
        );
        let mut invalid = expected();
        invalid[2].path = "../app".into();
        assert_eq!(
            verify_erofs(IMAGE, &invalid),
            Err(ErofsReadError::InvalidInventory)
        );
        let mut invalid = expected();
        invalid[2].payload_sha384 = None;
        assert_eq!(
            verify_erofs(IMAGE, &invalid),
            Err(ErofsReadError::InvalidInventory)
        );
    }
}
