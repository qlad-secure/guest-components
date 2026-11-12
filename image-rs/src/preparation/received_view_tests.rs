// SPDX-License-Identifier: Apache-2.0

//! Actual byte-parser and consuming receiver-boundary tests. Positive EROFS
//! mounting requires the separately opted-in native received-view harness.

use super::*;
use crate::preparation::launch_spec::tests as spec_fixture;
use nix::sys::memfd::{memfd_create, MFdFlags};
use std::{
    cell::Cell,
    ffi::CString,
    os::unix::fs::FileExt,
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};

const IMAGE: &[u8] = include_bytes!("testdata/erofs-flat-v1.8.10.img");
const MULTIBLOCK: &[u8] = include_bytes!("testdata/erofs-flat-multiblock-v1.8.10.img");
const ROOT: usize = 36 * 32;
const APP: usize = 50 * 32;

fn limits() -> ReceivedViewLimits {
    ReceivedViewLimits {
        mount: ErofsMountLimits {
            view: super::super::mounted_view_check::MountedViewLimits {
                inodes: 256,
                live_file_bytes: 64 * 1024,
                path_bytes: 256,
                path_components: 8,
                directory_entry_bytes: 64 * 1024,
            },
            backing_bytes: 64 * 1024,
            ramfs_data_bytes: 64 * 1024,
            wall_time: Duration::from_secs(10),
        },
        inventory_path_bytes: 64 * 1024,
    }
}

fn elf_limits() -> StaticElfLimits {
    StaticElfLimits {
        file_bytes: 8192,
        program_headers: 8,
        mapped_bytes: 8192,
        virtual_span_bytes: 8192,
    }
}

fn spec() -> BoundEffectiveSpec {
    let raw = serde_json::to_vec(&spec_fixture::fixture_value()).unwrap();
    let digest: String = Sha384::digest(&raw)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    BoundEffectiveSpec::parse(
        &raw,
        &digest,
        &spec_fixture::policy(),
        spec_fixture::limits(),
    )
    .unwrap()
}

fn expected(bytes: &[u8]) -> ReceivedOriginExpectation {
    ReceivedOriginExpectation {
        image_sha384: Sha384::digest(bytes).into(),
        byte_len: bytes.len() as u64,
    }
}

fn repair_checksum(bytes: &mut [u8]) {
    let mut crc = !0u32;
    for (index, byte) in bytes[SUPER..4096].iter().enumerate() {
        crc ^= if (4..8).contains(&index) {
            0
        } else {
            u32::from(*byte)
        };
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0x82f6_3b78 & 0u32.wrapping_sub(crc & 1));
        }
    }
    bytes[SUPER + 4..SUPER + 8].copy_from_slice(&crc.to_le_bytes());
}

#[test]
fn native_image_inventory_is_derived_from_actual_metadata_and_payload() {
    let inventory = read_inventory(IMAGE, limits(), &|| false).unwrap();
    assert_eq!(inventory.len(), 5);
    let root = inventory.iter().find(|node| node.path == ".").unwrap();
    assert!(root.is_dir);
    assert_eq!(
        (root.mode, root.uid, root.gid, root.mtime, root.size),
        (0o755, 0, 0, 0, 0)
    );
    let app = inventory
        .iter()
        .find(|node| node.path == "bin/app")
        .unwrap();
    assert!(!app.is_dir);
    assert_eq!(
        (app.mode, app.uid, app.gid, app.mtime, app.size),
        (0o555, 70000, 80000, 456, 7)
    );
    assert_eq!(app.payload_sha384, Some(Sha384::digest(b"payload").into()));
    let zero = inventory.iter().find(|node| node.path == "zero").unwrap();
    assert_eq!(zero.size, 0);
    assert_eq!(zero.payload_sha384, Some(Sha384::digest(b"").into()));
    // A separate existing verifier agrees with the derived inventory, without
    // constructing any producer typed result or accepting caller inventory.
    assert!(super::super::erofs_reader::verify_erofs(IMAGE, &inventory).is_ok());
}

#[test]
fn native_multiblock_directory_and_regular_file_inventory_is_complete() {
    let inventory = read_inventory(MULTIBLOCK, limits(), &|| false).unwrap();
    assert_eq!(inventory.len(), 162);
    let large = inventory.iter().find(|node| node.path == "large").unwrap();
    assert_eq!(large.size, 5003);
    let payload: Vec<_> = (0..5003).map(|index| (index % 251) as u8).collect();
    assert_eq!(large.payload_sha384, Some(Sha384::digest(&payload).into()));
    assert!(super::super::erofs_reader::verify_erofs(MULTIBLOCK, &inventory).is_ok());
}

#[test]
fn decoded_inventory_has_independent_inode_path_depth_and_payload_limits() {
    for case in 0..5 {
        let mut bound = limits();
        match case {
            0 => bound.mount.view.inodes = 4,
            1 => bound.mount.view.path_bytes = 6,
            2 => bound.mount.view.path_components = 1,
            3 => bound.mount.view.live_file_bytes = 6,
            4 => bound.inventory_path_bytes = 1,
            _ => unreachable!(),
        }
        assert!(matches!(
            read_inventory(IMAGE, bound, &|| false),
            Err(ReceivedViewError::TooLarge)
        ));
    }
    let mut bound = limits();
    bound.mount.view.inodes = 161;
    assert!(matches!(
        read_inventory(MULTIBLOCK, bound, &|| false),
        Err(ReceivedViewError::TooLarge)
    ));
}

#[test]
fn parser_rejects_unsupported_metadata_before_any_mount() {
    for (offset, replacement) in [
        (APP + 4, 0o120555u16.to_le_bytes().to_vec()),
        (APP + 4, 0o104555u16.to_le_bytes().to_vec()),
        (APP + 24, u32::MAX.to_le_bytes().to_vec()),
        (APP + 28, u32::MAX.to_le_bytes().to_vec()),
        (APP + 32, u64::MAX.to_le_bytes().to_vec()),
        (APP + 40, 1u32.to_le_bytes().to_vec()),
        (APP + 44, 2u32.to_le_bytes().to_vec()),
        (ROOT + 44, 2u32.to_le_bytes().to_vec()),
        (SUPER + 80, 1u32.to_le_bytes().to_vec()),
    ] {
        let mut image = IMAGE.to_vec();
        image[offset..offset + replacement.len()].copy_from_slice(&replacement);
        repair_checksum(&mut image);
        assert!(
            matches!(
                read_inventory(&image, limits(), &|| false),
                Err(ReceivedViewError::ImageRejected)
            ),
            "metadata offset{offset}"
        );
    }
    assert!(read_inventory(&IMAGE[..IMAGE.len() - 1], limits(), &|| false).is_err());
}

#[test]
fn actual_directory_nid_reuse_and_superblock_node_count_do_not_bypass_inventory() {
    let mut repeated = IMAGE.to_vec();
    // The root's first non-dot entry refers back to the root inode.
    let root_inline = ROOT + 64;
    let entry_nid = root_inline + 2 * 12;
    repeated[entry_nid..entry_nid + 8].copy_from_slice(&36u64.to_le_bytes());
    repair_checksum(&mut repeated);
    assert!(matches!(
        read_inventory(&repeated, limits(), &|| false),
        Err(ReceivedViewError::ImageRejected)
    ));
    for declared in [0u64, 4, 6, u64::MAX] {
        let mut changed = IMAGE.to_vec();
        changed[SUPER + 16..SUPER + 24].copy_from_slice(&declared.to_le_bytes());
        repair_checksum(&mut changed);
        assert!(read_inventory(&changed, limits(), &|| false).is_err());
    }
}

#[test]
fn snapshot_uses_immutable_source_and_cooperative_cancel_without_shared_offset_changes() {
    let sealed = SealedImageBytes::from_bytes(MULTIBLOCK, 65536).unwrap();
    // SAFETY: lseek only changes/inspects the live sealed source description.
    assert_eq!(
        unsafe { libc::lseek(sealed.as_fd().as_raw_fd(), 5, libc::SEEK_SET) },
        5
    );
    assert_eq!(&**read_snapshot(&sealed, &|| false).unwrap(), MULTIBLOCK);
    assert_eq!(
        unsafe { libc::lseek(sealed.as_fd().as_raw_fd(), 0, libc::SEEK_CUR) },
        5
    );
    let calls = Cell::new(0);
    let cancelled = || {
        calls.set(calls.get() + 1);
        calls.get() >= 3
    };
    assert!(matches!(
        read_snapshot(&sealed, &cancelled),
        Err(ReceivedViewError::Cancelled)
    ));
    assert!(matches!(
        read_inventory(IMAGE, limits(), &|| true),
        Err(ReceivedViewError::Cancelled)
    ));
    let calls = Cell::new(0);
    let cancelled = || {
        calls.set(calls.get() + 1);
        calls.get() >= 6
    };
    assert!(matches!(
        read_inventory(MULTIBLOCK, limits(), &cancelled),
        Err(ReceivedViewError::Cancelled)
    ));
}

struct DescriptorStamp {
    number: i32,
    target: PathBuf,
}

impl DescriptorStamp {
    fn new(fd: &OwnedFd) -> Self {
        let number = fd.as_raw_fd();
        Self {
            number,
            target: std::fs::read_link(format!("/proc/self/fd/{number}")).unwrap(),
        }
    }

    fn assert_closed(&self) {
        assert!(
            !std::fs::read_link(format!("/proc/self/fd/{}", self.number))
                .is_ok_and(|path| path == self.target)
        );
    }
}

fn received_source(bytes: &[u8], sealed: bool) -> OwnedFd {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let name = CString::new(format!(
        "received-view-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ))
    .unwrap();
    let descriptor = memfd_create(
        name.as_c_str(),
        MFdFlags::MFD_CLOEXEC
            | MFdFlags::MFD_ALLOW_SEALING
            | MFdFlags::from_bits_retain(libc::MFD_NOEXEC_SEAL),
    )
    .unwrap();
    let file = File::from(descriptor);
    file.write_all_at(bytes, 0).unwrap();
    if sealed {
        // SAFETY: adding fixed irreversible data-only seals to a live memfd.
        assert_eq!(
            unsafe {
                libc::fcntl(
                    file.as_raw_fd(),
                    libc::F_ADD_SEALS,
                    libc::F_SEAL_WRITE
                        | libc::F_SEAL_GROW
                        | libc::F_SEAL_SHRINK
                        | libc::F_SEAL_SEAL
                        | libc::F_SEAL_EXEC,
                )
            },
            0
        );
    }
    file.into()
}

#[test]
fn consuming_receiver_rejects_and_closes_bad_origin_before_mount() {
    for case in 0..5 {
        let fd = received_source(IMAGE, case != 0);
        let stamp = DescriptorStamp::new(&fd);
        let mut expectation = expected(IMAGE);
        match case {
            0 => (), // missing data seals
            1 => expectation.image_sha384[0] ^= 1,
            2 => expectation.byte_len -= 1,
            3 => expectation.byte_len = 0,
            4 => expectation.byte_len = 65537,
            _ => unreachable!(),
        }
        assert!(matches!(
            ReceivedMountedView::from_sealed_origin(
                fd,
                expectation,
                &spec(),
                elf_limits(),
                limits(),
                &|| false
            ),
            Err(ReceivedViewError::BackingRejected)
        ));
        stamp.assert_closed();
    }
    let fd = received_source(b"not erofs", true);
    let stamp = DescriptorStamp::new(&fd);
    assert!(ReceivedMountedView::from_sealed_origin(
        fd,
        expected(b"not erofs"),
        &spec(),
        elf_limits(),
        limits(),
        &|| false
    )
    .is_err());
    stamp.assert_closed();
}

#[test]
fn invalid_receiver_limits_and_precancellation_close_incoming_descriptors() {
    for case in 0..4 {
        let fd = received_source(IMAGE, true);
        let stamp = DescriptorStamp::new(&fd);
        let mut bound = limits();
        let mut elf = elf_limits();
        match case {
            0 => bound.inventory_path_bytes = 0,
            1 => bound.inventory_path_bytes = usize::MAX,
            2 => bound.mount.ramfs_data_bytes = 0,
            3 => elf.file_bytes = 0,
            _ => unreachable!(),
        }
        assert!(matches!(
            ReceivedMountedView::from_sealed_origin(
                fd,
                expected(IMAGE),
                &spec(),
                elf,
                bound,
                &|| false
            ),
            Err(ReceivedViewError::InvalidLimits)
        ));
        stamp.assert_closed();
    }
    let fd = received_source(IMAGE, true);
    let stamp = DescriptorStamp::new(&fd);
    assert!(matches!(
        ReceivedMountedView::from_sealed_origin(
            fd,
            expected(IMAGE),
            &spec(),
            elf_limits(),
            limits(),
            &|| true
        ),
        Err(ReceivedViewError::Cancelled)
    ));
    stamp.assert_closed();
}
