// SPDX-License-Identifier: Apache-2.0

use super::*;
use nix::sys::memfd::{memfd_create, MFdFlags};
use std::{
    cell::Cell,
    io::{Seek, SeekFrom},
};

fn destination() -> File {
    let flags = MFdFlags::MFD_CLOEXEC | MFdFlags::from_bits_retain(libc::MFD_NOEXEC_SEAL);
    File::from(memfd_create("ramfs-copy-test", flags).unwrap())
}

#[test]
fn allocation_budget_counts_the_last_partial_page() {
    assert_eq!(check_payload_budget(1, 4096, 4096), Ok(()));
    assert_eq!(check_payload_budget(4096, 4096, 4096), Ok(()));
    assert_eq!(
        check_payload_budget(4097, 4097, 4096),
        Err(RamImageError::TooLarge)
    );
    assert_eq!(check_payload_budget(4097, 8192, 4096), Ok(()));
    // Runtime page size is deliberately an input: a 4K-only policy is invalid
    // on a system whose RAMFS allocates 64K pages.
    assert_eq!(
        check_payload_budget(4096, 4096, 65536),
        Err(RamImageError::TooLarge)
    );
    assert_eq!(check_payload_budget(4096, 65536, 65536), Ok(()));
}

#[test]
fn allocation_budget_rejects_empty_invalid_and_overflowing_inputs() {
    assert_eq!(
        check_payload_budget(1, 0, 4096),
        Err(RamImageError::InvalidLimit)
    );
    assert_eq!(
        check_payload_budget(1, 4096, 0),
        Err(RamImageError::InvalidLimit)
    );
    assert_eq!(
        check_payload_budget(0, 4096, 4096),
        Err(RamImageError::Profile)
    );
    assert_eq!(
        check_payload_budget(u64::MAX, 4096, 4096),
        Err(RamImageError::TooLarge)
    );
    assert_eq!(
        check_payload_budget((isize::MAX - 1) as u64, isize::MAX as usize, 4096),
        Err(RamImageError::TooLarge)
    );
    assert_eq!(
        check_payload_budget(1, usize::MAX, 4096),
        Err(RamImageError::InvalidLimit)
    );
}

#[test]
fn copy_and_hash_cover_every_byte_without_changing_offsets() {
    let bytes: Vec<u8> = (0..(2 * CHUNK_BYTES + 17)).map(|i| i as u8).collect();
    let source = SealedImageBytes::from_bytes(&bytes, bytes.len() as u64).unwrap();
    let mut file = destination();
    file.seek(SeekFrom::Start(7)).unwrap();
    // SAFETY: lseek changes only the live sealed source's shared offset, not
    // its immutable data. The copy must use positional reads despite it.
    assert_eq!(
        unsafe { libc::lseek(source.as_fd().as_raw_fd(), 5, libc::SEEK_SET) },
        5
    );
    copy_source(&source, &file, &|| false).unwrap();
    assert_eq!(file.stream_position().unwrap(), 7);
    assert_eq!(
        unsafe { libc::lseek(source.as_fd().as_raw_fd(), 0, libc::SEEK_CUR) },
        5
    );
    assert_eq!(file.metadata().unwrap().len(), bytes.len() as u64);
    assert_eq!(
        digest_file(&file, bytes.len() as u64, &|| false).unwrap(),
        *source.sha384()
    );
    let mut actual = vec![0; bytes.len()];
    file.read_exact_at(&mut actual, 0).unwrap();
    assert_eq!(actual, bytes);
}

#[test]
fn copy_cancellation_stops_between_bounded_chunks() {
    let bytes = vec![7; 3 * CHUNK_BYTES];
    let source = SealedImageBytes::from_bytes(&bytes, bytes.len() as u64).unwrap();
    let file = destination();
    let calls = Cell::new(0);
    assert_eq!(
        copy_source(&source, &file, &|| {
            calls.set(calls.get() + 1);
            calls.get() >= 3
        }),
        Err(RamImageError::Cancelled)
    );
    assert_eq!(file.metadata().unwrap().len(), CHUNK_BYTES as u64);
}

#[test]
fn hash_rejects_short_read_and_checks_cancellation() {
    let file = destination();
    file.write_all_at(b"bounded bytes", 0).unwrap();
    assert_eq!(
        digest_file(&file, 14, &|| false),
        Err(RamImageError::Operation)
    );
    assert_eq!(
        digest_file(&file, 13, &|| true),
        Err(RamImageError::Cancelled)
    );
}

#[test]
fn constructor_rejects_limits_and_cancellation_before_mounting() {
    let source = SealedImageBytes::from_bytes(b"bytes", 5).unwrap();
    assert!(matches!(
        ReadOnlyRamImage::from_sealed(&source, 0, &|| false),
        Err(RamImageError::InvalidLimit)
    ));
    assert!(matches!(
        ReadOnlyRamImage::from_sealed(&source, 1, &|| false),
        Err(RamImageError::TooLarge)
    ));
    assert!(matches!(
        ReadOnlyRamImage::from_sealed(&source, 4096, &|| true),
        Err(RamImageError::Cancelled)
    ));
}
