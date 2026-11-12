//! Checks of the optional immutable-byte module with the parent workspace's
//! other dependencies excluded. No mount, root privilege, or listener is needed.

#[cfg(feature = "launch-preparation")]
#[path = "../../../src/preparation/mod.rs"]
pub mod preparation;

#[cfg(all(test, feature = "launch-preparation"))]
mod tests {
    use super::preparation::{SealedImageBytes, SealedImageError};
    use nix::{
        errno::Errno,
        fcntl::{fcntl, FcntlArg, FdFlag, SealFlag},
        libc,
        sys::{
            memfd::{memfd_create, MFdFlags},
            stat::{fchmod, fstat, Mode},
        },
        unistd::{dup, ftruncate, pipe},
    };
    use sha2::{Digest, Sha384};
    use std::{
        fs::File,
        io::{Seek, SeekFrom},
        os::{
            fd::{AsFd, AsRawFd, OwnedFd},
            unix::fs::FileExt,
        },
        sync::Mutex,
    };

    const DATA: &[u8] = b"arbitrary bytes; not a verified filesystem";
    const LIMIT: u64 = 64 * 1024;
    // FD-number closure assertions must not race this suite's other allocations.
    static FD_CASES: Mutex<()> = Mutex::new(());

    fn digest(bytes: &[u8]) -> [u8; 48] {
        Sha384::digest(bytes).into()
    }

    fn content_seals() -> SealFlag {
        SealFlag::F_SEAL_WRITE
            | SealFlag::F_SEAL_GROW
            | SealFlag::F_SEAL_SHRINK
            | SealFlag::F_SEAL_SEAL
    }

    fn raw_data_memfd(bytes: &[u8]) -> File {
        let file = File::from(
            memfd_create(
                "sealed-byte-test",
                MFdFlags::MFD_CLOEXEC
                    | MFdFlags::MFD_ALLOW_SEALING
                    | MFdFlags::from_bits_retain(libc::MFD_NOEXEC_SEAL),
            )
            .unwrap(),
        );
        file.write_all_at(bytes, 0).unwrap();
        file
    }

    fn executable_memfd() -> File {
        let file = File::from(
            memfd_create(
                "executable-negative-fixture",
                MFdFlags::MFD_CLOEXEC
                    | MFdFlags::MFD_ALLOW_SEALING
                    | MFdFlags::from_bits_retain(libc::MFD_EXEC),
            )
            .expect("negative fixture requires host policy permitting MFD_EXEC"),
        );
        file.write_all_at(DATA, 0).unwrap();
        file
    }

    fn assert_closed(raw_fd: i32) {
        // Every FD-allocating test holds FD_CASES. Do not create another
        // descriptor between dropping the owner and this kernel check.
        assert_eq!(unsafe { libc::fcntl(raw_fd, libc::F_GETFD) }, -1);
        assert_eq!(Errno::last(), Errno::EBADF);
    }

    #[test]
    fn actual_memfd_has_all_content_and_noexec_seals() {
        let _guard = FD_CASES.lock().unwrap();
        let image = SealedImageBytes::from_bytes(DATA, LIMIT).unwrap();
        assert_eq!(image.byte_len(), DATA.len() as u64);
        assert_eq!(image.sha384(), &digest(DATA));
        let seals = fcntl(&image, FcntlArg::F_GET_SEALS).unwrap();
        assert_eq!(seals & content_seals().bits(), content_seals().bits());
        assert_ne!(seals & libc::F_SEAL_EXEC, 0);
        assert_eq!(fstat(&image).unwrap().st_mode & 0o111, 0);
        assert_ne!(
            fcntl(&image, FcntlArg::F_GETFD).unwrap() & libc::FD_CLOEXEC,
            0
        );
    }

    #[test]
    fn actual_alias_cannot_write_resize_map_writable_or_enable_exec() {
        let _guard = FD_CASES.lock().unwrap();
        let image = SealedImageBytes::from_bytes(DATA, LIMIT).unwrap();
        let alias = File::from(dup(&image).unwrap());
        assert_eq!(
            alias.write_at(b"X", 0).unwrap_err().raw_os_error(),
            Some(libc::EPERM)
        );
        assert_eq!(ftruncate(&alias, 0), Err(Errno::EPERM));
        assert_eq!(ftruncate(&alias, DATA.len() as i64 + 1), Err(Errno::EPERM));
        let mapping = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                DATA.len(),
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                alias.as_raw_fd(),
                0,
            )
        };
        assert_eq!(mapping, libc::MAP_FAILED);
        assert_eq!(Errno::last(), Errno::EPERM);
        assert_eq!(
            fchmod(&alias, Mode::from_bits_truncate(0o700)),
            Err(Errno::EPERM)
        );
        let mut actual = vec![0; DATA.len()];
        alias.read_exact_at(&mut actual, 0).unwrap();
        assert_eq!(actual, DATA);
    }

    #[test]
    fn receiver_hashes_all_chunks_without_using_or_changing_shared_offset() {
        let _guard = FD_CASES.lock().unwrap();
        let bytes: Vec<u8> = (0..20_003).map(|index| (index % 251) as u8).collect();
        let image = SealedImageBytes::from_bytes(&bytes, LIMIT).unwrap();
        let mut alias = File::from(dup(&image).unwrap());
        alias.seek(SeekFrom::End(0)).unwrap();
        let received_fd = dup(&image).unwrap();
        fcntl(&received_fd, FcntlArg::F_SETFD(FdFlag::empty())).unwrap();
        let adopted =
            SealedImageBytes::from_received_fd(received_fd, LIMIT, digest(&bytes)).unwrap();
        assert_eq!(adopted.sha384(), image.sha384());
        assert_eq!(adopted.byte_len(), bytes.len() as u64);
        assert_eq!(alias.stream_position().unwrap(), bytes.len() as u64);
        assert_ne!(
            fcntl(&adopted, FcntlArg::F_GETFD).unwrap() & libc::FD_CLOEXEC,
            0
        );
    }

    #[test]
    fn wrong_expected_hash_rejects_and_closes_received_fd() {
        let _guard = FD_CASES.lock().unwrap();
        let image = SealedImageBytes::from_bytes(DATA, LIMIT).unwrap();
        let fd = dup(&image).unwrap();
        let raw = fd.as_raw_fd();
        assert_eq!(
            SealedImageBytes::from_received_fd(fd, LIMIT, [0; 48]).err(),
            Some(SealedImageError::DigestMismatch)
        );
        assert_closed(raw);
    }

    #[test]
    fn empty_oversize_and_zero_limit_are_rejected() {
        let _guard = FD_CASES.lock().unwrap();
        assert_eq!(
            SealedImageBytes::from_bytes(b"", LIMIT).err(),
            Some(SealedImageError::Empty)
        );
        assert_eq!(
            SealedImageBytes::from_bytes(DATA, 1).err(),
            Some(SealedImageError::TooLarge)
        );
        assert_eq!(
            SealedImageBytes::from_bytes(DATA, 0).err(),
            Some(SealedImageError::InvalidLimit)
        );
        assert_eq!(
            SealedImageBytes::from_bytes(DATA, DATA.len() as u64)
                .unwrap()
                .byte_len(),
            DATA.len() as u64
        );
        let empty = raw_data_memfd(b"");
        fcntl(&empty, FcntlArg::F_ADD_SEALS(content_seals())).unwrap();
        assert_eq!(
            SealedImageBytes::from_received_fd(empty.into(), LIMIT, digest(b"")).err(),
            Some(SealedImageError::Empty)
        );
        let image = SealedImageBytes::from_bytes(DATA, LIMIT).unwrap();
        let too_big = dup(&image).unwrap();
        let raw = too_big.as_raw_fd();
        assert_eq!(
            SealedImageBytes::from_received_fd(too_big, 1, digest(DATA)).err(),
            Some(SealedImageError::TooLarge)
        );
        assert_closed(raw);
    }

    #[test]
    fn plain_regular_file_and_pipe_are_rejected_without_reading() {
        let _guard = FD_CASES.lock().unwrap();
        let plain = File::open(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml")).unwrap();
        assert!(SealedImageBytes::from_received_fd(plain.into(), LIMIT, [0; 48]).is_err());
        let (read, _write) = pipe().unwrap();
        // A generic read would block: the pipe is empty and its writer is open.
        assert!(SealedImageBytes::from_received_fd(read, LIMIT, [0; 48]).is_err());
    }

    #[test]
    fn every_required_content_seal_is_checked_and_not_repaired() {
        let _guard = FD_CASES.lock().unwrap();
        for missing in [
            SealFlag::F_SEAL_WRITE,
            SealFlag::F_SEAL_GROW,
            SealFlag::F_SEAL_SHRINK,
            SealFlag::F_SEAL_SEAL,
        ] {
            let file = raw_data_memfd(DATA);
            let weaker = content_seals() & !missing;
            fcntl(&file, FcntlArg::F_ADD_SEALS(weaker)).unwrap();
            let alias = dup(&file).unwrap();
            let before = fcntl(&file, FcntlArg::F_GET_SEALS).unwrap();
            assert_eq!(
                SealedImageBytes::from_received_fd(alias, LIMIT, digest(DATA)).err(),
                Some(SealedImageError::MissingSeals)
            );
            assert_eq!(fcntl(&file, FcntlArg::F_GET_SEALS).unwrap(), before);
        }
    }

    #[test]
    fn receiver_rejects_missing_noexec_seal_without_repairing_it() {
        let _guard = FD_CASES.lock().unwrap();
        let file = executable_memfd();
        fcntl(&file, FcntlArg::F_ADD_SEALS(content_seals())).unwrap();
        let before = fcntl(&file, FcntlArg::F_GET_SEALS).unwrap();
        assert_eq!(before & libc::F_SEAL_EXEC, 0);
        assert_eq!(
            SealedImageBytes::from_received_fd(dup(&file).unwrap(), LIMIT, digest(DATA)).err(),
            Some(SealedImageError::MissingSeals)
        );
        assert_eq!(fcntl(&file, FcntlArg::F_GET_SEALS).unwrap(), before);
    }

    #[test]
    fn receiver_rejects_executable_backing_even_when_all_seals_are_present() {
        let _guard = FD_CASES.lock().unwrap();
        let file = executable_memfd();
        let seals = content_seals() | SealFlag::from_bits_retain(libc::F_SEAL_EXEC);
        fcntl(&file, FcntlArg::F_ADD_SEALS(seals)).unwrap();
        assert_ne!(fstat(&file).unwrap().st_mode & 0o111, 0);
        assert_eq!(
            SealedImageBytes::from_received_fd(dup(&file).unwrap(), LIMIT, digest(DATA)).err(),
            Some(SealedImageError::ExecutableBacking)
        );
    }

    #[test]
    fn writable_mapping_prevents_strong_seal_and_future_write_is_not_accepted() {
        let _guard = FD_CASES.lock().unwrap();
        let file = raw_data_memfd(DATA);
        let mapping = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                DATA.len(),
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                file.as_raw_fd(),
                0,
            )
        };
        assert_ne!(mapping, libc::MAP_FAILED);
        assert_eq!(
            fcntl(&file, FcntlArg::F_ADD_SEALS(SealFlag::F_SEAL_WRITE)),
            Err(Errno::EBUSY)
        );
        let weaker = SealFlag::F_SEAL_FUTURE_WRITE
            | SealFlag::F_SEAL_GROW
            | SealFlag::F_SEAL_SHRINK
            | SealFlag::F_SEAL_SEAL;
        fcntl(&file, FcntlArg::F_ADD_SEALS(weaker)).unwrap();
        unsafe { mapping.cast::<u8>().write(b'X') };
        assert_eq!(
            SealedImageBytes::from_received_fd(dup(&file).unwrap(), LIMIT, digest(DATA)).err(),
            Some(SealedImageError::MissingSeals)
        );
        assert_eq!(unsafe { libc::munmap(mapping, DATA.len()) }, 0);
    }

    #[test]
    fn drop_closes_the_owned_descriptor_but_immutable_alias_survives() {
        let _guard = FD_CASES.lock().unwrap();
        let image = SealedImageBytes::from_bytes(DATA, LIMIT).unwrap();
        let alias: OwnedFd = dup(&image).unwrap();
        let raw = image.as_fd().as_raw_fd();
        drop(image);
        assert_closed(raw);
        let alias = File::from(alias);
        let mut bytes = vec![0; DATA.len()];
        alias.read_exact_at(&mut bytes, 0).unwrap();
        assert_eq!(bytes, DATA);
        let raw = alias.as_raw_fd();
        drop(alias);
        assert_closed(raw);
    }
}
