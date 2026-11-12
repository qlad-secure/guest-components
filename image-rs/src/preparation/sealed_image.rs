// SPDX-License-Identifier: Apache-2.0

//! Owned, bounded, immutable data bytes, not a prepared filesystem or lease.
//!
//! This data-only profile requires Linux support for `MFD_NOEXEC_SEAL`
//! (introduced in Linux 6.3). Unsupported or unavailable memfds fail closed;
//! there is no executable-memfd or `F_SEAL_FUTURE_WRITE` fallback. The kernel
//! requirement applies whenever this optional primitive is enabled.
//! SHA384 here commits to these bytes; it is not an OCI SHA256 digest domain.

use nix::{
    fcntl::{fcntl, FcntlArg, FdFlag, SealFlag},
    libc,
    sys::{
        memfd::{memfd_create, MFdFlags},
        stat::fstat,
    },
};
use sha2::{Digest, Sha384};
use std::{
    fs::File,
    io,
    os::{
        fd::{AsFd, BorrowedFd, OwnedFd},
        unix::fs::FileExt,
    },
};

const CONTENT_SEALS: SealFlag = SealFlag::F_SEAL_WRITE
    .union(SealFlag::F_SEAL_GROW)
    .union(SealFlag::F_SEAL_SHRINK)
    .union(SealFlag::F_SEAL_SEAL);
const REQUIRED_SEAL_BITS: i32 = CONTENT_SEALS.bits() | libc::F_SEAL_EXEC;
const HASH_CHUNK_BYTES: usize = 8192;

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SealedImageError {
    #[error("sealed byte limit must be nonzero")]
    InvalidLimit,
    #[error("sealed bytes must be nonempty")]
    Empty,
    #[error("sealed bytes exceed the configured limit")]
    TooLarge,
    #[error("data-only memfd unavailable; supported Linux 6.3+ is required")]
    MemfdUnavailable,
    #[error("file does not support the required memfd seals")]
    SealsUnavailable,
    #[error("required immutable data seals are missing")]
    MissingSeals,
    #[error("immutable data seals could not be installed")]
    SealFailed,
    #[error("sealed bytes require a regular file")]
    NotRegular,
    #[error("sealed backing file must not be executable")]
    ExecutableBacking,
    #[error("sealed byte digest differs from the expected digest")]
    DigestMismatch,
    #[error("sealed byte file operation failed")]
    FileOperation,
}

/// Unique ownership of one sealed byte container, with no Clone/Debug/serde.
///
/// A borrowed FD permits immutable aliases for a future consumer/transport.
/// Neither this type nor an FD alias is a one-use admission/rootfs capability.
/// The caller owns the size policy and the origin of any expected digest.
pub struct SealedImageBytes {
    file: File,
    byte_len: u64,
    sha384: [u8; 48],
}

impl SealedImageBytes {
    /// Copy a bounded byte slice into a new data-only memfd and seal it.
    /// Arbitrary bytes are allowed; no filesystem or provenance is verified.
    /// No pathname, generic reader, mount, process, or network operation occurs.
    pub fn from_bytes(bytes: &[u8], max_bytes: u64) -> Result<Self, SealedImageError> {
        check_size(bytes.len() as u64, max_bytes)?;
        // Nix 0.31 does not name this flag yet; retain the Linux UAPI bit.
        let flags = MFdFlags::MFD_CLOEXEC
            | MFdFlags::MFD_ALLOW_SEALING
            | MFdFlags::from_bits_retain(libc::MFD_NOEXEC_SEAL);
        let fd = memfd_create("onb17-sealed-image-bytes", flags)
            .map_err(|_| SealedImageError::MemfdUnavailable)?;
        let file = File::from(fd);
        file.write_all_at(bytes, 0)
            .map_err(|_| SealedImageError::FileOperation)?;
        fcntl(&file, FcntlArg::F_ADD_SEALS(CONTENT_SEALS))
            .map_err(|_| SealedImageError::SealFailed)?;
        // Reuse the receiver checks and recompute the digest only after sealing.
        Self::from_received_fd(file.into(), max_bytes, Sha384::digest(bytes).into())
    }

    /// Adopt a descriptor only after verifying immutable inode seals and hashing
    /// its entire bounded contents with position-independent reads. No resealing,
    /// chmod, truncation, shared-offset read, or arbitrary blocking reader occurs.
    /// The descriptor is closed on every rejection; accepted FDs are CLOEXEC.
    /// Expected SHA384 equality establishes byte agreement, not trusted origin.
    pub fn from_received_fd(
        fd: OwnedFd,
        max_bytes: u64,
        expected_sha384: [u8; 48],
    ) -> Result<Self, SealedImageError> {
        let file = File::from(fd);
        if max_bytes == 0 {
            return Err(SealedImageError::InvalidLimit);
        }
        fcntl(&file, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC))
            .map_err(|_| SealedImageError::FileOperation)?;
        let seals =
            fcntl(&file, FcntlArg::F_GET_SEALS).map_err(|_| SealedImageError::SealsUnavailable)?;
        if seals & REQUIRED_SEAL_BITS != REQUIRED_SEAL_BITS {
            return Err(SealedImageError::MissingSeals);
        }
        // Size and mode are sampled after the mandatory seals were observed.
        let metadata = fstat(&file).map_err(|_| SealedImageError::FileOperation)?;
        if metadata.st_mode & libc::S_IFMT != libc::S_IFREG {
            return Err(SealedImageError::NotRegular);
        }
        if metadata.st_mode & 0o111 != 0 {
            return Err(SealedImageError::ExecutableBacking);
        }
        let byte_len =
            u64::try_from(metadata.st_size).map_err(|_| SealedImageError::FileOperation)?;
        check_size(byte_len, max_bytes)?;
        let sha384 = digest_file(&file, byte_len).map_err(|_| SealedImageError::FileOperation)?;
        if sha384 != expected_sha384 {
            return Err(SealedImageError::DigestMismatch);
        }
        Ok(Self {
            file,
            byte_len,
            sha384,
        })
    }

    pub fn byte_len(&self) -> u64 {
        self.byte_len
    }

    pub fn sha384(&self) -> &[u8; 48] {
        &self.sha384
    }
}

impl AsFd for SealedImageBytes {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.file.as_fd()
    }
}

fn check_size(byte_len: u64, max_bytes: u64) -> Result<(), SealedImageError> {
    if max_bytes == 0 {
        Err(SealedImageError::InvalidLimit)
    } else if byte_len == 0 {
        Err(SealedImageError::Empty)
    } else if byte_len > max_bytes {
        Err(SealedImageError::TooLarge)
    } else {
        Ok(())
    }
}

fn digest_file(file: &File, byte_len: u64) -> io::Result<[u8; 48]> {
    let mut digest = Sha384::new();
    let mut offset = 0;
    let mut buffer = [0u8; HASH_CHUNK_BYTES];
    while offset < byte_len {
        let remaining = (byte_len - offset).min(HASH_CHUNK_BYTES as u64) as usize;
        let count = file.read_at(&mut buffer[..remaining], offset)?;
        if count == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        digest.update(&buffer[..count]);
        offset += count as u64;
    }
    Ok(digest.finalize().into())
}
