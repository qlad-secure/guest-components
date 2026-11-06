// SPDX-License-Identifier: Apache-2.0

//! Native qualification of the actual private read-only RAMFS adapter.
//! Run in a fresh user and mount namespace. No EROFS, loop device, host mountpoint
//! or workload executable is used; this checks the data-copy custody primitive.

pub use onb17_sealed_image_source_checks::preparation::SealedImageBytes;
// Clippy's harness=false check includes the source module's unit-test helpers
// without registering its #[test] functions. The library checks that suite.
#[cfg_attr(test, allow(dead_code, unused_imports))]
#[path = "../../src/preparation/readonly_ramfs.rs"]
mod readonly_ramfs;

use nix::libc;
use readonly_ramfs::{RamImageError, ReadOnlyRamImage};
use serde_json::{json, Value};
use sha2::{Digest, Sha384};
use std::{
    cell::Cell,
    fs::{self, File},
    io::{self, Read},
    os::{
        fd::AsRawFd,
        unix::fs::{FileExt, MetadataExt},
    },
    path::Path,
    process::ExitCode,
};

type Check<T> = Result<T, String>;
const RAMFS_MAGIC: libc::c_long = 0x8584_58f6u32 as libc::c_long;

fn main() -> ExitCode {
    if std::env::args_os().len() != 1 {
        eprintln!("usage: native-ramfs-backing");
        return ExitCode::from(2);
    }
    if let Err(reason) = preflight() {
        eprintln!(
            "{}",
            json!({"status":"BLOCKED","reason":reason,"scope":"private RAMFS data adapter"})
        );
        return ExitCode::from(77);
    }
    match acceptance() {
        Ok(result) => {
            println!("{result}");
            ExitCode::SUCCESS
        }
        Err(reason) => {
            eprintln!("{}", json!({"status":"FAIL","reason":reason}));
            ExitCode::FAILURE
        }
    }
}
fn preflight() -> Check<()> {
    // A child user namespace cannot necessarily read PID1's namespace links.
    // Require the caller-owned one-user mapping created by the isolated runner.
    let mapping = bounded_read(Path::new("/proc/self/uid_map"), 4096)?;
    let mapping = std::str::from_utf8(&mapping).map_err(|_| "invalid user map")?;
    let fields: Vec<_> = mapping.split_whitespace().collect();
    ensure(
        fields.len() == 3 && fields[0] == "0" && fields[2] == "1",
        "run in an isolated one-user namespace",
    )?;
    fs::read_link("/proc/self/ns/mnt").map_err(|_| "mount namespace unavailable")?;
    let mounts = bounded_read(Path::new("/proc/self/mountinfo"), 2 * 1024 * 1024)?;
    let mounts = std::str::from_utf8(&mounts).map_err(|_| "invalid mountinfo")?;
    ensure(
        mounts.lines().all(|line| {
            line.split(" - ").next().is_some_and(|entry| {
                entry
                    .split_whitespace()
                    .skip(6)
                    .all(|field| !field.starts_with("shared:") && !field.starts_with("master:"))
            })
        }),
        "run with private mount propagation",
    )?;
    let bytes = bounded_read(Path::new("/proc/self/status"), 65536)?;
    let status = std::str::from_utf8(&bytes).map_err(|_| "invalid process status")?;
    let cap = status
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:").map(str::trim))
        .and_then(|value| u64::from_str_radix(value, 16).ok())
        .ok_or("capabilities unavailable")?;
    ensure(
        cap & (1 << 21) != 0,
        "CAP_SYS_ADMIN in the private namespace is required",
    )?;
    let bytes = bounded_read(Path::new("/proc/filesystems"), 65536)?;
    let filesystems = std::str::from_utf8(&bytes).map_err(|_| "invalid filesystem list")?;
    ensure(
        filesystems
            .lines()
            .any(|line| line.split_whitespace().last() == Some("ramfs")),
        "RAMFS must already be registered",
    )
}
fn acceptance() -> Check<Value> {
    // SAFETY: sysconf has no pointer arguments or side effects for this key.
    let page_size = usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) })
        .ok()
        .filter(|size| *size != 0)
        .ok_or("native page size unavailable")?;
    let page_budget = |length: usize| length.div_ceil(page_size) * page_size;
    let mountinfo = bounded_read(Path::new("/proc/self/mountinfo"), 2 * 1024 * 1024)?;
    let fd_before = descriptor_count()?;
    let mut lengths = Vec::new();
    for length in [8192usize, 24576] {
        let bytes: Vec<_> = (0..length)
            .map(|index| ((index * 17 + 31) % 251) as u8)
            .collect();
        let expected: [u8; 48] = Sha384::digest(&bytes).into();
        let sealed = SealedImageBytes::from_bytes(&bytes, length as u64)
            .map_err(|e| format!("seal source: {e}"))?;
        let image = ReadOnlyRamImage::from_sealed(&sealed, page_budget(length), &|| false)
            .map_err(|e| format!("create readonly RAMFS: {e:?}"))?;
        ensure(
            image.byte_len() == length as u64,
            "RAMFS byte length differs",
        )?;
        ensure(
            image.sha384() == &expected && image.sha384() == sealed.sha384(),
            "RAMFS commitment differs from sealed source",
        )?;
        check_readback(image.as_file(), &bytes)?;
        let stat = image
            .as_file()
            .metadata()
            .map_err(|_| "RAMFS file metadata failed")?;
        ensure(
            stat.mode() & libc::S_IFMT == libc::S_IFREG && stat.mode() & 0o111 == 0,
            "RAMFS data file type/mode rejected",
        )?;
        let mut fs = unsafe { std::mem::zeroed::<libc::statfs>() };
        let mut mount = unsafe { std::mem::zeroed::<libc::statvfs>() };
        // SAFETY: initialized output storage and a live owned descriptor.
        ensure(
            unsafe { libc::fstatfs(image.as_file().as_raw_fd(), &mut fs) } == 0,
            "RAMFS statfs failed",
        )?;
        ensure(
            unsafe { libc::fstatvfs(image.as_file().as_raw_fd(), &mut mount) } == 0,
            "RAMFS statvfs failed",
        )?;
        ensure(
            fs.f_type == RAMFS_MAGIC,
            "adapter did not retain a RAMFS data file",
        )?;
        let attrs = libc::ST_RDONLY | libc::ST_NOSUID | libc::ST_NODEV | libc::ST_NOEXEC;
        ensure(
            mount.f_flag & attrs == attrs,
            "RAMFS readonly/nosuid/nodev/noexec attributes missing",
        )?;
        ensure(
            image.as_file().write_at(b"x", 0).is_err(),
            "read-only RAMFS descriptor accepted write",
        )?;
        // SAFETY: valid owned FD; these operations must fail without mutation.
        ensure(
            unsafe { libc::ftruncate(image.as_file().as_raw_fd(), 0) } == -1,
            "RAMFS descriptor accepted truncate",
        )?;
        ensure(
            unsafe { libc::fchmod(image.as_file().as_raw_fd(), 0o700) } == -1,
            "readonly RAMFS accepted chmod",
        )?;
        ensure(
            io::Error::last_os_error().raw_os_error() == Some(libc::EROFS),
            "chmod did not observe a readonly superblock",
        )?;
        let writable = File::options()
            .write(true)
            .open(format!("/proc/self/fd/{}", image.as_file().as_raw_fd()));
        ensure(writable.is_err(), "RAMFS data path reopened writable")?;
        ensure(
            writable.err().and_then(|e| e.raw_os_error()) == Some(libc::EROFS),
            "writable reopen did not observe readonly superblock",
        )?;
        // SAFETY: a negative shared-writer mmap test; MAP_FAILED is not dereferenced.
        let mapping = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                length,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                image.as_file().as_raw_fd(),
                0,
            )
        };
        if mapping != libc::MAP_FAILED {
            unsafe {
                libc::munmap(mapping, length);
            }
            return Err("readonly RAMFS accepted writable shared mapping".into());
        }
        check_readback(image.as_file(), &bytes)?;
        let alias = image
            .as_file()
            .try_clone()
            .map_err(|_| "RAMFS retained alias creation failed")?;
        drop(image);
        check_readback(&alias, &bytes)?;
        drop(alias);
        drop(sealed);
        check_cleanup(fd_before, &mountinfo)?;
        lengths.push(length);
    }
    // A partial page consumes a complete RAMFS data page; a caller's byte cap
    // is not silently rounded upwards to admit the copy.
    let partial = vec![0x35; 9001];
    let sealed = SealedImageBytes::from_bytes(&partial, partial.len() as u64)
        .map_err(|e| format!("partial source seal: {e}"))?;
    ensure(
        matches!(
            ReadOnlyRamImage::from_sealed(&sealed, partial.len(), &|| false),
            Err(RamImageError::TooLarge)
        ),
        "partial-page budget was rounded up",
    )?;
    ensure(
        matches!(
            ReadOnlyRamImage::from_sealed(&sealed, 0, &|| false),
            Err(RamImageError::InvalidLimit)
        ),
        "zero RAMFS limit was accepted",
    )?;
    ensure(
        matches!(
            ReadOnlyRamImage::from_sealed(&sealed, page_budget(partial.len()), &|| true),
            Err(RamImageError::Cancelled)
        ),
        "precancelled RAMFS construction was accepted",
    )?;
    drop(sealed);
    check_cleanup(fd_before, &mountinfo)?;
    // Cancel only after a real private RAMFS descriptor becomes observable in
    // this single-threaded process. The callback never returns/exposes that FD.
    let sealed = SealedImageBytes::from_bytes(&vec![0x59; 24576], 24576)
        .map_err(|e| format!("cancel source seal: {e}"))?;
    let saw_ramfs = Cell::new(false);
    let cancelled = || {
        let found = has_ramfs_descriptor();
        if found {
            saw_ramfs.set(true);
        }
        found
    };
    ensure(
        matches!(
            ReadOnlyRamImage::from_sealed(&sealed, page_budget(24576), &cancelled),
            Err(RamImageError::Cancelled)
        ),
        "post-allocation cancellation was not rejected",
    )?;
    ensure(
        saw_ramfs.get(),
        "cancellation fixture never observed an allocated RAMFS object",
    )?;
    drop(sealed);
    check_cleanup(fd_before, &mountinfo)?;
    Ok(
        json!({"status":"PASS","backing_adapter":"private-ro-ramfs-v1","fixture_bytes":lengths,"native_page_size":page_size,"negative_cases":4,"readonly_alias_after_owner_drop":true,"namespace_mountinfo_unchanged":true,"descriptors_before":fd_before,"descriptors_after":descriptor_count()?,"erofs_mounted":false,"target_executed":false,"scope":"actual production readonly RAMFS constructor, full source/copy byte agreement, readonly operations and bounded cleanup"}),
    )
}
fn has_ramfs_descriptor() -> bool {
    let Ok(entries) = fs::read_dir("/proc/self/fd") else {
        return false;
    };
    for entry in entries.flatten() {
        let Some(fd) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<i32>().ok())
        else {
            continue;
        };
        let mut stat = unsafe { std::mem::zeroed::<libc::statfs>() };
        // SAFETY: fstatfs handles stale/non-filesystem FD numbers by returning
        // an error. This callback runs synchronously without other FD owners.
        if unsafe { libc::fstatfs(fd, &mut stat) } == 0 && stat.f_type == RAMFS_MAGIC {
            return true;
        }
    }
    false
}
fn check_readback(file: &File, expected: &[u8]) -> Check<()> {
    let mut actual = vec![0; expected.len()];
    file.read_exact_at(&mut actual, 0)
        .map_err(|_| "RAMFS positional read failed")?;
    ensure(actual == expected, "actual RAMFS payload differs")
}
fn check_cleanup(expected_fds: usize, mountinfo: &[u8]) -> Check<()> {
    ensure(
        descriptor_count()? == expected_fds,
        "RAMFS owner leaked a descriptor",
    )?;
    ensure(
        bounded_read(Path::new("/proc/self/mountinfo"), 2 * 1024 * 1024)? == mountinfo,
        "detached RAMFS changed namespace mountinfo",
    )
}
fn descriptor_count() -> Check<usize> {
    fs::read_dir("/proc/self/fd")
        .map_err(|_| "descriptor inventory unavailable")?
        .try_fold(0, |count, entry| {
            entry
                .map(|_| count + 1)
                .map_err(|_| "descriptor inventory failed".into())
        })
}
fn bounded_read(path: &Path, max: usize) -> Check<Vec<u8>> {
    let file = File::open(path).map_err(|_| format!("cannot read {}", path.display()))?;
    let mut bytes = Vec::new();
    file.take(max as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "bounded read failed")?;
    ensure(
        bytes.len() <= max,
        "bounded native observation exceeded cap",
    )?;
    Ok(bytes)
}
fn ensure(condition: bool, message: &str) -> Check<()> {
    if condition {
        Ok(())
    } else {
        Err(message.into())
    }
}
