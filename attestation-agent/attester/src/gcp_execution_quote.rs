// SPDX-License-Identifier: Apache-2.0

//! Raw evidence collection for the separately selected GCP execution profile.
//!
//! The measured guest must restrict access to quote collection. Execution
//! callers must hold a protected capture record before requesting a quote.
//! The relying party authenticates the evidence and appraises the producer.

use std::{
    ffi::{CStr, CString},
    fs::File,
    io::{Read, Write},
    os::fd::{AsRawFd, FromRawFd},
    sync::atomic::{AtomicU64, Ordering},
};
use thiserror::Error;

pub const MAX_GCP_QUOTE_BYTES: usize = 512 * 1024;
pub const MAX_GCP_CCEL_BYTES: usize = 1024 * 1024;
const QUOTE_HEADER: usize = 48;
const TDX10_BODY: usize = 584;
static REPORT_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum GcpExecutionQuoteError {
    #[error("invalid GCP execution report binding")]
    InvalidBinding,
    #[error("GCP TDX evidence collection is unavailable")]
    Unavailable,
    #[error("GCP TDX evidence exceeds its bound")]
    Bounds,
    #[error("GCP TDX evidence framing or provider state is invalid")]
    InvalidEvidence,
}
type Result<T> = std::result::Result<T, GcpExecutionQuoteError>;

/// Public raw data only. There is no verified status or authorization token.
#[derive(Debug)]
pub struct GcpRawExecutionEvidence {
    pub tdx_quote: Vec<u8>,
    pub ccel_table: Vec<u8>,
    pub ccel_log: Vec<u8>,
}

/// Blocking fixed-provider collection. Run on the dedicated bounded exporter
/// worker, outside task/reaper locks. No init-data reinterpretation, environment
/// selection, sample fallback, caller paths or caller boot hashes are accepted.
pub fn collect_gcp_tdx_execution_evidence(
    report_data: [u8; 64],
) -> Result<GcpRawExecutionEvidence> {
    validate_binding(&report_data)?;
    let tables = open_absolute_directory(&[c"sys", c"firmware", c"acpi", c"tables"])?;
    let data = open_directory_at(&tables, c"data")?;
    let table = read_at(&tables, c"CCEL", 56)?;
    let capacity = descriptor_capacity(&table)?;
    let log = read_at(&data, c"CCEL", capacity)?;
    if log.len() != capacity {
        return Err(GcpExecutionQuoteError::InvalidEvidence);
    }
    let reports = open_absolute_directory(&[c"sys", c"kernel", c"config", c"tsm", c"report"])?;
    let report = ReportDirectory::create(reports)?;
    report.exact(c"provider", b"tdx_guest\n")?;
    report.exact(c"generation", b"0\n")?;
    let mut input = open_regular_at(&report.item, c"inblob", true)?;
    // Configfs inblob is a single request write, not a retryable byte stream.
    if input
        .write(&report_data)
        .map_err(|_| GcpExecutionQuoteError::Unavailable)?
        != 64
    {
        return Err(GcpExecutionQuoteError::Unavailable);
    }
    drop(input);
    let quote = read_at(&report.item, c"outblob", MAX_GCP_QUOTE_BYTES)?;
    report.exact(c"generation", b"1\n")?;
    report.exact(c"provider", b"tdx_guest\n")?;
    check_quote_binding(&quote, &report_data)?;
    // A changing boot log is not silently combined with another descriptor or
    // quote snapshot. The independent verifier still checks all four RTMRs.
    if read_at(&tables, c"CCEL", 56)? != table || read_at(&data, c"CCEL", capacity)? != log {
        return Err(GcpExecutionQuoteError::InvalidEvidence);
    }
    Ok(GcpRawExecutionEvidence {
        tdx_quote: quote,
        ccel_table: table,
        ccel_log: log,
    })
}

fn validate_binding(report: &[u8; 64]) -> Result<()> {
    if report[..48].iter().all(|b| *b == 0) || report[48..].iter().any(|b| *b != 0) {
        return Err(GcpExecutionQuoteError::InvalidBinding);
    }
    Ok(())
}

fn open_absolute_directory(components: &[&CStr]) -> Result<File> {
    let raw = unsafe {
        libc::open(
            c"/".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if raw < 0 {
        return Err(GcpExecutionQuoteError::Unavailable);
    }
    // SAFETY: open returned a fresh descriptor transferred to this File.
    let mut directory = unsafe { File::from_raw_fd(raw) };
    for component in components {
        directory = open_directory_at(&directory, component)?;
    }
    Ok(directory)
}
fn open_at(directory: &File, name: &CStr, flags: i32) -> Result<File> {
    // All production names are fixed single components; report names are
    // generated internally. Reject separators even for internal/test callers.
    if name.to_bytes().is_empty()
        || name.to_bytes().contains(&b'/')
        || matches!(name.to_bytes(), b"." | b"..")
    {
        return Err(GcpExecutionQuoteError::InvalidEvidence);
    }
    // SAFETY: name is a NUL-terminated single component and directory is held.
    let raw = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        )
    };
    if raw < 0 {
        return Err(GcpExecutionQuoteError::Unavailable);
    }
    // SAFETY: openat returned a fresh descriptor transferred to this File.
    Ok(unsafe { File::from_raw_fd(raw) })
}
fn open_directory_at(directory: &File, name: &CStr) -> Result<File> {
    open_at(directory, name, libc::O_RDONLY | libc::O_DIRECTORY)
}
fn open_regular_at(directory: &File, name: &CStr, write: bool) -> Result<File> {
    let file = open_at(
        directory,
        name,
        if write {
            libc::O_WRONLY
        } else {
            libc::O_RDONLY
        },
    )?;
    if !file
        .metadata()
        .map_err(|_| GcpExecutionQuoteError::Unavailable)?
        .is_file()
    {
        return Err(GcpExecutionQuoteError::InvalidEvidence);
    }
    Ok(file)
}
fn read_at(directory: &File, name: &CStr, maximum: usize) -> Result<Vec<u8>> {
    if maximum == 0 || maximum > MAX_GCP_CCEL_BYTES {
        return Err(GcpExecutionQuoteError::Bounds);
    }
    let file = open_regular_at(directory, name, false)?;
    let mut data = Vec::new();
    file.take((maximum + 1) as u64)
        .read_to_end(&mut data)
        .map_err(|_| GcpExecutionQuoteError::Unavailable)?;
    if data.is_empty() || data.len() > maximum {
        return Err(GcpExecutionQuoteError::Bounds);
    }
    Ok(data)
}

struct ReportDirectory {
    parent: File,
    item: File,
    name: CString,
}
impl ReportDirectory {
    fn create(parent: File) -> Result<Self> {
        let sequence = REPORT_SEQUENCE
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_add(1))
            .map_err(|_| GcpExecutionQuoteError::Unavailable)?;
        // Predictability grants no access: atomic mkdir/open and no reuse. A
        // precreated name is a fail-closed denial, never another quote request.
        let name = CString::new(format!("qlad-exec-{}-{sequence}", std::process::id()))
            .map_err(|_| GcpExecutionQuoteError::Unavailable)?;
        // SAFETY: parent/name remain live; name is a generated component.
        if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
            return Err(GcpExecutionQuoteError::Unavailable);
        }
        let item = match open_directory_at(&parent, &name) {
            Ok(item) => item,
            Err(error) => {
                // SAFETY: only remove the empty child created by this call.
                unsafe {
                    libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR);
                }
                return Err(error);
            }
        };
        Ok(Self { parent, item, name })
    }
    fn exact(&self, name: &CStr, expected: &[u8]) -> Result<()> {
        if read_at(&self.item, name, 64)? != expected {
            return Err(GcpExecutionQuoteError::InvalidEvidence);
        }
        Ok(())
    }
}
impl Drop for ReportDirectory {
    fn drop(&mut self) {
        // SAFETY: held parent FD and private name identify our configfs item.
        // Removal failure does not convert failed collection into success.
        unsafe {
            libc::unlinkat(
                self.parent.as_raw_fd(),
                self.name.as_ptr(),
                libc::AT_REMOVEDIR,
            );
        }
    }
}

fn descriptor_capacity(table: &[u8]) -> Result<usize> {
    if table.len() != 56
        || &table[..4] != b"CCEL"
        || le32(table, 4)? != 56
        || table[8] != 1
        || table[36..40] != [2, 0, 0, 0]
        || table.iter().fold(0u8, |s, b| s.wrapping_add(*b)) != 0
    {
        return Err(GcpExecutionQuoteError::InvalidEvidence);
    }
    let capacity = le64(table, 40)?;
    let address = le64(table, 48)?;
    if capacity == 0
        || capacity > MAX_GCP_CCEL_BYTES as u64
        || address == 0
        || address.checked_add(capacity).is_none()
    {
        return Err(GcpExecutionQuoteError::InvalidEvidence);
    }
    Ok(capacity as usize)
}
fn le16(data: &[u8], offset: usize) -> Result<u16> {
    let bytes = data
        .get(offset..offset + 2)
        .ok_or(GcpExecutionQuoteError::InvalidEvidence)?;
    Ok(u16::from_le_bytes(
        bytes
            .try_into()
            .map_err(|_| GcpExecutionQuoteError::InvalidEvidence)?,
    ))
}
fn le32(data: &[u8], offset: usize) -> Result<u32> {
    let bytes = data
        .get(offset..offset + 4)
        .ok_or(GcpExecutionQuoteError::InvalidEvidence)?;
    Ok(u32::from_le_bytes(
        bytes
            .try_into()
            .map_err(|_| GcpExecutionQuoteError::InvalidEvidence)?,
    ))
}
fn le64(data: &[u8], offset: usize) -> Result<u64> {
    let bytes = data
        .get(offset..offset + 8)
        .ok_or(GcpExecutionQuoteError::InvalidEvidence)?;
    Ok(u64::from_le_bytes(
        bytes
            .try_into()
            .map_err(|_| GcpExecutionQuoteError::InvalidEvidence)?,
    ))
}
fn check_quote_binding(quote: &[u8], report: &[u8; 64]) -> Result<()> {
    if quote.is_empty() || quote.len() > MAX_GCP_QUOTE_BYTES {
        return Err(GcpExecutionQuoteError::Bounds);
    }
    if le16(quote, 2)? != 2
        || le32(quote, 4)? != 0x81
        || le32(quote, 8)? != 0
        || quote.get(12..28)
            != Some(
                [
                    0x93, 0x9a, 0x72, 0x33, 0xf7, 0x9c, 0x4c, 0xa9, 0x94, 0x0a, 0x0d, 0xb3, 0x95,
                    0x7f, 0x06, 0x07,
                ]
                .as_slice(),
            )
    {
        return Err(GcpExecutionQuoteError::InvalidEvidence);
    }
    let (body, size) = match le16(quote, 0)? {
        4 => (QUOTE_HEADER, TDX10_BODY),
        5 => match (le16(quote, 48)?, le32(quote, 50)?) {
            (2, 584) => (54, 584),
            (3, 648) => (54, 648),
            _ => return Err(GcpExecutionQuoteError::InvalidEvidence),
        },
        _ => return Err(GcpExecutionQuoteError::InvalidEvidence),
    };
    if quote.get(body + 520..body + 584) != Some(report.as_slice()) {
        return Err(GcpExecutionQuoteError::InvalidBinding);
    }
    let signature_bytes = le32(quote, body + size)? as usize;
    let frame = (body + size + 4)
        .checked_add(signature_bytes)
        .ok_or(GcpExecutionQuoteError::Bounds)?;
    if signature_bytes == 0 || frame > quote.len() {
        return Err(GcpExecutionQuoteError::InvalidEvidence);
    }
    let tail = &quote[frame..];
    if !tail.is_empty() && (quote.len() != 8000 || tail.iter().any(|b| *b != 0)) {
        return Err(GcpExecutionQuoteError::InvalidEvidence);
    }
    Ok(())
}

#[cfg(test)]
#[path = "gcp_execution_quote_tests.rs"]
mod tests;
