// SPDX-License-Identifier: Apache-2.0

//! Bounded inspection of a restricted static x86-64 ELF load profile.
//!
//! Accepted input is ELF64 little-endian ET_EXEC with 4 KiB mapping granularity.
//! The only program-header types are NULL, LOAD, PHDR, NOTE and one non-executable
//! GNU_STACK. Legitimate static binaries using TLS, GNU_RELRO, GNU_EH_FRAME or
//! other extensions are unsupported by this profile. Section tables and
//! instruction semantics are not inspected; p_paddr has no application authority.
//!
//! A summary describes these bytes only. It does not establish kernel acceptance,
//! a filesystem identity, immutable custody, admission, executable permissions,
//! future program behavior, successful execution or permission to start a task.

const ELF_HEADER_BYTES: usize = 64;
const PROGRAM_HEADER_BYTES: usize = 56;
const MAX_PROGRAM_HEADER_BYTES: usize = 65536;
const PAGE_BYTES: u64 = 4096;
const MIN_USER_ADDRESS: u64 = 0x10000;
const MAX_USER_ADDRESS: u64 = 0x0000_8000_0000_0000;
const PT_NULL: u32 = 0;
const PT_LOAD: u32 = 1;
const PT_NOTE: u32 = 4;
const PT_PHDR: u32 = 6;
const PT_GNU_STACK: u32 = 0x6474_e551;
const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;

/// Constructor-owned work and future mapping bounds, without deployment defaults.
#[derive(Clone, Copy)]
pub struct StaticElfLimits {
    pub file_bytes: usize,
    pub program_headers: usize,
    pub mapped_bytes: u64,
    pub virtual_span_bytes: u64,
}

impl StaticElfLimits {
    pub fn validate(self) -> Result<(), StaticElfError> {
        if self.file_bytes == 0
            || self.file_bytes > isize::MAX as usize
            || self.program_headers == 0
            || self.program_headers > MAX_PROGRAM_HEADER_BYTES / PROGRAM_HEADER_BYTES
            || self.mapped_bytes == 0
            || self.mapped_bytes > isize::MAX as u64
            || self.virtual_span_bytes == 0
            || self.virtual_span_bytes > isize::MAX as u64
        {
            return Err(StaticElfError::InvalidLimits);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum StaticElfError {
    #[error("static ELF limits are invalid")]
    InvalidLimits,
    #[error("static ELF exceeds its configured bounds")]
    TooLarge,
    #[error("static ELF header or program-header table is invalid")]
    InvalidHeader,
    #[error("static ELF uses an unsupported architecture, type or extension")]
    UnsupportedProfile,
    #[error("static ELF load segment is invalid")]
    InvalidLoad,
    #[error("static ELF load mappings overlap or are out of order")]
    OverlappingLoads,
    #[error("static ELF headers are not uniquely mapped as readonly file bytes")]
    InvalidHeaderMapping,
    #[error("static ELF requires exactly one non-executable GNU stack header")]
    InvalidStack,
    #[error("static ELF entry is not within one executable file-backed segment")]
    InvalidEntry,
}

/// Observations about a checked load profile, never an execution capability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StaticElfSummary {
    file_bytes: usize,
    entry: u64,
    program_headers: usize,
    load_segments: usize,
    mapped_bytes: u64,
    virtual_span_bytes: u64,
}

impl StaticElfSummary {
    pub fn file_bytes(&self) -> usize {
        self.file_bytes
    }
    pub fn entry(&self) -> u64 {
        self.entry
    }
    pub fn program_headers(&self) -> usize {
        self.program_headers
    }
    pub fn load_segments(&self) -> usize {
        self.load_segments
    }
    pub fn mapped_bytes(&self) -> u64 {
        self.mapped_bytes
    }
    pub fn virtual_span_bytes(&self) -> u64 {
        self.virtual_span_bytes
    }
}

#[derive(Clone, Copy)]
struct ProgramHeader {
    kind: u32,
    flags: u32,
    offset: u64,
    address: u64,
    file_bytes: u64,
    memory_bytes: u64,
    alignment: u64,
}

impl ProgramHeader {
    fn parse(bytes: &[u8]) -> Self {
        // The caller supplies exactly one already-bounded 56-byte table entry.
        Self {
            kind: u32_at(bytes, 0),
            flags: u32_at(bytes, 4),
            offset: u64_at(bytes, 8),
            address: u64_at(bytes, 16),
            file_bytes: u64_at(bytes, 32),
            memory_bytes: u64_at(bytes, 40),
            alignment: u64_at(bytes, 48),
        }
    }
}

struct Load {
    header: ProgramHeader,
    file_end: u64,
    page_start: u64,
    page_end: u64,
}

/// Inspect one bounded byte snapshot. All arithmetic derived from ELF input is
/// checked before indexing or range use; no segment-sized allocation occurs.
pub fn check_static_elf(
    bytes: &[u8],
    limits: StaticElfLimits,
) -> Result<StaticElfSummary, StaticElfError> {
    limits.validate()?;
    if bytes.len() > limits.file_bytes {
        return Err(StaticElfError::TooLarge);
    }
    if bytes.len() < ELF_HEADER_BYTES || &bytes[..4] != b"\x7fELF" {
        return Err(StaticElfError::InvalidHeader);
    }
    if bytes[4] != 2
        || bytes[5] != 1
        || bytes[6] != 1
        || !matches!(bytes[7], 0 | 3)
        || bytes[8..16].iter().any(|byte| *byte != 0)
        || u16_at(bytes, 16) != 2
        || u16_at(bytes, 18) != 62
        || u32_at(bytes, 20) != 1
        || u32_at(bytes, 48) != 0
    {
        return Err(StaticElfError::UnsupportedProfile);
    }
    if u16_at(bytes, 52) != ELF_HEADER_BYTES as u16
        || u16_at(bytes, 54) != PROGRAM_HEADER_BYTES as u16
    {
        return Err(StaticElfError::InvalidHeader);
    }
    let count = usize::from(u16_at(bytes, 56));
    if count == 0 || count == usize::from(u16::MAX) {
        return Err(StaticElfError::InvalidHeader);
    }
    if count > limits.program_headers {
        return Err(StaticElfError::TooLarge);
    }
    let table_bytes = count
        .checked_mul(PROGRAM_HEADER_BYTES)
        .ok_or(StaticElfError::InvalidHeader)?;
    let table_offset = u64_at(bytes, 32);
    let table_end = table_offset
        .checked_add(table_bytes as u64)
        .filter(|end| *end <= bytes.len() as u64)
        .ok_or(StaticElfError::InvalidHeader)?;
    if table_offset < ELF_HEADER_BYTES as u64 {
        return Err(StaticElfError::InvalidHeader);
    }
    let table_offset_usize =
        usize::try_from(table_offset).map_err(|_| StaticElfError::InvalidHeader)?;
    let table_end_usize = usize::try_from(table_end).map_err(|_| StaticElfError::InvalidHeader)?;
    let mut loads = Vec::<Load>::new();
    let mut phdr = None;
    let mut stack = false;
    let mut mapped_bytes = 0u64;
    for raw in bytes[table_offset_usize..table_end_usize]
        .as_chunks::<PROGRAM_HEADER_BYTES>()
        .0
    {
        let header = ProgramHeader::parse(raw);
        match header.kind {
            PT_NULL => (), // The ABI leaves all other NULL fields undefined.
            PT_LOAD => {
                let load = check_load(header, bytes.len() as u64)?;
                if loads.last().is_some_and(|prior| {
                    load.header.address <= prior.header.address || load.page_start < prior.page_end
                }) {
                    return Err(StaticElfError::OverlappingLoads);
                }
                mapped_bytes = mapped_bytes
                    .checked_add(load.page_end - load.page_start)
                    .filter(|total| *total <= limits.mapped_bytes)
                    .ok_or(StaticElfError::TooLarge)?;
                loads.push(load);
            }
            PT_PHDR => {
                if phdr.is_some() || !loads.is_empty() {
                    return Err(StaticElfError::InvalidHeaderMapping);
                }
                phdr = Some(header);
            }
            PT_NOTE => {
                // NOTE contents are not interpreted by this profile. Its file
                // range is bounded, and writable/executable note flags are not
                // part of the accepted metadata subset.
                if header.flags & !PF_R != 0
                    || header
                        .offset
                        .checked_add(header.file_bytes)
                        .is_none_or(|end| end > bytes.len() as u64)
                {
                    return Err(StaticElfError::UnsupportedProfile);
                }
            }
            PT_GNU_STACK => {
                // Linux uses stack flags, not these entries' file/VA fields.
                if stack || header.flags != (PF_R | PF_W) {
                    return Err(StaticElfError::InvalidStack);
                }
                stack = true;
            }
            _ => return Err(StaticElfError::UnsupportedProfile),
        }
    }
    if !stack {
        return Err(StaticElfError::InvalidStack);
    }
    let first = loads.first().ok_or(StaticElfError::InvalidLoad)?;
    let last = loads.last().ok_or(StaticElfError::InvalidLoad)?;
    let virtual_span_bytes = last.page_end - first.page_start;
    if virtual_span_bytes > limits.virtual_span_bytes {
        return Err(StaticElfError::TooLarge);
    }
    let mut header_loads = loads
        .iter()
        .filter(|load| load.header.offset <= table_offset && table_offset < load.file_end);
    let header_load = header_loads
        .next()
        .ok_or(StaticElfError::InvalidHeaderMapping)?;
    if header_loads.next().is_some()
        || header_load.header.offset != 0
        || header_load.file_end < table_end
        || header_load.header.flags & PF_R == 0
        || header_load.header.flags & PF_W != 0
    {
        return Err(StaticElfError::InvalidHeaderMapping);
    }
    if let Some(phdr) = phdr {
        let expected_address = header_load
            .header
            .address
            .checked_add(table_offset)
            .ok_or(StaticElfError::InvalidHeaderMapping)?;
        if phdr.flags != PF_R
            || phdr.offset != table_offset
            || phdr.file_bytes != table_bytes as u64
            || phdr.memory_bytes != table_bytes as u64
            || phdr.address != expected_address
        {
            return Err(StaticElfError::InvalidHeaderMapping);
        }
    }
    let entry = u64_at(bytes, 24);
    let entry_segments = loads
        .iter()
        .filter(|load| {
            load.header.flags == (PF_R | PF_X)
                && entry >= load.header.address
                && entry - load.header.address < load.header.file_bytes
        })
        .count();
    if entry_segments != 1 {
        return Err(StaticElfError::InvalidEntry);
    }
    Ok(StaticElfSummary {
        file_bytes: bytes.len(),
        entry,
        program_headers: count,
        load_segments: loads.len(),
        mapped_bytes,
        virtual_span_bytes,
    })
}

fn check_load(header: ProgramHeader, file_bytes: u64) -> Result<Load, StaticElfError> {
    let flags_valid =
        header.flags == PF_R || header.flags == (PF_R | PF_X) || header.flags == (PF_R | PF_W);
    let memory_end = header
        .address
        .checked_add(header.memory_bytes)
        .ok_or(StaticElfError::InvalidLoad)?;
    let file_end = header
        .offset
        .checked_add(header.file_bytes)
        .filter(|end| *end <= file_bytes)
        .ok_or(StaticElfError::InvalidLoad)?;
    if !flags_valid
        || header.memory_bytes == 0
        || header.file_bytes > header.memory_bytes
        || header.address < MIN_USER_ADDRESS
        || memory_end > MAX_USER_ADDRESS
        || header.address % PAGE_BYTES != header.offset % PAGE_BYTES
        || (header.alignment > 1
            && (!header.alignment.is_power_of_two()
                || header.address % header.alignment != header.offset % header.alignment))
    {
        return Err(StaticElfError::InvalidLoad);
    }
    let page_start = header.address & !(PAGE_BYTES - 1);
    let page_end = memory_end
        .checked_add(PAGE_BYTES - 1)
        .ok_or(StaticElfError::InvalidLoad)?
        & !(PAGE_BYTES - 1);
    Ok(Load {
        header,
        file_end,
        page_start,
        page_end,
    })
}

// Callers first bound complete Ehdr/Phdr slices; these fixed-width helpers never
// cast untrusted bytes to aligned structs or use input-controlled offsets.
fn u16_at(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}
fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(
        bytes[offset..offset + 4]
            .try_into()
            .expect("bounded u32 field"),
    )
}
fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(
        bytes[offset..offset + 8]
            .try_into()
            .expect("bounded u64 field"),
    )
}

#[cfg(test)]
#[path = "static_elf_tests.rs"]
mod tests;
