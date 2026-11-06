use super::*;

const BASE: u64 = 0x400000;

fn put16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}
fn put32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
fn put64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
fn ph32(bytes: &mut [u8], index: usize, offset: usize, value: u32) {
    put32(
        bytes,
        ELF_HEADER_BYTES + index * PROGRAM_HEADER_BYTES + offset,
        value,
    );
}
fn ph64(bytes: &mut [u8], index: usize, offset: usize, value: u64) {
    put64(
        bytes,
        ELF_HEADER_BYTES + index * PROGRAM_HEADER_BYTES + offset,
        value,
    );
}
fn write_phdr(bytes: &mut [u8], index: usize, header: ProgramHeader) {
    ph32(bytes, index, 0, header.kind);
    ph32(bytes, index, 4, header.flags);
    ph64(bytes, index, 8, header.offset);
    ph64(bytes, index, 16, header.address);
    ph64(bytes, index, 32, header.file_bytes);
    ph64(bytes, index, 40, header.memory_bytes);
    ph64(bytes, index, 48, header.alignment);
}

fn fixture() -> Vec<u8> {
    // Synthetic load-profile fixture, not an executed or complete application.
    let mut bytes = vec![0; 0x1008];
    bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    put16(&mut bytes, 16, 2);
    put16(&mut bytes, 18, 62);
    put32(&mut bytes, 20, 1);
    put64(&mut bytes, 24, BASE + 0x180);
    put64(&mut bytes, 32, ELF_HEADER_BYTES as u64);
    put16(&mut bytes, 52, ELF_HEADER_BYTES as u16);
    put16(&mut bytes, 54, PROGRAM_HEADER_BYTES as u16);
    put16(&mut bytes, 56, 4);
    write_phdr(
        &mut bytes,
        0,
        ProgramHeader {
            kind: PT_PHDR,
            flags: PF_R,
            offset: 64,
            address: BASE + 64,
            file_bytes: 4 * 56,
            memory_bytes: 4 * 56,
            alignment: 8,
        },
    );
    write_phdr(
        &mut bytes,
        1,
        ProgramHeader {
            kind: PT_LOAD,
            flags: PF_R | PF_X,
            offset: 0,
            address: BASE,
            file_bytes: 512,
            memory_bytes: 512,
            alignment: PAGE_BYTES,
        },
    );
    write_phdr(
        &mut bytes,
        2,
        ProgramHeader {
            kind: PT_LOAD,
            flags: PF_R | PF_W,
            offset: 4096,
            address: BASE + 4096,
            file_bytes: 8,
            memory_bytes: 4096,
            alignment: PAGE_BYTES,
        },
    );
    write_phdr(
        &mut bytes,
        3,
        ProgramHeader {
            kind: PT_GNU_STACK,
            flags: PF_R | PF_W,
            offset: 0,
            address: 0,
            file_bytes: 0,
            memory_bytes: 0,
            alignment: 16,
        },
    );
    bytes[0x180] = 0xc3;
    bytes[4096..].copy_from_slice(b"fixture!");
    bytes
}

fn append_header(bytes: &mut [u8], header: ProgramHeader) {
    let count = usize::from(u16_at(bytes, 56));
    write_phdr(bytes, count, header);
    put16(bytes, 56, (count + 1) as u16);
    ph64(bytes, 0, 32, ((count + 1) * PROGRAM_HEADER_BYTES) as u64);
    ph64(bytes, 0, 40, ((count + 1) * PROGRAM_HEADER_BYTES) as u64);
}

fn ignored_header(kind: u32) -> ProgramHeader {
    ProgramHeader {
        kind,
        flags: 0,
        offset: 0,
        address: 0,
        file_bytes: 0,
        memory_bytes: 0,
        alignment: 0,
    }
}

fn limits() -> StaticElfLimits {
    StaticElfLimits {
        file_bytes: 16 * 1024,
        program_headers: 16,
        mapped_bytes: 64 * 1024,
        virtual_span_bytes: 64 * 1024,
    }
}

#[test]
fn actual_bounded_snapshot_yields_only_load_profile_observations() {
    let bytes = fixture();
    let summary = check_static_elf(&bytes, limits()).unwrap();
    assert_eq!(summary.file_bytes(), bytes.len());
    assert_eq!(summary.entry(), BASE + 0x180);
    assert_eq!(summary.program_headers(), 4);
    assert_eq!(summary.load_segments(), 2);
    assert_eq!(summary.mapped_bytes(), 8192);
    assert_eq!(summary.virtual_span_bytes(), 8192);
    assert_eq!(summary.clone(), summary);
    let exact = StaticElfLimits {
        file_bytes: bytes.len(),
        program_headers: 4,
        mapped_bytes: 8192,
        virtual_span_bytes: 8192,
    };
    assert_eq!(check_static_elf(&bytes, exact).unwrap(), summary);
}

#[test]
fn optional_phdr_and_bounded_notes_nulls_linux_abi_and_bss_are_supported() {
    let mut bytes = fixture();
    ph32(&mut bytes, 0, 0, PT_NULL);
    bytes[7] = 3;
    ph64(&mut bytes, 2, 32, 0); // A BSS-only LOAD still consumes mapped pages.
    append_header(
        &mut bytes,
        ProgramHeader {
            kind: PT_NOTE,
            flags: PF_R,
            offset: 512,
            address: 0,
            file_bytes: 4,
            memory_bytes: 0,
            alignment: 4,
        },
    );
    // NULL fields are undefined by the ABI and are not interpreted as ranges.
    ph64(&mut bytes, 0, 8, u64::MAX);
    ph64(&mut bytes, 0, 16, u64::MAX);
    ph64(&mut bytes, 0, 32, u64::MAX);
    assert_eq!(
        check_static_elf(&bytes, limits()).unwrap().load_segments(),
        2
    );
}

#[test]
fn zero_unit_and_congruent_power_of_two_load_alignment_are_supported() {
    for alignment in [0, 1, 4096, 2 * 1024 * 1024] {
        let mut bytes = fixture();
        ph64(&mut bytes, 1, 48, alignment);
        ph64(&mut bytes, 2, 48, alignment);
        assert!(check_static_elf(&bytes, limits()).is_ok(), "{alignment}");
    }
}

#[test]
fn short_headers_and_unsupported_identification_never_parse_as_this_profile() {
    let good = fixture();
    for length in 0..=ELF_HEADER_BYTES {
        assert!(
            check_static_elf(&good[..length], limits()).is_err(),
            "{length}"
        );
    }
    for case in [
        "magic",
        "class",
        "endian",
        "ident-version",
        "osabi",
        "abi-version",
        "padding",
        "type",
        "machine",
        "version",
        "flags",
        "ehsize",
        "phentsize",
    ] {
        let mut bytes = good.clone();
        match case {
            "magic" => bytes[0] = 0,
            "class" => bytes[4] = 1,
            "endian" => bytes[5] = 2,
            "ident-version" => bytes[6] = 0,
            "osabi" => bytes[7] = 9,
            "abi-version" => bytes[8] = 1,
            "padding" => bytes[15] = 1,
            "type" => put16(&mut bytes, 16, 3),
            "machine" => put16(&mut bytes, 18, 183),
            "version" => put32(&mut bytes, 20, 0),
            "flags" => put32(&mut bytes, 48, 1),
            "ehsize" => put16(&mut bytes, 52, 63),
            "phentsize" => put16(&mut bytes, 54, 55),
            _ => unreachable!(),
        }
        assert!(check_static_elf(&bytes, limits()).is_err(), "{case}");
    }
}

#[test]
fn program_header_counts_offsets_overflow_and_truncation_are_bounded() {
    for offset in [0, 32, u64::MAX, fixture().len() as u64 - 1] {
        let mut bytes = fixture();
        put64(&mut bytes, 32, offset);
        assert!(check_static_elf(&bytes, limits()).is_err(), "{offset}");
    }
    for count in [0, u16::MAX, 17] {
        let mut bytes = fixture();
        put16(&mut bytes, 56, count);
        assert!(check_static_elf(&bytes, limits()).is_err(), "{count}");
    }
    let mut truncated = fixture();
    truncated.truncate(64 + 4 * 56 - 1);
    assert_eq!(
        check_static_elf(&truncated, limits()),
        Err(StaticElfError::InvalidHeader)
    );
}

#[test]
fn load_file_memory_address_flag_and_alignment_failures_are_rejected() {
    for case in [
        "wx",
        "execute-only",
        "unknown-flags",
        "filesz",
        "empty-memory",
        "file-overflow",
        "file-outside",
        "address-overflow",
        "below-user",
        "above-user",
        "page-congruence",
        "alignment-power",
        "alignment-congruence",
    ] {
        let mut bytes = fixture();
        match case {
            "wx" => ph32(&mut bytes, 2, 4, PF_R | PF_W | PF_X),
            "execute-only" => ph32(&mut bytes, 1, 4, PF_X),
            "unknown-flags" => ph32(&mut bytes, 2, 4, PF_R | 0x10000),
            "filesz" => ph64(&mut bytes, 1, 32, 513),
            "empty-memory" => ph64(&mut bytes, 2, 40, 0),
            "file-overflow" => ph64(&mut bytes, 2, 8, u64::MAX),
            "file-outside" => ph64(&mut bytes, 2, 8, 8192),
            "address-overflow" => ph64(&mut bytes, 2, 16, u64::MAX - 1),
            "below-user" => ph64(&mut bytes, 1, 16, 0),
            "above-user" => ph64(&mut bytes, 2, 16, MAX_USER_ADDRESS),
            "page-congruence" => ph64(&mut bytes, 2, 8, 4097),
            "alignment-power" => ph64(&mut bytes, 1, 48, 3),
            "alignment-congruence" => {
                ph64(&mut bytes, 2, 16, BASE + 8192);
                ph64(&mut bytes, 2, 48, 2 * 1024 * 1024);
            }
            _ => unreachable!(),
        }
        assert_eq!(
            check_static_elf(&bytes, limits()),
            Err(StaticElfError::InvalidLoad),
            "{case}"
        );
    }
}

#[test]
fn page_overlap_is_rejected_even_when_declared_memory_bytes_do_not_overlap() {
    let mut bytes = fixture();
    ph64(&mut bytes, 2, 8, 0x800);
    ph64(&mut bytes, 2, 16, BASE + 0x800);
    ph64(&mut bytes, 2, 40, 0x100);
    assert_eq!(
        check_static_elf(&bytes, limits()),
        Err(StaticElfError::OverlappingLoads)
    );
    let mut reversed = fixture();
    let first = reversed[120..176].to_vec();
    let second = reversed[176..232].to_vec();
    reversed[120..176].copy_from_slice(&second);
    reversed[176..232].copy_from_slice(&first);
    assert_eq!(
        check_static_elf(&reversed, limits()),
        Err(StaticElfError::OverlappingLoads)
    );
}

#[test]
fn entry_must_be_in_executable_file_bytes_not_data_bss_or_end_boundary() {
    for entry in [0, BASE + 0x200, BASE + 0x300, BASE + 4096, BASE + 8192] {
        let mut bytes = fixture();
        ph64(&mut bytes, 1, 40, 4096);
        put64(&mut bytes, 24, entry);
        assert_eq!(
            check_static_elf(&bytes, limits()),
            Err(StaticElfError::InvalidEntry),
            "{entry:#x}"
        );
    }
}

#[test]
fn interpreter_dynamic_and_unimplemented_static_extensions_fail_closed() {
    for kind in [
        2,
        3,
        7,
        0x6474_e550,
        0x6474_e552,
        0x6474_e553,
        0x7000_0000,
        8,
    ] {
        let mut bytes = fixture();
        append_header(&mut bytes, ignored_header(kind));
        assert_eq!(
            check_static_elf(&bytes, limits()),
            Err(StaticElfError::UnsupportedProfile),
            "{kind:#x}"
        );
    }
}

#[test]
fn missing_duplicate_or_non_rw_gnu_stack_is_rejected() {
    let mut missing = fixture();
    ph32(&mut missing, 3, 0, PT_NULL);
    assert_eq!(
        check_static_elf(&missing, limits()),
        Err(StaticElfError::InvalidStack)
    );
    for flags in [PF_R, PF_R | PF_X, PF_R | PF_W | PF_X] {
        let mut bytes = fixture();
        ph32(&mut bytes, 3, 4, flags);
        assert_eq!(
            check_static_elf(&bytes, limits()),
            Err(StaticElfError::InvalidStack)
        );
    }
    let mut duplicate = fixture();
    let mut stack = ignored_header(PT_GNU_STACK);
    stack.flags = PF_R | PF_W;
    append_header(&mut duplicate, stack);
    assert_eq!(
        check_static_elf(&duplicate, limits()),
        Err(StaticElfError::InvalidStack)
    );
}

#[test]
fn full_ehdr_and_program_table_require_one_nonwrite_file_backed_mapping() {
    for case in ["partial", "writable", "no-ehdr", "aliased-phoff", "no-load"] {
        let mut bytes = fixture();
        match case {
            "partial" => ph64(&mut bytes, 1, 32, (64 + 4 * 56 - 1) as u64),
            "writable" => ph32(&mut bytes, 1, 4, PF_R | PF_W),
            "no-ehdr" => {
                ph64(&mut bytes, 1, 8, 64);
                ph64(&mut bytes, 1, 16, BASE + 64);
            }
            "aliased-phoff" => append_header(
                &mut bytes,
                ProgramHeader {
                    kind: PT_LOAD,
                    flags: PF_R,
                    offset: 0,
                    address: BASE + 0x3000,
                    file_bytes: 512,
                    memory_bytes: 512,
                    alignment: PAGE_BYTES,
                },
            ),
            "no-load" => {
                ph32(&mut bytes, 1, 0, PT_NULL);
                ph32(&mut bytes, 2, 0, PT_NULL);
            }
            _ => unreachable!(),
        }
        assert!(check_static_elf(&bytes, limits()).is_err(), "{case}");
    }
}

#[test]
fn optional_phdr_must_be_unique_early_and_match_actual_mapping() {
    for field in [8, 16, 32, 40] {
        let mut bytes = fixture();
        ph64(&mut bytes, 0, field, 1);
        assert_eq!(
            check_static_elf(&bytes, limits()),
            Err(StaticElfError::InvalidHeaderMapping),
            "{field}"
        );
    }
    let mut flags = fixture();
    ph32(&mut flags, 0, 4, PF_R | PF_X);
    assert_eq!(
        check_static_elf(&flags, limits()),
        Err(StaticElfError::InvalidHeaderMapping)
    );
    for duplicate in [false, true] {
        let mut bytes = fixture();
        if !duplicate {
            ph32(&mut bytes, 0, 0, PT_NULL);
        }
        append_header(&mut bytes, ignored_header(PT_PHDR));
        assert_eq!(
            check_static_elf(&bytes, limits()),
            Err(StaticElfError::InvalidHeaderMapping)
        );
    }
}

#[test]
fn notes_cannot_request_unknown_permissions_or_unbounded_file_ranges() {
    for writable in [false, true] {
        let mut bytes = fixture();
        append_header(
            &mut bytes,
            ProgramHeader {
                kind: PT_NOTE,
                flags: if writable { PF_R | PF_W } else { PF_R },
                offset: if writable { 512 } else { u64::MAX },
                address: 0,
                file_bytes: 4,
                memory_bytes: 0,
                alignment: 4,
            },
        );
        assert_eq!(
            check_static_elf(&bytes, limits()),
            Err(StaticElfError::UnsupportedProfile)
        );
    }
}

#[test]
fn file_count_mapped_bytes_and_sparse_virtual_span_have_distinct_limits() {
    for field in 0..4 {
        let bytes = fixture();
        let mut cap = limits();
        match field {
            0 => cap.file_bytes = bytes.len() - 1,
            1 => cap.program_headers = 3,
            2 => cap.mapped_bytes = 8191,
            3 => cap.virtual_span_bytes = 8191,
            _ => unreachable!(),
        }
        assert_eq!(
            check_static_elf(&bytes, cap),
            Err(StaticElfError::TooLarge),
            "{field}"
        );
    }
    let mut sparse = fixture();
    ph64(&mut sparse, 2, 16, BASE + 0x20000);
    let mut cap = limits();
    cap.mapped_bytes = 8192;
    cap.virtual_span_bytes = 0x20000;
    assert_eq!(
        check_static_elf(&sparse, cap),
        Err(StaticElfError::TooLarge)
    );
}

#[test]
fn invalid_constructor_bounds_are_rejected_without_parsing() {
    for field in 0..4 {
        for maximum in [false, true] {
            let mut cap = limits();
            match field {
                0 => cap.file_bytes = if maximum { usize::MAX } else { 0 },
                1 => cap.program_headers = if maximum { usize::MAX } else { 0 },
                2 => cap.mapped_bytes = if maximum { u64::MAX } else { 0 },
                3 => cap.virtual_span_bytes = if maximum { u64::MAX } else { 0 },
                _ => unreachable!(),
            }
            assert_eq!(
                check_static_elf(b"", cap),
                Err(StaticElfError::InvalidLimits)
            );
        }
    }
}
