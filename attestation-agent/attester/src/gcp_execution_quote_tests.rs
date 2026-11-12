use super::*;
use std::{
    fs,
    os::unix::fs::{FileTypeExt, symlink},
};

fn report() -> [u8; 64] {
    let mut value = [0; 64];
    value[..48].fill(7);
    value
}
fn quote(version: u16, body_type: u16) -> Vec<u8> {
    let size = if body_type == 3 { 648 } else { 584 };
    let body = if version == 5 { 54 } else { 48 };
    let mut value = vec![0; body + size + 4 + 1];
    value[..2].copy_from_slice(&version.to_le_bytes());
    value[2..4].copy_from_slice(&2u16.to_le_bytes());
    value[4..8].copy_from_slice(&0x81u32.to_le_bytes());
    value[12..28].copy_from_slice(&[
        0x93, 0x9a, 0x72, 0x33, 0xf7, 0x9c, 0x4c, 0xa9, 0x94, 0x0a, 0x0d, 0xb3, 0x95, 0x7f, 0x06,
        0x07,
    ]);
    if version == 5 {
        value[48..50].copy_from_slice(&body_type.to_le_bytes());
        value[50..54].copy_from_slice(&(size as u32).to_le_bytes());
    }
    value[body + 520..body + 584].copy_from_slice(&report());
    value[body + size..body + size + 4].copy_from_slice(&1u32.to_le_bytes());
    value[body + size + 4] = 1;
    value // Framing fixture only; not genuine or cryptographically verified.
}
fn table(capacity: u64, address: u64) -> Vec<u8> {
    let mut value = vec![0; 56];
    value[..4].copy_from_slice(b"CCEL");
    value[4..8].copy_from_slice(&56u32.to_le_bytes());
    value[8] = 1;
    value[36] = 2;
    value[40..48].copy_from_slice(&capacity.to_le_bytes());
    value[48..56].copy_from_slice(&address.to_le_bytes());
    value[9] = 0u8.wrapping_sub(value.iter().fold(0u8, |s, b| s.wrapping_add(*b)));
    value
}

#[test]
fn binding_shape_fails_before_any_tsm_or_acpi_access() {
    assert_eq!(validate_binding(&report()), Ok(()));
    assert_eq!(
        collect_gcp_tdx_execution_evidence([0; 64]).unwrap_err(),
        GcpExecutionQuoteError::InvalidBinding
    );
    for offset in 48..64 {
        let mut value = report();
        value[offset] = 1;
        assert_eq!(
            validate_binding(&value),
            Err(GcpExecutionQuoteError::InvalidBinding)
        );
    }
}
#[test]
fn binds_every_report_byte_and_preserves_original_supported_frame() {
    for (version, body_type) in [(4, 2), (5, 2), (5, 3)] {
        let value = quote(version, body_type);
        assert_eq!(check_quote_binding(&value, &report()), Ok(()));
        let mut padded = value.clone();
        padded.resize(8000, 0);
        assert_eq!(check_quote_binding(&padded, &report()), Ok(()));
        for offset in 0..64 {
            let mut expected = report();
            expected[offset] ^= 1;
            assert_eq!(
                check_quote_binding(&padded, &expected),
                Err(GcpExecutionQuoteError::InvalidBinding)
            );
        }
        padded[7999] = 1;
        assert_eq!(
            check_quote_binding(&padded, &report()),
            Err(GcpExecutionQuoteError::InvalidEvidence)
        );
        padded[7999] = 0;
        padded.pop();
        assert!(check_quote_binding(&padded, &report()).is_err());
        for n in 0..value.len() {
            assert!(check_quote_binding(&value[..n], &report()).is_err());
        }
    }
}
#[test]
fn unknown_header_body_sizes_signature_bounds_and_empty_quote_reject() {
    for offset in [0, 2, 4, 8, 12] {
        let mut q = quote(4, 2);
        q[offset] ^= 0x40;
        assert!(check_quote_binding(&q, &report()).is_err());
    }
    let mut q = quote(5, 3);
    q[50] ^= 1;
    assert!(check_quote_binding(&q, &report()).is_err());
    let mut q = quote(4, 2);
    q[632..636].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(check_quote_binding(&q, &report()).is_err());
    q[632..636].copy_from_slice(&0u32.to_le_bytes());
    assert!(check_quote_binding(&q, &report()).is_err());
    assert_eq!(
        check_quote_binding(&[], &report()),
        Err(GcpExecutionQuoteError::Bounds)
    );
    assert_eq!(
        check_quote_binding(&vec![0; MAX_GCP_QUOTE_BYTES + 1], &report()),
        Err(GcpExecutionQuoteError::Bounds)
    );
}
#[test]
fn descriptor_is_exact_bounded_and_checks_checksum_and_address_overflow() {
    assert_eq!(descriptor_capacity(&table(262144, 0x100000)), Ok(262144));
    for (len, addr) in [
        (0, 1),
        (MAX_GCP_CCEL_BYTES as u64 + 1, 1),
        (1, 0),
        (56, u64::MAX),
    ] {
        assert!(descriptor_capacity(&table(len, addr)).is_err());
    }
    let value = table(262144, 1);
    for n in 0..56 {
        assert!(descriptor_capacity(&value[..n]).is_err());
    }
    for offset in [0, 4, 8, 9, 36, 40, 48] {
        let mut t = value.clone();
        t[offset] ^= 1;
        assert!(descriptor_capacity(&t).is_err());
    }
}
#[test]
fn bounded_reads_reject_symlinks_directories_fifo_empty_and_oversize() {
    let temp = tempfile::tempdir().unwrap();
    let dir = File::open(temp.path()).unwrap();
    fs::write(temp.path().join("data"), [7; 32]).unwrap();
    assert_eq!(read_at(&dir, c"data", 32).unwrap(), [7; 32]);
    assert_eq!(
        read_at(&dir, c"data", 31).unwrap_err(),
        GcpExecutionQuoteError::Bounds
    );
    fs::write(temp.path().join("empty"), []).unwrap();
    assert!(read_at(&dir, c"empty", 32).is_err());
    symlink(temp.path().join("data"), temp.path().join("link")).unwrap();
    assert!(read_at(&dir, c"link", 32).is_err());
    assert!(read_at(&dir, c"missing", 32).is_err());
    assert!(read_at(&dir, c"../data", 32).is_err());
    fs::create_dir(temp.path().join("directory")).unwrap();
    assert!(read_at(&dir, c"directory", 32).is_err());
    let path = CString::new(temp.path().join("fifo").as_os_str().as_encoded_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
    assert!(
        fs::metadata(temp.path().join("fifo"))
            .unwrap()
            .file_type()
            .is_fifo()
    );
    assert!(read_at(&dir, c"fifo", 32).is_err());
    assert!(read_at(&dir, c"data", 0).is_err());
    assert!(read_at(&dir, c"data", MAX_GCP_CCEL_BYTES + 1).is_err());
}
#[test]
fn directory_traversal_rejects_links_at_every_component() {
    let temp = tempfile::tempdir().unwrap();
    let dir = File::open(temp.path()).unwrap();
    fs::create_dir(temp.path().join("real")).unwrap();
    symlink(temp.path().join("real"), temp.path().join("link")).unwrap();
    assert!(open_directory_at(&dir, c"real").is_ok());
    assert!(open_directory_at(&dir, c"link").is_err());
    assert!(open_directory_at(&dir, c"..").is_err());
    assert!(open_absolute_directory(&[c"this-onb17-path-does-not-exist"]).is_err());
}
#[test]
fn report_directory_provider_generation_and_cleanup_are_checked_without_tdx() {
    let temp = tempfile::tempdir().unwrap();
    let parent = File::open(temp.path()).unwrap();
    let report = ReportDirectory::create(parent).unwrap();
    let path = temp.path().join(report.name.to_str().unwrap());
    fs::write(path.join("provider"), b"tdx_guest\n").unwrap();
    fs::write(path.join("generation"), b"0\n").unwrap();
    assert_eq!(report.exact(c"provider", b"tdx_guest\n"), Ok(()));
    assert!(report.exact(c"provider", b"sev_guest\n").is_err());
    assert_eq!(report.exact(c"generation", b"0\n"), Ok(()));
    for bad in [b"1\n".as_slice(), b"2\n", b"01\n", b"0", b"0\nextra"] {
        fs::write(path.join("generation"), bad).unwrap();
        assert!(report.exact(c"generation", b"0\n").is_err());
    }
    for name in ["provider", "generation"] {
        fs::remove_file(path.join(name)).unwrap();
    }
    drop(report);
    assert!(!path.exists());
}

#[test]
fn missing_native_tdx_and_ccel_returns_unavailable_without_sample_fallback() {
    // Hardware-independent CI host check. A TDX host runs separate native
    // qualification; this test does not manufacture evidence on such a host.
    if std::path::Path::new("/sys/firmware/acpi/tables/CCEL").exists()
        || std::path::Path::new("/sys/kernel/config/tsm/report").exists()
    {
        return;
    }
    assert_eq!(
        collect_gcp_tdx_execution_evidence(report()).unwrap_err(),
        GcpExecutionQuoteError::Unavailable
    );
}
