use super::*;
use crate::preparation::launch_spec::tests as spec_fixture;
use std::{
    cell::Cell,
    fs::{self, DirBuilder, FileTimes},
    os::unix::fs::{symlink, DirBuilderExt, MetadataExt, PermissionsExt},
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
    time::UNIX_EPOCH,
};

/// These are ordinary private-tree unit fixtures for the descriptor checker.
/// They never bypass the production EROFS mount-profile entry point.
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        loop {
            let path = std::env::temp_dir().join(format!(
                "mounted-view-unit-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match DirBuilder::new().mode(0o700).create(&path) {
                Ok(()) => {
                    let fixture = Self(path);
                    fixture.populate();
                    return fixture;
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => (),
                Err(error) => panic!("private fixture creation failed: {error}"),
            }
        }
    }
    fn populate(&self) {
        fs::create_dir(self.0.join("root")).unwrap();
        fs::create_dir(self.0.join("root/bin")).unwrap();
        fs::create_dir(self.0.join("root/work")).unwrap();
        fs::write(self.0.join("root/bin/app"), elf()).unwrap();
        fs::write(self.0.join("root/data"), vec![9; 9001]).unwrap();
        fs::write(self.0.join("root/empty"), []).unwrap();
        for path in [
            "root/bin/app",
            "root/data",
            "root/empty",
            "root/bin",
            "root/work",
            "root",
        ] {
            let file = File::open(self.0.join(path)).unwrap();
            file.set_permissions(fs::Permissions::from_mode(
                if path.ends_with("data") || path.ends_with("empty") {
                    0o644
                } else {
                    0o755
                },
            ))
            .unwrap();
            file.set_times(FileTimes::new().set_modified(UNIX_EPOCH))
                .unwrap();
        }
    }
    fn root(&self) -> File {
        let path = CString::new(self.0.join("root").as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: the path is a live NUL-terminated fixture path; success gives
        // one O_PATH descriptor transferred directly into File ownership.
        let fd = unsafe {
            libc::open(
                path.as_ptr(),
                libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        assert!(fd >= 0);
        unsafe { File::from_raw_fd(fd) }
    }
    fn path(&self, path: &str) -> PathBuf {
        self.0.join("root").join(path)
    }
    fn expected(&self) -> Vec<ExpectedNode> {
        [".", "bin", "bin/app", "data", "empty", "work"]
            .into_iter()
            .map(|path| {
                let file = if path == "." {
                    self.0.join("root")
                } else {
                    self.path(path)
                };
                let meta = fs::metadata(&file).unwrap();
                let is_dir = meta.is_dir();
                ExpectedNode {
                    path: path.to_owned(),
                    is_dir,
                    mode: meta.mode() & 0o7777,
                    uid: meta.uid(),
                    gid: meta.gid(),
                    mtime: meta.mtime() as u64,
                    size: if is_dir { 0 } else { meta.size() as usize },
                    payload_sha384: if is_dir {
                        None
                    } else {
                        Some(Sha384::digest(fs::read(file).unwrap()).into())
                    },
                }
            })
            .collect()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn limits() -> MountedViewLimits {
    MountedViewLimits {
        inodes: 32,
        live_file_bytes: 16384,
        path_bytes: 256,
        path_components: 8,
        directory_entry_bytes: 16384,
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
fn hash(bytes: &[u8]) -> String {
    Sha384::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn spec(executable: &str, cwd: &str) -> BoundEffectiveSpec {
    let mut value = spec_fixture::fixture_value();
    value["process"]["args"] = serde_json::json!([executable]);
    value["process"]["cwd"] = serde_json::json!(cwd);
    // The fixture owner may mutate its private setup. The candidate runs as a
    // distinct nonroot identity and therefore has the other permission class.
    let uid = unsafe { libc::geteuid() }.checked_add(1).unwrap().max(1);
    let gid = unsafe { libc::getegid() }.checked_add(1).unwrap().max(1);
    value["process"]["user"]["uid"] = uid.into();
    value["process"]["user"]["gid"] = gid.into();
    let mut policy = spec_fixture::policy();
    policy.uid = uid;
    policy.gid = gid;
    let raw = serde_json::to_vec(&value).unwrap();
    BoundEffectiveSpec::parse(&raw, &hash(&raw), &policy, spec_fixture::limits()).unwrap()
}
fn elf() -> Vec<u8> {
    let mut bytes = vec![0u8; 512];
    bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    for (offset, value) in [(16, 2u16), (18, 62), (52, 64), (54, 56), (56, 2)] {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }
    bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
    bytes[24..32].copy_from_slice(&0x400100u64.to_le_bytes());
    bytes[32..40].copy_from_slice(&64u64.to_le_bytes());
    bytes[64..68].copy_from_slice(&1u32.to_le_bytes());
    bytes[68..72].copy_from_slice(&5u32.to_le_bytes());
    bytes[80..88].copy_from_slice(&0x400000u64.to_le_bytes());
    bytes[96..104].copy_from_slice(&512u64.to_le_bytes());
    bytes[104..112].copy_from_slice(&512u64.to_le_bytes());
    bytes[112..120].copy_from_slice(&4096u64.to_le_bytes());
    bytes[120..124].copy_from_slice(&0x6474e551u32.to_le_bytes());
    bytes[124..128].copy_from_slice(&6u32.to_le_bytes());
    bytes[168..176].copy_from_slice(&16u64.to_le_bytes());
    bytes[256] = 0xc3;
    bytes
}
fn checked(
    fixture: &Fixture,
    expected: &[ExpectedNode],
) -> Result<MountedViewCheck, MountedViewError> {
    unit_tree(
        &fixture.root(),
        expected,
        &spec("/bin/app", "/work"),
        elf_limits(),
        limits(),
        &|| false,
    )
}

fn unit_tree(
    root: &File,
    expected: &[ExpectedNode],
    spec: &BoundEffectiveSpec,
    elf_limits: StaticElfLimits,
    limits: MountedViewLimits,
    cancelled: &impl Fn() -> bool,
) -> Result<MountedViewCheck, MountedViewError> {
    // This fixture is a directory beneath its mount root. Its dot-dot points at
    // the private containing directory; an actual detached mount root is self.
    // SAFETY: a fixed dot-dot lookup on the held private fixture FD returns one
    // new owned directory descriptor, used only for this unit fixture relation.
    let parent = unsafe {
        libc::openat(
            root.as_raw_fd(),
            c"..".as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    assert!(parent >= 0);
    let parent = unsafe { File::from_raw_fd(parent) };
    let parent_inode = snapshot(&parent)?.ino;
    check_tree_at(
        RootLocation {
            file: root,
            parent_inode: Some(parent_inode),
        },
        expected,
        spec,
        elf_limits,
        limits,
        cancelled,
    )
}

#[test]
fn ordinary_tree_unit_readback_binds_metadata_payload_and_same_owned_executable_snapshot() {
    let fixture = Fixture::new();
    let expected = fixture.expected();
    let root = fixture.root();
    let candidate = spec("/bin/app", "/work");
    let result = unit_tree(
        &root,
        &expected,
        &candidate,
        elf_limits(),
        limits(),
        &|| false,
    )
    .unwrap();
    assert_eq!(result.summary.spec_sha384(), candidate.sha384());
    assert_eq!(result.summary.executable_sha384(), hash(&elf()));
    assert_eq!(result.summary.executable(), "/bin/app");
    assert_eq!(result.summary.elf().file_bytes(), 512);
    assert_eq!(result.summary.inodes(), expected.len());
    assert_eq!(result.summary.live_file_bytes(), 9513);
    assert_eq!(result.summary.mount_id(), snapshot(&root).unwrap().mount_id);
    assert_eq!(
        snapshot(&result._executable).unwrap().mount_id,
        result.summary.mount_id()
    );
    assert_eq!(
        snapshot(&result._cwd).unwrap().mount_id,
        result.summary.mount_id()
    );
    let mut bytes = vec![0; 512];
    result._executable.read_exact_at(&mut bytes, 0).unwrap();
    assert_eq!(bytes, elf());
    assert_eq!(
        check_mounted_view(
            &root,
            &expected,
            &candidate,
            elf_limits(),
            limits(),
            &|| false
        )
        .err(),
        Some(MountedViewError::MountProfileRejected)
    );
}

#[test]
fn actual_regular_metadata_and_payload_mutations_cannot_match_expected_inventory() {
    for case in [
        "mode",
        "uid",
        "gid",
        "mtime",
        "nanoseconds",
        "size",
        "payload",
        "hardlink",
    ] {
        let fixture = Fixture::new();
        let mut expected = fixture.expected();
        let entry = expected.iter_mut().find(|n| n.path == "bin/app").unwrap();
        match case {
            "mode" => entry.mode = 0o700,
            "uid" => entry.uid += 1,
            "gid" => entry.gid += 1,
            "mtime" => entry.mtime += 1,
            "nanoseconds" => File::open(fixture.path("bin/app"))
                .unwrap()
                .set_times(
                    FileTimes::new().set_modified(UNIX_EPOCH + std::time::Duration::from_nanos(1)),
                )
                .unwrap(),
            "size" => entry.size += 1,
            "payload" => {
                let file = File::options()
                    .write(true)
                    .open(fixture.path("bin/app"))
                    .unwrap();
                file.write_all_at(b"X", 256).unwrap();
                file.set_times(FileTimes::new().set_modified(UNIX_EPOCH))
                    .unwrap();
            }
            "hardlink" => fs::hard_link(fixture.path("bin/app"), fixture.0.join("alias")).unwrap(),
            _ => unreachable!(),
        }
        assert!(checked(&fixture, &expected).is_err(), "{case}");
    }
}

#[test]
fn actual_directory_set_types_symlinks_missing_and_unexpected_nodes_are_rejected() {
    for case in [
        "extra-file",
        "extra-directory",
        "missing",
        "symlink",
        "directory-to-file",
        "directory-mode",
        "directory-time",
    ] {
        let fixture = Fixture::new();
        let expected = fixture.expected();
        match case {
            "extra-file" => fs::write(fixture.path("unexpected"), b"extra").unwrap(),
            "extra-directory" => fs::create_dir(fixture.path("unexpected")).unwrap(),
            "missing" => fs::remove_file(fixture.path("empty")).unwrap(),
            "symlink" => {
                fs::remove_file(fixture.path("empty")).unwrap();
                symlink("bin/app", fixture.path("empty")).unwrap();
            }
            "directory-to-file" => {
                fs::remove_dir(fixture.path("work")).unwrap();
                fs::write(fixture.path("work"), []).unwrap();
            }
            "directory-mode" => {
                fs::set_permissions(fixture.path("work"), fs::Permissions::from_mode(0o700))
                    .unwrap()
            }
            "directory-time" => File::open(fixture.path("work"))
                .unwrap()
                .set_times(
                    FileTimes::new().set_modified(UNIX_EPOCH + std::time::Duration::from_secs(1)),
                )
                .unwrap(),
            _ => unreachable!(),
        }
        assert!(checked(&fixture, &expected).is_err(), "{case}");
    }
}

#[test]
fn actual_special_files_and_outside_or_symlink_resolution_are_rejected_without_blocking() {
    let fixture = Fixture::new();
    let expected = fixture.expected();
    fs::remove_file(fixture.path("empty")).unwrap();
    let path = CString::new(fixture.path("empty").as_os_str().as_encoded_bytes()).unwrap();
    // SAFETY: this creates a private synthetic FIFO, which is never opened for blocking I/O.
    assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
    assert!(checked(&fixture, &expected).is_err());
    assert_eq!(
        open_beneath(&fixture.root(), "../", true, true).err(),
        Some(MountedViewError::IdentityMismatch)
    );
    fs::remove_file(fixture.path("empty")).unwrap();
    symlink("/", fixture.path("escape")).unwrap();
    assert!(open_beneath(&fixture.root(), "escape", true, true).is_err());
}

#[test]
fn changed_mount_identity_and_every_budget_fail_closed() {
    let fixture = Fixture::new();
    let expected = fixture.expected();
    let root = fixture.root();
    let inv = inventory(&expected, limits()).unwrap();
    let actual = snapshot(&root).unwrap();
    assert_eq!(
        check_node(actual, &expected[0], actual.mount_id + 1, &inv),
        Err(MountedViewError::IdentityMismatch)
    );
    for field in 0..5 {
        let mut zero = limits();
        match field {
            0 => zero.inodes = 0,
            1 => zero.live_file_bytes = 0,
            2 => zero.path_bytes = 0,
            3 => zero.path_components = 0,
            4 => zero.directory_entry_bytes = 0,
            _ => unreachable!(),
        }
        assert_eq!(zero.validate(), Err(MountedViewError::InvalidLimits));
    }
    for field in 0..5 {
        let mut small = limits();
        match field {
            0 => small.inodes = expected.len() - 1,
            1 => small.live_file_bytes = 9512,
            2 => small.path_bytes = 6,
            3 => small.path_components = 1,
            4 => small.directory_entry_bytes = 1,
            _ => unreachable!(),
        }
        assert!(
            unit_tree(
                &root,
                &expected,
                &spec("/bin/app", "/work"),
                elf_limits(),
                small,
                &|| false
            )
            .is_err(),
            "{field}"
        );
    }
    let mut elf_cap = elf_limits();
    elf_cap.file_bytes = 511;
    assert_eq!(
        unit_tree(
            &root,
            &expected,
            &spec("/bin/app", "/work"),
            elf_cap,
            limits(),
            &|| false
        )
        .err(),
        Some(MountedViewError::TooLarge)
    );
}

#[test]
fn candidate_entry_cwd_permissions_and_elf_are_rechecked_from_actual_tree() {
    for case in ["entry", "cwd", "cwd-file", "entry-mode", "cwd-mode", "elf"] {
        let fixture = Fixture::new();
        let mut expected = fixture.expected();
        if matches!(case, "entry-mode" | "cwd-mode") {
            let path = if case == "entry-mode" {
                "bin/app"
            } else {
                "work"
            };
            fs::set_permissions(fixture.path(path), fs::Permissions::from_mode(0o777)).unwrap();
            expected = fixture.expected();
        }
        if case == "elf" {
            fs::write(fixture.path("bin/app"), vec![0; 512]).unwrap();
            File::open(fixture.path("bin/app"))
                .unwrap()
                .set_times(FileTimes::new().set_modified(UNIX_EPOCH))
                .unwrap();
            expected = fixture.expected();
        }
        let candidate = spec(
            if case == "entry" {
                "/missing"
            } else {
                "/bin/app"
            },
            match case {
                "cwd" => "/missing",
                "cwd-file" => "/data",
                _ => "/work",
            },
        );
        assert!(
            unit_tree(
                &fixture.root(),
                &expected,
                &candidate,
                elf_limits(),
                limits(),
                &|| false
            )
            .is_err(),
            "{case}"
        );
    }
}

#[test]
fn malformed_expected_inventory_and_cancellation_never_return_owned_success() {
    let fixture = Fixture::new();
    let expected = fixture.expected();
    for case in [
        "root",
        "duplicate",
        "orphan",
        "traversal",
        "null",
        "type",
        "mode",
        "empty-commitment",
    ] {
        let mut malformed = expected.clone();
        match case {
            "root" => {
                malformed.remove(0);
            }
            "duplicate" => malformed.push(expected[0].clone()),
            "orphan" => malformed[2].path = "missing/app".into(),
            "traversal" => malformed[2].path = "bin/../app".into(),
            "null" => malformed[2].path = "bin/\0app".into(),
            "type" => malformed[0].is_dir = false,
            "mode" => malformed[0].mode = 0o4755,
            "empty-commitment" => malformed[2].payload_sha384 = None,
            _ => unreachable!(),
        }

        assert_eq!(
            inventory(&malformed, limits()).err(),
            Some(MountedViewError::InventoryMismatch),
            "{case}"
        );
    }
    let calls = Cell::new(0usize);
    let cancelled = || {
        calls.set(calls.get() + 1);
        calls.get() > 8
    };
    assert_eq!(
        unit_tree(
            &fixture.root(),
            &expected,
            &spec("/bin/app", "/work"),
            elf_limits(),
            limits(),
            &cancelled
        )
        .err(),
        Some(MountedViewError::Cancelled)
    );
}

#[test]
fn same_content_leaf_substitution_during_read_rejects_the_changed_named_inode() {
    let fixture = Fixture::new();
    let expected = fixture.expected();
    let target = fixture.path("bin/app");
    let changed = Cell::new(false);
    let observe_read = || {
        if !changed.get()
            && fs::read_dir("/proc/self/fd").unwrap().any(|entry| {
                entry
                    .is_ok_and(|entry| fs::read_link(entry.path()).is_ok_and(|path| path == target))
            })
        {
            // The checker already owns its regular file descriptor. Replace the
            // name with the same bytes/metadata while preserving the old inode
            // at a private name outside the checked root; content parity alone
            // cannot distinguish these files.
            fs::rename(&target, fixture.0.join("retained-old-app")).unwrap();
            fs::write(&target, elf()).unwrap();
            let replacement = File::open(&target).unwrap();
            replacement
                .set_permissions(fs::Permissions::from_mode(0o755))
                .unwrap();
            replacement
                .set_times(FileTimes::new().set_modified(UNIX_EPOCH))
                .unwrap();
            File::open(fixture.path("bin"))
                .unwrap()
                .set_times(FileTimes::new().set_modified(UNIX_EPOCH))
                .unwrap();
            changed.set(true);
        }
        false
    };
    let outcome = unit_tree(
        &fixture.root(),
        &expected,
        &spec("/bin/app", "/work"),
        elf_limits(),
        limits(),
        &observe_read,
    );
    assert!(changed.get(), "owned-file observation was reached");
    assert_eq!(outcome.err(), Some(MountedViewError::IdentityMismatch));
}
