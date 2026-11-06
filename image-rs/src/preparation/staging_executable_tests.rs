use super::*;
use crate::preparation::{
    launch_spec::{tests as spec_fixture, BoundEffectiveSpec},
    layer_content::{
        check_layer_content, CheckedLayerContent, LayerContentExpectation, LayerContentLimits,
    },
};
use base64::{engine::general_purpose::STANDARD, Engine};
use ocicrypt_rs::blockcipher::{
    EncryptionFinalizer, LayerBlockCipherHandler, LayerBlockCipherOptions, AES256CTR,
};
use sha2::Sha256;
use std::{
    fs::{self, DirBuilder},
    io::Read,
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

struct Parent(PathBuf);
impl Parent {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        loop {
            let path = std::env::temp_dir().join(format!(
                "onb17-executable-test-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match DirBuilder::new().mode(0o700).create(&path) {
                Ok(()) => return Self(path),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => (),
                Err(error) => panic!("private fixture parent creation failed: {error}"),
            }
        }
    }
    fn capability(&self) -> PrivateStagingParent {
        PrivateStagingParent::new(File::open(&self.0).unwrap()).unwrap()
    }
    fn assert_empty(&self) {
        assert_eq!(fs::read_dir(&self.0).unwrap().count(), 0);
    }
}
impl Drop for Parent {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Entry<'a> {
    path: &'a str,
    bytes: &'a [u8],
    directory: bool,
    mode: u32,
    uid: u64,
    gid: u64,
}
fn file<'a>(path: &'a str, bytes: &'a [u8]) -> Entry<'a> {
    Entry {
        path,
        bytes,
        directory: false,
        mode: 0o755,
        uid: 0,
        gid: 0,
    }
}
fn directory(path: &str) -> Entry<'_> {
    Entry {
        path,
        bytes: b"",
        directory: true,
        mode: 0o755,
        uid: 0,
        gid: 0,
    }
}

async fn checked(index: u32, entries: &[Entry<'_>]) -> CheckedLayerContent {
    let mut tar = Vec::new();
    for entry in entries {
        let mut header = tokio_tar::Header::new_ustar();
        header.set_path(entry.path).unwrap();
        header.set_size(entry.bytes.len() as u64);
        header.set_mode(entry.mode);
        header.set_uid(entry.uid);
        header.set_gid(entry.gid);
        header.set_mtime(0);
        header.set_entry_type(if entry.directory {
            tokio_tar::EntryType::Directory
        } else {
            tokio_tar::EntryType::Regular
        });
        header.set_cksum();
        tar.extend_from_slice(header.as_bytes());
        tar.extend_from_slice(entry.bytes);
        tar.resize(tar.len().div_ceil(512) * 512, 0);
    }
    tar.resize(tar.len() + 1024, 0);
    let mut options = LayerBlockCipherOptions::default();
    options.private.digest = format!("sha256:{}", hash256(&tar));
    let mut cipher = LayerBlockCipherHandler::default();
    cipher
        .encrypt(tar.as_slice(), AES256CTR, &mut options)
        .unwrap();
    let mut ciphertext = Vec::new();
    Read::read_to_end(&mut cipher, &mut ciphertext).unwrap();
    cipher.finalized_lbco(&mut options).unwrap();
    let private = serde_json::to_vec(&options.private).unwrap();
    let private_len = private.len();
    let public = serde_json::to_vec(&options.public).unwrap();
    check_layer_content(
        LayerContentExpectation {
            original_index: index,
            media_type: "application/vnd.oci.image.layer.v1.tar+encrypted",
            blob_sha256: &hash256(&ciphertext),
            descriptor_size: ciphertext.len() as u64,
            diff_id: &format!("sha256:{}", hash256(&tar)),
            public_options_b64: &STANDARD.encode(&public),
        },
        &ciphertext,
        Zeroizing::new(private),
        LayerContentLimits {
            ciphertext_bytes: ciphertext.len(),
            private_options_bytes: private_len,
            public_options_bytes: public.len(),
            plaintext_bytes: tar.len(),
            tar_bytes: tar.len(),
            tar_entries: entries.len().max(1),
            path_bytes: 256,
            file_bytes: 8192,
        },
    )
    .await
    .unwrap()
}

fn hash256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
fn hash384(bytes: &[u8]) -> String {
    Sha384::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
fn elf() -> Vec<u8> {
    let mut bytes = vec![0u8; 512];
    bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    bytes[16..18].copy_from_slice(&2u16.to_le_bytes());
    bytes[18..20].copy_from_slice(&62u16.to_le_bytes());
    bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
    bytes[24..32].copy_from_slice(&0x400100u64.to_le_bytes());
    bytes[32..40].copy_from_slice(&64u64.to_le_bytes());
    bytes[52..54].copy_from_slice(&64u16.to_le_bytes());
    bytes[54..56].copy_from_slice(&56u16.to_le_bytes());
    bytes[56..58].copy_from_slice(&2u16.to_le_bytes());
    bytes[64..68].copy_from_slice(&1u32.to_le_bytes());
    bytes[68..72].copy_from_slice(&5u32.to_le_bytes());
    bytes[80..88].copy_from_slice(&0x400000u64.to_le_bytes());
    bytes[96..104].copy_from_slice(&512u64.to_le_bytes());
    bytes[104..112].copy_from_slice(&512u64.to_le_bytes());
    bytes[112..120].copy_from_slice(&4096u64.to_le_bytes());
    bytes[120..124].copy_from_slice(&0x6474e551u32.to_le_bytes());
    bytes[124..128].copy_from_slice(&6u32.to_le_bytes());
    bytes[256] = 0xc3;
    bytes
}
fn elf_limits() -> StaticElfLimits {
    StaticElfLimits {
        file_bytes: 8192,
        program_headers: 8,
        mapped_bytes: 8192,
        virtual_span_bytes: 8192,
    }
}
fn staging_limits() -> RootfsStagingLimits {
    RootfsStagingLimits {
        layers: 4,
        total_tar_bytes: 64 * 1024,
        applied_entries: 32,
        inodes: 32,
        write_bytes: 16384,
        live_file_bytes: 16384,
        path_bytes: 256,
        path_components: 8,
    }
}
fn spec(executable: &str, cwd: &str) -> BoundEffectiveSpec {
    let mut value = spec_fixture::fixture_value();
    value["process"]["args"] = serde_json::json!([executable]);
    value["process"]["cwd"] = serde_json::json!(cwd);
    let raw = serde_json::to_vec(&value).unwrap();
    BoundEffectiveSpec::parse(
        &raw,
        &hash384(&raw),
        &spec_fixture::policy(),
        spec_fixture::limits(),
    )
    .unwrap()
}
async fn staged(parent: &Parent, entries: &[Entry<'_>]) -> RootfsStaging {
    RootfsStaging::from_checked_layers(
        parent.capability(),
        vec![checked(0, entries).await],
        staging_limits(),
    )
    .unwrap()
}
fn path(parent: &Parent, staging: &RootfsStaging, relative: &str) -> PathBuf {
    parent.0.join(&staging.name).join(relative)
}

#[tokio::test]
async fn checked_tar_to_actual_elf_returns_only_bound_commitments_and_metadata() {
    let parent = Parent::new();
    let bytes = elf();
    let staging = staged(
        &parent,
        &[
            file("bin/app", &bytes),
            directory("work"),
            directory("work/nested"),
        ],
    )
    .await;
    let spec = spec("/bin/app", "/work/nested");
    let checked = staging
        .check_static_executable(&spec, elf_limits())
        .unwrap();
    assert_eq!(checked.spec_sha384(), spec.sha384());
    assert_eq!(checked.executable_sha384(), hash384(&bytes));
    assert_eq!(checked.executable(), "/bin/app");
    assert_eq!(checked.elf().file_bytes(), bytes.len());
    assert_eq!(checked.clone(), checked);
    assert_eq!(
        fs::metadata(path(&parent, &staging, "bin/app"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    staging.discard().unwrap();
    parent.assert_empty();
}

#[tokio::test]
async fn upper_layer_updates_both_expected_inode_and_verified_payload_commitment() {
    let parent = Parent::new();
    let lower = elf();
    let mut upper = elf();
    upper[400] = 1;
    let staging = RootfsStaging::from_checked_layers(
        parent.capability(),
        vec![
            checked(0, &[file("app", &lower)]).await,
            checked(1, &[file("app", &upper)]).await,
        ],
        staging_limits(),
    )
    .unwrap();
    let checked = staging
        .check_static_executable(&spec("/app", "/"), elf_limits())
        .unwrap();
    assert_eq!(checked.executable_sha384(), hash384(&upper));
    assert_ne!(checked.executable_sha384(), hash384(&lower));
    staging.discard().unwrap();
    parent.assert_empty();
}

#[tokio::test]
async fn target_permission_class_must_execute_without_write_and_owner_takes_precedence() {
    let bytes = elf();
    for (mode, uid, gid) in [
        (0o744, 0, 0),
        (0o755, 1000, 0),
        (0o775, 0, 1000),
        (0o757, 0, 0),
        (0o055, 1000, 0),
    ] {
        let parent = Parent::new();
        let mut entry = file("app", &bytes);
        entry.mode = mode;
        entry.uid = uid;
        entry.gid = gid;
        let staging = staged(&parent, &[entry]).await;
        assert_eq!(
            staging
                .check_static_executable(&spec("/app", "/"), elf_limits())
                .unwrap_err(),
            StagedExecutableError::PermissionDenied
        );
        staging.discard().unwrap();
        parent.assert_empty();
    }
}

#[tokio::test]
async fn entry_and_cwd_ancestors_need_search_and_must_not_be_writable_by_launch_user() {
    let bytes = elf();
    for (directory_path, mode, uid, cwd) in [
        ("bin", 0o700, 0, "/"),
        ("bin", 0o777, 0, "/"),
        ("bin", 0o755, 1000, "/"),
        ("work", 0o700, 0, "/work"),
        ("work", 0o777, 0, "/work"),
    ] {
        let parent = Parent::new();
        let mut dir = directory(directory_path);
        dir.mode = mode;
        dir.uid = uid;
        let staging = staged(&parent, &[dir, file("bin/app", &bytes)]).await;
        assert_eq!(
            staging
                .check_static_executable(&spec("/bin/app", cwd), elf_limits())
                .unwrap_err(),
            StagedExecutableError::PermissionDenied
        );
        staging.discard().unwrap();
        parent.assert_empty();
    }
}

#[tokio::test]
async fn missing_entry_bad_cwd_nonelf_and_read_limits_reject_without_authorization() {
    let parent = Parent::new();
    let bytes = elf();
    let staging = staged(
        &parent,
        &[file("app", &bytes), file("script", b"#!/bin/sh\nexit 0\n")],
    )
    .await;
    for (entry, cwd) in [
        ("/missing", "/"),
        ("/app", "/missing"),
        ("/app", "/app"),
        ("/script", "/"),
    ] {
        assert!(staging
            .check_static_executable(&spec(entry, cwd), elf_limits())
            .is_err());
    }
    let mut limits = elf_limits();
    limits.file_bytes = bytes.len() - 1;
    assert_eq!(
        staging
            .check_static_executable(&spec("/app", "/"), limits)
            .unwrap_err(),
        StagedExecutableError::TooLarge
    );
    limits.file_bytes = 0;
    assert_eq!(
        staging
            .check_static_executable(&spec("/app", "/"), limits)
            .unwrap_err(),
        StagedExecutableError::InvalidLimits
    );
    staging.discard().unwrap();
    parent.assert_empty();
}

#[tokio::test]
async fn same_size_same_inode_mutation_is_detected_by_the_verified_tar_payload_hash() {
    let parent = Parent::new();
    let mut bytes = elf();
    let staging = staged(&parent, &[file("app", &bytes)]).await;
    let spec = spec("/app", "/");
    assert!(staging.check_static_executable(&spec, elf_limits()).is_ok());
    bytes[400] ^= 1;
    fs::write(path(&parent, &staging, "app"), &bytes).unwrap();
    assert_eq!(
        staging
            .check_static_executable(&spec, elf_limits())
            .unwrap_err(),
        StagedExecutableError::ContentMismatch
    );
    staging.discard().unwrap();
    parent.assert_empty();
}

#[tokio::test]
async fn replacement_leaf_inode_is_rejected_even_when_bytes_size_and_mode_match() {
    let parent = Parent::new();
    let bytes = elf();
    let staging = staged(&parent, &[file("app", &bytes)]).await;
    let app = path(&parent, &staging, "app");
    let saved = path(&parent, &staging, "saved");
    fs::rename(&app, &saved).unwrap();
    fs::write(&app, &bytes).unwrap();
    fs::set_permissions(&app, fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(
        staging
            .check_static_executable(&spec("/app", "/"), elf_limits())
            .unwrap_err(),
        StagedExecutableError::IdentityMismatch
    );
    fs::remove_file(&app).unwrap();
    fs::rename(saved, app).unwrap();
    staging.discard().unwrap();
    parent.assert_empty();
}

#[tokio::test]
async fn hardlink_alias_and_workspace_mode_changes_are_rejected() {
    let parent = Parent::new();
    let bytes = elf();
    let staging = staged(&parent, &[file("app", &bytes)]).await;
    let app = path(&parent, &staging, "app");
    let alias = path(&parent, &staging, "alias");
    fs::hard_link(&app, &alias).unwrap();
    assert_eq!(
        staging
            .check_static_executable(&spec("/app", "/"), elf_limits())
            .unwrap_err(),
        StagedExecutableError::WorkspaceMismatch
    );
    fs::remove_file(alias).unwrap();
    fs::set_permissions(&app, fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(
        staging
            .check_static_executable(&spec("/app", "/"), elf_limits())
            .unwrap_err(),
        StagedExecutableError::WorkspaceMismatch
    );
    fs::set_permissions(&app, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(staging
        .check_static_executable(&spec("/app", "/"), elf_limits())
        .is_ok());
    staging.discard().unwrap();
    parent.assert_empty();
}

#[tokio::test]
async fn symlink_and_fifo_leaf_substitution_never_follow_or_block() {
    for fifo in [false, true] {
        let parent = Parent::new();
        let outside = Parent::new();
        let bytes = elf();
        let staging = staged(&parent, &[file("app", &bytes)]).await;
        let app = path(&parent, &staging, "app");
        let saved = path(&parent, &staging, "saved");
        fs::rename(&app, &saved).unwrap();
        if fifo {
            nix::unistd::mkfifo(&app, Mode::S_IRUSR | Mode::S_IWUSR).unwrap();
        } else {
            fs::write(outside.0.join("sentinel"), &bytes).unwrap();
            std::os::unix::fs::symlink(outside.0.join("sentinel"), &app).unwrap();
        }
        assert!(staging
            .check_static_executable(&spec("/app", "/"), elf_limits())
            .is_err());
        if !fifo {
            assert_eq!(fs::read(outside.0.join("sentinel")).unwrap(), bytes);
        }
        fs::remove_file(&app).unwrap();
        fs::rename(saved, app).unwrap();
        staging.discard().unwrap();
        parent.assert_empty();
    }
}

#[tokio::test]
async fn ancestor_and_named_root_replacement_are_detected_and_original_tree_remains_owned() {
    for root in [false, true] {
        let parent = Parent::new();
        let bytes = elf();
        let staging = staged(&parent, &[file("bin/app", &bytes)]).await;
        let target = if root {
            parent.0.join(&staging.name)
        } else {
            path(&parent, &staging, "bin")
        };
        let saved = parent.0.join("saved-owned-directory");
        fs::rename(&target, &saved).unwrap();
        DirBuilder::new().mode(0o700).create(&target).unwrap();
        assert_eq!(
            staging
                .check_static_executable(&spec("/bin/app", "/"), elf_limits())
                .unwrap_err(),
            StagedExecutableError::IdentityMismatch
        );
        fs::remove_dir(&target).unwrap();
        fs::rename(saved, target).unwrap();
        staging.discard().unwrap();
        parent.assert_empty();
    }
}
