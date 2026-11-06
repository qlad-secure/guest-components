use super::*;
use crate::preparation::layer_content::{
    check_layer_content, CheckedLayerContent, LayerContentExpectation, LayerContentLimits,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use ocicrypt_rs::blockcipher::{
    EncryptionFinalizer, LayerBlockCipherHandler, LayerBlockCipherOptions, AES256CTR,
};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, DirBuilder},
    io::Read,
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
use zeroize::Zeroizing;

struct Parent(PathBuf);

impl Parent {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        loop {
            let path = std::env::temp_dir().join(format!(
                "onb17-staging-test-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match DirBuilder::new().mode(0o700).create(&path) {
                Ok(()) => return Self(path),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => panic!("private test parent creation: {e}"),
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
        fs::remove_dir_all(&self.0).unwrap();
    }
}

struct Entry<'a> {
    path: &'a str,
    payload: &'a [u8],
    dir: bool,
    mode: u32,
    uid: u64,
    gid: u64,
    mtime: u64,
}

fn file<'a>(path: &'a str, payload: &'a [u8]) -> Entry<'a> {
    Entry {
        path,
        payload,
        dir: false,
        mode: 0o755,
        uid: 11,
        gid: 12,
        mtime: 13,
    }
}

fn directory(path: &str) -> Entry<'_> {
    Entry {
        path,
        payload: b"",
        dir: true,
        mode: 0,
        uid: 21,
        gid: 22,
        mtime: 23,
    }
}

async fn checked(index: u32, entries: &[Entry<'_>]) -> CheckedLayerContent {
    let mut tar = Vec::new();
    for entry in entries {
        let mut header = tokio_tar::Header::new_ustar();
        header.set_path(entry.path).unwrap();
        header.set_size(entry.payload.len() as u64);
        header.set_mode(entry.mode);
        header.set_uid(entry.uid);
        header.set_gid(entry.gid);
        header.set_mtime(entry.mtime);
        header.set_entry_type(if entry.dir {
            tokio_tar::EntryType::Directory
        } else {
            tokio_tar::EntryType::Regular
        });
        header.set_cksum();
        tar.extend_from_slice(header.as_bytes());
        tar.extend_from_slice(entry.payload);
        tar.resize(tar.len().div_ceil(512) * 512, 0);
    }
    tar.resize(tar.len() + 1024, 0);
    let sha256 = |bytes: &[u8]| {
        Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    let mut options = LayerBlockCipherOptions::default();
    options.private.digest = format!("sha256:{}", sha256(&tar));
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
            blob_sha256: &sha256(&ciphertext),
            descriptor_size: ciphertext.len() as u64,
            diff_id: &format!("sha256:{}", sha256(&tar)),
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
            file_bytes: 4096,
        },
    )
    .await
    .unwrap()
}

fn limits() -> RootfsStagingLimits {
    // Local fixture budgets only, not deployment defaults.
    RootfsStagingLimits {
        layers: 4,
        total_tar_bytes: 32 * 1024,
        applied_entries: 16,
        inodes: 16,
        write_bytes: 4096,
        live_file_bytes: 4096,
        path_bytes: 256,
        path_components: 8,
    }
}

#[tokio::test]
async fn ordered_layers_merge_and_replace_bytes_while_retaining_archive_metadata() {
    let parent = Parent::new();
    let lower = checked(0, &[directory("."), file("bin/app", b"lower-long-payload")]).await;
    let mut replacement = file("bin/app", b"x");
    replacement.mode = 0o400;
    replacement.uid = 31;
    replacement.gid = 32;
    replacement.mtime = 33;
    let upper = checked(1, &[directory("bin"), replacement, file("bin/other", b"z")]).await;
    let tar_bytes = lower.tar_byte_len() + upper.tar_byte_len();
    let staged =
        RootfsStaging::from_checked_layers(parent.capability(), vec![lower, upper], limits())
            .unwrap();
    let root = parent.0.join(&staged.name);
    assert_eq!(fs::read(root.join("bin/app")).unwrap(), b"x");
    assert_eq!(fs::read(root.join("bin/other")).unwrap(), b"z");
    assert_eq!(
        fs::metadata(&root).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(root.join("bin")).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(root.join("bin/app"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    let app = &staged.nodes["bin/app"];
    assert!(!app.metadata.is_dir);
    assert_eq!(app.size, 1);
    assert_eq!(app.metadata.mode, 0o400);
    assert_eq!(
        (app.metadata.uid, app.metadata.gid, app.metadata.mtime),
        (31, 32, 33)
    );
    assert_eq!(staged.nodes["bin"].metadata.mode, 0);
    assert_eq!(staged.nodes["."].metadata.uid, 21);
    assert_eq!(staged.summary().layers(), 2);
    assert_eq!(staged.summary().applied_entries(), 5);
    assert_eq!(staged.summary().inodes(), 4);
    assert_eq!(
        staged.summary().write_bytes(),
        b"lower-long-payload".len() + 2
    );
    assert_eq!(staged.summary().live_file_bytes(), 2);
    assert_eq!(staged.summary().total_tar_bytes() as u64, tar_bytes);
    staged.discard().unwrap();
    parent.assert_empty();
}

#[tokio::test]
async fn implicit_directories_have_explicit_deterministic_metadata_and_drop_cleans_them() {
    let parent = Parent::new();
    let layer = checked(0, &[file("a/b/app", b"payload")]).await;
    let staged =
        RootfsStaging::from_checked_layers(parent.capability(), vec![layer], limits()).unwrap();
    for path in [".", "a", "a/b"] {
        let metadata = &staged.nodes[path].metadata;
        assert!(metadata.is_dir);
        assert_eq!(metadata.mode, 0o755);
        assert_eq!((metadata.uid, metadata.gid, metadata.mtime), (0, 0, 0));
    }
    assert_eq!(staged.summary().inodes(), 4);
    drop(staged);
    parent.assert_empty();
}

#[tokio::test]
async fn cross_layer_file_directory_collisions_fail_and_remove_partial_staging() {
    for file_first in [false, true] {
        let parent = Parent::new();
        let lower = if file_first {
            checked(0, &[file("node", b"lower")]).await
        } else {
            checked(0, &[file("node/child", b"lower")]).await
        };
        let upper = if file_first {
            checked(1, &[file("node/child", b"upper")]).await
        } else {
            checked(1, &[file("node", b"upper")]).await
        };
        assert!(RootfsStaging::from_checked_layers(
            parent.capability(),
            vec![lower, upper],
            limits(),
        )
        .is_err());
        parent.assert_empty();
    }
}

#[tokio::test]
async fn missing_reordered_duplicate_and_empty_layer_sequences_are_rejected() {
    for indices in [vec![], vec![1], vec![1, 0], vec![0, 0], vec![0, 2]] {
        let parent = Parent::new();
        let mut layers = Vec::new();
        for index in indices {
            layers.push(checked(index, &[file("app", b"payload")]).await);
        }
        assert!(RootfsStaging::from_checked_layers(parent.capability(), layers, limits()).is_err());
        parent.assert_empty();
    }
}

#[tokio::test]
async fn aggregate_work_live_bytes_inodes_and_paths_are_bounded_with_cleanup() {
    for case in [
        "layers", "tar", "entries", "inodes", "writes", "live", "path", "depth",
    ] {
        let parent = Parent::new();
        let lower = checked(0, &[file("a/b/app", b"lower"), file("second", b"data")]).await;
        let upper = checked(1, &[file("a/b/app", b"x")]).await;
        let mut cap = limits();
        match case {
            "layers" => cap.layers = 1,
            "tar" => {
                cap.total_tar_bytes = (lower.tar_byte_len() + upper.tar_byte_len() - 1) as usize
            }
            "entries" => cap.applied_entries = 1,
            "inodes" => cap.inodes = 3,
            "writes" => cap.write_bytes = 9,
            "live" => cap.live_file_bytes = 8,
            "path" => cap.path_bytes = 6,
            "depth" => cap.path_components = 2,
            _ => unreachable!(),
        }
        assert!(
            RootfsStaging::from_checked_layers(parent.capability(), vec![lower, upper], cap)
                .is_err(),
            "{case}"
        );
        parent.assert_empty();
    }
}

#[tokio::test]
async fn exact_aggregate_limits_are_accepted() {
    let parent = Parent::new();
    let lower = checked(0, &[file("bin/app", b"abc")]).await;
    let upper = checked(1, &[file("bin/app", b"x")]).await;
    let cap = RootfsStagingLimits {
        layers: 2,
        total_tar_bytes: (lower.tar_byte_len() + upper.tar_byte_len()) as usize,
        applied_entries: 2,
        inodes: 3,
        write_bytes: 4,
        live_file_bytes: 3,
        path_bytes: 7,
        path_components: 2,
    };
    let staged =
        RootfsStaging::from_checked_layers(parent.capability(), vec![lower, upper], cap).unwrap();
    assert_eq!(staged.summary().live_file_bytes(), 1);
    staged.discard().unwrap();
    parent.assert_empty();
}

#[tokio::test]
async fn substituted_parent_symlink_is_not_followed_for_lookup_or_write() {
    let parent = Parent::new();
    let outside = Parent::new();
    fs::write(outside.0.join("sentinel"), b"unchanged").unwrap();
    let layer = checked(0, &[file("bin/app", b"payload")]).await;
    let mut staged =
        RootfsStaging::from_checked_layers(parent.capability(), vec![layer], limits()).unwrap();
    let root = parent.0.join(&staged.name);
    fs::rename(root.join("bin"), root.join("saved-bin")).unwrap();
    std::os::unix::fs::symlink(&outside.0, root.join("bin")).unwrap();
    assert!(open_directory(&staged.root, "bin").is_err());
    assert!(staged
        .apply_entry(
            crate::preparation::layer_content::TarEntry {
                path: "bin/other".into(),
                is_dir: false,
                mode: 0o755,
                uid: 0,
                gid: 0,
                mtime: 0,
                payload: b"must not escape",
            },
            limits(),
        )
        .is_err());
    assert!(!outside.0.join("other").exists());
    assert_eq!(fs::read(outside.0.join("sentinel")).unwrap(), b"unchanged");
    // Restore the private-tree invariant deliberately violated by this test
    // before exercising ordinary explicit teardown.
    fs::remove_file(root.join("bin")).unwrap();
    fs::rename(root.join("saved-bin"), root.join("bin")).unwrap();
    staged.discard().unwrap();
    parent.assert_empty();
}

#[test]
fn staging_parent_must_be_an_owner_only_directory() {
    let parent = Parent::new();
    let plain = parent.0.join("plain");
    fs::write(&plain, b"not a directory").unwrap();
    assert!(PrivateStagingParent::new(File::open(&plain).unwrap()).is_err());
    for mode in [0o755, 0o750, 0o711, 0o777] {
        fs::set_permissions(&parent.0, fs::Permissions::from_mode(mode)).unwrap();
        assert!(PrivateStagingParent::new(File::open(&parent.0).unwrap()).is_err());
    }
    fs::set_permissions(&parent.0, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(PrivateStagingParent::new(File::open(&parent.0).unwrap()).is_ok());
}

#[tokio::test]
async fn staging_revalidates_the_retained_parent_before_creating_output() {
    let parent = Parent::new();
    let capability = parent.capability();
    fs::set_permissions(&parent.0, fs::Permissions::from_mode(0o755)).unwrap();
    let layer = checked(0, &[file("app", b"payload")]).await;
    assert!(RootfsStaging::from_checked_layers(capability, vec![layer], limits()).is_err());
    parent.assert_empty();
}

#[test]
fn every_staging_budget_is_required_and_machine_size_overflow_is_rejected() {
    for field in 0..8 {
        for value in [0, usize::MAX] {
            let mut cap = limits();
            match field {
                0 => cap.layers = value,
                1 => cap.total_tar_bytes = value,
                2 => cap.applied_entries = value,
                3 => cap.inodes = value,
                4 => cap.write_bytes = value,
                5 => cap.live_file_bytes = value,
                6 => cap.path_bytes = value,
                7 => cap.path_components = value,
                _ => unreachable!(),
            }
            assert!(cap.validate().is_err(), "field {field}, value {value}");
        }
    }
}
