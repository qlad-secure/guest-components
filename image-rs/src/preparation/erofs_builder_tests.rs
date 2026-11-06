use super::*;
use crate::preparation::{
    layer_content::{
        check_layer_content, CheckedLayerContent, LayerContentExpectation, LayerContentLimits,
    },
    rootfs_staging::{PrivateStagingParent, RootfsStagingLimits},
};
use base64::{engine::general_purpose::STANDARD, Engine};
use nix::{
    errno::Errno,
    sys::stat::{fchmod, Mode},
    unistd::{dup, ftruncate},
};
use ocicrypt_rs::blockcipher::{
    EncryptionFinalizer, LayerBlockCipherHandler, LayerBlockCipherOptions, AES256CTR,
};
use sha2::Sha256;
use std::{
    fs::{self, DirBuilder},
    io::Read,
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::UNIX_EPOCH,
};

struct Parent(PathBuf);
impl Parent {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "onb17-erofs-builder-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
    fn capability(&self) -> PrivateStagingParent {
        PrivateStagingParent::new(File::open(&self.0).unwrap()).unwrap()
    }
    fn assert_no_staging(&self) {
        assert!(!fs::read_dir(&self.0).unwrap().any(|entry| entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with("onb17-staging-")));
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
    directory: bool,
    mode: u32,
    uid: u64,
    gid: u64,
    mtime: u64,
}
fn file<'a>(path: &'a str, payload: &'a [u8]) -> Entry<'a> {
    Entry {
        path,
        payload,
        directory: false,
        mode: 0o541,
        uid: 11,
        gid: 22,
        mtime: 33,
    }
}
fn directory(path: &str) -> Entry<'_> {
    Entry {
        path,
        payload: b"",
        directory: true,
        mode: 0o755,
        uid: 44,
        gid: 55,
        mtime: 66,
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
        header.set_entry_type(if entry.directory {
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
    let hash = |bytes: &[u8]| {
        Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    let mut options = LayerBlockCipherOptions::default();
    options.private.digest = format!("sha256:{}", hash(&tar));
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
            blob_sha256: &hash(&ciphertext),
            descriptor_size: ciphertext.len() as u64,
            diff_id: &format!("sha256:{}", hash(&tar)),
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
            file_bytes: 128 * 1024,
        },
    )
    .await
    .unwrap()
}
fn stage_limits() -> RootfsStagingLimits {
    RootfsStagingLimits {
        layers: 4,
        total_tar_bytes: 256 * 1024,
        applied_entries: 32,
        inodes: 32,
        write_bytes: 256 * 1024,
        live_file_bytes: 128 * 1024,
        path_bytes: 256,
        path_components: 8,
    }
}
fn build_limits() -> ErofsBuildLimits {
    ErofsBuildLimits {
        input: BuilderInputLimits {
            tar_bytes: 256 * 1024,
            inodes: 32,
            live_file_bytes: 128 * 1024,
        },
        output_bytes: 1024 * 1024,
        tool_bytes: 8 * 1024 * 1024,
        address_space_bytes: 256 * 1024 * 1024,
        cpu_seconds: 5,
        wall_time: Duration::from_secs(10),
    }
}
fn tool_path() -> PathBuf {
    PathBuf::from(
        std::env::var_os("ONB17_EROFS_MKFS")
            .expect("set ONB17_EROFS_MKFS to the pinned static erofs-utils artifact"),
    )
}
fn tool_hash(path: &Path) -> [u8; 48] {
    Sha384::digest(fs::read(path).unwrap()).into()
}
fn builder_with_limits(limits: ErofsBuildLimits) -> TrustedErofsBuilder {
    let path = tool_path();
    TrustedErofsBuilder::new(File::open(&path).unwrap(), tool_hash(&path), limits).unwrap()
}
async fn staging(parent: &Parent) -> RootfsStaging {
    let large = large_payload();
    let lower = checked(
        0,
        &[
            file("bin/app", b"old-long-content"),
            file("implicit/nested/data", b"payload"),
            file("large", &large),
        ],
    )
    .await;
    let mut replacement = file("bin/app", b"new");
    replacement.mode = 0o501;
    replacement.uid = 101;
    replacement.gid = 102;
    replacement.mtime = 103;
    let upper = checked(1, &[directory("bin"), replacement, file("empty", b"")]).await;
    RootfsStaging::from_checked_layers(parent.capability(), vec![lower, upper], stage_limits())
        .unwrap()
}
fn large_payload() -> Vec<u8> {
    (0..9001).map(|index| (index % 251) as u8).collect()
}
fn image_bytes(backing: &VerifiedErofsBacking) -> Vec<u8> {
    let mut bytes = vec![0; backing.summary().byte_len() as usize];
    File::from(dup(backing).unwrap())
        .read_exact_at(&mut bytes, 0)
        .unwrap();
    bytes
}

#[tokio::test]
async fn native_erofs_preserves_final_desired_metadata_and_has_strong_data_only_seals() {
    let parent = Parent::new();
    let staging = staging(&parent).await;
    let builder = builder_with_limits(build_limits());
    let input = staging
        .builder_input(build_limits().input, &|| false)
        .unwrap();
    let backing = builder.build(&staging, &|| false).unwrap();
    assert_eq!(backing.summary().inodes(), 8);
    assert_eq!(backing.summary().input_tar_sha384(), input.tar.sha384());
    assert_eq!(backing.summary().tool_sha384(), &tool_hash(&tool_path()));
    assert_eq!(backing.summary().profile(), EROFS_PROFILE);
    let bytes = image_bytes(&backing);
    assert_eq!(
        backing.summary().image_sha384(),
        &<[u8; 48]>::from(Sha384::digest(&bytes))
    );
    verify_erofs(&bytes, &input.nodes).unwrap();
    let seals = fcntl(&backing, FcntlArg::F_GET_SEALS).unwrap();
    assert_eq!(seals & SEALS.bits(), SEALS.bits());
    assert_ne!(seals & libc::F_SEAL_EXEC, 0);
    let alias = File::from(dup(&backing).unwrap());
    assert_eq!(alias.metadata().unwrap().permissions().mode() & 0o111, 0);
    assert_eq!(
        alias.write_at(b"x", 0).unwrap_err().raw_os_error(),
        Some(libc::EPERM)
    );
    assert_eq!(ftruncate(&alias, 0), Err(Errno::EPERM));
    assert_eq!(
        ftruncate(&alias, backing.summary().byte_len() as i64 + 1),
        Err(Errno::EPERM)
    );
    assert_eq!(
        fchmod(&alias, Mode::from_bits_truncate(0o700)),
        Err(Errno::EPERM)
    );
    // SAFETY: this is a negative shared-writer mapping test; MAP_FAILED is not dereferenced.
    let mapping = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            bytes.len(),
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            alias.as_raw_fd(),
            0,
        )
    };
    assert_eq!(mapping, libc::MAP_FAILED);
    assert_eq!(Errno::last(), Errno::EPERM);
    let adopted = SealedImageBytes::from_received_fd(
        dup(&backing).unwrap(),
        build_limits().output_bytes as u64,
        *backing.summary().image_sha384(),
    )
    .unwrap();
    assert_eq!(adopted.byte_len(), backing.summary().byte_len());
    let second = builder.build(&staging, &|| false).unwrap();
    assert_eq!(image_bytes(&second), bytes);
    staging.discard().unwrap();
    parent.assert_no_staging();
}

#[tokio::test]
async fn independent_native_fsck_decodes_and_extracts_actual_file_bytes_modes_and_times() {
    let parent = Parent::new();
    let staging = staging(&parent).await;
    let backing = builder_with_limits(build_limits())
        .build(&staging, &|| false)
        .unwrap();
    let tool = std::env::var_os("ONB17_EROFS_FSCK")
        .expect("set ONB17_EROFS_FSCK to the pinned native readback artifact");
    let output = parent.0.join("native-readback");
    DirBuilder::new().mode(0o700).create(&output).unwrap();
    let fd = backing.as_fd().as_raw_fd();
    let mut command = Command::new(tool);
    command
        .arg(format!("--extract={}", output.display()))
        .args(["--no-preserve-owner", "--preserve-perms"])
        .arg(format!("/proc/self/fd/{fd}"));
    // SAFETY: only fcntl runs after fork; the fd remains owned until child completion.
    unsafe {
        command.pre_exec(move || {
            if libc::fcntl(fd, libc::F_SETFD, 0) < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        });
    }
    let result = command.output().unwrap();
    assert!(result.status.success(), "native fsck rejected fixture");
    assert!(
        result.stderr.is_empty(),
        "native fsck diagnostics: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(fs::read(output.join("bin/app")).unwrap(), b"new");
    assert_eq!(
        fs::read(output.join("implicit/nested/data")).unwrap(),
        b"payload"
    );
    assert!(fs::read(output.join("empty")).unwrap().is_empty());
    assert_eq!(fs::read(output.join("large")).unwrap(), large_payload());
    let app = fs::metadata(output.join("bin/app")).unwrap();
    assert_eq!(app.permissions().mode() & 0o777, 0o501);
    assert_eq!(
        app.modified()
            .unwrap()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        103
    );
    let explicit = fs::metadata(output.join("bin")).unwrap();
    assert_eq!(explicit.permissions().mode() & 0o777, 0o755);
    assert_eq!(
        explicit
            .modified()
            .unwrap()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        66
    );
    let implicit = fs::metadata(output.join("implicit/nested")).unwrap();
    assert_eq!(implicit.permissions().mode() & 0o777, 0o755);
    assert_eq!(
        implicit
            .modified()
            .unwrap()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        0
    );
    staging.discard().unwrap();
    parent.assert_no_staging();
}

#[test]
fn trusted_tool_hash_static_profile_and_every_resource_bound_are_required() {
    let path = tool_path();
    let limits = build_limits();
    assert_eq!(
        TrustedErofsBuilder::new(File::open(&path).unwrap(), [0; 48], limits).err(),
        Some(ErofsBuildError::ToolRejected)
    );
    let dynamic = Path::new("/usr/bin/true");
    assert_eq!(
        TrustedErofsBuilder::new(File::open(dynamic).unwrap(), tool_hash(dynamic), limits).err(),
        Some(ErofsBuildError::ToolRejected)
    );
    for field in 0..8 {
        let mut cap = limits;
        match field {
            0 => cap.input.tar_bytes = 0,
            1 => cap.input.inodes = 0,
            2 => cap.input.live_file_bytes = 0,
            3 => cap.output_bytes = 4095,
            4 => cap.tool_bytes = 63,
            5 => cap.address_space_bytes = 0,
            6 => cap.cpu_seconds = 0,
            7 => cap.wall_time = Duration::ZERO,
            _ => unreachable!(),
        };
        assert_eq!(cap.validate(), Err(ErofsBuildError::InvalidConfiguration));
    }
    let mut cap = limits;
    cap.tool_bytes = 64;
    assert_eq!(
        TrustedErofsBuilder::new(File::open(&path).unwrap(), tool_hash(&path), cap).err(),
        Some(ErofsBuildError::ToolRejected)
    );
}

#[tokio::test]
async fn native_expansion_input_bounds_and_cancel_cannot_publish_partial_backing() {
    let parent = Parent::new();
    let staging = staging(&parent).await;
    assert!(
        builder_with_limits(build_limits())
            .build(&staging, &|| false)
            .unwrap()
            .summary()
            .byte_len()
            > 4096
    );
    let mut limits = build_limits();
    limits.output_bytes = 4096;
    assert!(builder_with_limits(limits)
        .build(&staging, &|| false)
        .is_err());
    limits = build_limits();
    limits.input.tar_bytes = 1024;
    assert_eq!(
        builder_with_limits(limits).build(&staging, &|| false).err(),
        Some(ErofsBuildError::InputRejected)
    );
    assert_eq!(
        builder_with_limits(build_limits())
            .build(&staging, &|| true)
            .err(),
        Some(ErofsBuildError::Cancelled)
    );
    let root = fs::read_dir(&parent.0)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| {
            path.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("onb17-staging-")
        })
        .unwrap();
    fs::write(root.join("bin/app"), b"bad").unwrap();
    assert_eq!(
        builder_with_limits(build_limits())
            .build(&staging, &|| false)
            .err(),
        Some(ErofsBuildError::InputRejected)
    );
    staging.discard().unwrap();
    parent.assert_no_staging();
}

fn fake_builder(
    parent: &Parent,
    body: &str,
    limits: ErofsBuildLimits,
) -> (TrustedErofsBuilder, PathBuf) {
    let pidfile = parent.0.join("child.pid");
    let unpublished_pid = parent.0.join("child.pid.pending");
    let source = parent.0.join("fake.c");
    let program = parent.0.join("fake-tool");
    // Publish the barrier only after its PID is complete. Cancellation may kill
    // the child as soon as the final pathname appears.
    let code = format!(
        concat!(
            "#include <stdio.h>\n#include <stdlib.h>\n#include <unistd.h>\n#include <fcntl.h>\n#include <signal.h>\n#include <sys/prctl.h>\n",
            "int main(int argc,char**argv){{FILE*p=fopen({:?},\"w\");if(!p)return 91;",
            "if(fprintf(p,\"%d\\n\",getpid())<0)return 92;if(fclose(p)!=0)return 93;",
            "if(rename({:?},{:?})!=0)return 94;{} }}\n"
        ),
        unpublished_pid.to_str().unwrap(),
        unpublished_pid.to_str().unwrap(),
        pidfile.to_str().unwrap(),
        body
    );
    fs::write(&source, code).unwrap();
    let built = Command::new("cc")
        .args(["-static", "-O2"])
        .arg(&source)
        .arg("-o")
        .arg(&program)
        .output()
        .unwrap();
    assert!(
        built.status.success(),
        "static child fixture compilation failed: {}",
        String::from_utf8_lossy(&built.stderr)
    );
    (
        TrustedErofsBuilder::new(File::open(&program).unwrap(), tool_hash(&program), limits)
            .unwrap(),
        pidfile,
    )
}
fn assert_reaped(pidfile: &Path) {
    let pid: i32 = fs::read_to_string(pidfile).unwrap().trim().parse().unwrap();
    let mut status = 0;
    // SAFETY: status is writable and waitpid is scoped to this fixture's direct child.
    assert_eq!(
        unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) },
        -1
    );
    assert_eq!(Errno::last(), Errno::ECHILD);
}

#[tokio::test]
async fn failed_and_partial_output_children_are_reaped_and_never_become_backing() {
    for (body,expected) in [("return 7;",ErofsBuildError::ChildFailed),("int fd=open(argv[argc-1],O_WRONLY);if(fd<0)return 90;if(write(fd,\"partial\",7)!=7)return 89;close(fd);return 0;",ErofsBuildError::ParityRejected)] {
        let parent=Parent::new();let staging=staging(&parent).await;let(builder,pidfile)=fake_builder(&parent,body,build_limits());
        assert_eq!(builder.build(&staging,&||false).err(),Some(expected));assert_reaped(&pidfile);staging.discard().unwrap();parent.assert_no_staging();
    }
}

#[cfg(feature = "launch-preparation-custody")]
#[tokio::test]
async fn custody_builder_installs_parent_death_sigkill_before_exec() {
    let parent = Parent::new();
    let staging = staging(&parent).await;
    let body = "int sig=0;if(prctl(PR_GET_PDEATHSIG,&sig)!=0||sig!=SIGKILL)return 97;int fd=open(argv[argc-1],O_WRONLY);if(fd<0)return 90;if(write(fd,\"partial\",7)!=7)return 89;close(fd);return 0;";
    let (builder, pidfile) = fake_builder(&parent, body, build_limits());
    assert_eq!(
        builder.build(&staging, &|| false).err(),
        Some(ErofsBuildError::ParityRejected)
    );
    assert_reaped(&pidfile);
    staging.discard().unwrap();
    parent.assert_no_staging();
}

#[tokio::test]
async fn hung_children_are_killed_and_reaped_on_deadline_and_inflight_cancellation() {
    for use_deadline in [false, true] {
        let parent = Parent::new();
        let staging = staging(&parent).await;
        let mut limits = build_limits();
        if use_deadline {
            limits.wall_time = Duration::from_secs(1);
        }
        let (builder, pidfile) = fake_builder(&parent, "for(;;)pause();", limits);
        let start = Instant::now();
        assert_eq!(
            builder
                .build(&staging, &|| !use_deadline && pidfile.exists())
                .err(),
            Some(ErofsBuildError::Cancelled)
        );
        assert!(start.elapsed() < Duration::from_secs(4));
        assert_reaped(&pidfile);
        staging.discard().unwrap();
        parent.assert_no_staging();
    }
}
