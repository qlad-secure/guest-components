// SPDX-License-Identifier: Apache-2.0

//! Explicit privileged acceptance gate. Build first, then run in an isolated
//! private mount namespace. Missing capabilities or an unregistered EROFS driver
//! return BLOCKED/77; the program never loads modules or executes the workload.

use base64::{engine::general_purpose::STANDARD, Engine};
use ocicrypt_rs::blockcipher::{
    EncryptionFinalizer, LayerBlockCipherHandler, LayerBlockCipherOptions, AES256CTR,
};
use onb17_sealed_image_source_checks::preparation::{
    erofs_builder::{ErofsBuildLimits, TrustedErofsBuilder},
    erofs_mount::{ErofsMountError, ErofsMountLimits, MountedViewLimits},
    launch_spec::{BoundEffectiveSpec, EffectiveSpecLimits, EffectiveSpecPolicy},
    layer_content::{
        check_layer_content, CheckedLayerContent, LayerContentExpectation, LayerContentLimits,
    },
    rootfs_staging::{
        BuilderInputLimits, PrivateStagingParent, RootfsStaging, RootfsStagingLimits,
    },
    static_elf::StaticElfLimits,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256, Sha384};
use std::{
    fs::{self, DirBuilder, File},
    io::Read,
    os::unix::fs::DirBuilderExt,
    path::{Path, PathBuf},
    process::ExitCode,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};
use zeroize::Zeroizing;

type Check<T> = Result<T, String>;

fn main() -> ExitCode {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() > 1 || args.first().is_some_and(|arg| arg != "--preflight") {
        eprintln!("usage: native-erofs-mount [--preflight]");
        return ExitCode::from(2);
    }
    if let Err(reason) = preflight() {
        eprintln!(
            "{}",
            json!({"status":"BLOCKED","reason":reason,"mounted":false})
        );
        return ExitCode::from(77);
    }
    if !args.is_empty() {
        println!("{}", json!({"status":"READY","mounted":false}));
        return ExitCode::SUCCESS;
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
    let status = bounded_read(Path::new("/proc/self/status"), 64 * 1024)?;
    let status = std::str::from_utf8(&status).map_err(|_| "invalid process status")?;
    let cap = status
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:").map(str::trim))
        .and_then(|value| u64::from_str_radix(value, 16).ok())
        .ok_or("effective capabilities unavailable")?;
    if cap & (1 << 21) == 0 {
        return Err("CAP_SYS_ADMIN is required; no privileged mount was attempted".into());
    }
    let own = fs::read_link("/proc/self/ns/user").map_err(|_| "user namespace unavailable")?;
    let initial =
        fs::read_link("/proc/1/ns/user").map_err(|_| "PID1 user namespace unavailable")?;
    if own != initial {
        return Err("run in the host/PID1 user namespace; userns-root cannot mount EROFS".into());
    }
    let filesystems = bounded_read(Path::new("/proc/filesystems"), 1024 * 1024)?;
    let filesystems = std::str::from_utf8(&filesystems).map_err(|_| "invalid filesystem list")?;
    for required in ["erofs", "ramfs"] {
        if !filesystems
            .lines()
            .any(|line| line.split_whitespace().last() == Some(required))
        {
            return Err(format!(
                "{required} is not registered; module loading is outside this runner"
            ));
        }
    }
    Ok(())
}

fn acceptance() -> Check<Value> {
    let tool = configured_builder()?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .map_err(|_| "fixture runtime creation failed")?;
    let before = bounded_read(Path::new("/proc/self/mountinfo"), 2 * 1024 * 1024)?;
    let fd_before = descriptor_count()?;
    let (parent, staging) = runtime.block_on(fixture_staging(0o555, false))?;
    let backing = tool
        .build(&staging, &|| false)
        .map_err(|error| format!("build: {error}"))?;
    let backing_summary = backing.summary().clone();
    ensure(
        backing_summary.inodes() == 9,
        "unexpected fixture inode count",
    )?;
    let spec = bound_spec("/work")?;
    let view = backing
        .mount_checked(&spec, elf_limits(), mount_limits(), &|| false)
        .map_err(|error| format!("positive mount/view: {error:?}"))?;
    let summary = view.summary();
    ensure(
        summary.backing_adapter() == "private-ro-ramfs-v1",
        "backing adapter identity differs",
    )?;
    let backing_adapter = summary.backing_adapter();
    ensure(
        summary.backing() == &backing_summary,
        "backing summary changed",
    )?;
    ensure(summary.executable().mount_id() != 0, "mount ID is missing")?;
    ensure(
        summary.executable().inodes() == 9,
        "mounted inode count differs",
    )?;
    ensure(
        summary.executable().spec_sha384() == spec.sha384(),
        "candidate digest differs",
    )?;
    ensure(
        summary.executable().executable() == "/bin/app",
        "entry path differs",
    )?;
    ensure(
        summary.executable().executable_sha384() == hex(&Sha384::digest(elf())),
        "entry bytes differ",
    )?;
    ensure(
        summary.executable().elf().file_bytes() == elf().len(),
        "ELF snapshot differs",
    )?;
    let mount_id = summary.executable().mount_id();
    let image_sha384 = hex(summary.backing().image_sha384());
    drop(view);
    staging
        .discard()
        .map_err(|error| format!("staging cleanup: {error}"))?;
    parent.empty()?;
    drop(parent);
    ensure(
        descriptor_count()? == fd_before,
        "positive owner leaked a descriptor",
    )?;
    ensure(
        bounded_read(Path::new("/proc/self/mountinfo"), 2 * 1024 * 1024)? == before,
        "detached mount changed namespace mountinfo",
    )?;

    // Every negative begins with the same actual encrypted-content/staging/build
    // path. Failure must return no view and release every owned mount reference.
    for (name, mode, invalid_elf, cwd) in [
        ("non-executable permissions", 0o644, false, "/work"),
        ("writable executable", 0o755, false, "/work"),
        ("invalid static ELF", 0o555, true, "/work"),
        ("missing cwd", 0o555, false, "/missing"),
    ] {
        let (parent, staging) = runtime.block_on(fixture_staging(mode, invalid_elf))?;
        let backing = tool
            .build(&staging, &|| false)
            .map_err(|error| format!("negative build: {error}"))?;
        let spec = bound_spec(cwd)?;
        match backing.mount_checked(&spec, elf_limits(), mount_limits(), &|| false) {
            Err(ErofsMountError::ViewRejected(_)) => {}
            Err(error) => return Err(format!("{name}: unexpected rejection {error:?}")),
            Ok(_) => return Err(format!("{name}: invalid view was accepted")),
        }
        staging
            .discard()
            .map_err(|error| format!("negative cleanup: {error}"))?;
        parent.empty()?;
        drop(parent);
        ensure(
            descriptor_count()? == fd_before,
            "negative view leaked a descriptor",
        )?;
        ensure(
            bounded_read(Path::new("/proc/self/mountinfo"), 2 * 1024 * 1024)? == before,
            "negative changed namespace mountinfo",
        )?;
    }
    let (parent, staging) = runtime.block_on(fixture_staging(0o555, false))?;
    let backing = tool
        .build(&staging, &|| false)
        .map_err(|error| format!("cancel build: {error}"))?;
    match backing.mount_checked(&bound_spec("/work")?, elf_limits(), mount_limits(), &|| {
        true
    }) {
        Err(ErofsMountError::Cancelled) => {}
        Err(error) => return Err(format!("cancel returned unexpected error {error:?}")),
        Ok(_) => return Err("cancelled view was accepted".into()),
    }
    staging
        .discard()
        .map_err(|error| format!("cancel cleanup: {error}"))?;
    parent.empty()?;
    drop(parent);
    ensure(
        descriptor_count()? == fd_before,
        "cancel leaked a descriptor",
    )?;
    ensure(
        bounded_read(Path::new("/proc/self/mountinfo"), 2 * 1024 * 1024)? == before,
        "cancel changed namespace mountinfo",
    )?;
    Ok(json!({
        "status":"PASS", "positive_views":1,"negative_views":5,"backing_adapter":backing_adapter,
        "mount_id":mount_id,"image_sha384":image_sha384,
        "mountinfo_sha384":hex(&Sha384::digest(&before)),
        "namespace_mountinfo_unchanged":true,"descriptors_before":fd_before,
        "descriptors_after":descriptor_count()?,"target_executed":false,
        "scope":"actual typed checked-content/staging/build to detached read-only EROFS and mounted spec/ELF checks; no final lease or start permission"
    }))
}

fn configured_builder() -> Check<TrustedErofsBuilder> {
    let path =
        PathBuf::from(std::env::var_os("ONB17_EROFS_MKFS").ok_or("set pinned native tool path")?);
    let expected = std::env::var("ONB17_EROFS_MKFS_SHA384")
        .map_err(|_| "set independently pinned native tool SHA384")?;
    if expected.len() != 96 || !expected.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("invalid pinned tool SHA384".into());
    }
    let mut digest = [0; 48];
    for (index, byte) in digest.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&expected[index * 2..index * 2 + 2], 16)
            .map_err(|_| "invalid tool digest")?;
    }
    let tool = File::open(path).map_err(|_| "cannot open pinned native tool")?;
    TrustedErofsBuilder::new(
        tool,
        digest,
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
        },
    )
    .map_err(|error| format!("tool configuration: {error}"))
}
fn mount_limits() -> ErofsMountLimits {
    ErofsMountLimits {
        view: MountedViewLimits {
            inodes: 32,
            live_file_bytes: 128 * 1024,
            path_bytes: 256,
            path_components: 8,
            directory_entry_bytes: 32 * 1024,
        },
        backing_bytes: 1024 * 1024,
        ramfs_data_bytes: 1024 * 1024,
        wall_time: Duration::from_secs(10),
    }
}
fn elf_limits() -> StaticElfLimits {
    StaticElfLimits {
        file_bytes: 4096,
        program_headers: 16,
        mapped_bytes: 65536,
        virtual_span_bytes: 65536,
    }
}
fn bound_spec(cwd: &str) -> Check<BoundEffectiveSpec> {
    let raw=serde_json::to_vec(&json!({
        "ociVersion":"1.2.1","root":{"path":"rootfs","readonly":true},
        "process":{"terminal":false,"user":{"uid":1000,"gid":1000,"additionalGids":[]},
            "args":["/bin/app"],"env":["HOME=/"],"cwd":cwd,"noNewPrivileges":true,
            "capabilities":{"bounding":[],"effective":[],"inheritable":[],"permitted":[],"ambient":[]}},
        "mounts":[],"linux":{"namespaces":[{"type":"mount"},{"type":"pid"},{"type":"ipc"},{"type":"uts"},{"type":"network"}],
            "seccomp":{"defaultAction":"SCMP_ACT_ERRNO","defaultErrnoRet":1,"architectures":["SCMP_ARCH_X86_64"],
                "syscalls":[{"names":["execveat","exit_group","write"],"action":"SCMP_ACT_ALLOW"}]}}
    })).map_err(|_| "candidate serialization failed")?;
    BoundEffectiveSpec::parse(
        &raw,
        &hex(&Sha384::digest(&raw)),
        &EffectiveSpecPolicy {
            uid: 1000,
            gid: 1000,
            seccomp_syscalls: vec!["execveat".into(), "exit_group".into(), "write".into()],
        },
        EffectiveSpecLimits {
            spec_bytes: 16384,
            args: 16,
            env: 16,
            string_bytes: 1024,
            total_string_bytes: 4096,
            path_bytes: 256,
            path_components: 16,
            syscalls: 32,
            json_depth: 16,
        },
    )
    .map_err(|error| format!("candidate rejected: {error}"))
}
fn elf() -> Vec<u8> {
    let mut bytes = vec![0; 512];
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
    bytes[168..176].copy_from_slice(&16u64.to_le_bytes());
    bytes[256] = 0xc3;
    bytes
}

struct Parent(PathBuf);
impl Parent {
    fn new() -> Check<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "erofs-native-view-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .map_err(|_| "private fixture directory creation failed")?;
        Ok(Self(path))
    }
    fn capability(&self) -> Check<PrivateStagingParent> {
        PrivateStagingParent::new(File::open(&self.0).map_err(|_| "fixture directory open failed")?)
            .map_err(|error| format!("private parent rejected: {error}"))
    }
    fn empty(&self) -> Check<()> {
        ensure(
            fs::read_dir(&self.0)
                .map_err(|_| "fixture directory unavailable")?
                .next()
                .is_none(),
            "fixture staging/scratch remains",
        )
    }
}
impl Drop for Parent {
    fn drop(&mut self) {
        let _ = fs::remove_dir(&self.0);
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
        mode: 0o444,
        uid: 70000,
        gid: 80000,
        mtime: 123456789,
    }
}
fn directory(path: &str) -> Entry<'_> {
    Entry {
        path,
        payload: b"",
        directory: true,
        mode: 0o555,
        uid: 70000,
        gid: 80000,
        mtime: 123,
    }
}
async fn fixture_staging(mode: u32, invalid_elf: bool) -> Check<(Parent, RootfsStaging)> {
    let parent = Parent::new()?;
    let large: Vec<_> = (0..9001).map(|index| (index % 251) as u8).collect();
    let lower = checked(
        0,
        &[
            file("bin/app", b"overwritten"),
            file("implicit/nested/data", b"synthetic fixture"),
            file("large", &large),
            file("empty", b""),
        ],
    )
    .await?;
    let payload = if invalid_elf {
        b"invalid ELF".to_vec()
    } else {
        elf()
    };
    let mut app = file("bin/app", &payload);
    app.mode = mode;
    app.uid = 1000;
    app.gid = 1000;
    app.mtime = 456;
    let upper = checked(1, &[directory("bin"), directory("work"), app]).await?;
    let rootfs = RootfsStaging::from_checked_layers(
        parent.capability()?,
        vec![lower, upper],
        RootfsStagingLimits {
            layers: 4,
            total_tar_bytes: 256 * 1024,
            applied_entries: 32,
            inodes: 32,
            write_bytes: 256 * 1024,
            live_file_bytes: 128 * 1024,
            path_bytes: 256,
            path_components: 8,
        },
    )
    .map_err(|error| format!("staging rejected: {error}"))?;
    Ok((parent, rootfs))
}
async fn checked(index: u32, entries: &[Entry<'_>]) -> Check<CheckedLayerContent> {
    let mut tar = Vec::new();
    for entry in entries {
        let mut header = tokio_tar::Header::new_ustar();
        header
            .set_path(entry.path)
            .map_err(|_| "fixture path rejected")?;
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
    let hash = |bytes: &[u8]| hex(&Sha256::digest(bytes));
    let mut options = LayerBlockCipherOptions::default();
    options.private.digest = format!("sha256:{}", hash(&tar));
    let mut cipher = LayerBlockCipherHandler::default();
    cipher
        .encrypt(tar.as_slice(), AES256CTR, &mut options)
        .map_err(|_| "fixture encryption failed")?;
    let mut ciphertext = Vec::new();
    Read::read_to_end(&mut cipher, &mut ciphertext)
        .map_err(|_| "fixture encryption read failed")?;
    cipher
        .finalized_lbco(&mut options)
        .map_err(|_| "fixture encryption finalization failed")?;
    let private =
        serde_json::to_vec(&options.private).map_err(|_| "fixture private options failed")?;
    let private_len = private.len();
    let public =
        serde_json::to_vec(&options.public).map_err(|_| "fixture public options failed")?;
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
    .map_err(|error| format!("fixture layer rejected: {error}"))
}
fn bounded_read(path: &Path, max: usize) -> Check<Vec<u8>> {
    let file = File::open(path).map_err(|_| "required procfs file unavailable")?;
    let mut bytes = Vec::new();
    file.take(max as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "required procfs read failed")?;
    ensure(bytes.len() <= max, "procfs read exceeds fixture bound")?;
    Ok(bytes)
}
fn descriptor_count() -> Check<usize> {
    Ok(fs::read_dir("/proc/self/fd")
        .map_err(|_| "descriptor inventory unavailable")?
        .count())
}
fn ensure(condition: bool, message: &str) -> Check<()> {
    if condition {
        Ok(())
    } else {
        Err(message.into())
    }
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
