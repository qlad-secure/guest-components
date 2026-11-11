// SPDX-License-Identifier: Apache-2.0

//! Native test role for actual Kata receiver custody. Sealed fixture config and
//! argv provision this test only; neither is a production configuration source.

use anyhow::{Context, Result, bail, ensure};
use execution_proof_handoff::startup::{ExpectedStartup, Role, StartupBoundChannel};
use image_rs::preparation::{
    SealedImageBytes,
    erofs_mount::{ErofsMountLimits, MountedViewLimits},
    received_view::{ReceivedViewError, ReceivedViewLimits},
    static_elf::StaticElfLimits,
};
use onb17_launch_credential_checks::{
    custody_fixture_config::{FIXTURE_CONFIG_BYTES, FixtureMode, FixtureReceiverWire},
    kata_custody::{
        PreparedRootfsLease, ReceiverError, ReceiverFactory, ReceiverLimits, ReceiverOwner,
        ReceiverProgress, ReceiverStatus,
    },
};
use serde_json::json;
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    os::{fd::AsFd, unix::fs::FileExt},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

const WORK_TIME: Duration = Duration::from_secs(10);
const IMAGE_BYTES: usize = 1 << 20;

struct Arguments {
    config_fd: u32,
    config_sha384: [u8; 48],
    preparation_sha384: [u8; 48],
    kata_sha384: [u8; 48],
}

fn main() {
    let mut control = None;
    if let Err(error) = run(&mut control) {
        if let Some(directory) = control {
            let _ = write_json(
                &directory,
                "result.json",
                &json!({"status": "FAIL", "error": format!("{error:#}")}),
            );
        }
        eprintln!("native Kata custody fixture failed: {error:#}");
        std::process::exit(1);
    }
}

fn run(control: &mut Option<PathBuf>) -> Result<()> {
    let deadline = Instant::now() + WORK_TIME;
    let arguments = arguments()?;
    let fixture = read_configuration(&arguments)?;
    *control = Some(fixture.control_directory.clone());
    ensure!(
        fixture.mode != FixtureMode::NativePositive
            || cfg!(feature = "launch-preparation-mount-native"),
        "native positive custody requires launch-preparation-mount-native"
    );
    let mountinfo = fs::read("/proc/self/mountinfo").context("initial mountinfo")?;
    let spec = fixture.spec().context("fixture spec")?;
    let expected_spec = spec.sha384().to_owned();
    // SAFETY: this dedicated role entrypoint exclusively owns the inherited
    // startup descriptors. No preceding operation takes, closes or aliases them.
    let channel = unsafe {
        StartupBoundChannel::accept_inherited(
            ExpectedStartup {
                role: Role::Kata,
                boot_config_sha384: arguments.config_sha384,
                own_executable_sha384: arguments.kata_sha384,
                peer_executable_sha384: arguments.preparation_sha384,
            },
            remaining(deadline)?,
        )
    }
    .context("Kata role startup")?;
    let factory = ReceiverFactory::new(1).context("receiver factory")?;
    let mut owner = factory
        .begin(channel, fixture.admission(), spec, limits(fixture.mode))
        .context("receiver begin")?;
    match fixture.mode {
        FixtureMode::NativeFinalTask => {
            bail!("final-task mode requires the dedicated Kata final-task fixture")
        }
        FixtureMode::RejectBeforeMount => {
            run_rejection(&mut owner, &factory, deadline)?;
            drop(owner);
            let descriptors_after = descriptor_count()?;
            ensure!(descriptors_after == 4, "rejection descriptor cleanup");
            ensure!(
                fs::read("/proc/self/mountinfo").context("final mountinfo")? == mountinfo,
                "rejection changed mountinfo"
            );
            write_json(
                &fixture.control_directory,
                "result.json",
                &json!({
                    "status": "EXPECTED_REJECT",
                    "lease_published": false,
                    "active_after": factory.active(),
                    "mountinfo_unchanged": true,
                    "descriptors_after": descriptors_after,
                    "target_executed": false,
                }),
            )
        }
        FixtureMode::NativePositive => {
            let lease = run_positive(&mut owner, &fixture.control_directory, deadline)?;
            drop(owner);
            let active_after_owner_drop = factory.active();
            ensure!(active_after_owner_drop == 1, "taken lease lost its permit");
            write_marker(&fixture.control_directory, "owner-dropped")?;
            wait_marker(&fixture.control_directory, "producer-closed", deadline)?;
            verify_lease(&lease, &expected_spec)?;
            let record = lease.record().clone();
            let mount_id = lease.view_summary().mount_id();
            drop(lease);
            let active_after_lease_drop = factory.active();
            ensure!(
                active_after_lease_drop == 0,
                "lease permit was not returned"
            );
            let descriptors_after = descriptor_count()?;
            ensure!(descriptors_after == 4, "positive descriptor cleanup");
            ensure!(
                fs::read("/proc/self/mountinfo").context("final mountinfo")? == mountinfo,
                "positive changed mountinfo"
            );
            write_json(
                &fixture.control_directory,
                "result.json",
                &json!({
                    "status": "PASS",
                    "record": record,
                    "mount_id": mount_id,
                    "active_after_owner_drop": active_after_owner_drop,
                    "active_after_lease_drop": active_after_lease_drop,
                    "take_twice_rejected": true,
                    "finalizing_not_ready": true,
                    "mountinfo_unchanged": true,
                    "descriptors_after": descriptors_after,
                    "target_executed": false,
                }),
            )
        }
    }
}

fn run_rejection(
    owner: &mut ReceiverOwner,
    factory: &ReceiverFactory,
    deadline: Instant,
) -> Result<()> {
    loop {
        remaining(deadline)?;
        match owner.advance(&|| Instant::now() >= deadline) {
            Ok(ReceiverProgress::Pending) => poll_pause(),
            Ok(_) => {}
            Err(ReceiverError::View(ReceivedViewError::TooLarge)) => {
                ensure!(
                    matches!(owner.take_lease(), Err(ReceiverError::Unavailable)),
                    "rejected owner exposed a lease"
                );
                ensure!(factory.active() == 0, "rejected owner retained capacity");
                return Ok(());
            }
            Err(error) => bail!("unexpected receiver rejection: {error}"),
        }
    }
}

fn run_positive(
    owner: &mut ReceiverOwner,
    directory: &Path,
    deadline: Instant,
) -> Result<PreparedRootfsLease> {
    let mut view_ready = false;
    let mut finalizing_checked = false;
    let mut acknowledgements = 0;
    let mut lease = None;
    loop {
        remaining(deadline)?;
        if acknowledgements >= 2 && marker_exists(directory, "finish")? {
            return lease.context("finalized lease missing");
        }
        let before = owner.status();
        let progress = owner
            .advance(&|| Instant::now() >= deadline)
            .context("receiver advance")?;
        let after = owner.status();
        if !view_ready
            && before == ReceiverStatus::AwaitingCommit
            && after == ReceiverStatus::AwaitingCommit
            && progress == ReceiverProgress::Advanced
        {
            // SendValidated changes no public status; Advanced proves send Sent.
            view_ready = true;
            write_marker(directory, "view-ready")?;
            wait_marker(directory, "allow-retry", deadline)?;
        }
        if !finalizing_checked && after == ReceiverStatus::Finalizing {
            ensure!(view_ready, "commit preceded validated view");
            ensure!(
                matches!(owner.take_lease(), Err(ReceiverError::NotReady)),
                "lease was available before first final ACK"
            );
            finalizing_checked = true;
            write_marker(directory, "finalizing")?;
            wait_marker(directory, "allow-ack", deadline)?;
        }
        if progress == ReceiverProgress::Finalized {
            acknowledgements += 1;
            if acknowledgements == 1 {
                ensure!(finalizing_checked, "finalizing barrier was not checked");
                lease = Some(owner.take_lease().context("first lease take")?);
                ensure!(
                    matches!(owner.take_lease(), Err(ReceiverError::AlreadyTaken)),
                    "second lease take succeeded"
                );
                write_marker(directory, "ack-sent")?;
            } else if acknowledgements == 2 {
                ensure!(
                    matches!(owner.take_lease(), Err(ReceiverError::AlreadyTaken)),
                    "historical ACK recreated a lease"
                );
                write_marker(directory, "ack-replayed")?;
            }
        }
        if progress == ReceiverProgress::Pending {
            poll_pause();
        }
    }
}

fn verify_lease(lease: &PreparedRootfsLease, expected_spec: &str) -> Result<()> {
    let record = lease.record();
    let provenance = lease.provenance();
    let view = lease.view_summary();
    ensure!(
        record.context_sha384 == lease.admission_context_digest(),
        "P/admission context"
    );
    ensure!(
        provenance.context_sha384 == record.context_sha384,
        "P/provenance context"
    );
    ensure!(
        record.candidate_spec_sha384 == expected_spec,
        "P/trusted spec"
    );
    ensure!(
        lease.candidate_spec().sha384() == expected_spec,
        "lease/trusted spec"
    );
    ensure!(
        provenance.candidate_spec_sha384 == expected_spec,
        "provenance/trusted spec"
    );
    ensure!(
        record.image_sha384 == hex(view.image_sha384()),
        "P/actual image"
    );
    ensure!(
        record.image_sha384 == provenance.builder.image_sha384,
        "P/builder image"
    );
    ensure!(
        view.byte_len() == provenance.builder.image_bytes,
        "actual/builder image bytes"
    );
    ensure!(record.mount_id == view.mount_id(), "P/actual mount ID");
    ensure!(
        record.inodes == view.executable().inodes() as u64,
        "P/actual inode count"
    );
    ensure!(
        record.inodes == provenance.builder.inodes,
        "P/builder inode count"
    );
    ensure!(
        record.executable_sha384 == view.executable().executable_sha384(),
        "P/actual executable"
    );
    ensure!(
        record.candidate_spec_sha384 == view.executable().spec_sha384(),
        "P/actual spec"
    );
    ensure!(
        record.provenance_sha384 == hex(&provenance.sha384(FIXTURE_CONFIG_BYTES)?),
        "P/provenance bytes"
    );
    Ok(())
}

fn limits(mode: FixtureMode) -> ReceiverLimits {
    ReceiverLimits {
        admission_bytes: FIXTURE_CONFIG_BYTES,
        provenance_bytes: FIXTURE_CONFIG_BYTES,
        view: ReceivedViewLimits {
            mount: ErofsMountLimits {
                view: MountedViewLimits {
                    inodes: if mode == FixtureMode::RejectBeforeMount {
                        1
                    } else {
                        32
                    },
                    live_file_bytes: IMAGE_BYTES,
                    path_bytes: 256,
                    path_components: 16,
                    directory_entry_bytes: 16384,
                },
                backing_bytes: IMAGE_BYTES,
                ramfs_data_bytes: IMAGE_BYTES,
                wall_time: WORK_TIME,
            },
            inventory_path_bytes: 16384,
        },
        elf: StaticElfLimits {
            file_bytes: 4096,
            program_headers: 16,
            mapped_bytes: 65536,
            virtual_span_bytes: 65536,
        },
        wall_time: WORK_TIME,
    }
}

fn read_configuration(arguments: &Arguments) -> Result<FixtureReceiverWire> {
    unsafe extern "C" {
        fn getppid() -> std::ffi::c_int;
    }
    // SAFETY: getppid takes no pointers and returns the current parent process ID.
    let parent = unsafe { getppid() };
    ensure!(parent > 1, "fixture launcher missing");
    let file = File::open(format!("/proc/{parent}/fd/{}", arguments.config_fd))
        .context("fixture config descriptor")?;
    let sealed = SealedImageBytes::from_received_fd(
        file.into(),
        FIXTURE_CONFIG_BYTES as u64,
        arguments.config_sha384,
    )
    .context("sealed fixture config")?;
    let mut bytes = vec![0; sealed.byte_len() as usize];
    let alias = File::from(
        sealed
            .as_fd()
            .try_clone_to_owned()
            .context("fixture config alias")?,
    );
    alias
        .read_exact_at(&mut bytes, 0)
        .context("fixture config read")?;
    FixtureReceiverWire::decode(&bytes).map_err(anyhow::Error::msg)
}

fn arguments() -> Result<Arguments> {
    let arguments: Vec<_> = std::env::args().skip(1).collect();
    ensure!(arguments.len() == 8, "expected four fixture argument pairs");
    let mut config_fd = None;
    let mut config_sha384 = None;
    let mut preparation_sha384 = None;
    let mut kata_sha384 = None;
    for pair in arguments.as_chunks::<2>().0 {
        match pair[0].as_str() {
            "--fixture-config-fd" if config_fd.is_none() => {
                config_fd = Some(pair[1].parse::<u32>().context("fixture config FD number")?);
            }
            "--fixture-config-sha384" if config_sha384.is_none() => {
                config_sha384 = Some(decode(&pair[1])?)
            }
            "--preparation-sha384" if preparation_sha384.is_none() => {
                preparation_sha384 = Some(decode(&pair[1])?)
            }
            "--kata-sha384" if kata_sha384.is_none() => kata_sha384 = Some(decode(&pair[1])?),
            _ => bail!("unknown or duplicate fixture argument"),
        }
    }
    Ok(Arguments {
        config_fd: config_fd.context("fixture config FD missing")?,
        config_sha384: config_sha384.context("fixture config hash missing")?,
        preparation_sha384: preparation_sha384.context("preparation hash missing")?,
        kata_sha384: kata_sha384.context("Kata hash missing")?,
    })
}

fn decode(value: &str) -> Result<[u8; 48]> {
    ensure!(
        value.len() == 96
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "fixture SHA384 must be canonical lowercase hexadecimal"
    );
    let mut digest = [0; 48];
    for (index, pair) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let nibble = |b| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
        digest[index] = nibble(pair[0]) * 16 + nibble(pair[1]);
    }
    Ok(digest)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn descriptor_count() -> Result<usize> {
    // The directory iterator itself owns the fourth FD while it is counted.
    fs::read_dir("/proc/self/fd")
        .context("descriptor inventory")?
        .try_fold(0, |count, entry| entry.map(|_| count + 1))
        .context("descriptor inventory entry")
}

fn remaining(deadline: Instant) -> Result<Duration> {
    let duration = deadline.saturating_duration_since(Instant::now());
    ensure!(!duration.is_zero(), "native custody fixture deadline");
    Ok(duration)
}

fn marker_exists(directory: &Path, name: &str) -> Result<bool> {
    directory
        .join(name)
        .try_exists()
        .context("barrier readiness")
}

fn wait_marker(directory: &Path, name: &str, deadline: Instant) -> Result<()> {
    loop {
        remaining(deadline)?;
        if marker_exists(directory, name)? {
            return Ok(());
        }
        poll_pause();
    }
}

fn poll_pause() {
    // Throttle readiness polling; barrier files, rather than elapsed time,
    // determine when either protocol participant may make the next transition.
    std::thread::sleep(Duration::from_millis(1));
}

fn write_marker(directory: &Path, name: &str) -> Result<()> {
    write_atomic(directory, name, b"ready\n")
}

fn write_json(directory: &Path, name: &str, value: &serde_json::Value) -> Result<()> {
    let mut bytes = serde_json::to_vec(value).context("public result encoding")?;
    bytes.push(b'\n');
    write_atomic(directory, name, &bytes)
}

fn write_atomic(directory: &Path, name: &str, bytes: &[u8]) -> Result<()> {
    let temporary = directory.join(format!(".{name}.tmp"));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .context("public marker creation")?;
    file.write_all(bytes).context("public marker write")?;
    file.sync_all().context("public marker sync")?;
    drop(file);
    fs::rename(temporary, directory.join(name)).context("public marker publication")
}
