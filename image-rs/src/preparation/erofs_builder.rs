// SPDX-License-Identifier: Apache-2.0

//! Pinned native EROFS construction from owned, verified staging input.
//!
//! The synchronous caller owns scheduling. The preparation runtime bounds active
//! workers; this module never starts a background worker. A child is killed and
//! reaped before any error returns. The trusted process and guest kernel must
//! exclude hostile same-UID/root management; seals alone do not provide that
//! isolation. This result is neither a mount nor permission to start a task.

use super::{
    erofs_reader::verify_erofs,
    rootfs_staging::{BuilderInputLimits, RootfsStaging},
    SealedImageBytes,
};
use nix::{
    fcntl::{fcntl, FcntlArg, SealFlag},
    libc,
    sys::memfd::{memfd_create, MFdFlags},
};
use sha2::{Digest, Sha384};
use std::{
    fs::File,
    io,
    os::{
        fd::{AsFd, AsRawFd, BorrowedFd},
        unix::{fs::FileExt, process::CommandExt},
    },
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

pub const EROFS_PROFILE: &str = "erofs-utils-1.8.10/4096/extended/plain/single-device/v1";
const SEALS: SealFlag = SealFlag::F_SEAL_WRITE
    .union(SealFlag::F_SEAL_GROW)
    .union(SealFlag::F_SEAL_SHRINK)
    .union(SealFlag::F_SEAL_SEAL);
const OPTIONS: &[&str] = &[
    "--tar=f",
    "--sort=none",
    "-b4096",
    "-Eforce-inode-extended,^inline_data,^xattr-name-filter",
    "-x-1",
    "-T0",
    "--mkfs-time",
    "--preserve-mtime",
    "-U00000000-0000-0000-0000-000000000000",
    "--quiet",
];

#[derive(Clone, Copy)]
pub struct ErofsBuildLimits {
    pub input: BuilderInputLimits,
    pub output_bytes: usize,
    pub tool_bytes: usize,
    pub address_space_bytes: u64,
    pub cpu_seconds: u64,
    /// Includes export/build/readback. Cooperative CPU tails may finish after
    /// this deadline, but their result is rejected rather than published.
    pub wall_time: Duration,
}
impl ErofsBuildLimits {
    pub fn validate(self) -> Result<(), ErofsBuildError> {
        if self.input.tar_bytes == 0
            || self.input.inodes == 0
            || self.input.live_file_bytes == 0
            || self.output_bytes < 4096
            || self.tool_bytes < 64
            || self.address_space_bytes == 0
            || self.cpu_seconds == 0
            || self.cpu_seconds == u64::MAX
            || self.wall_time.is_zero()
            || Instant::now().checked_add(self.wall_time).is_none()
            || [
                self.input.tar_bytes,
                self.input.inodes,
                self.input.live_file_bytes,
                self.output_bytes,
                self.tool_bytes,
            ]
            .iter()
            .any(|n| *n > isize::MAX as usize)
            || self.address_space_bytes > isize::MAX as u64
        {
            return Err(ErofsBuildError::InvalidConfiguration);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ErofsBuildError {
    #[error("EROFS builder configuration rejected")]
    InvalidConfiguration,
    #[error("EROFS builder tool identity or static executable profile rejected")]
    ToolRejected,
    #[error("EROFS builder input rejected")]
    InputRejected,
    #[error("EROFS builder exceeded a bound")]
    TooLarge,
    #[error("EROFS builder cancelled or deadline exceeded")]
    Cancelled,
    #[error("EROFS builder child failed")]
    ChildFailed,
    #[error("EROFS builder file or process operation failed")]
    Operation,
    #[error("EROFS builder output rejected")]
    OutputRejected,
    #[error("EROFS image differs from the checked staging input")]
    ParityRejected,
}

/// Exact tool bytes are copied into an immutable executable memfd before use.
/// The expected SHA384 must come from independently trusted provisioning. The
/// operator pins a static erofs-utils 1.8.10 artifact for the fixed profile;
/// request bytes cannot select a program, arguments, environment or input path.
pub struct TrustedErofsBuilder {
    executable: File,
    tool_sha384: [u8; 48],
    limits: ErofsBuildLimits,
}
impl TrustedErofsBuilder {
    pub fn new(
        tool: File,
        expected_sha384: [u8; 48],
        limits: ErofsBuildLimits,
    ) -> Result<Self, ErofsBuildError> {
        limits.validate()?;
        let metadata = tool.metadata().map_err(|_| ErofsBuildError::ToolRejected)?;
        if !metadata.is_file() || metadata.len() < 64 || metadata.len() > limits.tool_bytes as u64 {
            return Err(ErofsBuildError::ToolRejected);
        }
        let mut bytes = Zeroizing::new(vec![0; metadata.len() as usize]);
        tool.read_exact_at(&mut bytes, 0)
            .map_err(|_| ErofsBuildError::ToolRejected)?;
        let hash: [u8; 48] = Sha384::digest(&bytes).into();
        if hash != expected_sha384 || !static_native_tool(&bytes) {
            return Err(ErofsBuildError::ToolRejected);
        }
        let executable = File::from(
            memfd_create(
                "pinned-erofs-builder",
                MFdFlags::MFD_CLOEXEC
                    | MFdFlags::MFD_ALLOW_SEALING
                    | MFdFlags::from_bits_retain(libc::MFD_EXEC),
            )
            .map_err(|_| ErofsBuildError::Operation)?,
        );
        executable
            .write_all_at(&bytes, 0)
            .map_err(|_| ErofsBuildError::Operation)?;
        fcntl(
            &executable,
            FcntlArg::F_ADD_SEALS(SEALS | SealFlag::from_bits_retain(libc::F_SEAL_EXEC)),
        )
        .map_err(|_| ErofsBuildError::Operation)?;
        Ok(Self {
            executable,
            tool_sha384: hash,
            limits,
        })
    }

    /// Only an attempt-owned staging tree can supply lineage. All input bytes
    /// and desired metadata are checked before constructing a sealed TAR. The
    /// builder never receives a staging pathname or arbitrary expected digest.
    pub fn build(
        &self,
        staging: &RootfsStaging,
        cancelled: &impl Fn() -> bool,
    ) -> Result<VerifiedErofsBacking, ErofsBuildError> {
        let deadline = Instant::now()
            .checked_add(self.limits.wall_time)
            .ok_or(ErofsBuildError::InvalidConfiguration)?;
        let stopped = || cancelled() || Instant::now() >= deadline;
        check_cancel(&stopped)?;
        let input = staging
            .builder_input(self.limits.input, &stopped)
            .map_err(|_| {
                if stopped() {
                    ErofsBuildError::Cancelled
                } else {
                    ErofsBuildError::InputRejected
                }
            })?;
        check_cancel(&stopped)?;
        let output = File::from(
            memfd_create(
                "erofs-builder-output",
                MFdFlags::MFD_CLOEXEC
                    | MFdFlags::MFD_ALLOW_SEALING
                    | MFdFlags::from_bits_retain(libc::MFD_NOEXEC_SEAL),
            )
            .map_err(|_| ErofsBuildError::Operation)?,
        );
        let input_file = File::from(
            input
                .tar
                .as_fd()
                .try_clone_to_owned()
                .map_err(|_| ErofsBuildError::Operation)?,
        );
        // The input is newly created with offset zero and has never been given
        // to another reader. Its immutable inode seals survive this alias.
        let mut scratch = staging
            .builder_scratch()
            .map_err(|_| ErofsBuildError::Operation)?;
        let scratch_fd = scratch.root.as_raw_fd();
        let output_fd = output.as_raw_fd();
        let program = format!("/proc/self/fd/{}", self.executable.as_raw_fd());
        let mut command = Command::new(program);
        command
            .args(OPTIONS)
            .arg(format!("/proc/self/fd/{output_fd}"))
            .env_clear()
            .env("LC_ALL", "C")
            .env("TMPDIR", format!("/proc/self/fd/{scratch_fd}"))
            .current_dir("/")
            .stdin(Stdio::from(input_file))
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let limits = self.limits;
        #[cfg(feature = "launch-preparation-custody")]
        let parent_pid = std::process::id() as libc::pid_t;
        // SAFETY: only async-signal-safe libc calls run between fork and exec;
        // the captured values are plain integers with no locks or allocation.
        unsafe {
            command.pre_exec(move || {
                #[cfg(feature = "launch-preparation-custody")]
                {
                    // A killed preparation role must not leave its builder
                    // holding plaintext aliases. The worker owns/waits this
                    // child; reparenting during setup rejects execution.
                    if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) != 0 {
                        return Err(io::Error::last_os_error());
                    }
                    if libc::getppid() != parent_pid {
                        return Err(io::Error::from_raw_os_error(libc::ESRCH));
                    }
                }
                if libc::setpgid(0, 0) != 0
                    || libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
                    || libc::fcntl(output_fd, libc::F_SETFD, 0) < 0
                    || libc::fcntl(scratch_fd, libc::F_SETFD, 0) < 0
                    || libc::signal(libc::SIGXFSZ, libc::SIG_IGN) == libc::SIG_ERR
                {
                    return Err(io::Error::last_os_error());
                }
                for (resource, value) in [
                    (libc::RLIMIT_CORE, 0),
                    (libc::RLIMIT_FSIZE, limits.output_bytes as u64),
                    (libc::RLIMIT_AS, limits.address_space_bytes),
                    (libc::RLIMIT_CPU, limits.cpu_seconds),
                    (libc::RLIMIT_NOFILE, 64),
                ] {
                    let bound = libc::rlimit {
                        rlim_cur: value,
                        rlim_max: value,
                    };
                    if libc::setrlimit(resource, &bound) != 0 {
                        return Err(io::Error::last_os_error());
                    }
                }
                Ok(())
            });
        }
        let mut child = ReapedChild(Some(
            command.spawn().map_err(|_| ErofsBuildError::Operation)?,
        ));
        loop {
            if stopped() {
                child.stop()?;
                return Err(ErofsBuildError::Cancelled);
            }
            match child.0.as_mut().expect("owned child").try_wait() {
                Ok(Some(status)) => {
                    child.0.take();
                    if !status.success() {
                        return Err(ErofsBuildError::ChildFailed);
                    }
                    break;
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(2)),
                Err(_) => return Err(ErofsBuildError::Operation),
            }
        }
        scratch.cleanup().map_err(|_| ErofsBuildError::Operation)?;
        check_cancel(&stopped)?;
        // Child writers have exited and been reaped. Seal the same data-only
        // inode, then sample size and read it; no mutable output is published.
        fcntl(&output, FcntlArg::F_ADD_SEALS(SEALS))
            .map_err(|_| ErofsBuildError::OutputRejected)?;
        let len = output
            .metadata()
            .map_err(|_| ErofsBuildError::Operation)?
            .len();
        if len == 0 || len > self.limits.output_bytes as u64 {
            return Err(ErofsBuildError::TooLarge);
        }
        let mut bytes = Zeroizing::new(vec![0; len as usize]);
        read_bounded(&output, &mut bytes, &stopped)?;
        let sha384: [u8; 48] = Sha384::digest(&bytes).into();
        let sealed = SealedImageBytes::from_received_fd(
            output.into(),
            self.limits.output_bytes as u64,
            sha384,
        )
        .map_err(|_| ErofsBuildError::OutputRejected)?;
        check_cancel(&stopped)?;
        verify_erofs(&bytes, &input.nodes).map_err(|_| ErofsBuildError::ParityRejected)?;
        check_cancel(&stopped)?;
        let summary = VerifiedErofsSummary {
            image_sha384: sha384,
            byte_len: len,
            tool_sha384: self.tool_sha384,
            input_tar_sha384: *input.tar.sha384(),
            inodes: input.nodes.len(),
        };
        Ok(VerifiedErofsBacking {
            sealed,
            summary,
            #[cfg(feature = "launch-preparation-mount")]
            inventory: input.nodes,
        })
    }
}

/// Immutable, format/parity checked bytes with retained trusted-input lineage.
/// No conversion to a rootfs lease, preparation record or start permit exists.
pub struct VerifiedErofsBacking {
    sealed: SealedImageBytes,
    summary: VerifiedErofsSummary,
    #[cfg(feature = "launch-preparation-mount")]
    inventory: Vec<super::erofs_reader::ExpectedNode>,
}
impl VerifiedErofsBacking {
    pub fn summary(&self) -> &VerifiedErofsSummary {
        &self.summary
    }
    #[cfg(feature = "launch-preparation-mount")]
    pub(crate) fn into_mount_parts(
        self,
    ) -> (
        SealedImageBytes,
        VerifiedErofsSummary,
        Vec<super::erofs_reader::ExpectedNode>,
    ) {
        (self.sealed, self.summary, self.inventory)
    }
}
impl AsFd for VerifiedErofsBacking {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.sealed.as_fd()
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedErofsSummary {
    image_sha384: [u8; 48],
    byte_len: u64,
    tool_sha384: [u8; 48],
    input_tar_sha384: [u8; 48],
    inodes: usize,
}
impl VerifiedErofsSummary {
    pub fn image_sha384(&self) -> &[u8; 48] {
        &self.image_sha384
    }
    pub fn byte_len(&self) -> u64 {
        self.byte_len
    }
    pub fn tool_sha384(&self) -> &[u8; 48] {
        &self.tool_sha384
    }
    pub fn input_tar_sha384(&self) -> &[u8; 48] {
        &self.input_tar_sha384
    }
    pub fn inodes(&self) -> usize {
        self.inodes
    }
    pub fn profile(&self) -> &'static str {
        EROFS_PROFILE
    }
}

fn check_cancel(cancelled: &impl Fn() -> bool) -> Result<(), ErofsBuildError> {
    if cancelled() {
        Err(ErofsBuildError::Cancelled)
    } else {
        Ok(())
    }
}
fn read_bounded(
    file: &File,
    bytes: &mut [u8],
    cancelled: &impl Fn() -> bool,
) -> Result<(), ErofsBuildError> {
    for (index, chunk) in bytes.chunks_mut(8192).enumerate() {
        check_cancel(cancelled)?;
        file.read_exact_at(chunk, (index * 8192) as u64)
            .map_err(|_| ErofsBuildError::Operation)?;
    }
    Ok(())
}
// Only static ELF64 x86_64 native tools are accepted. This checks the trusted
// tool's loader dependence, not the workload ELF profile or executable semantics.
fn static_native_tool(bytes: &[u8]) -> bool {
    if bytes.len() < 64
        || &bytes[..7] != b"\x7fELF\x02\x01\x01"
        || u16::from_le_bytes([bytes[18], bytes[19]]) != 62
    {
        return false;
    }
    let offset = u64::from_le_bytes(bytes[32..40].try_into().expect("header"));
    let size = u16::from_le_bytes([bytes[54], bytes[55]]) as u64;
    let count = u16::from_le_bytes([bytes[56], bytes[57]]) as u64;
    if size != 56 || count == 0 || count > 128 {
        return false;
    }
    let Some(end) = count.checked_mul(size).and_then(|n| offset.checked_add(n)) else {
        return false;
    };
    if end > bytes.len() as u64 {
        return false;
    }
    bytes[offset as usize..end as usize]
        .as_chunks::<56>()
        .0
        .iter()
        .all(|ph| u32::from_le_bytes(ph[..4].try_into().expect("header")) != 3)
}
struct ReapedChild(Option<Child>);
impl ReapedChild {
    fn stop(&mut self) -> Result<(), ErofsBuildError> {
        if let Some(mut child) = self.0.take() {
            // The profile uses a static single-worker binary, without helpers.
            // Kill its private group as well, then wait for the direct child.
            // SAFETY: a negative pid addresses the child-created process group.
            unsafe {
                libc::kill(-(child.id() as i32), libc::SIGKILL);
            }
            let _ = child.kill();
            child.wait().map_err(|_| ErofsBuildError::Operation)?;
        }
        Ok(())
    }
}
impl Drop for ReapedChild {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

#[cfg(test)]
#[path = "erofs_builder_tests.rs"]
mod tests;
