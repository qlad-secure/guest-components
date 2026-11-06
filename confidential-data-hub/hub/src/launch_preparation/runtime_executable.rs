//! Mandatory signed-spec and static-executable preflight for mutable staging.
//!
//! These types are distinct from legacy staging-only observations. They do not
//! attest that Kata used this candidate spec or that a final immutable view,
//! rootfs lease, mount or executable task exists.
use super::*;
use image_rs::preparation::{
    launch_spec::{BoundEffectiveSpec, EffectiveSpecLimits, EffectiveSpecPolicy},
    rootfs_staging::CheckedStagingExecutable,
    static_elf::StaticElfLimits,
};

pub struct CheckedRuntimeAttemptConfig {
    pub base: RuntimeAttemptConfig,
    pub effective_spec: Vec<u8>,
    pub spec_policy: EffectiveSpecPolicy,
    pub spec_limits: EffectiveSpecLimits,
    pub executable_limits: StaticElfLimits,
}

pub(super) struct RequiredExecution {
    pub(super) spec: BoundEffectiveSpec,
    pub(super) limits: StaticElfLimits,
}

impl RuntimeFactory {
    /// Bind exact raw candidate OCI-spec bytes before network. This is a local
    /// signed-byte preflight; future final Kata transforms need their own binding.
    pub fn begin_checked_attempt(
        &self,
        config: CheckedRuntimeAttemptConfig,
        recorder: LaunchRecorder,
    ) -> Result<CheckedRuntimeAttempt, RuntimeError> {
        let limits = config.executable_limits;
        limits
            .validate()
            .map_err(|_| RuntimeError::InvalidConfiguration)?;
        let expected_spec = config
            .base
            .preparation
            .binding
            .effective_launch_sha384
            .clone();
        let mut attempt = self.begin_attempt(config.base, recorder)?;
        // The active permit also covers this bounded per-attempt parse. A
        // rejected candidate drops the pending gate before returning capacity.
        let spec = BoundEffectiveSpec::parse(
            &config.effective_spec,
            &expected_spec,
            &config.spec_policy,
            config.spec_limits,
        )
        .map_err(|_| RuntimeError::InvalidConfiguration)?;
        match &mut attempt.state {
            RuntimeState::Pending(pending) => {
                pending.executable = Some(RequiredExecution { spec, limits })
            }
            _ => return Err(RuntimeError::InvalidConfiguration),
        }
        Ok(CheckedRuntimeAttempt(attempt))
    }
}

/// No constructor, conversion or Deref from the legacy staging-only runtime.
/// A checked summary is published only after this attempt's actor validates the
/// required spec and actual staged executable snapshot.
pub struct CheckedRuntimeAttempt(RuntimeAttempt);
impl CheckedRuntimeAttempt {
    pub fn challenge_nonce(&self) -> &str {
        self.0.challenge_nonce()
    }

    pub async fn prepare(
        &mut self,
        delivery: RuntimeDelivery<'_>,
    ) -> Result<ContentBinding, RuntimeError> {
        self.0.prepare(delivery).await
    }

    pub fn summary(&self) -> Result<CheckedRuntimeSummary, RuntimeError> {
        let RuntimeState::Staged(retained) = &self.0.state else {
            return Err(RuntimeError::Unavailable);
        };
        let executable = retained
            .snapshot
            .executable
            .as_ref()
            .ok_or(RuntimeError::Unavailable)?;
        Ok(CheckedRuntimeSummary {
            staging: retained.snapshot.staging.clone(),
            executable: executable.clone(),
        })
    }

    pub async fn cancel_and_wait(&mut self) -> Result<(), RuntimeError> {
        self.0.cancel_and_wait().await
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckedRuntimeSummary {
    staging: RuntimePreparationSummary,
    executable: CheckedStagingExecutable,
}
impl CheckedRuntimeSummary {
    pub fn staging(&self) -> &RuntimePreparationSummary {
        &self.staging
    }
    pub fn executable(&self) -> &CheckedStagingExecutable {
        &self.executable
    }
}

#[cfg(test)]
impl CheckedRuntimeAttempt {
    pub(crate) fn set_stage_barrier(
        &mut self,
        reached: oneshot::Sender<()>,
        release: std::sync::mpsc::Receiver<()>,
    ) {
        self.0.set_stage_barrier(reached, release);
    }

    pub(crate) async fn prepare_fixture(
        &mut self,
        delivery: RuntimeDelivery<'_>,
        replies: Vec<fixture::Reply>,
        trace: Arc<std::sync::Mutex<fixture::Trace>>,
    ) -> Result<ContentBinding, RuntimeError> {
        self.0.prepare_fixture(delivery, replies, trace).await
    }
}
