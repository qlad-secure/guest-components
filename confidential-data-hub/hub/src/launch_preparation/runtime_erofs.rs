//! Checked native image construction, retained by the same preparation actor.
//! The sealed backing is not a mount, final preparation record or start permit.
use super::*;
use image_rs::preparation::{
    erofs_builder::{TrustedErofsBuilder, VerifiedErofsSummary},
    rootfs_staging::CheckedStagingExecutable,
};

pub struct ErofsRuntimeAttemptConfig {
    pub checked: CheckedRuntimeAttemptConfig,
    pub builder: TrustedErofsBuilder,
}
impl RuntimeFactory {
    /// Require signed-spec/executable checks and a pinned native builder before
    /// publishing a backing summary. Received delivery cannot select the tool.
    pub fn begin_erofs_attempt(
        &self,
        config: ErofsRuntimeAttemptConfig,
        recorder: LaunchRecorder,
    ) -> Result<ErofsRuntimeAttempt, RuntimeError> {
        let mut attempt = self.begin_checked_attempt(config.checked, recorder)?.0;
        let RuntimeState::Pending(pending) = &mut attempt.state else {
            return Err(RuntimeError::InvalidConfiguration);
        };
        pending.builder = Some(config.builder);
        Ok(ErofsRuntimeAttempt(attempt))
    }
}

/// This type cannot be constructed from staging-only or executable-only status.
/// The retained actor owns the actual backing; only observations cross threads.
pub struct ErofsRuntimeAttempt(pub(super) RuntimeAttempt);
impl ErofsRuntimeAttempt {
    pub fn challenge_nonce(&self) -> &str {
        self.0.challenge_nonce()
    }
    pub async fn prepare(
        &mut self,
        delivery: RuntimeDelivery<'_>,
    ) -> Result<ContentBinding, RuntimeError> {
        self.0.prepare(delivery).await
    }
    pub fn summary(&self) -> Result<ErofsRuntimeSummary, RuntimeError> {
        let RuntimeState::Staged(retained) = &self.0.state else {
            return Err(RuntimeError::Unavailable);
        };
        Ok(ErofsRuntimeSummary {
            staging: retained.snapshot.staging.clone(),
            executable: retained
                .snapshot
                .executable
                .clone()
                .ok_or(RuntimeError::Unavailable)?,
            backing: retained
                .snapshot
                .backing
                .clone()
                .ok_or(RuntimeError::Unavailable)?,
        })
    }
    pub async fn cancel_and_wait(&mut self) -> Result<(), RuntimeError> {
        self.0.cancel_and_wait().await
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ErofsRuntimeSummary {
    staging: RuntimePreparationSummary,
    executable: CheckedStagingExecutable,
    backing: VerifiedErofsSummary,
}
impl ErofsRuntimeSummary {
    pub fn staging(&self) -> &RuntimePreparationSummary {
        &self.staging
    }
    pub fn executable(&self) -> &CheckedStagingExecutable {
        &self.executable
    }
    pub fn backing(&self) -> &VerifiedErofsSummary {
        &self.backing
    }
}
#[cfg(test)]
impl ErofsRuntimeAttempt {
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
