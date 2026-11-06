//! Detached checked rootfs views retained by the preparation actor.
//! These observations do not establish authenticated Kata custody, a final
//! effective spec/preparation record, lease or permission to start a task.
use super::*;
use image_rs::preparation::erofs_mount::{ErofsMountLimits, MountedRootfsSummary};

pub struct MountedRuntimeAttemptConfig {
    pub erofs: ErofsRuntimeAttemptConfig,
    pub mount_limits: ErofsMountLimits,
}
impl RuntimeFactory {
    pub fn begin_mounted_attempt(
        &self,
        config: MountedRuntimeAttemptConfig,
        recorder: LaunchRecorder,
    ) -> Result<MountedRuntimeAttempt, RuntimeError> {
        config
            .mount_limits
            .validate()
            .map_err(|_| RuntimeError::InvalidConfiguration)?;
        let mut attempt = self.begin_erofs_attempt(config.erofs, recorder)?.0;
        let RuntimeState::Pending(pending) = &mut attempt.state else {
            return Err(RuntimeError::InvalidConfiguration);
        };
        pending.mount = Some(config.mount_limits);
        Ok(MountedRuntimeAttempt(attempt))
    }
}
/// No unchecked staging/backing conversion; mounted summary requires success
/// from this attempt's actual kernel mount and mounted-tree validation.
pub struct MountedRuntimeAttempt(pub(super) RuntimeAttempt);
impl MountedRuntimeAttempt {
    pub fn challenge_nonce(&self) -> &str {
        self.0.challenge_nonce()
    }
    pub async fn prepare(
        &mut self,
        delivery: RuntimeDelivery<'_>,
    ) -> Result<ContentBinding, RuntimeError> {
        self.0.prepare(delivery).await
    }
    pub fn summary(&self) -> Result<MountedRuntimeSummary, RuntimeError> {
        let RuntimeState::Staged(retained) = &self.0.state else {
            return Err(RuntimeError::Unavailable);
        };
        Ok(MountedRuntimeSummary {
            staging: retained.snapshot.staging.clone(),
            view: retained
                .snapshot
                .mounted
                .clone()
                .ok_or(RuntimeError::Unavailable)?,
        })
    }
    pub async fn cancel_and_wait(&mut self) -> Result<(), RuntimeError> {
        self.0.cancel_and_wait().await
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MountedRuntimeSummary {
    staging: RuntimePreparationSummary,
    view: MountedRootfsSummary,
}
impl MountedRuntimeSummary {
    pub fn staging(&self) -> &RuntimePreparationSummary {
        &self.staging
    }
    pub fn view(&self) -> &MountedRootfsSummary {
        &self.view
    }
}
#[cfg(test)]
impl MountedRuntimeAttempt {
    pub(crate) async fn prepare_fixture(
        &mut self,
        delivery: RuntimeDelivery<'_>,
        replies: Vec<fixture::Reply>,
        trace: Arc<std::sync::Mutex<fixture::Trace>>,
    ) -> Result<ContentBinding, RuntimeError> {
        self.0.prepare_fixture(delivery, replies, trace).await
    }
}
