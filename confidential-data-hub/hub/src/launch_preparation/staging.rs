//! Attempt-owned, non-authorizing private filesystem staging of checked layers.
//!
//! The trusted constructor supplies the private parent and work budgets. There
//! is no received path, caller layer list, builder callback, root FD export,
//! immutable-rootfs claim, final preparation P, lease or start permission here.

use super::*;
use image_rs::preparation::rootfs_staging::{
    PrivateStagingParent, RootfsStaging, RootfsStagingLimits, RootfsStagingSummary,
};

pub(super) struct StagingConfiguration {
    parent: PrivateStagingParent,
    limits: RootfsStagingLimits,
}

pub(super) struct StagedBinding {
    pub(super) checked: content::CheckedBinding,
    rootfs: RootfsStaging,
}

impl PreparationAttempt {
    /// Provision staging independently of untrusted manifest/blob responses.
    /// Construction does not create a staging directory or apply any layer.
    pub fn new_with_staging(
        admission: AcceptedAttemptContext,
        credential: AttemptCredential,
        profile: PreparationProfile,
        limits: PreparationLimits,
        content_limits: ImageContentLimits,
        parent: PrivateStagingParent,
        staging_limits: RootfsStagingLimits,
    ) -> Result<Self, PreparationError> {
        staging_limits
            .validate()
            .map_err(|_| PreparationError::InvalidConfiguration)?;
        let mut attempt =
            Self::new_with_content(admission, credential, profile, limits, content_limits)?;
        if let State::Pending(material) = &mut attempt.state {
            material.staging = Some(StagingConfiguration {
                parent,
                limits: staging_limits,
            });
        }
        Ok(attempt)
    }

    /// Consume only the attempt's checked layers. State is terminal during all
    /// filesystem work; errors dispose the owned staging and admission. Exact
    /// retries return retained metadata without another extraction or unwrap.
    /// Run this synchronous filesystem work on a blocking worker. This library
    /// does not spawn background tasks.
    pub fn stage_rootfs(&mut self) -> Result<ContentBinding, PreparationError> {
        let mut checked = match std::mem::replace(&mut self.state, State::Terminal) {
            State::ContentChecked(checked) => checked,
            State::RootfsStaged(staged) => {
                self.state = State::RootfsStaged(staged);
                return Ok(ContentBinding::Historical);
            }
            State::Terminal => return Err(PreparationError::Unavailable),
            _ => return Err(PreparationError::NotReady),
        };
        let configuration = checked
            .signed
            .bound
            ._material
            .staging
            .take()
            .ok_or(PreparationError::InvalidConfiguration)?;
        let layers = std::mem::take(&mut checked._layers);
        let rootfs =
            RootfsStaging::from_checked_layers(configuration.parent, layers, configuration.limits)
                .map_err(|_| PreparationError::StagingRejected)?;
        self.state = State::RootfsStaged(StagedBinding { checked, rootfs });
        Ok(ContentBinding::FirstChecked)
    }

    /// Metadata about a mutable private staging tree, never a rootfs lease.
    pub fn rootfs_staging_summary(&self) -> Result<&RootfsStagingSummary, PreparationError> {
        match &self.state {
            State::RootfsStaged(staged) => Ok(staged.rootfs.summary()),
            State::Terminal => Err(PreparationError::Unavailable),
            _ => Err(PreparationError::NotReady),
        }
    }
}

#[cfg(feature = "launch-preparation-executable")]
impl PreparationAttempt {
    // Internal borrowed view only. No public method exports staging FDs or
    // constructs a checked runtime result from caller assertions.
    pub(super) fn check_staged_executable(
        &self,
        spec: &image_rs::preparation::launch_spec::BoundEffectiveSpec,
        limits: image_rs::preparation::static_elf::StaticElfLimits,
    ) -> Result<image_rs::preparation::rootfs_staging::CheckedStagingExecutable, PreparationError>
    {
        match &self.state {
            State::RootfsStaged(staged) => staged
                .rootfs
                .check_static_executable(spec, limits)
                .map_err(|_| PreparationError::StagingRejected),
            State::Terminal => Err(PreparationError::Unavailable),
            _ => Err(PreparationError::NotReady),
        }
    }
}
