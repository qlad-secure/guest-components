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
    #[cfg(feature = "launch-preparation-erofs")]
    erofs: ErofsState,
}

#[cfg(feature = "launch-preparation-erofs")]
enum ErofsState {
    Unbuilt,
    Built(Box<image_rs::preparation::erofs_builder::VerifiedErofsBacking>),
    #[cfg(feature = "launch-preparation-mount")]
    Mounted(Box<image_rs::preparation::erofs_mount::VerifiedMountedView>),
}

#[cfg(feature = "launch-preparation-offer")]
impl PreparationAttempt {
    pub(super) fn rootfs_offer_origin(
        &self,
        max_backing_bytes: u64,
    ) -> Result<
        (
            execution_proof_handoff::rootfs_offer::RootfsOfferDraft,
            std::os::fd::OwnedFd,
        ),
        runtime::RootfsOfferError,
    > {
        use execution_proof_handoff::rootfs_offer::{
            BackingDescriptor, RootfsOfferDraft, IMAGE_PROFILE,
        };
        use std::os::fd::AsFd;
        let State::RootfsStaged(staged) = &self.state else {
            return Err(runtime::RootfsOfferError::Unavailable);
        };
        let (summary, descriptor) = match &staged.erofs {
            ErofsState::Built(backing) => (
                backing.summary(),
                backing
                    .as_fd()
                    .try_clone_to_owned()
                    .map_err(|_| runtime::RootfsOfferError::Backing)?,
            ),
            #[cfg(feature = "launch-preparation-mount")]
            ErofsState::Mounted(view) => (
                view.summary().backing(),
                view.duplicate_sealed_origin()
                    .map_err(|_| runtime::RootfsOfferError::Backing)?,
            ),
            ErofsState::Unbuilt => return Err(runtime::RootfsOfferError::Unavailable),
        };
        if summary.profile() != IMAGE_PROFILE {
            return Err(runtime::RootfsOfferError::Backing);
        }
        let admission = &staged.checked.signed.bound._material.admission;
        let draft = RootfsOfferDraft::new(
            admission,
            BackingDescriptor {
                sha384: *summary.image_sha384(),
                byte_len: summary.byte_len(),
            },
            max_backing_bytes,
        )
        .map_err(runtime::RootfsOfferError::Protocol)?;
        Ok((draft, descriptor))
    }

    #[cfg(feature = "launch-preparation-custody")]
    pub(super) fn custody_builder_summary(
        &self,
    ) -> Result<
        &image_rs::preparation::erofs_builder::VerifiedErofsSummary,
        runtime::CustodyProducerError,
    > {
        let State::RootfsStaged(staged) = &self.state else {
            return Err(runtime::CustodyProducerError::Unavailable);
        };
        match &staged.erofs {
            ErofsState::Built(backing) => Ok(backing.summary()),
            #[cfg(feature = "launch-preparation-mount")]
            ErofsState::Mounted(view) => Ok(view.summary().backing()),
            ErofsState::Unbuilt => Err(runtime::CustodyProducerError::Unavailable),
        }
    }
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
        self.state = State::RootfsStaged(StagedBinding {
            checked,
            rootfs,
            #[cfg(feature = "launch-preparation-erofs")]
            erofs: ErofsState::Unbuilt,
        });
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

#[cfg(feature = "launch-preparation-erofs")]
impl PreparationAttempt {
    /// Consume only this attempt's retained checked staging. Failure is terminal;
    /// a historical observation never invokes the tool or unwraps a key again.
    pub(super) fn build_staged_rootfs(
        &mut self,
        builder: &image_rs::preparation::erofs_builder::TrustedErofsBuilder,
        cancelled: &impl Fn() -> bool,
    ) -> Result<image_rs::preparation::erofs_builder::VerifiedErofsSummary, PreparationError> {
        let mut staged = match std::mem::replace(&mut self.state, State::Terminal) {
            State::RootfsStaged(staged) => staged,
            State::Terminal => return Err(PreparationError::Unavailable),
            _ => return Err(PreparationError::NotReady),
        };
        if matches!(staged.erofs, ErofsState::Unbuilt) {
            staged.erofs = ErofsState::Built(Box::new(
                builder
                    .build(&staged.rootfs, cancelled)
                    .map_err(|_| PreparationError::StagingRejected)?,
            ));
        }
        let summary = match &staged.erofs {
            ErofsState::Built(backing) => backing.summary().clone(),
            #[cfg(feature = "launch-preparation-mount")]
            ErofsState::Mounted(view) => view.summary().backing().clone(),
            ErofsState::Unbuilt => return Err(PreparationError::NotReady),
        };
        self.state = State::RootfsStaged(staged);
        Ok(summary)
    }
}

#[cfg(feature = "launch-preparation-mount")]
impl PreparationAttempt {
    pub(super) fn mount_staged_rootfs(
        &mut self,
        spec: &image_rs::preparation::launch_spec::BoundEffectiveSpec,
        elf_limits: image_rs::preparation::static_elf::StaticElfLimits,
        limits: image_rs::preparation::erofs_mount::ErofsMountLimits,
        cancelled: &impl Fn() -> bool,
    ) -> Result<image_rs::preparation::erofs_mount::MountedRootfsSummary, PreparationError> {
        let mut staged = match std::mem::replace(&mut self.state, State::Terminal) {
            State::RootfsStaged(staged) => staged,
            State::Terminal => return Err(PreparationError::Unavailable),
            _ => return Err(PreparationError::NotReady),
        };
        staged.erofs = match std::mem::replace(&mut staged.erofs, ErofsState::Unbuilt) {
            ErofsState::Built(backing) => ErofsState::Mounted(Box::new(
                (*backing)
                    .mount_checked(spec, elf_limits, limits, cancelled)
                    .map_err(|_| PreparationError::StagingRejected)?,
            )),
            ErofsState::Mounted(view) => ErofsState::Mounted(view),
            ErofsState::Unbuilt => return Err(PreparationError::NotReady),
        };
        let ErofsState::Mounted(view) = &staged.erofs else {
            return Err(PreparationError::NotReady);
        };
        let summary = view.summary().clone();
        self.state = State::RootfsStaged(staged);
        Ok(summary)
    }
}
