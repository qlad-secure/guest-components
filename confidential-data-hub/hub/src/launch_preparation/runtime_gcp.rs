//! GCP-v2 admission and credential ownership through the bounded preparation actor.
//! These constructors share the legacy resource owner, not its wire types. They
//! do not establish measured startup or producer qualification.
use super::*;
#[cfg(feature = "launch-preparation-executable")]
use image_rs::preparation::launch_spec::BoundEffectiveSpec;

pub type GcpRuntimeAttemptConfig = RuntimeAttemptConfig<GcpGuestAdmissionConfig>;
#[cfg(feature = "launch-preparation-executable")]
pub type GcpCheckedRuntimeAttemptConfig = CheckedRuntimeAttemptConfig<GcpGuestAdmissionConfig>;
#[cfg(feature = "launch-preparation-erofs")]
pub type GcpErofsRuntimeAttemptConfig = ErofsRuntimeAttemptConfig<GcpGuestAdmissionConfig>;
#[cfg(feature = "launch-preparation-mount")]
pub type GcpMountedRuntimeAttemptConfig = MountedRuntimeAttemptConfig<GcpGuestAdmissionConfig>;

impl RuntimeFactory {
    /// Requires independently pinned roots, B, full aggregate, and image policy.
    /// Capacity is reserved before creating the guest-owned admission nonce.
    pub fn begin_gcp_attempt(
        &self,
        config: GcpRuntimeAttemptConfig,
        recorder: GcpLaunchRecorder,
    ) -> Result<RuntimeAttempt, RuntimeError> {
        validate_gcp_attempt_config(&config, self.resources.registry.repository())?;
        let (admission, config) = split_config(config);
        self.begin_owned_attempt(config, || {
            let admission_policy_sha384 = admission.admission_policy_sha384.clone();
            let gate = GcpGuestAdmissionGate::new(admission)
                .map_err(|_| RuntimeError::InvalidConfiguration)?;
            Ok(RuntimeAdmission::Gcp {
                gate,
                recorder: Box::new(recorder),
                admission_policy_sha384,
            })
        })
    }
}

fn validate_gcp_attempt_config(
    config: &GcpRuntimeAttemptConfig,
    repository: &str,
) -> Result<(), RuntimeError> {
    validate_configuration(&config.preparation, &config.metadata_limits)
        .map_err(|_| RuntimeError::InvalidConfiguration)?;
    content::validate_content_limits(config.content_limits)
        .map_err(|_| RuntimeError::InvalidConfiguration)?;
    config
        .staging_limits
        .validate()
        .map_err(|_| RuntimeError::InvalidConfiguration)?;
    let gate = &config.admission;
    let profile = &config.preparation;
    let aggregate = &gate.aggregate.expected;
    if gate.expected_grant.binding != profile.binding
        || gate.expected_grant.validity != profile.validity
        || gate.expected_grant.digest_sha384().ok().as_deref() != Some(&profile.grant_sha384)
        || gate.grant.authority_public_key != profile.authority_public_key
        || gate.aggregate.kbs_proof_public_key != profile.kbs_proof_public_key
        || aggregate.grant_sha384 != profile.grant_sha384
        || aggregate.request.workflow_id != profile.workflow_id
        || aggregate.request.resource_path != profile.resource_path
        || config.signature_policy.policy_sha384() != profile.binding.image_policy_sha384
        || config.signature_policy.repository() != repository
        || !sha256_hex(&config.signature_artifact_sha256)
    {
        return Err(RuntimeError::InvalidConfiguration);
    }
    Ok(())
}

#[cfg(feature = "launch-preparation-executable")]
impl RuntimeFactory {
    /// Bind the signed OCI candidate before network access. Kata independently
    /// binds the final specification before starting the task.
    pub fn begin_gcp_checked_attempt(
        &self,
        config: GcpCheckedRuntimeAttemptConfig,
        recorder: GcpLaunchRecorder,
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
        let mut attempt = self.begin_gcp_attempt(config.base, recorder)?;
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
                pending.executable = Some(executable::RequiredExecution { spec, limits })
            }
            _ => return Err(RuntimeError::InvalidConfiguration),
        }
        Ok(CheckedRuntimeAttempt(attempt))
    }
}

#[cfg(feature = "launch-preparation-erofs")]
impl RuntimeFactory {
    /// Require signed-spec/executable checks and a pinned native builder before
    /// publishing a backing summary. Received delivery cannot select the tool.
    pub fn begin_gcp_erofs_attempt(
        &self,
        config: GcpErofsRuntimeAttemptConfig,
        recorder: GcpLaunchRecorder,
    ) -> Result<ErofsRuntimeAttempt, RuntimeError> {
        let mut attempt = self.begin_gcp_checked_attempt(config.checked, recorder)?.0;
        let RuntimeState::Pending(pending) = &mut attempt.state else {
            return Err(RuntimeError::InvalidConfiguration);
        };
        pending.builder = Some(config.builder);
        Ok(ErofsRuntimeAttempt(attempt))
    }
}

#[cfg(feature = "launch-preparation-mount")]
impl RuntimeFactory {
    pub fn begin_gcp_mounted_attempt(
        &self,
        config: GcpMountedRuntimeAttemptConfig,
        recorder: GcpLaunchRecorder,
    ) -> Result<MountedRuntimeAttempt, RuntimeError> {
        config
            .mount_limits
            .validate()
            .map_err(|_| RuntimeError::InvalidConfiguration)?;
        let mut attempt = self.begin_gcp_erofs_attempt(config.erofs, recorder)?.0;
        let RuntimeState::Pending(pending) = &mut attempt.state else {
            return Err(RuntimeError::InvalidConfiguration);
        };
        pending.mount = Some(config.mount_limits);
        Ok(MountedRuntimeAttempt(attempt))
    }
}

impl RuntimeAttempt {
    /// Request only this pending recorder's pinned aggregate credential. The
    /// owned preparation gate still checks admission before JWE consumption.
    pub fn gcp_credential_request(&self, aggregate: &[u8]) -> Result<Vec<u8>, RuntimeError> {
        let RuntimeState::Pending(pending) = &self.state else {
            return Err(RuntimeError::Unavailable);
        };
        let RuntimeAdmission::Gcp { recorder, .. } = &pending.admission else {
            return Err(RuntimeError::Unavailable);
        };
        recorder.credential_request(aggregate).map_err(|_| RuntimeError::CredentialRejected)
    }
    /// Signs the authority request with the pending factory-owned nonce and
    /// pinned policy. A caller cannot select another nonce, audience or policy.
    /// Available only before this owner consumes admission/credential state.
    pub fn gcp_admission_request(
        &self,
        aggregate: &[u8],
        operation: execution_proof_contract::admission::gcp::GcpAdmissionOperation,
    ) -> Result<Vec<u8>, RuntimeError> {
        let RuntimeState::Pending(pending) = &self.state else {
            return Err(RuntimeError::Unavailable);
        };
        let RuntimeAdmission::Gcp {
            gate,
            recorder,
            admission_policy_sha384,
        } = &pending.admission
        else {
            return Err(RuntimeError::Unavailable);
        };
        recorder
            .policy_admission_request(
                aggregate,
                gate.challenge_nonce(),
                admission_policy_sha384,
                operation,
            )
            .map_err(|_| RuntimeError::AdmissionRejected)
    }
}
