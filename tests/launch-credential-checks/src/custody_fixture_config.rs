//! Public configuration for the native custody test helper only.
//!
//! No producer private keys, credentials, unwrap options, or live producer state
//! are serialized. The fixture's sealed config and argv are test provisioning,
//! not an alternative production trust source or an RPC configuration path.

use execution_proof_contract::{
    policy_receipt::{AggregateExpectations, LaunchPolicyAggregateV1},
    GrantExpectations, LaunchGrant,
};
use execution_proof_handoff::admission::GuestAdmissionConfig;
use image_rs::preparation::launch_spec::{
    BoundEffectiveSpec, EffectiveSpecError, EffectiveSpecLimits, EffectiveSpecPolicy,
};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub const FIXTURE_CONFIG_BYTES: usize = 1 << 20;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FixtureMode {
    RejectBeforeMount,
    NativePositive,
    NativeFinalTask,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskCase {
    Positive,
    CancelBeforeStart,
    SpecMismatch,
    PostExecFailure,
    CaptureRejected,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureReceiverWire {
    pub version: u16,
    pub authority_public_key: [u8; 32],
    pub grant_audience: String,
    pub authority: String,
    pub tenant: String,
    pub profile_sha384: String,
    pub launch_policy_sha384: String,
    pub image_policy_sha384: String,
    pub expected_grant: LaunchGrant,
    pub kbs_proof_public_key: [u8; 32],
    pub expected_aggregate: LaunchPolicyAggregateV1,
    pub audience: String,
    pub issuer: String,
    pub admission_policy_sha384: String,
    pub candidate_spec: Vec<u8>,
    pub uid: u32,
    pub gid: u32,
    pub seccomp_syscalls: Vec<String>,
    pub control_directory: PathBuf,
    pub mode: FixtureMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_case: Option<TaskCase>,
}
impl FixtureReceiverWire {
    pub fn from_config(
        admission: &GuestAdmissionConfig,
        candidate_spec: &[u8],
        policy: &EffectiveSpecPolicy,
        control_directory: PathBuf,
        mode: FixtureMode,
    ) -> Self {
        Self {
            version: 1,
            authority_public_key: admission.grant.authority_public_key,
            grant_audience: admission.grant.audience.clone(),
            authority: admission.grant.authority.clone(),
            tenant: admission.grant.tenant.clone(),
            profile_sha384: admission.grant.profile_sha384.clone(),
            launch_policy_sha384: admission.grant.launch_policy_sha384.clone(),
            image_policy_sha384: admission.grant.image_policy_sha384.clone(),
            expected_grant: admission.expected_grant.clone(),
            kbs_proof_public_key: admission.aggregate.kbs_proof_public_key,
            expected_aggregate: admission.aggregate.expected.clone(),
            audience: admission.audience.clone(),
            issuer: admission.issuer.clone(),
            admission_policy_sha384: admission.admission_policy_sha384.clone(),
            candidate_spec: candidate_spec.to_vec(),
            uid: policy.uid,
            gid: policy.gid,
            seccomp_syscalls: policy.seccomp_syscalls.clone(),
            control_directory,
            mode,
            task_case: None,
        }
    }
    pub fn admission(&self) -> GuestAdmissionConfig {
        GuestAdmissionConfig {
            grant: GrantExpectations {
                authority_public_key: self.authority_public_key,
                audience: self.grant_audience.clone(),
                authority: self.authority.clone(),
                tenant: self.tenant.clone(),
                profile_sha384: self.profile_sha384.clone(),
                launch_policy_sha384: self.launch_policy_sha384.clone(),
                image_policy_sha384: self.image_policy_sha384.clone(),
            },
            expected_grant: self.expected_grant.clone(),
            aggregate: AggregateExpectations {
                kbs_proof_public_key: self.kbs_proof_public_key,
                expected: self.expected_aggregate.clone(),
            },
            audience: self.audience.clone(),
            issuer: self.issuer.clone(),
            admission_policy_sha384: self.admission_policy_sha384.clone(),
        }
    }
    pub fn spec(&self) -> Result<BoundEffectiveSpec, EffectiveSpecError> {
        BoundEffectiveSpec::parse(
            &self.candidate_spec,
            &self.expected_grant.binding.effective_launch_sha384,
            &EffectiveSpecPolicy {
                uid: self.uid,
                gid: self.gid,
                seccomp_syscalls: self.seccomp_syscalls.clone(),
            },
            fixture_spec_limits(),
        )
    }
    pub fn encode(&self) -> Result<Vec<u8>, &'static str> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|_| "fixture config encoding")?;
        if bytes.len() > FIXTURE_CONFIG_BYTES {
            return Err("fixture config too large");
        }
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() > FIXTURE_CONFIG_BYTES {
            return Err("fixture config too large");
        }
        let result: Self = serde_json::from_slice(bytes).map_err(|_| "fixture config schema")?;
        result.validate()?;
        if result.encode()? != bytes {
            return Err("fixture config noncanonical");
        }
        Ok(result)
    }
    fn validate(&self) -> Result<(), &'static str> {
        if self.version != 1
            || (self.mode == FixtureMode::NativeFinalTask) != self.task_case.is_some()
            || self.candidate_spec.len() > 16384
            || self.seccomp_syscalls.len() > 32
            || self
                .seccomp_syscalls
                .iter()
                .any(|name| name.is_empty() || name.len() > 128)
            || !self.control_directory.is_absolute()
        {
            return Err("fixture config bounds");
        }
        Ok(())
    }
}

pub fn fixture_spec_limits() -> EffectiveSpecLimits {
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
    }
}
