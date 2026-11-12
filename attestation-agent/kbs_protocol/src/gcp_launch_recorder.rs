//! Guest-owned launch keys, fixed TDX evidence collection, and credential consumption.
//!
//! Keys remain in this process. Measured key origin, isolation from other guest
//! users, and protected execution records require separate enforcement. Evidence
//! collection uses TDX without a Sample fallback.
//! The trusted owner pins the complete aggregate after learning the recorder
//! session, including AS/claims-derived commitments. Received JSON cannot select
//! these expectations.

use crate::keypair::{TeeKeyAlgorithm, TeeKeyPair};
use execution_proof_client::gcp::{GcpClientProtocol, VerifiedGcpCredentialResponse};
use execution_proof_contract::{
    gcp_boot_binding::GcpBootBindingV1,
    gcp_bootstrap::{
        self, GcpBootstrapBinding, GcpBootstrapChallenge, GCP_BOOTSTRAP_BINDING_PURPOSE,
        GCP_BOOTSTRAP_VERSION,
    },
    gcp_session::GcpLaunchEvidence,
    policy_receipt::ResourcePolicyRequest,
};
use execution_proof_contract::{
    gcp_credential::{
        GcpDeliveryExpectations, VerifiedGcpCredentialDelivery, MAX_CREDENTIAL_BYTES,
    },
    gcp_policy_receipt::{
        GcpAggregateExpectations, POLICY_AGGREGATE_PROFILE, POLICY_AGGREGATE_PURPOSE,
        POLICY_AGGREGATE_VERSION,
    },
    GrantExpectations, LaunchBinding,
};
use ring::{
    digest,
    rand::{SecureRandom, SystemRandom},
    signature::{Ed25519KeyPair, KeyPair},
};
use zeroize::Zeroizing;

pub use super::launch_recorder::RecorderError;

/// Trusted static scope. This is not an RPC payload or an inferred server result.
pub struct GcpRecorderConfig {
    pub grant: GrantExpectations,
    pub expected_boot_binding: GcpBootBindingV1,
    pub kbs_proof_public_key: [u8; 32],
    pub aggregate_audience: String,
    pub aggregate_issuer: String,
    pub as_policy_id: String,
    pub as_policy_sha384: String,
    pub as_data_sha384: Option<String>,
    pub kbs_policy_id: String,
    pub kbs_policy_sha384: String,
    pub resource_path: [String; 3],
    pub workflow_id: String,
    pub delivery_audience: String,
    pub delivery_issuer: String,
}

/// Neither Clone/Debug nor a PEM import/export API is exposed.
pub struct GcpLaunchKeys {
    recorder: Ed25519KeyPair,
    keywrap: TeeKeyPair,
    boot_binding: GcpBootBindingV1,
    boot_id: String,
    boot_nonce_hex: String,
    pending: Option<(GcpBootstrapChallenge, [u8; 32])>,
    capture: Option<GcpBootstrapCapture>,
}
/// Public authenticated capture data only; not a boot/producer capability.
pub struct GcpBootstrapCapture {
    pub challenge: GcpBootstrapChallenge,
    pub binding: GcpBootstrapBinding,
    pub evidence: GcpLaunchEvidence,
    pub context_sha384: String,
}
impl GcpLaunchKeys {
    pub fn generate(boot_binding: GcpBootBindingV1) -> Result<Self, RecorderError> {
        boot_binding
            .validate()
            .map_err(|_| RecorderError::InvalidConfig)?;
        let random = SystemRandom::new();
        let encoded = Ed25519KeyPair::generate_pkcs8(&random).map_err(|_| RecorderError::Crypto)?;
        let recorder =
            Ed25519KeyPair::from_pkcs8(encoded.as_ref()).map_err(|_| RecorderError::Crypto)?;
        let keywrap = TeeKeyPair::new_with_algorithm(TeeKeyAlgorithm::RsaOaep256)
            .map_err(|_| RecorderError::Crypto)?;
        let mut boot_id = [0; 32];
        let mut boot_nonce = [0; 32];
        random
            .fill(&mut boot_id)
            .map_err(|_| RecorderError::Crypto)?;
        random
            .fill(&mut boot_nonce)
            .map_err(|_| RecorderError::Crypto)?;
        if boot_id == [0; 32] || boot_nonce == [0; 32] {
            return Err(RecorderError::Crypto);
        }
        Ok(Self {
            recorder,
            keywrap,
            boot_binding,
            boot_id: hex(&boot_id),
            boot_nonce_hex: hex(&boot_nonce),
            pending: None,
            capture: None,
        })
    }
    pub fn boot_id(&self) -> &str {
        &self.boot_id
    }
    pub fn boot_nonce_hex(&self) -> &str {
        &self.boot_nonce_hex
    }
    /// Synchronous owned call: the caller must retain ownership until kernel I/O
    /// returns. No background task, RPC or cancellation/timeout guarantee exists.
    pub fn collect_bootstrap(
        &mut self,
        signed: &[u8],
        expected: &GcpBootstrapChallenge,
        authority: &[u8; 32],
    ) -> Result<&GcpBootstrapCapture, RecorderError> {
        let challenge = gcp_bootstrap::verify_challenge_signature(signed, authority, expected)
            .map_err(|_| RecorderError::BindingMismatch)?;
        if challenge.boot_binding != self.boot_binding {
            return Err(RecorderError::BindingMismatch);
        }
        if let Some((prior, key)) = &self.pending {
            if prior != &challenge || key != authority {
                return Err(RecorderError::Conflict);
            }
        } else {
            self.pending = Some((challenge.clone(), *authority));
        }
        if self.capture.is_none() {
            let canonical = serde_json_canonicalizer::to_vec(&self.legacy_key()?)
                .map_err(|_| RecorderError::Crypto)?;
            let binding = GcpBootstrapBinding {
                version: GCP_BOOTSTRAP_VERSION,
                purpose: GCP_BOOTSTRAP_BINDING_PURPOSE.into(),
                challenge_sha384: challenge
                    .digest_sha384()
                    .map_err(|_| RecorderError::InvalidConfig)?,
                boot_binding_sha384: self
                    .boot_binding
                    .digest_sha384()
                    .map_err(|_| RecorderError::InvalidConfig)?,
                boot_id: self.boot_id.clone(),
                boot_nonce_hex: self.boot_nonce_hex.clone(),
                recorder_key_sha384: hash(&self.recorder_public_key()),
                keywrap_key_sha384: hash(&canonical),
            };
            let report = gcp_bootstrap::report_data(&challenge, &binding)
                .map_err(|_| RecorderError::InvalidConfig)?;
            let evidence = collect_fixed(report)?;
            let context_sha384 =
                gcp_bootstrap::bootstrap_context_sha384(&challenge, &binding, &evidence)
                    .map_err(|_| RecorderError::InvalidEvidence)?;
            self.capture = Some(GcpBootstrapCapture {
                challenge,
                binding,
                evidence,
                context_sha384,
            });
        }
        self.capture.as_ref().ok_or(RecorderError::NotReady)
    }
    fn legacy_key(&self) -> Result<legacy_kbs_types::TeePubKey, RecorderError> {
        match self.keywrap_public_key()? {
            kbs_types::TeePubKey::RSA { alg, k_mod, k_exp } if alg == "RSA-OAEP-256" => {
                Ok(legacy_kbs_types::TeePubKey::RSA { alg, k_mod, k_exp })
            }
            _ => Err(RecorderError::Crypto),
        }
    }
    pub fn recorder_public_key(&self) -> [u8; 32] {
        self.recorder
            .public_key()
            .as_ref()
            .try_into()
            .expect("Ed25519 public key is 32 bytes")
    }

    /// Sign only the owner's immutable captured bootstrap context. This is not
    /// an arbitrary signing API, a grant, or a hardware appraisal.
    pub fn bootstrap_possession_signature(&self) -> Result<String, RecorderError> {
        let capture = self.capture.as_ref().ok_or(RecorderError::NotReady)?;
        let bytes = gcp_bootstrap::bootstrap_possession_signing_bytes(
            &capture.challenge,
            &capture.binding,
            &capture.evidence,
        )
        .map_err(|_| RecorderError::BindingMismatch)?;
        Ok(hex(self.recorder.sign(&bytes).as_ref()))
    }
    pub fn keywrap_public_key(&self) -> Result<kbs_types::TeePubKey, RecorderError> {
        self.keywrap
            .export_pubkey()
            .map_err(|_| RecorderError::Crypto)
    }
    /// Authenticate the authority grant without relying on a guest wall clock.
    /// Live time is checked by the authority before its admission is committed.
    pub fn into_recorder(
        self,
        signed_grant: Vec<u8>,
        config: GcpRecorderConfig,
    ) -> Result<GcpLaunchRecorder, RecorderError> {
        validate_config(&config)?;
        if config.kbs_proof_public_key == [0; 32]
            || config.kbs_proof_public_key == config.grant.authority_public_key
            || config.kbs_proof_public_key == self.recorder_public_key()
        {
            return Err(RecorderError::InvalidConfig);
        }
        let legacy_key = self.legacy_key()?;
        let canonical =
            serde_json_canonicalizer::to_vec(&legacy_key).map_err(|_| RecorderError::Crypto)?;
        let keywrap_sha384 = hash(&canonical);
        let capture = self.capture.as_ref().ok_or(RecorderError::NotReady)?;
        if config.expected_boot_binding != self.boot_binding
            || self.pending.as_ref().map(|(_, key)| *key) != Some(config.grant.authority_public_key)
        {
            return Err(RecorderError::BindingMismatch);
        }
        let grant =
            execution_proof_contract::verify_launch_grant_historical(&signed_grant, &config.grant)
                .map_err(|_| RecorderError::BindingMismatch)?;
        let scope = grant.binding();
        let challenge = &capture.challenge;
        if scope.authority != challenge.authority
            || scope.tenant != challenge.tenant
            || scope.workload_id != challenge.workload_id
            || scope.attempt_id != challenge.attempt_id
            || scope.boot_id != self.boot_id
            || scope.channel_key_sha384 != hash(&self.recorder_public_key())
            || scope.bootstrap_context_sha384 != capture.context_sha384
        {
            return Err(RecorderError::BindingMismatch);
        }
        let client = GcpClientProtocol::new_authority_time(
            signed_grant,
            &config.grant,
            self.recorder,
            legacy_key,
            config.expected_boot_binding.clone(),
        )?;
        Ok(GcpLaunchRecorder {
            client,
            keywrap: self.keywrap,
            keywrap_sha384,
            config,
            expected: None,
            evidence: None,
            capture_request: None,
            request: None,
            consumed: false,
        })
    }
}

pub struct GcpLaunchRecorder {
    client: GcpClientProtocol,
    keywrap: TeeKeyPair,
    keywrap_sha384: String,
    config: GcpRecorderConfig,
    expected: Option<GcpAggregateExpectations>,
    evidence: Option<Vec<u8>>,
    capture_request: Option<Vec<u8>>,
    request: Option<ResourcePolicyRequest>,
    consumed: bool,
}

impl GcpLaunchRecorder {
    pub fn begin_request(&self) -> Result<Vec<u8>, RecorderError> {
        Ok(self.client.begin_request()?)
    }
    pub fn accept_begin_response(&mut self, bytes: &[u8]) -> Result<(), RecorderError> {
        Ok(self.client.accept_begin_response(bytes)?)
    }
    pub fn session_id(&self) -> Option<&str> {
        self.client.session_id()
    }
    pub fn quote_nonce(&self) -> Option<&str> {
        self.client.quote_nonce()
    }
    pub fn request_nonce(&self) -> Option<&str> {
        self.client.request_nonce()
    }
    pub fn keywrap_sha384(&self) -> &str {
        &self.keywrap_sha384
    }

    /// Fixed synchronous GCP collection; no init-data operation or fallback.
    pub fn collect_capture_request(&mut self) -> Result<Vec<u8>, RecorderError> {
        if let Some(request) = &self.capture_request {
            return Ok(request.clone());
        }
        let evidence = collect_fixed(self.client.report_data_full64()?)?
            .encode()
            .map_err(|_| RecorderError::InvalidEvidence)?;
        let request = self.client.capture_request(&evidence)?;
        self.evidence = Some(evidence);
        self.capture_request = Some(request.clone());
        Ok(request)
    }
    pub fn report_data(&self) -> Result<[u8; 48], RecorderError> {
        Ok(self.client.report_data()?)
    }
    pub fn boot_binding(&self) -> &GcpBootBindingV1 {
        &self.config.expected_boot_binding
    }
    pub fn report_data_full64(&self) -> Result<[u8; 64], RecorderError> {
        Ok(self.client.report_data_full64()?)
    }

    pub fn resource_challenge_request(&self) -> Result<Vec<u8>, RecorderError> {
        Ok(self.client.resource_challenge_request()?)
    }
    pub fn accept_resource_challenge_response(
        &mut self,
        bytes: &[u8],
    ) -> Result<(), RecorderError> {
        Ok(self.client.accept_resource_challenge_response(bytes)?)
    }
    pub fn resource_decision_request(
        &mut self,
        request: &ResourcePolicyRequest,
    ) -> Result<Vec<u8>, RecorderError> {
        if request.resource_path != self.config.resource_path
            || request.workflow_id != self.config.workflow_id
        {
            return Err(RecorderError::BindingMismatch);
        }
        let bytes = self.client.resource_decision_request(request)?;
        if self.request.is_none() {
            self.request = Some(request.clone());
        }
        Ok(bytes)
    }

    /// Trusted one-time provisioning of the complete per-attempt expectation.
    /// This is intentionally not exposed through a host-controlled RPC or JSON.
    pub fn pin_aggregate_expectations(
        &mut self,
        expected: GcpAggregateExpectations,
    ) -> Result<(), RecorderError> {
        if expected.boot_binding != self.config.expected_boot_binding {
            return Err(RecorderError::BindingMismatch);
        }
        let statement = &expected.expected;
        let config = &self.config;
        statement
            .signing_bytes()
            .map_err(|_| RecorderError::InvalidConfig)?;
        let request = self.request.as_ref().ok_or(RecorderError::NotReady)?;
        let evidence = self.evidence.as_ref().ok_or(RecorderError::NotReady)?;
        let grant = self.client.grant();
        if expected.kbs_proof_public_key != config.kbs_proof_public_key
            || statement.version != POLICY_AGGREGATE_VERSION
            || statement.purpose != POLICY_AGGREGATE_PURPOSE
            || statement.profile != POLICY_AGGREGATE_PROFILE
            || statement.audience != config.aggregate_audience
            || statement.issuer != config.aggregate_issuer
            || statement.grant_sha384 != grant.grant_digest()
            || statement.authority_key_sha384 != grant.authority_key_sha384()
            || Some(statement.session_id.as_str()) != self.client.session_id()
            || Some(statement.nonce.as_str()) != self.client.quote_nonce()
            || statement.runtime_sha384 != hex(&self.client.report_data()?)
            || statement.evidence_sha384 != hash(evidence)
            || statement.boot_binding_sha384
                != config
                    .expected_boot_binding
                    .digest_sha384()
                    .map_err(|_| RecorderError::InvalidConfig)?
            || statement.recorder_key_sha384 != grant.binding().channel_key_sha384
            || &statement.request != request
            || statement.as_evaluation.policy_id != config.as_policy_id
            || statement.as_evaluation.policy_sha384 != config.as_policy_sha384
            || statement.as_evaluation.data_sha384 != config.as_data_sha384
            || statement.kbs_evaluation.policy_id != config.kbs_policy_id
            || statement.kbs_evaluation.policy_sha384 != config.kbs_policy_sha384
        {
            return Err(RecorderError::BindingMismatch);
        }
        if let Some(prior) = &self.expected {
            return if prior.kbs_proof_public_key == expected.kbs_proof_public_key
                && prior.expected == expected.expected
            {
                Ok(())
            } else {
                Err(RecorderError::Conflict)
            };
        }
        self.expected = Some(expected);
        Ok(())
    }

    /// Authenticate a KBS response before deriving its per-session commitments.
    /// Static policy, resource and locally captured session scope remain selected
    /// by this recorder's immutable configuration, never by the response.
    pub fn pin_signed_aggregate(
        &mut self,
        bytes: &[u8],
    ) -> Result<GcpAggregateExpectations, RecorderError> {
        if bytes.is_empty() || bytes.len() > execution_proof_contract::MAX_WIRE_BYTES {
            return Err(RecorderError::BindingMismatch);
        }
        let signed: execution_proof_contract::Signed<
            execution_proof_contract::gcp_policy_receipt::GcpLaunchPolicyAggregateV2,
        > = serde_json::from_slice(bytes).map_err(|_| RecorderError::BindingMismatch)?;
        let expected = GcpAggregateExpectations {
            kbs_proof_public_key: self.config.kbs_proof_public_key,
            boot_binding: self.config.expected_boot_binding.clone(),
            expected: signed.statement,
        };
        execution_proof_contract::gcp_policy_receipt::verify_policy_aggregate(
            bytes,
            self.client.grant(),
            &expected,
        )
        .map_err(|_| RecorderError::BindingMismatch)?;
        self.pin_aggregate_expectations(GcpAggregateExpectations {
            kbs_proof_public_key: expected.kbs_proof_public_key,
            boot_binding: expected.boot_binding.clone(),
            expected: expected.expected.clone(),
        })?;
        Ok(expected)
    }

    /// Sign an admission operation only for the independently pinned, signed
    /// aggregate and this recorder's authority audience. This does not redeem
    /// locally, expose a general signing oracle, or open preparation.
    pub fn policy_admission_request(
        &self,
        aggregate_json: &[u8],
        guest_nonce: &str,
        admission_policy_sha384: &str,
        operation: execution_proof_contract::admission::gcp::GcpAdmissionOperation,
    ) -> Result<Vec<u8>, RecorderError> {
        if self.consumed {
            return Err(RecorderError::AlreadyConsumed);
        }
        let expected = self.expected.as_ref().ok_or(RecorderError::NotReady)?;
        let aggregate = execution_proof_contract::gcp_policy_receipt::verify_policy_aggregate(
            aggregate_json,
            self.client.grant(),
            expected,
        )
        .map_err(|_| RecorderError::BindingMismatch)?;
        Ok(self.client.sign_policy_admission_request(
            &aggregate,
            guest_nonce,
            admission_policy_sha384,
            operation,
        )?)
    }

    pub fn credential_request(&self, aggregate_json: &[u8]) -> Result<Vec<u8>, RecorderError> {
        if self.consumed {
            return Err(RecorderError::AlreadyConsumed);
        }
        Ok(self.client.credential_request(
            aggregate_json,
            self.expected.as_ref().ok_or(RecorderError::NotReady)?,
        )?)
    }

    /// Authenticate historical authority/KBS evidence before opening one secret.
    /// CDH separately requires a fresh gate-minted admission for using it.
    pub fn decrypt_credential_response(
        &mut self,
        response_json: &[u8],
        aggregate_json: &[u8],
    ) -> Result<GcpAttemptCredential, RecorderError> {
        if self.consumed {
            return Err(RecorderError::AlreadyConsumed);
        }
        let expected = self.expected.as_ref().ok_or(RecorderError::NotReady)?;
        let delivery = GcpDeliveryExpectations {
            aggregate: GcpAggregateExpectations {
                kbs_proof_public_key: expected.kbs_proof_public_key,
                boot_binding: self.config.expected_boot_binding.clone(),
                expected: expected.expected.clone(),
            },
            audience: self.config.delivery_audience.clone(),
            issuer: self.config.delivery_issuer.clone(),
            keywrap_sha384: self.keywrap_sha384.clone(),
        };
        // Authenticate the actual producer and exact ciphertext/context before
        // parsing/decrypting a JWE; AEAD alone does not authenticate its sender.
        let response = self.client.verify_credential_response_historical(
            response_json,
            aggregate_json,
            &delivery,
        )?;
        // An authenticated delivery consumes this recorder even when its JWE
        // is malformed or fails decryption. It can never yield another secret.
        self.consumed = true;
        let jwe = super::launch_recorder::strict_jwe(response.jwe_bytes())?;
        let secret = Zeroizing::new(
            self.keywrap
                .decrypt_gcp_credential_response(jwe)
                .map_err(|_| RecorderError::InvalidCredential)?,
        );
        if secret.is_empty() || secret.len() > MAX_CREDENTIAL_BYTES {
            return Err(RecorderError::InvalidCredential);
        }
        Ok(GcpAttemptCredential {
            boot_binding: self.config.expected_boot_binding.clone(),
            binding: self.client.grant().binding().clone(),
            grant_digest: self.client.grant().grant_digest().into(),
            authority_key_digest: self.client.grant().authority_key_sha384().into(),
            response,
            secret,
        })
    }
}

/// One decrypted, authenticated, attempt-bound secret. No raw Debug/serde/Clone.
pub struct GcpAttemptCredential {
    boot_binding: GcpBootBindingV1,
    binding: LaunchBinding,
    grant_digest: String,
    authority_key_digest: String,
    response: VerifiedGcpCredentialResponse,
    secret: Zeroizing<Vec<u8>>,
}
impl GcpAttemptCredential {
    pub fn boot_binding(&self) -> &GcpBootBindingV1 {
        &self.boot_binding
    }
    pub fn binding(&self) -> &LaunchBinding {
        &self.binding
    }
    pub fn grant_digest(&self) -> &str {
        &self.grant_digest
    }
    pub fn authority_key_sha384(&self) -> &str {
        &self.authority_key_digest
    }
    pub fn delivery(&self) -> &VerifiedGcpCredentialDelivery {
        self.response.delivery()
    }
    pub fn into_secret(self) -> Zeroizing<Vec<u8>> {
        self.secret
    }
}

fn collect_fixed(report: [u8; 64]) -> Result<GcpLaunchEvidence, RecorderError> {
    #[cfg(feature = "launch-recorder-gcp-tdx")]
    {
        let raw = attester::gcp_execution_quote::collect_gcp_tdx_execution_evidence(report)
            .map_err(|_| RecorderError::AttesterUnavailable)?;
        GcpLaunchEvidence::new(raw.tdx_quote, raw.ccel_table, raw.ccel_log)
            .map_err(|_| RecorderError::InvalidEvidence)
    }
    #[cfg(not(feature = "launch-recorder-gcp-tdx"))]
    {
        let _ = report;
        Err(RecorderError::AttesterUnavailable)
    }
}
fn validate_config(config: &GcpRecorderConfig) -> Result<(), RecorderError> {
    for value in [
        &config.aggregate_audience,
        &config.aggregate_issuer,
        &config.as_policy_id,
        &config.kbs_policy_id,
        &config.workflow_id,
        &config.delivery_audience,
        &config.delivery_issuer,
    ] {
        if value.is_empty()
            || value.len() > 128
            || !value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
        {
            return Err(RecorderError::InvalidConfig);
        }
    }
    for hash in [&config.as_policy_sha384, &config.kbs_policy_sha384]
        .into_iter()
        .chain(config.as_data_sha384.as_ref())
    {
        if hash.len() != 96
            || !hash
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(RecorderError::InvalidConfig);
        }
    }
    if config.as_policy_sha384 != config.grant.launch_policy_sha384 {
        return Err(RecorderError::InvalidConfig);
    }
    let dummy = ResourcePolicyRequest {
        method: "GET".into(),
        plugin: "resource".into(),
        resource_path: config.resource_path.clone(),
        workflow_id: config.workflow_id.clone(),
        request_nonce: "validation".into(),
    };
    dummy
        .signing_bytes()
        .map_err(|_| RecorderError::InvalidConfig)?;
    Ok(())
}
fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8] = b"0123456789abcdef";
    bytes
        .iter()
        .flat_map(|b| {
            [
                DIGITS[(b >> 4) as usize] as char,
                DIGITS[(b & 15) as usize] as char,
            ]
        })
        .collect()
}
fn hash(bytes: &[u8]) -> String {
    hex(digest::digest(&digest::SHA384, bytes).as_ref())
}

#[cfg(test)]
#[path = "gcp_launch_recorder_tests.rs"]
pub(crate) mod test_support;
