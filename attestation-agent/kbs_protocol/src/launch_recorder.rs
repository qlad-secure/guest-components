//! Guest-owned launch keys, fixed TDX evidence collection, and credential consumption.
//!
//! Keys remain in this process. Measured key origin, isolation from other guest
//! users, and protected execution records require separate enforcement. Evidence
//! collection uses TDX without a Sample fallback.
//! The trusted owner pins the complete aggregate after learning the recorder
//! session, including AS/claims-derived commitments. Received JSON cannot select
//! these expectations.

use crate::keypair::{TeeKeyAlgorithm, TeeKeyPair};
#[cfg(any(feature = "launch-recorder-tdx", test))]
use attester::{Attester, InitDataResult};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use execution_proof_client::{ClientError, ClientProtocol, VerifiedCredentialResponse};
use execution_proof_contract::{
    GrantExpectations, LaunchBinding,
    credential::{
        DeliveryExpectations, MAX_CREDENTIAL_BYTES, MAX_CREDENTIAL_JWE_BYTES,
        VerifiedCredentialDelivery,
    },
    policy_receipt::{
        AggregateExpectations, POLICY_AGGREGATE_PROFILE, POLICY_AGGREGATE_PURPOSE,
        POLICY_AGGREGATE_VERSION, ResourcePolicyRequest,
    },
};
use ring::{
    digest,
    rand::SystemRandom,
    signature::{Ed25519KeyPair, KeyPair},
};
use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecorderError {
    Client(ClientError),
    InvalidConfig,
    Crypto,
    AttesterUnavailable,
    InitDataMismatch,
    AttestationFailed,
    InvalidEvidence,
    TooLarge,
    NotReady,
    Conflict,
    BindingMismatch,
    InvalidCredential,
    AlreadyConsumed,
}
impl fmt::Display for RecorderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "launch recorder rejected: {self:?}")
    }
}
impl std::error::Error for RecorderError {}
impl From<ClientError> for RecorderError {
    fn from(error: ClientError) -> Self {
        Self::Client(error)
    }
}

/// Trusted static scope. This is not an RPC payload or an inferred server result.
pub struct RecorderConfig {
    pub grant: GrantExpectations,
    pub expected_init: [u8; 48],
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
pub struct LaunchKeys {
    recorder: Ed25519KeyPair,
    keywrap: TeeKeyPair,
}
impl LaunchKeys {
    pub fn generate() -> Result<Self, RecorderError> {
        let encoded = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
            .map_err(|_| RecorderError::Crypto)?;
        let recorder =
            Ed25519KeyPair::from_pkcs8(encoded.as_ref()).map_err(|_| RecorderError::Crypto)?;
        let keywrap = TeeKeyPair::new_with_algorithm(TeeKeyAlgorithm::RsaOaep256)
            .map_err(|_| RecorderError::Crypto)?;
        Ok(Self { recorder, keywrap })
    }
    pub fn recorder_public_key(&self) -> [u8; 32] {
        self.recorder
            .public_key()
            .as_ref()
            .try_into()
            .expect("Ed25519 public key is 32 bytes")
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
        config: RecorderConfig,
    ) -> Result<LaunchRecorder, RecorderError> {
        validate_config(&config)?;
        if config.kbs_proof_public_key == [0; 32]
            || config.kbs_proof_public_key == config.grant.authority_public_key
            || config.kbs_proof_public_key == self.recorder_public_key()
        {
            return Err(RecorderError::InvalidConfig);
        }
        // Explicit bridge of the supported RSA wire fields between GC 0.18 and
        // the launch protocol's 0.15 types. New variants are never coerced.
        let legacy_key = match self.keywrap_public_key()? {
            kbs_types::TeePubKey::RSA { alg, k_mod, k_exp } if alg == "RSA-OAEP-256" => {
                legacy_kbs_types::TeePubKey::RSA { alg, k_mod, k_exp }
            }
            _ => return Err(RecorderError::Crypto),
        };
        let canonical =
            serde_json_canonicalizer::to_vec(&legacy_key).map_err(|_| RecorderError::Crypto)?;
        let keywrap_sha384 = hash(&canonical);
        let client = ClientProtocol::new_authority_time(
            signed_grant,
            &config.grant,
            self.recorder,
            legacy_key,
            config.expected_init,
        )?;
        Ok(LaunchRecorder {
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

pub struct LaunchRecorder {
    client: ClientProtocol,
    keywrap: TeeKeyPair,
    keywrap_sha384: String,
    config: RecorderConfig,
    expected: Option<AggregateExpectations>,
    evidence: Option<Vec<u8>>,
    capture_request: Option<Vec<u8>>,
    request: Option<ResourcePolicyRequest>,
    consumed: bool,
}

impl LaunchRecorder {
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

    /// Only this fixed production factory can collect new evidence. No public
    /// attester/callback or caller-selected report data is accepted.
    pub async fn collect_capture_request(&mut self) -> Result<Vec<u8>, RecorderError> {
        if let Some(request) = &self.capture_request {
            return Ok(request.clone());
        }
        #[cfg(feature = "launch-recorder-tdx")]
        {
            let attester = attester::BoxedAttester::try_from(kbs_types::Tee::Tdx)
                .map_err(|_| RecorderError::AttesterUnavailable)?;
            self.collect_with(attester.as_ref()).await
        }
        #[cfg(not(feature = "launch-recorder-tdx"))]
        Err(RecorderError::AttesterUnavailable)
    }

    // Tests implement the attester trait privately. Production evidence
    // collection uses the fixed TDX factory above.
    #[cfg(any(feature = "launch-recorder-tdx", test))]
    async fn collect_with(
        &mut self,
        attester: &(dyn Attester + Send + Sync),
    ) -> Result<Vec<u8>, RecorderError> {
        if let Some(request) = &self.capture_request {
            return Ok(request.clone());
        }
        let report_data = self.client.report_data()?;
        let init = self.client.expected_init_data();
        match attester
            .bind_init_data(&init)
            .await
            .map_err(|_| RecorderError::InitDataMismatch)?
        {
            InitDataResult::Ok => {}
            InitDataResult::Unsupported => return Err(RecorderError::InitDataMismatch),
        }
        let evidence = attester
            .get_evidence(report_data.to_vec())
            .await
            .map_err(|_| RecorderError::AttestationFailed)?;
        if !evidence.is_object() {
            return Err(RecorderError::InvalidEvidence);
        }
        let evidence = serde_json::to_vec(&evidence).map_err(|_| RecorderError::InvalidEvidence)?;
        if evidence.len() > execution_proof_client::MAX_EVIDENCE_BYTES {
            return Err(RecorderError::TooLarge);
        }
        let request = self.client.capture_request(&evidence)?;
        self.evidence = Some(evidence);
        self.capture_request = Some(request.clone());
        Ok(request)
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
        expected: AggregateExpectations,
    ) -> Result<(), RecorderError> {
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
            || statement.init_data_sha384 != hex(&config.expected_init)
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
    ) -> Result<AttemptCredential, RecorderError> {
        if self.consumed {
            return Err(RecorderError::AlreadyConsumed);
        }
        let expected = self.expected.as_ref().ok_or(RecorderError::NotReady)?;
        let delivery = DeliveryExpectations {
            aggregate: AggregateExpectations {
                kbs_proof_public_key: expected.kbs_proof_public_key,
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
        let jwe = strict_jwe(response.jwe_bytes())?;
        let secret = Zeroizing::new(
            self.keywrap
                .decrypt_response(jwe)
                .map_err(|_| RecorderError::InvalidCredential)?,
        );
        if secret.is_empty() || secret.len() > MAX_CREDENTIAL_BYTES {
            return Err(RecorderError::InvalidCredential);
        }
        Ok(AttemptCredential {
            binding: self.client.grant().binding().clone(),
            grant_digest: self.client.grant().grant_digest().into(),
            authority_key_digest: self.client.grant().authority_key_sha384().into(),
            response,
            secret,
        })
    }
}

/// One decrypted, authenticated, attempt-bound secret. No raw Debug/serde/Clone.
pub struct AttemptCredential {
    binding: LaunchBinding,
    grant_digest: String,
    authority_key_digest: String,
    response: VerifiedCredentialResponse,
    secret: Zeroizing<Vec<u8>>,
}
impl AttemptCredential {
    pub fn binding(&self) -> &LaunchBinding {
        &self.binding
    }
    pub fn grant_digest(&self) -> &str {
        &self.grant_digest
    }
    pub fn authority_key_sha384(&self) -> &str {
        &self.authority_key_digest
    }
    pub fn delivery(&self) -> &VerifiedCredentialDelivery {
        self.response.delivery()
    }
    pub fn into_secret(self) -> Zeroizing<Vec<u8>> {
        self.secret
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StrictJwe {
    protected: String,
    encrypted_key: String,
    iv: String,
    ciphertext: String,
    tag: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StrictHeader {
    alg: String,
    enc: String,
}

pub(super) fn strict_jwe(bytes: &[u8]) -> Result<kbs_types::Response, RecorderError> {
    if bytes.len() > MAX_CREDENTIAL_JWE_BYTES {
        return Err(RecorderError::TooLarge);
    }
    let wire: StrictJwe =
        serde_json::from_slice(bytes).map_err(|_| RecorderError::InvalidCredential)?;
    let header_bytes = canonical_url(&wire.protected, 256)?;
    let header: StrictHeader =
        serde_json::from_slice(&header_bytes).map_err(|_| RecorderError::InvalidCredential)?;
    if header.alg != "RSA-OAEP-256"
        || header.enc != "A256GCM"
        || serde_json::to_vec(&header).map_err(|_| RecorderError::InvalidCredential)?
            != header_bytes
        || canonical_url(&wire.encrypted_key, 256)?.len() != 256
        || canonical_url(&wire.iv, 12)?.len() != 12
        || canonical_url(&wire.tag, 16)?.len() != 16
        || canonical_url(&wire.ciphertext, MAX_CREDENTIAL_BYTES)?.is_empty()
    {
        return Err(RecorderError::InvalidCredential);
    }
    // Parse the actual GC 0.18 Response only after strict shared-wire validation.
    serde_json::from_slice(bytes).map_err(|_| RecorderError::InvalidCredential)
}
fn canonical_url(value: &str, max: usize) -> Result<Vec<u8>, RecorderError> {
    if value.len() > max.div_ceil(3) * 4 {
        return Err(RecorderError::TooLarge);
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| RecorderError::InvalidCredential)?;
    if decoded.len() > max {
        return Err(RecorderError::TooLarge);
    }
    if URL_SAFE_NO_PAD.encode(&decoded) != value {
        return Err(RecorderError::InvalidCredential);
    }
    Ok(decoded)
}
fn validate_config(config: &RecorderConfig) -> Result<(), RecorderError> {
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
#[path = "launch_recorder/test_support.rs"]
pub(crate) mod test_support;
