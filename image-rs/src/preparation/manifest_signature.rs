// SPDX-License-Identifier: Apache-2.0

//! Offline, mandatory Cosign verification for one exact manifest digest.
//!
//! This optional profile accepts the existing containers-policy `sigstoreSigned`
//! rule and Cosign simple-signing payload, with an inline pinned P-256 public
//! key. It performs no registry, key-path, certificate, or transparency lookup.
//! A verified signature is reusable publisher metadata, not fresh admission,
//! encrypted-content verification, a preparation record, or a rootfs lease.

use base64::{engine::general_purpose::STANDARD, Engine};
// Use the same Reference type reexported by oci-client, without a registry/TLS
// client dependency in this offline verifier.
use oci_spec::distribution::Reference;
use serde::{de, Deserialize, Deserializer};
use sha2::{Digest, Sha256, Sha384};
use sigstore::crypto::{CosignVerificationKey, Signature, SigningScheme};
use std::{collections::BTreeMap, fmt};

const COSIGN_TYPE: &str = "cosign container image signature";
const MAX_JSON_DEPTH: usize = 16;

/// Constructor-owned budgets, never selected by received signature metadata.
#[derive(Clone, Copy)]
pub struct SignatureLimits {
    pub policy_bytes: usize,
    pub key_bytes: usize,
    pub manifest_bytes: usize,
    pub payload_bytes: usize,
    pub signature_bytes: usize,
    pub json_depth: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignatureError {
    InvalidConfiguration,
    TooLarge,
    TooDeep,
    MalformedPolicy,
    PolicyHashMismatch,
    UnsupportedPolicy,
    InvalidKey,
    InvalidManifestDigest,
    ManifestDigestMismatch,
    MalformedPayload,
    InvalidSignature,
    PayloadTypeMismatch,
    RepositoryMismatch,
    PayloadDigestMismatch,
}

impl fmt::Display for SignatureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidConfiguration => "manifest signature configuration rejected",
            Self::TooLarge => "manifest signature input exceeds configured bounds",
            Self::TooDeep => "manifest signature JSON exceeds depth budget",
            Self::MalformedPolicy => "manifest signature policy rejected",
            Self::PolicyHashMismatch => "manifest signature policy commitment differs",
            Self::UnsupportedPolicy => "manifest signature policy profile unsupported",
            Self::InvalidKey => "manifest signature pinned key rejected",
            Self::InvalidManifestDigest => "manifest signature digest encoding rejected",
            Self::ManifestDigestMismatch => "manifest bytes differ from the admitted digest",
            Self::MalformedPayload => "manifest signature payload rejected",
            Self::InvalidSignature => "manifest cryptographic signature rejected",
            Self::PayloadTypeMismatch => "manifest signature payload type differs",
            Self::RepositoryMismatch => "manifest signature repository differs",
            Self::PayloadDigestMismatch => "signed digest differs from the selected manifest",
        })
    }
}
impl std::error::Error for SignatureError {}

/// One requiring policy and actual public key, constructed from trusted bytes.
/// No general-policy `Ok(())`, caller callback, or mutable SignatureLayer is used.
pub struct RequiredCosignPolicy {
    repository: String,
    policy_sha384: String,
    key_sha384: String,
    policy_bytes: Vec<u8>,
    key_bytes: Vec<u8>,
    key: CosignVerificationKey,
    limits: SignatureLimits,
}

/// Actual signature verification and claims from the same authenticated bytes.
/// Private construction; no Clone, Deserialize, or raw Debug implementation.
/// This object does not consume admission or permit content preparation/start.
pub struct VerifiedManifestSignature {
    manifest_sha256: String,
    policy_sha384: String,
    key_sha384: String,
    payload_sha384: String,
    signature_sha384: String,
    repository: String,
}

impl VerifiedManifestSignature {
    pub fn manifest_sha256(&self) -> &str {
        &self.manifest_sha256
    }
    pub fn policy_sha384(&self) -> &str {
        &self.policy_sha384
    }
    pub fn key_sha384(&self) -> &str {
        &self.key_sha384
    }
    pub fn payload_sha384(&self) -> &str {
        &self.payload_sha384
    }
    pub fn signature_sha384(&self) -> &str {
        &self.signature_sha384
    }
    pub fn repository(&self) -> &str {
        &self.repository
    }
}

impl RequiredCosignPolicy {
    pub fn policy_sha384(&self) -> &str {
        &self.policy_sha384
    }
    pub fn key_sha384(&self) -> &str {
        &self.key_sha384
    }
    pub fn repository(&self) -> &str {
        &self.repository
    }
    /// Exact bounded public policy snapshot used to construct this verifier.
    pub fn policy_bytes(&self) -> &[u8] {
        &self.policy_bytes
    }
    /// Exact decoded public PEM snapshot, already covered by the inline policy.
    pub fn key_bytes(&self) -> &[u8] {
        &self.key_bytes
    }

    /// Supported subset: one `reject` default and one exact docker-repository
    /// `sigstoreSigned` rule with inline canonical Base64 PEM and exactRepository.
    /// Expected policy digest/repository originate outside the received bundle.
    pub fn new(
        policy_bytes: &[u8],
        expected_policy_sha384: &str,
        trusted_repository: &str,
        limits: SignatureLimits,
    ) -> Result<Self, SignatureError> {
        validate_limits(limits)?;
        if !hex_digest(expected_policy_sha384, 96)
            || trusted_repository.len() > limits.policy_bytes
            || !canonical_repository(trusted_repository)
        {
            return Err(SignatureError::InvalidConfiguration);
        }
        bounded(policy_bytes, limits.policy_bytes)?;
        let policy_sha384 = sha384(policy_bytes);
        if policy_sha384 != expected_policy_sha384 {
            return Err(SignatureError::PolicyHashMismatch);
        }
        check_depth(policy_bytes, limits.json_depth)?;
        let policy: Policy =
            serde_json::from_slice(policy_bytes).map_err(|_| SignatureError::MalformedPolicy)?;
        if policy.default.len() != 1 || policy.default[0].kind != "reject" {
            return Err(SignatureError::UnsupportedPolicy);
        }
        let mut scopes = policy.transports.docker;
        if scopes.len() != 1 {
            return Err(SignatureError::UnsupportedPolicy);
        }
        let mut requirements = scopes
            .remove(trusted_repository)
            .ok_or(SignatureError::UnsupportedPolicy)?;
        if requirements.len() != 1 {
            return Err(SignatureError::UnsupportedPolicy);
        }
        let rule = requirements
            .pop()
            .ok_or(SignatureError::UnsupportedPolicy)?;
        if rule.kind != "sigstoreSigned"
            || rule.signed_identity.kind != "exactRepository"
            || rule.signed_identity.repository != trusted_repository
        {
            return Err(SignatureError::UnsupportedPolicy);
        }
        let key_bytes = decode_key(&rule.key_data, limits.key_bytes)?;
        let key =
            CosignVerificationKey::from_pem(&key_bytes, &SigningScheme::ECDSA_P256_SHA256_ASN1)
                .map_err(|_| SignatureError::InvalidKey)?;
        Ok(Self {
            repository: trusted_repository.to_owned(),
            policy_sha384,
            key_sha384: sha384(&key_bytes),
            policy_bytes: policy_bytes.to_vec(),
            key_bytes,
            key,
            limits,
        })
    }

    /// Verify the standard Cosign payload's raw P-256 ASN.1 signature, then
    /// parse claims from those exact bytes. The expected digest is bare lowercase
    /// SHA256; no tag resolution or manifest-list fallback is performed.
    pub fn verify(
        &self,
        raw_manifest: &[u8],
        expected_selected_manifest_sha256: &str,
        raw_payload: &[u8],
        raw_signature: &[u8],
    ) -> Result<VerifiedManifestSignature, SignatureError> {
        if !hex_digest(expected_selected_manifest_sha256, 64) {
            return Err(SignatureError::InvalidManifestDigest);
        }
        bounded(raw_manifest, self.limits.manifest_bytes)?;
        bounded(raw_payload, self.limits.payload_bytes)?;
        bounded(raw_signature, self.limits.signature_bytes)?;
        let manifest_sha256 = sha256(raw_manifest);
        if manifest_sha256 != expected_selected_manifest_sha256 {
            return Err(SignatureError::ManifestDigestMismatch);
        }
        check_depth(raw_payload, self.limits.json_depth)?;
        self.key
            .verify_signature(Signature::Raw(raw_signature), raw_payload)
            .map_err(|_| SignatureError::InvalidSignature)?;
        let payload: Payload =
            serde_json::from_slice(raw_payload).map_err(|_| SignatureError::MalformedPayload)?;
        if payload.critical.kind != COSIGN_TYPE {
            return Err(SignatureError::PayloadTypeMismatch);
        }
        if payload.critical.identity.repository != self.repository {
            return Err(SignatureError::RepositoryMismatch);
        }
        let expected = format!("sha256:{expected_selected_manifest_sha256}");
        if payload.critical.image.digest != expected {
            return Err(SignatureError::PayloadDigestMismatch);
        }
        Ok(VerifiedManifestSignature {
            manifest_sha256,
            policy_sha384: self.policy_sha384.clone(),
            key_sha384: self.key_sha384.clone(),
            payload_sha384: sha384(raw_payload),
            signature_sha384: sha384(raw_signature),
            repository: self.repository.clone(),
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Policy {
    default: Vec<DefaultRule>,
    transports: Transports,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DefaultRule {
    #[serde(rename = "type")]
    kind: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Transports {
    #[serde(deserialize_with = "unique_scopes")]
    docker: BTreeMap<String, Vec<CosignRule>>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CosignRule {
    #[serde(rename = "type")]
    kind: String,
    #[serde(rename = "keyData")]
    key_data: String,
    #[serde(rename = "signedIdentity")]
    signed_identity: SignedIdentity,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedIdentity {
    #[serde(rename = "type")]
    kind: String,
    #[serde(rename = "dockerRepository")]
    repository: String,
}

// The existing Cosign simple-signing JSON schema, with strict critical members.
// Optional publisher metadata is bounded and does not influence authorization.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Payload {
    critical: Critical,
    #[serde(rename = "optional")]
    _optional: Option<serde_json::Value>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Critical {
    #[serde(rename = "type")]
    kind: String,
    image: Image,
    identity: Identity,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Image {
    #[serde(rename = "docker-manifest-digest")]
    digest: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Identity {
    #[serde(rename = "docker-reference")]
    repository: String,
}

fn canonical_repository(value: &str) -> bool {
    if value.is_empty() || !value.is_ascii() {
        return false;
    }
    let pinned = format!("{value}@sha256:{}", "0".repeat(64));
    let Ok(reference) = pinned.parse::<Reference>() else {
        return false;
    };
    reference.tag().is_none()
        && format!("{}/{}", reference.registry(), reference.repository()) == value
}

fn validate_limits(limits: SignatureLimits) -> Result<(), SignatureError> {
    if [
        limits.policy_bytes,
        limits.key_bytes,
        limits.manifest_bytes,
        limits.payload_bytes,
        limits.signature_bytes,
        limits.json_depth,
    ]
    .contains(&0)
        || limits.json_depth > MAX_JSON_DEPTH
    {
        return Err(SignatureError::InvalidConfiguration);
    }
    Ok(())
}

fn bounded(bytes: &[u8], limit: usize) -> Result<(), SignatureError> {
    if bytes.is_empty() || bytes.len() > limit {
        return Err(SignatureError::TooLarge);
    }
    Ok(())
}

fn decode_key(value: &str, limit: usize) -> Result<Vec<u8>, SignatureError> {
    let encoded_limit = limit
        .div_ceil(3)
        .checked_mul(4)
        .ok_or(SignatureError::InvalidConfiguration)?;
    if value.len() > encoded_limit {
        return Err(SignatureError::TooLarge);
    }
    let bytes = STANDARD
        .decode(value)
        .map_err(|_| SignatureError::InvalidKey)?;
    bounded(&bytes, limit)?;
    if STANDARD.encode(&bytes) != value {
        return Err(SignatureError::InvalidKey);
    }
    Ok(bytes)
}

// Allocation-free structural depth budget. Serde performs the full JSON syntax
// validation later; braces and escapes within strings do not consume depth.
fn check_depth(bytes: &[u8], max: usize) -> Result<(), SignatureError> {
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for &byte in bytes {
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
        } else {
            match byte {
                b'"' => in_string = true,
                b'{' | b'[' => {
                    depth += 1;
                    if depth > max {
                        return Err(SignatureError::TooDeep);
                    }
                }
                b'}' | b']' => depth = depth.saturating_sub(1),
                _ => {}
            }
        }
    }
    Ok(())
}

fn unique_scopes<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<BTreeMap<String, Vec<CosignRule>>, D::Error> {
    struct UniqueScopes;
    impl<'de> de::Visitor<'de> for UniqueScopes {
        type Value = BTreeMap<String, Vec<CosignRule>>;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("unique exact repository scopes")
        }
        fn visit_map<M: de::MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
            let mut scopes = BTreeMap::new();
            while let Some((key, value)) = map.next_entry()? {
                if scopes.insert(key, value).is_some() {
                    return Err(de::Error::custom("duplicate repository scope"));
                }
            }
            Ok(scopes)
        }
    }
    deserializer.deserialize_map(UniqueScopes)
}

fn hex_digest(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
fn sha384(bytes: &[u8]) -> String {
    Sha384::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
#[path = "manifest_signature_tests.rs"]
mod tests;
