//! Default-off manifest binding scoped to an admitted attempt.
//!
//! A BoundManifestPlan binds raw metadata to one admitted attempt. The separate
//! content feature adds mandatory signature verification and fresh, attempt-owned
//! GCP content checks and optional private layer staging. These states do not
//! establish immutable rootfs custody or launch permission.

use base64::{engine::general_purpose::STANDARD, Engine};
use execution_proof_contract::{LaunchBinding, ValidityWindow};
use execution_proof_handoff::admission::AcceptedAttemptContext;
use kbs_protocol::launch_recorder::AttemptCredential;
use percent_encoding::{percent_decode_str, utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
use serde::{de, Deserialize, Deserializer};
use sha2::{Digest, Sha256, Sha384};
use std::{collections::BTreeMap, fmt};

#[cfg(feature = "launch-preparation-content")]
#[path = "launch_preparation/content.rs"]
mod content;
#[cfg(feature = "launch-preparation-runtime")]
#[path = "launch_preparation/runtime.rs"]
pub mod runtime;
#[cfg(feature = "launch-preparation-content")]
#[path = "launch_preparation/staging.rs"]
mod staging;
#[cfg(feature = "launch-preparation-custody")]
#[path = "launch_preparation/provenance.rs"]
mod provenance;
#[cfg(all(test, feature = "launch-preparation-content"))]
pub(crate) use content::fixture;
#[cfg(feature = "launch-preparation-content")]
pub use content::{ContentBinding, ContentSummary, ImageContentLimits, LayerContentSummary};

const MANIFEST_MEDIA_TYPE: &str = "application/vnd.oci.image.manifest.v1+json";
const CONFIG_MEDIA_TYPE: &str = "application/vnd.oci.image.config.v1+json";
const ENCRYPTED_TAR: &str = "application/vnd.oci.image.layer.v1.tar+encrypted";
const ENCRYPTED_GZIP: &str = "application/vnd.oci.image.layer.v1.tar+gzip+encrypted";
const PACKET_ANNOTATION: &str = "org.opencontainers.image.enc.keys.provider.attestation-agent";
const PUBLIC_OPTIONS_ANNOTATION: &str = "org.opencontainers.image.enc.pubopts";
const KID_PREFIX: &str = "kbs:///default/key/";
const KID_ESCAPES: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');

/// Trusted scope, provisioned independently of manifest/credential responses.
/// There is no caller-supplied list of layer operations.
pub struct PreparationProfile {
    pub authority_public_key: [u8; 32],
    pub kbs_proof_public_key: [u8; 32],
    pub binding: LaunchBinding,
    pub grant_sha384: String,
    pub validity: ValidityWindow,
    pub workflow_id: String,
    pub resource_path: [String; 3],
    pub project_id: String,
    pub client_email: String,
    pub kms_key_version: String,
}

/// Every bound is supplied by the trusted owner; no deployment defaults are
/// introduced here. Layer count and actual selected-operation count are distinct.
#[derive(Clone, Copy)]
pub struct PreparationLimits {
    pub manifest_bytes: usize,
    pub config_bytes: usize,
    pub layer_count: usize,
    pub packets_per_layer: usize,
    pub packet_bytes: usize,
    pub public_options_bytes: usize,
    pub kms_ciphertext_bytes: usize,
    pub operations: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PreparationError {
    InvalidConfiguration,
    ScopeMismatch,
    TooLarge,
    InvalidManifest,
    InvalidConfig,
    InvalidPacket,
    UnsupportedProfile,
    NotReady,
    Conflict,
    Unavailable,
    #[cfg(feature = "launch-preparation-content")]
    SignatureRejected,
    #[cfg(feature = "launch-preparation-content")]
    ContentRejected,
    #[cfg(feature = "launch-preparation-content")]
    StagingRejected,
}

impl fmt::Display for PreparationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidConfiguration => "preparation configuration rejected",
            Self::ScopeMismatch => "preparation scope differs from admitted attempt",
            Self::TooLarge => "preparation metadata exceeds configured bounds",
            Self::InvalidManifest => "preparation manifest rejected",
            Self::InvalidConfig => "preparation image config rejected",
            Self::InvalidPacket => "preparation key packet rejected",
            Self::UnsupportedProfile => "preparation metadata uses an unsupported profile",
            Self::NotReady => "preparation metadata has not been bound",
            Self::Conflict => "preparation metadata conflicts with retained binding",
            Self::Unavailable => "preparation attempt is terminal",
            #[cfg(feature = "launch-preparation-content")]
            Self::SignatureRejected => "preparation image signature rejected",
            #[cfg(feature = "launch-preparation-content")]
            Self::ContentRejected => "preparation layer content rejected",
            #[cfg(feature = "launch-preparation-content")]
            Self::StagingRejected => "preparation rootfs staging rejected",
        })
    }
}
impl std::error::Error for PreparationError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifestBinding {
    FirstBound,
    Historical,
}

/// Metadata only: the encrypted blob has not been read or verified.
pub struct BoundLayerPlan {
    original_index: u32,
    blob_sha256: String,
    descriptor_size: u64,
    media_type: String,
    expected_diff_id: String,
    packet_ordinal: usize,
    packet_sha384: String,
    kms_ciphertext_sha384: String,
}

impl BoundLayerPlan {
    pub fn original_index(&self) -> u32 {
        self.original_index
    }
    pub fn blob_sha256(&self) -> &str {
        &self.blob_sha256
    }
    pub fn descriptor_size(&self) -> u64 {
        self.descriptor_size
    }
    pub fn media_type(&self) -> &str {
        &self.media_type
    }
    pub fn expected_diff_id(&self) -> &str {
        &self.expected_diff_id
    }
    pub fn packet_ordinal(&self) -> usize {
        self.packet_ordinal
    }
    pub fn packet_sha384(&self) -> &str {
        &self.packet_sha384
    }
    pub fn kms_ciphertext_sha384(&self) -> &str {
        &self.kms_ciphertext_sha384
    }
}

/// Raw-byte digest/shape binding, never a signature-verification or preparation
/// success object. Its constructor and fields are private, with no serde/Clone.
pub struct BoundManifestPlan {
    manifest_sha256: String,
    config_sha256: String,
    admission_context_sha384: String,
    credential_delivery_sha384: String,
    layers: Vec<BoundLayerPlan>,
}

impl BoundManifestPlan {
    pub fn manifest_sha256(&self) -> &str {
        &self.manifest_sha256
    }
    pub fn config_sha256(&self) -> &str {
        &self.config_sha256
    }
    pub fn admission_context_sha384(&self) -> &str {
        &self.admission_context_sha384
    }
    pub fn credential_delivery_sha384(&self) -> &str {
        &self.credential_delivery_sha384
    }
    pub fn layers(&self) -> &[BoundLayerPlan] {
        &self.layers
    }
}

struct AttemptMaterial {
    admission: AcceptedAttemptContext,
    credential: Option<AttemptCredential>,
    profile: PreparationProfile,
    limits: PreparationLimits,
    #[cfg(feature = "launch-preparation-content")]
    content_limits: Option<ImageContentLimits>,
    #[cfg(feature = "launch-preparation-content")]
    staging: Option<staging::StagingConfiguration>,
}

struct RetainedBinding {
    _material: AttemptMaterial,
    manifest: Vec<u8>,
    config: Vec<u8>,
    plan: BoundManifestPlan,
}

enum State {
    Pending(AttemptMaterial),
    Bound(RetainedBinding),
    #[cfg(feature = "launch-preparation-content")]
    SignatureChecked(content::SignedBinding),
    #[cfg(feature = "launch-preparation-content")]
    ContentChecked(content::CheckedBinding),
    #[cfg(feature = "launch-preparation-content")]
    RootfsStaged(staging::StagedBinding),
    Terminal,
}

/// Unique ownership of admission and credential. Exact retry returns metadata;
/// conflict, validation failure and cancellation drop both owned inputs.
pub struct PreparationAttempt {
    state: State,
}

impl PreparationAttempt {
    pub fn new(
        admission: AcceptedAttemptContext,
        credential: AttemptCredential,
        profile: PreparationProfile,
        limits: PreparationLimits,
    ) -> Result<Self, PreparationError> {
        validate_configuration(&profile, &limits)?;
        if credential.authority_key_sha384() != sha384(&profile.authority_public_key)
            || admission.authority_key_sha384() != sha384(&profile.authority_public_key)
            || credential.delivery().kbs_proof_key_sha384() != sha384(&profile.kbs_proof_public_key)
            || admission.aggregate_key_sha384() != sha384(&profile.kbs_proof_public_key)
            || credential.binding() != &profile.binding
            || admission.binding() != &profile.binding
            || credential.grant_digest() != profile.grant_sha384
            || admission.grant_digest() != profile.grant_sha384
            || credential.delivery().grant_digest() != profile.grant_sha384
            || credential.delivery().aggregate_digest() != admission.aggregate_digest()
            || credential.delivery().validity() != &profile.validity
            || admission.validity() != &profile.validity
            || credential.delivery().workflow_id() != profile.workflow_id
            || admission.workflow_id() != profile.workflow_id
            || credential.delivery().resource_path() != &profile.resource_path
            || admission.resource_path() != &profile.resource_path
        {
            return Err(PreparationError::ScopeMismatch);
        }
        Ok(Self {
            state: State::Pending(AttemptMaterial {
                admission,
                credential: Some(credential),
                profile,
                limits,
                #[cfg(feature = "launch-preparation-content")]
                content_limits: None,
                #[cfg(feature = "launch-preparation-content")]
                staging: None,
            }),
        })
    }

    pub fn bind_manifest(
        &mut self,
        manifest: &[u8],
        config: &[u8],
    ) -> Result<ManifestBinding, PreparationError> {
        match std::mem::replace(&mut self.state, State::Terminal) {
            State::Terminal => Err(PreparationError::Unavailable),
            State::Bound(prior) => {
                if prior.manifest != manifest || prior.config != config {
                    return Err(PreparationError::Conflict);
                }
                self.state = State::Bound(prior);
                Ok(ManifestBinding::Historical)
            }
            State::Pending(material) => {
                let plan = bind_metadata(&material, manifest, config)?;
                self.state = State::Bound(RetainedBinding {
                    _material: material,
                    manifest: manifest.to_vec(),
                    config: config.to_vec(),
                    plan,
                });
                Ok(ManifestBinding::FirstBound)
            }
            #[cfg(feature = "launch-preparation-content")]
            State::SignatureChecked(prior) => {
                if prior.bound.manifest != manifest || prior.bound.config != config {
                    return Err(PreparationError::Conflict);
                }
                self.state = State::SignatureChecked(prior);
                Ok(ManifestBinding::Historical)
            }
            #[cfg(feature = "launch-preparation-content")]
            State::ContentChecked(prior) => {
                if prior.signed.bound.manifest != manifest || prior.signed.bound.config != config {
                    return Err(PreparationError::Conflict);
                }
                self.state = State::ContentChecked(prior);
                Ok(ManifestBinding::Historical)
            }
            #[cfg(feature = "launch-preparation-content")]
            State::RootfsStaged(prior) => {
                if prior.checked.signed.bound.manifest != manifest
                    || prior.checked.signed.bound.config != config
                {
                    return Err(PreparationError::Conflict);
                }
                self.state = State::RootfsStaged(prior);
                Ok(ManifestBinding::Historical)
            }
        }
    }

    pub fn manifest_plan(&self) -> Result<&BoundManifestPlan, PreparationError> {
        match &self.state {
            State::Bound(bound) => Ok(&bound.plan),
            #[cfg(feature = "launch-preparation-content")]
            State::SignatureChecked(signed) => Ok(&signed.bound.plan),
            #[cfg(feature = "launch-preparation-content")]
            State::ContentChecked(checked) => Ok(&checked.signed.bound.plan),
            #[cfg(feature = "launch-preparation-content")]
            State::RootfsStaged(staged) => Ok(&staged.checked.signed.bound.plan),
            State::Pending(_) => Err(PreparationError::NotReady),
            State::Terminal => Err(PreparationError::Unavailable),
        }
    }

    pub fn cancel(&mut self) {
        self.state = State::Terminal;
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    #[serde(rename = "schemaVersion")]
    schema_version: u32,
    #[serde(rename = "mediaType")]
    media_type: String,
    config: Descriptor,
    layers: Vec<Descriptor>,
    #[serde(default, deserialize_with = "unique_map")]
    annotations: BTreeMap<String, String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Descriptor {
    #[serde(rename = "mediaType")]
    media_type: String,
    digest: String,
    size: u64,
    #[serde(default, deserialize_with = "unique_map")]
    annotations: BTreeMap<String, String>,
}

// Other OCI config fields are retained in the exact raw bytes but are not
// interpreted or approved as an effective launch configuration.
#[derive(Deserialize)]
struct ImageConfig {
    os: String,
    architecture: String,
    rootfs: RootFs,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RootFs {
    #[serde(rename = "type")]
    kind: String,
    diff_ids: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Packet {
    kid: String,
    wrapped_data: String,
    iv: String,
    wrap_type: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicOptions {
    cipher: String,
    #[serde(deserialize_with = "unique_map")]
    cipheroptions: BTreeMap<String, String>,
    hmac: String,
}

fn bind_metadata(
    material: &AttemptMaterial,
    manifest_bytes: &[u8],
    config_bytes: &[u8],
) -> Result<BoundManifestPlan, PreparationError> {
    let limits = &material.limits;
    if manifest_bytes.len() > limits.manifest_bytes || config_bytes.len() > limits.config_bytes {
        return Err(PreparationError::TooLarge);
    }
    let manifest_sha256 = sha256(manifest_bytes);
    if manifest_sha256 != material.profile.binding.selected_manifest_sha256 {
        return Err(PreparationError::ScopeMismatch);
    }
    let manifest: Manifest =
        serde_json::from_slice(manifest_bytes).map_err(|_| PreparationError::InvalidManifest)?;
    if manifest.schema_version != 2 || manifest.media_type != MANIFEST_MEDIA_TYPE {
        return Err(PreparationError::UnsupportedProfile);
    }
    if manifest.layers.is_empty() || manifest.layers.len() > limits.layer_count {
        return Err(PreparationError::TooLarge);
    }
    if manifest.layers.len() > limits.operations {
        return Err(PreparationError::TooLarge);
    }
    let config_sha256 = sha256(config_bytes);
    if manifest.config.media_type != CONFIG_MEDIA_TYPE
        || digest_value(&manifest.config.digest) != Some(config_sha256.as_str())
        || manifest.config.size != config_bytes.len() as u64
        || !manifest.config.annotations.is_empty()
    {
        return Err(PreparationError::InvalidConfig);
    }
    let config: ImageConfig =
        serde_json::from_slice(config_bytes).map_err(|_| PreparationError::InvalidConfig)?;
    if config.os != "linux" || config.architecture != "amd64" || config.rootfs.kind != "layers" {
        return Err(PreparationError::UnsupportedProfile);
    }
    if config.rootfs.diff_ids.len() != manifest.layers.len() {
        return Err(PreparationError::InvalidConfig);
    }
    let _ = manifest.annotations;
    let mut layers = Vec::with_capacity(manifest.layers.len());
    for (index, (layer, diff_id)) in manifest
        .layers
        .into_iter()
        .zip(config.rootfs.diff_ids)
        .enumerate()
    {
        if !matches!(layer.media_type.as_str(), ENCRYPTED_TAR | ENCRYPTED_GZIP) || layer.size == 0 {
            return Err(PreparationError::UnsupportedProfile);
        }
        let blob_sha256 = digest_value(&layer.digest).ok_or(PreparationError::InvalidManifest)?;
        if digest_value(&diff_id).is_none() {
            return Err(PreparationError::InvalidConfig);
        }
        validate_public_options(&layer.annotations, limits)?;
        let (packet_ordinal, packet_sha384, kms_ciphertext_sha384) = select_packet(
            &layer.annotations,
            &material.profile.kms_key_version,
            limits,
        )?;
        layers.push(BoundLayerPlan {
            original_index: u32::try_from(index).map_err(|_| PreparationError::TooLarge)?,
            blob_sha256: blob_sha256.into(),
            descriptor_size: layer.size,
            media_type: layer.media_type,
            expected_diff_id: diff_id,
            packet_ordinal,
            packet_sha384,
            kms_ciphertext_sha384,
        });
    }
    Ok(BoundManifestPlan {
        manifest_sha256,
        config_sha256,
        admission_context_sha384: material.admission.context_digest().into(),
        credential_delivery_sha384: material
            .credential
            .as_ref()
            .ok_or(PreparationError::Unavailable)?
            .delivery()
            .digest_sha384()
            .into(),
        layers,
    })
}

fn select_packet(
    annotations: &BTreeMap<String, String>,
    expected_key: &str,
    limits: &PreparationLimits,
) -> Result<(usize, String, String), PreparationError> {
    if annotations.keys().any(|key| {
        key.starts_with("org.opencontainers.image.enc.keys.") && key != PACKET_ANNOTATION
    }) {
        return Err(PreparationError::UnsupportedProfile);
    }
    let list = annotations
        .get(PACKET_ANNOTATION)
        .ok_or(PreparationError::InvalidPacket)?;
    let mut selected = None;
    for (ordinal, encoded) in list.split(',').enumerate() {
        if ordinal >= limits.packets_per_layer {
            return Err(PreparationError::TooLarge);
        }
        let bytes = canonical_base64(encoded, limits.packet_bytes)?;
        let packet: Packet =
            serde_json::from_slice(&bytes).map_err(|_| PreparationError::InvalidPacket)?;
        if packet.wrap_type != "KMS-DIRECT" || !packet.iv.is_empty() {
            return Err(PreparationError::UnsupportedProfile);
        }
        let escaped = packet
            .kid
            .strip_prefix(KID_PREFIX)
            .ok_or(PreparationError::InvalidPacket)?;
        let key = percent_decode_str(escaped)
            .decode_utf8()
            .map_err(|_| PreparationError::InvalidPacket)?;
        if utf8_percent_encode(&key, KID_ESCAPES).to_string() != escaped || !key_version(&key, None)
        {
            return Err(PreparationError::InvalidPacket);
        }
        let wrapped = canonical_base64(&packet.wrapped_data, limits.packet_bytes)?;
        let wrapped = std::str::from_utf8(&wrapped).map_err(|_| PreparationError::InvalidPacket)?;
        let encoded_ciphertext = wrapped
            .strip_prefix("gcp:")
            .ok_or(PreparationError::UnsupportedProfile)?;
        let ciphertext = canonical_base64(encoded_ciphertext, limits.kms_ciphertext_bytes)?;
        if key == expected_key {
            if selected.is_some() {
                return Err(PreparationError::InvalidPacket);
            }
            selected = Some((ordinal, sha384(&bytes), sha384(&ciphertext)));
        }
    }
    selected.ok_or(PreparationError::InvalidPacket)
}

fn validate_public_options(
    annotations: &BTreeMap<String, String>,
    limits: &PreparationLimits,
) -> Result<(), PreparationError> {
    let encoded = annotations
        .get(PUBLIC_OPTIONS_ANNOTATION)
        .ok_or(PreparationError::InvalidPacket)?;
    let bytes = canonical_base64(encoded, limits.public_options_bytes)?;
    let options: PublicOptions =
        serde_json::from_slice(&bytes).map_err(|_| PreparationError::InvalidPacket)?;
    if options.cipher != "AES_256_CTR_HMAC_SHA256" || options.cipheroptions.len() > 1 {
        return Err(PreparationError::UnsupportedProfile);
    }
    // Existing ocicrypt encryption keeps the nonce in the private options. A
    // public override is accepted only with its exact supported shape.
    for (name, nonce) in &options.cipheroptions {
        if name != "nonce" || canonical_base64(nonce, 16)?.len() != 16 {
            return Err(PreparationError::InvalidPacket);
        }
    }
    if canonical_base64(&options.hmac, 32)?.len() != 32 {
        return Err(PreparationError::InvalidPacket);
    }
    Ok(())
}

fn canonical_base64(value: &str, max: usize) -> Result<Vec<u8>, PreparationError> {
    if value.len()
        > max
            .div_ceil(3)
            .checked_mul(4)
            .ok_or(PreparationError::InvalidConfiguration)?
    {
        return Err(PreparationError::TooLarge);
    }
    let bytes = STANDARD
        .decode(value)
        .map_err(|_| PreparationError::InvalidPacket)?;
    if bytes.is_empty() || bytes.len() > max {
        return Err(PreparationError::TooLarge);
    }
    if STANDARD.encode(&bytes) != value {
        return Err(PreparationError::InvalidPacket);
    }
    Ok(bytes)
}

fn validate_configuration(
    profile: &PreparationProfile,
    limits: &PreparationLimits,
) -> Result<(), PreparationError> {
    if profile.authority_public_key == [0; 32]
        || profile.kbs_proof_public_key == [0; 32]
        || profile.authority_public_key == profile.kbs_proof_public_key
        || !hex_digest(&profile.grant_sha384, 96)
        || !hex_digest(&profile.binding.selected_manifest_sha256, 64)
        || profile.validity.validate().is_err()
        || !key_version(&profile.kms_key_version, Some(&profile.project_id))
        || profile.client_email.len() > 320
        || !profile.client_email.ends_with(".iam.gserviceaccount.com")
        || profile
            .client_email
            .bytes()
            .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
        || limits.operations > 32
        || limits.kms_ciphertext_bytes > crate::launch_credential::MAX_KMS_CIPHERTEXT_BYTES
        || [
            limits.manifest_bytes,
            limits.config_bytes,
            limits.layer_count,
            limits.packets_per_layer,
            limits.packet_bytes,
            limits.public_options_bytes,
            limits.kms_ciphertext_bytes,
            limits.operations,
        ]
        .contains(&0)
    {
        return Err(PreparationError::InvalidConfiguration);
    }
    Ok(())
}

fn key_version(value: &str, project: Option<&str>) -> bool {
    if value.len() > 1024 {
        return false;
    }
    let parts: Vec<_> = value.split('/').collect();
    parts.len() == 10
        && parts[0] == "projects"
        && project.is_none_or(|p| parts[1] == p)
        && parts[2] == "locations"
        && parts[4] == "keyRings"
        && parts[6] == "cryptoKeys"
        && parts[8] == "cryptoKeyVersions"
        && [parts[1], parts[3], parts[5], parts[7]].iter().all(|part| {
            !part.is_empty()
                && part.len() <= 128
                && part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
        })
        && parts[9]
            .parse::<u64>()
            .is_ok_and(|n| n > 0 && n.to_string() == parts[9])
}

fn digest_value(value: &str) -> Option<&str> {
    value
        .strip_prefix("sha256:")
        .filter(|value| hex_digest(value, 64))
}
fn hex_digest(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn sha384(bytes: &[u8]) -> String {
    Sha384::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn unique_map<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<BTreeMap<String, String>, D::Error> {
    struct UniqueMap;
    impl<'de> de::Visitor<'de> for UniqueMap {
        type Value = BTreeMap<String, String>;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("an object with unique string keys")
        }
        fn visit_map<M: de::MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
            let mut result = BTreeMap::new();
            while let Some((key, value)) = map.next_entry::<String, String>()? {
                if result.insert(key, value).is_some() {
                    return Err(de::Error::custom("duplicate metadata key"));
                }
            }
            Ok(result)
        }
    }
    deserializer.deserialize_map(UniqueMap)
}
