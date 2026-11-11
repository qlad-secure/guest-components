//! Mandatory publisher verification and fresh GCP checks for sealed TAR bytes.
//!
//! No API exports credentials, accepts a provider callback in production,
//! grants launch permission or exports a usable rootfs. Content stays private;
//! the separate staging transition consumes these TARs into a mutable tree.

use super::*;
use crate::launch_credential::{AttemptGcpDecrypter, TrustedGcpAttempt, TrustedGcpLayerOperation};
use image_rs::preparation::{
    layer_content::{
        check_layer_content, CheckedLayerContent, LayerContentExpectation, LayerContentLimits,
    },
    manifest_signature::{RequiredCosignPolicy, VerifiedManifestSignature},
};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ImageContentLimits {
    pub layer: LayerContentLimits,
    pub total_ciphertext_bytes: usize,
    pub total_tar_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContentBinding {
    FirstChecked,
    Historical,
}

/// Summaries are observations about fully checked bytes, not a rootfs lease.
#[derive(Debug, Eq, PartialEq)]
pub struct LayerContentSummary {
    original_index: u32,
    blob_sha256: String,
    plaintext_sha256: String,
    diff_id: String,
    tar_sha384: String,
    tar_bytes: u64,
    tar_entries: usize,
}

impl LayerContentSummary {
    pub fn original_index(&self) -> u32 {
        self.original_index
    }
    pub fn blob_sha256(&self) -> &str {
        &self.blob_sha256
    }
    pub fn plaintext_sha256(&self) -> &str {
        &self.plaintext_sha256
    }
    pub fn diff_id(&self) -> &str {
        &self.diff_id
    }
    pub fn tar_sha384(&self) -> &str {
        &self.tar_sha384
    }
    pub fn tar_bytes(&self) -> u64 {
        self.tar_bytes
    }
    pub fn tar_entries(&self) -> usize {
        self.tar_entries
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct ContentSummary {
    manifest_sha256: String,
    policy_sha384: String,
    total_ciphertext_bytes: usize,
    total_tar_bytes: usize,
    layers: Vec<LayerContentSummary>,
}

impl ContentSummary {
    pub fn manifest_sha256(&self) -> &str {
        &self.manifest_sha256
    }
    pub fn policy_sha384(&self) -> &str {
        &self.policy_sha384
    }
    pub fn total_ciphertext_bytes(&self) -> usize {
        self.total_ciphertext_bytes
    }
    pub fn total_tar_bytes(&self) -> usize {
        self.total_tar_bytes
    }
    pub fn layers(&self) -> &[LayerContentSummary] {
        &self.layers
    }
}

pub(super) struct SignedBinding {
    pub(super) bound: RetainedBinding,
    // Retain the requiring policy and exact verified signature commitments.
    policy: RequiredCosignPolicy,
    signature: VerifiedManifestSignature,
    payload: Vec<u8>,
    raw_signature: Vec<u8>,
}

pub(super) struct CheckedBinding {
    pub(super) signed: SignedBinding,
    summary: ContentSummary,
    // These owned sealed objects have no public accessor on the CDH attempt.
    pub(super) _layers: Vec<CheckedLayerContent>,
}

struct SelectedOperation {
    original_index: u32,
    public_options: String,
    kms_ciphertext: Vec<u8>,
}

impl PreparationAttempt {
    /// Construct the attempt with independently provisioned content budgets.
    /// No signature, OAuth, KMS, blob read or filesystem operation occurs here.
    pub fn new_with_content(
        admission: AcceptedAttemptContext,
        credential: AttemptCredential,
        profile: PreparationProfile,
        limits: PreparationLimits,
        content_limits: ImageContentLimits,
    ) -> Result<Self, PreparationError> {
        validate_content_limits(content_limits)?;
        let mut attempt = Self::new(admission, credential, profile, limits)?;
        if let State::Pending(material) = &mut attempt.state {
            material.content_limits = Some(content_limits);
        }
        Ok(attempt)
    }

    #[cfg(feature = "launch-preparation-gcp")]
    pub fn new_gcp_with_content(
        admission: AcceptedAttemptContext,
        credential: kbs_protocol::gcp_launch_recorder::GcpAttemptCredential,
        profile: PreparationProfile,
        limits: PreparationLimits,
        content_limits: ImageContentLimits,
    ) -> Result<Self, PreparationError> {
        validate_content_limits(content_limits)?;
        let mut attempt = Self::new_gcp(admission, credential, profile, limits)?;
        if let State::Pending(material) = &mut attempt.state {
            material.content_limits = Some(content_limits);
        }
        Ok(attempt)
    }

    /// Own the actual requiring policy, pin it to admission, and verify claims
    /// from the exact cryptographically authenticated Cosign payload bytes.
    pub fn verify_image_signature(
        &mut self,
        policy: RequiredCosignPolicy,
        payload: &[u8],
        signature: &[u8],
    ) -> Result<ContentBinding, PreparationError> {
        let (bound, prior, checked) = match std::mem::replace(&mut self.state, State::Terminal) {
            State::Bound(bound) => (bound, None, None),
            State::SignatureChecked(signed) => (
                signed.bound,
                Some((
                    signed.policy,
                    signed.signature,
                    signed.payload,
                    signed.raw_signature,
                )),
                None,
            ),
            State::ContentChecked(checked) => {
                let CheckedBinding {
                    signed,
                    summary,
                    _layers,
                } = checked;
                (
                    signed.bound,
                    Some((
                        signed.policy,
                        signed.signature,
                        signed.payload,
                        signed.raw_signature,
                    )),
                    Some((summary, _layers)),
                )
            }
            State::RootfsStaged(staged) => {
                let signed = &staged.checked.signed;
                if signed.signature.policy_sha384() != policy.policy_sha384()
                    || signed.signature.key_sha384() != policy.key_sha384()
                    || signed.signature.repository() != policy.repository()
                    || signed.payload.len() != payload.len()
                    || signed.raw_signature.len() != signature.len()
                    || signed.payload != payload
                    || signed.raw_signature != signature
                {
                    return Err(PreparationError::Conflict);
                }
                self.state = State::RootfsStaged(staged);
                return Ok(ContentBinding::Historical);
            }
            State::Pending(_) => return Err(PreparationError::NotReady),
            State::Terminal => return Err(PreparationError::Unavailable),
        };
        if bound._material.content_limits.is_none() {
            return Err(PreparationError::InvalidConfiguration);
        }
        let binding = &bound._material.profile.binding;
        if policy.policy_sha384() != binding.image_policy_sha384
            || sha256(&bound.manifest) != binding.selected_manifest_sha256
        {
            return Err(PreparationError::ScopeMismatch);
        }
        if let Some((old_policy, old, prior_payload, prior_signature)) = prior {
            // Compare lengths first: retry must not hash an unbounded received
            // slice. These retained inputs passed the original policy limits.
            if prior_payload.len() != payload.len()
                || prior_signature.len() != signature.len()
                || prior_payload != payload
                || prior_signature != signature
                || old.policy_sha384() != policy.policy_sha384()
                || old.key_sha384() != policy.key_sha384()
                || old.repository() != policy.repository()
            {
                return Err(PreparationError::Conflict);
            }
            let signed = SignedBinding {
                bound,
                policy: old_policy,
                signature: old,
                payload: prior_payload,
                raw_signature: prior_signature,
            };
            self.state = match checked {
                Some((summary, _layers)) => State::ContentChecked(CheckedBinding {
                    signed,
                    summary,
                    _layers,
                }),
                None => State::SignatureChecked(signed),
            };
            return Ok(ContentBinding::Historical);
        }
        let verified = policy
            .verify(
                &bound.manifest,
                &binding.selected_manifest_sha256,
                payload,
                signature,
            )
            .map_err(|_| PreparationError::SignatureRejected)?;
        if verified.policy_sha384() != binding.image_policy_sha384
            || verified.manifest_sha256() != bound.plan.manifest_sha256
        {
            return Err(PreparationError::ScopeMismatch);
        }
        self.state = State::SignatureChecked(SignedBinding {
            bound,
            policy,
            signature: verified,
            payload: payload.to_vec(),
            raw_signature: signature.to_vec(),
        });
        Ok(ContentBinding::FirstChecked)
    }

    pub fn image_signature(&self) -> Result<&VerifiedManifestSignature, PreparationError> {
        match &self.state {
            State::SignatureChecked(signed) => Ok(&signed.signature),
            State::ContentChecked(checked) => Ok(&checked.signed.signature),
            State::RootfsStaged(staged) => Ok(&staged.checked.signed.signature),
            State::Terminal => Err(PreparationError::Unavailable),
            _ => Err(PreparationError::NotReady),
        }
    }

    pub fn content_summary(&self) -> Result<&ContentSummary, PreparationError> {
        match &self.state {
            State::ContentChecked(checked) => Ok(&checked.summary),
            State::RootfsStaged(staged) => Ok(&staged.checked.summary),
            State::Terminal => Err(PreparationError::Unavailable),
            _ => Err(PreparationError::NotReady),
        }
    }

    /// Every operation is derived internally from the signed original manifest.
    /// Taking the entire state before the first await makes cancellation terminal
    /// and drops the sole provider, plaintext and any already checked sealed TARs.
    /// SDK retries do not imply one physical Cloud KMS request.
    pub async fn prepare_layers(
        &mut self,
        ciphertexts: &[&[u8]],
    ) -> Result<ContentBinding, PreparationError> {
        let signed = match self.begin_content(ciphertexts)? {
            Some(signed) => signed,
            None => return Ok(ContentBinding::Historical),
        };
        let mut signed = signed;
        let (operations, expected) = derive_operations(&signed.bound)?;
        let credential = signed
            .bound
            ._material
            .credential
            .take()
            .ok_or(PreparationError::Unavailable)?;
        let decrypter = credential
            .into_decrypter(expected, &signed.bound._material.admission)
            .map_err(|_| PreparationError::ContentRejected)?;
        let mut resolver = GcpResolver(decrypter);
        let checked = check_all_content(signed, operations, ciphertexts, &mut resolver).await?;
        self.state = State::ContentChecked(checked);
        Ok(ContentBinding::FirstChecked)
    }

    fn begin_content(
        &mut self,
        ciphertexts: &[&[u8]],
    ) -> Result<Option<SignedBinding>, PreparationError> {
        match std::mem::replace(&mut self.state, State::Terminal) {
            State::ContentChecked(checked) => {
                validate_ciphertexts(&checked.signed.bound, ciphertexts)?;
                self.state = State::ContentChecked(checked);
                Ok(None)
            }
            State::RootfsStaged(staged) => {
                validate_ciphertexts(&staged.checked.signed.bound, ciphertexts)?;
                self.state = State::RootfsStaged(staged);
                Ok(None)
            }
            State::SignatureChecked(signed) => {
                // Recheck all bytes before the first possible SDK operation.
                validate_ciphertexts(&signed.bound, ciphertexts)?;
                if signed.signature.manifest_sha256() != sha256(&signed.bound.manifest)
                    || signed.signature.policy_sha384()
                        != signed.bound._material.profile.binding.image_policy_sha384
                {
                    return Err(PreparationError::ScopeMismatch);
                }
                Ok(Some(signed))
            }
            State::Terminal => Err(PreparationError::Unavailable),
            _ => Err(PreparationError::NotReady),
        }
    }
}

pub(super) fn validate_content_limits(limits: ImageContentLimits) -> Result<(), PreparationError> {
    let layer = limits.layer;
    if [
        layer.ciphertext_bytes,
        layer.private_options_bytes,
        layer.public_options_bytes,
        layer.plaintext_bytes,
        layer.tar_bytes,
        layer.tar_entries,
        layer.path_bytes,
        layer.file_bytes,
        limits.total_ciphertext_bytes,
        limits.total_tar_bytes,
    ]
    .iter()
    .any(|value| *value == 0 || *value > isize::MAX as usize)
        || layer.tar_bytes < 1024
        || limits.total_tar_bytes < 1024
    {
        return Err(PreparationError::InvalidConfiguration);
    }
    Ok(())
}

fn content_limits(bound: &RetainedBinding) -> Result<ImageContentLimits, PreparationError> {
    bound
        ._material
        .content_limits
        .ok_or(PreparationError::InvalidConfiguration)
}

fn validate_ciphertexts(
    bound: &RetainedBinding,
    ciphertexts: &[&[u8]],
) -> Result<(), PreparationError> {
    let limits = content_limits(bound)?;
    if ciphertexts.len() != bound.plan.layers.len() {
        return Err(PreparationError::Conflict);
    }
    let mut total = 0usize;
    for (layer, ciphertext) in bound.plan.layers.iter().zip(ciphertexts) {
        total = total
            .checked_add(ciphertext.len())
            .ok_or(PreparationError::TooLarge)?;
        if ciphertext.len() > limits.layer.ciphertext_bytes || total > limits.total_ciphertext_bytes
        {
            return Err(PreparationError::TooLarge);
        }
        if layer.descriptor_size != ciphertext.len() as u64
            || sha256(ciphertext) != layer.blob_sha256
        {
            return Err(PreparationError::Conflict);
        }
    }
    Ok(())
}

/// Reparse the owned exact raw metadata and revalidate every selected packet
/// commitment. No externally supplied operation list can reach the SDK.
fn derive_operations(
    bound: &RetainedBinding,
) -> Result<(Vec<SelectedOperation>, TrustedGcpAttempt), PreparationError> {
    let material = &bound._material;
    // Credential is still present before it is consumed by the actual provider.
    let rebound = bind_metadata(material, &bound.manifest, &bound.config)?;
    if rebound.manifest_sha256 != bound.plan.manifest_sha256
        || rebound.config_sha256 != bound.plan.config_sha256
        || rebound.admission_context_sha384 != bound.plan.admission_context_sha384
        || rebound.credential_delivery_sha384 != bound.plan.credential_delivery_sha384
        || rebound.layers.len() != bound.plan.layers.len()
    {
        return Err(PreparationError::ScopeMismatch);
    }
    let manifest: Manifest =
        serde_json::from_slice(&bound.manifest).map_err(|_| PreparationError::InvalidManifest)?;
    let mut operations = Vec::with_capacity(bound.plan.layers.len());
    let mut trusted_operations = Vec::with_capacity(bound.plan.layers.len());
    for (descriptor, layer) in manifest.layers.iter().zip(&bound.plan.layers) {
        let (ordinal, packet_hash, ciphertext_hash) = select_packet(
            &descriptor.annotations,
            &material.profile.kms_key_version,
            &material.limits,
        )?;
        if ordinal != layer.packet_ordinal
            || packet_hash != layer.packet_sha384
            || ciphertext_hash != layer.kms_ciphertext_sha384
            || digest_value(&descriptor.digest) != Some(layer.blob_sha256.as_str())
            || descriptor.size != layer.descriptor_size
            || descriptor.media_type != layer.media_type
        {
            return Err(PreparationError::ScopeMismatch);
        }
        let encoded = descriptor
            .annotations
            .get(PACKET_ANNOTATION)
            .and_then(|list| list.split(',').nth(ordinal))
            .ok_or(PreparationError::InvalidPacket)?;
        let bytes = canonical_base64(encoded, material.limits.packet_bytes)?;
        let packet: Packet =
            serde_json::from_slice(&bytes).map_err(|_| PreparationError::InvalidPacket)?;
        let wrapped = canonical_base64(&packet.wrapped_data, material.limits.packet_bytes)?;
        let wrapped = std::str::from_utf8(&wrapped).map_err(|_| PreparationError::InvalidPacket)?;
        let kms_ciphertext = canonical_base64(
            wrapped
                .strip_prefix("gcp:")
                .ok_or(PreparationError::UnsupportedProfile)?,
            material.limits.kms_ciphertext_bytes,
        )?;
        if sha384(&kms_ciphertext) != layer.kms_ciphertext_sha384 {
            return Err(PreparationError::ScopeMismatch);
        }
        let public_options = descriptor
            .annotations
            .get(PUBLIC_OPTIONS_ANNOTATION)
            .ok_or(PreparationError::InvalidPacket)?
            .clone();
        operations.push(SelectedOperation {
            original_index: layer.original_index,
            public_options,
            kms_ciphertext,
        });
        trusted_operations.push(TrustedGcpLayerOperation {
            layer_index: layer.original_index,
            layer_digest_sha256: layer.blob_sha256.clone(),
            ciphertext_sha384: layer.kms_ciphertext_sha384.clone(),
        });
    }
    let profile = &material.profile;
    let expected = TrustedGcpAttempt {
        authority_public_key: profile.authority_public_key,
        kbs_proof_public_key: profile.kbs_proof_public_key,
        binding: profile.binding.clone(),
        grant_sha384: profile.grant_sha384.clone(),
        validity: profile.validity,
        workflow_id: profile.workflow_id.clone(),
        resource_path: profile.resource_path.clone(),
        project_id: profile.project_id.clone(),
        client_email: profile.client_email.clone(),
        kms_key_version: profile.kms_key_version.clone(),
        operation_limit: material.limits.operations,
        layer_operations: trusted_operations,
    };
    Ok((operations, expected))
}

trait Resolver {
    async fn resolve(
        &mut self,
        index: u32,
        digest: &str,
        ciphertext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, PreparationError>;
    fn all_succeeded(&self) -> bool;
}

struct GcpResolver(AttemptGcpDecrypter);
impl Resolver for GcpResolver {
    async fn resolve(
        &mut self,
        index: u32,
        digest: &str,
        ciphertext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, PreparationError> {
        self.0
            .decrypt_layer_once(index, digest, ciphertext)
            .await
            .map_err(|_| PreparationError::ContentRejected)
    }
    fn all_succeeded(&self) -> bool {
        self.0.all_operations_succeeded()
    }
}

async fn check_all_content(
    signed: SignedBinding,
    operations: Vec<SelectedOperation>,
    ciphertexts: &[&[u8]],
    resolver: &mut impl Resolver,
) -> Result<CheckedBinding, PreparationError> {
    let limits = content_limits(&signed.bound)?;
    let mut total_tar = 0usize;
    let mut total_ciphertext = 0usize;
    let mut checked_layers = Vec::with_capacity(operations.len());
    let mut summaries = Vec::with_capacity(operations.len());
    for ((layer, operation), ciphertext) in signed
        .bound
        .plan
        .layers
        .iter()
        .zip(operations)
        .zip(ciphertexts)
    {
        let remaining_tar = limits
            .total_tar_bytes
            .checked_sub(total_tar)
            .ok_or(PreparationError::TooLarge)?;
        // Every accepted TAR needs at least its two end blocks. Reject an
        // exhausted aggregate budget before consuming another KMS operation.
        if remaining_tar < 1024 {
            return Err(PreparationError::TooLarge);
        }
        let mut layer_limits = limits.layer;
        layer_limits.tar_bytes = layer_limits.tar_bytes.min(remaining_tar);
        let private_options = resolver
            .resolve(
                operation.original_index,
                &layer.blob_sha256,
                &operation.kms_ciphertext,
            )
            .await?;
        let checked = check_layer_content(
            LayerContentExpectation {
                original_index: layer.original_index,
                media_type: &layer.media_type,
                blob_sha256: &layer.blob_sha256,
                descriptor_size: layer.descriptor_size,
                diff_id: &layer.expected_diff_id,
                public_options_b64: &operation.public_options,
            },
            ciphertext,
            private_options,
            layer_limits,
        )
        .await
        .map_err(|_| PreparationError::ContentRejected)?;
        let tar_bytes =
            usize::try_from(checked.tar_byte_len()).map_err(|_| PreparationError::TooLarge)?;
        total_tar = total_tar
            .checked_add(tar_bytes)
            .ok_or(PreparationError::TooLarge)?;
        total_ciphertext = total_ciphertext
            .checked_add(ciphertext.len())
            .ok_or(PreparationError::TooLarge)?;
        if total_tar > limits.total_tar_bytes || total_ciphertext > limits.total_ciphertext_bytes {
            return Err(PreparationError::TooLarge);
        }
        summaries.push(LayerContentSummary {
            original_index: checked.original_index(),
            blob_sha256: checked.blob_sha256().into(),
            plaintext_sha256: checked.plaintext_sha256().into(),
            diff_id: checked.diff_id().into(),
            tar_sha384: checked
                .sealed_tar()
                .sha384()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect(),
            tar_bytes: checked.tar_byte_len(),
            tar_entries: checked.tar_entries(),
        });
        checked_layers.push(checked);
    }
    if checked_layers.len() != signed.bound.plan.layers.len() || !resolver.all_succeeded() {
        return Err(PreparationError::ContentRejected);
    }
    let summary = ContentSummary {
        manifest_sha256: signed.bound.plan.manifest_sha256.clone(),
        policy_sha384: signed.signature.policy_sha384().into(),
        total_ciphertext_bytes: total_ciphertext,
        total_tar_bytes: total_tar,
        layers: summaries,
    };
    Ok(CheckedBinding {
        signed,
        summary,
        _layers: checked_layers,
    })
}

// Private test resolver. This cannot replace the production
// GCP provider, mint an SDK success, or be compiled into the service API.
#[cfg(test)]
pub(crate) mod fixture {
    use super::*;
    use std::sync::{Arc, Mutex};

    pub(crate) enum Reply {
        Options(Zeroizing<Vec<u8>>),
        Fail,
        Pending,
    }
    #[derive(Default)]
    pub(crate) struct Trace {
        pub calls: Vec<(u32, String, String)>,
    }
    struct LocalResolver {
        replies: std::collections::VecDeque<Reply>,
        trace: Arc<Mutex<Trace>>,
        succeeded: usize,
        expected: usize,
    }
    impl Resolver for LocalResolver {
        async fn resolve(
            &mut self,
            index: u32,
            digest: &str,
            ciphertext: &[u8],
        ) -> Result<Zeroizing<Vec<u8>>, PreparationError> {
            self.trace
                .lock()
                .unwrap()
                .calls
                .push((index, digest.into(), sha384(ciphertext)));
            match self
                .replies
                .pop_front()
                .ok_or(PreparationError::ContentRejected)?
            {
                Reply::Options(options) => {
                    self.succeeded += 1;
                    Ok(options)
                }
                Reply::Fail => Err(PreparationError::ContentRejected),
                Reply::Pending => std::future::pending().await,
            }
        }
        fn all_succeeded(&self) -> bool {
            self.succeeded == self.expected && self.replies.is_empty()
        }
    }
    impl PreparationAttempt {
        pub(crate) async fn prepare_layers_fixture(
            &mut self,
            ciphertexts: &[&[u8]],
            replies: Vec<Reply>,
            trace: Arc<Mutex<Trace>>,
        ) -> Result<ContentBinding, PreparationError> {
            let mut signed = match self.begin_content(ciphertexts)? {
                Some(signed) => signed,
                None => return Ok(ContentBinding::Historical),
            };
            let (operations, expected) = derive_operations(&signed.bound)?;
            // Consume the opaque input and validate SDK construction without
            // performing OAuth or Cloud KMS requests.
            let credential = signed
                .bound
                ._material
                .credential
                .take()
                .ok_or(PreparationError::Unavailable)?;
            let _sdk = credential
                .into_decrypter(expected, &signed.bound._material.admission)
                .map_err(|_| PreparationError::ContentRejected)?;
            let mut resolver = LocalResolver {
                expected: operations.len(),
                replies: replies.into(),
                trace,
                succeeded: 0,
            };
            let checked = check_all_content(signed, operations, ciphertexts, &mut resolver).await?;
            self.state = State::ContentChecked(checked);
            Ok(ContentBinding::FirstChecked)
        }
    }
}
