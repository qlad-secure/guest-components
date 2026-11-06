//! Public provenance derived only from one retained checked preparation.
//! No credentials, key material, unwrap options or caller-supplied success
//! records enter this transcript. Ordered original occurrences are retained.

use super::*;
use execution_proof_handoff::rootfs_custody::{
    BuilderProvenance, LayerProvenance, PreparationProvenance, SignatureProvenance,
};
use runtime::CustodyProducerError;

impl PreparationAttempt {
    pub(super) fn custody_provenance(
        &self,
        max_bytes: usize,
    ) -> Result<PreparationProvenance, CustodyProducerError> {
        let State::RootfsStaged(staged) = &self.state else {
            return Err(CustodyProducerError::Unavailable);
        };
        let plan = self
            .manifest_plan()
            .map_err(|_| CustodyProducerError::Backing)?;
        let checked = self
            .content_summary()
            .map_err(|_| CustodyProducerError::Backing)?;
        let signature = self
            .image_signature()
            .map_err(|_| CustodyProducerError::Backing)?;
        let builder = self.custody_builder_summary()?;
        if plan.layers().len() != checked.layers().len()
            || plan.manifest_sha256() != checked.manifest_sha256()
            || plan.manifest_sha256() != signature.manifest_sha256()
        {
            return Err(CustodyProducerError::Backing);
        }
        let mut layers = Vec::with_capacity(plan.layers().len());
        for (expected, actual) in plan.layers().iter().zip(checked.layers()) {
            if expected.original_index() != actual.original_index()
                || expected.blob_sha256() != actual.blob_sha256()
                || expected.expected_diff_id() != actual.diff_id()
            {
                return Err(CustodyProducerError::Backing);
            }
            layers.push(LayerProvenance {
                original_index: actual.original_index(),
                blob_sha256: actual.blob_sha256().into(),
                descriptor_size: expected.descriptor_size(),
                plaintext_sha256: actual.plaintext_sha256().into(),
                diff_id: actual.diff_id().into(),
                tar_sha384: actual.tar_sha384().into(),
                tar_bytes: actual.tar_bytes(),
                tar_entries: actual
                    .tar_entries()
                    .try_into()
                    .map_err(|_| CustodyProducerError::Backing)?,
                packet_ordinal: expected
                    .packet_ordinal()
                    .try_into()
                    .map_err(|_| CustodyProducerError::Backing)?,
                packet_sha384: expected.packet_sha384().into(),
                kms_ciphertext_sha384: expected.kms_ciphertext_sha384().into(),
            });
        }
        let material = &staged.checked.signed.bound._material;
        let provenance = PreparationProvenance {
            context_sha384: material.admission.context_digest().into(),
            manifest_sha256: plan.manifest_sha256().into(),
            config_sha256: plan.config_sha256().into(),
            credential_delivery_sha384: plan.credential_delivery_sha384().into(),
            signature: SignatureProvenance {
                policy_sha384: signature.policy_sha384().into(),
                key_sha384: signature.key_sha384().into(),
                payload_sha384: signature.payload_sha384().into(),
                signature_sha384: signature.signature_sha384().into(),
                repository_sha384: sha384(signature.repository().as_bytes()),
            },
            kms_key_version: material.profile.kms_key_version.clone(),
            layers,
            builder: BuilderProvenance {
                tool_sha384: hex_digest(builder.tool_sha384()),
                input_tar_sha384: hex_digest(builder.input_tar_sha384()),
                image_sha384: hex_digest(builder.image_sha384()),
                image_bytes: builder.byte_len(),
                inodes: builder
                    .inodes()
                    .try_into()
                    .map_err(|_| CustodyProducerError::Backing)?,
            },
            candidate_spec_sha384: material.admission.binding().effective_launch_sha384.clone(),
        };
        provenance
            .validate(max_bytes)
            .map_err(CustodyProducerError::Protocol)?;
        Ok(provenance)
    }
}

fn hex_digest(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
