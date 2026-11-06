//! Attempt-owned GCP credentials from an authenticated recorder delivery.
//!
//! This default-off path does not use Hub initialization, a legacy KBS token,
//! environment variables, or credential files. It validates its own roots and
//! attempt scope before consuming an opaque credential. Construction performs
//! no OAuth/KMS request and does not authenticate a Google service account.
//! `decrypt_layer_once` invokes the existing GCP SDK for a preapproved layer
//! operation. The trusted embedding runtime must derive the bounded operation
//! list from its verified manifest; this adapter does not verify that manifest.

use execution_proof_contract::{LaunchBinding, ValidityWindow};
use execution_proof_handoff::admission::AcceptedAttemptContext;
use kbs_protocol::launch_recorder::AttemptCredential;
use kms::plugins::gcp::GcpKmsClient;
use kms::{Annotations, Decrypter};
use sha2::{Digest, Sha384};
use std::{collections::BTreeSet, fmt};
use zeroize::Zeroizing;

pub const MAX_KMS_CIPHERTEXT_BYTES: usize = 64 * 1024;

/// Operator/runtime-owned expectations, never derived from a delivery response.
/// The full binding pins boot, attempt, tenant, image/launch/profile commitments,
/// and the recorder key. The provider is fixed to GCP by this API's type.
#[derive(Clone)]
pub struct TrustedGcpAttempt {
    pub authority_public_key: [u8; 32],
    pub kbs_proof_public_key: [u8; 32],
    pub binding: LaunchBinding,
    pub grant_sha384: String,
    pub validity: ValidityWindow,
    pub workflow_id: String,
    pub resource_path: [String; 3],
    pub project_id: String,
    pub client_email: String,
    /// Full immutable CryptoKeyVersion name, never a caller-selected key alias.
    pub kms_key_version: String,
    /// Trusted profile budget, not a value taken from the delivery response.
    pub operation_limit: usize,
    /// Selected packets for encrypted layers of `binding.selected_manifest_sha256`.
    /// Manifest verification and construction of this list belong to the trusted
    /// preparation runtime; neither is implemented by this adapter.
    pub layer_operations: Vec<TrustedGcpLayerOperation>,
}

#[derive(Clone)]
pub struct TrustedGcpLayerOperation {
    /// Index in the selected manifest, including any unencrypted layers.
    pub layer_index: u32,
    /// SHA256 of the exact encrypted layer descriptor's blob, without a prefix.
    pub layer_digest_sha256: String,
    /// SHA384 of the selected wrapped KMS-DIRECT bytes for this layer.
    pub ciphertext_sha384: String,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum OperationState {
    Pending,
    Consumed,
    Succeeded,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialError {
    InvalidConfiguration,
    ScopeMismatch,
    UntrustedKey,
    InvalidCredential,
    InvalidCiphertext,
    AlreadyUsed,
    AttemptUnavailable,
    KmsOperationFailed,
}

impl fmt::Display for CredentialError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidConfiguration => "invalid attempt GCP configuration",
            Self::ScopeMismatch => "credential does not match the expected attempt",
            Self::UntrustedKey => "credential producer root mismatch",
            Self::InvalidCredential => "attempt GCP credential rejected",
            Self::InvalidCiphertext => "ciphertext does not match the approved KMS operation",
            Self::AlreadyUsed => "attempt GCP layer operation already consumed",
            Self::AttemptUnavailable => {
                "attempt GCP provider unavailable after failure or cancellation"
            }
            Self::KmsOperationFailed => "attempt Cloud KMS operation failed",
        })
    }
}
impl std::error::Error for CredentialError {}

/// Unique ownership of the actual provider, with no Clone/Debug/serde or secret
/// accessor. SDK-internal credential copies retain the SDK's existing lifetime
/// behavior; only the received plaintext buffer is explicitly zeroized here.
pub struct AttemptGcpDecrypter {
    client: Option<GcpKmsClient>,
    expected: TrustedGcpAttempt,
    operation_states: Vec<OperationState>,
    delivery_sha384: String,
}

impl AttemptGcpDecrypter {
    pub fn from_credential(
        credential: AttemptCredential,
        expected: TrustedGcpAttempt,
        admission: &AcceptedAttemptContext,
    ) -> Result<Self, CredentialError> {
        validate_configuration(&expected)?;
        if credential.authority_key_sha384() != hash(&expected.authority_public_key)
            || admission.authority_key_sha384() != hash(&expected.authority_public_key)
            || credential.delivery().kbs_proof_key_sha384() != hash(&expected.kbs_proof_public_key)
            || admission.aggregate_key_sha384() != hash(&expected.kbs_proof_public_key)
        {
            return Err(CredentialError::UntrustedKey);
        }
        if credential.binding() != &expected.binding
            || admission.binding() != &expected.binding
            || admission.grant_digest() != expected.grant_sha384
            || admission.aggregate_digest() != credential.delivery().aggregate_digest()
            || admission.validity() != &expected.validity
            || admission.workflow_id() != expected.workflow_id
            || admission.resource_path() != &expected.resource_path
            || credential.grant_digest() != expected.grant_sha384
            || credential.delivery().grant_digest() != expected.grant_sha384
            || credential.delivery().workflow_id() != expected.workflow_id
            || credential.delivery().resource_path() != &expected.resource_path
            || credential.delivery().validity() != &expected.validity
        {
            return Err(CredentialError::ScopeMismatch);
        }
        let delivery_sha384 = credential.delivery().digest_sha384().to_owned();
        let secret = credential.into_secret();
        let client = GcpKmsClient::from_credential_bytes(
            &secret,
            &expected.project_id,
            &expected.client_email,
        )
        .map_err(|_| CredentialError::InvalidCredential)?;
        drop(secret);
        // The authority already committed admission after checking its clock.
        // The gate authenticates that exact boot/attempt/aggregate and issues a
        // nonforgeable, one-use context; guest wall time is not an authority.
        Ok(Self {
            client: Some(client),
            operation_states: vec![OperationState::Pending; expected.layer_operations.len()],
            expected,
            delivery_sha384,
        })
    }

    pub fn grant_digest(&self) -> &str {
        &self.expected.grant_sha384
    }
    pub fn delivery_digest(&self) -> &str {
        &self.delivery_sha384
    }

    /// True only after every configured operation succeeded. This does not
    /// assert that image verification, unpacking, or protected handoff finished.
    pub fn all_operations_succeeded(&self) -> bool {
        self.client.is_some()
            && self
                .operation_states
                .iter()
                .all(|state| *state == OperationState::Succeeded)
    }

    /// Execute one preapproved layer operation through the existing provider.
    /// Each entry is consumed before awaiting the SDK. Failure or cancellation
    /// leaves the sole provider unavailable for the rest of this attempt.
    /// SDK-internal retries are not a guarantee of one physical network request.
    pub async fn decrypt_layer_once(
        &mut self,
        layer_index: u32,
        layer_digest_sha256: &str,
        ciphertext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, CredentialError> {
        let (mut client, position) =
            self.start_operation(layer_index, layer_digest_sha256, ciphertext)?;
        let plaintext = Zeroizing::new(
            client
                .decrypt(
                    ciphertext,
                    &self.expected.kms_key_version,
                    &Annotations::default(),
                )
                .await
                .map_err(|_| CredentialError::KmsOperationFailed)?,
        );
        self.finish_operation(client, position);
        Ok(plaintext)
    }

    fn start_operation(
        &mut self,
        layer_index: u32,
        layer_digest_sha256: &str,
        ciphertext: &[u8],
    ) -> Result<(GcpKmsClient, usize), CredentialError> {
        // Taking ownership first also makes a scope/packet rejection
        // terminal. Callers cannot ignore an error and continue preparation.
        let client = self
            .client
            .take()
            .ok_or(CredentialError::AttemptUnavailable)?;
        let position = self
            .expected
            .layer_operations
            .iter()
            .position(|operation| operation.layer_index == layer_index)
            .ok_or(CredentialError::ScopeMismatch)?;
        if self.operation_states[position] != OperationState::Pending {
            return Err(CredentialError::AlreadyUsed);
        }
        let operation = &self.expected.layer_operations[position];
        if operation.layer_digest_sha256 != layer_digest_sha256 {
            return Err(CredentialError::ScopeMismatch);
        }
        if ciphertext.is_empty()
            || ciphertext.len() > MAX_KMS_CIPHERTEXT_BYTES
            || hash(ciphertext) != operation.ciphertext_sha384
        {
            return Err(CredentialError::InvalidCiphertext);
        }
        self.operation_states[position] = OperationState::Consumed;
        Ok((client, position))
    }

    // Production calls this only after the actual SDK decrypt succeeded.
    fn finish_operation(&mut self, client: GcpKmsClient, position: usize) {
        self.operation_states[position] = OperationState::Succeeded;
        self.client = Some(client);
    }
}

fn validate_configuration(expected: &TrustedGcpAttempt) -> Result<(), CredentialError> {
    if expected.authority_public_key == [0; 32]
        || expected.kbs_proof_public_key == [0; 32]
        || expected.authority_public_key == expected.kbs_proof_public_key
        || !hash_field(&expected.grant_sha384)
        || !identifier(&expected.workflow_id)
        || expected.resource_path.iter().any(|part| !segment(part))
        || !segment(&expected.project_id)
        || expected.client_email.len() > 320
        || !expected.client_email.ends_with(".iam.gserviceaccount.com")
        || expected
            .client_email
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
        || expected.validity.validate().is_err()
        || !key_version(&expected.kms_key_version, &expected.project_id)
        || expected.operation_limit == 0
        || expected.layer_operations.is_empty()
        || expected.layer_operations.len() > expected.operation_limit
    {
        return Err(CredentialError::InvalidConfiguration);
    }
    let mut layer_indices = BTreeSet::new();
    for operation in &expected.layer_operations {
        if !digest_field(&operation.layer_digest_sha256, 64)
            || !hash_field(&operation.ciphertext_sha384)
            || !layer_indices.insert(operation.layer_index)
        {
            return Err(CredentialError::InvalidConfiguration);
        }
    }
    Ok(())
}

fn key_version(value: &str, project: &str) -> bool {
    if value.len() > 1024 {
        return false;
    }
    let parts: Vec<_> = value.split('/').collect();
    parts.len() == 10
        && parts[0] == "projects"
        && parts[1] == project
        && parts[2] == "locations"
        && parts[4] == "keyRings"
        && parts[6] == "cryptoKeys"
        && parts[8] == "cryptoKeyVersions"
        && [parts[1], parts[3], parts[5], parts[7]]
            .iter()
            .all(|part| segment(part))
        && !parts[9].is_empty()
        && parts[9].bytes().all(|byte| byte.is_ascii_digit())
        && parts[9].parse::<u64>().is_ok_and(|version| version > 0)
}
fn segment(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte))
}
fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.:-".contains(&byte))
}
fn hash_field(value: &str) -> bool {
    digest_field(value, 96)
}
fn digest_field(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn hash(bytes: &[u8]) -> String {
    Sha384::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_an_exact_versioned_key_in_the_configured_project_is_supported() {
        let key = "projects/project-1/locations/us-central1/keyRings/ring/cryptoKeys/key/cryptoKeyVersions/1";
        assert!(key_version(key, "project-1"));
        assert!(!key_version(&"/".repeat(2048), "project-1"));
        for other in [
            key.replace("project-1", "project-2"),
            key.replace("/1", "/latest"),
            key.replace("/1", "/0"),
            key.replace("/cryptoKeyVersions/1", ""),
            format!("{key}/extra"),
        ] {
            assert!(!key_version(&other, "project-1"));
        }
    }

    /// Exercise the SDK call's state guards without invoking OAuth or decrypt.
    /// Delivery authentication and Cloud KMS success require separate fixtures.
    fn guard_fixture() -> AttemptGcpDecrypter {
        let expected = TrustedGcpAttempt {
            authority_public_key: [1; 32], kbs_proof_public_key: [2; 32],
            binding: LaunchBinding {
                authority:"authority".into(),tenant:"tenant".into(),workload_id:"workload".into(),container_role:"application-init".into(),attempt_id:"attempt".into(),boot_id:"boot".into(),
                channel_key_sha384:"03".repeat(48),bootstrap_context_sha384:"04".repeat(48),selected_manifest_sha256:"05".repeat(32),effective_launch_sha384:"06".repeat(48),
                profile_sha384:"07".repeat(48),launch_policy_sha384:"08".repeat(48),image_policy_sha384:"09".repeat(48),challenge_sha384:"0a".repeat(48),
            },
            grant_sha384:"0b".repeat(48),validity:ValidityWindow{not_before:1000,expires:1030},
            workflow_id:"gcp-credential".into(),resource_path:["tenant".into(),"gcp-credential".into(),"v1".into()],
            project_id:"project-1".into(),client_email:"svc@project-1.iam.gserviceaccount.com".into(),
            kms_key_version:"projects/project-1/locations/us-central1/keyRings/ring/cryptoKeys/key/cryptoKeyVersions/1".into(),
            operation_limit: 2,
            layer_operations: vec![
                TrustedGcpLayerOperation {
                    layer_index: 0,
                    layer_digest_sha256: "11".repeat(32),
                    ciphertext_sha384: hash(b"wrapped-layer-key"),
                },
                TrustedGcpLayerOperation {
                    layer_index: 2,
                    layer_digest_sha256: "12".repeat(32),
                    ciphertext_sha384: hash(b"second-wrapped-layer-key"),
                },
            ],
        };
        validate_configuration(&expected).unwrap();
        let credential=br#"{"type":"service_account","project_id":"project-1","client_email":"svc@project-1.iam.gserviceaccount.com","private_key":"software-fixture-not-a-valid-key","token_uri":"https://oauth2.googleapis.com/token"}"#;
        let client = GcpKmsClient::from_credential_bytes(
            credential,
            &expected.project_id,
            &expected.client_email,
        )
        .unwrap();
        AttemptGcpDecrypter {
            client: Some(client),
            operation_states: vec![OperationState::Pending; expected.layer_operations.len()],
            expected,
            delivery_sha384: "0c".repeat(48),
        }
    }

    #[test]
    fn operation_plan_rejects_empty_over_budget_duplicate_and_malformed_entries() {
        let decrypter = guard_fixture();
        for change in [
            "empty",
            "zero-budget",
            "over-budget",
            "duplicate",
            "layer",
            "packet",
        ] {
            let mut expected = decrypter.expected.clone();
            match change {
                "empty" => expected.layer_operations.clear(),
                "zero-budget" => expected.operation_limit = 0,
                "over-budget" => expected.operation_limit = 1,
                "duplicate" => expected.layer_operations[1].layer_index = 0,
                "layer" => expected.layer_operations[0].layer_digest_sha256 = "bad".into(),
                "packet" => expected.layer_operations[0].ciphertext_sha384 = "bad".into(),
                _ => unreachable!(),
            }
            assert_eq!(
                validate_configuration(&expected).err(),
                Some(CredentialError::InvalidConfiguration),
                "{change}"
            );
        }
        let mut expected = decrypter.expected.clone();
        expected.layer_operations[1].layer_digest_sha256 =
            expected.layer_operations[0].layer_digest_sha256.clone();
        expected.layer_operations[1].ciphertext_sha384 =
            expected.layer_operations[0].ciphertext_sha384.clone();
        assert!(validate_configuration(&expected).is_ok());
    }

    #[test]
    fn two_preapproved_layer_guards_complete_under_the_same_configured_key() {
        let mut decrypter = guard_fixture();
        assert!(!decrypter.all_operations_succeeded());
        let (client, position) = decrypter
            .start_operation(0, &"11".repeat(32), b"wrapped-layer-key")
            .unwrap();
        assert!(!decrypter.all_operations_succeeded());
        decrypter.finish_operation(client, position);
        assert!(!decrypter.all_operations_succeeded());
        let (client, position) = decrypter
            .start_operation(2, &"12".repeat(32), b"second-wrapped-layer-key")
            .unwrap();
        assert!(!decrypter.all_operations_succeeded());
        decrypter.finish_operation(client, position);
        assert!(decrypter.all_operations_succeeded());
    }

    #[test]
    fn repeating_a_completed_operation_poison_remaining_preparation() {
        let mut decrypter = guard_fixture();
        let (client, position) = decrypter
            .start_operation(0, &"11".repeat(32), b"wrapped-layer-key")
            .unwrap();
        decrypter.finish_operation(client, position);
        assert_eq!(
            decrypter
                .start_operation(0, &"11".repeat(32), b"wrapped-layer-key")
                .err(),
            Some(CredentialError::AlreadyUsed)
        );
        assert_eq!(
            decrypter
                .start_operation(2, &"12".repeat(32), b"second-wrapped-layer-key")
                .err(),
            Some(CredentialError::AttemptUnavailable)
        );
        assert!(!decrypter.all_operations_succeeded());
    }

    #[tokio::test]
    async fn unknown_layer_digest_or_packet_rejects_before_sdk_and_poison_attempt() {
        for (index, digest, ciphertext, error) in [
            (
                1,
                "11".repeat(32),
                b"wrapped-layer-key".as_slice(),
                CredentialError::ScopeMismatch,
            ),
            (
                0,
                "ff".repeat(32),
                b"wrapped-layer-key".as_slice(),
                CredentialError::ScopeMismatch,
            ),
            (
                0,
                "11".repeat(32),
                b"unapproved-ciphertext".as_slice(),
                CredentialError::InvalidCiphertext,
            ),
            (
                0,
                "11".repeat(32),
                b"".as_slice(),
                CredentialError::InvalidCiphertext,
            ),
        ] {
            let mut decrypter = guard_fixture();
            assert_eq!(
                decrypter
                    .decrypt_layer_once(index, &digest, ciphertext)
                    .await
                    .err(),
                Some(error)
            );
            assert_eq!(
                decrypter
                    .start_operation(2, &"12".repeat(32), b"second-wrapped-layer-key")
                    .err(),
                Some(CredentialError::AttemptUnavailable)
            );
            assert!(!decrypter.all_operations_succeeded());
        }
    }

    #[test]
    fn losing_in_flight_client_prevents_remaining_operations_and_completion() {
        let mut decrypter = guard_fixture();
        let (client, _) = decrypter
            .start_operation(0, &"11".repeat(32), b"wrapped-layer-key")
            .unwrap();
        // This is the guard state left by cancellation or an SDK failure.
        drop(client);
        assert_eq!(
            decrypter
                .start_operation(2, &"12".repeat(32), b"second-wrapped-layer-key")
                .err(),
            Some(CredentialError::AttemptUnavailable)
        );
        assert!(!decrypter.all_operations_succeeded());
    }
}
