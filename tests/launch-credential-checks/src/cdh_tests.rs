//! Recorder signatures, RSA/AES decryption, and GCP credential loading in memory.
//! No file, OAuth token, Cloud KMS request, or SDK stub is used in this suite.

use crate::{launch_credential::*, launch_recorder::test_support::credential_fixture_with_scope};
use execution_proof_contract::ValidityWindow;
use sha2::{Digest, Sha384};
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};

const SERVICE_ACCOUNT:&[u8]=br#"{"type":"service_account","project_id":"project-1","client_email":"svc@project-1.iam.gserviceaccount.com","private_key":"software-fixture-not-a-valid-private-key","token_uri":"https://oauth2.googleapis.com/token"}"#;
const WRAPPED_KMS_BYTES: &[u8] = b"software-wrapped-layer-key";

struct Clock(Mutex<VecDeque<Result<u64, CredentialClockError>>>);
impl Clock {
    fn fixed(now: u64) -> Arc<Self> {
        Self::sequence([Ok(now)])
    }
    fn sequence(values: impl IntoIterator<Item = Result<u64, CredentialClockError>>) -> Arc<Self> {
        Arc::new(Self(Mutex::new(values.into_iter().collect())))
    }
}
impl CredentialClock for Clock {
    fn now_unix_seconds(&self) -> Result<u64, CredentialClockError> {
        let mut values = self.0.lock().unwrap();
        if values.len() > 1 {
            values.pop_front().unwrap()
        } else {
            *values.front().unwrap()
        }
    }
}

async fn fixture(
    plaintext: &[u8],
) -> (crate::launch_recorder::AttemptCredential, TrustedGcpAttempt) {
    // The expected binding/digest are captured from the trusted recorder's
    // independently authenticated L before it consumes the delivery response.
    let (credential, authority, kbs, binding, grant_sha384) =
        credential_fixture_with_scope(plaintext).await;
    assert_eq!(binding.boot_id, "boot");
    assert_eq!(binding.attempt_id, "attempt");
    let expected=TrustedGcpAttempt {
        authority_public_key:authority,kbs_proof_public_key:kbs,binding,grant_sha384,
        validity:ValidityWindow{not_before:100,expires:200},workflow_id:"gcp-credential".into(),
        resource_path:["tenant".into(),"credential".into(),"v1".into()],project_id:"project-1".into(),
        client_email:"svc@project-1.iam.gserviceaccount.com".into(),
        kms_key_version:"projects/project-1/locations/us-central1/keyRings/ring/cryptoKeys/key/cryptoKeyVersions/1".into(),
        ciphertext_sha384:Sha384::digest(WRAPPED_KMS_BYTES).iter().map(|byte|format!("{byte:02x}")).collect(),
    };
    (credential, expected)
}

#[tokio::test]
async fn authenticated_opaque_credential_constructs_actual_gcp_provider_in_memory_only() {
    let (credential, expected) = fixture(SERVICE_ACCOUNT).await;
    let grant = expected.grant_sha384.clone();
    let delivery = credential.delivery().digest_sha384().to_owned();
    let mut provider =
        AttemptGcpDecrypter::from_credential(credential, expected, Clock::fixed(100)).unwrap();
    assert_eq!(provider.grant_digest(), grant);
    assert_eq!(provider.delivery_digest(), delivery);
    // Wrong ciphertext exits before the real SDK path. A successful constructor
    // proves neither valid private PEM nor a Cloud KMS operation.
    assert_eq!(
        provider.decrypt_once(b"unapproved-wrapped-key").await.err(),
        Some(CredentialError::InvalidCiphertext)
    );
}

#[tokio::test]
async fn actual_root_fingerprints_are_checked_in_addition_to_identical_binding() {
    for change_authority in [true, false] {
        let (credential, mut expected) = fixture(SERVICE_ACCOUNT).await;
        if change_authority {
            expected.authority_public_key = [0x71; 32];
        } else {
            expected.kbs_proof_public_key = [0x72; 32];
        }
        assert_eq!(
            AttemptGcpDecrypter::from_credential(credential, expected, Clock::fixed(100)).err(),
            Some(CredentialError::UntrustedKey)
        );
    }
}

#[tokio::test]
async fn own_boot_attempt_workflow_resource_and_grant_scope_are_required() {
    for field in ["boot", "attempt", "workflow", "resource", "grant"] {
        let (credential, mut expected) = fixture(SERVICE_ACCOUNT).await;
        match field {
            "boot" => expected.binding.boot_id = "other-boot".into(),
            "attempt" => expected.binding.attempt_id = "other-attempt".into(),
            "workflow" => expected.workflow_id = "other-workflow".into(),
            "resource" => expected.resource_path[0] = "other-tenant".into(),
            "grant" => expected.grant_sha384 = "73".repeat(48),
            _ => unreachable!(),
        }
        assert_eq!(
            AttemptGcpDecrypter::from_credential(credential, expected, Clock::fixed(100)).err(),
            Some(CredentialError::ScopeMismatch),
            "{field}"
        );
    }
}

#[tokio::test]
async fn authenticated_delivery_does_not_bypass_strict_gcp_credential_scope() {
    for field in ["type", "project_id", "client_email", "token_uri"] {
        let mut plaintext: serde_json::Value = serde_json::from_slice(SERVICE_ACCOUNT).unwrap();
        plaintext[field] = serde_json::Value::String(
            match field {
                "type" => "aws",
                "project_id" => "other-project",
                "client_email" => "other@project-1.iam.gserviceaccount.com",
                _ => "https://attacker.invalid/token",
            }
            .into(),
        );
        let bytes = serde_json::to_vec(&plaintext).unwrap();
        let (credential, expected) = fixture(&bytes).await;
        assert_eq!(
            AttemptGcpDecrypter::from_credential(credential, expected, Clock::fixed(100)).err(),
            Some(CredentialError::InvalidCredential),
            "{field}"
        );
    }
}

#[tokio::test]
async fn constructor_clock_is_injected_and_rechecked_after_credential_parsing() {
    for (times, error) in [
        (vec![Ok(100), Ok(200)], CredentialError::Expired),
        (vec![Ok(101), Ok(100)], CredentialError::ClockRegression),
        (
            vec![Ok(100), Err(CredentialClockError::Unavailable)],
            CredentialError::ClockUnavailable,
        ),
    ] {
        let (credential, expected) = fixture(SERVICE_ACCOUNT).await;
        assert_eq!(
            AttemptGcpDecrypter::from_credential(credential, expected, Clock::sequence(times))
                .err(),
            Some(error)
        );
    }
}
