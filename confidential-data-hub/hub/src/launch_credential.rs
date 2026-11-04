//! Attempt-owned GCP credentials from an authenticated recorder delivery.
//!
//! This default-off path does not use Hub initialization, a legacy KBS token,
//! environment variables, or credential files. It validates its own roots and
//! attempt scope before consuming an opaque credential. Construction performs
//! no OAuth/KMS request and does not authenticate a Google service account.
//! `decrypt_once` invokes the actual GCP SDK path only when explicitly called;
//! it is not an unrestricted key-id/ciphertext decryption interface.

use execution_proof_contract::{LaunchBinding, ValidityWindow};
use kbs_protocol::launch_recorder::AttemptCredential;
use kms::{plugins::gcp::GcpKmsClient, Annotations, Decrypter};
use sha2::{Digest, Sha384};
use std::{fmt, sync::Arc};
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
    /// SHA384 of the exact wrapped KMS-DIRECT bytes approved for this attempt.
    pub ciphertext_sha384: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialClockError {
    Unavailable,
    OutOfRange,
}

/// Supplied by the trusted embedding runtime. There is no wall-clock default:
/// a host-controlled guest clock is insufficient, and an actual trusted guest
/// time source is not established by this software adapter.
pub trait CredentialClock: Send + Sync {
    fn now_unix_seconds(&self) -> Result<u64, CredentialClockError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialError {
    InvalidConfiguration,
    ScopeMismatch,
    UntrustedKey,
    InvalidCredential,
    InvalidCiphertext,
    AlreadyUsed,
    ClockUnavailable,
    ClockOutOfRange,
    ClockRegression,
    NotYetValid,
    Expired,
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
            Self::AlreadyUsed => "attempt GCP operation already consumed",
            Self::ClockUnavailable => "attempt credential clock unavailable",
            Self::ClockOutOfRange => "attempt credential clock out of range",
            Self::ClockRegression => "attempt credential clock regressed",
            Self::NotYetValid => "attempt credential is not yet valid",
            Self::Expired => "attempt credential expired",
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
    clock: Arc<dyn CredentialClock>,
    last_seen: u64,
    delivery_sha384: String,
}

impl AttemptGcpDecrypter {
    pub fn from_credential(
        credential: AttemptCredential,
        expected: TrustedGcpAttempt,
        clock: Arc<dyn CredentialClock>,
    ) -> Result<Self, CredentialError> {
        validate_configuration(&expected)?;
        if credential.authority_key_sha384() != hash(&expected.authority_public_key)
            || credential.delivery().kbs_proof_key_sha384() != hash(&expected.kbs_proof_public_key)
        {
            return Err(CredentialError::UntrustedKey);
        }
        if credential.binding() != &expected.binding
            || credential.grant_digest() != expected.grant_sha384
            || credential.delivery().grant_digest() != expected.grant_sha384
            || credential.delivery().workflow_id() != expected.workflow_id
            || credential.delivery().resource_path() != &expected.resource_path
            || credential.delivery().validity() != &expected.validity
        {
            return Err(CredentialError::ScopeMismatch);
        }
        let now = clock_now(clock.as_ref())?;
        check_window(&expected.validity, now)?;
        let delivery_sha384 = credential.delivery().digest_sha384().to_owned();
        let secret = credential.into_secret();
        let client = GcpKmsClient::from_credential_bytes(
            &secret,
            &expected.project_id,
            &expected.client_email,
        )
        .map_err(|_| CredentialError::InvalidCredential)?;
        drop(secret);
        // Parsing may take time; do not return a newly admitted provider after
        // clock failure, rollback, or expiry during construction.
        let later = clock_now(clock.as_ref())?;
        if later < now {
            return Err(CredentialError::ClockRegression);
        }
        check_window(&expected.validity, later)?;
        Ok(Self {
            client: Some(client),
            expected,
            clock,
            last_seen: later,
            delivery_sha384,
        })
    }

    pub fn grant_digest(&self) -> &str {
        &self.expected.grant_sha384
    }
    pub fn delivery_digest(&self) -> &str {
        &self.delivery_sha384
    }

    /// One explicit, exact KMS-DIRECT operation. The actual provider is consumed
    /// before awaiting the SDK, so cancellation, response loss, and SDK failure
    /// cannot silently trigger a second Cloud KMS call through this object.
    pub async fn decrypt_once(
        &mut self,
        ciphertext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, CredentialError> {
        let mut client = self.start_operation(ciphertext)?;
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
        self.observe_clock()?;
        Ok(plaintext)
    }

    fn start_operation(&mut self, ciphertext: &[u8]) -> Result<GcpKmsClient, CredentialError> {
        if self.client.is_none() {
            return Err(CredentialError::AlreadyUsed);
        }
        if ciphertext.is_empty()
            || ciphertext.len() > MAX_KMS_CIPHERTEXT_BYTES
            || hash(ciphertext) != self.expected.ciphertext_sha384
        {
            return Err(CredentialError::InvalidCiphertext);
        }
        self.observe_clock()?;
        self.client.take().ok_or(CredentialError::AlreadyUsed)
    }

    fn observe_clock(&mut self) -> Result<(), CredentialError> {
        let now = clock_now(self.clock.as_ref())?;
        if now < self.last_seen {
            return Err(CredentialError::ClockRegression);
        }
        self.last_seen = now;
        check_window(&self.expected.validity, now)
    }
}

fn validate_configuration(expected: &TrustedGcpAttempt) -> Result<(), CredentialError> {
    if expected.authority_public_key == [0; 32]
        || expected.kbs_proof_public_key == [0; 32]
        || expected.authority_public_key == expected.kbs_proof_public_key
        || !hash_field(&expected.grant_sha384)
        || !hash_field(&expected.ciphertext_sha384)
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
    {
        return Err(CredentialError::InvalidConfiguration);
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
    value.len() == 96
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
fn clock_now(clock: &dyn CredentialClock) -> Result<u64, CredentialError> {
    let now = clock.now_unix_seconds().map_err(|error| match error {
        CredentialClockError::Unavailable => CredentialError::ClockUnavailable,
        CredentialClockError::OutOfRange => CredentialError::ClockOutOfRange,
    })?;
    if now > i64::MAX as u64 {
        return Err(CredentialError::ClockOutOfRange);
    }
    Ok(now)
}
fn check_window(validity: &ValidityWindow, now: u64) -> Result<(), CredentialError> {
    if now < validity.not_before {
        return Err(CredentialError::NotYetValid);
    }
    if now >= validity.expires {
        return Err(CredentialError::Expired);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[test]
    fn only_an_exact_versioned_key_in_the_configured_project_is_supported() {
        let key="projects/project-1/locations/us-central1/keyRings/ring/cryptoKeys/key/cryptoKeyVersions/1";
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

    struct FixedClock(Result<u64, CredentialClockError>);
    impl CredentialClock for FixedClock {
        fn now_unix_seconds(&self) -> Result<u64, CredentialClockError> {
            self.0
        }
    }
    #[test]
    fn trusted_clock_and_half_open_window_checks_fail_closed() {
        assert_eq!(
            clock_now(&FixedClock(Err(CredentialClockError::Unavailable))).err(),
            Some(CredentialError::ClockUnavailable)
        );
        assert_eq!(
            clock_now(&FixedClock(Ok(u64::MAX))).err(),
            Some(CredentialError::ClockOutOfRange)
        );
        let window = ValidityWindow {
            not_before: 1000,
            expires: 1030,
        };
        assert_eq!(
            check_window(&window, 999).err(),
            Some(CredentialError::NotYetValid)
        );
        assert!(check_window(&window, 1000).is_ok());
        assert_eq!(
            check_window(&window, 1030).err(),
            Some(CredentialError::Expired)
        );
    }

    struct ManualClock(Mutex<Result<u64, CredentialClockError>>);
    impl CredentialClock for ManualClock {
        fn now_unix_seconds(&self) -> Result<u64, CredentialClockError> {
            *self.0.lock().unwrap()
        }
    }

    /// Construct the SDK provider from synthetic public JSON to test its guards.
    /// Delivery authentication, OAuth, and Cloud KMS are outside this fixture.
    fn guard_fixture() -> (AttemptGcpDecrypter, Arc<ManualClock>) {
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
            ciphertext_sha384:hash(b"wrapped-layer-key"),
        };
        validate_configuration(&expected).unwrap();
        let credential=br#"{"type":"service_account","project_id":"project-1","client_email":"svc@project-1.iam.gserviceaccount.com","private_key":"software-fixture-not-a-valid-key","token_uri":"https://oauth2.googleapis.com/token"}"#;
        let client = GcpKmsClient::from_credential_bytes(
            credential,
            &expected.project_id,
            &expected.client_email,
        )
        .unwrap();
        let clock = Arc::new(ManualClock(Mutex::new(Ok(1000))));
        (
            AttemptGcpDecrypter {
                client: Some(client),
                expected,
                clock: clock.clone(),
                last_seen: 1000,
                delivery_sha384: "0c".repeat(48),
            },
            clock,
        )
    }

    #[tokio::test]
    async fn unrelated_ciphertext_is_rejected_before_sdk_and_correct_operation_is_one_use() {
        let (mut decrypter, _) = guard_fixture();
        assert_eq!(
            decrypter.decrypt_once(b"unapproved-ciphertext").await.err(),
            Some(CredentialError::InvalidCiphertext)
        );
        drop(decrypter.start_operation(b"wrapped-layer-key").unwrap());
        assert_eq!(
            decrypter.decrypt_once(b"wrapped-layer-key").await.err(),
            Some(CredentialError::AlreadyUsed)
        );
    }

    #[tokio::test]
    async fn clock_failure_expiry_and_rollback_reject_before_sdk() {
        let (mut decrypter, clock) = guard_fixture();
        *clock.0.lock().unwrap() = Err(CredentialClockError::Unavailable);
        assert_eq!(
            decrypter.decrypt_once(b"wrapped-layer-key").await.err(),
            Some(CredentialError::ClockUnavailable)
        );
        *clock.0.lock().unwrap() = Ok(1030);
        assert_eq!(
            decrypter.decrypt_once(b"wrapped-layer-key").await.err(),
            Some(CredentialError::Expired)
        );
        *clock.0.lock().unwrap() = Ok(1029);
        assert_eq!(
            decrypter.decrypt_once(b"wrapped-layer-key").await.err(),
            Some(CredentialError::ClockRegression)
        );
        *clock.0.lock().unwrap() = Ok(u64::MAX);
        assert_eq!(
            decrypter.decrypt_once(b"wrapped-layer-key").await.err(),
            Some(CredentialError::ClockOutOfRange)
        );
    }
}
