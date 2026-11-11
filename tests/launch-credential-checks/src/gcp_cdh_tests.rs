//! Recorder signatures, RSA/AES decryption, and GCP credential loading in memory.
//! No file, OAuth token, Cloud KMS request, or SDK stub is used in this suite.

use crate::{
    gcp_launch_recorder::{
        GcpAttemptCredential, RecorderError,
        test_support::{Fixture, fixture_jwe},
    },
    launch_credential::*,
};
use execution_proof_contract::{
    GrantExpectations, LaunchBinding, LaunchGrant, Signed, ValidityWindow,
    gcp_policy_receipt::GcpAggregateExpectations,
};
use execution_proof_handoff::admission::AcceptedAttemptContext;
use ring::signature::KeyPair;
use sha2::{Digest, Sha384};

pub(crate) const SERVICE_ACCOUNT:&[u8]=br#"{"type":"service_account","project_id":"project-1","client_email":"svc@project-1.iam.gserviceaccount.com","private_key":"software-fixture-not-a-valid-private-key","token_uri":"https://oauth2.googleapis.com/token"}"#;
const WRAPPED_KMS_BYTES: &[u8] = b"software-wrapped-layer-key";

fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

impl Fixture {
    pub(crate) fn raw_grant(&self) -> LaunchGrant {
        serde_json::from_slice::<Signed<LaunchGrant>>(&self.signed_grant)
            .unwrap()
            .statement
    }
    pub(crate) fn admission_config(
        &self,
        aggregate: GcpAggregateExpectations,
    ) -> execution_proof_handoff::admission::gcp::GcpGuestAdmissionConfig {
        use execution_proof_handoff::admission::gcp::GcpGuestAdmissionConfig;
        let raw = self.raw_grant();
        let binding = &raw.binding;
        GcpGuestAdmissionConfig {
            grant: GrantExpectations {
                authority_public_key: self.authority.public_key().as_ref().try_into().unwrap(),
                audience: raw.audience.clone(),
                authority: binding.authority.clone(),
                tenant: binding.tenant.clone(),
                profile_sha384: binding.profile_sha384.clone(),
                launch_policy_sha384: binding.launch_policy_sha384.clone(),
                image_policy_sha384: binding.image_policy_sha384.clone(),
            },
            expected_grant: raw,
            aggregate,
            audience: "preparation-guest".into(),
            issuer: "authority-issuer".into(),
            admission_policy_sha384: "19".repeat(48),
        }
    }

    /// Signed admission fixture without a durable issuer/SQLite commit.
    fn admission_bundle(
        &self,
        expected: GcpAggregateExpectations,
    ) -> (
        execution_proof_handoff::admission::gcp::GcpGuestAdmissionGate,
        Vec<u8>,
        Vec<u8>,
    ) {
        use execution_proof_contract::{
            admission::{
                ADMISSION_PROFILE, ADMISSION_PURPOSE, ADMISSION_VERSION, AdmissionAuthorizationV1,
                gcp::policy_admission_context_gcp,
            },
            gcp_policy_receipt::verify_policy_aggregate,
        };
        use execution_proof_handoff::admission::gcp::GcpGuestAdmissionGate;

        let aggregate = serde_json::to_vec(&Signed {
            signature: hex_bytes(
                self.proof
                    .sign(&expected.expected.signing_bytes().unwrap())
                    .as_ref(),
            ),
            statement: expected.expected.clone(),
        })
        .unwrap();
        let config = self.admission_config(expected);
        let grant = execution_proof_contract::verify_launch_grant_historical(
            &self.signed_grant,
            &config.grant,
        )
        .unwrap();
        let verified = verify_policy_aggregate(&aggregate, &grant, &config.aggregate).unwrap();
        let audience = config.audience.clone();
        let issuer = config.issuer.clone();
        let policy = config.admission_policy_sha384.clone();
        let gate = GcpGuestAdmissionGate::new(config).unwrap();
        let statement = AdmissionAuthorizationV1 {
            version: ADMISSION_VERSION,
            purpose: ADMISSION_PURPOSE.into(),
            audience,
            issuer,
            profile: ADMISSION_PROFILE.into(),
            grant_id: grant.grant_id().into(),
            grant_sha384: grant.grant_digest().into(),
            aggregate_sha384: verified.digest_sha384().into(),
            aggregate_key_sha384: verified.kbs_proof_key_sha384().into(),
            context_sha384: policy_admission_context_gcp(
                &grant,
                &verified,
                gate.challenge_nonce(),
                &policy,
            )
            .unwrap(),
            guest_nonce: gate.challenge_nonce().into(),
            admission_policy_sha384: policy,
            validity: *grant.validity(),
            binding: grant.binding().clone(),
        };
        let receipt = serde_json::to_vec(&Signed {
            signature: hex_bytes(
                self.authority
                    .sign(&statement.signing_bytes().unwrap())
                    .as_ref(),
            ),
            statement,
        })
        .unwrap();
        (gate, aggregate, receipt)
    }
}

struct AdmittedCredentialFixture {
    pub credential: GcpAttemptCredential,
    pub authority: [u8; 32],
    pub producer: [u8; 32],
    pub binding: LaunchBinding,
    pub grant_digest: String,
    pub admission: execution_proof_handoff::admission::AcceptedAttemptContext,
}

async fn credential_fixture_with_admission(plaintext: &[u8]) -> AdmittedCredentialFixture {
    admitted_credential_fixture(plaintext, false).await
}

/// Different authenticated aggregate, with the same grant, binding, and roots.
async fn credential_fixture_with_other_aggregate(plaintext: &[u8]) -> AdmittedCredentialFixture {
    admitted_credential_fixture(plaintext, true).await
}

async fn admitted_credential_fixture(
    plaintext: &[u8],
    other_aggregate: bool,
) -> AdmittedCredentialFixture {
    let f = Fixture::ready().await;
    admitted_from_fixture(f, plaintext, other_aggregate)
}

fn admitted_from_fixture(
    mut f: Fixture,
    plaintext: &[u8],
    other_aggregate: bool,
) -> AdmittedCredentialFixture {
    let aggregate = f.pin_and_sign();
    let mut admission_expected = f.expectations();
    if other_aggregate {
        admission_expected.expected.kbs_evaluation.input_sha384 = "21".repeat(48);
    }
    let (gate, admitted_aggregate, receipt) = f.admission_bundle(admission_expected);
    gate.verify_bundle(&f.signed_grant, &admitted_aggregate, &receipt)
        .unwrap();
    let admission = gate.take_accepted_attempt().unwrap();
    assert!(gate.take_accepted_attempt().is_err());
    let authority = f.authority.public_key().as_ref().try_into().unwrap();
    let producer = f.proof.public_key().as_ref().try_into().unwrap();
    let raw = f.raw_grant();
    let binding = raw.binding.clone();
    let grant_digest = raw.digest_sha384().unwrap();
    let jwe = fixture_jwe(&f.public, plaintext);
    let response = f.response(&aggregate, &jwe);
    let credential = f
        .recorder
        .decrypt_credential_response(&response, &aggregate)
        .unwrap();
    // Consuming the unique opaque credential cannot be retried at its source.
    assert_eq!(
        f.recorder
            .decrypt_credential_response(&response, &aggregate)
            .err(),
        Some(RecorderError::AlreadyConsumed)
    );
    AdmittedCredentialFixture {
        credential,
        authority,
        producer,
        binding,
        grant_digest,
        admission,
    }
}

#[tokio::test]
async fn historical_signed_admission_is_boot_local_and_mints_context_once() {
    use execution_proof_handoff::admission::{AdmissionCheck, gcp::GcpGuestAdmissionGate};

    let mut f = Fixture::ready().await;
    f.pin_and_sign();
    // Authority live acceptance is a separate check. No trusted guest clock is
    // available, and a committed receipt has no physical-execution deadline.
    assert!(f.raw_grant().validity.check_at(200).is_err());
    let (gate, aggregate, receipt) = f.admission_bundle(f.expectations());
    assert!(matches!(
        gate.verify_bundle(&f.signed_grant, &aggregate, &receipt),
        Ok(AdmissionCheck::FirstVerified)
    ));
    let context = gate.take_accepted_attempt().unwrap();
    assert_eq!(context.binding(), &f.raw_grant().binding);
    assert_eq!(
        context.aggregate_digest(),
        f.expectations().expected.digest_sha384().unwrap()
    );
    assert!(matches!(
        gate.verify_bundle(&f.signed_grant, &aggregate, &receipt),
        Ok(AdmissionCheck::Historical)
    ));
    assert!(gate.take_accepted_attempt().is_err());

    let fresh = GcpGuestAdmissionGate::new(f.admission_config(f.expectations())).unwrap();
    assert_ne!(fresh.challenge_nonce(), context.guest_nonce());
    assert!(
        fresh
            .verify_bundle(&f.signed_grant, &aggregate, &receipt)
            .is_err()
    );
    assert!(fresh.take_accepted_attempt().is_err());
}

async fn fixture(
    plaintext: &[u8],
) -> (
    crate::gcp_launch_recorder::GcpAttemptCredential,
    TrustedGcpAttempt,
    AcceptedAttemptContext,
) {
    // The expected binding/digest are captured from the trusted recorder's
    // independently authenticated L before it consumes the delivery response.
    let AdmittedCredentialFixture {
        credential,
        authority,
        producer: kbs,
        binding,
        grant_digest: grant_sha384,
        admission,
    } = credential_fixture_with_admission(plaintext).await;
    assert_eq!(binding.boot_id.len(), 64);
    assert_eq!(binding.attempt_id, "attempt");
    let expected = trusted_attempt(authority, kbs, binding, grant_sha384);
    (credential, expected, admission)
}

pub(crate) fn trusted_attempt(
    authority: [u8; 32],
    kbs: [u8; 32],
    binding: execution_proof_contract::LaunchBinding,
    grant_sha384: String,
) -> TrustedGcpAttempt {
    TrustedGcpAttempt {
        authority_public_key:authority,kbs_proof_public_key:kbs,binding,grant_sha384,
        validity:ValidityWindow{not_before:100,expires:200},workflow_id:"gcp-credential".into(),
        resource_path:["tenant".into(),"credential".into(),"v1".into()],project_id:"project-1".into(),
        client_email:"svc@project-1.iam.gserviceaccount.com".into(),
        kms_key_version:"projects/project-1/locations/us-central1/keyRings/ring/cryptoKeys/key/cryptoKeyVersions/1".into(),
        operation_limit: 1,
        layer_operations: vec![TrustedGcpLayerOperation {
            layer_index: 0,
            layer_digest_sha256: "15".repeat(32),
            ciphertext_sha384:Sha384::digest(WRAPPED_KMS_BYTES).iter().map(|byte|format!("{byte:02x}")).collect(),
        }],
    }
}

#[tokio::test]
async fn authenticated_opaque_credential_constructs_actual_gcp_provider_in_memory_only() {
    let (credential, expected, admission) = fixture(SERVICE_ACCOUNT).await;
    let grant = expected.grant_sha384.clone();
    let delivery = credential.delivery().digest_sha384().to_owned();
    let mut provider =
        AttemptGcpDecrypter::from_gcp_credential(credential, expected, &admission).unwrap();
    assert_eq!(provider.grant_digest(), grant);
    assert_eq!(provider.delivery_digest(), delivery);
    // Wrong ciphertext exits before the real SDK path. A successful constructor
    // proves neither valid private PEM nor a Cloud KMS operation.
    assert_eq!(
        provider
            .decrypt_layer_once(0, &"15".repeat(32), b"unapproved-wrapped-key")
            .await
            .err(),
        Some(CredentialError::InvalidCiphertext)
    );
}

#[tokio::test]
async fn actual_root_fingerprints_are_checked_in_addition_to_identical_binding() {
    for change_authority in [true, false] {
        let (credential, mut expected, admission) = fixture(SERVICE_ACCOUNT).await;
        if change_authority {
            expected.authority_public_key = [0x71; 32];
        } else {
            expected.kbs_proof_public_key = [0x72; 32];
        }
        assert_eq!(
            AttemptGcpDecrypter::from_gcp_credential(credential, expected, &admission).err(),
            Some(CredentialError::UntrustedKey)
        );
    }
}

#[tokio::test]
async fn own_boot_attempt_workflow_resource_and_grant_scope_are_required() {
    for field in [
        "boot", "attempt", "image", "profile", "recorder", "workflow", "resource", "grant",
    ] {
        let (credential, mut expected, admission) = fixture(SERVICE_ACCOUNT).await;
        match field {
            "boot" => expected.binding.boot_id = "other-boot".into(),
            "attempt" => expected.binding.attempt_id = "other-attempt".into(),
            "image" => expected.binding.selected_manifest_sha256 = "74".repeat(32),
            "profile" => expected.binding.profile_sha384 = "75".repeat(48),
            "recorder" => expected.binding.channel_key_sha384 = "76".repeat(48),
            "workflow" => expected.workflow_id = "other-workflow".into(),
            "resource" => expected.resource_path[0] = "other-tenant".into(),
            "grant" => expected.grant_sha384 = "73".repeat(48),
            _ => unreachable!(),
        }
        assert_eq!(
            AttemptGcpDecrypter::from_gcp_credential(credential, expected, &admission).err(),
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
        let (credential, expected, admission) = fixture(&bytes).await;
        assert_eq!(
            AttemptGcpDecrypter::from_gcp_credential(credential, expected, &admission).err(),
            Some(CredentialError::InvalidCredential),
            "{field}"
        );
    }
}

#[tokio::test]
async fn admitted_context_must_match_the_actual_delivery_aggregate() {
    let AdmittedCredentialFixture {
        credential,
        authority,
        producer,
        binding,
        grant_digest,
        admission,
    } = credential_fixture_with_other_aggregate(SERVICE_ACCOUNT).await;
    assert_eq!(credential.binding(), admission.binding());
    assert_eq!(credential.grant_digest(), admission.grant_digest());
    assert_ne!(
        credential.delivery().aggregate_digest(),
        admission.aggregate_digest()
    );
    // Matching trusted roots and exact grant/binding cannot compensate for a
    // different aggregate admitted under those same trusted signing keys.
    let expected = trusted_attempt(authority, producer, binding, grant_digest);
    assert_eq!(
        AttemptGcpDecrypter::from_gcp_credential(credential, expected, &admission).err(),
        Some(CredentialError::ScopeMismatch)
    );
}

#[tokio::test]
async fn a_real_admission_from_another_authority_does_not_authorize_this_credential() {
    let (credential, expected, _) = fixture(SERVICE_ACCOUNT).await;
    let (_, _, admission) = fixture(SERVICE_ACCOUNT).await;
    assert_eq!(
        AttemptGcpDecrypter::from_gcp_credential(credential, expected, &admission).err(),
        Some(CredentialError::UntrustedKey)
    );
}

#[tokio::test]
async fn signed_validity_is_scope_not_a_guest_clock_dependency() {
    let (credential, expected, admission) = fixture(SERVICE_ACCOUNT).await;
    assert!(expected.validity.check_at(200).is_err());
    assert_eq!(credential.delivery().validity(), &expected.validity);
    assert_eq!(admission.validity(), &expected.validity);
    // Exercise signatures, gate admission, JWE, and SDK credential loading.
    // Authority time and SQLite commits belong to the issuer suite.
    assert!(AttemptGcpDecrypter::from_gcp_credential(credential, expected, &admission).is_ok());

    let (credential, mut expected, admission) = fixture(SERVICE_ACCOUNT).await;
    expected.validity.expires += 1;
    assert_eq!(
        AttemptGcpDecrypter::from_gcp_credential(credential, expected, &admission).err(),
        Some(CredentialError::ScopeMismatch)
    );
    let (credential, mut expected, admission) = fixture(SERVICE_ACCOUNT).await;
    expected.validity.expires = expected.validity.not_before;
    assert_eq!(
        AttemptGcpDecrypter::from_gcp_credential(credential, expected, &admission).err(),
        Some(CredentialError::InvalidConfiguration)
    );
}

#[cfg(feature = "launch-preparation-gcp")]
pub(crate) async fn preparation_fixture(
    manifest_sha256: String,
) -> (
    GcpAttemptCredential,
    TrustedGcpAttempt,
    AcceptedAttemptContext,
) {
    let f = Fixture::ready_with_manifest(manifest_sha256).await;
    let f = admitted_from_fixture(f, SERVICE_ACCOUNT, false);
    let expected = trusted_attempt(f.authority, f.producer, f.binding, f.grant_digest);
    (f.credential, expected, f.admission)
}

#[cfg(feature = "launch-preparation-content-gcp")]
pub(crate) async fn content_preparation_fixture(
    manifest_sha256: String,
    image_policy_sha384: String,
) -> (
    GcpAttemptCredential,
    TrustedGcpAttempt,
    AcceptedAttemptContext,
) {
    // Both commitments are fixed before authority/grant/admission signatures.
    let f = Fixture::ready_with_image_policy(manifest_sha256, image_policy_sha384).await;
    let f = admitted_from_fixture(f, SERVICE_ACCOUNT, false);
    let expected = trusted_attempt(f.authority, f.producer, f.binding, f.grant_digest);
    (f.credential, expected, f.admission)
}
