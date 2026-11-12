//! GCP-v2 software authority/JWE through the actual bounded runtime actor.
//! TLS registry and image signatures are actual; KMS resolver and TDX evidence
//! are private fixtures. These tests cannot qualify a deployed producer.
use super::*;
use crate::gcp_launch_recorder::{
    test_support::{fixture_jwe as gcp_fixture_jwe, Fixture as GcpFixture},
    GcpLaunchRecorder,
};
use execution_proof_contract::{
    admission::gcp::policy_admission_context_gcp,
    gcp_policy_receipt::{
        verify_policy_aggregate as verify_gcp_aggregate, VerifiedGcpPolicyAggregate,
    },
};

struct GcpReceiptSigner {
    authority: Ed25519KeyPair,
    grant: VerifiedLaunchGrant,
    aggregate: VerifiedGcpPolicyAggregate,
    delivery: Delivery,
    audience: String,
    issuer: String,
    policy: String,
}
impl GcpReceiptSigner {
    fn delivery(mut self, nonce: &str) -> Delivery {
        let statement = AdmissionAuthorizationV1 {
            version: ADMISSION_VERSION,
            purpose: ADMISSION_PURPOSE.into(),
            profile: ADMISSION_PROFILE.into(),
            audience: self.audience,
            issuer: self.issuer,
            grant_id: self.grant.grant_id().into(),
            grant_sha384: self.grant.grant_digest().into(),
            aggregate_sha384: self.aggregate.digest_sha384().into(),
            aggregate_key_sha384: self.aggregate.kbs_proof_key_sha384().into(),
            context_sha384: policy_admission_context_gcp(
                &self.grant,
                &self.aggregate,
                nonce,
                &self.policy,
            )
            .unwrap(),
            guest_nonce: nonce.into(),
            admission_policy_sha384: self.policy,
            validity: *self.grant.validity(),
            binding: self.grant.binding().clone(),
        };
        self.delivery.receipt = serde_json::to_vec(&Signed {
            signature: self
                .authority
                .sign(&statement.signing_bytes().unwrap())
                .as_ref()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>(),
            statement,
        })
        .unwrap();
        self.delivery
    }
}

async fn inputs(
    image: &ContentFixture,
    parent: &StagingFixtureParent,
    signature_artifact_sha256: String,
) -> (GcpRuntimeAttemptConfig, GcpLaunchRecorder, GcpReceiptSigner) {
    let mut fixture =
        GcpFixture::ready_with_image_policy(hash256(&image.manifest), hash384(&image.policy)).await;
    let aggregate_wire = fixture.pin_and_sign();
    let admission = fixture.admission_config(fixture.expectations());
    let raw = fixture.raw_grant();
    let trusted = crate::gcp_cdh_tests::trusted_attempt(
        fixture.authority.public_key().as_ref().try_into().unwrap(),
        fixture.proof.public_key().as_ref().try_into().unwrap(),
        raw.binding.clone(),
        raw.digest_sha384().unwrap(),
    );
    let grant = execution_proof_contract::verify_launch_grant_historical(
        &fixture.signed_grant,
        &admission.grant,
    )
    .unwrap();
    let aggregate = verify_gcp_aggregate(&aggregate_wire, &grant, &admission.aggregate).unwrap();
    let credential = fixture.response(
        &aggregate_wire,
        &gcp_fixture_jwe(&fixture.public, SERVICE_ACCOUNT),
    );
    let signer = GcpReceiptSigner {
        authority: fixture.authority,
        grant,
        aggregate,
        delivery: Delivery {
            grant: fixture.signed_grant,
            aggregate: aggregate_wire,
            receipt: Vec::new(),
            credential,
        },
        audience: admission.audience.clone(),
        issuer: admission.issuer.clone(),
        policy: admission.admission_policy_sha384.clone(),
    };
    let config = GcpRuntimeAttemptConfig {
        admission,
        preparation: PreparationProfile {
            authority_public_key: trusted.authority_public_key,
            kbs_proof_public_key: trusted.kbs_proof_public_key,
            binding: trusted.binding,
            grant_sha384: trusted.grant_sha384,
            validity: trusted.validity,
            workflow_id: trusted.workflow_id,
            resource_path: trusted.resource_path,
            project_id: trusted.project_id,
            client_email: trusted.client_email,
            kms_key_version: trusted.kms_key_version,
        },
        metadata_limits: metadata_limits(),
        content_limits: content_limits(),
        staging_parent: parent.capability(),
        staging_limits: staging_limits(),
        signature_policy: image.verifier(),
        signature_artifact_sha256,
    };
    (config, fixture.recorder, signer)
}

#[tokio::test]
async fn gcp_actor_binds_nonce_jwe_content_and_retains_one_use_state() {
    let server = Server::new();
    let image = ContentFixture::new_for_repository(2, true, &server.repository());
    let signature = server.image(&image);
    let parent = StagingFixtureParent::new();
    let factory = RuntimeFactory::new(server.client(), 1, Duration::from_secs(10)).unwrap();
    let (config, recorder, signer) = inputs(&image, &parent, signature).await;
    let mut attempt = factory.begin_gcp_attempt(config, recorder).unwrap();
    let delivery = signer.delivery(attempt.challenge_nonce());
    use execution_proof_contract::admission::gcp::{GcpAdmissionOperation, GcpAdmissionRequestV2};
    let request: Signed<GcpAdmissionRequestV2> = serde_json::from_slice(
        &attempt
            .gcp_admission_request(&delivery.aggregate, GcpAdmissionOperation::Redeem)
            .unwrap(),
    )
    .unwrap();
    let receipt: Signed<AdmissionAuthorizationV1> =
        serde_json::from_slice(&delivery.receipt).unwrap();
    assert_eq!(
        request.statement.context_sha384,
        receipt.statement.context_sha384
    );
    assert_eq!(request.statement.audience, "recorder-fixture");
    assert_ne!(request.statement.audience, receipt.statement.audience);
    assert!(attempt.gcp_credential_request(&delivery.aggregate).is_ok());
    let mut wrong_aggregate = delivery.aggregate.clone();
    wrong_aggregate.push(b'X');
    assert_eq!(
        attempt.gcp_admission_request(&wrong_aggregate, GcpAdmissionOperation::Redeem),
        Err(RuntimeError::AdmissionRejected)
    );
    assert_eq!(
        attempt.gcp_credential_request(&wrong_aggregate),
        Err(RuntimeError::CredentialRejected)
    );
    let trace = Arc::new(Mutex::new(Trace::default()));
    assert_eq!(
        attempt
            .prepare_fixture(delivery.borrowed(), image.replies(), trace.clone())
            .await,
        Ok(ContentBinding::FirstChecked)
    );
    let summary = attempt.summary().unwrap().clone();
    assert_eq!(summary.manifest_sha256, hash256(&image.manifest));
    assert_eq!(summary.layers, 2);
    assert_eq!(parent.children(), 1);
    assert_eq!(
        attempt.gcp_admission_request(&delivery.aggregate, GcpAdmissionOperation::Status),
        Err(RuntimeError::Unavailable)
    );
    assert_eq!(
        attempt.gcp_credential_request(&delivery.aggregate),
        Err(RuntimeError::Unavailable)
    );
    let requests = server.requests();
    assert_eq!(
        attempt.prepare(delivery.borrowed()).await,
        Ok(ContentBinding::Historical)
    );
    assert_eq!(attempt.summary().unwrap(), &summary);
    assert_eq!(requests, server.requests());
    assert_eq!(trace.lock().unwrap().calls.len(), 2);
    attempt.cancel_and_wait().await.unwrap();
    assert_eq!(parent.children(), 0);
    assert!(attempt.prepare(delivery.borrowed()).await.is_err());
}

#[tokio::test]
async fn gcp_runtime_rejects_wrong_boot_binding_and_mixed_roots_before_ingress() {
    let server = Server::new();
    let image = ContentFixture::new_for_repository(1, false, &server.repository());
    let signature = server.image(&image);
    let parent = StagingFixtureParent::new();
    let factory = RuntimeFactory::new(server.client(), 1, Duration::from_secs(10)).unwrap();
    for changed in ["B", "root", "scope", "workflow", "locator"] {
        let (mut config, recorder, _) = inputs(&image, &parent, signature.clone()).await;
        match changed {
            "B" => {
                config
                    .admission
                    .aggregate
                    .boot_binding
                    .artifact_manifest_sha384 = "71".repeat(48)
            }
            "root" => config.preparation.kbs_proof_public_key = [71; 32],
            "scope" => config.preparation.binding.boot_id = "foreign".into(),
            "workflow" => config.preparation.workflow_id = "foreign".into(),
            "locator" => config.signature_artifact_sha256 = "not-a-digest".into(),
            _ => unreachable!(),
        }
        assert!(
            matches!(
                factory.begin_gcp_attempt(config, recorder),
                Err(RuntimeError::InvalidConfiguration)
            ),
            "{changed}"
        );
    }
    assert!(server.requests().is_empty());
    assert_eq!(parent.children(), 0);
}

#[tokio::test]
async fn gcp_bad_nonce_or_credential_fail_closed_and_release_actor_capacity() {
    let server = Server::new();
    let image = ContentFixture::new_for_repository(1, false, &server.repository());
    let signature = server.image(&image);
    let parent = StagingFixtureParent::new();
    let factory = RuntimeFactory::new(server.client(), 1, Duration::from_secs(10)).unwrap();
    for changed in ["nonce", "credential"] {
        let (config, recorder, signer) = inputs(&image, &parent, signature.clone()).await;
        let mut attempt = factory.begin_gcp_attempt(config, recorder).unwrap();
        let wrong_nonce = "01".repeat(32);
        let mut delivery = signer.delivery(if changed == "nonce" {
            &wrong_nonce
        } else {
            attempt.challenge_nonce()
        });
        if changed == "credential" {
            delivery.credential.push(b'X');
        }
        let expected = if changed == "nonce" {
            RuntimeError::AdmissionRejected
        } else {
            RuntimeError::CredentialRejected
        };
        assert_eq!(
            attempt
                .prepare_fixture(
                    delivery.borrowed(),
                    image.replies(),
                    Arc::new(Mutex::new(Trace::default()))
                )
                .await,
            Err(expected)
        );
        assert!(attempt.summary().is_err());
        attempt.cancel_and_wait().await.unwrap();
        assert!(attempt.prepare(delivery.borrowed()).await.is_err());
    }
    assert!(server.requests().is_empty());
    assert_eq!(parent.children(), 0);
}
