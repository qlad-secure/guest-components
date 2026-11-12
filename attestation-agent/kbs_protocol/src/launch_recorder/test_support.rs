//! Software evidence fixtures and generated RSA/AES-GCM roundtrips.
//! No fixture is reachable from the production attester factory.

use super::*;
use base64::engine::general_purpose::STANDARD;
use execution_proof_contract::{
    GRANT_PURPOSE, LaunchGrant, Signed, VERSION, ValidityWindow,
    credential::{
        CREDENTIAL_DELIVERY_PROFILE, CREDENTIAL_DELIVERY_PURPOSE, CREDENTIAL_DELIVERY_VERSION,
        CredentialDeliveryV1,
    },
    policy_receipt::{LaunchPolicyAggregateV1, PolicyCommitments},
};
use ring::rand::SecureRandom;
use serde_json::{Value, json};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

fn key() -> Ed25519KeyPair {
    let encoded = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    Ed25519KeyPair::from_pkcs8(encoded.as_ref()).unwrap()
}

pub(crate) struct Fixture {
    pub(crate) recorder: LaunchRecorder,
    pub(crate) proof: Ed25519KeyPair,
    pub(crate) public: kbs_types::TeePubKey,
    pub(crate) authority: Ed25519KeyPair,
    pub(crate) signed_grant: Vec<u8>,
}
impl Fixture {
    fn new() -> Self {
        Self::new_with_manifest("02".repeat(32))
    }
    fn new_with_manifest(manifest_sha256: String) -> Self {
        Self::new_with_image_policy(manifest_sha256, "06".repeat(48))
    }
    fn new_with_image_policy(manifest_sha256: String, image_policy_sha384: String) -> Self {
        Self::new_with_effective_spec(manifest_sha256, image_policy_sha384, "03".repeat(48))
    }
    fn new_with_effective_spec(
        manifest_sha256: String,
        image_policy_sha384: String,
        effective_launch_sha384: String,
    ) -> Self {
        let keys = LaunchKeys::generate().unwrap();
        let public = keys.keywrap_public_key().unwrap();
        let authority = key();
        let proof = key();
        let raw = LaunchGrant {
            version: VERSION,
            purpose: GRANT_PURPOSE.into(),
            audience: "recorder-fixture".into(),
            proof_required: true,
            grant_id: "grant".into(),
            validity: ValidityWindow {
                not_before: 100,
                expires: 200,
            },
            binding: LaunchBinding {
                authority: "authority".into(),
                tenant: "tenant".into(),
                workload_id: "workload".into(),
                container_role: "application-init".into(),
                attempt_id: "attempt".into(),
                boot_id: "boot".into(),
                channel_key_sha384: hash(&keys.recorder_public_key()),
                bootstrap_context_sha384: "01".repeat(48),
                selected_manifest_sha256: manifest_sha256,
                effective_launch_sha384,
                profile_sha384: "04".repeat(48),
                launch_policy_sha384: "05".repeat(48),
                image_policy_sha384,
                challenge_sha384: "07".repeat(48),
            },
        };
        let config = RecorderConfig {
            grant: GrantExpectations {
                authority_public_key: authority.public_key().as_ref().try_into().unwrap(),
                audience: raw.audience.clone(),
                authority: raw.binding.authority.clone(),
                tenant: raw.binding.tenant.clone(),
                profile_sha384: raw.binding.profile_sha384.clone(),
                launch_policy_sha384: raw.binding.launch_policy_sha384.clone(),
                image_policy_sha384: raw.binding.image_policy_sha384.clone(),
            },
            expected_init: [8; 48],
            kbs_proof_public_key: proof.public_key().as_ref().try_into().unwrap(),
            aggregate_audience: "policy-auditor".into(),
            aggregate_issuer: "kbs-producer".into(),
            as_policy_id: "launch_cpu".into(),
            as_policy_sha384: raw.binding.launch_policy_sha384.clone(),
            as_data_sha384: None,
            kbs_policy_id: "resource_launch".into(),
            kbs_policy_sha384: "09".repeat(48),
            resource_path: ["tenant".into(), "credential".into(), "v1".into()],
            workflow_id: "gcp-credential".into(),
            delivery_audience: "credential-recorder".into(),
            delivery_issuer: "kbs-delivery".into(),
        };
        let signature = hex(authority.sign(&raw.signing_bytes().unwrap()).as_ref());
        let wire = serde_json::to_vec(&Signed {
            statement: raw,
            signature,
        })
        .unwrap();
        let mut recorder = keys.into_recorder(wire.clone(), config).unwrap();
        let nonce = format!("onb17-launch-v1:{}", "0a".repeat(48));
        let runtime = serde_json_canonicalizer::to_vec(
            &json!({"tee-pubkey":public,"nonce":nonce,"additional-evidence":""}),
        )
        .unwrap();
        recorder.accept_begin_response(&serde_json::to_vec(&json!({"session_id":"0b".repeat(32),"quote_nonce":nonce,
            "grant_digest":recorder.client.grant().grant_digest(),"canonical_runtime_b64":STANDARD.encode(runtime),"init_data_sha384":hex(&[8;48])})).unwrap()).unwrap();
        Self {
            recorder,
            proof,
            public,
            authority,
            signed_grant: wire,
        }
    }
    pub(crate) async fn ready() -> Self {
        Self::finish_ready(Self::new()).await
    }
    #[allow(dead_code)] // Used only by the optional preparation source harness.
    pub(crate) async fn ready_with_manifest(manifest_sha256: String) -> Self {
        Self::finish_ready(Self::new_with_manifest(manifest_sha256)).await
    }
    #[allow(dead_code)] // Optional source harness pins policy before grant signing.
    pub(crate) async fn ready_with_image_policy(
        manifest_sha256: String,
        image_policy_sha384: String,
    ) -> Self {
        Self::finish_ready(Self::new_with_image_policy(
            manifest_sha256,
            image_policy_sha384,
        ))
        .await
    }
    #[allow(dead_code)] // Optional checked-runtime harness fixes the digest before signing.
    pub(crate) async fn ready_with_effective_spec(
        manifest_sha256: String,
        image_policy_sha384: String,
        effective_launch_sha384: String,
    ) -> Self {
        Self::finish_ready(Self::new_with_effective_spec(
            manifest_sha256,
            image_policy_sha384,
            effective_launch_sha384,
        ))
        .await
    }
    async fn finish_ready(mut f: Self) -> Self {
        let fake = SoftwareAttester::new(&f.recorder);
        f.recorder.collect_with(&fake).await.unwrap();
        let r = &f.recorder;
        let response=serde_json::to_vec(&json!({"session_id":r.client.session_id().unwrap(),"request_nonce":"0c".repeat(32),
            "grant_sha384":r.client.grant().grant_digest(),"runtime_sha384":hex(&r.client.report_data().unwrap()),
            "evidence_sha384":hash(r.evidence.as_ref().unwrap()),"init_data_sha384":hex(&[8;48]),
            "recorder_key_sha384":r.client.grant().binding().channel_key_sha384})).unwrap();
        f.recorder
            .accept_resource_challenge_response(&response)
            .unwrap();
        let request = ResourcePolicyRequest {
            method: "GET".into(),
            plugin: "resource".into(),
            resource_path: f.recorder.config.resource_path.clone(),
            workflow_id: f.recorder.config.workflow_id.clone(),
            request_nonce: f.recorder.request_nonce().unwrap().into(),
        };
        f.recorder.resource_decision_request(&request).unwrap();
        f
    }
    pub(crate) fn expectations(&self) -> AggregateExpectations {
        let r = &self.recorder;
        let g = r.client.grant();
        AggregateExpectations {
            kbs_proof_public_key: r.config.kbs_proof_public_key,
            expected: LaunchPolicyAggregateV1 {
                version: POLICY_AGGREGATE_VERSION,
                purpose: POLICY_AGGREGATE_PURPOSE.into(),
                audience: r.config.aggregate_audience.clone(),
                issuer: r.config.aggregate_issuer.clone(),
                profile: POLICY_AGGREGATE_PROFILE.into(),
                grant_sha384: g.grant_digest().into(),
                authority_key_sha384: g.authority_key_sha384().into(),
                session_id: r.session_id().unwrap().into(),
                nonce: r.quote_nonce().unwrap().into(),
                runtime_sha384: hex(&r.client.report_data().unwrap()),
                init_data_sha384: hex(&r.config.expected_init),
                evidence_sha384: hash(r.evidence.as_ref().unwrap()),
                recorder_key_sha384: g.binding().channel_key_sha384.clone(),
                request: r.request.as_ref().unwrap().clone(),
                as_evaluation: PolicyCommitments {
                    policy_id: r.config.as_policy_id.clone(),
                    policy_sha384: r.config.as_policy_sha384.clone(),
                    input_sha384: "0d".repeat(48),
                    data_sha384: None,
                },
                kbs_evaluation: PolicyCommitments {
                    policy_id: r.config.kbs_policy_id.clone(),
                    policy_sha384: r.config.kbs_policy_sha384.clone(),
                    input_sha384: "0e".repeat(48),
                    data_sha384: Some("0f".repeat(48)),
                },
            },
        }
    }
    pub(crate) fn pin_and_sign(&mut self) -> Vec<u8> {
        let expected = self.expectations();
        let signature = hex(self
            .proof
            .sign(&expected.expected.signing_bytes().unwrap())
            .as_ref());
        let bytes = serde_json::to_vec(&Signed {
            statement: expected.expected.clone(),
            signature,
        })
        .unwrap();
        self.recorder.pin_aggregate_expectations(expected).unwrap();
        bytes
    }
    pub(crate) fn response(&self, aggregate: &[u8], jwe: &[u8]) -> Vec<u8> {
        let r = &self.recorder;
        let expected = r.expected.as_ref().unwrap();
        let s = &expected.expected;
        let receipt = CredentialDeliveryV1 {
            version: CREDENTIAL_DELIVERY_VERSION,
            purpose: CREDENTIAL_DELIVERY_PURPOSE.into(),
            audience: r.config.delivery_audience.clone(),
            issuer: r.config.delivery_issuer.clone(),
            profile: CREDENTIAL_DELIVERY_PROFILE.into(),
            grant_sha384: s.grant_sha384.clone(),
            aggregate_sha384: s.digest_sha384().unwrap(),
            request_sha384: s.request.digest_sha384().unwrap(),
            session_id: s.session_id.clone(),
            runtime_sha384: s.runtime_sha384.clone(),
            evidence_sha384: s.evidence_sha384.clone(),
            init_data_sha384: s.init_data_sha384.clone(),
            recorder_key_sha384: s.recorder_key_sha384.clone(),
            keywrap_sha384: r.keywrap_sha384.clone(),
            ciphertext_sha384: hash(jwe),
            workflow_id: s.request.workflow_id.clone(),
            resource_path: s.request.resource_path.clone(),
            validity: *r.client.grant().validity(),
        };
        // The aggregate is independently authenticated by the recorder API later;
        // fixtures never infer expected policy commitments from response bytes.
        assert!(!aggregate.is_empty());
        let wire = serde_json::to_vec(&Signed {
            signature: hex(self.proof.sign(&receipt.signing_bytes().unwrap()).as_ref()),
            statement: receipt,
        })
        .unwrap();
        serde_json::to_vec(
            &json!({"signed_delivery_b64":STANDARD.encode(wire),"jwe_b64":STANDARD.encode(jwe)}),
        )
        .unwrap()
    }
}

struct SoftwareAttester {
    report: [u8; 48],
    init: [u8; 48],
    calls: Arc<AtomicUsize>,
    supported: bool,
}
impl SoftwareAttester {
    fn new(recorder: &LaunchRecorder) -> Self {
        Self {
            report: recorder.client.report_data().unwrap(),
            init: recorder.client.expected_init_data(),
            calls: Arc::new(AtomicUsize::new(0)),
            supported: true,
        }
    }
}
#[async_trait::async_trait]
impl Attester for SoftwareAttester {
    async fn bind_init_data(&self, init: &[u8]) -> anyhow::Result<InitDataResult> {
        anyhow::ensure!(init == self.init, "wrong software init binding");
        Ok(if self.supported {
            InitDataResult::Ok
        } else {
            InitDataResult::Unsupported
        })
    }
    async fn get_evidence(&self, report: Vec<u8>) -> anyhow::Result<attester::TeeEvidence> {
        anyhow::ensure!(report == self.report, "wrong software report binding");
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(json!({"software_only":true,"report":hex(&report),"init":hex(&self.init)}))
    }
}

/// RSA-OAEP and GC AES-GCM encryption using the shared 0.15 JWE wire format.
/// This is an encryption fixture, not a KBS resource-backend publication.
pub(crate) fn fixture_jwe(public: &kbs_types::TeePubKey, plaintext: &[u8]) -> Vec<u8> {
    let kbs_types::TeePubKey::RSA { k_mod, k_exp, .. } = public else {
        panic!("RSA fixture expected")
    };
    let public = rsa::RsaPublicKey::new(
        rsa::BigUint::from_bytes_be(&URL_SAFE_NO_PAD.decode(k_mod).unwrap()),
        rsa::BigUint::from_bytes_be(&URL_SAFE_NO_PAD.decode(k_exp).unwrap()),
    )
    .unwrap();
    let mut cek = Zeroizing::new(vec![0; 32]);
    let mut iv = vec![0; 12];
    SystemRandom::new().fill(&mut cek).unwrap();
    SystemRandom::new().fill(&mut iv).unwrap();
    let protected = legacy_kbs_types::ProtectedHeader {
        alg: "RSA-OAEP-256".into(),
        enc: "A256GCM".into(),
        other_fields: serde_json::Map::new(),
    };
    let encrypted = crypto::encrypt_aead(
        Zeroizing::new(cek.to_vec()),
        plaintext.to_vec(),
        iv.clone(),
        protected.generate_aad().unwrap(),
        crypto::WrapType::Aes256Gcm,
    )
    .unwrap();
    let encrypted_key = public
        .encrypt(
            &mut rsa::rand_core::OsRng,
            rsa::Oaep::new::<rsa::sha2::Sha256>(),
            &cek,
        )
        .unwrap();
    serde_json::to_vec(&legacy_kbs_types::Response {
        protected,
        encrypted_key,
        iv,
        ciphertext: encrypted.ciphertext,
        aad: None,
        tag: encrypted.tag,
    })
    .unwrap()
}

#[allow(dead_code)] // Shared only when the optional CDH source tests are enabled.
pub(crate) async fn credential_fixture(
    plaintext: &[u8],
) -> (AttemptCredential, [u8; 32], [u8; 32]) {
    let (credential, authority, producer, _, _) = credential_fixture_with_scope(plaintext).await;
    (credential, authority, producer)
}

#[allow(dead_code)] // Shared with the optional CDH source test module.
pub(crate) async fn credential_fixture_with_scope(
    plaintext: &[u8],
) -> (AttemptCredential, [u8; 32], [u8; 32], LaunchBinding, String) {
    let mut f = Fixture::ready().await;
    let aggregate = f.pin_and_sign();
    let authority = f.authority.public_key().as_ref().try_into().unwrap();
    let producer = f.proof.public_key().as_ref().try_into().unwrap();
    let raw: Signed<LaunchGrant> = serde_json::from_slice(&f.signed_grant).unwrap();
    let binding = raw.statement.binding.clone();
    let grant_digest = raw.statement.digest_sha384().unwrap();
    let jwe = fixture_jwe(&f.public, plaintext);
    let response = f.response(&aggregate, &jwe);
    (
        f.recorder
            .decrypt_credential_response(&response, &aggregate)
            .unwrap(),
        authority,
        producer,
        binding,
        grant_digest,
    )
}

#[tokio::test]
async fn exact_capture_is_cached_and_unsupported_init_never_becomes_evidence() {
    let mut f = Fixture::new();
    let mut fake = SoftwareAttester::new(&f.recorder);
    fake.supported = false;
    assert_eq!(
        f.recorder.collect_with(&fake).await.err(),
        Some(RecorderError::InitDataMismatch)
    );
    assert!(f.recorder.evidence.is_none());
    fake.supported = true;
    let first = f.recorder.collect_with(&fake).await.unwrap();
    let retry = f.recorder.collect_with(&fake).await.unwrap();
    assert_eq!(first, retry);
    assert_eq!(fake.calls.load(Ordering::SeqCst), 1);
    assert_eq!(f.recorder.collect_capture_request().await.unwrap(), first);
}

#[cfg(not(feature = "launch-recorder-tdx"))]
#[tokio::test]
async fn fixed_production_factory_never_falls_back_to_sample() {
    let mut f = Fixture::new();
    assert_eq!(
        f.recorder.collect_capture_request().await.err(),
        Some(RecorderError::AttesterUnavailable)
    );
}

#[tokio::test]
async fn trusted_pin_rejects_foreign_root_policy_request_and_retained_context() {
    let mut f = Fixture::ready().await;
    for change in [
        (|e: &mut AggregateExpectations| {
            e.kbs_proof_public_key = key().public_key().as_ref().try_into().unwrap()
        }) as fn(&mut AggregateExpectations),
        |e| e.expected.as_evaluation.policy_sha384 = "11".repeat(48),
        |e| e.expected.as_evaluation.data_sha384 = Some("11".repeat(48)),
        |e| e.expected.evidence_sha384 = "11".repeat(48),
        |e| e.expected.request.workflow_id = "other".into(),
    ] {
        let mut expected = f.expectations();
        change(&mut expected);
        assert_eq!(
            f.recorder.pin_aggregate_expectations(expected).err(),
            Some(RecorderError::BindingMismatch)
        );
    }
    f.pin_and_sign();
    let mut expected = f.expectations();
    expected.expected.as_evaluation.input_sha384 = "11".repeat(48);
    assert_eq!(
        f.recorder.pin_aggregate_expectations(expected).err(),
        Some(RecorderError::Conflict)
    );
}

#[tokio::test]
async fn actual_rsa_jwe_decryption_yields_one_attempt_bound_credential() {
    let mut f = Fixture::ready().await;
    let aggregate = f.pin_and_sign();
    assert!(f.recorder.credential_request(&aggregate).is_ok());
    let jwe = fixture_jwe(&f.public, b"fixture-secret-only");
    let response = f.response(&aggregate, &jwe);
    let credential = f
        .recorder
        .decrypt_credential_response(&response, &aggregate)
        .unwrap();
    assert_eq!(credential.binding(), f.recorder.client.grant().binding());
    assert_eq!(
        credential.grant_digest(),
        f.recorder.client.grant().grant_digest()
    );
    assert_eq!(
        credential.authority_key_sha384(),
        f.recorder.client.grant().authority_key_sha384()
    );
    assert_eq!(
        credential.delivery().kbs_proof_key_sha384(),
        hash(f.proof.public_key().as_ref())
    );
    assert_eq!(credential.into_secret().as_slice(), b"fixture-secret-only");
    assert_eq!(
        f.recorder
            .decrypt_credential_response(&response, &aggregate)
            .err(),
        Some(RecorderError::AlreadyConsumed)
    );
}

#[tokio::test]
async fn signature_ciphertext_and_aead_tampering_never_yield_a_secret() {
    let mut f = Fixture::ready().await;
    let aggregate = f.pin_and_sign();
    let jwe = fixture_jwe(&f.public, b"fixture-secret-only");
    let response = f.response(&aggregate, &jwe);
    let mut forged: Value = serde_json::from_slice(&response).unwrap();
    let mut signed: Value = serde_json::from_slice(
        &STANDARD
            .decode(forged["signed_delivery_b64"].as_str().unwrap())
            .unwrap(),
    )
    .unwrap();
    signed["signature"] = "00".repeat(64).into();
    forged["signed_delivery_b64"] = STANDARD.encode(serde_json::to_vec(&signed).unwrap()).into();
    assert!(
        f.recorder
            .decrypt_credential_response(&serde_json::to_vec(&forged).unwrap(), &aggregate)
            .is_err()
    );
    assert!(!f.recorder.consumed);
    let mut changed: Value = serde_json::from_slice(&jwe).unwrap();
    changed["tag"] = URL_SAFE_NO_PAD.encode([0; 16]).into();
    let changed = serde_json::to_vec(&changed).unwrap();
    let mut substituted: Value = serde_json::from_slice(&response).unwrap();
    substituted["jwe_b64"] = STANDARD.encode(&changed).into();
    assert!(matches!(
        f.recorder
            .decrypt_credential_response(&serde_json::to_vec(&substituted).unwrap(), &aggregate),
        Err(RecorderError::Client(_))
    ));
    assert!(!f.recorder.consumed);
    let signed_changed = f.response(&aggregate, &changed);
    assert_eq!(
        f.recorder
            .decrypt_credential_response(&signed_changed, &aggregate)
            .err(),
        Some(RecorderError::InvalidCredential)
    );
    // Once an authenticated producer delivery is opened, even failed AEAD is
    // terminal. A later valid response cannot create a second consume attempt.
    assert!(f.recorder.consumed);
    assert_eq!(
        f.recorder
            .decrypt_credential_response(&response, &aggregate)
            .err(),
        Some(RecorderError::AlreadyConsumed)
    );
}

#[tokio::test]
async fn unsupported_headers_unknown_fields_and_wrong_recipient_are_rejected() {
    let mut f = Fixture::ready().await;
    let aggregate = f.pin_and_sign();
    let jwe = fixture_jwe(&f.public, b"fixture-secret-only");
    for header in [
        json!({"alg":"RSA1_5","enc":"A256GCM"}),
        json!({"alg":"RSA-OAEP-256","enc":"A128GCM"}),
        json!({"alg":"RSA-OAEP-256","enc":"A256GCM","extra":true}),
    ] {
        let mut raw: Value = serde_json::from_slice(&jwe).unwrap();
        raw["protected"] = URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&header).unwrap())
            .into();
        assert!(strict_jwe(&serde_json::to_vec(&raw).unwrap()).is_err());
    }
    let mut raw: Value = serde_json::from_slice(&jwe).unwrap();
    raw["aad"] = "".into();
    assert!(strict_jwe(&serde_json::to_vec(&raw).unwrap()).is_err());
    let other = LaunchKeys::generate().unwrap();
    let foreign = fixture_jwe(&other.keywrap_public_key().unwrap(), b"fixture-secret-only");
    let signed_foreign = f.response(&aggregate, &foreign);
    assert_eq!(
        f.recorder
            .decrypt_credential_response(&signed_foreign, &aggregate)
            .err(),
        Some(RecorderError::InvalidCredential)
    );
}
