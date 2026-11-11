//! Software evidence fixtures and generated RSA/AES-GCM roundtrips.
//! No fixture is reachable from the production attester factory.

use super::*;
use base64::engine::general_purpose::STANDARD;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use execution_proof_contract::{
    gcp_credential::{
        GcpCredentialDeliveryV2, CREDENTIAL_DELIVERY_PROFILE, CREDENTIAL_DELIVERY_PURPOSE,
        CREDENTIAL_DELIVERY_VERSION,
    },
    gcp_policy_receipt::GcpLaunchPolicyAggregateV2,
    policy_receipt::PolicyCommitments,
    LaunchGrant, Signed, ValidityWindow, GRANT_PURPOSE, VERSION,
};
use serde_json::{json, Value};

fn key() -> Ed25519KeyPair {
    let encoded = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    Ed25519KeyPair::from_pkcs8(encoded.as_ref()).unwrap()
}

pub(crate) struct Fixture {
    pub(crate) recorder: GcpLaunchRecorder,
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
        let mut keys = GcpLaunchKeys::generate(binding()).unwrap();
        let public = keys.keywrap_public_key().unwrap();
        let authority = key();
        let proof = key();
        install_invalid_qvl_software_capture(&mut keys, &authority);
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
                boot_id: keys.boot_id().into(),
                channel_key_sha384: hash(&keys.recorder_public_key()),
                bootstrap_context_sha384: keys.capture.as_ref().unwrap().context_sha384.clone(),
                selected_manifest_sha256: manifest_sha256,
                effective_launch_sha384,
                profile_sha384: binding().digest_sha384().unwrap(),
                launch_policy_sha384: "05".repeat(48),
                image_policy_sha384,
                challenge_sha384: "07".repeat(48),
            },
        };
        let config = GcpRecorderConfig {
            grant: GrantExpectations {
                authority_public_key: authority.public_key().as_ref().try_into().unwrap(),
                audience: raw.audience.clone(),
                authority: raw.binding.authority.clone(),
                tenant: raw.binding.tenant.clone(),
                profile_sha384: raw.binding.profile_sha384.clone(),
                launch_policy_sha384: raw.binding.launch_policy_sha384.clone(),
                image_policy_sha384: raw.binding.image_policy_sha384.clone(),
            },
            expected_boot_binding: binding(),
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
        let server_nonce = [10; 32];
        let nonce = execution_proof_client::gcp::quote_nonce(
            recorder.client.grant().grant_digest(),
            &binding(),
            server_nonce,
        )
        .unwrap();
        let runtime = serde_json_canonicalizer::to_vec(
            &json!({"tee-pubkey":public,"nonce":nonce,"additional-evidence":""}),
        )
        .unwrap();
        recorder.accept_begin_response(&serde_json::to_vec(&json!({"session_id":"0b".repeat(32),"quote_nonce":nonce,
            "grant_digest":recorder.client.grant().grant_digest(),"canonical_runtime_b64":STANDARD.encode(runtime),"version":2,"purpose":execution_proof_client::gcp::BEGIN_PURPOSE,"boot_binding_sha384":binding().digest_sha384().unwrap(),"server_nonce_hex":hex(&server_nonce)})).unwrap()).unwrap();
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
    #[allow(dead_code, reason = "Used by the CDH integration fixture")]
    pub(crate) async fn ready_with_manifest(manifest: String) -> Self {
        Self::finish_ready(Self::new_with_manifest(manifest)).await
    }
    #[allow(dead_code, reason = "Used by the CDH integration fixture")]
    pub(crate) async fn ready_with_image_policy(manifest: String, policy: String) -> Self {
        Self::finish_ready(Self::new_with_image_policy(manifest, policy)).await
    }
    async fn finish_ready(mut f: Self) -> Self {
        let evidence =
            GcpLaunchEvidence::new(b"INVALID-QVL-launch-quote".to_vec(), vec![1], vec![2])
                .unwrap()
                .encode()
                .unwrap();
        let request = f.recorder.client.capture_request(&evidence).unwrap();
        f.recorder.evidence = Some(evidence);
        f.recorder.capture_request = Some(request);
        let r = &f.recorder;
        let response=serde_json::to_vec(&json!({"session_id":r.client.session_id().unwrap(),"request_nonce":"0c".repeat(32),
            "grant_sha384":r.client.grant().grant_digest(),"runtime_sha384":hex(&r.client.report_data().unwrap()),
            "evidence_sha384":hash(r.evidence.as_ref().unwrap()),"version":2,"purpose":execution_proof_client::gcp::RESOURCE_CHALLENGE_PURPOSE,"boot_binding_sha384":binding().digest_sha384().unwrap(),
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
    pub(crate) fn expectations(&self) -> GcpAggregateExpectations {
        let r = &self.recorder;
        let g = r.client.grant();
        GcpAggregateExpectations {
            kbs_proof_public_key: r.config.kbs_proof_public_key,
            boot_binding: binding(),
            expected: GcpLaunchPolicyAggregateV2 {
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
                boot_binding_sha384: binding().digest_sha384().unwrap(),
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
        let receipt = GcpCredentialDeliveryV2 {
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
            boot_binding_sha384: s.boot_binding_sha384.clone(),
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
            &json!({"version":2,"purpose":execution_proof_client::gcp::CREDENTIAL_PURPOSE,"boot_binding_sha384":binding().digest_sha384().unwrap(),"signed_delivery_b64":STANDARD.encode(wire),"jwe_b64":STANDARD.encode(jwe)}),
        )
        .unwrap()
    }
}

fn binding() -> GcpBootBindingV1 {
    GcpBootBindingV1::new([1; 48], [2; 48], [3; 48], [4; 48]).unwrap()
}

#[tokio::test]
async fn signed_aggregate_derivation_requires_signature_static_scope_and_local_capture() {
    let mut f = Fixture::ready().await;
    let statement = f.expectations().expected;
    let wire = |s: GcpLaunchPolicyAggregateV2, signer: &Ed25519KeyPair| {
        serde_json::to_vec(&Signed {
            signature: hex(signer.sign(&s.signing_bytes().unwrap()).as_ref()),
            statement: s,
        })
        .unwrap()
    };
    let signed = wire(statement.clone(), &f.proof);
    assert!(f
        .recorder
        .pin_signed_aggregate(&wire(statement.clone(), &key()))
        .is_err());
    assert!(f.recorder.expected.is_none());
    for modify in [
        |s: &mut GcpLaunchPolicyAggregateV2| s.as_evaluation.policy_id = "other".into(),
        |s: &mut GcpLaunchPolicyAggregateV2| s.kbs_evaluation.policy_sha384 = "aa".repeat(48),
        |s: &mut GcpLaunchPolicyAggregateV2| s.evidence_sha384 = "aa".repeat(48),
        |s: &mut GcpLaunchPolicyAggregateV2| s.session_id = "aa".repeat(32),
        |s: &mut GcpLaunchPolicyAggregateV2| s.request.resource_path[0] = "other".into(),
    ] {
        let mut altered = statement.clone();
        modify(&mut altered);
        assert!(f
            .recorder
            .pin_signed_aggregate(&wire(altered, &f.proof))
            .is_err());
        assert!(f.recorder.expected.is_none());
    }
    let expected = f.recorder.pin_signed_aggregate(&signed).unwrap();
    assert!(expected.expected == statement);
    assert!(f.recorder.credential_request(&signed).is_ok());
    assert!(f.recorder.pin_signed_aggregate(&signed).is_ok());
    let mut changed = statement;
    changed.kbs_evaluation.input_sha384 = "aa".repeat(48);
    assert!(matches!(
        f.recorder.pin_signed_aggregate(&wire(changed, &f.proof)),
        Err(RecorderError::Conflict)
    ));
}
fn challenge() -> GcpBootstrapChallenge {
    GcpBootstrapChallenge {
        version: GCP_BOOTSTRAP_VERSION,
        purpose: gcp_bootstrap::GCP_BOOTSTRAP_CHALLENGE_PURPOSE.into(),
        audience: "bootstrap".into(),
        authority: "authority".into(),
        tenant: "tenant".into(),
        workload_id: "workload".into(),
        attempt_id: "attempt".into(),
        challenge_id: "challenge".into(),
        nonce_hex: "11".repeat(32),
        intent_sha384: "12".repeat(48),
        boot_binding: binding(),
        validity: ValidityWindow {
            not_before: 100,
            expires: 200,
        },
    }
}
fn sign_challenge(c: &GcpBootstrapChallenge, key: &Ed25519KeyPair) -> Vec<u8> {
    serde_json::to_vec(&Signed {
        statement: c.clone(),
        signature: hex(key.sign(&c.canonical_bytes().unwrap()).as_ref()),
    })
    .unwrap()
}
// Deliberately INVALID-QVL public bytes, confined to this private cfg(test) module.
fn install_invalid_qvl_software_capture(keys: &mut GcpLaunchKeys, authority: &Ed25519KeyPair) {
    let c = challenge();
    let signed = sign_challenge(&c, authority);
    let public = authority.public_key().as_ref().try_into().unwrap();
    assert_eq!(
        gcp_bootstrap::verify_challenge_signature(&signed, &public, &c).unwrap(),
        c
    );
    let b = GcpBootstrapBinding {
        version: GCP_BOOTSTRAP_VERSION,
        purpose: GCP_BOOTSTRAP_BINDING_PURPOSE.into(),
        challenge_sha384: c.digest_sha384().unwrap(),
        boot_binding_sha384: binding().digest_sha384().unwrap(),
        boot_id: keys.boot_id.clone(),
        boot_nonce_hex: keys.boot_nonce_hex.clone(),
        recorder_key_sha384: hash(&keys.recorder_public_key()),
        keywrap_key_sha384: hash(
            &serde_json_canonicalizer::to_vec(&keys.legacy_key().unwrap()).unwrap(),
        ),
    };
    let evidence =
        GcpLaunchEvidence::new(b"INVALID-QVL-bootstrap-quote".to_vec(), vec![1], vec![2]).unwrap();
    let context_sha384 = gcp_bootstrap::bootstrap_context_sha384(&c, &b, &evidence).unwrap();
    keys.pending = Some((c.clone(), public));
    keys.capture = Some(GcpBootstrapCapture {
        challenge: c,
        binding: b,
        evidence,
        context_sha384,
    });
}
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

#[test]
fn authenticated_bootstrap_unavailable_is_sticky_and_bad_signature_never_pins() {
    let mut keys = GcpLaunchKeys::generate(binding()).unwrap();
    let authority = key();
    let c = challenge();
    let public = authority.public_key().as_ref().try_into().unwrap();
    let bad = sign_challenge(&c, &key());
    assert_eq!(
        keys.collect_bootstrap(&bad, &c, &public).err(),
        Some(RecorderError::BindingMismatch)
    );
    assert!(keys.pending.is_none());
    let signed = sign_challenge(&c, &authority);
    #[cfg(not(feature = "launch-recorder-gcp-tdx"))]
    assert_eq!(
        keys.collect_bootstrap(&signed, &c, &public).err(),
        Some(RecorderError::AttesterUnavailable)
    );
    #[cfg(feature = "launch-recorder-gcp-tdx")]
    {
        assert!(keys.collect_bootstrap(&signed, &c, &public).is_err());
    }
    assert!(keys.pending.is_some());
    assert!(keys.capture.is_none());
    let mut other = c.clone();
    other.challenge_id = "other".into();
    let wire = sign_challenge(&other, &authority);
    assert_eq!(
        keys.collect_bootstrap(&wire, &other, &public).err(),
        Some(RecorderError::Conflict)
    );
    let mut wrong_b = c.clone();
    wrong_b.boot_binding = GcpBootBindingV1::new([9; 48], [2; 48], [3; 48], [4; 48]).unwrap();
    assert_eq!(
        keys.collect_bootstrap(&sign_challenge(&wrong_b, &authority), &wrong_b, &public)
            .err(),
        Some(RecorderError::BindingMismatch)
    );
}
#[tokio::test]
async fn wrong_context_is_rejected_before_decrypt_and_authenticated_bad_aead_consumes() {
    let mut f = Fixture::ready().await;
    let aggregate = f.pin_and_sign();
    let jwe = fixture_jwe(&f.public, b"private-software-secret");
    let response = f.response(&aggregate, &jwe);
    let mut mixed: Value = serde_json::from_slice(&response).unwrap();
    mixed["boot_binding_sha384"] = json!("aa".repeat(48));
    assert!(f
        .recorder
        .decrypt_credential_response(&serde_json::to_vec(&mixed).unwrap(), &aggregate)
        .is_err());
    assert!(!f.recorder.consumed);
    let mut malformed: Value = serde_json::from_slice(&jwe).unwrap();
    malformed["tag"] = json!(URL_SAFE_NO_PAD.encode([0; 16]));
    let malformed = serde_json::to_vec(&malformed).unwrap();
    let signed_bad = f.response(&aggregate, &malformed);
    assert_eq!(
        f.recorder
            .decrypt_credential_response(&signed_bad, &aggregate)
            .err(),
        Some(RecorderError::InvalidCredential)
    );
    assert!(f.recorder.consumed);
    assert_eq!(
        f.recorder
            .decrypt_credential_response(&response, &aggregate)
            .err(),
        Some(RecorderError::AlreadyConsumed)
    );
}
#[test]
fn grant_cannot_create_capture_and_random_boot_scope_is_distinct() {
    let f = Fixture::new();
    let a = GcpLaunchKeys::generate(binding()).unwrap();
    let b = GcpLaunchKeys::generate(binding()).unwrap();
    assert_ne!(a.boot_id(), b.boot_id());
    assert_ne!(a.boot_nonce_hex(), b.boot_nonce_hex());
    assert_ne!(a.recorder_public_key(), b.recorder_public_key());
    assert_eq!(
        a.into_recorder(vec![], f.recorder.config).err(),
        Some(RecorderError::NotReady)
    );
}

#[test]
fn authenticated_grant_cannot_switch_cached_boot_scope_keys_or_capture_context() {
    for field in [
        "boot_id",
        "channel_key_sha384",
        "bootstrap_context_sha384",
        "workload_id",
        "attempt_id",
    ] {
        let f = Fixture::new();
        let mut keys = GcpLaunchKeys::generate(binding()).unwrap();
        install_invalid_qvl_software_capture(&mut keys, &f.authority);
        let mut raw: Signed<LaunchGrant> = serde_json::from_slice(&f.signed_grant).unwrap();
        raw.statement.binding.boot_id = keys.boot_id().into();
        raw.statement.binding.channel_key_sha384 = hash(&keys.recorder_public_key());
        raw.statement.binding.bootstrap_context_sha384 =
            keys.capture.as_ref().unwrap().context_sha384.clone();
        match field {
            "boot_id" => raw.statement.binding.boot_id = "other-boot".into(),
            "channel_key_sha384" => raw.statement.binding.channel_key_sha384 = "ab".repeat(48),
            "bootstrap_context_sha384" => {
                raw.statement.binding.bootstrap_context_sha384 = "bc".repeat(48)
            }
            "workload_id" => raw.statement.binding.workload_id = "other-workload".into(),
            _ => raw.statement.binding.attempt_id = "other-attempt".into(),
        };
        raw.signature = hex(f
            .authority
            .sign(&raw.statement.signing_bytes().unwrap())
            .as_ref());
        assert_eq!(
            keys.into_recorder(serde_json::to_vec(&raw).unwrap(), f.recorder.config)
                .err(),
            Some(RecorderError::BindingMismatch),
            "{field}"
        );
    }
}
