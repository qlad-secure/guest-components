//! Actual offline Cosign P-256 signatures over the standard simple-signing
//! payload. Ephemeral synthetic signing keys stay in memory; no CLI, registry,
//! network, certificate, filesystem image, or preparation success is involved.

use super::*;
use serde_json::{json, Value};
use sigstore::crypto::SigStoreSigner;

const REPOSITORY: &str = "registry.example/owner/image";

struct Fixture {
    signer: SigStoreSigner,
    key: Vec<u8>,
    policy: Vec<u8>,
    manifest: Vec<u8>,
    payload: Vec<u8>,
    signature: Vec<u8>,
}

fn limits() -> SignatureLimits {
    // Synthetic fixture budgets, not deployment defaults.
    SignatureLimits {
        policy_bytes: 16 * 1024,
        key_bytes: 4096,
        manifest_bytes: 128 * 1024,
        payload_bytes: 16 * 1024,
        signature_bytes: 128,
        json_depth: 16,
    }
}

fn policy_for(key: &[u8]) -> Value {
    let mut value = json!({"default":[{"type":"reject"}],"transports":{"docker":{}}});
    value["transports"]["docker"][REPOSITORY] = json!([{
        "type":"sigstoreSigned",
        "keyData":STANDARD.encode(key),
        "signedIdentity":{"type":"exactRepository","dockerRepository":REPOSITORY}
    }]);
    value
}

impl Fixture {
    fn new() -> Self {
        let signer = SigningScheme::ECDSA_P256_SHA256_ASN1
            .create_signer()
            .unwrap();
        let key = signer
            .to_sigstore_keypair()
            .unwrap()
            .public_key_to_pem()
            .unwrap()
            .into_bytes();
        let policy = serde_json::to_vec(&policy_for(&key)).unwrap();
        let manifest = serde_json::to_vec(&json!({
            "schemaVersion":2,
            "mediaType":"application/vnd.oci.image.manifest.v1+json",
            "config":{"mediaType":"application/vnd.oci.image.config.v1+json",
                "digest":format!("sha256:{}", "11".repeat(32)), "size":1},
            "layers":[]
        }))
        .unwrap();
        let payload = serde_json::to_vec(&json!({
            "critical":{
                "type":"cosign container image signature",
                "identity":{"docker-reference":REPOSITORY},
                "image":{"docker-manifest-digest":format!("sha256:{}",sha256(&manifest))}
            },
            "optional":null
        }))
        .unwrap();
        let signature = signer.sign(&payload).unwrap();
        Self {
            signer,
            key,
            policy,
            manifest,
            payload,
            signature,
        }
    }

    fn verifier(&self) -> RequiredCosignPolicy {
        self.verifier_with(limits())
    }

    fn verifier_with(&self, configured: SignatureLimits) -> RequiredCosignPolicy {
        RequiredCosignPolicy::new(&self.policy, &sha384(&self.policy), REPOSITORY, configured)
            .unwrap()
    }
}

#[test]
fn actual_cosign_signature_commits_exact_manifest_policy_key_and_payload() {
    let f = Fixture::new();
    let policy = f.verifier();
    let verified = policy
        .verify(&f.manifest, &sha256(&f.manifest), &f.payload, &f.signature)
        .unwrap();
    assert_eq!(verified.manifest_sha256(), sha256(&f.manifest));
    assert_eq!(verified.policy_sha384(), sha384(&f.policy));
    assert_eq!(verified.key_sha384(), sha384(&f.key));
    assert_eq!(verified.payload_sha384(), sha384(&f.payload));
    assert_eq!(verified.signature_sha384(), sha384(&f.signature));
    assert_eq!(verified.repository(), REPOSITORY);
    assert_eq!(policy.policy_sha384(), verified.policy_sha384());
    assert_eq!(policy.key_sha384(), verified.key_sha384());
    assert_eq!(policy.repository(), verified.repository());
    assert_eq!(policy.policy_bytes(), f.policy);
    assert_eq!(policy.key_bytes(), f.key);
    // Publisher signatures are reusable metadata. The CDH attempt owner must
    // separately enforce its admission transition and exact input history.
    assert!(policy
        .verify(&f.manifest, &sha256(&f.manifest), &f.payload, &f.signature)
        .is_ok());
}

#[test]
fn forged_signature_wrong_key_and_changed_raw_payload_fail_actual_crypto() {
    let f = Fixture::new();
    let policy = f.verifier();
    let mut changed = f.payload.clone();
    changed.push(b' ');
    assert_eq!(
        policy
            .verify(&f.manifest, &sha256(&f.manifest), &changed, &f.signature)
            .err(),
        Some(SignatureError::InvalidSignature)
    );
    let foreign = SigningScheme::ECDSA_P256_SHA256_ASN1
        .create_signer()
        .unwrap();
    assert_eq!(
        policy
            .verify(
                &f.manifest,
                &sha256(&f.manifest),
                &f.payload,
                &foreign.sign(&f.payload).unwrap()
            )
            .err(),
        Some(SignatureError::InvalidSignature)
    );
    let mut signature = f.signature.clone();
    *signature.last_mut().unwrap() ^= 1;
    assert_eq!(
        policy
            .verify(&f.manifest, &sha256(&f.manifest), &f.payload, &signature)
            .err(),
        Some(SignatureError::InvalidSignature)
    );
}

#[test]
fn valid_signatures_do_not_authorize_other_types_repositories_or_digests() {
    let f = Fixture::new();
    let policy = f.verifier();
    for (field, expected) in [
        ("type", SignatureError::PayloadTypeMismatch),
        ("repository", SignatureError::RepositoryMismatch),
        ("digest", SignatureError::PayloadDigestMismatch),
    ] {
        let mut payload: Value = serde_json::from_slice(&f.payload).unwrap();
        match field {
            "type" => payload["critical"]["type"] = "atomic container signature".into(),
            "repository" => {
                payload["critical"]["identity"]["docker-reference"] =
                    "registry.example/other/image".into()
            }
            "digest" => {
                payload["critical"]["image"]["docker-manifest-digest"] =
                    format!("sha256:{}", "22".repeat(32)).into()
            }
            _ => unreachable!(),
        }
        let raw = serde_json::to_vec(&payload).unwrap();
        assert_eq!(
            policy
                .verify(
                    &f.manifest,
                    &sha256(&f.manifest),
                    &raw,
                    &f.signer.sign(&raw).unwrap()
                )
                .err(),
            Some(expected),
            "{field}"
        );
    }
}

#[test]
fn manifest_bytes_and_bare_digest_are_checked_without_index_fallback() {
    let f = Fixture::new();
    let policy = f.verifier();
    let mut changed = f.manifest.clone();
    changed.push(b' ');
    assert_eq!(
        policy
            .verify(&changed, &sha256(&f.manifest), &f.payload, &f.signature)
            .err(),
        Some(SignatureError::ManifestDigestMismatch)
    );
    assert_eq!(
        policy
            .verify(&changed, &sha256(&changed), &f.payload, &f.signature)
            .err(),
        Some(SignatureError::PayloadDigestMismatch)
    );
    for digest in [
        "AA".repeat(32),
        "a".repeat(63),
        format!("sha256:{}", sha256(&f.manifest)),
    ] {
        assert_eq!(
            policy
                .verify(&f.manifest, &digest, &f.payload, &f.signature)
                .err(),
            Some(SignatureError::InvalidManifestDigest)
        );
    }
}

#[test]
fn only_one_exact_requiring_rule_with_reject_default_is_supported() {
    let f = Fixture::new();
    for case in [
        "accept-default",
        "empty-default",
        "empty-scopes",
        "empty-requirements",
        "accept-requirement",
        "wrong-scope",
        "wrong-repository",
        "implicit-identity",
        "key-path",
        "extra-rule",
    ] {
        let mut policy = policy_for(&f.key);
        match case {
            "accept-default" => policy["default"] = json!([{"type":"insecureAcceptAnything"}]),
            "empty-default" => policy["default"] = json!([]),
            "empty-scopes" => policy["transports"]["docker"] = json!({}),
            "empty-requirements" => policy["transports"]["docker"][REPOSITORY] = json!([]),
            "accept-requirement" => {
                policy["transports"]["docker"][REPOSITORY] =
                    json!([{"type":"insecureAcceptAnything"}])
            }
            "wrong-scope" => {
                let requirements = policy["transports"]["docker"][REPOSITORY].take();
                policy["transports"]["docker"] = json!({"":requirements});
            }
            "wrong-repository" => {
                policy["transports"]["docker"][REPOSITORY][0]["signedIdentity"]
                    ["dockerRepository"] = "registry.example/other/image".into()
            }
            "implicit-identity" => {
                policy["transports"]["docker"][REPOSITORY][0]
                    .as_object_mut()
                    .unwrap()
                    .remove("signedIdentity");
            }
            "key-path" => {
                policy["transports"]["docker"][REPOSITORY][0]["keyPath"] =
                    "/untrusted/key.pem".into()
            }
            "extra-rule" => {
                let rule = policy["transports"]["docker"][REPOSITORY][0].clone();
                policy["transports"]["docker"][REPOSITORY]
                    .as_array_mut()
                    .unwrap()
                    .push(rule);
            }
            _ => unreachable!(),
        }
        let raw = serde_json::to_vec(&policy).unwrap();
        assert!(
            RequiredCosignPolicy::new(&raw, &sha384(&raw), REPOSITORY, limits()).is_err(),
            "{case}"
        );
    }
    assert_eq!(
        RequiredCosignPolicy::new(&f.policy, &"00".repeat(48), REPOSITORY, limits()).err(),
        Some(SignatureError::PolicyHashMismatch)
    );
}

#[test]
fn only_pinned_p256_pem_and_canonical_key_encoding_are_accepted() {
    let f = Fixture::new();
    let other_scheme = SigningScheme::ED25519.create_signer().unwrap();
    let other_key = other_scheme
        .to_sigstore_keypair()
        .unwrap()
        .public_key_to_pem()
        .unwrap();
    let raw = serde_json::to_vec(&policy_for(other_key.as_bytes())).unwrap();
    assert_eq!(
        RequiredCosignPolicy::new(&raw, &sha384(&raw), REPOSITORY, limits()).err(),
        Some(SignatureError::InvalidKey)
    );
    let mut policy = policy_for(&f.key);
    policy["transports"]["docker"][REPOSITORY][0]["keyData"] =
        format!("{}\n", STANDARD.encode(&f.key)).into();
    let raw = serde_json::to_vec(&policy).unwrap();
    assert_eq!(
        RequiredCosignPolicy::new(&raw, &sha384(&raw), REPOSITORY, limits()).err(),
        Some(SignatureError::InvalidKey)
    );
    for repository in [
        "owner/image",
        "registry.example/owner/image:tag",
        "https://registry.example/image",
    ] {
        assert_eq!(
            RequiredCosignPolicy::new(&f.policy, &sha384(&f.policy), repository, limits()).err(),
            Some(SignatureError::InvalidConfiguration)
        );
    }
}

#[test]
fn duplicate_policy_scopes_and_authenticated_critical_fields_are_rejected() {
    let f = Fixture::new();
    let raw = String::from_utf8(f.policy.clone())
        .unwrap()
        .replacen(
            "\"docker\":{",
            &format!("\"docker\":{{\"{REPOSITORY}\":[],"),
            1,
        )
        .into_bytes();
    assert_eq!(
        RequiredCosignPolicy::new(&raw, &sha384(&raw), REPOSITORY, limits()).err(),
        Some(SignatureError::MalformedPolicy)
    );
    let policy = f.verifier();
    for raw in [
        String::from_utf8(f.payload.clone()).unwrap().replacen(
            "\"critical\":{",
            "\"critical\":{\"type\":\"cosign container image signature\",",
            1,
        ),
        String::from_utf8(f.payload.clone()).unwrap().replacen(
            "\"critical\":{",
            "\"critical\":{\"unknown-critical-member\":true,",
            1,
        ),
    ] {
        assert_eq!(
            policy
                .verify(
                    &f.manifest,
                    &sha256(&f.manifest),
                    raw.as_bytes(),
                    &f.signer.sign(raw.as_bytes()).unwrap()
                )
                .err(),
            Some(SignatureError::MalformedPayload)
        );
    }
}

#[test]
fn independent_byte_budgets_accept_exact_lengths_and_reject_one_byte_over() {
    let f = Fixture::new();
    let exact = SignatureLimits {
        policy_bytes: f.policy.len(),
        key_bytes: f.key.len(),
        manifest_bytes: f.manifest.len(),
        payload_bytes: f.payload.len(),
        signature_bytes: f.signature.len(),
        json_depth: 16,
    };
    assert!(f
        .verifier_with(exact)
        .verify(&f.manifest, &sha256(&f.manifest), &f.payload, &f.signature)
        .is_ok());
    for field in 0..5 {
        let mut bounded = exact;
        match field {
            0 => bounded.policy_bytes -= 1,
            1 => bounded.key_bytes -= 1,
            2 => bounded.manifest_bytes -= 1,
            3 => bounded.payload_bytes -= 1,
            4 => bounded.signature_bytes -= 1,
            _ => unreachable!(),
        }
        let result = RequiredCosignPolicy::new(&f.policy, &sha384(&f.policy), REPOSITORY, bounded);
        let error = match result {
            Err(error) => error,
            Ok(verifier) => verifier
                .verify(&f.manifest, &sha256(&f.manifest), &f.payload, &f.signature)
                .err()
                .unwrap(),
        };
        assert_eq!(error, SignatureError::TooLarge, "field {field}");
    }
}

#[test]
fn zero_limits_and_excessive_depth_fail_before_unbounded_parsing() {
    let f = Fixture::new();
    for field in 0..6 {
        let mut configured = limits();
        match field {
            0 => configured.policy_bytes = 0,
            1 => configured.key_bytes = 0,
            2 => configured.manifest_bytes = 0,
            3 => configured.payload_bytes = 0,
            4 => configured.signature_bytes = 0,
            5 => configured.json_depth = 0,
            _ => unreachable!(),
        }
        assert_eq!(
            RequiredCosignPolicy::new(&f.policy, &sha384(&f.policy), REPOSITORY, configured).err(),
            Some(SignatureError::InvalidConfiguration)
        );
    }
    let mut nested = Value::Null;
    for _ in 0..16 {
        nested = json!([nested]);
    }
    let mut payload: Value = serde_json::from_slice(&f.payload).unwrap();
    payload["optional"] = nested;
    let raw = serde_json::to_vec(&payload).unwrap();
    assert_eq!(
        f.verifier()
            .verify(
                &f.manifest,
                &sha256(&f.manifest),
                &raw,
                &f.signer.sign(&raw).unwrap()
            )
            .err(),
        Some(SignatureError::TooDeep)
    );
    // Structural-looking publisher strings do not consume nesting depth.
    assert!(check_depth(br#"{"text":"[{}]\\\""}"#, 1).is_ok());
}
