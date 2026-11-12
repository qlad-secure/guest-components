//! Signed gate/RSA credential fixtures followed by raw metadata binding.
//! Image signatures, KMS, blob download, layer decryption, and rootfs preparation
//! are outside this suite.

use crate::{
    gcp_cdh_tests::preparation_fixture, launch_credential::TrustedGcpAttempt, launch_preparation::*,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use sha2::{Digest, Sha256, Sha384};
use std::sync::{Arc, Mutex};

const KEY: &str =
    "projects/project-1/locations/us-central1/keyRings/ring/cryptoKeys/key/cryptoKeyVersions/1";
const PACKET_KEY: &str = "org.opencontainers.image.enc.keys.provider.attestation-agent";
const PUBLIC_KEY: &str = "org.opencontainers.image.enc.pubopts";

fn hash256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn hash384(bytes: &[u8]) -> String {
    Sha384::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn packet(key: &str, provider: &str, ciphertext: &[u8]) -> String {
    STANDARD.encode(
        serde_json::to_vec(&json!({
            "kid": format!("kbs:///default/key/{}", key.replace('/', "%2F")),
            "wrapped_data": STANDARD.encode(format!("{provider}:{}", STANDARD.encode(ciphertext))),
            "iv":"", "wrap_type":"KMS-DIRECT",
        }))
        .unwrap(),
    )
}

fn inputs(count: usize) -> (Value, Value) {
    let config = json!({"os":"linux","architecture":"amd64", "config":{"Env":["PUBLIC_TEST=1"]},
        "rootfs":{"type":"layers","diff_ids":vec![format!("sha256:{}", "41".repeat(32));count]}});
    let packets = format!(
        "{},{}",
        packet(&KEY.replace("/1", "/2"), "gcp", b"other-packet"),
        packet(KEY, "gcp", b"selected-kms-ciphertext")
    );
    let public = STANDARD.encode(serde_json::to_vec(&json!({"cipher":"AES_256_CTR_HMAC_SHA256", "cipheroptions":{}, "hmac":STANDARD.encode([7;32])})).unwrap());
    let layer = json!({"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip+encrypted",
        "digest":format!("sha256:{}", "31".repeat(32)), "size":123,
        "annotations":{PACKET_KEY:packets, PUBLIC_KEY:public}});
    let manifest = json!({"schemaVersion":2, "mediaType":"application/vnd.oci.image.manifest.v1+json",
        "config":{"mediaType":"application/vnd.oci.image.config.v1+json", "digest":"", "size":0},
        "layers":vec![layer;count]});
    (manifest, config)
}

fn encode(mut manifest: Value, config: Value) -> (Vec<u8>, Vec<u8>) {
    let config = serde_json::to_vec(&config).unwrap();
    manifest["config"]["digest"] = format!("sha256:{}", hash256(&config)).into();
    manifest["config"]["size"] = config.len().into();
    (serde_json::to_vec(&manifest).unwrap(), config)
}

fn limits() -> PreparationLimits {
    // Synthetic fixture budgets, not proposed deployment defaults.
    PreparationLimits {
        manifest_bytes: 128 * 1024,
        config_bytes: 16 * 1024,
        layer_count: 64,
        packets_per_layer: 4,
        packet_bytes: 4096,
        public_options_bytes: 1024,
        kms_ciphertext_bytes: 1024,
        operations: 32,
    }
}

fn profile(expected: TrustedGcpAttempt) -> PreparationProfile {
    PreparationProfile {
        authority_public_key: expected.authority_public_key,
        kbs_proof_public_key: expected.kbs_proof_public_key,
        binding: expected.binding,
        grant_sha384: expected.grant_sha384,
        validity: expected.validity,
        workflow_id: expected.workflow_id,
        resource_path: expected.resource_path,
        project_id: expected.project_id,
        client_email: expected.client_email,
        kms_key_version: expected.kms_key_version,
    }
}

async fn attempt(manifest: &[u8], configured: PreparationLimits) -> PreparationAttempt {
    let (credential, expected, admission) = preparation_fixture(hash256(manifest)).await;
    PreparationAttempt::new_gcp(admission, credential, profile(expected), configured).unwrap()
}

#[tokio::test]
async fn actual_raw_manifest_and_config_bind_original_duplicate_descriptors_once() {
    let (manifest, config) = inputs(2);
    let (manifest, config) = encode(manifest, config);
    let mut attempt = attempt(&manifest, limits()).await;
    assert_eq!(
        attempt.bind_manifest(&manifest, &config),
        Ok(ManifestBinding::FirstBound)
    );
    let bound = attempt.manifest_plan().unwrap();
    assert_eq!(bound.manifest_sha256(), hash256(&manifest));
    assert_eq!(bound.config_sha256(), hash256(&config));
    assert_eq!(bound.layers().len(), 2);
    for (i, layer) in bound.layers().iter().enumerate() {
        assert_eq!(layer.original_index(), i as u32);
        assert_eq!(layer.blob_sha256(), "31".repeat(32));
        assert_eq!(layer.packet_ordinal(), 1);
        assert_eq!(
            layer.kms_ciphertext_sha384(),
            hash384(b"selected-kms-ciphertext")
        );
        assert_ne!(layer.packet_sha384(), layer.kms_ciphertext_sha384());
        assert_eq!(layer.descriptor_size(), 123);
        assert!(layer.media_type().ends_with("gzip+encrypted"));
        assert_eq!(
            layer.expected_diff_id(),
            format!("sha256:{}", "41".repeat(32))
        );
    }
    assert_eq!(bound.admission_context_sha384().len(), 96);
    assert_eq!(bound.credential_delivery_sha384().len(), 96);
    assert_eq!(
        attempt.bind_manifest(&manifest, &config),
        Ok(ManifestBinding::Historical)
    );
    let mut changed = manifest.clone();
    changed.push(b' ');
    assert_eq!(
        attempt.bind_manifest(&changed, &config),
        Err(PreparationError::Conflict)
    );
    assert!(attempt.manifest_plan().is_err());
    assert_eq!(
        attempt.bind_manifest(&manifest, &config),
        Err(PreparationError::Unavailable)
    );
}

#[tokio::test]
async fn digest_mismatch_and_cancel_are_terminal_without_a_credential_release_api() {
    let (m, c) = inputs(1);
    let (m, c) = encode(m, c);
    let mut a = attempt(&m, limits()).await;
    let mut changed = m.clone();
    changed.push(b' ');
    assert_eq!(
        a.bind_manifest(&changed, &c),
        Err(PreparationError::ScopeMismatch)
    );
    assert_eq!(a.bind_manifest(&m, &c), Err(PreparationError::Unavailable));
    let mut a = attempt(&m, limits()).await;
    a.cancel();
    a.cancel();
    assert_eq!(a.bind_manifest(&m, &c), Err(PreparationError::Unavailable));
}

#[tokio::test]
async fn signed_context_and_delivery_must_match_independent_roots_and_exact_scope() {
    let (m, c) = inputs(1);
    let (m, _) = encode(m, c);
    let (credential, expected, admission) = preparation_fixture(hash256(&m)).await;
    let mut expected = profile(expected);
    expected.binding.boot_id = "other-boot".into();
    assert!(matches!(
        PreparationAttempt::new_gcp(admission, credential, expected, limits()),
        Err(PreparationError::ScopeMismatch)
    ));
    let (credential, expected, _) = preparation_fixture(hash256(&m)).await;
    let (_, _, admission) = preparation_fixture(hash256(&m)).await;
    assert!(matches!(
        PreparationAttempt::new_gcp(admission, credential, profile(expected), limits()),
        Err(PreparationError::ScopeMismatch)
    ));
}

#[tokio::test]
async fn wrong_config_digest_size_and_diffid_shape_never_bind() {
    for case in ["bytes", "size", "diffids", "malformed-diffid", "os"] {
        let (m, mut c) = inputs(1);
        match case {
            "diffids" => c["rootfs"]["diff_ids"] = json!([]),
            "malformed-diffid" => c["rootfs"]["diff_ids"] = json!(["sha512:unsupported"]),
            "os" => c["os"] = "windows".into(),
            _ => {}
        }
        let (mut m, mut c) = encode(m, c);
        if case == "bytes" {
            c.push(b' ');
        }
        if case == "size" {
            let mut raw: Value = serde_json::from_slice(&m).unwrap();
            raw["config"]["size"] = 1.into();
            m = serde_json::to_vec(&raw).unwrap();
        }
        let mut a = attempt(&m, limits()).await;
        assert!(a.bind_manifest(&m, &c).is_err(), "{case}");
        assert_eq!(a.bind_manifest(&m, &c), Err(PreparationError::Unavailable));
    }
}

#[tokio::test]
async fn unsupported_index_plaintext_and_malformed_packet_profiles_are_terminal() {
    for case in [
        "index",
        "plaintext",
        "zstd",
        "foreign-provider",
        "foreign-key",
        "percent-lower",
        "ambiguous",
        "unknown-field",
        "bad-base64",
        "noncanonical-inner-base64",
        "public-hmac",
        "extra-keyprovider",
    ] {
        let (mut m, c) = inputs(1);
        match case {
            "index"=>m["mediaType"]="application/vnd.oci.image.index.v1+json".into(),
            "plaintext"=>m["layers"][0]["mediaType"]="application/vnd.oci.image.layer.v1.tar+gzip".into(),
            "zstd"=>m["layers"][0]["mediaType"]="application/vnd.oci.image.layer.v1.tar+zstd+encrypted".into(),
            "foreign-provider"=>m["layers"][0]["annotations"][PACKET_KEY]=packet(KEY,"aws",b"selected-kms-ciphertext").into(),
            "foreign-key"=>m["layers"][0]["annotations"][PACKET_KEY]=packet(&KEY.replace("/1","/3"),"gcp",b"selected-kms-ciphertext").into(),
            "percent-lower"=>{let raw=STANDARD.decode(packet(KEY,"gcp",b"ciphertext")).unwrap();let raw=String::from_utf8(raw).unwrap().replace("%2F","%2f");m["layers"][0]["annotations"][PACKET_KEY]=STANDARD.encode(raw).into();},
            "ambiguous"=>m["layers"][0]["annotations"][PACKET_KEY]=format!("{},{}",packet(KEY,"gcp",b"a"),packet(KEY,"gcp",b"b")).into(),
            "unknown-field"=>{let mut p:Value=serde_json::from_slice(&STANDARD.decode(packet(KEY,"gcp",b"a")).unwrap()).unwrap();p["provider"]="gcp".into();m["layers"][0]["annotations"][PACKET_KEY]=STANDARD.encode(serde_json::to_vec(&p).unwrap()).into();},
            "bad-base64"=>m["layers"][0]["annotations"][PACKET_KEY]="a===".into(),
            "noncanonical-inner-base64" => {
                let mut p: Value = serde_json::from_slice(
                    &STANDARD.decode(packet(KEY, "gcp", b"a")).unwrap(),
                ).unwrap();
                // Nonzero unused pad bits, unlike the canonical YQ==.
                p["wrapped_data"] = STANDARD.encode("gcp:YR==").into();
                m["layers"][0]["annotations"][PACKET_KEY] =
                    STANDARD.encode(serde_json::to_vec(&p).unwrap()).into();
            }
            "public-hmac"=>m["layers"][0]["annotations"][PUBLIC_KEY]=STANDARD.encode(serde_json::to_vec(&json!({"cipher":"AES_256_CTR_HMAC_SHA256","cipheroptions":{},"hmac":STANDARD.encode([0;31])})).unwrap()).into(),
            "extra-keyprovider"=>m["layers"][0]["annotations"]["org.opencontainers.image.enc.keys.provider.other"]="ignored".into(),
            _=>unreachable!(),
        }
        let (m, c) = encode(m, c);
        let mut a = attempt(&m, limits()).await;
        assert!(a.bind_manifest(&m, &c).is_err(), "{case}");
        assert!(a.manifest_plan().is_err());
        assert_eq!(a.bind_manifest(&m, &c), Err(PreparationError::Unavailable));
    }
}

#[tokio::test]
async fn duplicate_annotation_and_recognized_struct_fields_are_rejected() {
    for case in ["annotation", "manifest-field", "packet-field"] {
        let (mut m, c) = inputs(1);
        if case == "packet-field" {
            let p = String::from_utf8(STANDARD.decode(packet(KEY, "gcp", b"a")).unwrap())
                .unwrap()
                .replace(
                    "\"wrap_type\":\"KMS-DIRECT\"",
                    "\"wrap_type\":\"KMS-DIRECT\",\"wrap_type\":\"KMS-DIRECT\"",
                );
            m["layers"][0]["annotations"][PACKET_KEY] = STANDARD.encode(p).into();
        }
        let (m, c) = encode(m, c);
        let m = String::from_utf8(m).unwrap();
        let m = match case {
            "annotation" => m.replacen(
                &format!("\"{PACKET_KEY}\":"),
                &format!("\"{PACKET_KEY}\":\"\",\"{PACKET_KEY}\":"),
                1,
            ),
            "manifest-field" => m.replace(
                "\"schemaVersion\":2",
                "\"schemaVersion\":2,\"schemaVersion\":2",
            ),
            _ => m,
        }
        .into_bytes();
        let mut a = attempt(&m, limits()).await;
        let expected = if case == "packet-field" {
            PreparationError::InvalidPacket
        } else {
            PreparationError::InvalidManifest
        };
        assert_eq!(a.bind_manifest(&m, &c), Err(expected), "{case}");
        assert_eq!(a.bind_manifest(&m, &c), Err(PreparationError::Unavailable));
    }
}

#[tokio::test]
async fn constructor_and_metadata_bounds_cover_exact_and_over_limit_inputs() {
    let (m, c) = inputs(1);
    let (m, c) = encode(m, c);
    let mut exact = limits();
    exact.manifest_bytes = m.len();
    exact.config_bytes = c.len();
    let mut a = attempt(&m, exact).await;
    assert!(a.bind_manifest(&m, &c).is_ok());
    for case in [
        "manifest",
        "config",
        "packet-count",
        "packet-bytes",
        "ciphertext-bytes",
        "public-options",
    ] {
        let mut configured = limits();
        match case {
            "manifest" => configured.manifest_bytes = m.len() - 1,
            "config" => configured.config_bytes = c.len() - 1,
            "packet-count" => configured.packets_per_layer = 1,
            "packet-bytes" => configured.packet_bytes = 8,
            "ciphertext-bytes" => configured.kms_ciphertext_bytes = 1,
            "public-options" => configured.public_options_bytes = 1,
            _ => unreachable!(),
        }
        let mut a = attempt(&m, configured).await;
        assert_eq!(
            a.bind_manifest(&m, &c),
            Err(PreparationError::TooLarge),
            "{case}"
        );
        assert_eq!(a.bind_manifest(&m, &c), Err(PreparationError::Unavailable));
    }
    let (credential, expected, admission) = preparation_fixture(hash256(&m)).await;
    let mut configured = limits();
    configured.operations = 33;
    assert!(matches!(
        PreparationAttempt::new_gcp(admission, credential, profile(expected), configured),
        Err(PreparationError::InvalidConfiguration)
    ));
}

#[tokio::test]
async fn selected_operation_budget_accepts_32_and_rejects_33_without_dedup() {
    let (m, c) = inputs(32);
    let (m, c) = encode(m, c);
    let mut a = attempt(&m, limits()).await;
    assert!(a.bind_manifest(&m, &c).is_ok());
    assert_eq!(a.manifest_plan().unwrap().layers().len(), 32);
    assert_eq!(a.manifest_plan().unwrap().layers()[31].original_index(), 31);
    let (m, c) = inputs(33);
    let (m, c) = encode(m, c);
    let mut a = attempt(&m, limits()).await;
    assert_eq!(a.bind_manifest(&m, &c), Err(PreparationError::TooLarge));
    assert!(a.manifest_plan().is_err());
}

#[tokio::test]
async fn shared_owner_serializes_one_initial_binding_then_metadata_history_only() {
    let (m, c) = inputs(2);
    let (m, c) = encode(m, c);
    let owner = Arc::new(Mutex::new(attempt(&m, limits()).await));
    let results = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..2)
            .map(|_| {
                let owner = owner.clone();
                let m = &m;
                let c = &c;
                scope.spawn(move || owner.lock().unwrap().bind_manifest(m, c))
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().unwrap().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(
        results
            .iter()
            .filter(|r| **r == ManifestBinding::FirstBound)
            .count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .filter(|r| **r == ManifestBinding::Historical)
            .count(),
        1
    );
    owner.lock().unwrap().cancel();
    assert!(owner.lock().unwrap().manifest_plan().is_err());
}

#[tokio::test]
async fn independently_selected_boot_binding_must_match_gcp_credential_before_storage() {
    let (manifest, config) = inputs(1);
    let (manifest, _) = encode(manifest, config);
    let (credential, expected, admission) = preparation_fixture(hash256(&manifest)).await;
    let mut expected = profile(expected);
    expected.binding.profile_sha384 = "cd".repeat(48);
    assert!(matches!(
        PreparationAttempt::new_gcp(admission, credential, expected, limits()),
        Err(PreparationError::ScopeMismatch)
    ));
}
