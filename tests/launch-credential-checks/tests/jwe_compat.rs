//! Cross-version wire test of both unchanged production crypto implementations.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use onb17_launch_credential_checks::keypair::{TeeKeyAlgorithm, TeeKeyPair};

fn rsa_key() -> TeeKeyPair {
    TeeKeyPair::new_with_algorithm(TeeKeyAlgorithm::RsaOaep256).unwrap()
}
fn legacy_public(key: &TeeKeyPair) -> legacy_kbs_types::TeePubKey {
    let kbs_types::TeePubKey::RSA { alg, k_mod, k_exp } = key.export_pubkey().unwrap() else {
        panic!("configured RSA profile");
    };
    legacy_kbs_types::TeePubKey::RSA { alg, k_mod, k_exp }
}

#[test]
fn actual_trustee_jwe_is_decrypted_by_actual_gc_across_kbs_wire_versions() {
    let key = rsa_key();
    let plaintext = b"public-synthetic-credential-fixture";
    let jwe = credential_jwe::jwe(legacy_public(&key), plaintext.to_vec()).unwrap();
    let encoded = serde_json::to_vec(&jwe).unwrap();
    let current: kbs_types::Response = serde_json::from_slice(&encoded).unwrap();
    assert_eq!(key.decrypt_response(current).unwrap(), plaintext);
}

#[test]
fn actual_trustee_ciphertext_rejects_foreign_gc_key_and_changed_aead_tag() {
    let key = rsa_key();
    let jwe = credential_jwe::jwe(legacy_public(&key), b"synthetic-fixture".to_vec()).unwrap();
    let encoded = serde_json::to_vec(&jwe).unwrap();
    assert!(
        rsa_key()
            .decrypt_response(serde_json::from_slice(&encoded).unwrap())
            .is_err()
    );
    let mut changed: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
    let mut tag = URL_SAFE_NO_PAD
        .decode(changed["tag"].as_str().unwrap())
        .unwrap();
    tag[0] ^= 1;
    changed["tag"] = URL_SAFE_NO_PAD.encode(tag).into();
    let changed = serde_json::to_vec(&changed).unwrap();
    assert!(
        key.decrypt_response(serde_json::from_slice(&changed).unwrap())
            .is_err()
    );
}
