use std::collections::HashMap;
use std::fmt::{self, Debug};

use crate::config::{DecryptConfig, EncryptConfig};
use crate::keywrap::KeyWrapper;
use anyhow::{anyhow, bail, Result};
use base64::Engine;
use josekit::jwe::alg::aeskw::AeskwJweAlgorithm;
use lazy_static::lazy_static;
use ml_kem::array::Array;
use ml_kem::kem::{Decapsulate, DecapsulationKey, Encapsulate, EncapsulationKey, Kem as MlKem};
use ml_kem::EncodedSizeUser;
use ml_kem::KemCore;
use ml_kem::MlKem768Params;
use rand_chacha::ChaCha8Rng;
use rand_core::SeedableRng;
use serde_json::Value;

#[derive(Serialize, Deserialize, Debug)]
pub struct MLKEMAnnotationPacket {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_url: Option<String>,
    pub encapsulated_ss: String,
    pub ciphertext: String,
    pub wrap_type: String,
}

// Add this struct for the MLKEM key wrapper implementation
pub struct MLKEMKeyWrapper {
    decapsulation_key: Option<DecapsulationKey<MlKem768Params>>,
    encapsulation_key: Option<EncapsulationKey<MlKem768Params>>,
}

impl MLKEMKeyWrapper {
    pub fn new() -> Self {
        Self {
            decapsulation_key: None,
            encapsulation_key: None,
        }
    }

    pub fn generate() -> Self {
        let mut rng = ChaCha8Rng::from_entropy();
        let (dk, ek) = MlKem::<MlKem768Params>::generate(&mut rng);

        Self {
            decapsulation_key: Some(dk),
            encapsulation_key: Some(ek),
        }
    }

    fn init_from_seed(
        seed: &[u8],
    ) -> Result<(
        DecapsulationKey<MlKem768Params>,
        EncapsulationKey<MlKem768Params>,
    )> {
        if seed.len() != 64 {
            bail!("Seed must be exactly 64 bytes (32+32 for d and z)");
        }
        let (d, z) = seed.split_at(32);
        let mut d_bytes = [0u8; 32];
        d_bytes.copy_from_slice(d);
        let mut z_bytes = [0u8; 32];
        z_bytes.copy_from_slice(z);

        // Generate deterministic keys using ml-kem's API
        let (dk, ek) = MlKem::<MlKem768Params>::generate_deterministic(
            &Array::from(d_bytes),
            &Array::from(z_bytes),
        );
        Ok((dk, ek))
    }

    pub fn with_private_key(sk_b64: &str) -> Result<Self> {
        let sk_bytes = base64::engine::general_purpose::STANDARD.decode(sk_b64)?;
        let (dk, _ek) = Self::init_from_seed(&sk_bytes)?;
        let ek = dk.encapsulation_key().clone();

        Ok(Self {
            decapsulation_key: Some(dk),
            encapsulation_key: Some(ek),
        })
    }

    pub fn with_public_key(pk_b64: &str) -> Result<Self> {
        let pk = base64::engine::general_purpose::STANDARD.decode(pk_b64)?;
        let pk_array: [u8; 1184] = pk.try_into().map_err(|_| anyhow!("Invalid PK length"))?;
        let ek = EncapsulationKey::<MlKem768Params>::from_bytes(&Array::from(pk_array));

        Ok(Self {
            decapsulation_key: None,
            encapsulation_key: Some(ek),
        })
    }

    fn wrap_keys(&self, _ec: &EncryptConfig, opts_data: &[u8]) -> Result<Vec<u8>> {
        let ek = self
            .encapsulation_key
            .as_ref()
            .ok_or(anyhow!("No public key available"))?;

        // Encapsulate shared secret using ml-kem's API
        let mut rng = ChaCha8Rng::from_entropy();
        let (ct, ss) = Encapsulate::encapsulate(ek, &mut rng)?;
        println!("Generated shared secret length: {}", ss.as_slice().len());

        // Build JWE with josekit
        let mut claims = josekit::jwe::JweHeader::new().into_map();
        claims.insert("alg".to_string(), Value::String("A256KW".to_string()));
        claims.insert("enc".to_string(), Value::String("A256GCM".to_string()));
        claims.insert(
            "encapsulated_ss".to_string(),
            Value::String(base64::engine::general_purpose::STANDARD.encode(ct.as_slice())),
        );
        let protected_header = josekit::jwe::JweHeader::from_map(claims)?;

        // Use AES Key Wrap with shared secret directly
        let encrypter = AeskwJweAlgorithm::A256kw.encrypter_from_bytes(ss.as_slice())?;
        let jwe = josekit::jwe::serialize_compact(opts_data, &protected_header, &encrypter)?;
        Ok(jwe.into_bytes())
    }

    fn unwrap_keys(&self, _: &DecryptConfig, jwe_data: &[u8]) -> Result<Vec<u8>> {
        let dk = self
            .decapsulation_key
            .as_ref()
            .ok_or(anyhow!("No private key available"))?;

        // Parse the JWE string
        let jwe_str = std::str::from_utf8(jwe_data)?;
        println!("JWE input: {}", jwe_str);

        // Parse JWE string to get components
        let (protected, header_bytes, encrypted_key, iv, ciphertext, tag) = if jwe_str
            .starts_with('{')
        {
            println!("JWE json format detected");
            // Parse JSON format
            let jwe: serde_json::Value = serde_json::from_str(jwe_str)?;

            let protected = jwe["protected"]
                .as_str()
                .ok_or(anyhow!("Missing protected header"))?
                .to_string();
            let header_bytes =
                base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&protected)?;
            let encrypted_key = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(
                jwe["encrypted_key"]
                    .as_str()
                    .ok_or(anyhow!("Missing encrypted_key"))?,
            )?;
            let iv = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(jwe["iv"].as_str().ok_or(anyhow!("Missing iv"))?)?;
            let ciphertext = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(
                jwe["ciphertext"]
                    .as_str()
                    .ok_or(anyhow!("Missing ciphertext"))?,
            )?;
            let tag = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(jwe["tag"].as_str().ok_or(anyhow!("Missing tag"))?)?;

            (protected, header_bytes, encrypted_key, iv, ciphertext, tag)
        } else {
            println!("JWE compact format detected");
            // Parse compact format - format is: header.encrypted_key.iv.ciphertext.tag
            let parts: Vec<&str> = jwe_str.split('.').collect();
            if parts.len() != 5 {
                return Err(anyhow!("Invalid JWE format"));
            }

            let protected = parts[0].to_string();
            let header_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(parts[0])?;
            let encrypted_key =
                base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(parts[1])?;
            let iv = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(parts[2])?;
            let ciphertext = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(parts[3])?;
            let tag = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(parts[4])?;

            (protected, header_bytes, encrypted_key, iv, ciphertext, tag)
        };

        println!("passed parsing");

        // Extract encapsulated_ss from header
        let header: serde_json::Value = serde_json::from_slice(&header_bytes)?;
        let encapsulated_ss = header["encapsulated_ss"]
            .as_str()
            .ok_or(anyhow!("Missing encapsulated_ss"))?;

        println!("encapsulated_ss: {}", encapsulated_ss);

        // Decode encapsulated_ss using STANDARD base64
        let ct = base64::engine::general_purpose::STANDARD.decode(encapsulated_ss)?;

        // Convert to fixed size array
        let ct_array: [u8; 1088] = ct
            .try_into()
            .map_err(|_| anyhow!("Invalid ciphertext length"))?;

        println!(
            "Using decapsulated shared secret, length: {}",
            ct_array.len()
        );

        // Decapsulate to get shared secret
        let ss = Decapsulate::decapsulate(dk, &Array::from(ct_array))?;

        println!("Decapsulated shared secret bytes: {:?}", ss.as_slice());

        // Try direct AES key unwrap before JWE decryption
        let aes = openssl::aes::AesKey::new_decrypt(ss.as_slice())
            .map_err(|e| anyhow!("Failed to create AES key: {:?}", e))?;

        println!("Encrypted key length: {}", encrypted_key.len());

        // AES key wrap adds 8 bytes of padding, so output buffer should be 8 bytes smaller
        let mut content_key = vec![0; encrypted_key.len() - 8];
        let key_len = openssl::aes::unwrap_key(&aes, None, &mut content_key, &encrypted_key)
            .map_err(|e| anyhow!("Failed to unwrap key: {:?}", e))?;
        content_key.truncate(key_len);

        println!("Unwrapped key length: {}", content_key.len());
        println!("Unwrapped key: {:?}", content_key);

        let aad = protected.as_bytes();
        println!("AAD length: {}", aad.len());
        println!("IV length: {}", iv.len());
        println!("Tag length: {}", tag.len());

        // Create cipher for content decryption
        let cipher = openssl::symm::Cipher::aes_256_gcm();
        let plaintext =
            openssl::symm::decrypt_aead(cipher, &content_key, Some(&iv), aad, &ciphertext, &tag)
                .map_err(|e| anyhow!("Failed to decrypt content: {:?}", e))?;

        Ok(plaintext)
    }
}

impl KeyWrapper for MLKEMKeyWrapper {
    fn wrap_keys(&self, ec: &EncryptConfig, opts_data: &[u8]) -> Result<Vec<u8>> {
        self.wrap_keys(ec, opts_data)
    }

    fn unwrap_keys(&self, dc: &DecryptConfig, jwe_data: &[u8]) -> Result<Vec<u8>> {
        self.unwrap_keys(dc, jwe_data)
    }

    fn annotation_id(&self) -> String {
        "org.opencontainers.image.enc.keys.provider.mlkem".to_string()
    }

    fn probe(&self, _dc_param: &HashMap<String, Vec<Vec<u8>>>) -> bool {
        true
    }
}

// Add this function to get the MLKEM key wrapper
pub fn get_mlkem_wrapper() -> Box<dyn KeyWrapper> {
    Box::new(MLKEMKeyWrapper::new())
}

// Then in your crate root (lib.rs or main.rs), register the MLKEM wrapper:
lazy_static! {
    pub static ref KEY_WRAPPERS_ANNOTATIONS: HashMap<String, String> = {
        let mut m = HashMap::new();
        m.insert(
            "org.opencontainers.image.enc.keys.provider.mlkem".to_string(),
            "mlkem".to_string(),
        );
        m
    };
}

// Manual Debug impl to work around pqcrypto types not implementing Debug
impl Debug for MLKEMKeyWrapper {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MLKEMKeyWrapper")
            .field(
                "decapsulation_key",
                &self.decapsulation_key.as_ref().map(|_| "[redacted]"),
            )
            .field(
                "encapsulation_key",
                &self
                    .encapsulation_key
                    .as_ref()
                    .map(|k| base64::engine::general_purpose::STANDARD.encode(k.as_bytes())),
            )
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::Path;

    #[test]
    fn test_mlkem_key_bundle() {
        println!("Starting test_mlkem_key_bundle");

        // Create wrapper with fresh keys
        let wrapper = MLKEMKeyWrapper::generate();

        // Generate a shared secret
        let ss = vec![0u8; 32]; // Test shared secret
        println!("Generated shared secret length: {}", ss.len());

        // Create test encryption config
        let ec = EncryptConfig::default();

        // Wrap the shared secret
        let wrapped = wrapper.wrap_keys(&ec, &ss).expect("Failed to wrap keys");
        println!(
            "Encrypted data (compact JWE):\n{}",
            String::from_utf8_lossy(&wrapped)
        );

        // Unwrap and verify
        let unwrapped = wrapper
            .unwrap_keys(&DecryptConfig::default(), &wrapped)
            .expect("Failed to unwrap keys");

        assert_eq!(ss, unwrapped, "Unwrapped data does not match original");
    }

    #[test]
    fn test_jwe_decryption() {
        println!("Starting test_mlkem_jwe_decryption");

        // Load and decode private key from key bundle
        let key_bundle = std::fs::read_to_string("test_data/key-bundle.golden")
            .expect("Failed to read key bundle");
        let bundle: serde_json::Value = serde_json::from_str(&key_bundle).unwrap();
        let sk = base64::engine::general_purpose::STANDARD
            .decode(bundle["sk"].as_str().unwrap())
            .expect("Failed to decode SK");

        // Create key wrapper with test private key
        let wrapper = MLKEMKeyWrapper::with_private_key(
            &base64::engine::general_purpose::STANDARD.encode(&sk),
        )
        .unwrap();

        // Load golden JWE from file
        let jwe_data = fs::read_to_string(Path::new("test_data/cipherdata_256.enc"))
            .expect("Failed to read cipherdata file");

        // Test decryption
        let decrypted = wrapper.unwrap_keys(&DecryptConfig::default(), jwe_data.as_bytes());
        assert!(
            decrypted.is_ok(),
            "Decryption failed: {:?}",
            decrypted.err()
        );
        assert_eq!(decrypted.unwrap(), b"abc");
    }
    #[test]
    fn test_decapsulation() -> Result<()> {
        // Load test vectors
        let encapsulated_ss = std::fs::read("test_data/encapsulated_ss.bin")
            .expect("Failed to read encapsulated_ss.bin");
        let expected_ss = std::fs::read("test_data/ss.key").expect("Failed to read ss.key");

        // Load and decode private key from key bundle
        let key_bundle = std::fs::read_to_string("test_data/key-bundle.golden")
            .expect("Failed to read key bundle");
        let bundle: serde_json::Value = serde_json::from_str(&key_bundle).unwrap();
        let sk = base64::engine::general_purpose::STANDARD
            .decode(bundle["sk"].as_str().unwrap())
            .expect("Failed to decode SK");

        // Create key wrapper with test private key
        let mut wrapper = MLKEMKeyWrapper::new();
        let (dk, _) = MLKEMKeyWrapper::init_from_seed(&sk)?;
        wrapper.decapsulation_key = Some(dk);

        // Perform decapsulation
        let ct_array: [u8; 1088] = encapsulated_ss
            .as_slice()
            .try_into()
            .expect("Invalid encapsulated_ss length");
        let ss = Decapsulate::decapsulate(
            wrapper.decapsulation_key.as_ref().unwrap(),
            &Array::from(ct_array),
        )
        .expect("Decapsulation failed");

        // Compare results
        assert_eq!(ss.as_slice(), expected_ss.as_slice());
        Ok(())
    }

    #[test]
    fn test_encrypt_decrypt_separate_wrappers() {
        // Load keys from bundle
        let key_bundle = std::fs::read_to_string("test_data/key-bundle.golden")
            .expect("Failed to read key bundle");
        let bundle: serde_json::Value = serde_json::from_str(&key_bundle).unwrap();

        // Create encryption wrapper with public key only
        let enc_wrapper = MLKEMKeyWrapper::with_public_key(bundle["pk"].as_str().unwrap())
            .expect("Failed to create encryption wrapper");

        // Create decryption wrapper with private key only
        let dec_wrapper = MLKEMKeyWrapper::with_private_key(bundle["sk"].as_str().unwrap())
            .expect("Failed to create decryption wrapper");

        // Test data to encrypt
        let test_data = b"test encryption data";

        // Encrypt with public key
        let wrapped = enc_wrapper
            .wrap_keys(&EncryptConfig::default(), test_data)
            .expect("Failed to wrap keys");

        // Decrypt with private key
        let unwrapped = dec_wrapper
            .unwrap_keys(&DecryptConfig::default(), &wrapped)
            .expect("Failed to unwrap keys");

        // Verify decrypted data matches original
        assert_eq!(
            test_data,
            unwrapped.as_slice(),
            "Decrypted data doesn't match original"
        );
    }
}
