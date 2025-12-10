use anyhow::{anyhow, bail, Result};
use base64::Engine;
use hkdf::Hkdf;
use tracing::debug;
use ml_kem::array::Array;
use ml_kem::kem::{Decapsulate, DecapsulationKey, Encapsulate, EncapsulationKey, Kem};
use ml_kem::{EncodedSizeUser, KemCore};
use ml_kem::{MlKem1024Params, MlKem768Params};
use rand_chacha_09::ChaCha8Rng;
use rand_core_09::SeedableRng;
use sha2::Sha256;

/// MLKEM variant specification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Variant {
    /// MLKEM-768 variant
    Mlkem768,
    /// MLKEM-1024 variant
    Mlkem1024,
}

#[cfg(feature = "openssl")]
use crate::native::*;

#[cfg(all(feature = "rust-crypto", not(feature = "openssl")))]
use crate::rust::*;

// /// Encrypt data using a shared secret derived from the encapsulation key.
pub fn mlkem_encrypt(key: &[u8], data: &[u8], iv: &[u8], variant: Variant) -> Result<Vec<u8>> {
    debug!("Encrypting data with MLKEMKeyPair, variant: {:?}", variant);

    let sk = base64::engine::general_purpose::STANDARD
        .decode(&key)
        .map_err(|e| anyhow!("Failed to decode mlkem key: {:?}", e))?;

    let sk_encoded = base64::engine::general_purpose::STANDARD.encode(&sk);
    let (ct, ss) = match variant {
        Variant::Mlkem768 => {
            let key_pair = MLKEMKeyPair768::from_secret_key(&sk_encoded)
                .map_err(|e| anyhow!("Failed to create MLKEMKeyPair: {:?}", e))?;
            key_pair
                .encapsulate()
                .map_err(|e| anyhow!("Key encapsulation failed: {:?}", e))?
        }
        Variant::Mlkem1024 => {
            let key_pair = MLKEMKeyPair1024::from_secret_key(&sk_encoded)
                .map_err(|e| anyhow!("Failed to create MLKEMKeyPair: {:?}", e))?;
            key_pair
                .encapsulate()
                .map_err(|e| anyhow!("Key encapsulation failed: {:?}", e))?
        }
    };

    debug!("Deriving key from shared secret");
    let derive_info: &[u8] = match variant {
        Variant::Mlkem768 => b"MLKEM768-A256GCM",
        Variant::Mlkem1024 => b"MLKEM1024-A256GCM",
    };
    let hkdf = Hkdf::<Sha256>::new(None, &ss);
    let mut derived_key = vec![0u8; 32];
    hkdf.expand(derive_info, &mut derived_key)
        .map_err(|e| anyhow!("HKDF expansion failed: {:?}", e))?;

    debug!("Encrypting with derived key");
    let wrapped_data = aes256gcm::encrypt(&derived_key, &data, &iv)
        .map_err(|e| anyhow!("AES encryption failed: {:?}", e))?;

    let wrapped_data_b64 = base64::engine::general_purpose::STANDARD.encode(&wrapped_data);
    let encapsulated_ss_b64 = base64::engine::general_purpose::STANDARD.encode(&ct);
    let encrypted_data = format!("{}:{}", wrapped_data_b64, encapsulated_ss_b64);

    Ok(encrypted_data.into_bytes())
}

/// Decrypt data using a shared secret derived from the decapsulation key.
/// The `encrypted_data` is expected to be in the format "{wrapped_data}:{encapsulated_ss}".
pub fn mlkem_decrypt(
    key: &[u8],
    encrypted_data: &[u8],
    iv: &[u8],
    variant: Variant,
) -> Result<Vec<u8>> {
    debug!("Decrypting data with MLKEMKeyPair, variant: {:?}", variant);

    let (wrapped_data, encapsulated_ss) = parse_encapsulated_ss(encrypted_data)
        .map_err(|e| anyhow!("Failed to parse encrypted data: {:?}", e))?;

    let shared_secret = match variant {
        Variant::Mlkem768 => {
            let key_pair = MLKEMKeyPair768::from_secret_key(&String::from_utf8_lossy(&key))
                .map_err(|e| anyhow!("Failed to create MLKEMKeyPair: {:?}", e))?;
            key_pair
                .decapsulate(encapsulated_ss.as_slice())
                .map_err(|e| anyhow!("Key decapsulation failed: {:?}", e))?
        }
        Variant::Mlkem1024 => {
            let key_pair = MLKEMKeyPair1024::from_secret_key(&String::from_utf8_lossy(&key))
                .map_err(|e| anyhow!("Failed to create MLKEMKeyPair: {:?}", e))?;
            key_pair
                .decapsulate(encapsulated_ss.as_slice())
                .map_err(|e| anyhow!("Key decapsulation failed: {:?}", e))?
        }
    };

    debug!("Deriving key from shared secret");
    let derive_info: &[u8] = match variant {
        Variant::Mlkem768 => b"MLKEM768-A256GCM",
        Variant::Mlkem1024 => b"MLKEM1024-A256GCM",
    };
    let hkdf = Hkdf::<Sha256>::new(None, &shared_secret);
    let mut derived_key = vec![0u8; 32];
    hkdf.expand(derive_info, &mut derived_key)
        .map_err(|e| anyhow!("HKDF expansion failed: {:?}", e))?;

    debug!("Decrypting with derived key");
    aes256gcm::decrypt(&derived_key, &wrapped_data, &iv)
}

pub fn parse_encapsulated_ss(wrapped_data: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let parts: Vec<&str> = std::str::from_utf8(wrapped_data)
        .map_err(|_| anyhow!("Invalid wrapped data format"))?
        .split(':')
        .collect();
    if parts.len() != 2 {
        bail!("Invalid wrapped data format. Expected 'wrapped_data:encapsulated_ss'");
    }

    let wrapped_data_decoded = base64::engine::general_purpose::STANDARD
        .decode(parts[0])
        .map_err(|e| anyhow!("Failed to decode wrapped_data: {:?}", e))?;
    let encapsulated_ss_decoded = base64::engine::general_purpose::STANDARD
        .decode(parts[1])
        .map_err(|e| anyhow!("Failed to decode encapsulated_ss: {:?}", e))?;

    Ok((wrapped_data_decoded, encapsulated_ss_decoded))
}

// Macro to define struct and implement methods for each parameter type
macro_rules! define_mlkem_keypair {
    ($name:ident, $params:ty, $ct_size:expr, $pk_size:expr) => {
        pub struct $name {
            decapsulation_key: Option<DecapsulationKey<$params>>,
            encapsulation_key: Option<EncapsulationKey<$params>>,
        }

        impl $name {
            pub fn new() -> Self {
                Self {
                    decapsulation_key: None,
                    encapsulation_key: None,
                }
            }

            pub fn generate() -> Result<Self> {
                debug!("generating new mlkem keypair");
                let mut thread_rng = rand::rng();
                let mut rng = ChaCha8Rng::from_rng(&mut thread_rng);
                let (dk, ek) = Kem::<$params>::generate(&mut rng);
                Ok(Self {
                    decapsulation_key: Some(dk),
                    encapsulation_key: Some(ek),
                })
            }

            pub fn decapsulate(&self, ct: &[u8]) -> Result<Vec<u8>> {
                debug!("decapsulating with MLKEMKeyPair");
                let dk = self
                    .decapsulation_key
                    .as_ref()
                    .ok_or_else(|| anyhow!("Decapsulation key is not set"))?;

                if ct.len() != $ct_size {
                    bail!(
                        "Invalid CT length, expected {} bytes, got {}",
                        $ct_size,
                        ct.len()
                    );
                }

                let ct_array: [u8; $ct_size] = ct
                    .try_into()
                    .map_err(|_| anyhow!("Invalid CT length, expected {} bytes", $ct_size))?;
                let shared_secret = Decapsulate::decapsulate(dk, &Array::from(ct_array))?;
                Ok(shared_secret.to_vec())
            }

            pub fn encapsulate(&self) -> Result<(Vec<u8>, Vec<u8>)> {
                debug!("encapsulating shared secret");
                let ek = self
                    .encapsulation_key
                    .as_ref()
                    .ok_or_else(|| anyhow!("Encapsulation key is not set"))?;
                let mut thread_rng = rand::rng();
                let mut rng = ChaCha8Rng::from_rng(&mut thread_rng);
                let (ct, ss) = Encapsulate::encapsulate(ek, &mut rng)
                    .map_err(|e| anyhow!("Key encapsulation failed: {:?}", e))?;
                Ok((ct.to_vec(), ss.to_vec()))
            }

            pub fn derive(&self, shared_secret: &[u8], info: &[u8]) -> Result<Vec<u8>> {
                debug!("mlkem deriving key");
                let hkdf = Hkdf::<Sha256>::new(None, shared_secret);
                let mut key = vec![0u8; 32];
                hkdf.expand(info, &mut key)
                    .map_err(|e| anyhow!("HKDF expansion failed: {:?}", e))?;
                Ok(key)
            }

            fn init_from_seed(
                seed: &[u8],
            ) -> Result<(DecapsulationKey<$params>, EncapsulationKey<$params>)> {
                if seed.len() != 64 {
                    bail!("Seed must be exactly 64 bytes");
                }
                let mut seed_array = [0u8; 64];
                seed_array.copy_from_slice(seed);
                let (dk, ek) = Kem::<$params>::from_seed(Array::from(seed_array));
                Ok((dk, ek))
            }

            pub fn from_secret_key(sk_input: &str) -> Result<Self> {
                let sk_bytes = match base64::engine::general_purpose::STANDARD.decode(sk_input) {
                    Ok(decoded) => {
                        debug!(
                            "Successfully decoded input as base64: length={}",
                            decoded.len()
                        );
                        decoded
                    }
                    Err(e) => {
                        debug!("Input is not valid base64, using as raw bytes: {}", e);
                        sk_input.as_bytes().to_vec()
                    }
                };
                let mut seed = vec![0u8; 64];
                let bytes_to_copy = std::cmp::min(sk_bytes.len(), 64);
                seed[..bytes_to_copy].copy_from_slice(&sk_bytes[..bytes_to_copy]);
                let (dk, ek) = Self::init_from_seed(&seed)?;
                Ok(Self {
                    decapsulation_key: Some(dk),
                    encapsulation_key: Some(ek),
                })
            }

            pub fn with_public_key(pk_b64: &str) -> Result<Self> {
                debug!("Creating MLKEMKeyPair with public key");
                let pk = base64::engine::general_purpose::STANDARD.decode(pk_b64)?;
                if pk.len() != $pk_size {
                    bail!(
                        "Invalid PK length, expected {} bytes, got {}",
                        $pk_size,
                        pk.len()
                    );
                }
                let pk_array: [u8; $pk_size] = pk
                    .try_into()
                    .map_err(|_| anyhow!("Invalid PK length, expected {} bytes", $pk_size))?;
                let ek = EncapsulationKey::<$params>::from_bytes(&Array::from(pk_array));
                Ok(Self {
                    decapsulation_key: None,
                    encapsulation_key: Some(ek),
                })
            }
        }
    };
}

define_mlkem_keypair!(MLKEMKeyPair768, MlKem768Params, 1088, 1184);
define_mlkem_keypair!(MLKEMKeyPair1024, MlKem1024Params, 1568, 1568);

// Type alias for backward compatibility (using 768 as default)
pub type MLKEMKeyPair = MLKEMKeyPair768;

#[cfg(test)]
mod tests {
    use rstest::rstest;
    use base64::Engine;

    use crate::{mlkem_decrypt, mlkem_encrypt, MLKEMKeyPair1024, MLKEMKeyPair768, Variant};

    #[test]
    fn test_mlkem_key_pair() {
        let key_pair = MLKEMKeyPair768::generate().expect("failed to generate key pair");
        let (ct, ss) = key_pair.encapsulate().expect("failed to encapsulate");
        let ss_from_decaps = key_pair.decapsulate(&ct).expect("failed to decapsulate");
        assert_eq!(ss, ss_from_decaps);
    }

    #[test]
    fn test_mlkem_key_pair_1024() {
        let key_pair = MLKEMKeyPair1024::generate().expect("failed to generate key pair");
        let (ct, ss) = key_pair.encapsulate().expect("failed to encapsulate");
        let ss_from_decaps = key_pair.decapsulate(&ct).expect("failed to decapsulate");
        assert_eq!(ss, ss_from_decaps);
    }

    #[rstest]
    #[case(
        b"QmVKOnIEVIjYICXHF33IZ+owdqY2J4z7RNtFIvzQmGVQOpfiRFRmdE6OpEGK5iCN5R+6QR5UfBvsSko/UneVvQ==",
        b"plaintext1",
        b"unique nonce"
    )]
    fn mlkem_encrypt_decrypt(#[case] key: &[u8], #[case] plaintext: &[u8], #[case] iv: &[u8]) {
        let ciphertext =
            mlkem_encrypt(key, plaintext, iv, Variant::Mlkem768).expect("encryption failed");
        let plaintext_de =
            mlkem_decrypt(key, &ciphertext, iv, Variant::Mlkem768).expect("decryption failed");
        assert_eq!(plaintext, plaintext_de);
    }

    #[rstest]
    #[case(
        b"2MK3zpbKIATk8cWYsKQ4T5isdTGEVz634E3yCPL8GbuxY0mF7tzqu1YJaBNYPe0U3Z5jxLox+K1rWa4yildhpw==",
        b"TmVJaXNWMHp4eGNRbUwrRmozSS8vM0VJOXc2STVXV3VVUUNjOkxBNHJVRHF0QXY5OWd5U3dsbWlKTStFYXJSUG1KQVhIZmlDZHFlQ3VXMTRxOGdlQmN1OUg4a2FoUkdXTy9oZzRpNHByaDNpQXVDcHhEeHl4eS9VUHJsWDdodU5JZzdQaUZNQklQRjk3VUVSalN3RTZKaElrRHBlOXNMa05QUTVuY0VjeHkyNlR1YlBpeDM4eWlBNjZjeFBpdjZwaW9vUkJVRG5TakNVb01kVGozZXBWMGhKVHBWSGZxTTFxZUh0cHYzTVRPekhEWlRnMlY1OGxOVDZPZ1l6YXhhTml1NWhPeXZTdDJsVER2S2V3UG80UXVPdFRTV05IMnhUSUxIQ1RncGtrWTlldG1BdFhSUjZ1NzNwTEdtRk1mTUVpSWIzeTgyOHc1cDUzWUxBMWZWemNudUM0OFBuU29BSmR3S2QyZkNhZGNlU0U0TjBPdkpPOEFMalp0SDRXRlpBblFiUENnT016dXQ2OUtvUXlNNWtNL085QVdSaktnTnQya2lvZW1QTDN4M2R3WWErZ0IvdzkyRkQxaEZLZEFUdVhVNGhlQkRHNWNBbXJLbVh6b3huVlRUbjUwUkNRWUQ4OVAxbnVndkFjWWpralN1MjZEQUx4YWhRaFhBSWpqaXRBZWVDQVBIaWxEVnNwQ1JxU2cydjI3ZWNvVVRycmorMERQbk9pNjRxR0dpUWZaQmoyRU52MTJHMFVzMS9GcTEzTTczdGxzeGdsVC9qZjFjdVExNjNqZll5WFI4SWZpU1hPWmxjNXdiOEdXVTlkeG9hbVhQZDV3Z09uMWpjMGp6YkIzajJLdmNOanZsYkQxeUxDeFJMOWxlNzQzaExkVlJYbUwvRFJMVVBESk1Ia3VCZ2t6aXZPbkVjQmtTcFJiTkh5c2EyT2p0Q0psUkl0eXI2RVJoVlJwclNKdVZFd203dTRGN284S0xsRExyN3ZhMnpKbW9VSGRoUytUN1pIRzNFQjlUa2ZXdVorSS9iNllmWDZwK216alZDRlZ1STJ6UUt1bGFBUmFmb3d4VkVYWnRvb1AwQXh5L2hNbHA4bFNWbGdPWUJScTgzVFpmZXMwSFpQTGNIUENZeCtKQmlUUlZiN1R5c3VGY3g2QmFDUHdaMStiM21kSnBXaWV2OHZibGRmYnJDSWVhMjFpazl6bjhnYlQzOUMyNTJDOFdIcTducFNnR05JdGtyKzJNSE1iWEZGQmtOb29ZS2xHMU91WHcxY0RoaWN1ZHFKZGkvckUwTHM0TzVLM01zUlh5dHM4aHZrM2dSQ0g3eWgrTjNuTmZIc2FyVkN5cU1wQmdRQXlBT2FKNi94bWJtTUV2Ym1vNzZETXVxRVVSb1NTbG9TY1orTUJsR1JXNTRUcHlmdjZHdFlYV3BlMFhvd0ZPNU13RXZHRXFVSEdrcGI4WUdrOFYxT1QrV09DL0ZlTi9sd0o4YzZEOEdDTXFzNnZyVXMyOUNSR24vNEwwSmhxNjVxWmpzZ0dCQjRjREJRNWJmZFJVYlFLdDdhK21ncGx0bzJFaDVnbmppZTZwTnB3dXBYNlk4d0Q0bGcwcC9QdzBvdFVld1JPTkF3UEpjeXVWRlhqdnhuTys2SnR4ZzEzbFpUZlhiN2YxZzRhaFkrVGdKTzdIeG9Oa0tVZnFXZjdaaTg2MzN0YWMzcUErWFlsSjdIODhlWWhscjFER3lIVTZRZWE2OUFCNUhENjZCVE9DQldvSjB0RzdzQ0dlbmhjTzVvWFVaSjZCRThiR0kra2NKd3M5YzV4c3pRTGVRR2Uwa241SDVCSWpaREJpcExPZWs2eHpOQmM5Q05hTnFzdk4ydW44UUNKMkdhNkdwZGs2b0RxOUlWN0pZT2ZvdkltV0t4UUlwKzA5R25IdmxwU04zWVBIMFN0SUcyYm15R2ZrcWpsWUtSR1V1ellBRUhPc2lpZjM0PQ==",
        b"secret data",
        b"lzGXynOgzBoBLuC7"
    )]
    fn mlkem_decrypt_compatibility(
        #[case] key: &[u8],
        #[case] wrapped_data_64: &[u8],
        #[case] plaintext: &[u8],
        #[case] iv_64: &[u8],
    ) {
        let iv = base64::engine::general_purpose::STANDARD
            .decode(iv_64)
            .expect("failed to decode iv");
        let wrapped_data = base64::engine::general_purpose::STANDARD
            .decode(wrapped_data_64)
            .expect("failed to decode wrapped data");

        let plaintext_de = mlkem_decrypt(key, &wrapped_data, &iv, Variant::Mlkem768).expect("decryption failed");
        assert_eq!(plaintext, plaintext_de);
    }
}
