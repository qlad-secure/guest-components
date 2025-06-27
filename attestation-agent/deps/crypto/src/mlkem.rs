use anyhow::{anyhow, bail, Result};
use base64::Engine;
use log::debug;
use ml_kem::array::Array;
use ml_kem::kem::{Decapsulate, DecapsulationKey, Encapsulate, EncapsulationKey, Kem as MlKem};
use ml_kem::EncodedSizeUser;
use ml_kem::KemCore;
use ml_kem::MlKem768Params;
use rand_chacha::ChaCha8Rng;
use rand_core::SeedableRng;

#[cfg(feature = "openssl")]
use crate::native::*;

#[cfg(all(feature = "rust-crypto", not(feature = "openssl")))]
use crate::rust::*;

// /// Encrypt data using a shared secret derived from the encapsulation key.
pub fn mlkem_encrypt(key: &[u8], data: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    debug!("Encrypting data with MLKEMKeyPair");

    let sk = base64::engine::general_purpose::STANDARD
        .decode(&key)
        .map_err(|e| anyhow!("Failed to decode mlkem key: {:?}", e))?;

    let key_pair =
        MLKEMKeyPair::from_secret_key(&base64::engine::general_purpose::STANDARD.encode(&sk))
            .map_err(|e| anyhow!("Failed to create MLKEMKeyPair: {:?}", e))?;

    let (ct, ss) = key_pair
        .encapsulate()
        .map_err(|e| anyhow!("Key encapsulation failed: {:?}", e))?;

    debug!("Encrypting with shared secret");
    let wrapped_data = aes256gcm::encrypt(&ss, &data, &iv)
        .map_err(|e| anyhow!("AES encryption failed: {:?}", e))?;

    let wrapped_data_b64 = base64::engine::general_purpose::STANDARD.encode(&wrapped_data);
    let encapsulated_ss_b64 = base64::engine::general_purpose::STANDARD.encode(&ct);
    let encrypted_data = format!("{}:{}", wrapped_data_b64, encapsulated_ss_b64);

    Ok(encrypted_data.into_bytes())
}

/// Decrypt data using a shared secret derived from the decapsulation key.
/// The `encrypted_data` is expected to be in the format "{wrapped_data}:{encapsulated_ss}".
pub fn mlkem_decrypt(key: &[u8], encrypted_data: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    debug!("Decrypting data with MLKEMKeyPair");

    let (wrapped_data, encapsulated_ss) = parse_encapsulated_ss(encrypted_data)
        .map_err(|e| anyhow!("Failed to parse encrypted data: {:?}", e))?;

    // // Parse the encrypted data format "{wrapped_data}:{encapsulated_ss}"
    // let encrypted_str = std::str::from_utf8(encrypted_data)
    //     .map_err(|e| anyhow!("Invalid encrypted data format: {:?}", e))?;
    // let parts: Vec<&str> = encrypted_str.split(':').collect();
    // if parts.len() != 2 {
    //     bail!("Invalid encrypted data format. Expected 'wrapped_data:encapsulated_ss'");
    // }

    // // Decode Base64-encoded components
    // let wrapped_data = base64::engine::general_purpose::STANDARD
    //     .decode(parts[0])
    //     .map_err(|e| anyhow!("Failed to decode wrapped_data: {:?}", e))?;
    // let encapsulated_ss = base64::engine::general_purpose::STANDARD
    //     .decode(parts[1])
    //     .map_err(|e| anyhow!("Failed to decode encapsulated_ss: {:?}", e))?;
    // let sk = base64::engine::general_purpose::STANDARD
    //     .decode(&key)
    //     .map_err(|e| anyhow!("Failed to decode mlkem key: {:?}", e))?;

    let key_pair = MLKEMKeyPair::from_secret_key(&String::from_utf8_lossy(&key))
        .map_err(|e| anyhow!("Failed to create MLKEMKeyPair: {:?}", e))?;
    let shared_secret = key_pair
        .decapsulate(encapsulated_ss.as_slice())
        .map_err(|e| anyhow!("Key decapsulation failed: {:?}", e))?;

    debug!("Decrypting with shared secret");
    aes256gcm::decrypt(&shared_secret, &wrapped_data, &iv)
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

pub struct MLKEMKeyPair {
    decapsulation_key: Option<DecapsulationKey<MlKem768Params>>,
    encapsulation_key: Option<EncapsulationKey<MlKem768Params>>,
}

impl MLKEMKeyPair {
    pub fn new() -> Self {
        Self {
            decapsulation_key: None,
            encapsulation_key: None,
        }
    }

    pub fn generate() -> Result<Self> {
        debug!("generating new mlkem keypair");

        let mut rng = ChaCha8Rng::from_rng(rand_08::thread_rng())
            .map_err(|e| anyhow!("Failed to create RNG: {:?}", e))?;
        let (dk, ek) = MlKem::<MlKem768Params>::generate(&mut rng);

        Ok(Self {
            decapsulation_key: Some(dk),
            encapsulation_key: Some(ek),
        })
    }

    pub fn decapsulate(&self, ct: &[u8]) -> Result<Vec<u8>> {
        debug!("decapsulating with MLKEMKeyPair");
        if let Some(dk) = &self.decapsulation_key {
            let ct_array: [u8; 1088] = ct.try_into().map_err(|_| anyhow!("Invalid CT length"))?;
            let shared_secret = Decapsulate::decapsulate(dk, &Array::from(ct_array))?;
            Ok(shared_secret.to_vec())
        } else {
            bail!("Decapsulation key is not set");
        }
    }

    pub fn encapsulate(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        debug!("encapsulating shared secret");

        if let Some(ek) = &self.encapsulation_key {
            let mut rng = ChaCha8Rng::from_rng(&mut rand_08::thread_rng())
                .map_err(|e| anyhow!("Failed to create RNG: {:?}", e))?;
            let (ct, ss) = Encapsulate::encapsulate(ek, &mut rng)
                .map_err(|e| anyhow!("Key encapsulation failed: {:?}", e))?;

            Ok((ct.to_vec(), ss.to_vec()))
        } else {
            bail!("Decapsulation key is not set");
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

        let (dk, ek) = MlKem::<MlKem768Params>::generate_deterministic(
            &Array::from(d_bytes),
            &Array::from(z_bytes),
        );
        Ok((dk, ek))
    }

    pub fn from_secret_key(sk_input: &str) -> Result<Self> {
        debug!(
            "Creating MLKEMKeyPair with input: length={}",
            sk_input.len()
        );

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

        debug!("Created 64-byte seed from key bytes");

        let (dk, _ek) = Self::init_from_seed(&seed)?;
        let ek = dk.encapsulation_key().clone();

        Ok(Self {
            decapsulation_key: Some(dk),
            encapsulation_key: Some(ek),
        })
    }

    pub fn with_public_key(pk_b64: &str) -> Result<Self> {
        debug!("Creating MLKEMKeyPair with public key");
        let pk = base64::engine::general_purpose::STANDARD.decode(pk_b64)?;
        let pk_array: [u8; 1184] = pk.try_into().map_err(|_| anyhow!("Invalid PK length"))?;
        let ek = EncapsulationKey::<MlKem768Params>::from_bytes(&Array::from(pk_array));

        Ok(Self {
            decapsulation_key: None,
            encapsulation_key: Some(ek),
        })
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine;
    use rstest::rstest;

    use crate::{mlkem_decrypt, mlkem_encrypt, MLKEMKeyPair};

    #[test]
    fn test_mlkem_key_pair() {
        // Create wrapper with fresh keys
        let key_pair = MLKEMKeyPair::generate().expect("failed to generate key pair");

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
        let ciphertext = mlkem_encrypt(key, plaintext, iv).expect("encryption failed");
        let plaintext_de = mlkem_decrypt(key, &ciphertext, iv).expect("decryption failed");
        assert_eq!(plaintext, plaintext_de);
    }

    #[rstest]
    #[case(
        b"QmVKOnIEVIjYICXHF33IZ+owdqY2J4z7RNtFIvzQmGVQOpfiRFRmdE6OpEGK5iCN5R+6QR5UfBvsSko/UneVvQ==",
        b"L0xyN0ZBb054MzdzQ3pjWGRtOXphMWorTzQyNk5GZnpOSWtLOnVCMjgvRmo2MFY3N285SU9yR3BTd215VktGSkNLZ2Fha2dkQWI3b1BldkRrUzdpMkFkZFhzUHUyU0lBV2RtTkhvRHcwMThGYzY1STJVbWJGV3J5NTZya05CY2VTSU9uVnRDUUlnTnMxRG1XWXk0QklXU2ZCV1JPWmRmWVdwa2krelBETlYvSGJIQjkxc0puQmZyWHJQYnkwNkVnUlc3RzVDSzZLZ2p4S2NJQVpFSUw3cmVJMCtxNE82NHVBM1JybXZRR241VFY5a0lOQ01Cc0w5UUNWZE9hU3FUQmFuMGFER1dvNERmSGJEejZ1eDRnMkE4TjJSNm9WekJqeFhOTXJFdis3bXRYbHJ0SlR5NCs5T2ZkNVQ0NjFEZEwrVWVwbEZaTzdHNTRySXVCNTZYaENWYXV6dEVPNDNvRzFKcFlBbWJnREwxeER4T2ZKMDFTOSs4VkI0WjF3biszR3lQOHNMMHZGSmRJa1BmaGdIc0pCNkpkbWd5a1NQYWFpQnZxS3hieFdFZ2pFMVd0WldINWF2QmpVNXhaMDJaVjM2djZqVHlPSUREWWZ4a1RSWFcxcElxeUgzVGRVem52ZXEyMTN1bThiZ0dyejRmVjFCTlBPNW1oOXlySGJOb2txWHRVVDh5Qy9iNTA0eXRzWU1vbnBmbXpsZFAyUzNtZ2Zwcm9jT3lqU0dyMmJxOXJSeCtUTVJ6OCtGdEk1VXNsMDYvd0tGb3ZNZ3JnQXBKa2dvMWd5UWFXQ3ExRUZRS1ZEbG03bDJyam83a3RBK3luZmZGa0RJb1lNamRMMjcyQjNLaDk4L28yMnliUUNGTXIzRHVicWh3QlZTM3dRbHpPYjhDejJIV3ZNOENGOEd6d25aaFJXQ2d3RXJKeVZzaVdyTlRaMENzdTFVa2ZqWkY2VU9MQjkrVmI0eGQraUJFbzJmQXh5VnBnMTEwWC95ajRuN052S0FEY2tPV1ZJTVZxa1BibzQ0Y3VjZ2gvOTFwVDVYV3BzQWJTbXgyR3BUZEtoQTFqN3FHbll1UnhlRExXc3lCbGQ4TGYxM2RHbXQyMVYwM3RORWNZL0diZ2crSG51MkhlUkdUZVV6cmorRjlNY1ZxRzg3ek5zZGNnMUQ5R0s1bGJnaSt3NGs3YWRVSmR6UXBtRGlGMVJ2bkhJeFM5Umx0RksxenJIVmtPVlRGa0p0ODhHS1dJT3dXVXpKaVJNNTJhLzErNlFGU3M5Skd2am5oUzN2TzJ3WVF3Q0tXdEdzZzJwOHNacFNKZzd6U0NpMzFPK1RoeUh4bHA2NVdNOTJXOEM3aXVGc2dpczhqODhkZWtza2ptVkNlejVSY0ZEdlduazZrUUljZlBEaDNqWGRnM1V3ZjNIdzRKek5zWnB4VXpzTTVzS2J6aGtXaHh2T2xkZ3A3K3ZkakRYUEdPaDVjVWoybFBkQm9aUzB5QWJ2SGhvclZwd0owV3pUdHRrQSs4ZDltczU2dzdPRzJLMG5PZXg1OGEvODg5cHdYTi95em5RUFBDbzdCby9nbDU1V3JPaklHMWxxcVVRemZ4QzZNSCs1TWdqU09NRElTd05FTVA4TlhEWmdRTmdyQVQ1ZFBCYzBqRi95N0tJRktXVVRJTmxWWnhSTUJRdlBnajhSbi9ZdkUzc3c0M1krTGpvL0pqNUxvclJacjg4M0dYY0wvanNpeGZXOHhmVjFDRjFiQXo1WExoSTAxRWY1WHJFR2dMdWxSRVZPbmpXSFU4TCt3czIxbUwwa2lXbWl6RDVWVTdQS0JiWjU2NTJWSVNZWnhQR2JvTnd0WVFpWi9tZk5oeUhQanA1MkZvdm42YVRYbmZsMUZjOFYweHZEK0t1WjhIdDFYZDIvSzNLWFFGTEVybFVjVzMvd2FQbDFITExBSXpxNXdaTjByM3N1YlNmckZzUXQ4NVRiZ1gyUGlJPQ==",
        b"secret data",
        b"cXDR6i5A7F1U9g4R"
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

        let plaintext_de = mlkem_decrypt(key, &wrapped_data, &iv).expect("decryption failed");
        assert_eq!(plaintext, plaintext_de);
    }
}
