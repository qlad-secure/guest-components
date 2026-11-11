// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::*;
use openssl::{
    encrypt::Decrypter,
    hash::MessageDigest,
    pkey::{PKey, Private},
    rsa::{Padding, Rsa},
};
use zeroize::Zeroizing;

use crate::rsa::{PaddingMode, RSA_PUBKEY_LENGTH};

#[derive(Debug, Clone)]
pub struct RSAKeyPair {
    private_key: Rsa<Private>,
}

impl RSAKeyPair {
    pub fn new() -> Result<RSAKeyPair> {
        let private_key = Rsa::generate(RSA_PUBKEY_LENGTH as u32)?;
        Ok(Self { private_key })
    }

    pub fn decrypt(&self, mode: PaddingMode, cipher_text: Vec<u8>) -> Result<Vec<u8>> {
        let mut plaintext = [0; RSA_PUBKEY_LENGTH];
        let decrypted_size = match mode {
            // TODO: Update to OAEP + Sha256 API
            // Now the OAEP decrypter provided by openssl API is an ffi binding for
            // `RSA_public_encrypt` in openssl
            // Due to <https://docs.openssl.org/master/man3/RSA_public_encrypt/#synopsis>
            // this api assumes the digest algorithm is SHA-1.
            // This is not compatible with the implementation of the KBS side who uses
            // sha256.
            //
            // Let's mark this as a TODO because we are using EC now. Even if we want
            // to use RSA OAEP, the rust version of this crate can work normally.
            PaddingMode::OAEP => self
                .private_key
                .private_decrypt(&cipher_text, &mut plaintext, Padding::PKCS1_OAEP)
                .map_err(|e| anyhow!("RSA key decrypt OAEP failed: {:?}", e))?,
            #[allow(deprecated)]
            PaddingMode::PKCS1v15 => self
                .private_key
                .private_decrypt(&cipher_text, &mut plaintext, Padding::PKCS1)
                .map_err(|e| anyhow!("RSA key pkcs1v15 decrypt failed: {:?}", e))?,
        };

        Ok(plaintext[..decrypted_size].to_vec())
    }

    /// Unwrap RSA-OAEP-256 for a caller that requires SHA-256 for OAEP and MGF1.
    pub fn decrypt_oaep256(&self, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let key = PKey::from_rsa(self.private_key.clone())?;
        let mut decrypter = Decrypter::new(&key)?;
        decrypter.set_rsa_padding(Padding::PKCS1_OAEP)?;
        decrypter.set_rsa_oaep_md(MessageDigest::sha256())?;
        decrypter.set_rsa_mgf1_md(MessageDigest::sha256())?;
        let mut plaintext = Zeroizing::new(vec![0; decrypter.decrypt_len(ciphertext)?]);
        let size = decrypter.decrypt(ciphertext, &mut plaintext)?;
        plaintext.truncate(size);
        Ok(plaintext)
    }

    pub fn n(&self) -> Vec<u8> {
        self.private_key.n().to_vec()
    }

    pub fn e(&self) -> Vec<u8> {
        self.private_key.e().to_vec()
    }

    pub fn to_pkcs1_pem(&self) -> Result<Zeroizing<String>> {
        let res = self.private_key.private_key_to_pem()?;
        let pem = String::from_utf8(res)?;
        Ok(Zeroizing::new(pem))
    }

    pub fn from_pkcs1_pem(pem: &str) -> Result<Self> {
        let private_key = Rsa::<Private>::private_key_from_pem(pem.as_bytes())?;

        Ok(Self { private_key })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::encrypt::Encrypter;

    #[test]
    fn explicit_oaep256_rejects_sha1_and_preserves_legacy_mode() {
        let pair = RSAKeyPair::new().unwrap();
        let plaintext = b"synthetic content-encryption key";
        let key = PKey::from_rsa(pair.private_key.clone()).unwrap();
        let mut encrypter = Encrypter::new(&key).unwrap();
        encrypter.set_rsa_padding(Padding::PKCS1_OAEP).unwrap();
        encrypter.set_rsa_oaep_md(MessageDigest::sha256()).unwrap();
        encrypter.set_rsa_mgf1_md(MessageDigest::sha256()).unwrap();
        let mut sha256 = vec![0; encrypter.encrypt_len(plaintext).unwrap()];
        let size = encrypter.encrypt(plaintext, &mut sha256).unwrap();
        sha256.truncate(size);
        assert_eq!(&*pair.decrypt_oaep256(&sha256).unwrap(), plaintext);

        let mut sha1 = vec![0; pair.private_key.size() as usize];
        let size = pair
            .private_key
            .public_encrypt(plaintext, &mut sha1, Padding::PKCS1_OAEP)
            .unwrap();
        sha1.truncate(size);
        assert!(pair.decrypt_oaep256(&sha1).is_err());
        assert_eq!(pair.decrypt(PaddingMode::OAEP, sha1).unwrap(), plaintext);
        assert!(pair.decrypt(PaddingMode::OAEP, sha256).is_err());
    }
}
