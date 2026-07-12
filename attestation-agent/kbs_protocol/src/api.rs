// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::Result;
use async_trait::async_trait;
pub use resource_uri::ResourceUri;

#[async_trait]
pub trait KbsClientCapabilities {
    async fn get_resource(&mut self, resource_uri: ResourceUri) -> Result<Vec<u8>>;
    #[cfg(feature = "kms_unwrap")]
    /// Ask KBS to decrypt a cloud-KMS-encrypted key on behalf of the TEE.
    ///
    /// `provider` selects the cloud KMS backend (e.g. "aws", "azure", "gcp").
    /// The plaintext response is JWE-encrypted with the TEE public key and
    /// decrypted locally before being returned.
    async fn decrypt_with_kms(
        &mut self,
        resource_uri: ResourceUri,
        ciphertext: Vec<u8>,
        provider: &str,
    ) -> Result<Vec<u8>>;
}
