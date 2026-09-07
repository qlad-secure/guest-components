// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use resource_uri::ResourceUri;
use serde::{Deserialize, Serialize};

use crate::image::{Error, Result};

/// `AnnotationPacket` is what a encrypted image layer's
/// `org.opencontainers.image.enc.keys.provider.attestation-agent`
/// annotation should contain when it is encrypted by CoCo's
/// encryption modules. Please refer to issue
/// <https://github.com/confidential-containers/attestation-agent/issues/113>
#[derive(Serialize, Deserialize, Eq, PartialEq, Debug, Clone)]
pub struct AnnotationPacket {
    // Key ID to manage multiple keys
    pub kid: ResourceUri,
    // Encrypted key to unwrap (base64-encoded)
    pub wrapped_data: String,
    // Initialisation vector (base64-encoded). Empty for KMS wrap type.
    #[serde(default)]
    pub iv: String,
    // Wrap type to specify encryption algorithm and mode
    pub wrap_type: String,
}

impl AnnotationPacket {
    pub(crate) async fn unwrap_key(&self) -> Result<Vec<u8>> {
        use base64::{engine::general_purpose::STANDARD, Engine};
        #[cfg(feature = "kms_unwrap")]
        use crypto::parse_kms_ciphertext;
        use crypto::WrapType;
        use kms::{plugins::VaultProvider, Annotations, ProviderSettings};

        let wrap_type = WrapType::try_from(&self.wrap_type[..])
            .map_err(|_| Error::UnknownWrapType(self.wrap_type.to_string()))?;
        let name = self.kid.whole_uri();

        #[cfg(feature = "kms_unwrap")]
        if wrap_type == WrapType::KmsDirect {
            let (provider, kms_ciphertext) =
                parse_kms_ciphertext(&STANDARD.decode(&self.wrapped_data).map_err(|e| {
                    Error::Base64DecodeFailed {
                        context: "decode `wrapped_data` for KMS unwrap",
                        source: e,
                    }
                })?)
                .map_err(|e| Error::DecryptFailed { source: e })?;

            let mut annotations = Annotations::default();
            annotations.insert("provider".to_string(), serde_json::Value::String(provider));

            let kms_client =
                kms::new_kms_decrypter(VaultProvider::Kbs.as_ref(), ProviderSettings::default())
                    .await
                    .map_err(|e| Error::KmsError {
                        context: "create KBC failed",
                        source: e,
                    })?;

            // KMS decrypts the ciphertext directly to the layer key options
            return kms_client
                .decrypt(&name, kms_ciphertext, &annotations)
                .await
                .map_err(|e| Error::KmsError {
                    context: "KMS decryption failed",
                    source: e,
                });
        }

        let kbs_client = kms::new_getter(VaultProvider::Kbs.as_ref(), ProviderSettings::default())
            .await
            .map_err(|e| Error::KmsError {
                context: "create KBC failed",
                source: e,
            })?;

        let kek = kbs_client
            .get_secret(&name, &Annotations::default())
            .await
            .map_err(|e| Error::KmsError {
                context: "get KEK failed",
                source: e,
            })?;

        let lek = crypto::decrypt(
            kek.into(),
            STANDARD
                .decode(&self.wrapped_data)
                .map_err(|e| Error::Base64DecodeFailed {
                    context: "decode `wrapped_data`",
                    source: e,
                })?,
            STANDARD
                .decode(&self.iv)
                .map_err(|e| Error::Base64DecodeFailed {
                    context: "decode `iv`",
                    source: e,
                })?,
            wrap_type,
        )
        .map_err(|e| Error::DecryptFailed { source: e })?;

        Ok(lek)
    }
}
