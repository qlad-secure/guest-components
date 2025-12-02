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
    // Initialisation vector (base64-encoded)
    pub iv: String,
    // Wrap type to specify encryption algorithm and mode
    pub wrap_type: String,
}

impl AnnotationPacket {
    pub(crate) async fn unwrap_key(&self) -> Result<Vec<u8>> {
        use base64::{engine::general_purpose::STANDARD, Engine};
        use crypto::{parse_encapsulated_ss, WrapType};
        use kms::{plugins::VaultProvider, Annotations, ProviderSettings};

        let mut wrap_type = WrapType::try_from(&self.wrap_type[..])
            .map_err(|_| Error::UnknownWrapType(self.wrap_type.to_string()))?;
        let kbs_client = kms::new_getter(VaultProvider::Kbs.as_ref(), ProviderSettings::default())
            .await
            .map_err(|e| Error::KmsError {
                context: "create KBC failed",
                source: e,
            })?;
        let name = self.kid.whole_uri();

        let (kek, wrapped_data, iv) = match wrap_type {
            #[cfg(feature = "mlkem_mlkem")]
            WrapType::Mlkem768Aes256Gcm => {
                let mlkem_client =
                    kms::new_decapsulator(VaultProvider::Kbs.as_ref(), ProviderSettings::default())
                        .await
                        .map_err(|e| Error::KmsError {
                            context: "create KBC failed",
                            source: e,
                        })?;

                let (parsed_wrapped_data, encapsulated_ss) =
                    parse_encapsulated_ss(&STANDARD.decode(&self.wrapped_data).map_err(|e| {
                        Error::Base64DecodeFailed {
                            context: "decode `wrapped_data` for ML-KEM",
                            source: e,
                        }
                    })?)
                    .map_err(|e| Error::DecryptFailed { source: e })?;

                let kek = mlkem_client
                    .decapsulate_key(&name, encapsulated_ss)
                    .await
                    .map_err(|e| Error::KmsError {
                        context: "ML-KEM decapsulation failed",
                        source: e,
                    })?;

                wrap_type = WrapType::Aes256Gcm;

                (kek, STANDARD.encode(parsed_wrapped_data), self.iv.clone())
            }
            _ => {
                let kek = kbs_client
                    .get_secret(&name, &Annotations::default())
                    .await
                    .map_err(|e| Error::KmsError {
                        context: "get KEK failed",
                        source: e,
                    })?;

                (kek, self.wrapped_data.clone(), self.iv.clone())
            }
        };

        let lek = crypto::decrypt(
            kek.into(),
            STANDARD
                .decode(&wrapped_data)
                .map_err(|e| Error::Base64DecodeFailed {
                    context: "decode `wrapped_data`",
                    source: e,
                })?,
            STANDARD
                .decode(&iv)
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
