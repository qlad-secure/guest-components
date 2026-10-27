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

            // the cloud KMS key id travels percent-escaped in the kid path:
            // kbs:///default/key/<escaped key id>
            let key_id = kms_direct_key_id(&self.kid)?;

            // the decryptor needs settings the encryptor would normally export;
            // for KMS-DIRECT the kid carries everything (AWS region is in the ARN)
            let provider_settings = kms_direct_provider_settings(&provider, &key_id)?;

            let mut kms_client = kms::new_decryptor(&provider, provider_settings)
                .await
                .map_err(|e| Error::KmsError {
                    context: "create KMS decrypter",
                    source: e,
                })?;

            // KMS-DIRECT wraps are asymmetric RSA OAEP SHA-256 (see panoplia's
            // kms_direct); AWS KMS Decrypt needs the algorithm stated explicitly
            let mut annotations = Annotations::default();
            if provider == "aws" {
                annotations.insert(
                    "encryption_algorithm".to_string(),
                    "RSAES_OAEP_SHA_256".into(),
                );
            }

            // KMS decrypts the ciphertext directly to the layer key options
            return kms_client
                .decrypt(&kms_ciphertext, &key_id, &annotations)
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

/// Extract the raw cloud KMS key id from a KMS-DIRECT kid resource URI
/// (`kbs:///default/key/<percent-escaped key id>`).
#[cfg(feature = "kms_unwrap")]
fn kms_direct_key_id(kid: &ResourceUri) -> Result<String> {
    use percent_encoding::percent_decode_str;

    let path = kid.resource_path();
    let escaped = path
        .strip_prefix("default/key/")
        .ok_or_else(|| Error::DecryptFailed {
            source: anyhow::anyhow!("kid {path} is not a KMS-DIRECT key resource"),
        })?;

    percent_decode_str(escaped)
        .decode_utf8()
        .map(|s| s.into_owned())
        .map_err(|e| Error::DecryptFailed {
            source: anyhow::anyhow!("kid key id is not valid utf-8: {e:?}"),
        })
}

/// Build the provider settings for a KMS-DIRECT unwrap. AWS requires the
/// region at client construction; it is part of the key ARN
/// (`arn:aws:kms:<region>:<account>:key/<id>`). Other providers take all
/// parameters from the key id itself and need no settings.
#[cfg(feature = "kms_unwrap")]
fn kms_direct_provider_settings(provider: &str, key_id: &str) -> Result<kms::ProviderSettings> {
    let mut settings = kms::ProviderSettings::default();

    if provider == "aws" {
        let region = key_id
            .strip_prefix("arn:aws:kms:")
            .and_then(|rest| rest.split(':').next())
            .filter(|r| !r.is_empty())
            .ok_or_else(|| Error::DecryptFailed {
                source: anyhow::anyhow!(
                    "AWS KMS-DIRECT key id {key_id} is not an ARN with a region"
                ),
            })?;
        settings.insert("region".to_string(), region.into());
    }

    Ok(settings)
}

#[cfg(test)]
mod tests {
    use super::{kms_direct_key_id, kms_direct_provider_settings};
    use resource_uri::ResourceUri;

    #[test]
    fn extract_arn_key_id() {
        let kid = ResourceUri::try_from(
            "kbs:///default/key/arn%3Aaws%3Akms%3Aus-east-1%3A123456789012%3Akey%2Fabc",
        )
        .unwrap();
        assert_eq!(
            kms_direct_key_id(&kid).unwrap(),
            "arn:aws:kms:us-east-1:123456789012:key/abc"
        );
    }

    #[test]
    fn extract_gcp_key_id() {
        let kid = ResourceUri::try_from(
            "kbs:///default/key/projects%2Fp%2Flocations%2Fl%2FkeyRings%2Fr%2FcryptoKeys%2Fk%2FcryptoKeyVersions%2F1",
        )
        .unwrap();
        assert_eq!(
            kms_direct_key_id(&kid).unwrap(),
            "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1"
        );
    }

    #[test]
    fn reject_non_key_resource() {
        let kid = ResourceUri::try_from("kbs:///default/workload/key").unwrap();
        assert!(kms_direct_key_id(&kid).is_err());
    }

    #[test]
    fn aws_region_from_arn() {
        let settings =
            kms_direct_provider_settings("aws", "arn:aws:kms:us-east-1:123456789012:key/abc")
                .unwrap();
        assert_eq!(
            settings.get("region").and_then(|v| v.as_str()),
            Some("us-east-1")
        );
    }

    #[test]
    fn aws_region_rejects_non_arn() {
        assert!(kms_direct_provider_settings("aws", "abc").is_err());
        assert!(kms_direct_provider_settings("aws", "arn:aws:kms::123456789012:key/abc").is_err());
    }

    #[test]
    fn other_providers_need_no_settings() {
        let settings = kms_direct_provider_settings("azure", "https://vault/keys/k/v").unwrap();
        assert!(settings.is_empty());
    }
}
