// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::{KbcCheckInfo, KbcInterface};
use crypto::{decrypt, parse_kms_ciphertext, WrapType};
use kbs_protocol::{
    KbsClientBuilder, KbsClientCapabilities,
    client::KbsClient,
    evidence_provider::{EvidenceProvider, NativeEvidenceProvider},
};
use tracing::debug;

use super::AnnotationPacket;
use anyhow::*;
use async_trait::async_trait;
use base64::Engine;
use resource_uri::ResourceUri;
use zeroize::Zeroizing;

pub struct Kbc {
    kbs_client: KbsClient<Box<dyn EvidenceProvider>>,
}

#[async_trait]
impl KbcInterface for Kbc {
    async fn decrypt_payload(&mut self, ap: AnnotationPacket) -> Result<Vec<u8>> {
        let mut wrap_type = WrapType::try_from(&ap.wrap_type[..])?;

        debug!("fetching key from KBS");
        let (key_data, annotation_packet) = match wrap_type {
            #[cfg(feature = "kms_unwrap")]
            WrapType::KmsAes256Gcm => {
                debug!("KMS wrap type detected, calling kbs to unwrap key");

                let (provider, wrapped_data, kms_ciphertext) = parse_kms_ciphertext(
                    &base64::engine::general_purpose::STANDARD.decode(ap.wrapped_data)?,
                )?;

                let key_data = self
                    .kbs_client
                    .decrypt_with_kms(ap.kid.clone(), kms_ciphertext, &provider)
                    .await
                    .context("Failed to decrypt key with KMS via KBS")?;

                wrap_type = WrapType::Aes256Gcm;

                (
                    key_data,
                    AnnotationPacket {
                        kid: ap.kid,
                        wrapped_data: base64::engine::general_purpose::STANDARD
                            .encode(wrapped_data),
                        iv: ap.iv.clone(),
                        wrap_type: WrapType::Aes256Gcm.as_ref().to_string(),
                    },
                )
            }
            _ => {
                let key_data = self.kbs_client.get_resource(ap.kid.clone()).await?;
                (key_data, ap)
            }
        };
        debug!("key data fetched from KBS");

        let key = Zeroizing::new(key_data);

        debug!("trying to parse wrap type");
        debug!("parsed wrap type: {:?}", wrap_type);
        decrypt(
            key,
            base64::engine::general_purpose::STANDARD.decode(annotation_packet.wrapped_data)?,
            base64::engine::general_purpose::STANDARD.decode(annotation_packet.iv)?,
            wrap_type,
        )
    }

    async fn get_resource(&mut self, resource_uri: ResourceUri) -> Result<Vec<u8>> {
        let data = self.kbs_client.get_resource(resource_uri).await?;

        Ok(data)
    }
}

impl Kbc {
    pub fn new(kbs_uri: String) -> Result<Kbc> {
        let kbs_client = KbsClientBuilder::with_evidence_provider(
            Box::new(NativeEvidenceProvider::new()?),
            &kbs_uri,
        )
        .build()?;
        Ok(Kbc { kbs_client })
    }
}
