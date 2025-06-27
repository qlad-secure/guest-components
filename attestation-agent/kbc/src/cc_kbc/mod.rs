// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::{KbcCheckInfo, KbcInterface};
use crypto::{decrypt, parse_encapsulated_ss, WrapType};
use kbs_protocol::{
    client::KbsClient,
    evidence_provider::{EvidenceProvider, NativeEvidenceProvider},
    KbsClientBuilder, KbsClientCapabilities,
};
use log::debug;

use super::AnnotationPacket;
use anyhow::*;
use async_trait::async_trait;
use base64::Engine;
use resource_uri::ResourceUri;
use zeroize::Zeroizing;

pub struct Kbc {
    token: Option<String>,
    kbs_client: KbsClient<Box<dyn EvidenceProvider>>,
}

#[async_trait]
impl KbcInterface for Kbc {
    fn check(&self) -> Result<KbcCheckInfo> {
        Err(anyhow!("Check API of this KBC is unimplemented."))
    }

    async fn decrypt_payload(&mut self, ap: AnnotationPacket) -> Result<Vec<u8>> {
        let wrap_type = WrapType::try_from(&ap.wrap_type[..])?;

        debug!("fetching key from KBS");
        let (key_data, annotation_packet) = match wrap_type {
            #[cfg(feature = "mlkem")]
            WrapType::Mlkem768Aes256Gcm => {
                debug!("ML-KEM wrap type detected, calling kbs to unwrap key");

                let (wrapped_data, encapsulated_ss) = parse_encapsulated_ss(&ap.wrapped_data)?;

                (
                    self.kbs_client
                        .decapsulate_key(ap.kid, encapsulated_ss)
                        .await,
                    AnnotationPacket {
                        kid: ap.kid.clone(),
                        wrapped_data: wrapped_data.as_str().to_string(),
                        iv: ap.iv.clone(),
                        wrap_type: WrapType::aes256gcm.to_string(),
                    },
                )
            }
            _ => (self.kbs_client.get_resource(ap.kid).await, ap.clone()),
        }?;
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

    async fn get_resource(&mut self, desc: ResourceUri) -> Result<Vec<u8>> {
        let data = self.kbs_client.get_resource(desc).await?;

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
        Ok(Kbc {
            token: None,
            kbs_client,
        })
    }
}
