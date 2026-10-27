// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::{KbcCheckInfo, KbcInterface};
use crypto::{WrapType, decrypt};
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
        let wrap_type = WrapType::try_from(&ap.wrap_type[..])?;

        debug!("fetching key from KBS");

        let key_data = self.kbs_client.get_resource(ap.kid.clone()).await?;
        debug!("key data fetched from KBS");

        let key = Zeroizing::new(key_data);

        debug!("trying to parse wrap type");
        debug!("parsed wrap type: {:?}", wrap_type);
        decrypt(
            key,
            base64::engine::general_purpose::STANDARD.decode(ap.wrapped_data)?,
            base64::engine::general_purpose::STANDARD.decode(ap.iv)?,
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
