use std::env;

use async_trait::async_trait;
use const_format::concatcp;
use google_cloud_auth::credentials::service_account;
use google_cloud_kms_v1::client::KeyManagementService;
use tokio::fs;
use tracing::info;

use super::credential::parse_credential;
use crate::plugins::_IN_GUEST_DEFAULT_KEY_PATH;
use crate::{Annotations, Decrypter, Error, ProviderSettings, Result};

const GCP_IN_GUEST_DEFAULT_KEY_PATH: &str = concatcp!(_IN_GUEST_DEFAULT_KEY_PATH, "/gcp");
const GCP_CREDENTIAL_FILE_NAME: &str = "credential.json";

#[derive(Clone, Debug)]
pub struct GcpKmsClient {
    service_account_key: serde_json::Value,
}

impl GcpKmsClient {
    pub async fn from_provider_settings(_provider_settings: &ProviderSettings) -> Result<Self> {
        let key_path =
            env::var("GCP_IN_GUEST_KEY_PATH").unwrap_or(GCP_IN_GUEST_DEFAULT_KEY_PATH.to_owned());
        info!("GCP_IN_GUEST_KEY_PATH = {key_path}");

        let credential_path = format!("{key_path}/{GCP_CREDENTIAL_FILE_NAME}");
        let contents = fs::read_to_string(&credential_path).await.map_err(|e| {
            Error::GcpKmsError(format!(
                "read credential file {credential_path} failed: {e:?}"
            ))
        })?;
        let service_account_key = parse_credential(&contents)
            .map_err(|e| Error::GcpKmsError(format!("parse credential failed: {e:?}")))?;

        Ok(Self {
            service_account_key,
        })
    }

    /// Export the [`ProviderSettings`] of the current client.
    pub fn export_provider_settings(&self) -> Result<ProviderSettings> {
        Ok(serde_json::Map::new())
    }
}

#[async_trait]
impl Decrypter for GcpKmsClient {
    async fn decrypt(
        &mut self,
        ciphertext: &[u8],
        key_id: &str,
        _crypto_context: &Annotations,
    ) -> Result<Vec<u8>> {
        let credentials = service_account::Builder::new(self.service_account_key.clone())
            .build()
            .map_err(|e| Error::GcpKmsError(format!("build credentials failed: {e:?}")))?;

        let client = KeyManagementService::builder()
            .with_credentials(credentials)
            .build()
            .await
            .map_err(|e| Error::GcpKmsError(format!("create Cloud KMS client failed: {e:?}")))?;

        let response = client
            .asymmetric_decrypt()
            .set_name(key_id)
            .set_ciphertext(ciphertext.to_vec())
            .send()
            .await
            .map_err(|e| {
                Error::GcpKmsError(format!("Cloud KMS asymmetric_decrypt failed: {e:?}"))
            })?;

        Ok(response.plaintext.to_vec())
    }
}
