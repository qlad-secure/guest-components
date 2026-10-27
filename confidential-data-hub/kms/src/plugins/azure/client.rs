use std::env;
use std::sync::Arc;

use async_trait::async_trait;
use azure_core::credentials::Secret;
use azure_core::http::RequestContent;
use azure_identity::ClientSecretCredential;
use azure_security_keyvault_keys::KeyClient;
use azure_security_keyvault_keys::models::{
    EncryptionAlgorithm, KeyOperationParameters, KeyOperationResult,
};
use const_format::concatcp;
use tokio::fs;
use tracing::info;
use url::Url;

use crate::{Annotations, Decrypter, ProviderSettings};
use crate::{Error, Result};

use super::credential::AzureCredential;
use crate::plugins::_IN_GUEST_DEFAULT_KEY_PATH;

const AZURE_IN_GUEST_DEFAULT_KEY_PATH: &str = concatcp!(_IN_GUEST_DEFAULT_KEY_PATH, "/azure");
const AZURE_CREDENTIAL_FILE_NAME: &str = "credential.json";

#[derive(Clone, Debug)]
pub struct AzureKeyVaultClient {
    credential: Arc<AzureCredential>,
}

impl AzureKeyVaultClient {
    pub async fn from_provider_settings(_provider_settings: &ProviderSettings) -> Result<Self> {
        let key_path = env::var("AZURE_IN_GUEST_KEY_PATH")
            .unwrap_or(AZURE_IN_GUEST_DEFAULT_KEY_PATH.to_owned());
        info!("AZURE_IN_GUEST_KEY_PATH = {key_path}");

        let credential_path = format!("{key_path}/{AZURE_CREDENTIAL_FILE_NAME}");
        let credential = fs::read_to_string(&credential_path).await.map_err(|e| {
            Error::AzureKmsError(format!(
                "read credential file {credential_path} failed: {e:?}"
            ))
        })?;
        let credential: AzureCredential = serde_json::from_str(&credential)
            .map_err(|e| Error::AzureKmsError(format!("parse credential failed: {e:?}")))?;

        Ok(Self {
            credential: Arc::new(credential),
        })
    }

    /// Export the [`ProviderSettings`] of the current client.
    pub fn export_provider_settings(&self) -> Result<ProviderSettings> {
        Ok(serde_json::Map::new())
    }
}

/// Split a full Key Vault key URL (`https://{vault}.vault.azure.net/keys/{name}/{version}`)
/// into `(vault_endpoint, key_name, key_version)`. Empty version = latest.
pub(crate) fn parse_key_url(key_url: &str) -> Result<(String, String, String)> {
    let url = Url::parse(key_url)
        .map_err(|e| Error::AzureKmsError(format!("parse key url {key_url} failed: {e:?}")))?;

    let endpoint = url
        .host_str()
        .map(|host| format!("{}://{}", url.scheme(), host))
        .ok_or_else(|| Error::AzureKmsError(format!("no host in key url {key_url}")))?;

    let segments: Vec<&str> = url.path_segments().map(|s| s.collect()).unwrap_or_default();
    if segments.len() < 2 || segments[0] != "keys" || segments[1].is_empty() {
        return Err(Error::AzureKmsError(format!(
            "key url {key_url} is not in the form .../keys/<name>[/<version>]"
        )));
    }

    let name = segments[1].to_string();
    let version = segments.get(2).map(|s| s.to_string()).unwrap_or_default();
    Ok((endpoint, name, version))
}

#[async_trait]
impl Decrypter for AzureKeyVaultClient {
    async fn decrypt(
        &mut self,
        ciphertext: &[u8],
        key_id: &str,
        _crypto_context: &Annotations,
    ) -> Result<Vec<u8>> {
        let (endpoint, name, version) = parse_key_url(key_id)?;
        // Key Vault decrypt requires a key version; encrypt-side "latest" is
        // not resolvable here.
        if version.is_empty() {
            return Err(Error::AzureKmsError(format!(
                "key url {key_id} has no key version; a versioned url is required"
            )));
        }

        let credential = ClientSecretCredential::new(
            &self.credential.tenant_id,
            self.credential.client_id.clone(),
            Secret::from(self.credential.client_secret.clone()),
            None,
        )
        .map_err(|e| Error::AzureKmsError(format!("create credential failed: {e:?}")))?;

        let client = KeyClient::new(endpoint.as_str(), credential, None)
            .map_err(|e| Error::AzureKmsError(format!("create keyvault client failed: {e:?}")))?;

        let parameters = KeyOperationParameters {
            value: Some(ciphertext.to_vec()),
            algorithm: Some(EncryptionAlgorithm::RsaOaep256),
            ..Default::default()
        };
        let parameters = serde_json::to_string(&parameters)
            .map_err(|e| Error::AzureKmsError(format!("serialize decrypt parameters: {e:?}")))?;

        let body = client
            .decrypt(&name, &version, RequestContent::from_str(&parameters), None)
            .await
            .map_err(|e| Error::AzureKmsError(format!("Azure Key Vault decrypt failed: {e:?}")))?
            .into_body();

        let result: KeyOperationResult = body
            .json()
            .map_err(|e| Error::AzureKmsError(format!("decode decrypt response failed: {e:?}")))?;

        result.result.ok_or_else(|| {
            Error::AzureKmsError("Azure Key Vault decrypt returned no result".into())
        })
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::parse_key_url;

    #[rstest]
    #[case(
        "https://myvault.vault.azure.net/keys/mykey/abc123",
        "https://myvault.vault.azure.net",
        "mykey",
        "abc123"
    )]
    #[case(
        "https://myvault.vault.azure.net/keys/mykey",
        "https://myvault.vault.azure.net",
        "mykey",
        ""
    )]
    fn parse_valid_key_urls(
        #[case] url: &str,
        #[case] endpoint: &str,
        #[case] name: &str,
        #[case] version: &str,
    ) {
        let (got_endpoint, got_name, got_version) = parse_key_url(url).unwrap();
        assert_eq!(got_endpoint, endpoint);
        assert_eq!(got_name, name);
        assert_eq!(got_version, version);
    }

    #[rstest]
    #[case("https://myvault.vault.azure.net/secrets/mykey/abc123")]
    #[case("https://myvault.vault.azure.net/")]
    #[case("not-a-url")]
    fn reject_invalid_key_urls(#[case] url: &str) {
        assert!(parse_key_url(url).is_err());
    }
}
