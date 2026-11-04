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
    /// Parse an explicit, bounded service-account credential without reading
    /// files or environment variables. No OAuth or Cloud KMS request occurs.
    /// This strict profile pins the standard Google token endpoint and the
    /// operator-selected project/principal. Private PEM validation is deferred
    /// to the actual SDK when `decrypt` is invoked, as in the legacy provider.
    #[cfg(feature = "launch-credential")]
    pub fn from_credential_bytes(
        bytes: &[u8],
        expected_project: &str,
        expected_email: &str,
    ) -> Result<Self> {
        const MAX_MEMORY_CREDENTIAL_BYTES: usize = 64 * 1024;
        let rejected = || Error::GcpKmsError("explicit memory credential rejected".into());
        if bytes.is_empty()
            || bytes.len() > MAX_MEMORY_CREDENTIAL_BYTES
            || expected_project.is_empty()
            || expected_email.is_empty()
        {
            return Err(rejected());
        }
        let contents = std::str::from_utf8(bytes).map_err(|_| rejected())?;
        let service_account_key = parse_credential(contents).map_err(|_| rejected())?;
        if service_account_key
            .get("project_id")
            .and_then(serde_json::Value::as_str)
            != Some(expected_project)
            || service_account_key
                .get("client_email")
                .and_then(serde_json::Value::as_str)
                != Some(expected_email)
            || service_account_key
                .get("token_uri")
                .and_then(serde_json::Value::as_str)
                != Some("https://oauth2.googleapis.com/token")
            || service_account_key
                .get("universe_domain")
                .is_some_and(|value| value.as_str() != Some("googleapis.com"))
        {
            return Err(rejected());
        }
        Ok(Self {
            service_account_key,
        })
    }

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

#[cfg(all(test, feature = "launch-credential"))]
mod memory_credential_tests {
    use super::*;
    use serde_json::json;

    fn credential() -> serde_json::Value {
        json!({"type":"service_account","project_id":"project-1",
            "client_email":"svc@project-1.iam.gserviceaccount.com",
            "private_key":"software-fixture-only-not-a-valid-private-key",
            "token_uri":"https://oauth2.googleapis.com/token"})
    }

    #[test]
    fn explicit_memory_constructor_parses_without_files_or_sdk_calls() {
        let bytes = serde_json::to_vec(&credential()).unwrap();
        // Constructor success means structure/scope checks, not valid private
        // PEM, authenticated Google identity, or a completed Cloud KMS call.
        let client = GcpKmsClient::from_credential_bytes(
            &bytes,
            "project-1",
            "svc@project-1.iam.gserviceaccount.com",
        )
        .unwrap();
        assert!(client.export_provider_settings().unwrap().is_empty());
    }

    #[test]
    fn memory_profile_rejects_other_principals_endpoints_and_invalid_payloads() {
        for field in [
            "type",
            "project_id",
            "client_email",
            "token_uri",
            "universe_domain",
            "private_key",
        ] {
            let mut value = credential();
            value[field] = serde_json::Value::String(
                match field {
                    "type" => "authorized_user",
                    "project_id" => "other-project",
                    "client_email" => "other@example.com",
                    "token_uri" => "https://attacker.invalid/token",
                    "universe_domain" => "attacker.invalid",
                    _ => "",
                }
                .into(),
            );
            let result = GcpKmsClient::from_credential_bytes(
                &serde_json::to_vec(&value).unwrap(),
                "project-1",
                "svc@project-1.iam.gserviceaccount.com",
            );
            assert!(matches!(result, Err(Error::GcpKmsError(_))));
            assert_eq!(
                result.err().unwrap().to_string(),
                "Google Cloud KMS error: explicit memory credential rejected"
            );
        }
        for bytes in [b"not json".as_slice(), b"[]", b"", &[0xff]] {
            assert!(
                GcpKmsClient::from_credential_bytes(
                    bytes,
                    "project-1",
                    "svc@project-1.iam.gserviceaccount.com"
                )
                .is_err()
            );
        }
        assert!(
            GcpKmsClient::from_credential_bytes(
                &vec![b' '; 64 * 1024 + 1],
                "project-1",
                "svc@project-1.iam.gserviceaccount.com"
            )
            .is_err()
        );
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
