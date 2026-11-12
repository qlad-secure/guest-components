//! Fixed GCP-v2 SDK policy. No endpoint, retry or timeout is caller selected.
use super::GcpKmsClient;
use crate::{Error, Result};
use google_cloud_auth::credentials::service_account;
use google_cloud_gax::{options::RequestOptionsBuilder, retry_policy::NeverRetry};
use google_cloud_kms_v1::client::KeyManagementService;
use std::{future::Future, time::Duration};

const DEADLINE: Duration = Duration::from_secs(30);

impl GcpKmsClient {
    /// One owned SDK future, with no GAX retry. The deadline includes credential
    /// construction, client construction, authentication and request completion.
    /// Cancellation cannot establish the remote outcome.
    pub async fn decrypt_gcp_attempt_once(
        &mut self,
        ciphertext: &[u8],
        key: &str,
    ) -> Result<Vec<u8>> {
        bounded(async {
            let credentials = service_account::Builder::new(self.service_account_key.clone())
                .build()
                .map_err(|_| rejected())?;
            let client = KeyManagementService::builder()
                .with_credentials(credentials)
                .build()
                .await
                .map_err(|_| rejected())?;
            send_once(&client, ciphertext, key).await
        })
        .await
    }
}

fn rejected() -> Error {
    Error::GcpKmsError("bounded GCP-v2 SDK operation rejected".into())
}
async fn bounded(future: impl Future<Output = Result<Vec<u8>>>) -> Result<Vec<u8>> {
    tokio::time::timeout(DEADLINE, future)
        .await
        .map_err(|_| rejected())?
}
async fn send_once(client: &KeyManagementService, ciphertext: &[u8], key: &str) -> Result<Vec<u8>> {
    let response = client
        .asymmetric_decrypt()
        .set_name(key)
        .set_ciphertext(ciphertext.to_vec())
        .with_idempotency(false)
        .with_attempt_timeout(DEADLINE)
        .with_retry_policy(NeverRetry)
        .send()
        .await
        .map_err(|_| rejected())?;
    Ok(response.plaintext.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use google_cloud_gax::retry_policy::{AlwaysRetry, RetryPolicyExt};
    use std::sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        sync::oneshot,
    };

    #[tokio::test]
    async fn actual_sdk_request_overrides_retrying_client_and_sends_one_503_request() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let requests = Arc::new(AtomicUsize::new(0));
        let count = requests.clone();
        let (stop, mut stopped) = oneshot::channel();
        let server = tokio::spawn(async move {
            loop {
                let (mut socket, _) = tokio::select! {_=&mut stopped=>break,accepted=listener.accept()=>accepted.unwrap()};
                let mut input = Vec::new();
                let mut block = [0; 2048];
                loop {
                    let n = tokio::time::timeout(Duration::from_secs(2), socket.read(&mut block))
                        .await
                        .unwrap()
                        .unwrap();
                    if n == 0 {
                        break;
                    }
                    input.extend_from_slice(&block[..n]);
                    assert!(input.len() <= 8192);
                    if input.windows(4).any(|b| b == b"\r\n\r\n") {
                        break;
                    }
                }
                assert!(input.starts_with(b"POST /v1/projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1:asymmetricDecrypt"));
                count.fetch_add(1, Ordering::SeqCst);
                let body=br#"{"error":{"code":503,"status":"UNAVAILABLE","message":"local transport fixture"}}"#;
                let headers = format!(
                    "HTTP/1.1 503 Service Unavailable\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                socket.write_all(headers.as_bytes()).await.unwrap();
                socket.write_all(body).await.unwrap();
            }
        });
        // Only cfg(test) supplies an anonymous credential and local endpoint.
        // A deliberately retrying client proves the request-level override wins.
        let client = KeyManagementService::builder()
            .with_credentials(google_cloud_auth::credentials::anonymous::Builder::new().build())
            .with_endpoint(format!("http://{address}"))
            .with_retry_policy(AlwaysRetry.with_attempt_limit(3))
            .build()
            .await
            .unwrap();
        let result = bounded(send_once(
            &client,
            b"public-fixture",
            "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1",
        ))
        .await;
        let _ = stop.send(());
        server.await.unwrap();
        assert!(result.is_err());
        assert_eq!(requests.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn total_deadline_drops_the_owned_auth_build_or_send_future() {
        struct Held(Arc<AtomicBool>);
        impl Drop for Held {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        let dropped = Arc::new(AtomicBool::new(false));
        let held = Held(dropped.clone());
        let task = tokio::spawn(bounded(async move {
            let _held = held;
            std::future::pending::<Result<Vec<u8>>>().await
        }));
        tokio::task::yield_now().await;
        tokio::time::advance(DEADLINE + Duration::from_secs(1)).await;
        assert!(task.await.unwrap().is_err());
        assert!(dropped.load(Ordering::SeqCst));
    }
}
