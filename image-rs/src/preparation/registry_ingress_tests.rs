use super::*;
use openssl::{
    asn1::Asn1Time,
    bn::BigNum,
    hash::MessageDigest,
    pkey::{PKey, Private},
    rsa::Rsa,
    ssl::{SslAcceptor, SslMethod},
    x509::{
        extension::{BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName},
        X509NameBuilder, X509,
    },
};
use serde_json::json;
use std::{
    io::{Read, Write},
    net::TcpListener,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, OnceLock,
    },
    thread::{self, JoinHandle},
};

// Test-only CA/server keys are generated and retained solely in process memory.
// No certificate/key files, credentials or external network endpoints are used.
struct TlsMaterial {
    ca_pem: Vec<u8>,
    certificate: X509,
    key: PKey<Private>,
}

fn tls_material() -> &'static TlsMaterial {
    static MATERIAL: OnceLock<TlsMaterial> = OnceLock::new();
    MATERIAL.get_or_init(|| {
        let ca_key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "ONB17 in-memory test CA")
            .unwrap();
        let name = name.build();
        let mut ca = X509::builder().unwrap();
        ca.set_version(2).unwrap();
        ca.set_serial_number(
            BigNum::from_u32(1)
                .unwrap()
                .to_asn1_integer()
                .unwrap()
                .as_ref(),
        )
        .unwrap();
        ca.set_subject_name(&name).unwrap();
        ca.set_issuer_name(&name).unwrap();
        ca.set_pubkey(&ca_key).unwrap();
        ca.set_not_before(Asn1Time::days_from_now(0).unwrap().as_ref())
            .unwrap();
        ca.set_not_after(Asn1Time::days_from_now(1).unwrap().as_ref())
            .unwrap();
        ca.append_extension(BasicConstraints::new().critical().ca().build().unwrap())
            .unwrap();
        ca.append_extension(
            KeyUsage::new()
                .critical()
                .key_cert_sign()
                .crl_sign()
                .build()
                .unwrap(),
        )
        .unwrap();
        ca.sign(&ca_key, MessageDigest::sha256()).unwrap();
        let ca = ca.build();
        let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let mut leaf = X509::builder().unwrap();
        leaf.set_version(2).unwrap();
        leaf.set_serial_number(
            BigNum::from_u32(2)
                .unwrap()
                .to_asn1_integer()
                .unwrap()
                .as_ref(),
        )
        .unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "registry.test").unwrap();
        leaf.set_subject_name(&name.build()).unwrap();
        leaf.set_issuer_name(ca.subject_name()).unwrap();
        leaf.set_pubkey(&key).unwrap();
        leaf.set_not_before(Asn1Time::days_from_now(0).unwrap().as_ref())
            .unwrap();
        leaf.set_not_after(Asn1Time::days_from_now(1).unwrap().as_ref())
            .unwrap();
        leaf.append_extension(BasicConstraints::new().critical().build().unwrap())
            .unwrap();
        leaf.append_extension(
            KeyUsage::new()
                .critical()
                .digital_signature()
                .key_encipherment()
                .build()
                .unwrap(),
        )
        .unwrap();
        leaf.append_extension(ExtendedKeyUsage::new().server_auth().build().unwrap())
            .unwrap();
        let san = SubjectAlternativeName::new()
            .dns("registry.test")
            .build(&leaf.x509v3_context(Some(&ca), None))
            .unwrap();
        leaf.append_extension(san).unwrap();
        leaf.sign(&ca_key, MessageDigest::sha256()).unwrap();
        TlsMaterial {
            ca_pem: ca.to_pem().unwrap(),
            certificate: leaf.build(),
            key,
        }
    })
}

struct Reply {
    wire: Vec<u8>,
    pause: Option<Duration>,
}
impl Reply {
    fn ok(bytes: &[u8], mime: &str) -> Self {
        Self::raw(format!("HTTP/1.1 200 OK\r\nContent-Type: {mime}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", bytes.len()), bytes)
    }
    fn raw(header: String, body: &[u8]) -> Self {
        let mut wire = header.into_bytes();
        wire.extend_from_slice(body);
        Self { wire, pause: None }
    }
}

struct Server {
    address: SocketAddr,
    requests: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    request_seen: Arc<tokio::sync::Notify>,
    worker: Option<JoinHandle<()>>,
}
impl Server {
    fn new(replies: Vec<Reply>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let observed = requests.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = stop.clone();
        let request_seen = Arc::new(tokio::sync::Notify::new());
        let notify = request_seen.clone();
        let material = tls_material();
        let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
        acceptor.set_certificate(&material.certificate).unwrap();
        acceptor.set_private_key(&material.key).unwrap();
        let acceptor = acceptor.build();
        let worker = thread::spawn(move || {
            for reply in replies {
                let deadline = Instant::now() + Duration::from_secs(5);
                let stream = loop {
                    if stopping.load(Ordering::Relaxed) || Instant::now() >= deadline {
                        return;
                    }
                    match listener.accept() {
                        Ok((stream, _)) => break stream,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(2))
                        }
                        Err(error) => panic!("local TLS accept failed: {error}"),
                    }
                };
                stream
                    .set_read_timeout(Some(Duration::from_secs(1)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(1)))
                    .unwrap();
                let Ok(mut tls) = acceptor.accept(stream) else {
                    continue;
                };
                let mut request = Vec::new();
                let mut byte = [0u8; 1];
                while !request.ends_with(b"\r\n\r\n") && request.len() < 16384 {
                    match tls.read(&mut byte) {
                        Ok(0) | Err(_) => break,
                        Ok(_) => request.push(byte[0]),
                    }
                }
                observed
                    .lock()
                    .unwrap()
                    .push(String::from_utf8(request).unwrap());
                if let Some(pause) = reply.pause {
                    let split = reply
                        .wire
                        .windows(4)
                        .position(|bytes| bytes == b"\r\n\r\n")
                        .unwrap()
                        + 4;
                    let _ = tls.write_all(&reply.wire[..split]);
                    let _ = tls.flush();
                    notify.notify_one();
                    thread::sleep(pause);
                    let _ = tls.write_all(&reply.wire[split..]);
                } else {
                    notify.notify_one();
                    let _ = tls.write_all(&reply.wire);
                }
                let _ = tls.flush();
                let _ = tls.shutdown();
            }
        });
        Self {
            address,
            requests,
            stop,
            request_seen,
            worker: Some(worker),
        }
    }
    fn config(&self) -> TrustedRegistryConfig {
        TrustedRegistryConfig {
            origin: format!("https://registry.test:{}", self.address.port()),
            repository: format!("registry.test:{}/team/app", self.address.port()),
            addresses: vec![self.address],
            tls_ca_pem: tls_material().ca_pem.clone(),
            bearer_token: None,
        }
    }
    fn client(&self) -> TrustedRegistry {
        TrustedRegistry::new(self.config(), limits()).unwrap()
    }
    fn requests(&self) -> Vec<String> {
        self.requests.lock().unwrap().clone()
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.worker.take().unwrap().join().unwrap();
    }
}

fn limits() -> RegistryIngressLimits {
    RegistryIngressLimits {
        manifest_bytes: 8192,
        blob_bytes: 8192,
        signature_payload_bytes: 2048,
        signature_bytes: 128,
        connect_timeout: Duration::from_secs(1),
        read_timeout: Duration::from_secs(1),
        request_timeout: Duration::from_secs(2),
    }
}
fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[tokio::test]
async fn actual_tls_pinned_dns_and_explicit_roots_fetch_exact_manifest_and_blob() {
    let bytes = b"public registry fixture";
    let server = Server::new(vec![
        Reply::ok(bytes, OCI_MANIFEST),
        Reply::ok(bytes, OCTET_STREAM),
    ]);
    let registry = server.client();
    assert_eq!(registry.repository(), server.config().repository);
    assert_eq!(
        registry
            .fetch_manifest(&digest(bytes), bytes.len())
            .await
            .unwrap(),
        bytes
    );
    assert_eq!(
        registry
            .fetch_blob(&digest(bytes), bytes.len() as u64, bytes.len())
            .await
            .unwrap(),
        bytes
    );
    let requests = server.requests();
    assert_eq!(requests.len(), 2);
    assert!(requests[0].starts_with(&format!(
        "GET /v2/team/app/manifests/sha256:{} HTTP/1.1",
        digest(bytes)
    )));
    assert!(requests[1].starts_with(&format!(
        "GET /v2/team/app/blobs/sha256:{} HTTP/1.1",
        digest(bytes)
    )));
    assert!(requests.iter().all(|request| request
        .to_ascii_lowercase()
        .contains("accept-encoding: identity")));
    assert!(requests
        .iter()
        .all(|request| !request.to_ascii_lowercase().contains("authorization:")));
}

#[tokio::test]
async fn chunked_and_close_delimited_bodies_require_actual_eof_at_the_exact_cap() {
    let bytes = b"abc";
    let chunked = Reply::raw(format!("HTTP/1.1 200 OK\r\nContent-Type: {OCTET_STREAM}\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"), b"1\r\na\r\n2\r\nbc\r\n0\r\n\r\n");
    let close = Reply::raw(
        format!("HTTP/1.1 200 OK\r\nContent-Type: {OCTET_STREAM}\r\nConnection: close\r\n\r\n"),
        bytes,
    );
    let server = Server::new(vec![chunked, close]);
    let registry = server.client();
    for _ in 0..2 {
        assert_eq!(
            registry.fetch_blob(&digest(bytes), 3, 3).await.unwrap(),
            bytes
        );
    }
    // A valid first chunk at the cap must not manufacture EOF: the following
    // chunk is still part of the same HTTP body and must make the read fail.
    let server = Server::new(vec![Reply::raw(
        format!("HTTP/1.1 200 OK\r\nContent-Type: {OCTET_STREAM}\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"),
        b"3\r\nabc\r\n1\r\nd\r\n0\r\n\r\n",
    )]);
    assert!(server
        .client()
        .fetch_blob(&digest(bytes), 3, 3)
        .await
        .is_err());
}

#[tokio::test]
async fn matching_digest_and_identity_headers_are_checked_without_changing_bytes() {
    let bytes = b"abc";
    let server = Server::new(vec![Reply::raw(
        format!("HTTP/1.1 200 OK\r\nContent-Type: {OCTET_STREAM}\r\nContent-Length: 3\r\nDocker-Content-Digest: sha256:{}\r\nContent-Encoding: identity\r\nConnection: close\r\n\r\n", digest(bytes)),
        bytes,
    )]);
    assert_eq!(
        server
            .client()
            .fetch_blob(&digest(bytes), 3, 3)
            .await
            .unwrap(),
        bytes
    );
}

#[tokio::test]
async fn size_hash_truncation_and_constructor_caps_reject_actual_wire_responses() {
    for case in [
        "over-cap",
        "truncated",
        "wrong-hash",
        "length",
        "header-digest",
        "constructor-cap",
    ] {
        let reply = match case {
            "over-cap" => Reply::raw(format!("HTTP/1.1 200 OK\r\nContent-Type: {OCTET_STREAM}\r\nTransfer-Encoding: chunked\r\n\r\n"), b"4\r\nabcd\r\n0\r\n\r\n"),
            "truncated" => Reply::raw(format!("HTTP/1.1 200 OK\r\nContent-Type: {OCTET_STREAM}\r\nContent-Length: 3\r\n\r\n"), b"ab"),
            "wrong-hash" => Reply::ok(b"xyz", OCTET_STREAM),
            "length" => Reply::ok(b"abcd", OCTET_STREAM),
            "header-digest" => Reply::raw(format!("HTTP/1.1 200 OK\r\nContent-Type: {OCTET_STREAM}\r\nContent-Length: 3\r\nDocker-Content-Digest: sha256:{}\r\n\r\n", "0".repeat(64)), b"abc"),
            _ => Reply::ok(b"abc", OCTET_STREAM),
        };
        let server = Server::new(vec![reply]);
        let mut cap = limits();
        if case == "constructor-cap" {
            cap.blob_bytes = 2;
        }
        let registry = TrustedRegistry::new(server.config(), cap).unwrap();
        assert!(
            registry.fetch_blob(&digest(b"abc"), 3, 3).await.is_err(),
            "{case}"
        );
        if case == "constructor-cap" {
            assert!(server.requests().is_empty());
        }
    }
}

#[tokio::test]
async fn non_success_mime_encoding_and_duplicate_headers_fail_closed() {
    for header in [
        "HTTP/1.1 206 Partial Content\r\nContent-Type: application/octet-stream\r\n",
        "HTTP/1.1 500 Server Error\r\nContent-Type: application/octet-stream\r\n",
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n",
        "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Encoding: gzip\r\n",
        "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Encoding: identity, gzip\r\n",
        "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Type: application/octet-stream\r\n",
    ] {
        let server = Server::new(vec![Reply::raw(format!("{header}Content-Length: 3\r\nConnection: close\r\n\r\n"), b"abc")]);
        assert!(server.client().fetch_blob(&digest(b"abc"), 3, 3).await.is_err());
    }
}

#[tokio::test]
async fn redirects_and_auth_challenges_never_contact_another_endpoint_or_retry() {
    for challenge in [false, true] {
        let sentinel = TcpListener::bind("127.0.0.1:0").unwrap();
        sentinel.set_nonblocking(true).unwrap();
        let port = sentinel.local_addr().unwrap().port();
        let response = if challenge {
            format!("HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Bearer realm=\"https://127.0.0.1:{port}/token\"\r\n")
        } else {
            format!(
                "HTTP/1.1 307 Temporary Redirect\r\nLocation: https://127.0.0.1:{port}/steal\r\n"
            )
        };
        let server = Server::new(vec![Reply::raw(
            format!("{response}Content-Length: 0\r\nConnection: close\r\n\r\n"),
            b"",
        )]);
        let mut config = server.config();
        config.bearer_token = Some(Zeroizing::new("synthetic-public-token".into()));
        let registry = TrustedRegistry::new(config, limits()).unwrap();
        assert_eq!(
            registry
                .fetch_blob(&digest(b"abc"), 3, 3)
                .await
                .unwrap_err(),
            RegistryIngressError::ResponseRejected
        );
        let requests = server.requests();
        assert_eq!(requests.len(), 1);
        assert!(requests[0]
            .to_ascii_lowercase()
            .contains("authorization: bearer synthetic-public-token"));
        assert_eq!(
            sentinel.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }
}

fn signature_artifact(payload: &[u8], signature: &[u8]) -> serde_json::Value {
    json!({"schemaVersion":2,"mediaType":OCI_MANIFEST,
        "config":{"mediaType":OCI_CONFIG,"digest":format!("sha256:{}",digest(b"{}")),"size":2},
        "layers":[{"mediaType":COSIGN_PAYLOAD,"digest":format!("sha256:{}",digest(payload)),"size":payload.len(),
            "annotations":{COSIGN_SIGNATURE:STANDARD.encode(signature)}}]})
}

#[tokio::test]
async fn signature_ingress_reads_one_digest_pinned_graph_and_returns_untrusted_material() {
    let payload = b"public untrusted simple-signing payload";
    let signature = b"public synthetic DER placeholder";
    let artifact = serde_json::to_vec(&signature_artifact(payload, signature)).unwrap();
    let server = Server::new(vec![
        Reply::ok(&artifact, OCI_MANIFEST),
        Reply::ok(payload, OCTET_STREAM),
    ]);
    let result = server
        .client()
        .fetch_signature(&digest(&artifact))
        .await
        .unwrap();
    assert_eq!(result.payload, payload);
    assert_eq!(result.signature, signature);
    let requests = server.requests();
    assert_eq!(requests.len(), 2);
    assert!(requests[1].starts_with(&format!(
        "GET /v2/team/app/blobs/sha256:{} ",
        digest(payload)
    )));
}

#[tokio::test]
async fn malformed_or_expanding_signature_graph_is_rejected_before_payload_fetch() {
    for case in [
        "multiple-layers",
        "url",
        "annotation",
        "base64",
        "signature-cap",
        "payload-cap",
        "media",
        "config-digest",
        "unknown",
    ] {
        let mut artifact = signature_artifact(b"payload", b"sig");
        match case {
            "multiple-layers" => {
                let layer = artifact["layers"][0].clone();
                artifact["layers"].as_array_mut().unwrap().push(layer);
            }
            "url" => artifact["layers"][0]["urls"] = json!(["https://127.0.0.1/private"]),
            "annotation" => artifact["layers"][0]["annotations"]["extra"] = json!("value"),
            "base64" => {
                artifact["layers"][0]["annotations"][COSIGN_SIGNATURE] = json!("not canonical===")
            }
            "signature-cap" => {
                artifact["layers"][0]["annotations"][COSIGN_SIGNATURE] =
                    json!(STANDARD.encode([1; 129]))
            }
            "payload-cap" => artifact["layers"][0]["size"] = json!(2049),
            "media" => artifact["layers"][0]["mediaType"] = json!("application/gzip"),
            "config-digest" => artifact["config"]["digest"] = json!("sha256:not-a-digest"),
            _ => artifact["unexpected"] = json!(true),
        }
        let bytes = serde_json::to_vec(&artifact).unwrap();
        let server = Server::new(vec![Reply::ok(&bytes, OCI_MANIFEST)]);
        assert!(
            server
                .client()
                .fetch_signature(&digest(&bytes))
                .await
                .is_err(),
            "{case}"
        );
        assert_eq!(server.requests().len(), 1, "{case}");
    }
}

#[tokio::test]
async fn total_request_deadline_and_dropped_fetch_release_the_response() {
    for cancel in [false, true] {
        let mut reply = Reply::ok(b"abc", OCTET_STREAM);
        reply.pause = Some(Duration::from_millis(400));
        let server = Server::new(vec![reply]);
        let mut cap = limits();
        if !cancel {
            cap.request_timeout = Duration::from_millis(150);
        }
        let registry = TrustedRegistry::new(server.config(), cap).unwrap();
        let hash = digest(b"abc");
        let fetch = registry.fetch_blob(&hash, 3, 3);
        if cancel {
            let mut fetch = Box::pin(fetch);
            tokio::select! {
                outcome = &mut fetch => panic!("fetch completed before controlled body cancellation: {outcome:?}"),
                _ = server.request_seen.notified() => (),
            }
            drop(fetch);
        } else {
            assert_eq!(fetch.await.unwrap_err(), RegistryIngressError::Transport);
        }
        assert_eq!(server.requests().len(), 1);
    }
}

#[tokio::test]
async fn wrong_ca_hostname_or_pinned_socket_never_gets_an_http_request() {
    for case in ["ca", "hostname", "socket"] {
        let server = Server::new(vec![Reply::ok(b"abc", OCTET_STREAM)]);
        let mut config = server.config();
        match case {
            "ca" => {
                // A distinct valid CA, not an invalid-PEM constructor test.
                let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
                let mut cert = X509::builder().unwrap();
                cert.set_version(2).unwrap();
                cert.set_serial_number(
                    BigNum::from_u32(99)
                        .unwrap()
                        .to_asn1_integer()
                        .unwrap()
                        .as_ref(),
                )
                .unwrap();
                cert.set_subject_name(tls_material().certificate.subject_name())
                    .unwrap();
                cert.set_issuer_name(tls_material().certificate.subject_name())
                    .unwrap();
                cert.set_pubkey(&key).unwrap();
                cert.set_not_before(Asn1Time::days_from_now(0).unwrap().as_ref())
                    .unwrap();
                cert.set_not_after(Asn1Time::days_from_now(1).unwrap().as_ref())
                    .unwrap();
                cert.append_extension(BasicConstraints::new().critical().ca().build().unwrap())
                    .unwrap();
                cert.sign(&key, MessageDigest::sha256()).unwrap();
                config.tls_ca_pem = cert.build().to_pem().unwrap();
            }
            "hostname" => {
                config.origin = config.origin.replace("registry.test", "other.test");
                config.repository = config.repository.replace("registry.test", "other.test");
            }
            _ => {
                config.addresses[0].set_ip("127.0.0.2".parse().unwrap());
            }
        }
        let registry = TrustedRegistry::new(config, limits()).unwrap();
        assert!(
            registry.fetch_blob(&digest(b"abc"), 3, 3).await.is_err(),
            "{case}"
        );
        assert!(server.requests().is_empty(), "{case}");
    }
}

#[test]
fn constructor_rejects_untrusted_endpoint_shapes_and_invalid_budgets_without_network() {
    let server = Server::new(Vec::new());
    for case in [
        "http",
        "path",
        "query",
        "userinfo",
        "fragment",
        "repository",
        "addresses",
        "address-port",
        "ca",
        "token",
    ] {
        let mut config = server.config();
        match case {
            "http" => config.origin = config.origin.replace("https://", "http://"),
            "path" => config.origin.push_str("/v2"),
            "query" => config.origin.push_str("?x=1"),
            "userinfo" => config.origin = config.origin.replace("https://", "https://u:p@"),
            "fragment" => config.origin.push_str("#part"),
            "repository" => config.repository = "other.test/team/app".into(),
            "addresses" => config.addresses.clear(),
            "address-port" => config.addresses[0].set_port(1),
            "ca" => config.tls_ca_pem = b"not a certificate".to_vec(),
            _ => config.bearer_token = Some(Zeroizing::new("bad\r\nheader".into())),
        }
        assert!(TrustedRegistry::new(config, limits()).is_err(), "{case}");
    }
    for value in [0, usize::MAX] {
        for field in 0..4 {
            let mut cap = limits();
            match field {
                0 => cap.manifest_bytes = value,
                1 => cap.blob_bytes = value,
                2 => cap.signature_payload_bytes = value,
                _ => cap.signature_bytes = value,
            };
            assert!(TrustedRegistry::new(server.config(), cap).is_err());
        }
    }
    for duration in [Duration::ZERO, Duration::MAX] {
        for field in 0..3 {
            let mut cap = limits();
            match field {
                0 => cap.connect_timeout = duration,
                1 => cap.read_timeout = duration,
                _ => cap.request_timeout = duration,
            };
            assert!(TrustedRegistry::new(server.config(), cap).is_err());
        }
    }
    assert!(server.requests().is_empty());
}

#[tokio::test]
async fn malformed_digests_and_impossible_sizes_are_rejected_without_a_request() {
    let server = Server::new(Vec::new());
    let registry = server.client();
    for value in [
        "abc".to_owned(),
        "A".repeat(64),
        format!("sha256:{}", "0".repeat(64)),
        "0/../".repeat(13),
    ] {
        assert_eq!(
            registry.fetch_manifest(&value, 64).await.unwrap_err(),
            RegistryIngressError::InvalidDigest
        );
    }
    for size in [0, 8193, u64::MAX] {
        assert!(registry
            .fetch_blob(&digest(b"abc"), size, 8192)
            .await
            .is_err());
    }
    assert!(registry.fetch_manifest(&digest(b"abc"), 0).await.is_err());
    assert!(server.requests().is_empty());
}
