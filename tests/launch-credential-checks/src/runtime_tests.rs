//! Loopback TLS ingress, signed gate admission/JWE, content checks, and staging.
//! A private test resolver supplies synthetic unwrapped options. Google OAuth,
//! Cloud KMS, immutable rootfs custody, TEE, and execution are outside this suite.
use crate::cdh_tests::{SERVICE_ACCOUNT, trusted_attempt};
use crate::content_tests::{
    ContentFixture, StagingFixtureParent, content_limits, metadata_limits, staging_limits,
};
use crate::launch_preparation::{
    ContentBinding, PreparationProfile,
    fixture::{Reply, Trace},
    runtime::*,
};
use crate::launch_recorder::{
    LaunchRecorder,
    test_support::{Fixture, fixture_jwe},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use execution_proof_contract::{
    Signed, VerifiedLaunchGrant,
    admission::{
        ADMISSION_PROFILE, ADMISSION_PURPOSE, ADMISSION_VERSION, AdmissionAuthorizationV1,
        policy_admission_context,
    },
    policy_receipt::{VerifiedPolicyAggregate, verify_policy_aggregate},
};
use image_rs::preparation::registry_ingress::{
    RegistryIngressLimits, TrustedRegistry, TrustedRegistryConfig,
};
use openssl::{
    asn1::Asn1Time,
    bn::BigNum,
    hash::MessageDigest,
    pkey::{PKey, Private},
    rsa::Rsa,
    ssl::{SslAcceptor, SslMethod},
    x509::{
        X509, X509NameBuilder,
        extension::{BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName},
    },
};
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::json;
use sha2::{Digest, Sha256, Sha384};
use std::{
    collections::BTreeMap,
    io::{Read, Write},
    net::{SocketAddr, TcpListener},
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};
use tokio::sync::Notify;

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

fn hash256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn hash384(bytes: &[u8]) -> String {
    Sha384::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

type RegistryReply = (Vec<u8>, &'static str);
type BodyPause = (std::sync::mpsc::Receiver<()>, Arc<Notify>);

struct Server {
    address: SocketAddr,
    bodies: Arc<Mutex<BTreeMap<String, RegistryReply>>>,
    requests: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    pause: Arc<Mutex<Option<BodyPause>>>,
    release: Option<std::sync::mpsc::Sender<()>>,
    worker: Option<thread::JoinHandle<()>>,
}
impl Server {
    fn new() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let bodies = Arc::new(Mutex::new(
            BTreeMap::<String, (Vec<u8>, &'static str)>::new(),
        ));
        let serving = bodies.clone();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let observed = requests.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = stop.clone();
        let pause = Arc::new(Mutex::new(
            None::<(std::sync::mpsc::Receiver<()>, Arc<Notify>)>,
        ));
        let pausing = pause.clone();
        let material = tls_material();
        let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
        acceptor.set_certificate(&material.certificate).unwrap();
        acceptor.set_private_key(&material.key).unwrap();
        let acceptor = acceptor.build();
        let worker = thread::spawn(move || {
            while !stopping.load(Ordering::Relaxed) {
                let stream = match listener.accept() {
                    Ok((stream, _)) => stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                        continue;
                    }
                    Err(error) => panic!("TLS fixture accept failed: {error}"),
                };
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(2)))
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
                let request = String::from_utf8(request).unwrap();
                let path = request
                    .split_whitespace()
                    .nth(1)
                    .unwrap_or_default()
                    .to_owned();
                observed.lock().unwrap().push(path.clone());
                let body = serving.lock().unwrap().get(&path).cloned();
                let Some((bytes, mime)) = body else {
                    let _ = tls.write_all(
                        b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    );
                    continue;
                };
                let _ = tls.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: {mime}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", bytes.len()).as_bytes());
                let _ = tls.flush();
                if let Some((release, notify)) = pausing.lock().unwrap().take() {
                    notify.notify_one();
                    let _ = release.recv();
                }
                let _ = tls.write_all(&bytes);
                let _ = tls.flush();
                let _ = tls.shutdown();
            }
        });
        Self {
            address,
            bodies,
            requests,
            stop,
            pause,
            release: None,
            worker: Some(worker),
        }
    }
    fn repository(&self) -> String {
        format!("registry.test:{}/team/app", self.address.port())
    }
    fn client(&self) -> TrustedRegistry {
        TrustedRegistry::new(
            TrustedRegistryConfig {
                origin: format!("https://registry.test:{}", self.address.port()),
                repository: self.repository(),
                addresses: vec![self.address],
                tls_ca_pem: tls_material().ca_pem.clone(),
                bearer_token: None,
            },
            RegistryIngressLimits {
                manifest_bytes: 131072,
                blob_bytes: 65536,
                signature_payload_bytes: 16384,
                signature_bytes: 128,
                connect_timeout: Duration::from_secs(2),
                read_timeout: Duration::from_secs(2),
                request_timeout: Duration::from_secs(3),
            },
        )
        .unwrap()
    }
    fn image(&self, image: &ContentFixture) -> String {
        let signature_artifact = serde_json::to_vec(&json!({"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json",
            "config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":format!("sha256:{}",hash256(b"{}")),"size":2},
            "layers":[{"mediaType":"application/vnd.dev.cosign.simplesigning.v1+json","digest":format!("sha256:{}",hash256(&image.payload)),"size":image.payload.len(),
                "annotations":{"dev.cosignproject.cosign/signature":STANDARD.encode(&image.signature)}}]})).unwrap();
        let artifact_digest = hash256(&signature_artifact);
        let mut bodies = self.bodies.lock().unwrap();
        bodies.insert(
            format!("/v2/team/app/manifests/sha256:{}", hash256(&image.manifest)),
            (
                image.manifest.clone(),
                "application/vnd.oci.image.manifest.v1+json",
            ),
        );
        bodies.insert(
            format!("/v2/team/app/manifests/sha256:{artifact_digest}"),
            (
                signature_artifact,
                "application/vnd.oci.image.manifest.v1+json",
            ),
        );
        for bytes in std::iter::once(&image.config)
            .chain(std::iter::once(&image.payload))
            .chain(image.ciphertexts.iter())
        {
            bodies.insert(
                format!("/v2/team/app/blobs/sha256:{}", hash256(bytes)),
                (bytes.clone(), "application/octet-stream"),
            );
        }
        artifact_digest
    }
    fn pause_first_response(&mut self) -> Arc<Notify> {
        let (release, wait) = std::sync::mpsc::channel();
        let seen = Arc::new(Notify::new());
        *self.pause.lock().unwrap() = Some((wait, seen.clone()));
        self.release = Some(release);
        seen
    }
    fn release(&mut self) {
        if let Some(release) = self.release.take() {
            let _ = release.send(());
        }
    }
    fn requests(&self) -> Vec<String> {
        self.requests.lock().unwrap().clone()
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.release();
        self.stop.store(true, Ordering::Relaxed);
        self.worker.take().unwrap().join().unwrap();
    }
}

struct Delivery {
    grant: Vec<u8>,
    aggregate: Vec<u8>,
    receipt: Vec<u8>,
    credential: Vec<u8>,
}
impl Delivery {
    fn borrowed(&self) -> RuntimeDelivery<'_> {
        RuntimeDelivery {
            grant: &self.grant,
            aggregate: &self.aggregate,
            admission_receipt: &self.receipt,
            credential_response: &self.credential,
        }
    }
}
struct ReceiptSigner {
    authority: Ed25519KeyPair,
    grant: VerifiedLaunchGrant,
    aggregate: VerifiedPolicyAggregate,
    delivery: Delivery,
    audience: String,
    issuer: String,
    policy: String,
}
impl ReceiptSigner {
    fn delivery(mut self, nonce: &str) -> Delivery {
        let statement = AdmissionAuthorizationV1 {
            version: ADMISSION_VERSION,
            purpose: ADMISSION_PURPOSE.into(),
            profile: ADMISSION_PROFILE.into(),
            audience: self.audience,
            issuer: self.issuer,
            grant_id: self.grant.grant_id().into(),
            grant_sha384: self.grant.grant_digest().into(),
            aggregate_sha384: self.aggregate.digest_sha384().into(),
            aggregate_key_sha384: self.aggregate.kbs_proof_key_sha384().into(),
            context_sha384: policy_admission_context(
                &self.grant,
                &self.aggregate,
                nonce,
                &self.policy,
            )
            .unwrap(),
            guest_nonce: nonce.into(),
            admission_policy_sha384: self.policy,
            validity: *self.grant.validity(),
            binding: self.grant.binding().clone(),
        };
        self.delivery.receipt = serde_json::to_vec(&Signed {
            signature: self
                .authority
                .sign(&statement.signing_bytes().unwrap())
                .as_ref()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>(),
            statement,
        })
        .unwrap();
        self.delivery
    }
}

async fn inputs(
    image: &ContentFixture,
    parent: &StagingFixtureParent,
    signature_artifact_sha256: String,
) -> (RuntimeAttemptConfig, LaunchRecorder, ReceiptSigner) {
    let fixture =
        Fixture::ready_with_image_policy(hash256(&image.manifest), hash384(&image.policy)).await;
    inputs_from_fixture(image, parent, signature_artifact_sha256, fixture)
}

fn inputs_from_fixture(
    image: &ContentFixture,
    parent: &StagingFixtureParent,
    signature_artifact_sha256: String,
    mut fixture: Fixture,
) -> (RuntimeAttemptConfig, LaunchRecorder, ReceiptSigner) {
    let aggregate_wire = fixture.pin_and_sign();
    let admission = fixture.admission_config(fixture.expectations());
    let raw = fixture.raw_grant();
    let trusted = trusted_attempt(
        fixture.authority.public_key().as_ref().try_into().unwrap(),
        fixture.proof.public_key().as_ref().try_into().unwrap(),
        raw.binding.clone(),
        raw.digest_sha384().unwrap(),
    );
    let grant = execution_proof_contract::verify_launch_grant_historical(
        &fixture.signed_grant,
        &admission.grant,
    )
    .unwrap();
    let aggregate = verify_policy_aggregate(&aggregate_wire, &grant, &admission.aggregate).unwrap();
    let credential = fixture.response(
        &aggregate_wire,
        &fixture_jwe(&fixture.public, SERVICE_ACCOUNT),
    );
    let signer = ReceiptSigner {
        authority: fixture.authority,
        grant,
        aggregate,
        delivery: Delivery {
            grant: fixture.signed_grant,
            aggregate: aggregate_wire,
            receipt: Vec::new(),
            credential,
        },
        audience: admission.audience.clone(),
        issuer: admission.issuer.clone(),
        policy: admission.admission_policy_sha384.clone(),
    };
    let config = RuntimeAttemptConfig {
        admission,
        preparation: PreparationProfile {
            authority_public_key: trusted.authority_public_key,
            kbs_proof_public_key: trusted.kbs_proof_public_key,
            binding: trusted.binding,
            grant_sha384: trusted.grant_sha384,
            validity: trusted.validity,
            workflow_id: trusted.workflow_id,
            resource_path: trusted.resource_path,
            project_id: trusted.project_id,
            client_email: trusted.client_email,
            kms_key_version: trusted.kms_key_version,
        },
        metadata_limits: metadata_limits(),
        content_limits: content_limits(),
        staging_parent: parent.capability(),
        staging_limits: staging_limits(),
        signature_policy: image.verifier(),
        signature_artifact_sha256,
    };
    (config, fixture.recorder, signer)
}

#[tokio::test]
async fn real_factory_nonce_tls_admission_content_and_retained_actor_retry() {
    let server = Server::new();
    let image = ContentFixture::new_for_repository(2, true, &server.repository());
    let signature = server.image(&image);
    let parent = StagingFixtureParent::new();
    let factory = RuntimeFactory::new(server.client(), 1, Duration::from_secs(10)).unwrap();
    let (config, recorder, signer) = inputs(&image, &parent, signature.clone()).await;
    let mut attempt = factory.begin_attempt(config, recorder).unwrap();
    let delivery = signer.delivery(attempt.challenge_nonce());
    let trace = Arc::new(Mutex::new(Trace::default()));
    assert_eq!(
        attempt
            .prepare_fixture(delivery.borrowed(), image.replies(), trace.clone())
            .await,
        Ok(ContentBinding::FirstChecked)
    );
    assert_eq!(parent.children(), 1);
    let summary = attempt.summary().unwrap().clone();
    assert_eq!(summary.manifest_sha256, hash256(&image.manifest));
    assert_eq!(summary.layers, 2);
    assert_eq!(summary.write_bytes, 14);
    assert_eq!(summary.live_file_bytes, 7);
    let requests = server.requests();
    assert_eq!(requests.len(), 6);
    assert_eq!(
        attempt.prepare(delivery.borrowed()).await,
        Ok(ContentBinding::Historical)
    );
    assert_eq!(attempt.summary().unwrap(), &summary);
    assert_eq!(server.requests(), requests);
    assert_eq!(trace.lock().unwrap().calls.len(), 2);
    let (config, recorder, _) = inputs(&image, &parent, signature).await;
    assert!(matches!(
        factory.begin_attempt(config, recorder),
        Err(RuntimeError::Busy)
    ));
    attempt.cancel_and_wait().await.unwrap();
    assert_eq!(parent.children(), 0);
    assert!(attempt.summary().is_err());
}

#[tokio::test]
async fn constructor_scope_limits_and_pending_capacity_are_network_free() {
    let server = Server::new();
    let image = ContentFixture::new_for_repository(1, false, &server.repository());
    let signature = server.image(&image);
    let parent = StagingFixtureParent::new();
    for (active, timeout) in [
        (0, Duration::from_secs(1)),
        (5, Duration::from_secs(1)),
        (1, Duration::ZERO),
        (1, Duration::MAX),
    ] {
        assert!(matches!(
            RuntimeFactory::new(server.client(), active, timeout),
            Err(RuntimeError::InvalidConfiguration)
        ));
    }
    let factory = RuntimeFactory::new(server.client(), 1, Duration::from_secs(5)).unwrap();
    for changed in ["root", "binding", "workflow", "policy", "locator"] {
        let (mut config, recorder, _) = inputs(&image, &parent, signature.clone()).await;
        match changed {
            "root" => config.preparation.authority_public_key = [71; 32],
            "binding" => config.preparation.binding.boot_id = "foreign".into(),
            "workflow" => config.preparation.workflow_id = "foreign".into(),
            "policy" => config.preparation.binding.image_policy_sha384 = "71".repeat(48),
            "locator" => config.signature_artifact_sha256 = "not-a-digest".into(),
            _ => unreachable!(),
        }
        assert!(
            matches!(
                factory.begin_attempt(config, recorder),
                Err(RuntimeError::InvalidConfiguration)
            ),
            "{changed}"
        );
    }
    let (config, recorder, _) = inputs(&image, &parent, signature.clone()).await;
    let pending = factory.begin_attempt(config, recorder).unwrap();
    let (config, recorder, _) = inputs(&image, &parent, signature.clone()).await;
    assert!(matches!(
        factory.begin_attempt(config, recorder),
        Err(RuntimeError::Busy)
    ));
    drop(pending);
    let (config, recorder, _) = inputs(&image, &parent, signature).await;
    let pending = factory.begin_attempt(config, recorder).unwrap();
    drop(pending);
    assert!(server.requests().is_empty());
    assert_eq!(parent.children(), 0);
}

#[tokio::test]
async fn admission_delivery_bounds_and_authentication_fail_before_registry() {
    let server = Server::new();
    let image = ContentFixture::new_for_repository(1, false, &server.repository());
    let signature = server.image(&image);
    let parent = StagingFixtureParent::new();
    let factory = RuntimeFactory::new(server.client(), 1, Duration::from_secs(5)).unwrap();
    for changed in ["oversize", "nonce", "credential"] {
        let (config, recorder, signer) = inputs(&image, &parent, signature.clone()).await;
        let mut attempt = factory.begin_attempt(config, recorder).unwrap();
        let mut delivery = signer.delivery(
            if changed == "nonce" {
                "01".repeat(32)
            } else {
                attempt.challenge_nonce().to_owned()
            }
            .as_str(),
        );
        match changed {
            "oversize" => delivery
                .grant
                .resize(execution_proof_contract::MAX_WIRE_BYTES + 1, 0),
            "credential" => delivery.credential[0] ^= 1,
            _ => {}
        }
        let trace = Arc::new(Mutex::new(Trace::default()));
        assert!(
            attempt
                .prepare_fixture(delivery.borrowed(), image.replies(), trace.clone())
                .await
                .is_err(),
            "{changed}"
        );
        attempt.cancel_and_wait().await.unwrap();
        assert!(trace.lock().unwrap().calls.is_empty());
        assert!(attempt.summary().is_err());
    }
    assert!(server.requests().is_empty());
    assert_eq!(parent.children(), 0);
}

#[tokio::test]
async fn all_layer_sizes_preflight_before_first_layer_download_or_unwrap() {
    let server = Server::new();
    let image = ContentFixture::new_for_repository(2, false, &server.repository());
    let signature = server.image(&image);
    let parent = StagingFixtureParent::new();
    let factory = RuntimeFactory::new(server.client(), 1, Duration::from_secs(5)).unwrap();
    let (mut config, recorder, signer) = inputs(&image, &parent, signature).await;
    config.content_limits.total_ciphertext_bytes =
        image.ciphertexts.iter().map(Vec::len).sum::<usize>() - 1;
    let mut attempt = factory.begin_attempt(config, recorder).unwrap();
    let delivery = signer.delivery(attempt.challenge_nonce());
    let trace = Arc::new(Mutex::new(Trace::default()));
    assert_eq!(
        attempt
            .prepare_fixture(delivery.borrowed(), image.replies(), trace.clone())
            .await,
        Err(RuntimeError::TooLarge)
    );
    attempt.cancel_and_wait().await.unwrap();
    assert_eq!(server.requests().len(), 4);
    let layer = format!(
        "/v2/team/app/blobs/sha256:{}",
        hash256(&image.ciphertexts[0])
    );
    assert!(!server.requests().contains(&layer));
    assert!(trace.lock().unwrap().calls.is_empty());
    assert_eq!(parent.children(), 0);
}

#[tokio::test]
async fn workflow_deadline_cancels_a_controlled_stalled_body_without_implicit_retry() {
    let mut server = Server::new();
    let image = ContentFixture::new_for_repository(1, false, &server.repository());
    let signature = server.image(&image);
    let parent = StagingFixtureParent::new();
    let seen = server.pause_first_response();
    let factory = RuntimeFactory::new(server.client(), 1, Duration::from_millis(500)).unwrap();
    let (config, recorder, signer) = inputs(&image, &parent, signature).await;
    let mut attempt = factory.begin_attempt(config, recorder).unwrap();
    let delivery = signer.delivery(attempt.challenge_nonce());
    let trace = Arc::new(Mutex::new(Trace::default()));
    let mut preparation =
        Box::pin(attempt.prepare_fixture(delivery.borrowed(), image.replies(), trace.clone()));
    tokio::select! { result = &mut preparation => panic!("workflow ended before controlled response stall: {result:?}"), _ = seen.notified() => {} }
    assert_eq!(preparation.await, Err(RuntimeError::Deadline));
    attempt.cancel_and_wait().await.unwrap();
    server.release();
    assert_eq!(server.requests().len(), 1);
    assert!(trace.lock().unwrap().calls.is_empty());
    assert_eq!(parent.children(), 0);
}

#[tokio::test]
async fn dropped_content_future_cooperatively_drops_pending_unwrap_and_drains_worker() {
    let server = Server::new();
    let image = ContentFixture::new_for_repository(2, false, &server.repository());
    let signature = server.image(&image);
    let parent = StagingFixtureParent::new();
    let factory = RuntimeFactory::new(server.client(), 1, Duration::from_secs(30)).unwrap();
    let (config, recorder, signer) = inputs(&image, &parent, signature).await;
    let mut attempt = factory.begin_attempt(config, recorder).unwrap();
    let delivery = signer.delivery(attempt.challenge_nonce());
    let trace = Arc::new(Mutex::new(Trace::default()));
    let mut replies = image.replies();
    replies[0] = Reply::Pending;
    let mut preparation =
        Box::pin(attempt.prepare_fixture(delivery.borrowed(), replies, trace.clone()));
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            tokio::select! { result = &mut preparation => panic!("unexpected completed content: {result:?}"), _ = tokio::task::yield_now() => {} }
            if trace.lock().unwrap().calls.len() == 1 { break; }
        }
    }).await.unwrap();
    drop(preparation);
    tokio::time::timeout(Duration::from_secs(3), attempt.cancel_and_wait())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(trace.lock().unwrap().calls.len(), 1);
    assert_eq!(parent.children(), 0);
    assert!(attempt.summary().is_err());
}

#[tokio::test]
async fn cancelled_running_stage_keeps_capacity_and_tree_until_actual_worker_cleanup() {
    let server = Server::new();
    let image = ContentFixture::new_for_repository(1, false, &server.repository());
    let signature = server.image(&image);
    let parent = StagingFixtureParent::new();
    let factory = RuntimeFactory::new(server.client(), 1, Duration::from_secs(30)).unwrap();
    let (config, recorder, signer) = inputs(&image, &parent, signature.clone()).await;
    let mut attempt = factory.begin_attempt(config, recorder).unwrap();
    let delivery = signer.delivery(attempt.challenge_nonce());
    let (reached, staged) = tokio::sync::oneshot::channel();
    let (release, wait) = std::sync::mpsc::channel();
    attempt.set_stage_barrier(reached, wait);
    let trace = Arc::new(Mutex::new(Trace::default()));
    let mut preparation =
        Box::pin(attempt.prepare_fixture(delivery.borrowed(), image.replies(), trace));
    tokio::select! { result = &mut preparation => panic!("stage escaped barrier: {result:?}"), result = staged => result.unwrap() }
    assert_eq!(parent.children(), 1);
    drop(preparation);
    let (config, recorder, _) = inputs(&image, &parent, signature.clone()).await;
    assert!(matches!(
        factory.begin_attempt(config, recorder),
        Err(RuntimeError::Busy)
    ));
    release.send(()).unwrap();
    attempt.cancel_and_wait().await.unwrap();
    assert_eq!(parent.children(), 0);
    let (config, recorder, _) = inputs(&image, &parent, signature).await;
    let mut next = factory.begin_attempt(config, recorder).unwrap();
    next.cancel_and_wait().await.unwrap();
}

#[tokio::test]
async fn changed_historical_delivery_closes_actor_and_requires_explicit_drain() {
    let server = Server::new();
    let image = ContentFixture::new_for_repository(1, false, &server.repository());
    let signature = server.image(&image);
    let parent = StagingFixtureParent::new();
    let factory = RuntimeFactory::new(server.client(), 1, Duration::from_secs(10)).unwrap();
    let (config, recorder, signer) = inputs(&image, &parent, signature).await;
    let mut attempt = factory.begin_attempt(config, recorder).unwrap();
    let mut delivery = signer.delivery(attempt.challenge_nonce());
    let trace = Arc::new(Mutex::new(Trace::default()));
    assert_eq!(
        attempt
            .prepare_fixture(delivery.borrowed(), image.replies(), trace)
            .await,
        Ok(ContentBinding::FirstChecked)
    );
    delivery.credential.push(b' ');
    assert_eq!(
        attempt.prepare(delivery.borrowed()).await,
        Err(RuntimeError::Conflict)
    );
    assert!(attempt.summary().is_err());
    attempt.cancel_and_wait().await.unwrap();
    assert_eq!(parent.children(), 0);
}

#[cfg(feature = "launch-preparation-executable")]
mod checked {
    use super::*;
    use image_rs::preparation::{
        launch_spec::{EffectiveSpecLimits, EffectiveSpecPolicy},
        static_elf::StaticElfLimits,
    };

    fn spec_value(cwd: &str) -> serde_json::Value {
        json!({
            "ociVersion":"1.2.1", "root":{"path":"rootfs","readonly":true},
            "process":{
                "terminal":false,"user":{"uid":1000,"gid":1000,"additionalGids":[]},
                "args":["/app"],"env":["HOME=/"],"cwd":cwd,"noNewPrivileges":true,
                "capabilities":{"bounding":[],"effective":[],"inheritable":[],"permitted":[],"ambient":[]}
            },
            "mounts":[],
            "linux":{
                "namespaces":[{"type":"mount"},{"type":"pid"},{"type":"ipc"},{"type":"uts"},{"type":"network"}],
                "seccomp":{"defaultAction":"SCMP_ACT_ERRNO","defaultErrnoRet":1,"architectures":["SCMP_ARCH_X86_64"],
                    "syscalls":[{"names":["execveat","exit_group","write"],"action":"SCMP_ACT_ALLOW"}]}
            }
        })
    }
    fn spec(cwd: &str) -> Vec<u8> {
        serde_json::to_vec(&spec_value(cwd)).unwrap()
    }
    fn spec_policy() -> EffectiveSpecPolicy {
        EffectiveSpecPolicy {
            uid: 1000,
            gid: 1000,
            seccomp_syscalls: vec!["execveat".into(), "exit_group".into(), "write".into()],
        }
    }
    fn spec_limits() -> EffectiveSpecLimits {
        EffectiveSpecLimits {
            spec_bytes: 16384,
            args: 16,
            env: 16,
            string_bytes: 1024,
            total_string_bytes: 4096,
            path_bytes: 256,
            path_components: 16,
            syscalls: 32,
            json_depth: 16,
        }
    }
    fn elf_limits() -> StaticElfLimits {
        StaticElfLimits {
            file_bytes: 4096,
            program_headers: 16,
            mapped_bytes: 65536,
            virtual_span_bytes: 65536,
        }
    }
    fn elf() -> Vec<u8> {
        let mut bytes = vec![0u8; 512];
        bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        bytes[16..18].copy_from_slice(&2u16.to_le_bytes());
        bytes[18..20].copy_from_slice(&62u16.to_le_bytes());
        bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
        bytes[24..32].copy_from_slice(&0x400100u64.to_le_bytes());
        bytes[32..40].copy_from_slice(&64u64.to_le_bytes());
        bytes[52..54].copy_from_slice(&64u16.to_le_bytes());
        bytes[54..56].copy_from_slice(&56u16.to_le_bytes());
        bytes[56..58].copy_from_slice(&2u16.to_le_bytes());
        bytes[64..68].copy_from_slice(&1u32.to_le_bytes());
        bytes[68..72].copy_from_slice(&5u32.to_le_bytes());
        bytes[80..88].copy_from_slice(&0x400000u64.to_le_bytes());
        bytes[96..104].copy_from_slice(&512u64.to_le_bytes());
        bytes[104..112].copy_from_slice(&512u64.to_le_bytes());
        bytes[112..120].copy_from_slice(&4096u64.to_le_bytes());
        bytes[120..124].copy_from_slice(&0x6474e551u32.to_le_bytes());
        bytes[124..128].copy_from_slice(&6u32.to_le_bytes());
        bytes[168..176].copy_from_slice(&16u64.to_le_bytes());
        bytes[256] = 0xc3;
        bytes
    }
    fn tar(payload: &[u8], mode: u64) -> Vec<u8> {
        let mut header = [0u8; 512];
        header[..3].copy_from_slice(b"app");
        for (start, len, value) in [
            (100, 8, mode),
            (108, 8, 0),
            (116, 8, 0),
            (124, 12, payload.len() as u64),
            (136, 12, 0),
            (329, 8, 0),
            (337, 8, 0),
        ] {
            header[start..start + len]
                .copy_from_slice(format!("{value:0width$o}\0", width = len - 1).as_bytes());
        }
        header[156] = b'0';
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        header[148..156].fill(b' ');
        let sum: u64 = header.iter().map(|b| u64::from(*b)).sum();
        header[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        let mut bytes = header.to_vec();
        bytes.extend_from_slice(payload);
        bytes.resize(512 + payload.len().div_ceil(512) * 512 + 1024, 0);
        bytes
    }
    async fn checked_inputs(
        image: &ContentFixture,
        parent: &StagingFixtureParent,
        signature: String,
        raw: Vec<u8>,
    ) -> (CheckedRuntimeAttemptConfig, LaunchRecorder, ReceiptSigner) {
        let fixture = Fixture::ready_with_effective_spec(
            hash256(&image.manifest),
            hash384(&image.policy),
            hash384(&raw),
        )
        .await;
        let (base, recorder, signer) = inputs_from_fixture(image, parent, signature, fixture);
        (
            CheckedRuntimeAttemptConfig {
                base,
                effective_spec: raw,
                spec_policy: spec_policy(),
                spec_limits: spec_limits(),
                executable_limits: elf_limits(),
            },
            recorder,
            signer,
        )
    }

    #[tokio::test]
    async fn checked_runtime_actual_signed_spec_and_static_elf_are_mandatory_before_summary() {
        let server = Server::new();
        let executable = elf();
        let image =
            ContentFixture::new_with_tar(2, true, &server.repository(), tar(&executable, 0o755));
        let signature = server.image(&image);
        let parent = StagingFixtureParent::new();
        let raw = spec("/");
        let factory = RuntimeFactory::new(server.client(), 1, Duration::from_secs(10)).unwrap();
        let (config, recorder, signer) =
            checked_inputs(&image, &parent, signature, raw.clone()).await;
        let mut attempt = factory.begin_checked_attempt(config, recorder).unwrap();
        let delivery = signer.delivery(attempt.challenge_nonce());
        assert!(attempt.summary().is_err());
        let trace = Arc::new(Mutex::new(Trace::default()));
        assert_eq!(
            attempt
                .prepare_fixture(delivery.borrowed(), image.replies(), trace.clone())
                .await,
            Ok(ContentBinding::FirstChecked)
        );
        let summary = attempt.summary().unwrap();
        assert_eq!(summary.executable().spec_sha384(), hash384(&raw));
        assert_eq!(
            summary.executable().executable_sha384(),
            hash384(&executable)
        );
        assert_eq!(summary.executable().elf().file_bytes(), executable.len());
        assert_eq!(summary.staging().layers, 2);
        assert_eq!(summary.staging().write_bytes, 1024);
        assert_eq!(parent.children(), 1);
        let requests = server.requests();
        assert_eq!(
            attempt.prepare(delivery.borrowed()).await,
            Ok(ContentBinding::Historical)
        );
        assert_eq!(attempt.summary().unwrap(), summary);
        assert_eq!(server.requests(), requests);
        assert_eq!(trace.lock().unwrap().calls.len(), 2);
        attempt.cancel_and_wait().await.unwrap();
        assert_eq!(parent.children(), 0);
        assert!(attempt.summary().is_err());
    }

    #[tokio::test]
    async fn checked_runtime_hash_profile_and_limit_rejections_happen_before_network() {
        let server = Server::new();
        let image =
            ContentFixture::new_with_tar(1, false, &server.repository(), tar(&elf(), 0o755));
        let signature = server.image(&image);
        let parent = StagingFixtureParent::new();
        let factory = RuntimeFactory::new(server.client(), 1, Duration::from_secs(10)).unwrap();
        for case in [
            "digest",
            "uid",
            "root",
            "hook",
            "relative",
            "bounds",
            "elf-limits",
        ] {
            let mut document = spec_value("/");
            match case {
                "uid" => document["process"]["user"]["uid"] = 0.into(),
                "root" => document["root"]["readonly"] = false.into(),
                "hook" => document["hooks"] = json!({}),
                "relative" => document["process"]["args"] = json!(["app"]),
                _ => {}
            }
            let raw = serde_json::to_vec(&document).unwrap();
            let (mut config, recorder, _) =
                checked_inputs(&image, &parent, signature.clone(), raw).await;
            match case {
                "digest" => config.effective_spec.push(b' '),
                "bounds" => config.spec_limits.spec_bytes = 1,
                "elf-limits" => config.executable_limits.file_bytes = 0,
                _ => {}
            }
            assert!(
                matches!(
                    factory.begin_checked_attempt(config, recorder),
                    Err(RuntimeError::InvalidConfiguration)
                ),
                "{case}"
            );
        }
        assert!(server.requests().is_empty());
        assert_eq!(parent.children(), 0);
    }

    #[tokio::test]
    async fn checked_runtime_invalid_elf_cwd_and_permissions_are_terminal_after_staging() {
        for case in ["elf", "cwd", "cwd-file", "entry", "permissions"] {
            let server = Server::new();
            let executable = if case == "elf" {
                b"payload".to_vec()
            } else {
                elf()
            };
            let mode = if case == "permissions" { 0o700 } else { 0o755 };
            let image = ContentFixture::new_with_tar(
                1,
                false,
                &server.repository(),
                tar(&executable, mode),
            );
            let signature = server.image(&image);
            let parent = StagingFixtureParent::new();
            let mut document = spec_value(match case {
                "cwd" => "/missing",
                "cwd-file" => "/app",
                _ => "/",
            });
            if case == "entry" {
                document["process"]["args"] = json!(["/missing"]);
            }
            let factory = RuntimeFactory::new(server.client(), 1, Duration::from_secs(10)).unwrap();
            let (config, recorder, signer) = checked_inputs(
                &image,
                &parent,
                signature,
                serde_json::to_vec(&document).unwrap(),
            )
            .await;
            let mut attempt = factory.begin_checked_attempt(config, recorder).unwrap();
            let delivery = signer.delivery(attempt.challenge_nonce());
            let trace = Arc::new(Mutex::new(Trace::default()));
            assert_eq!(
                attempt
                    .prepare_fixture(delivery.borrowed(), image.replies(), trace.clone())
                    .await,
                Err(RuntimeError::ExecutableRejected),
                "{case}"
            );
            assert!(attempt.summary().is_err());
            let requests = server.requests();
            assert_eq!(
                attempt.prepare(delivery.borrowed()).await,
                Err(RuntimeError::Unavailable)
            );
            assert_eq!(server.requests(), requests);
            assert_eq!(trace.lock().unwrap().calls.len(), 1);
            attempt.cancel_and_wait().await.unwrap();
            assert_eq!(parent.children(), 0, "{case}");
        }
    }

    #[tokio::test]
    async fn checked_runtime_cancelled_actor_retains_tree_and_capacity_until_cleanup() {
        let server = Server::new();
        let image =
            ContentFixture::new_with_tar(1, false, &server.repository(), tar(&elf(), 0o755));
        let signature = server.image(&image);
        let parent = StagingFixtureParent::new();
        let factory = RuntimeFactory::new(server.client(), 1, Duration::from_secs(30)).unwrap();
        let (config, recorder, signer) =
            checked_inputs(&image, &parent, signature.clone(), spec("/")).await;
        let mut attempt = factory.begin_checked_attempt(config, recorder).unwrap();
        let delivery = signer.delivery(attempt.challenge_nonce());
        let (reached, staged) = tokio::sync::oneshot::channel();
        let (release, wait) = std::sync::mpsc::channel();
        attempt.set_stage_barrier(reached, wait);
        let trace = Arc::new(Mutex::new(Trace::default()));
        let mut preparation =
            Box::pin(attempt.prepare_fixture(delivery.borrowed(), image.replies(), trace));
        tokio::select! {result=&mut preparation=>panic!("checked actor escaped barrier: {result:?}"),result=staged=>result.unwrap()}
        assert_eq!(parent.children(), 1);
        drop(preparation);
        assert!(attempt.summary().is_err());
        let (config, recorder, _) = checked_inputs(&image, &parent, signature, spec("/")).await;
        assert!(matches!(
            factory.begin_checked_attempt(config, recorder),
            Err(RuntimeError::Busy)
        ));
        release.send(()).unwrap();
        attempt.cancel_and_wait().await.unwrap();
        assert_eq!(parent.children(), 0);
        assert!(attempt.summary().is_err());
    }

    #[tokio::test]
    async fn checked_runtime_changed_retry_drops_checked_summary_and_closes_actor() {
        let server = Server::new();
        let image =
            ContentFixture::new_with_tar(1, false, &server.repository(), tar(&elf(), 0o755));
        let signature = server.image(&image);
        let parent = StagingFixtureParent::new();
        let factory = RuntimeFactory::new(server.client(), 1, Duration::from_secs(10)).unwrap();
        let (config, recorder, signer) =
            checked_inputs(&image, &parent, signature, spec("/")).await;
        let mut attempt = factory.begin_checked_attempt(config, recorder).unwrap();
        let mut delivery = signer.delivery(attempt.challenge_nonce());
        let trace = Arc::new(Mutex::new(Trace::default()));
        assert_eq!(
            attempt
                .prepare_fixture(delivery.borrowed(), image.replies(), trace)
                .await,
            Ok(ContentBinding::FirstChecked)
        );
        assert!(attempt.summary().is_ok());
        delivery.receipt.push(b' ');
        assert_eq!(
            attempt.prepare(delivery.borrowed()).await,
            Err(RuntimeError::Conflict)
        );
        assert!(attempt.summary().is_err());
        attempt.cancel_and_wait().await.unwrap();
        assert_eq!(parent.children(), 0);
    }
    #[cfg(feature = "launch-preparation-erofs")]
    mod erofs_tests {
        use super::*;
        #[cfg(feature = "launch-preparation-offer")]
        mod offer_tests {
            include!("runtime_offer_tests.rs");
        }
        use image_rs::preparation::{
            erofs_builder::{ErofsBuildLimits, TrustedErofsBuilder},
            rootfs_staging::BuilderInputLimits,
        };
        use std::{fs::File, path::PathBuf};
        fn limits() -> ErofsBuildLimits {
            ErofsBuildLimits {
                input: BuilderInputLimits {
                    tar_bytes: 1 << 20,
                    inodes: 64,
                    live_file_bytes: 1 << 20,
                },
                output_bytes: 1 << 20,
                tool_bytes: 4 << 20,
                address_space_bytes: 128 << 20,
                cpu_seconds: 2,
                wall_time: Duration::from_secs(5),
            }
        }
        fn builder(limits: ErofsBuildLimits) -> TrustedErofsBuilder {
            let path = PathBuf::from(
                std::env::var_os("ONB17_EROFS_MKFS")
                    .expect("provide pinned static native mkfs.erofs fixture"),
            );
            let hash = Sha384::digest(std::fs::read(&path).unwrap()).into();
            TrustedErofsBuilder::new(File::open(path).unwrap(), hash, limits).unwrap()
        }
        #[tokio::test]
        async fn erofs_runtime_retains_actual_backing_and_exact_retry_does_no_work() {
            let server = Server::new();
            let image =
                ContentFixture::new_with_tar(2, true, &server.repository(), tar(&elf(), 0o755));
            let signature = server.image(&image);
            let parent = StagingFixtureParent::new();
            let factory = RuntimeFactory::new(server.client(), 1, Duration::from_secs(15)).unwrap();
            let (checked, recorder, signer) =
                checked_inputs(&image, &parent, signature, spec("/")).await;
            let mut attempt = factory
                .begin_erofs_attempt(
                    ErofsRuntimeAttemptConfig {
                        checked,
                        builder: builder(limits()),
                    },
                    recorder,
                )
                .unwrap();
            let mut delivery = signer.delivery(attempt.challenge_nonce());
            let trace = Arc::new(Mutex::new(Trace::default()));
            assert!(attempt.summary().is_err());
            assert_eq!(
                attempt
                    .prepare_fixture(delivery.borrowed(), image.replies(), trace.clone())
                    .await,
                Ok(ContentBinding::FirstChecked)
            );
            let summary = attempt.summary().unwrap();
            assert_eq!(summary.backing().inodes(), 2);
            assert!(summary.backing().byte_len() >= 8192);
            assert_eq!(summary.executable().executable_sha384(), hash384(&elf()));
            assert_eq!(parent.children(), 1);
            let requests = server.requests();
            assert_eq!(
                attempt.prepare(delivery.borrowed()).await,
                Ok(ContentBinding::Historical)
            );
            assert_eq!(attempt.summary().unwrap(), summary);
            assert_eq!(trace.lock().unwrap().calls.len(), 2);
            assert_eq!(server.requests(), requests);
            delivery.receipt.push(b' ');
            assert_eq!(
                attempt.prepare(delivery.borrowed()).await,
                Err(RuntimeError::Conflict)
            );
            assert!(attempt.summary().is_err());
            attempt.cancel_and_wait().await.unwrap();
            assert_eq!(parent.children(), 0);
            assert_eq!(
                attempt.prepare(delivery.borrowed()).await,
                Err(RuntimeError::Unavailable)
            );
        }
        #[tokio::test]
        async fn erofs_runtime_failed_builder_is_terminal_without_second_unwrap() {
            let server = Server::new();
            let image =
                ContentFixture::new_with_tar(1, false, &server.repository(), tar(&elf(), 0o755));
            let signature = server.image(&image);
            let parent = StagingFixtureParent::new();
            let factory = RuntimeFactory::new(server.client(), 1, Duration::from_secs(15)).unwrap();
            let (checked, recorder, signer) =
                checked_inputs(&image, &parent, signature, spec("/")).await;
            let mut small = limits();
            small.output_bytes = 4096;
            let mut attempt = factory
                .begin_erofs_attempt(
                    ErofsRuntimeAttemptConfig {
                        checked,
                        builder: builder(small),
                    },
                    recorder,
                )
                .unwrap();
            let delivery = signer.delivery(attempt.challenge_nonce());
            let trace = Arc::new(Mutex::new(Trace::default()));
            assert_eq!(
                attempt
                    .prepare_fixture(delivery.borrowed(), image.replies(), trace.clone())
                    .await,
                Err(RuntimeError::BackingRejected)
            );
            assert!(attempt.summary().is_err());
            let requests = server.requests();
            assert_eq!(
                attempt.prepare(delivery.borrowed()).await,
                Err(RuntimeError::Unavailable)
            );
            assert_eq!(trace.lock().unwrap().calls.len(), 1);
            assert_eq!(server.requests(), requests);
            attempt.cancel_and_wait().await.unwrap();
            assert_eq!(parent.children(), 0);
        }
        #[tokio::test]
        async fn erofs_runtime_cancelled_publication_retains_capacity_until_actual_cleanup() {
            let server = Server::new();
            let image =
                ContentFixture::new_with_tar(1, false, &server.repository(), tar(&elf(), 0o755));
            let signature = server.image(&image);
            let parent = StagingFixtureParent::new();
            let factory = RuntimeFactory::new(server.client(), 1, Duration::from_secs(30)).unwrap();
            let (checked, recorder, signer) =
                checked_inputs(&image, &parent, signature.clone(), spec("/")).await;
            let mut attempt = factory
                .begin_erofs_attempt(
                    ErofsRuntimeAttemptConfig {
                        checked,
                        builder: builder(limits()),
                    },
                    recorder,
                )
                .unwrap();
            let delivery = signer.delivery(attempt.challenge_nonce());
            let (reached, staged) = tokio::sync::oneshot::channel();
            let (release, wait) = std::sync::mpsc::channel();
            attempt.set_stage_barrier(reached, wait);
            let mut preparation = Box::pin(attempt.prepare_fixture(
                delivery.borrowed(),
                image.replies(),
                Arc::new(Mutex::new(Trace::default())),
            ));
            tokio::select! {r=&mut preparation=>panic!("actor escaped publication barrier: {r:?}"),r=staged=>r.unwrap()}
            drop(preparation);
            assert!(attempt.summary().is_err());
            assert_eq!(parent.children(), 1);
            let (checked, recorder, _) =
                checked_inputs(&image, &parent, signature, spec("/")).await;
            assert!(matches!(
                factory.begin_erofs_attempt(
                    ErofsRuntimeAttemptConfig {
                        checked,
                        builder: builder(limits())
                    },
                    recorder
                ),
                Err(RuntimeError::Busy)
            ));
            release.send(()).unwrap();
            attempt.cancel_and_wait().await.unwrap();
            assert_eq!(parent.children(), 0);
        }
        #[tokio::test]
        async fn erofs_runtime_inflight_cancel_kills_reaps_and_cleans_before_drain_returns() {
            use std::sync::atomic::{AtomicUsize, Ordering};
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let helper = std::env::temp_dir().join(format!(
                "erofs-runtime-child-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&helper).unwrap();
            let source = helper.join("hang.c");
            let program = helper.join("hang");
            let marker = helper.join("child.pid");
            let pending_marker = helper.join("child.pending");
            let code = format!(
                "#include <stdio.h>\n#include <unistd.h>\nint main(void){{FILE*f=fopen({:?},\"w\");if(!f)return 1;if(fprintf(f,\"%d\\n\",getpid())<0||fclose(f))return 2;if(rename({:?},{:?}))return 3;for(;;)pause();}}",
                pending_marker.to_str().unwrap(),
                pending_marker.to_str().unwrap(),
                marker.to_str().unwrap()
            );
            std::fs::write(&source, code).unwrap();
            let built = std::process::Command::new("cc")
                .args(["-static", "-O2"])
                .arg(&source)
                .arg("-o")
                .arg(&program)
                .output()
                .unwrap();
            assert!(built.status.success());
            let hash = Sha384::digest(std::fs::read(&program).unwrap()).into();
            let mut caps = limits();
            caps.wall_time = Duration::from_secs(10);
            let hanging =
                TrustedErofsBuilder::new(File::open(&program).unwrap(), hash, caps).unwrap();
            let server = Server::new();
            let image =
                ContentFixture::new_with_tar(1, false, &server.repository(), tar(&elf(), 0o755));
            let signature = server.image(&image);
            let parent = StagingFixtureParent::new();
            let factory = RuntimeFactory::new(server.client(), 1, Duration::from_secs(30)).unwrap();
            let (checked, recorder, signer) =
                checked_inputs(&image, &parent, signature, spec("/")).await;
            let mut attempt = factory
                .begin_erofs_attempt(
                    ErofsRuntimeAttemptConfig {
                        checked,
                        builder: hanging,
                    },
                    recorder,
                )
                .unwrap();
            let delivery = signer.delivery(attempt.challenge_nonce());
            let trace = Arc::new(Mutex::new(Trace::default()));
            let mut preparation = Box::pin(attempt.prepare_fixture(
                delivery.borrowed(),
                image.replies(),
                trace.clone(),
            ));
            let reached = async {
                loop {
                    if marker.exists() {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(2)).await;
                }
            };
            tokio::select! {r=&mut preparation=>panic!("hung child returned before cancellation: {r:?}"),_=tokio::time::timeout(Duration::from_secs(10),reached)=>{assert!(marker.exists());}}
            assert_eq!(parent.children(), 2); // retained staging and private builder scratch
            drop(preparation);
            assert!(attempt.summary().is_err());
            attempt.cancel_and_wait().await.unwrap();
            assert_eq!(parent.children(), 0);
            assert_eq!(trace.lock().unwrap().calls.len(), 1);
            let pid: i32 = std::fs::read_to_string(&marker)
                .unwrap()
                .trim()
                .parse()
                .unwrap();
            let mut status = 0;
            // SAFETY: status is writable; waitpid targets only this fixture's child.
            assert_eq!(unsafe { image_rs_nix_waitpid(pid, &mut status, 1) }, -1);
            assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(10)); // ECHILD
            std::fs::remove_dir_all(helper).unwrap();
        }

        #[cfg(feature = "launch-preparation-mount")]
        fn mount_limits() -> image_rs::preparation::erofs_mount::ErofsMountLimits {
            use image_rs::preparation::erofs_mount::{ErofsMountLimits, MountedViewLimits};
            ErofsMountLimits {
                view: MountedViewLimits {
                    inodes: 32,
                    live_file_bytes: 1 << 20,
                    path_bytes: 256,
                    path_components: 16,
                    directory_entry_bytes: 16384,
                },
                backing_bytes: 1 << 20,
                ramfs_data_bytes: 1 << 20,
                wall_time: Duration::from_secs(5),
            }
        }
        #[cfg(feature = "launch-preparation-mount")]
        #[tokio::test]
        async fn mounted_runtime_invalid_limits_reject_before_network_or_content() {
            let server = Server::new();
            let image =
                ContentFixture::new_with_tar(1, false, &server.repository(), tar(&elf(), 0o755));
            let signature = server.image(&image);
            let parent = StagingFixtureParent::new();
            let factory = RuntimeFactory::new(server.client(), 1, Duration::from_secs(10)).unwrap();
            for case in 0..8 {
                let (checked, recorder, _) =
                    checked_inputs(&image, &parent, signature.clone(), spec("/")).await;
                let mut cap = mount_limits();
                match case {
                    0 => cap.backing_bytes = 0,
                    1 => cap.wall_time = Duration::ZERO,
                    2 => cap.view.inodes = 0,
                    3 => cap.view.live_file_bytes = 0,
                    4 => cap.view.path_bytes = 0,
                    5 => cap.view.path_components = 0,
                    6 => cap.view.directory_entry_bytes = 0,
                    _ => cap.ramfs_data_bytes = 0,
                }
                assert!(matches!(
                    factory.begin_mounted_attempt(
                        MountedRuntimeAttemptConfig {
                            erofs: ErofsRuntimeAttemptConfig {
                                checked,
                                builder: builder(limits())
                            },
                            mount_limits: cap
                        },
                        recorder
                    ),
                    Err(RuntimeError::InvalidConfiguration)
                ));
            }
            assert!(server.requests().is_empty());
            assert_eq!(parent.children(), 0);
        }
        #[cfg(feature = "launch-preparation-mount")]
        #[tokio::test]
        async fn mounted_runtime_failed_mount_or_view_is_terminal_and_never_reunwraps() {
            let server = Server::new();
            let image =
                ContentFixture::new_with_tar(1, false, &server.repository(), tar(&elf(), 0o755));
            let signature = server.image(&image);
            let parent = StagingFixtureParent::new();
            let factory = RuntimeFactory::new(server.client(), 1, Duration::from_secs(15)).unwrap();
            let (checked, recorder, signer) =
                checked_inputs(&image, &parent, signature, spec("/")).await;
            let mut caps = mount_limits();
            caps.view.inodes = 1; // Two-inode fixture cannot pass mounted inventory even on a privileged host.
            let mut attempt = factory
                .begin_mounted_attempt(
                    MountedRuntimeAttemptConfig {
                        erofs: ErofsRuntimeAttemptConfig {
                            checked,
                            builder: builder(limits()),
                        },
                        mount_limits: caps,
                    },
                    recorder,
                )
                .unwrap();
            let delivery = signer.delivery(attempt.challenge_nonce());
            let trace = Arc::new(Mutex::new(Trace::default()));
            assert!(attempt.summary().is_err());
            assert_eq!(
                attempt
                    .prepare_fixture(delivery.borrowed(), image.replies(), trace.clone())
                    .await,
                Err(RuntimeError::MountRejected)
            );
            assert!(attempt.summary().is_err());
            let requests = server.requests();
            assert_eq!(
                attempt.prepare(delivery.borrowed()).await,
                Err(RuntimeError::Unavailable)
            );
            assert_eq!(server.requests(), requests);
            assert_eq!(trace.lock().unwrap().calls.len(), 1);
            attempt.cancel_and_wait().await.unwrap();
            assert_eq!(parent.children(), 0);
        }
        // This separate opt-in native gate must run with initial-userns mount
        // privilege and registered EROFS. It never treats missing privilege as a skip.
        #[cfg(feature = "launch-preparation-mount-native")]
        #[tokio::test]
        async fn native_mounted_runtime_retains_view_and_historical_delivery_without_rebuild() {
            let server = Server::new();
            let image =
                ContentFixture::new_with_tar(2, true, &server.repository(), tar(&elf(), 0o755));
            let signature = server.image(&image);
            let parent = StagingFixtureParent::new();
            let factory = RuntimeFactory::new(server.client(), 1, Duration::from_secs(20)).unwrap();
            let (checked, recorder, signer) =
                checked_inputs(&image, &parent, signature, spec("/")).await;
            let mut attempt = factory
                .begin_mounted_attempt(
                    MountedRuntimeAttemptConfig {
                        erofs: ErofsRuntimeAttemptConfig {
                            checked,
                            builder: builder(limits()),
                        },
                        mount_limits: mount_limits(),
                    },
                    recorder,
                )
                .unwrap();
            let mut delivery = signer.delivery(attempt.challenge_nonce());
            let trace = Arc::new(Mutex::new(Trace::default()));
            assert_eq!(
                attempt
                    .prepare_fixture(delivery.borrowed(), image.replies(), trace.clone())
                    .await,
                Ok(ContentBinding::FirstChecked)
            );
            let summary = attempt.summary().unwrap();
            assert_eq!(summary.view().backing().inodes(), 2);
            assert_eq!(summary.view().backing_adapter(), "private-ro-ramfs-v1");
            assert_ne!(summary.view().mount_id(), 0);
            assert_eq!(
                summary.view().executable().executable_sha384(),
                hash384(&elf())
            );
            #[cfg(feature = "launch-preparation-offer")]
            {
                use execution_proof_handoff::{
                    fd_transport::{FdExpectation, PrivateFdChannel, SendOutcome},
                    rootfs_offer::{ReceiverTransfer, RootfsOfferDraft, SenderStatus},
                };
                let expected: Signed<AdmissionAuthorizationV1> =
                    serde_json::from_slice(&delivery.receipt).unwrap();
                let decode = |hex: &str| -> [u8; 48] {
                    std::array::from_fn(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap())
                };
                let (producer, mut receiver) = PrivateFdChannel::pair().unwrap();
                let sent = attempt.begin_rootfs_offer(producer, 1 << 20).await.unwrap();
                let (wire, descriptor) = receiver
                    .try_receive(FdExpectation::One)
                    .unwrap()
                    .unwrap()
                    .into_parts();
                let draft = RootfsOfferDraft::decode(&wire, 1 << 20).unwrap();
                assert_eq!(&draft, sent.draft());
                assert_eq!(
                    draft.backing().sha384,
                    *summary.view().backing().image_sha384()
                );
                let origin = image_rs::preparation::SealedImageBytes::from_received_fd(
                    descriptor.unwrap(),
                    1 << 20,
                    draft.backing().sha384,
                )
                .unwrap();
                assert_eq!(origin.byte_len(), summary.view().backing().byte_len());
                let mut received = ReceiverTransfer::new(
                    decode(&expected.statement.context_sha384),
                    decode(&expected.statement.binding.effective_launch_sha384),
                    1 << 20,
                )
                .unwrap();
                received.receive(draft).unwrap();
                assert_eq!(
                    receiver.try_send(&received.receipt().unwrap().encode(), None),
                    Ok(SendOutcome::Sent),
                );
                assert_eq!(
                    attempt.poll_rootfs_offer().await.unwrap().status(),
                    SenderStatus::EnvelopeReceived,
                );
                assert_eq!(
                    attempt.retry_rootfs_offer().await.unwrap().status(),
                    SenderStatus::EnvelopeReceived,
                );
                assert!(receiver.try_receive(FdExpectation::One).unwrap().is_none());
                assert_eq!(attempt.summary().unwrap(), summary);
            }
            let requests = server.requests();
            assert_eq!(
                attempt.prepare(delivery.borrowed()).await,
                Ok(ContentBinding::Historical)
            );
            assert_eq!(attempt.summary().unwrap(), summary);
            assert_eq!(trace.lock().unwrap().calls.len(), 2);
            assert_eq!(server.requests(), requests);
            delivery.receipt.push(b' ');
            assert_eq!(
                attempt.prepare(delivery.borrowed()).await,
                Err(RuntimeError::Conflict)
            );
            assert!(attempt.summary().is_err());
            attempt.cancel_and_wait().await.unwrap();
            assert_eq!(parent.children(), 0);
        }
        unsafe extern "C" {
            #[link_name = "waitpid"]
            fn image_rs_nix_waitpid(pid: i32, status: *mut i32, options: i32) -> i32;
        }
    }
}
