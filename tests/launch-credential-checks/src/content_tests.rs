//! Signed admission, Cosign verification, AES encryption/decryption, complete
//! digest/authentication checks, and sealed TAR bytes.
//! A private test resolver supplies ephemeral private options. Cloud KMS,
//! provider authentication, rootfs leases, and launch are outside this suite.

use crate::launch_preparation::fixture::{Reply, Trace};
use crate::{cdh_tests::content_preparation_fixture, launch_preparation::*};
use base64::{Engine, engine::general_purpose::STANDARD};
use image_rs::preparation::{
    layer_content::LayerContentLimits,
    manifest_signature::{RequiredCosignPolicy, SignatureLimits},
    rootfs_staging::{PrivateStagingParent, RootfsStagingLimits},
};
use ocicrypt_rs::blockcipher::{
    AES256CTR, EncryptionFinalizer, LayerBlockCipherHandler, LayerBlockCipherOptions,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256, Sha384};
use sigstore::crypto::SigningScheme;
use std::{
    future::Future,
    io::{Read, Write},
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
};
use zeroize::Zeroizing;

const REPOSITORY: &str = "registry.example/owner/image";
const KEY: &str =
    "projects/project-1/locations/us-central1/keyRings/ring/cryptoKeys/key/cryptoKeyVersions/1";
const PACKET: &str = "org.opencontainers.image.enc.keys.provider.attestation-agent";
const PUBLIC: &str = "org.opencontainers.image.enc.pubopts";

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

fn tar_bytes() -> Vec<u8> {
    let mut header = [0u8; 512];
    header[..3].copy_from_slice(b"app");
    for (start, len, number) in [
        (100, 8, 0o755u64),
        (108, 8, 0),
        (116, 8, 0),
        (124, 12, 7),
        (136, 12, 0),
        (329, 8, 0),
        (337, 8, 0),
    ] {
        let value = format!("{number:0width$o}\0", width = len - 1);
        header[start..start + len].copy_from_slice(value.as_bytes());
    }
    header[156] = b'0';
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");
    header[148..156].fill(b' ');
    let checksum: u64 = header.iter().map(|b| u64::from(*b)).sum();
    header[148..156].copy_from_slice(format!("{checksum:06o}\0 ").as_bytes());
    let mut bytes = header.to_vec();
    bytes.extend_from_slice(b"payload");
    bytes.resize(1024, 0);
    bytes.resize(2048, 0);
    bytes
}

fn packet(key: &str, ciphertext: &[u8]) -> String {
    STANDARD.encode(serde_json::to_vec(&json!({"kid":format!("kbs:///default/key/{}",key.replace('/',"%2F")),
        "wrapped_data":STANDARD.encode(format!("gcp:{}",STANDARD.encode(ciphertext))),"iv":"","wrap_type":"KMS-DIRECT"})).unwrap())
}

pub(crate) struct ContentFixture {
    pub(crate) manifest: Vec<u8>,
    pub(crate) config: Vec<u8>,
    pub(crate) policy: Vec<u8>,
    pub(crate) payload: Vec<u8>,
    pub(crate) signature: Vec<u8>,
    pub(crate) ciphertexts: Vec<Vec<u8>>,
    pub(crate) private_options: Vec<Vec<u8>>,
    pub(crate) tar: Vec<u8>,
    repository: String,
}

pub(crate) fn signature_limits() -> SignatureLimits {
    SignatureLimits {
        policy_bytes: 16384,
        key_bytes: 4096,
        manifest_bytes: 131072,
        payload_bytes: 16384,
        signature_bytes: 128,
        json_depth: 16,
    }
}
pub(crate) fn metadata_limits() -> PreparationLimits {
    PreparationLimits {
        manifest_bytes: 131072,
        config_bytes: 16384,
        layer_count: 4,
        packets_per_layer: 4,
        packet_bytes: 4096,
        public_options_bytes: 2048,
        kms_ciphertext_bytes: 1024,
        operations: 4,
    }
}
pub(crate) fn content_limits() -> ImageContentLimits {
    ImageContentLimits {
        layer: LayerContentLimits {
            ciphertext_bytes: 16384,
            private_options_bytes: 4096,
            public_options_bytes: 2048,
            plaintext_bytes: 16384,
            tar_bytes: 16384,
            tar_entries: 8,
            path_bytes: 256,
            file_bytes: 4096,
        },
        total_ciphertext_bytes: 65536,
        total_tar_bytes: 65536,
    }
}

impl ContentFixture {
    fn new(count: usize, gzip: bool) -> Self {
        Self::new_for_repository(count, gzip, REPOSITORY)
    }
    pub(crate) fn new_for_repository(count: usize, gzip: bool, repository: &str) -> Self {
        Self::new_with_tar(count, gzip, repository, tar_bytes())
    }
    pub(crate) fn new_with_tar(count: usize, gzip: bool, repository: &str, tar: Vec<u8>) -> Self {
        let plaintext = if gzip {
            let mut encoder =
                flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            encoder.write_all(&tar).unwrap();
            encoder.finish().unwrap()
        } else {
            tar.clone()
        };
        let mut options = LayerBlockCipherOptions::default();
        let mut cipher = LayerBlockCipherHandler::default();
        cipher
            .encrypt(plaintext.as_slice(), AES256CTR, &mut options)
            .unwrap();
        let mut ciphertext = Vec::new();
        cipher.read_to_end(&mut ciphertext).unwrap();
        cipher.finalized_lbco(&mut options).unwrap();
        options.private.digest = format!("sha256:{}", hash256(&plaintext));
        let private_options = serde_json::to_vec(&options.private).unwrap();
        let public = STANDARD.encode(serde_json::to_vec(&options.public).unwrap());
        let config = serde_json::to_vec(&json!({"os":"linux","architecture":"amd64",
            "rootfs":{"type":"layers","diff_ids":vec![format!("sha256:{}",hash256(&tar));count]}}))
        .unwrap();
        let layers: Vec<_> = (0..count).map(|index| json!({"mediaType":if gzip {"application/vnd.oci.image.layer.v1.tar+gzip+encrypted"} else {"application/vnd.oci.image.layer.v1.tar+encrypted"},
            "digest":format!("sha256:{}",hash256(&ciphertext)),"size":ciphertext.len(),
            "annotations":{PUBLIC:public,PACKET:format!("{},{}",packet(&KEY.replace("/1","/2"),b"not-selected"),packet(KEY,format!("selected-kms-{index}").as_bytes()))}})).collect();
        let manifest = serde_json::to_vec(&json!({"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json",
            "config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":format!("sha256:{}",hash256(&config)),"size":config.len()},"layers":layers})).unwrap();
        let signer = SigningScheme::ECDSA_P256_SHA256_ASN1
            .create_signer()
            .unwrap();
        let key = signer
            .to_sigstore_keypair()
            .unwrap()
            .public_key_to_pem()
            .unwrap();
        let mut policy = json!({"default":[{"type":"reject"}],"transports":{"docker":{}}});
        policy["transports"]["docker"][repository] = json!([{"type":"sigstoreSigned","keyData":STANDARD.encode(key.as_bytes()),
            "signedIdentity":{"type":"exactRepository","dockerRepository":repository}}]);
        let policy = serde_json::to_vec(&policy).unwrap();
        let payload = serde_json::to_vec(&json!({"critical":{"type":"cosign container image signature",
            "identity":{"docker-reference":repository},"image":{"docker-manifest-digest":format!("sha256:{}",hash256(&manifest))}},"optional":null})).unwrap();
        let signature = signer.sign(&payload).unwrap();
        Self {
            manifest,
            config,
            policy,
            payload,
            signature,
            ciphertexts: vec![ciphertext; count],
            private_options: vec![private_options; count],
            tar,
            repository: repository.into(),
        }
    }
    pub(crate) fn verifier(&self) -> RequiredCosignPolicy {
        RequiredCosignPolicy::new(
            &self.policy,
            &hash384(&self.policy),
            &self.repository,
            signature_limits(),
        )
        .unwrap()
    }
    fn blobs(&self) -> Vec<&[u8]> {
        self.ciphertexts.iter().map(Vec::as_slice).collect()
    }
    pub(crate) fn replies(&self) -> Vec<Reply> {
        self.private_options
            .iter()
            .map(|bytes| Reply::Options(Zeroizing::new(bytes.clone())))
            .collect()
    }
    async fn attempt(&self, limits: ImageContentLimits) -> PreparationAttempt {
        self.attempt_with_staging(limits, None).await
    }
    async fn attempt_with_staging(
        &self,
        limits: ImageContentLimits,
        staging: Option<(PrivateStagingParent, RootfsStagingLimits)>,
    ) -> PreparationAttempt {
        let (credential, trusted, admission) =
            content_preparation_fixture(hash256(&self.manifest), hash384(&self.policy)).await;
        let profile = PreparationProfile {
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
        };
        let mut attempt = match staging {
            Some((parent, staging_limits)) => PreparationAttempt::new_with_staging(
                admission,
                credential,
                profile,
                metadata_limits(),
                limits,
                parent,
                staging_limits,
            ),
            None => PreparationAttempt::new_with_content(
                admission,
                credential,
                profile,
                metadata_limits(),
                limits,
            ),
        }
        .unwrap();
        assert_eq!(
            attempt.bind_manifest(&self.manifest, &self.config),
            Ok(ManifestBinding::FirstBound)
        );
        attempt
    }
    async fn signed_attempt(&self, limits: ImageContentLimits) -> PreparationAttempt {
        let mut attempt = self.attempt(limits).await;
        assert_eq!(
            attempt.verify_image_signature(self.verifier(), &self.payload, &self.signature),
            Ok(ContentBinding::FirstChecked)
        );
        attempt
    }
}

#[tokio::test]
async fn mandatory_signature_and_admitted_policy_are_checked_before_content() {
    let f = ContentFixture::new(1, false);
    let trace = Arc::new(Mutex::new(Trace::default()));
    let mut attempt = f.attempt(content_limits()).await;
    assert_eq!(
        attempt
            .prepare_layers_fixture(&f.blobs(), f.replies(), trace.clone())
            .await,
        Err(PreparationError::NotReady)
    );
    assert!(trace.lock().unwrap().calls.is_empty());
    assert_eq!(
        attempt.verify_image_signature(f.verifier(), &f.payload, &f.signature),
        Err(PreparationError::Unavailable)
    );

    let other = ContentFixture::new(1, false);
    let mut attempt = f.attempt(content_limits()).await;
    assert_eq!(
        attempt.verify_image_signature(other.verifier(), &f.payload, &f.signature),
        Err(PreparationError::ScopeMismatch)
    );
    assert!(attempt.manifest_plan().is_err());

    let mut attempt = f.attempt(content_limits()).await;
    let mut bad_signature = f.signature.clone();
    bad_signature[0] ^= 1;
    assert_eq!(
        attempt.verify_image_signature(f.verifier(), &f.payload, &bad_signature),
        Err(PreparationError::SignatureRejected)
    );
    assert!(attempt.image_signature().is_err());
}

#[tokio::test]
async fn actual_encrypted_duplicate_descriptors_check_original_operations_and_retry_metadata_only()
{
    let f = ContentFixture::new(2, true);
    let mut attempt = f.signed_attempt(content_limits()).await;
    assert!(attempt.content_summary().is_err());
    let trace = Arc::new(Mutex::new(Trace::default()));
    assert_eq!(
        attempt
            .prepare_layers_fixture(&f.blobs(), f.replies(), trace.clone())
            .await,
        Ok(ContentBinding::FirstChecked)
    );
    let summary = attempt.content_summary().unwrap();
    assert_eq!(summary.manifest_sha256(), hash256(&f.manifest));
    assert_eq!(summary.policy_sha384(), hash384(&f.policy));
    assert_eq!(summary.total_tar_bytes(), 2 * f.tar.len());
    assert_eq!(summary.total_ciphertext_bytes(), 2 * f.ciphertexts[0].len());
    assert_eq!(summary.layers().len(), 2);
    for (index, layer) in summary.layers().iter().enumerate() {
        assert_eq!(layer.original_index(), index as u32);
        assert_eq!(layer.tar_sha384(), hash384(&f.tar));
        assert_eq!(layer.diff_id(), format!("sha256:{}", hash256(&f.tar)));
        assert_eq!(layer.tar_entries(), 1);
        assert_eq!(layer.tar_bytes(), f.tar.len() as u64);
    }
    {
        let observed = trace.lock().unwrap();
        assert_eq!(observed.calls.len(), 2);
        for (index, (actual_index, digest, kms_digest)) in observed.calls.iter().enumerate() {
            assert_eq!(*actual_index, index as u32);
            assert_eq!(digest, &hash256(&f.ciphertexts[index]));
            assert_eq!(
                kms_digest,
                &hash384(format!("selected-kms-{index}").as_bytes())
            );
        }
    }
    assert_eq!(
        attempt.prepare_layers(&f.blobs()).await,
        Ok(ContentBinding::Historical)
    );
    assert_eq!(
        attempt.verify_image_signature(f.verifier(), &f.payload, &f.signature),
        Ok(ContentBinding::Historical)
    );
    assert_eq!(
        attempt.bind_manifest(&f.manifest, &f.config),
        Ok(ManifestBinding::Historical)
    );
    let mut changed = f.ciphertexts.clone();
    changed[1][0] ^= 1;
    let changed: Vec<_> = changed.iter().map(Vec::as_slice).collect();
    assert_eq!(
        attempt.prepare_layers(&changed).await,
        Err(PreparationError::Conflict)
    );
    assert!(attempt.content_summary().is_err());
    assert_eq!(
        attempt.prepare_layers(&f.blobs()).await,
        Err(PreparationError::Unavailable)
    );
}

#[tokio::test]
async fn whole_blob_and_aggregate_ciphertext_limits_reject_before_any_resolver_call() {
    let f = ContentFixture::new(2, false);
    for case in ["count", "changed", "aggregate"] {
        let mut limits = content_limits();
        if case == "aggregate" {
            limits.total_ciphertext_bytes = f.ciphertexts.iter().map(Vec::len).sum::<usize>() - 1;
        }
        let mut attempt = f.signed_attempt(limits).await;
        let trace = Arc::new(Mutex::new(Trace::default()));
        let mut blobs = f.ciphertexts.clone();
        if case == "count" {
            blobs.pop();
        }
        if case == "changed" {
            blobs[0].push(0);
        }
        let refs: Vec<_> = blobs.iter().map(Vec::as_slice).collect();
        assert!(
            attempt
                .prepare_layers_fixture(&refs, f.replies(), trace.clone())
                .await
                .is_err(),
            "{case}"
        );
        assert!(trace.lock().unwrap().calls.is_empty(), "{case}");
        assert!(attempt.manifest_plan().is_err(), "{case}");
        assert_eq!(
            attempt.prepare_layers(&f.blobs()).await,
            Err(PreparationError::Unavailable)
        );
    }
}

#[tokio::test]
async fn authentication_failure_or_missing_operation_never_publishes_partial_success() {
    let f = ContentFixture::new(2, false);
    for case in ["key", "provider", "extra", "missing"] {
        let mut attempt = f.signed_attempt(content_limits()).await;
        let trace = Arc::new(Mutex::new(Trace::default()));
        let mut replies = f.replies();
        match case {
            "key" => {
                let mut raw: Value = serde_json::from_slice(&f.private_options[1]).unwrap();
                raw["symkey"] = STANDARD.encode([0; 32]).into();
                replies[1] = Reply::Options(Zeroizing::new(serde_json::to_vec(&raw).unwrap()));
            }
            "provider" => replies[1] = Reply::Fail,
            "extra" => replies.push(Reply::Fail),
            "missing" => {
                replies.pop();
            }
            _ => unreachable!(),
        }
        assert_eq!(
            attempt
                .prepare_layers_fixture(&f.blobs(), replies, trace.clone())
                .await,
            Err(PreparationError::ContentRejected),
            "{case}"
        );
        assert!(attempt.content_summary().is_err(), "{case}");
        assert_eq!(
            attempt.prepare_layers(&f.blobs()).await,
            Err(PreparationError::Unavailable)
        );
    }
}

#[tokio::test]
async fn dropping_pending_content_future_is_terminal_after_a_real_first_layer_check() {
    let f = ContentFixture::new(2, false);
    let mut attempt = f.signed_attempt(content_limits()).await;
    let trace = Arc::new(Mutex::new(Trace::default()));
    let mut replies = f.replies();
    replies[1] = Reply::Pending;
    let blobs = f.blobs();
    {
        let mut future = Box::pin(attempt.prepare_layers_fixture(&blobs, replies, trace.clone()));
        let mut cx = Context::from_waker(Waker::noop());
        assert!(matches!(future.as_mut().poll(&mut cx), Poll::Pending));
        assert_eq!(trace.lock().unwrap().calls.len(), 2);
        // Drop synchronously disposes the first real sealed TAR and local resolver.
    }
    assert!(attempt.content_summary().is_err());
    assert_eq!(
        attempt.prepare_layers(&blobs).await,
        Err(PreparationError::Unavailable)
    );
    assert_eq!(
        attempt.verify_image_signature(f.verifier(), &f.payload, &f.signature),
        Err(PreparationError::Unavailable)
    );
}

#[tokio::test]
async fn aggregate_tar_cap_and_signature_retry_conflict_are_terminal() {
    let f = ContentFixture::new(2, true);
    for (budget, expected_calls) in [
        (f.tar.len(), 1),
        (f.tar.len() + 1023, 1),
        (2 * f.tar.len() - 1, 2),
    ] {
        let mut limits = content_limits();
        limits.total_tar_bytes = budget;
        let mut attempt = f.signed_attempt(limits).await;
        let trace = Arc::new(Mutex::new(Trace::default()));
        assert!(
            attempt
                .prepare_layers_fixture(&f.blobs(), f.replies(), trace.clone())
                .await
                .is_err()
        );
        assert_eq!(trace.lock().unwrap().calls.len(), expected_calls);
        assert!(attempt.content_summary().is_err());
        assert_eq!(
            attempt.prepare_layers(&f.blobs()).await,
            Err(PreparationError::Unavailable)
        );
    }
    let mut attempt = f.signed_attempt(content_limits()).await;
    let mut payload = f.payload.clone();
    payload.push(b' ');
    assert_eq!(
        attempt.verify_image_signature(f.verifier(), &payload, &f.signature),
        Err(PreparationError::Conflict)
    );
    assert!(attempt.image_signature().is_err());
}

#[tokio::test]
async fn invalid_content_budgets_are_rejected_by_constructor_before_provider_creation() {
    let f = ContentFixture::new(1, false);
    for case in ["zero", "oversize-layer", "oversize-total", "short-tar"] {
        let mut limits = content_limits();
        match case {
            "zero" => limits.layer.public_options_bytes = 0,
            "oversize-layer" => limits.layer.private_options_bytes = usize::MAX,
            "oversize-total" => limits.total_ciphertext_bytes = usize::MAX,
            "short-tar" => limits.total_tar_bytes = 1023,
            _ => unreachable!(),
        }
        let (credential, trusted, admission) =
            content_preparation_fixture(hash256(&f.manifest), hash384(&f.policy)).await;
        let profile = PreparationProfile {
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
        };
        assert!(
            matches!(
                PreparationAttempt::new_with_content(
                    admission,
                    credential,
                    profile,
                    metadata_limits(),
                    limits
                ),
                Err(PreparationError::InvalidConfiguration)
            ),
            "{case}"
        );
    }
}

// Fixtures own their temporary parent directories. The production API requires
// a separately provisioned and validated parent FD.
pub(crate) struct StagingFixtureParent(std::path::PathBuf);
impl StagingFixtureParent {
    pub(crate) fn new() -> Self {
        use std::os::unix::fs::DirBuilderExt;
        use std::sync::atomic::{AtomicUsize, Ordering};
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        for _ in 0..32 {
            let path = std::env::temp_dir().join(format!(
                "onb17-cdh-staging-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match std::fs::DirBuilder::new().mode(0o700).create(&path) {
                Ok(()) => return Self(path),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("private fixture parent creation failed: {error}"),
            }
        }
        panic!("private fixture parent names exhausted")
    }
    pub(crate) fn capability(&self) -> PrivateStagingParent {
        PrivateStagingParent::new(std::fs::File::open(&self.0).unwrap()).unwrap()
    }
    pub(crate) fn children(&self) -> usize {
        std::fs::read_dir(&self.0).unwrap().count()
    }
}
impl Drop for StagingFixtureParent {
    fn drop(&mut self) {
        // Explicit assertions below check disposal; avoid double panic if an
        // earlier assertion failed, and never recursively erase unknown paths.
        let _ = std::fs::remove_dir(&self.0);
    }
}

pub(crate) fn staging_limits() -> RootfsStagingLimits {
    RootfsStagingLimits {
        layers: 4,
        total_tar_bytes: 65536,
        applied_entries: 32,
        inodes: 32,
        write_bytes: 16384,
        live_file_bytes: 8192,
        path_bytes: 256,
        path_components: 16,
    }
}

async fn checked_staging_attempt(
    fixture: &ContentFixture,
    parent: &StagingFixtureParent,
    limits: RootfsStagingLimits,
) -> (PreparationAttempt, Arc<Mutex<Trace>>) {
    let mut attempt = fixture
        .attempt_with_staging(content_limits(), Some((parent.capability(), limits)))
        .await;
    assert_eq!(
        attempt.verify_image_signature(fixture.verifier(), &fixture.payload, &fixture.signature),
        Ok(ContentBinding::FirstChecked)
    );
    let trace = Arc::new(Mutex::new(Trace::default()));
    assert_eq!(
        attempt
            .prepare_layers_fixture(&fixture.blobs(), fixture.replies(), trace.clone())
            .await,
        Ok(ContentBinding::FirstChecked)
    );
    assert_eq!(parent.children(), 0);
    (attempt, trace)
}

#[tokio::test]
async fn staging_owns_checked_layers_and_all_exact_retries_preserve_one_tree() {
    let fixture = ContentFixture::new(2, true);
    let parent = StagingFixtureParent::new();
    let (mut attempt, trace) = checked_staging_attempt(&fixture, &parent, staging_limits()).await;
    assert!(attempt.rootfs_staging_summary().is_err());
    assert_eq!(attempt.stage_rootfs(), Ok(ContentBinding::FirstChecked));
    assert_eq!(parent.children(), 1);
    let summary = attempt.rootfs_staging_summary().unwrap();
    assert_eq!(summary.layers(), 2);
    assert_eq!(summary.total_tar_bytes(), 2 * fixture.tar.len());
    assert_eq!(summary.applied_entries(), 2);
    assert_eq!(summary.inodes(), 2); // staging root plus app
    assert_eq!(summary.write_bytes(), 14);
    assert_eq!(summary.live_file_bytes(), 7);
    assert_eq!(attempt.stage_rootfs(), Ok(ContentBinding::Historical));
    assert_eq!(
        attempt.verify_image_signature(fixture.verifier(), &fixture.payload, &fixture.signature),
        Ok(ContentBinding::Historical)
    );
    assert_eq!(
        attempt.bind_manifest(&fixture.manifest, &fixture.config),
        Ok(ManifestBinding::Historical)
    );
    assert_eq!(
        attempt.prepare_layers(&fixture.blobs()).await,
        Ok(ContentBinding::Historical)
    );
    assert_eq!(attempt.content_summary().unwrap().layers().len(), 2);
    assert_eq!(attempt.manifest_plan().unwrap().layers().len(), 2);
    assert_eq!(
        attempt.image_signature().unwrap().manifest_sha256(),
        hash256(&fixture.manifest)
    );
    assert_eq!(trace.lock().unwrap().calls.len(), 2);
    assert_eq!(parent.children(), 1);
    attempt.cancel();
    assert_eq!(parent.children(), 0);
    assert_eq!(attempt.stage_rootfs(), Err(PreparationError::Unavailable));
    assert!(attempt.rootfs_staging_summary().is_err());
}

#[tokio::test]
async fn staging_conflicting_retries_are_terminal_and_dispose_the_private_tree() {
    let fixture = ContentFixture::new(1, false);
    for operation in ["manifest", "signature", "ciphertext"] {
        let parent = StagingFixtureParent::new();
        let (mut attempt, trace) =
            checked_staging_attempt(&fixture, &parent, staging_limits()).await;
        assert_eq!(attempt.stage_rootfs(), Ok(ContentBinding::FirstChecked));
        assert_eq!(parent.children(), 1);
        match operation {
            "manifest" => {
                let mut changed = fixture.manifest.clone();
                changed.push(b' ');
                assert_eq!(
                    attempt.bind_manifest(&changed, &fixture.config),
                    Err(PreparationError::Conflict)
                );
            }
            "signature" => {
                let mut changed = fixture.signature.clone();
                changed[0] ^= 1;
                assert_eq!(
                    attempt.verify_image_signature(fixture.verifier(), &fixture.payload, &changed),
                    Err(PreparationError::Conflict)
                );
            }
            "ciphertext" => {
                let mut changed = fixture.ciphertexts[0].clone();
                changed[0] ^= 1;
                assert_eq!(
                    attempt.prepare_layers(&[&changed]).await,
                    Err(PreparationError::Conflict)
                );
            }
            _ => unreachable!(),
        }
        assert_eq!(parent.children(), 0, "{operation}");
        assert_eq!(trace.lock().unwrap().calls.len(), 1);
        assert!(attempt.rootfs_staging_summary().is_err());
        assert!(attempt.content_summary().is_err());
        assert_eq!(attempt.stage_rootfs(), Err(PreparationError::Unavailable));
    }
}

#[tokio::test]
async fn staging_without_content_or_constructor_provisioning_fails_closed() {
    let fixture = ContentFixture::new(1, false);
    let parent = StagingFixtureParent::new();
    let mut attempt = fixture
        .attempt_with_staging(
            content_limits(),
            Some((parent.capability(), staging_limits())),
        )
        .await;
    assert_eq!(attempt.stage_rootfs(), Err(PreparationError::NotReady));
    assert_eq!(parent.children(), 0);
    assert_eq!(
        attempt.verify_image_signature(fixture.verifier(), &fixture.payload, &fixture.signature),
        Err(PreparationError::Unavailable)
    );

    let mut attempt = fixture.signed_attempt(content_limits()).await;
    let trace = Arc::new(Mutex::new(Trace::default()));
    assert_eq!(
        attempt
            .prepare_layers_fixture(&fixture.blobs(), fixture.replies(), trace)
            .await,
        Ok(ContentBinding::FirstChecked)
    );
    assert_eq!(
        attempt.stage_rootfs(),
        Err(PreparationError::InvalidConfiguration)
    );
    assert!(attempt.content_summary().is_err());
    assert_eq!(attempt.stage_rootfs(), Err(PreparationError::Unavailable));
}

#[tokio::test]
async fn staging_work_budget_failure_and_drop_cleanup_never_publish_a_lease() {
    let fixture = ContentFixture::new(2, false);
    let parent = StagingFixtureParent::new();
    let mut limits = staging_limits();
    limits.write_bytes = 13; // two 7-byte writes, even though final app is 7 bytes
    let (mut attempt, trace) = checked_staging_attempt(&fixture, &parent, limits).await;
    assert_eq!(
        attempt.stage_rootfs(),
        Err(PreparationError::StagingRejected)
    );
    assert_eq!(parent.children(), 0);
    assert!(attempt.rootfs_staging_summary().is_err());
    assert_eq!(attempt.stage_rootfs(), Err(PreparationError::Unavailable));
    assert_eq!(trace.lock().unwrap().calls.len(), 2);

    let (mut attempt, _) = checked_staging_attempt(&fixture, &parent, staging_limits()).await;
    assert_eq!(attempt.stage_rootfs(), Ok(ContentBinding::FirstChecked));
    assert_eq!(parent.children(), 1);
    drop(attempt);
    assert_eq!(parent.children(), 0);
}
