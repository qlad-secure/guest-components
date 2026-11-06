use super::*;
use execution_proof_handoff::{
    fd_transport::{FdExpectation, PrivateFdChannel, SendOutcome, TransportError},
    rootfs_offer::{OfferError, OfferProgress, ReceiverTransfer, RootfsOfferDraft, SenderStatus},
};
use image_rs::preparation::SealedImageBytes;
use std::os::{
    fd::{AsFd, AsRawFd},
    unix::fs::MetadataExt,
};

const OFFER_BYTES: u64 = 1 << 20;

fn digest_bytes(hex: &str) -> [u8; 48] {
    assert_eq!(hex.len(), 96);
    std::array::from_fn(|index| u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).unwrap())
}

struct OfferFixture {
    server: Server,
    image: ContentFixture,
    parent: StagingFixtureParent,
    factory: RuntimeFactory,
    attempt: ErofsRuntimeAttempt,
    delivery: Delivery,
    trace: Arc<Mutex<Trace>>,
    signature: String,
    expected_context: [u8; 48],
    expected_spec: [u8; 48],
    layers: usize,
}

impl OfferFixture {
    async fn new(layers: usize) -> Self {
        let server = Server::new();
        let image = ContentFixture::new_with_tar(
            layers,
            layers > 1,
            &server.repository(),
            tar(&elf(), 0o755),
        );
        let signature = server.image(&image);
        let parent = StagingFixtureParent::new();
        let factory = RuntimeFactory::new(server.client(), 1, Duration::from_secs(30)).unwrap();
        let raw = spec("/");
        let (checked, recorder, signer) =
            checked_inputs(&image, &parent, signature.clone(), raw.clone()).await;
        let attempt = factory
            .begin_erofs_attempt(
                ErofsRuntimeAttemptConfig {
                    checked,
                    builder: builder(limits()),
                },
                recorder,
            )
            .unwrap();
        // Expectations belong to the independently configured signed admission
        // fixture. They are derived before receiving any offer or descriptor.
        let expected_context = digest_bytes(
            &policy_admission_context(
                &signer.grant,
                &signer.aggregate,
                attempt.challenge_nonce(),
                &signer.policy,
            )
            .unwrap(),
        );
        let expected_spec = Sha384::digest(&raw).into();
        let delivery = signer.delivery(attempt.challenge_nonce());
        Self {
            server,
            image,
            parent,
            factory,
            attempt,
            delivery,
            trace: Arc::new(Mutex::new(Trace::default())),
            signature,
            expected_context,
            expected_spec,
            layers,
        }
    }

    async fn prepare(&mut self) {
        assert_eq!(
            self.attempt
                .prepare_fixture(
                    self.delivery.borrowed(),
                    self.image.replies(),
                    self.trace.clone()
                )
                .await,
            Ok(ContentBinding::FirstChecked)
        );
        assert_eq!(self.parent.children(), 1);
    }

    async fn next(&self) -> (ErofsRuntimeAttemptConfig, LaunchRecorder) {
        let (checked, recorder, _) =
            checked_inputs(&self.image, &self.parent, self.signature.clone(), spec("/")).await;
        (
            ErofsRuntimeAttemptConfig {
                checked,
                builder: builder(limits()),
            },
            recorder,
        )
    }

    async fn assert_terminal_cleanup(&mut self, requests: &[String]) {
        assert!(self.attempt.summary().is_err());
        assert_eq!(
            self.attempt.retry_rootfs_offer().await,
            Err(RootfsOfferError::Unavailable)
        );
        assert_eq!(
            self.attempt.prepare(self.delivery.borrowed()).await,
            Err(RuntimeError::Unavailable)
        );
        self.attempt.cancel_and_wait().await.unwrap();
        assert_eq!(self.parent.children(), 0);
        assert_eq!(self.server.requests(), requests);
        assert_eq!(self.trace.lock().unwrap().calls.len(), self.layers);
    }
}

fn receive_source(channel: &mut PrivateFdChannel) -> (RootfsOfferDraft, SealedImageBytes) {
    let (bytes, descriptor) = channel
        .try_receive(FdExpectation::One)
        .unwrap()
        .expect("worker replied only after its complete descriptor packet")
        .into_parts();
    let draft = RootfsOfferDraft::decode(&bytes, OFFER_BYTES).unwrap();
    let source = SealedImageBytes::from_received_fd(
        descriptor.unwrap(),
        OFFER_BYTES,
        draft.backing().sha384,
    )
    .unwrap();
    assert_eq!(source.byte_len(), draft.backing().byte_len);
    (draft, source)
}

fn inode_identity(source: &SealedImageBytes) -> (u64, u64) {
    let metadata =
        std::fs::metadata(format!("/proc/self/fd/{}", source.as_fd().as_raw_fd())).unwrap();
    (metadata.dev(), metadata.ino())
}

fn descriptor_aliases(identity: (u64, u64)) -> usize {
    std::fs::read_dir("/proc/self/fd")
        .unwrap()
        .map(|entry| entry.unwrap().path())
        // Other test/runtime threads may close unrelated descriptors during
        // enumeration. Only the stable, uniquely identified source inode counts.
        .filter_map(|path| std::fs::metadata(path).ok())
        .filter(|metadata| (metadata.dev(), metadata.ino()) == identity)
        .count()
}

#[tokio::test]
async fn rootfs_offer_retains_one_identity_and_envelope_receipt_does_no_preparation_work() {
    let mut fixture = OfferFixture::new(2).await;
    fixture.prepare().await;
    let summary = fixture.attempt.summary().unwrap();
    let requests = fixture.server.requests();
    let (sender, mut receiver) = PrivateFdChannel::pair().unwrap();
    let observation = fixture
        .attempt
        .begin_rootfs_offer(sender, OFFER_BYTES)
        .await
        .unwrap();
    assert_eq!(observation.status(), SenderStatus::Sent);
    let (draft, source) = receive_source(&mut receiver);
    assert_eq!(&draft, observation.draft());
    assert_eq!(draft.context_sha384(), &fixture.expected_context);
    assert_eq!(draft.candidate_spec_sha384(), &fixture.expected_spec);
    assert_eq!(draft.backing().sha384, *summary.backing().image_sha384());
    assert_eq!(draft.backing().byte_len, summary.backing().byte_len());
    assert_eq!(draft.backing_adapter(), "private-ro-ramfs-v1");
    let mut metadata_receiver =
        ReceiverTransfer::new(fixture.expected_context, fixture.expected_spec, OFFER_BYTES)
            .unwrap();
    assert_eq!(
        metadata_receiver.receive(draft.clone()),
        Ok(OfferProgress::First)
    );
    let identity = inode_identity(&source);
    let before_duplicate = descriptor_aliases(identity);

    let retry = fixture.attempt.retry_rootfs_offer().await.unwrap();
    assert_eq!(retry, observation);
    let (duplicate, extra_source) = receive_source(&mut receiver);
    assert_eq!(duplicate, draft);
    assert_eq!(inode_identity(&extra_source), identity);
    assert_eq!(descriptor_aliases(identity), before_duplicate + 1);
    assert_eq!(
        metadata_receiver.receive(duplicate),
        Ok(OfferProgress::Historical)
    );
    drop(extra_source);
    assert_eq!(descriptor_aliases(identity), before_duplicate);

    let receipt = metadata_receiver.receipt().unwrap().encode();
    assert_eq!(receiver.try_send(&receipt, None), Ok(SendOutcome::Sent));
    let received = fixture.attempt.poll_rootfs_offer().await.unwrap();
    assert_eq!(received.status(), SenderStatus::EnvelopeReceived);
    assert_eq!(received.draft(), &draft);
    assert_eq!(
        fixture.attempt.retry_rootfs_offer().await.unwrap(),
        received
    );
    assert!(receiver.try_receive(FdExpectation::One).unwrap().is_none());
    assert_eq!(receiver.try_send(&receipt, None), Ok(SendOutcome::Sent));
    assert_eq!(fixture.attempt.poll_rootfs_offer().await.unwrap(), received);
    assert_eq!(
        fixture.attempt.prepare(fixture.delivery.borrowed()).await,
        Ok(ContentBinding::Historical)
    );
    assert_eq!(fixture.attempt.summary().unwrap(), summary);
    assert_eq!(fixture.trace.lock().unwrap().calls.len(), 2);
    assert_eq!(fixture.server.requests(), requests);

    let (second_sender, second_receiver) = PrivateFdChannel::pair().unwrap();
    assert_eq!(
        fixture
            .attempt
            .begin_rootfs_offer(second_sender, OFFER_BYTES)
            .await,
        Err(RootfsOfferError::Conflict)
    );
    drop(second_receiver);
    fixture.assert_terminal_cleanup(&requests).await;
    // Aborting the sender cannot revoke the already delivered sealed reference.
    assert_eq!(descriptor_aliases(identity), 1);
    assert_eq!(source.sha384(), &draft.backing().sha384);
    drop(source);
    assert_eq!(descriptor_aliases(identity), 0);
}

#[tokio::test]
async fn rootfs_offer_peer_exit_and_invalid_receipts_terminally_close_retained_worker() {
    for case in ["peer-exit", "malformed", "descriptor", "wrong-binding"] {
        let mut fixture = OfferFixture::new(1).await;
        fixture.prepare().await;
        let requests = fixture.server.requests();
        let (sender, mut receiver) = PrivateFdChannel::pair().unwrap();
        if case == "peer-exit" {
            drop(receiver);
            assert!(matches!(
                fixture
                    .attempt
                    .begin_rootfs_offer(sender, OFFER_BYTES)
                    .await,
                Err(RootfsOfferError::Transport(_))
            ));
        } else {
            fixture
                .attempt
                .begin_rootfs_offer(sender, OFFER_BYTES)
                .await
                .unwrap();
            let (draft, source) = receive_source(&mut receiver);
            let mut metadata_receiver =
                ReceiverTransfer::new(fixture.expected_context, fixture.expected_spec, OFFER_BYTES)
                    .unwrap();
            metadata_receiver.receive(draft).unwrap();
            let mut receipt = metadata_receiver.receipt().unwrap().encode().to_vec();
            match case {
                "malformed" => receipt.truncate(3),
                "wrong-binding" => receipt[16] ^= 1,
                "descriptor" => {}
                _ => unreachable!(),
            }
            let extra_descriptor = (case == "descriptor").then(|| source.as_fd());
            assert_eq!(
                receiver.try_send(&receipt, extra_descriptor),
                Ok(SendOutcome::Sent)
            );
            let result = fixture.attempt.poll_rootfs_offer().await;
            match case {
                "malformed" => assert_eq!(
                    result,
                    Err(RootfsOfferError::Protocol(OfferError::InvalidFrame))
                ),
                "descriptor" => assert_eq!(
                    result,
                    Err(RootfsOfferError::Transport(TransportError::DescriptorCount))
                ),
                "wrong-binding" => assert_eq!(
                    result,
                    Err(RootfsOfferError::Protocol(OfferError::Conflict))
                ),
                _ => unreachable!(),
            }
            drop(source);
            drop(receiver);
        }
        fixture.assert_terminal_cleanup(&requests).await;
    }
}

#[tokio::test]
async fn rootfs_offer_invalid_or_insufficient_limits_publish_no_descriptor_and_cleanup() {
    for bound in [0, 1] {
        let mut fixture = OfferFixture::new(1).await;
        fixture.prepare().await;
        let requests = fixture.server.requests();
        let (sender, mut receiver) = PrivateFdChannel::pair().unwrap();
        let result = fixture.attempt.begin_rootfs_offer(sender, bound).await;
        if bound == 0 {
            assert_eq!(result, Err(RootfsOfferError::InvalidLimit));
        } else {
            assert!(result.is_err());
        }
        fixture.assert_terminal_cleanup(&requests).await;
        assert!(matches!(
            receiver.try_receive(FdExpectation::One),
            Err(TransportError::Disconnected)
        ));
        let (next, recorder) = fixture.next().await;
        assert!(fixture.factory.begin_erofs_attempt(next, recorder).is_ok());
    }
}

#[tokio::test]
async fn rootfs_offer_dropped_queued_reply_retains_capacity_until_actual_worker_cleanup() {
    let mut fixture = OfferFixture::new(1).await;
    let (next, recorder) = fixture.next().await;
    let (reached, offered) = tokio::sync::oneshot::channel();
    let (release, wait) = std::sync::mpsc::channel();
    fixture.attempt.set_offer_barrier(reached, wait);
    fixture.prepare().await;
    let requests = fixture.server.requests();
    let (sender, mut receiver) = PrivateFdChannel::pair().unwrap();
    let mut offer = Box::pin(fixture.attempt.begin_rootfs_offer(sender, OFFER_BYTES));
    tokio::select! {
        result = &mut offer => panic!("offer escaped worker barrier: {result:?}"),
        result = offered => result.unwrap(),
    }
    drop(offer);
    assert!(fixture.attempt.summary().is_err());
    assert_eq!(fixture.parent.children(), 1);
    assert!(matches!(
        fixture.factory.begin_erofs_attempt(next, recorder),
        Err(RuntimeError::Busy)
    ));
    release.send(()).unwrap();
    fixture.assert_terminal_cleanup(&requests).await;
    assert!(matches!(
        receiver.try_receive(FdExpectation::One),
        Err(TransportError::Disconnected)
    ));
    let (next, recorder) = fixture.next().await;
    assert!(fixture.factory.begin_erofs_attempt(next, recorder).is_ok());
}
