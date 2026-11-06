//! Bounded orchestration of default-off image preparation.
//!
//! Trusted provisioning supplies all roots, expectations, repository, policy and
//! filesystem parent. Received delivery bytes cannot create those expectations.
//! Construction is network-free and leaves the generic Hub's lazy path alone.
//! A ready recorder is supplied by trusted bootstrap; its earlier key generation
//! and quote workflow are outside this factory's active-attempt resource bound.
//!
//! Final mutable staging stays in an owned blocking worker. Only summaries cross
//! back to the async owner. Dropping preparation closes its local keepalive;
//! `cancel_and_wait` drains the retained worker. Drop cannot synchronously join a
//! running blocking task, but that task keeps the permit through actual cleanup.
//! The optional offer feature adds a capacity-one command queue to that same
//! owner. It sends only the sealed origin and returns non-authorizing status.
//! The base runtime does not authorize task start. Opt-in custody adds receiver
//! validation and P/ACK coordination; the receiver owns the usable lease.

use super::*;
#[cfg(feature = "launch-preparation-executable")]
#[path = "runtime_executable.rs"]
mod executable;
#[cfg(feature = "launch-preparation-executable")]
pub use executable::{CheckedRuntimeAttempt, CheckedRuntimeAttemptConfig, CheckedRuntimeSummary};
#[cfg(feature = "launch-preparation-erofs")]
#[path = "runtime_erofs.rs"]
mod erofs;
#[cfg(feature = "launch-preparation-erofs")]
pub use erofs::{ErofsRuntimeAttempt, ErofsRuntimeAttemptConfig, ErofsRuntimeSummary};
#[cfg(feature = "launch-preparation-offer")]
#[path = "runtime_offer.rs"]
mod offer;
#[cfg(feature = "launch-preparation-offer")]
use offer::ActorCommand;
#[cfg(feature = "launch-preparation-offer")]
pub use offer::{RootfsOfferError, RootfsOfferObservation};
#[cfg(feature = "launch-preparation-custody")]
#[path = "runtime_custody.rs"]
mod custody;
#[cfg(feature = "launch-preparation-custody")]
pub use custody::{
    CustodyProducerError, CustodyProducerLimits, CustodyProducerStatus, CustodyRuntimeAttempt,
};
#[cfg(not(feature = "launch-preparation-offer"))]
type ActorCommand = ();
#[cfg(feature = "launch-preparation-mount")]
#[path = "runtime_mount.rs"]
mod mounted;
use execution_proof_client::MAX_CREDENTIAL_RESPONSE_BYTES;
use execution_proof_contract::MAX_WIRE_BYTES;
use execution_proof_handoff::admission::{GuestAdmissionConfig, GuestAdmissionGate};
use image_rs::preparation::{
    manifest_signature::RequiredCosignPolicy,
    registry_ingress::TrustedRegistry,
    rootfs_staging::{PrivateStagingParent, RootfsStagingLimits},
};
use kbs_protocol::launch_recorder::LaunchRecorder;
#[cfg(feature = "launch-preparation-mount")]
pub use mounted::{MountedRuntimeAttempt, MountedRuntimeAttemptConfig, MountedRuntimeSummary};
use std::{sync::Arc, time::Duration};
use tokio::{
    sync::{oneshot, OwnedSemaphorePermit, Semaphore},
    task::JoinHandle,
    time::{timeout_at, Instant},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeError {
    InvalidConfiguration,
    Busy,
    TooLarge,
    AdmissionRejected,
    CredentialRejected,
    PreparationRejected,
    #[cfg(feature = "launch-preparation-executable")]
    ExecutableRejected,
    #[cfg(feature = "launch-preparation-erofs")]
    BackingRejected,
    #[cfg(feature = "launch-preparation-mount")]
    MountRejected,
    RegistryRejected,
    Deadline,
    WorkerUnavailable,
    Conflict,
    Unavailable,
}
impl fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidConfiguration => "preparation runtime configuration rejected",
            Self::Busy => "preparation runtime capacity exhausted",
            Self::TooLarge => "preparation runtime input exceeds configured bounds",
            Self::AdmissionRejected => "preparation runtime admission rejected",
            Self::CredentialRejected => "preparation runtime credential rejected",
            Self::PreparationRejected => "preparation runtime content or staging rejected",
            #[cfg(feature = "launch-preparation-executable")]
            Self::ExecutableRejected => "preparation runtime spec or executable rejected",
            #[cfg(feature = "launch-preparation-erofs")]
            Self::BackingRejected => "preparation runtime EROFS backing rejected",
            #[cfg(feature = "launch-preparation-mount")]
            Self::MountRejected => "preparation runtime actual mount or view rejected",
            Self::RegistryRejected => "preparation runtime registry response rejected",
            Self::Deadline => "preparation runtime workflow deadline exceeded",
            Self::WorkerUnavailable => "preparation runtime worker unavailable",
            Self::Conflict => "preparation runtime delivery conflicts with retained attempt",
            Self::Unavailable => "preparation runtime attempt is terminal",
        })
    }
}
impl std::error::Error for RuntimeError {}

/// Per-attempt trusted provisioning, not a host RPC or a received JSON schema.
/// The ready recorder must already have independently pinned aggregate scope.
pub struct RuntimeAttemptConfig {
    pub admission: GuestAdmissionConfig,
    pub preparation: PreparationProfile,
    pub metadata_limits: PreparationLimits,
    pub content_limits: ImageContentLimits,
    pub staging_parent: PrivateStagingParent,
    pub staging_limits: RootfsStagingLimits,
    pub signature_policy: RequiredCosignPolicy,
    /// Digest-addressed lookup only; the requiring policy remains the authority.
    pub signature_artifact_sha256: String,
}

struct Resources {
    registry: TrustedRegistry,
    active: Arc<Semaphore>,
    workflow_timeout: Duration,
}

pub struct RuntimeFactory {
    resources: Arc<Resources>,
}
impl RuntimeFactory {
    pub fn new(
        registry: TrustedRegistry,
        active_limit: usize,
        workflow_timeout: Duration,
    ) -> Result<Self, RuntimeError> {
        if !(1..=4).contains(&active_limit)
            || workflow_timeout.is_zero()
            || Instant::now().checked_add(workflow_timeout).is_none()
        {
            return Err(RuntimeError::InvalidConfiguration);
        }
        Ok(Self {
            resources: Arc::new(Resources {
                registry,
                active: Arc::new(Semaphore::new(active_limit)),
                workflow_timeout,
            }),
        })
    }

    /// Reserve capacity before creating a pending gate; there is no waiter queue.
    /// Caller-owned recorder bootstrap/key generation precedes this reservation.
    pub fn begin_attempt(
        &self,
        config: RuntimeAttemptConfig,
        recorder: LaunchRecorder,
    ) -> Result<RuntimeAttempt, RuntimeError> {
        validate_attempt_config(&config, self.resources.registry.repository())?;
        let permit = self
            .resources
            .active
            .clone()
            .try_acquire_owned()
            .map_err(|_| RuntimeError::Busy)?;
        let RuntimeAttemptConfig {
            admission,
            preparation,
            metadata_limits,
            content_limits,
            staging_parent,
            staging_limits,
            signature_policy,
            signature_artifact_sha256,
        } = config;
        let gate =
            GuestAdmissionGate::new(admission).map_err(|_| RuntimeError::InvalidConfiguration)?;
        let nonce = gate.challenge_nonce().to_owned();
        Ok(RuntimeAttempt {
            resources: self.resources.clone(),
            nonce,
            state: RuntimeState::Pending(Box::new(Pending {
                gate,
                recorder,
                preparation,
                metadata_limits,
                content_limits,
                staging_parent,
                staging_limits,
                signature_policy,
                signature_artifact_sha256,
                #[cfg(feature = "launch-preparation-executable")]
                executable: None,
                #[cfg(feature = "launch-preparation-erofs")]
                builder: None,
                #[cfg(feature = "launch-preparation-mount")]
                mount: None,
                permit,
            })),
            delivery: None,
            worker: None,
            #[cfg(test)]
            stage_barrier: None,
            #[cfg(all(test, feature = "launch-preparation-offer"))]
            offer_barrier: None,
        })
    }
}

/// Bounded authenticated delivery inputs. No root, provider, repository, image
/// path, admission capability or decrypted credential is accepted here.
#[derive(Clone, Copy)]
pub struct RuntimeDelivery<'a> {
    pub grant: &'a [u8],
    pub aggregate: &'a [u8],
    pub admission_receipt: &'a [u8],
    pub credential_response: &'a [u8],
}
struct DeliveryRecord {
    grant: Vec<u8>,
    aggregate: Vec<u8>,
    receipt: Vec<u8>,
    credential: Vec<u8>,
}
impl DeliveryRecord {
    fn new(input: RuntimeDelivery<'_>) -> Result<Self, RuntimeError> {
        validate_delivery(input)?;
        Ok(Self {
            grant: input.grant.to_vec(),
            aggregate: input.aggregate.to_vec(),
            receipt: input.admission_receipt.to_vec(),
            credential: input.credential_response.to_vec(),
        })
    }
    fn matches(&self, input: RuntimeDelivery<'_>) -> bool {
        self.grant == input.grant
            && self.aggregate == input.aggregate
            && self.receipt == input.admission_receipt
            && self.credential == input.credential_response
    }
}

struct Pending {
    gate: GuestAdmissionGate,
    recorder: LaunchRecorder,
    preparation: PreparationProfile,
    metadata_limits: PreparationLimits,
    content_limits: ImageContentLimits,
    staging_parent: PrivateStagingParent,
    staging_limits: RootfsStagingLimits,
    signature_policy: RequiredCosignPolicy,
    signature_artifact_sha256: String,
    #[cfg(feature = "launch-preparation-executable")]
    executable: Option<executable::RequiredExecution>,
    #[cfg(feature = "launch-preparation-erofs")]
    builder: Option<image_rs::preparation::erofs_builder::TrustedErofsBuilder>,
    #[cfg(feature = "launch-preparation-mount")]
    mount: Option<image_rs::preparation::erofs_mount::ErofsMountLimits>,
    // Last: all owned attempt/credential state must drop before capacity returns.
    permit: OwnedSemaphorePermit,
}

struct Workflow {
    // First: teardown must precede returning the active permit.
    attempt: PreparationAttempt,
    policy: Option<RequiredCosignPolicy>,
    signature_artifact_sha256: String,
    metadata_limits: PreparationLimits,
    content_limits: ImageContentLimits,
    layers: Vec<Blob>,
    #[cfg(feature = "launch-preparation-executable")]
    executable: Option<executable::RequiredExecution>,
    #[cfg(feature = "launch-preparation-erofs")]
    builder: Option<image_rs::preparation::erofs_builder::TrustedErofsBuilder>,
    #[cfg(feature = "launch-preparation-mount")]
    mount: Option<image_rs::preparation::erofs_mount::ErofsMountLimits>,
    _permit: OwnedSemaphorePermit,
}
struct Blob {
    digest: String,
    size: u64,
}

/// Software observations from a mutable staging tree retained by its worker.
/// These counts and digests do not authorize execution or establish a lease.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimePreparationSummary {
    pub manifest_sha256: String,
    pub policy_sha384: String,
    pub layers: usize,
    pub ciphertext_bytes: usize,
    pub tar_bytes: usize,
    pub applied_entries: usize,
    pub inodes: usize,
    pub write_bytes: usize,
    pub live_file_bytes: usize,
}
impl RuntimePreparationSummary {
    fn capture(attempt: &PreparationAttempt) -> Result<Self, RuntimeError> {
        let content = attempt
            .content_summary()
            .map_err(|_| RuntimeError::PreparationRejected)?;
        let staging = attempt
            .rootfs_staging_summary()
            .map_err(|_| RuntimeError::PreparationRejected)?;
        Ok(Self {
            manifest_sha256: content.manifest_sha256().into(),
            policy_sha384: content.policy_sha384().into(),
            layers: staging.layers(),
            ciphertext_bytes: content.total_ciphertext_bytes(),
            tar_bytes: staging.total_tar_bytes(),
            applied_entries: staging.applied_entries(),
            inodes: staging.inodes(),
            write_bytes: staging.write_bytes(),
            live_file_bytes: staging.live_file_bytes(),
        })
    }
}

struct ActorSnapshot {
    staging: RuntimePreparationSummary,
    #[cfg(feature = "launch-preparation-erofs")]
    backing: Option<image_rs::preparation::erofs_builder::VerifiedErofsSummary>,
    #[cfg(feature = "launch-preparation-mount")]
    mounted: Option<image_rs::preparation::erofs_mount::MountedRootfsSummary>,
    #[cfg(feature = "launch-preparation-executable")]
    executable: Option<image_rs::preparation::rootfs_staging::CheckedStagingExecutable>,
}
impl ActorSnapshot {
    fn capture(
        workflow: &mut Workflow,
        _deadline: Instant,
        _closed: &std::sync::mpsc::Receiver<ActorCommand>,
    ) -> Result<Self, RuntimeError> {
        #[cfg(feature = "launch-preparation-executable")]
        let executable = workflow
            .executable
            .as_ref()
            .map(|required| {
                workflow
                    .attempt
                    .check_staged_executable(&required.spec, required.limits)
                    .map_err(|_| RuntimeError::ExecutableRejected)
            })
            .transpose()?;
        let staging = RuntimePreparationSummary::capture(&workflow.attempt)?;
        #[cfg(feature = "launch-preparation-erofs")]
        let backing = workflow
            .builder
            .as_ref()
            .map(|builder| {
                workflow
                    .attempt
                    .build_staged_rootfs(builder, &|| {
                        Instant::now() >= _deadline
                            || !matches!(
                                _closed.try_recv(),
                                Err(std::sync::mpsc::TryRecvError::Empty)
                            )
                    })
                    .map_err(|_| RuntimeError::BackingRejected)
            })
            .transpose()?;
        #[cfg(feature = "launch-preparation-mount")]
        let mounted = workflow
            .mount
            .as_ref()
            .map(|limits| {
                let required = workflow
                    .executable
                    .as_ref()
                    .ok_or(RuntimeError::InvalidConfiguration)?;
                workflow
                    .attempt
                    .mount_staged_rootfs(&required.spec, required.limits, *limits, &|| {
                        Instant::now() >= _deadline
                            || !matches!(
                                _closed.try_recv(),
                                Err(std::sync::mpsc::TryRecvError::Empty)
                            )
                    })
                    .map_err(|_| RuntimeError::MountRejected)
            })
            .transpose()?;
        Ok(Self {
            staging,
            #[cfg(feature = "launch-preparation-executable")]
            executable,
            #[cfg(feature = "launch-preparation-erofs")]
            backing,
            #[cfg(feature = "launch-preparation-mount")]
            mounted,
        })
    }
}

struct Retained {
    snapshot: ActorSnapshot,
    // Closing the only sender tells the bounded blocking owner to clean up.
    _keepalive: std::sync::mpsc::SyncSender<ActorCommand>,
}
enum RuntimeState {
    Pending(Box<Pending>),
    Staged(Box<Retained>),
    Terminal,
}

pub struct RuntimeAttempt {
    resources: Arc<Resources>,
    nonce: String,
    state: RuntimeState,
    delivery: Option<Arc<DeliveryRecord>>,
    // Stored before any await, including if the preparation future is dropped.
    worker: Option<JoinHandle<()>>,
    #[cfg(test)]
    stage_barrier: Option<StageBarrier>,
    #[cfg(all(test, feature = "launch-preparation-offer"))]
    offer_barrier: Option<StageBarrier>,
}
#[cfg(test)]
struct StageBarrier {
    reached: oneshot::Sender<()>,
    release: std::sync::mpsc::Receiver<()>,
}

impl RuntimeAttempt {
    pub fn challenge_nonce(&self) -> &str {
        &self.nonce
    }

    pub fn summary(&self) -> Result<&RuntimePreparationSummary, RuntimeError> {
        match &self.state {
            RuntimeState::Staged(retained) => Ok(&retained.snapshot.staging),
            _ => Err(RuntimeError::Unavailable),
        }
    }

    pub async fn prepare(
        &mut self,
        delivery: RuntimeDelivery<'_>,
    ) -> Result<ContentBinding, RuntimeError> {
        self.prepare_with_mode(delivery, ContentMode::Gcp).await
    }

    async fn prepare_with_mode(
        &mut self,
        delivery: RuntimeDelivery<'_>,
        mode: ContentMode,
    ) -> Result<ContentBinding, RuntimeError> {
        // A failed/mismatched retry closes the retained actor as well.
        validate_delivery(delivery).inspect_err(|_| {
            self.state = RuntimeState::Terminal;
        })?;
        if matches!(self.state, RuntimeState::Staged(_)) {
            if self
                .delivery
                .as_ref()
                .is_some_and(|record| record.matches(delivery))
            {
                return Ok(ContentBinding::Historical);
            }
            self.state = RuntimeState::Terminal;
            return Err(RuntimeError::Conflict);
        }
        let pending = match std::mem::replace(&mut self.state, RuntimeState::Terminal) {
            RuntimeState::Pending(pending) => pending,
            _ => return Err(RuntimeError::Unavailable),
        };
        let deadline = Instant::now()
            .checked_add(self.resources.workflow_timeout)
            .ok_or(RuntimeError::InvalidConfiguration)?;
        let record = Arc::new(DeliveryRecord::new(delivery)?);
        self.delivery = Some(record.clone());
        let outcome = self.run_workflow(*pending, record, deadline, mode).await;
        if outcome.is_err() {
            self.delivery = None;
        }
        outcome
    }

    async fn run_workflow(
        &mut self,
        pending: Pending,
        record: Arc<DeliveryRecord>,
        deadline: Instant,
        mode: ContentMode,
    ) -> Result<ContentBinding, RuntimeError> {
        let workflow = self
            .blocking_step(deadline, move || admit(pending, &record))
            .await?;
        let manifest_digest = match &workflow.attempt.state {
            State::Pending(material) => material.profile.binding.selected_manifest_sha256.clone(),
            _ => return Err(RuntimeError::PreparationRejected),
        };
        let manifest = timeout_at(
            deadline,
            self.resources
                .registry
                .fetch_manifest(&manifest_digest, workflow.metadata_limits.manifest_bytes),
        )
        .await
        .map_err(|_| RuntimeError::Deadline)?
        .map_err(|_| RuntimeError::RegistryRejected)?;
        let metadata_limits = workflow.metadata_limits;
        let (mut workflow, manifest, config_descriptor) = self
            .blocking_step(deadline, move || {
                let descriptor = config_descriptor(&manifest, metadata_limits)?;
                Ok((workflow, manifest, descriptor))
            })
            .await?;
        let config = timeout_at(
            deadline,
            self.resources.registry.fetch_blob(
                &config_descriptor.digest,
                config_descriptor.size,
                metadata_limits.config_bytes,
            ),
        )
        .await
        .map_err(|_| RuntimeError::Deadline)?
        .map_err(|_| RuntimeError::RegistryRejected)?;
        let signature = timeout_at(
            deadline,
            self.resources
                .registry
                .fetch_signature(&workflow.signature_artifact_sha256),
        )
        .await
        .map_err(|_| RuntimeError::Deadline)?
        .map_err(|_| RuntimeError::RegistryRejected)?;
        workflow = self
            .blocking_step(deadline, move || {
                workflow
                    .attempt
                    .bind_manifest(&manifest, &config)
                    .map_err(|_| RuntimeError::PreparationRejected)?;
                let policy = workflow
                    .policy
                    .take()
                    .ok_or(RuntimeError::PreparationRejected)?;
                workflow
                    .attempt
                    .verify_image_signature(policy, &signature.payload, &signature.signature)
                    .map_err(|_| RuntimeError::PreparationRejected)?;
                workflow.layers = preflight_layers(&workflow)?;
                Ok(workflow)
            })
            .await?;
        let mut ciphertexts = Vec::with_capacity(workflow.layers.len());
        for layer in &workflow.layers {
            let ciphertext = timeout_at(
                deadline,
                self.resources.registry.fetch_blob(
                    &layer.digest,
                    layer.size,
                    workflow.content_limits.layer.ciphertext_bytes,
                ),
            )
            .await
            .map_err(|_| RuntimeError::Deadline)?
            .map_err(|_| RuntimeError::RegistryRejected)?;
            ciphertexts.push(ciphertext);
        }
        let runtime = tokio::runtime::Handle::current();
        let (cancel_content, mut content_cancelled) = oneshot::channel::<()>();
        // The sender remains in this preparation future, never in self or the
        // blocking closure. Dropping the future cancels further async unwraps.
        workflow = self
            .blocking_step(deadline, move || {
                let references: Vec<_> = ciphertexts.iter().map(Vec::as_slice).collect();
                // The SDK future runs on this runtime handle from a bounded
                // blocking worker; TAR/hash/seal CPU and filesystem work stay
                // off async workers. A running blocking closure is not aborted.
                runtime.block_on(async {
                    let checked = async {
                        match mode {
                            ContentMode::Gcp => workflow.attempt.prepare_layers(&references).await,
                            #[cfg(test)]
                            ContentMode::Fixture { replies, trace } => {
                                workflow
                                    .attempt
                                    .prepare_layers_fixture(&references, replies, trace)
                                    .await
                            }
                        }
                    };
                    tokio::select! {
                        biased;
                        _ = &mut content_cancelled => Err(RuntimeError::Unavailable),
                        result = timeout_at(deadline, checked) => result
                            .map_err(|_| RuntimeError::Deadline)?
                            .map_err(|_| RuntimeError::PreparationRejected),
                    }
                })?;
                // Synchronous parsing/hash/seal tails are bounded but cannot
                // be preempted. Reject their result if cancellation arrived.
                if !matches!(
                    content_cancelled.try_recv(),
                    Err(oneshot::error::TryRecvError::Empty)
                ) {
                    return Err(RuntimeError::Unavailable);
                }
                check_deadline(deadline)?;
                Ok(workflow)
            })
            .await?;
        drop(cancel_content);

        let (send_summary, receive_summary) = oneshot::channel();
        let (keepalive, close) = std::sync::mpsc::sync_channel(1);
        #[cfg(test)]
        let stage_barrier = self.stage_barrier.take();
        #[cfg(all(test, feature = "launch-preparation-offer"))]
        let offer_barrier = self.offer_barrier.take();
        self.worker = Some(tokio::task::spawn_blocking(move || {
            let staged = workflow
                .attempt
                .stage_rootfs()
                .map_err(|_| RuntimeError::PreparationRejected)
                .and_then(|_| ActorSnapshot::capture(&mut workflow, deadline, &close));
            let successful = staged.is_ok();
            #[cfg(test)]
            if let Some(barrier) = stage_barrier {
                let _ = barrier.reached.send(());
                let _ = barrier.release.recv();
            }
            if send_summary.send(staged).is_ok() && successful {
                // The sender remains local to the async preparation future
                // until summary receipt succeeds, then belongs to Staged.
                #[cfg(feature = "launch-preparation-offer")]
                offer::serve(
                    &mut workflow.attempt,
                    &close,
                    #[cfg(test)]
                    offer_barrier,
                );
                #[cfg(not(feature = "launch-preparation-offer"))]
                let _ = close.recv();
            }
            // Explicitly drop attempt before returning the permit, including
            // receiver cancellation and partial staging failures.
            drop(workflow);
        }));
        let snapshot = timeout_at(deadline, receive_summary)
            .await
            .map_err(|_| RuntimeError::Deadline)?
            .map_err(|_| RuntimeError::WorkerUnavailable)??;
        check_deadline(deadline)?;
        self.state = RuntimeState::Staged(Box::new(Retained {
            snapshot,
            _keepalive: keepalive,
        }));
        Ok(ContentBinding::FirstChecked)
    }

    async fn blocking_step<T: Send + 'static>(
        &mut self,
        deadline: Instant,
        operation: impl FnOnce() -> Result<T, RuntimeError> + Send + 'static,
    ) -> Result<T, RuntimeError> {
        if self.worker.is_some() {
            return Err(RuntimeError::WorkerUnavailable);
        }
        let (send, receive) = oneshot::channel();
        self.worker = Some(tokio::task::spawn_blocking(move || {
            let _ = send.send(operation());
        }));
        let outcome = timeout_at(deadline, receive)
            .await
            .map_err(|_| RuntimeError::Deadline)?
            .map_err(|_| RuntimeError::WorkerUnavailable)?;
        let joined = timeout_at(
            deadline,
            self.worker
                .as_mut()
                .ok_or(RuntimeError::WorkerUnavailable)?,
        )
        .await
        .map_err(|_| RuntimeError::Deadline)?;
        self.worker = None;
        joined.map_err(|_| RuntimeError::WorkerUnavailable)?;
        check_deadline(deadline)?;
        outcome
    }

    /// Close any retained actor and wait for actual blocking cleanup. No new
    /// attempt is opened, even when this drain observes a cancelled queued job.
    pub async fn cancel_and_wait(&mut self) -> Result<(), RuntimeError> {
        self.state = RuntimeState::Terminal;
        self.delivery = None;
        if let Some(worker) = self.worker.as_mut() {
            worker.abort(); // queued closures may abort; running ones finish.
            let outcome = worker.await;
            self.worker = None;
            if outcome.is_err_and(|error| !error.is_cancelled()) {
                return Err(RuntimeError::WorkerUnavailable);
            }
        }
        Ok(())
    }
}
impl Drop for RuntimeAttempt {
    fn drop(&mut self) {
        self.state = RuntimeState::Terminal;
        if let Some(worker) = &self.worker {
            worker.abort();
        }
        // A running closure cannot be stopped by abort. It owns cleanup and its
        // permit; closing keepalive above makes it finish without publication.
    }
}

enum ContentMode {
    Gcp,
    #[cfg(test)]
    Fixture {
        replies: Vec<fixture::Reply>,
        trace: Arc<std::sync::Mutex<fixture::Trace>>,
    },
}

fn admit(mut pending: Pending, record: &DeliveryRecord) -> Result<Workflow, RuntimeError> {
    pending
        .gate
        .verify_bundle(&record.grant, &record.aggregate, &record.receipt)
        .map_err(|_| RuntimeError::AdmissionRejected)?;
    let admission = pending
        .gate
        .take_accepted_attempt()
        .map_err(|_| RuntimeError::AdmissionRejected)?;
    let credential = pending
        .recorder
        .decrypt_credential_response(&record.credential, &record.aggregate)
        .map_err(|_| RuntimeError::CredentialRejected)?;
    let attempt = PreparationAttempt::new_with_staging(
        admission,
        credential,
        pending.preparation,
        pending.metadata_limits,
        pending.content_limits,
        pending.staging_parent,
        pending.staging_limits,
    )
    .map_err(|_| RuntimeError::PreparationRejected)?;
    Ok(Workflow {
        attempt,
        policy: Some(pending.signature_policy),
        signature_artifact_sha256: pending.signature_artifact_sha256,
        metadata_limits: pending.metadata_limits,
        content_limits: pending.content_limits,
        layers: Vec::new(),
        #[cfg(feature = "launch-preparation-executable")]
        executable: pending.executable,
        #[cfg(feature = "launch-preparation-erofs")]
        builder: pending.builder,
        #[cfg(feature = "launch-preparation-mount")]
        mount: pending.mount,
        _permit: pending.permit,
    })
}

fn validate_delivery(delivery: RuntimeDelivery<'_>) -> Result<(), RuntimeError> {
    if [
        delivery.grant,
        delivery.aggregate,
        delivery.admission_receipt,
    ]
    .iter()
    .any(|bytes| bytes.is_empty() || bytes.len() > MAX_WIRE_BYTES)
        || delivery.credential_response.is_empty()
        || delivery.credential_response.len() > MAX_CREDENTIAL_RESPONSE_BYTES
    {
        return Err(RuntimeError::TooLarge);
    }
    Ok(())
}

fn validate_attempt_config(
    config: &RuntimeAttemptConfig,
    repository: &str,
) -> Result<(), RuntimeError> {
    validate_configuration(&config.preparation, &config.metadata_limits)
        .map_err(|_| RuntimeError::InvalidConfiguration)?;
    content::validate_content_limits(config.content_limits)
        .map_err(|_| RuntimeError::InvalidConfiguration)?;
    config
        .staging_limits
        .validate()
        .map_err(|_| RuntimeError::InvalidConfiguration)?;
    let gate = &config.admission;
    let profile = &config.preparation;
    let aggregate = &gate.aggregate.expected;
    if gate.expected_grant.binding != profile.binding
        || gate.expected_grant.validity != profile.validity
        || gate.expected_grant.digest_sha384().ok().as_deref() != Some(&profile.grant_sha384)
        || gate.grant.authority_public_key != profile.authority_public_key
        || gate.aggregate.kbs_proof_public_key != profile.kbs_proof_public_key
        || aggregate.grant_sha384 != profile.grant_sha384
        || aggregate.request.workflow_id != profile.workflow_id
        || aggregate.request.resource_path != profile.resource_path
        || config.signature_policy.policy_sha384() != profile.binding.image_policy_sha384
        || config.signature_policy.repository() != repository
        || !sha256_hex(&config.signature_artifact_sha256)
    {
        return Err(RuntimeError::InvalidConfiguration);
    }
    Ok(())
}

fn config_descriptor(manifest: &[u8], limits: PreparationLimits) -> Result<Blob, RuntimeError> {
    if manifest.len() > limits.manifest_bytes {
        return Err(RuntimeError::TooLarge);
    }
    // Reuse the strict manifest schema. Digest, config, and layer binding
    // complete before content use.
    let parsed: Manifest =
        serde_json::from_slice(manifest).map_err(|_| RuntimeError::PreparationRejected)?;
    if parsed.schema_version != 2
        || parsed.media_type != MANIFEST_MEDIA_TYPE
        || parsed.config.media_type != CONFIG_MEDIA_TYPE
        || parsed.layers.is_empty()
        || parsed.layers.len() > limits.layer_count
        || parsed.config.size == 0
        || parsed.config.size > limits.config_bytes as u64
    {
        return Err(RuntimeError::PreparationRejected);
    }
    let digest = digest_value(&parsed.config.digest)
        .filter(|value| sha256_hex(value))
        .ok_or(RuntimeError::PreparationRejected)?;
    Ok(Blob {
        digest: digest.into(),
        size: parsed.config.size,
    })
}

fn preflight_layers(workflow: &Workflow) -> Result<Vec<Blob>, RuntimeError> {
    let plan = workflow
        .attempt
        .manifest_plan()
        .map_err(|_| RuntimeError::PreparationRejected)?;
    let limits = workflow.content_limits;
    let mut total = 0usize;
    let mut layers = Vec::with_capacity(plan.layers().len());
    for layer in plan.layers() {
        let size = usize::try_from(layer.descriptor_size()).map_err(|_| RuntimeError::TooLarge)?;
        total = total
            .checked_add(size)
            .filter(|value| *value <= limits.total_ciphertext_bytes)
            .ok_or(RuntimeError::TooLarge)?;
        if size == 0 || size > limits.layer.ciphertext_bytes {
            return Err(RuntimeError::TooLarge);
        }
        layers.push(Blob {
            digest: layer.blob_sha256().into(),
            size: layer.descriptor_size(),
        });
    }
    Ok(layers)
}

fn sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn check_deadline(deadline: Instant) -> Result<(), RuntimeError> {
    if Instant::now() >= deadline {
        Err(RuntimeError::Deadline)
    } else {
        Ok(())
    }
}

#[cfg(test)]
impl RuntimeAttempt {
    pub(crate) fn set_stage_barrier(
        &mut self,
        reached: oneshot::Sender<()>,
        release: std::sync::mpsc::Receiver<()>,
    ) {
        self.stage_barrier = Some(StageBarrier { reached, release });
    }

    pub(crate) async fn prepare_fixture(
        &mut self,
        delivery: RuntimeDelivery<'_>,
        replies: Vec<fixture::Reply>,
        trace: Arc<std::sync::Mutex<fixture::Trace>>,
    ) -> Result<ContentBinding, RuntimeError> {
        self.prepare_with_mode(delivery, ContentMode::Fixture { replies, trace })
            .await
    }
}
