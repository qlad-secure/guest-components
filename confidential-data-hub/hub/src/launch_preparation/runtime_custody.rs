//! Bounded custody protocol owned by one actual preparation attempt.
//! Exported records are observations; the receiver alone owns its checked view
//! and publishes the local lease. Unknown peer outcomes never reissue a context.

use super::*;
use execution_proof_handoff::{
    admission::ReceiverEnrollmentError,
    fd_transport::{FdExpectation, SendOutcome, TransportError},
    rootfs_custody::{
        AdmissionBundle, AdmissionDescriptor, CustodyAnnouncement, CustodyError, FinalizedAck,
        PreparationProvenance, PreparationRecord, ProducerTransaction, ProvenanceDescriptor,
        ValidatedReceipt, MAX_PROVENANCE_BYTES,
    },
    startup::{Role, StartupBoundChannel},
};
use image_rs::preparation::SealedImageBytes;
use std::os::fd::{AsFd, OwnedFd};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CustodyProducerError {
    InvalidLimits,
    Unavailable,
    WrongRole,
    Conflict,
    Backing,
    Deadline,
    Worker,
    Preparation(RuntimeError),
    Enrollment(ReceiverEnrollmentError),
    Transport(TransportError),
    Protocol(CustodyError),
}
impl fmt::Display for CustodyProducerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "rootfs custody producer: {self:?}")
    }
}
impl std::error::Error for CustodyProducerError {}

#[derive(Clone, Copy)]
pub struct CustodyProducerLimits {
    pub backing_bytes: u64,
    pub provenance_bytes: usize,
    pub admission_bytes: usize,
}
impl CustodyProducerLimits {
    fn validate(self) -> Result<(), CustodyProducerError> {
        if self.backing_bytes == 0
            || self.backing_bytes > isize::MAX as u64
            || self.provenance_bytes == 0
            || self.provenance_bytes > MAX_PROVENANCE_BYTES
            || self.admission_bytes == 0
            || self.admission_bytes > MAX_PROVENANCE_BYTES
        {
            return Err(CustodyProducerError::InvalidLimits);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CustodyProducerStatus {
    PendingEnrollment,
    Enrolled,
    SendingAdmission,
    SendingOffer,
    SendingProvenance,
    AwaitingValidation,
    SendingCommit,
    AwaitingFinalizedAck,
    Finalized,
    Terminal,
}

pub(super) struct CustodyMaterial {
    announcement: CustodyAnnouncement,
    origin: OwnedFd,
    provenance: PreparationProvenance,
    provenance_fd: SealedImageBytes,
    admission_fd: SealedImageBytes,
}
impl PreparationAttempt {
    pub(super) fn export_custody_material(
        &self,
        limits: CustodyProducerLimits,
        admission: AdmissionBundle,
    ) -> Result<CustodyMaterial, CustodyProducerError> {
        limits.validate()?;
        let (offer, origin) = self
            .rootfs_offer_origin(limits.backing_bytes)
            .map_err(|_| CustodyProducerError::Backing)?;
        let provenance = self.custody_provenance(limits.provenance_bytes)?;
        let encoded = provenance
            .encode(limits.provenance_bytes)
            .map_err(CustodyProducerError::Protocol)?;
        let provenance_fd = SealedImageBytes::from_bytes(&encoded, limits.provenance_bytes as u64)
            .map_err(|_| CustodyProducerError::Backing)?;
        let announcement = CustodyAnnouncement {
            offer,
            provenance_sha384: *provenance_fd.sha384(),
            provenance_bytes: provenance_fd.byte_len(),
        };
        provenance
            .validate_for(&announcement)
            .map_err(CustodyProducerError::Protocol)?;
        let bundle = admission
            .encode(limits.admission_bytes)
            .map_err(CustodyProducerError::Protocol)?;
        let admission_fd = SealedImageBytes::from_bytes(&bundle, limits.admission_bytes as u64)
            .map_err(|_| CustodyProducerError::Backing)?;
        Ok(CustodyMaterial {
            announcement,
            origin,
            provenance,
            provenance_fd,
            admission_fd,
        })
    }
}

enum State {
    Pending(StartupBoundChannel),
    Enrolled(StartupBoundChannel),
    Active(Box<Active>),
    Terminal,
}
struct Active {
    channel: StartupBoundChannel,
    material: CustodyMaterial,
    transaction: ProducerTransaction,
    phase: CustodyProducerStatus,
    deadline: Instant,
    // Drop local aliases/channel before releasing the original worker keepalive.
    _retained: Box<Retained>,
}

pub struct CustodyRuntimeAttempt {
    state: State,
    attempt: RuntimeAttempt,
    limits: CustodyProducerLimits,
}

impl RuntimeFactory {
    pub fn begin_custody_attempt(
        &self,
        config: ErofsRuntimeAttemptConfig,
        recorder: LaunchRecorder,
        channel: StartupBoundChannel,
        limits: CustodyProducerLimits,
    ) -> Result<CustodyRuntimeAttempt, CustodyProducerError> {
        limits.validate()?;
        if channel.role() != Role::Preparation {
            return Err(CustodyProducerError::WrongRole);
        }
        let attempt = self
            .begin_erofs_attempt(config, recorder)
            .map_err(CustodyProducerError::Preparation)?
            .0;
        Ok(CustodyRuntimeAttempt {
            state: State::Pending(channel),
            attempt,
            limits,
        })
    }
    #[cfg(feature = "launch-preparation-mount")]
    pub fn begin_mounted_custody_attempt(
        &self,
        config: MountedRuntimeAttemptConfig,
        recorder: LaunchRecorder,
        channel: StartupBoundChannel,
        limits: CustodyProducerLimits,
    ) -> Result<CustodyRuntimeAttempt, CustodyProducerError> {
        limits.validate()?;
        if channel.role() != Role::Preparation {
            return Err(CustodyProducerError::WrongRole);
        }
        let attempt = self
            .begin_mounted_attempt(config, recorder)
            .map_err(CustodyProducerError::Preparation)?
            .0;
        Ok(CustodyRuntimeAttempt {
            state: State::Pending(channel),
            attempt,
            limits,
        })
    }
}

impl CustodyRuntimeAttempt {
    pub fn challenge_nonce(&self) -> &str {
        self.attempt.challenge_nonce()
    }
    pub fn status(&self) -> CustodyProducerStatus {
        match &self.state {
            State::Pending(_) => CustodyProducerStatus::PendingEnrollment,
            State::Enrolled(_) => CustodyProducerStatus::Enrolled,
            State::Active(active) => active.phase,
            State::Terminal => CustodyProducerStatus::Terminal,
        }
    }
    /// Enroll the receiver while the factory-owned gate is still pending. The
    /// future owns both the sole channel and pending attempt through every await.
    pub async fn enroll_receiver(&mut self) -> Result<(), CustodyProducerError> {
        if matches!(self.state, State::Enrolled(_) | State::Active(_)) {
            return Ok(());
        }
        let State::Pending(mut channel) = std::mem::replace(&mut self.state, State::Terminal)
        else {
            return Err(CustodyProducerError::Unavailable);
        };
        let RuntimeState::Pending(pending) =
            std::mem::replace(&mut self.attempt.state, RuntimeState::Terminal)
        else {
            return Err(CustodyProducerError::Unavailable);
        };
        let deadline = Instant::now()
            .checked_add(self.attempt.resources.workflow_timeout)
            .ok_or(CustodyProducerError::InvalidLimits)?;
        let packet = loop {
            if Instant::now() >= deadline {
                return Err(CustodyProducerError::Deadline);
            }
            if let Some(packet) = channel
                .try_receive_bound(FdExpectation::None)
                .map_err(CustodyProducerError::Transport)?
            {
                break packet;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        };
        let wire = pending
            .gate
            .receiver_enrollment(packet, &channel)
            .map_err(CustodyProducerError::Enrollment)?;
        loop {
            if Instant::now() >= deadline {
                return Err(CustodyProducerError::Deadline);
            }
            if channel
                .try_send(&wire, None)
                .map_err(CustodyProducerError::Transport)?
                == SendOutcome::Sent
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        self.attempt.state = RuntimeState::Pending(pending);
        self.state = State::Enrolled(channel);
        Ok(())
    }

    pub async fn prepare(
        &mut self,
        delivery: RuntimeDelivery<'_>,
    ) -> Result<ContentBinding, CustodyProducerError> {
        self.prepare_mode(delivery, ContentMode::Gcp).await
    }
    async fn prepare_mode(
        &mut self,
        delivery: RuntimeDelivery<'_>,
        mode: ContentMode,
    ) -> Result<ContentBinding, CustodyProducerError> {
        if matches!(self.state, State::Active(_)) {
            if self
                .attempt
                .delivery
                .as_ref()
                .is_some_and(|saved| saved.matches(delivery))
            {
                return Ok(ContentBinding::Historical);
            }
            self.state = State::Terminal;
            self.attempt.state = RuntimeState::Terminal;
            return Err(CustodyProducerError::Conflict);
        }
        let State::Enrolled(channel) = std::mem::replace(&mut self.state, State::Terminal) else {
            self.attempt.state = RuntimeState::Terminal;
            return Err(CustodyProducerError::Unavailable);
        };
        self.attempt
            .prepare_with_mode(delivery, mode)
            .await
            .map_err(CustodyProducerError::Preparation)?;
        let RuntimeState::Staged(retained) =
            std::mem::replace(&mut self.attempt.state, RuntimeState::Terminal)
        else {
            return Err(CustodyProducerError::Unavailable);
        };
        let saved = self
            .attempt
            .delivery
            .as_ref()
            .ok_or(CustodyProducerError::Unavailable)?;
        let admission = AdmissionBundle {
            grant: saved.grant.clone(),
            aggregate: saved.aggregate.clone(),
            receipt: saved.receipt.clone(),
        };
        let (reply, receive) = oneshot::channel();
        retained
            ._keepalive
            .try_send(offer::ActorCommand::ExportCustody {
                limits: self.limits,
                admission,
                reply,
            })
            .map_err(|_| CustodyProducerError::Worker)?;
        let material = tokio::time::timeout(self.attempt.resources.workflow_timeout, receive)
            .await
            .map_err(|_| CustodyProducerError::Deadline)?
            .map_err(|_| CustodyProducerError::Worker)??;
        let transaction = ProducerTransaction::new(material.announcement.clone())
            .map_err(CustodyProducerError::Protocol)?;
        let deadline = Instant::now()
            .checked_add(self.attempt.resources.workflow_timeout)
            .ok_or(CustodyProducerError::InvalidLimits)?;
        self.state = State::Active(Box::new(Active {
            channel,
            material,
            transaction,
            phase: CustodyProducerStatus::SendingAdmission,
            deadline,
            _retained: retained,
        }));
        Ok(ContentBinding::FirstChecked)
    }

    /// Perform at most one nonblocking protocol I/O step. A partial send keeps
    /// its exact stage; explicit retry never inserts a new packet mid-sequence.
    pub fn advance(&mut self) -> Result<CustodyProducerStatus, CustodyProducerError> {
        let state = std::mem::replace(&mut self.state, State::Terminal);
        let State::Active(mut active) = state else {
            self.state = state;
            return Err(CustodyProducerError::Unavailable);
        };
        let result = active.advance();
        if result.is_ok() {
            self.state = State::Active(active);
        }
        result
    }
    pub fn retry(&mut self) -> Result<CustodyProducerStatus, CustodyProducerError> {
        let State::Active(active) = &mut self.state else {
            return Err(CustodyProducerError::Unavailable);
        };
        match active.phase {
            CustodyProducerStatus::AwaitingValidation => {
                active.phase = CustodyProducerStatus::SendingAdmission
            }
            CustodyProducerStatus::AwaitingFinalizedAck => {
                active.phase = CustodyProducerStatus::SendingCommit
            }
            _ => {}
        }
        Ok(active.phase)
    }
    pub fn record(&self) -> Option<&PreparationRecord> {
        match &self.state {
            State::Active(active) => active.transaction.committed().map(|commit| &commit.record),
            _ => None,
        }
    }
    pub async fn cancel_and_wait(&mut self) -> Result<(), CustodyProducerError> {
        self.state = State::Terminal;
        self.attempt
            .cancel_and_wait()
            .await
            .map_err(CustodyProducerError::Preparation)
    }
    #[cfg(all(test, feature = "launch-preparation-custody-native"))]
    pub(crate) async fn prepare_fixture(
        &mut self,
        delivery: RuntimeDelivery<'_>,
        replies: Vec<fixture::Reply>,
        trace: Arc<std::sync::Mutex<fixture::Trace>>,
    ) -> Result<ContentBinding, CustodyProducerError> {
        self.prepare_mode(delivery, ContentMode::Fixture { replies, trace })
            .await
    }
}
impl Drop for CustodyRuntimeAttempt {
    fn drop(&mut self) {
        self.state = State::Terminal;
    }
}

impl Active {
    fn advance(&mut self) -> Result<CustodyProducerStatus, CustodyProducerError> {
        if self.phase != CustodyProducerStatus::Finalized && Instant::now() >= self.deadline {
            return Err(CustodyProducerError::Deadline);
        }
        let (wire, descriptor, next) = match self.phase {
            CustodyProducerStatus::SendingAdmission => (
                AdmissionDescriptor {
                    sha384: *self.material.admission_fd.sha384(),
                    byte_len: self.material.admission_fd.byte_len(),
                }
                .encode()
                .map_err(CustodyProducerError::Protocol)?,
                Some(self.material.admission_fd.as_fd()),
                CustodyProducerStatus::SendingOffer,
            ),
            CustodyProducerStatus::SendingOffer => (
                self.material
                    .announcement
                    .encode()
                    .map_err(CustodyProducerError::Protocol)?,
                Some(self.material.origin.as_fd()),
                CustodyProducerStatus::SendingProvenance,
            ),
            CustodyProducerStatus::SendingProvenance => (
                ProvenanceDescriptor::for_announcement(&self.material.announcement)
                    .map_err(CustodyProducerError::Protocol)?
                    .encode()
                    .map_err(CustodyProducerError::Protocol)?,
                Some(self.material.provenance_fd.as_fd()),
                CustodyProducerStatus::AwaitingValidation,
            ),
            CustodyProducerStatus::SendingCommit => (
                self.transaction
                    .committed()
                    .ok_or(CustodyProducerError::Unavailable)?
                    .encode()
                    .map_err(CustodyProducerError::Protocol)?,
                None,
                CustodyProducerStatus::AwaitingFinalizedAck,
            ),
            CustodyProducerStatus::AwaitingValidation => {
                if let Some(packet) = self
                    .channel
                    .try_receive_bound(FdExpectation::None)
                    .map_err(CustodyProducerError::Transport)?
                {
                    let receipt = ValidatedReceipt::decode(packet.payload())
                        .map_err(CustodyProducerError::Protocol)?;
                    if receipt.inodes != self.material.provenance.builder.inodes
                        || receipt.startup_binding_sha384 != self.channel.binding_commitment()
                    {
                        return Err(CustodyProducerError::Conflict);
                    }
                    self.transaction
                        .validated(&receipt)
                        .map_err(CustodyProducerError::Protocol)?;
                    self.phase = CustodyProducerStatus::SendingCommit;
                }
                return Ok(self.phase);
            }
            CustodyProducerStatus::AwaitingFinalizedAck => {
                if let Some(packet) = self
                    .channel
                    .try_receive_bound(FdExpectation::None)
                    .map_err(CustodyProducerError::Transport)?
                {
                    if let Ok(ack) = FinalizedAck::decode(packet.payload()) {
                        self.transaction
                            .finalized(&ack)
                            .map_err(CustodyProducerError::Protocol)?;
                        self.phase = CustodyProducerStatus::Finalized;
                    } else {
                        // An explicit pre-validation retry can leave another
                        // exact receipt queued before the final ACK. It must
                        // match the retained validation and cannot mint P again.
                        let receipt = ValidatedReceipt::decode(packet.payload())
                            .map_err(CustodyProducerError::Protocol)?;
                        self.transaction
                            .validated(&receipt)
                            .map_err(CustodyProducerError::Protocol)?;
                    }
                }
                return Ok(self.phase);
            }
            CustodyProducerStatus::Finalized => return Ok(self.phase),
            _ => return Err(CustodyProducerError::Unavailable),
        };
        if self
            .channel
            .try_send(&wire, descriptor)
            .map_err(CustodyProducerError::Transport)?
            == SendOutcome::Sent
        {
            self.phase = next;
        }
        Ok(self.phase)
    }
}
