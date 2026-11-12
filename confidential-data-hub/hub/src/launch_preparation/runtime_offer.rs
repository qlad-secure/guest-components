//! Non-authorizing sealed-origin offers from the retained preparation worker.
//! No caller-supplied descriptor, path, image hash or admission expectation is
//! accepted. Receipt means envelope delivery only; the worker keeps the original
//! preparation and capacity permit until explicit cancellation or teardown.

use super::*;
use execution_proof_handoff::{
    fd_transport::{FdExpectation, PrivateFdChannel, TransportError},
    rootfs_offer::{OfferError, OfferReceipt, RootfsOfferDraft, SenderStatus, SenderTransfer},
};
use std::os::fd::{AsFd, OwnedFd};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RootfsOfferError {
    InvalidLimit,
    Unavailable,
    Conflict,
    Backing,
    Worker,
    Deadline,
    Protocol(OfferError),
    Transport(TransportError),
}
impl fmt::Display for RootfsOfferError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "rootfs offer unavailable: {self:?}")
    }
}
impl std::error::Error for RootfsOfferError {}

/// A historical observation, never a preparation record or rootfs lease.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RootfsOfferObservation {
    draft: RootfsOfferDraft,
    status: SenderStatus,
}
impl RootfsOfferObservation {
    pub fn draft(&self) -> &RootfsOfferDraft {
        &self.draft
    }
    pub fn status(&self) -> SenderStatus {
        self.status
    }
}

type Reply = oneshot::Sender<Result<RootfsOfferObservation, RootfsOfferError>>;
pub(super) enum ActorCommand {
    #[cfg(feature = "launch-preparation-custody")]
    ExportCustody {
        limits: super::custody::CustodyProducerLimits,
        admission: execution_proof_handoff::rootfs_custody::AdmissionBundle,
        reply: oneshot::Sender<
            Result<super::custody::CustodyMaterial, super::custody::CustodyProducerError>,
        >,
    },
    Begin {
        channel: PrivateFdChannel,
        max_backing_bytes: u64,
        reply: Reply,
    },
    Retry {
        reply: Reply,
    },
    Poll {
        reply: Reply,
    },
}
enum Request {
    Begin(PrivateFdChannel, u64),
    Retry,
    Poll,
}

struct RetainedOffer {
    transfer: SenderTransfer,
    origin: OwnedFd,
    channel: PrivateFdChannel,
}
impl RetainedOffer {
    fn observation(&self) -> RootfsOfferObservation {
        RootfsOfferObservation {
            draft: self.transfer.draft().clone(),
            status: self.transfer.status(),
        }
    }
    fn send(&mut self) -> Result<RootfsOfferObservation, RootfsOfferError> {
        if self.transfer.status() != SenderStatus::EnvelopeReceived {
            // Record possible remote effects before invoking sendmsg. A full
            // socket queue retains this same identity for the explicit retry.
            self.transfer
                .mark_sent()
                .map_err(RootfsOfferError::Protocol)?;
            self.channel
                .try_send(&self.transfer.draft().encode(), Some(self.origin.as_fd()))
                .map_err(RootfsOfferError::Transport)?;
        }
        Ok(self.observation())
    }
    fn poll(&mut self) -> Result<RootfsOfferObservation, RootfsOfferError> {
        if let Some(packet) = self
            .channel
            .try_receive(FdExpectation::None)
            .map_err(RootfsOfferError::Transport)?
        {
            let (bytes, _no_descriptor) = packet.into_parts();
            let receipt = OfferReceipt::decode(&bytes).map_err(RootfsOfferError::Protocol)?;
            self.transfer
                .accept_receipt(&receipt)
                .map_err(RootfsOfferError::Protocol)?;
        }
        Ok(self.observation())
    }
}
impl Drop for RetainedOffer {
    fn drop(&mut self) {
        // This cannot revoke a descriptor already queued or owned by the peer.
        self.transfer.abort();
    }
}

pub(super) fn serve(
    attempt: &mut PreparationAttempt,
    commands: &std::sync::mpsc::Receiver<ActorCommand>,
    #[cfg(test)] mut barrier: Option<StageBarrier>,
) {
    let mut retained: Option<RetainedOffer> = None;
    #[cfg(feature = "launch-preparation-custody")]
    let mut custody_exported = false;
    while let Ok(command) = commands.recv() {
        #[cfg(feature = "launch-preparation-custody")]
        let command = match command {
            ActorCommand::ExportCustody {
                limits,
                admission,
                reply,
            } => {
                if reply.is_closed() {
                    break;
                }
                let result = if custody_exported || retained.is_some() {
                    Err(super::custody::CustodyProducerError::Conflict)
                } else {
                    custody_exported = true;
                    attempt.export_custody_material(limits, admission)
                };
                let failed = result.is_err();
                if reply.send(result).is_err() || failed {
                    break;
                }
                continue;
            }
            command if custody_exported => {
                drop(command);
                break;
            }
            command => command,
        };
        let (request, reply) = match command {
            #[cfg(feature = "launch-preparation-custody")]
            ActorCommand::ExportCustody { .. } => break,
            ActorCommand::Begin {
                channel,
                max_backing_bytes,
                reply,
            } => (Request::Begin(channel, max_backing_bytes), reply),
            ActorCommand::Retry { reply } => (Request::Retry, reply),
            ActorCommand::Poll { reply } => (Request::Poll, reply),
        };
        #[cfg(test)]
        if let Some(barrier) = barrier.take() {
            let _ = barrier.reached.send(());
            let _ = barrier.release.recv();
        }
        if reply.is_closed() {
            break;
        }
        let outcome = match request {
            Request::Begin(channel, max_backing_bytes) => {
                if retained.is_some() {
                    Err(RootfsOfferError::Conflict)
                } else {
                    attempt
                        .rootfs_offer_origin(max_backing_bytes)
                        .and_then(|(draft, origin)| {
                            let mut offer = RetainedOffer {
                                transfer: SenderTransfer::new(draft),
                                origin,
                                channel,
                            };
                            let result = offer.send();
                            retained = Some(offer);
                            result
                        })
                }
            }
            Request::Retry => retained
                .as_mut()
                .ok_or(RootfsOfferError::Unavailable)
                .and_then(RetainedOffer::send),
            Request::Poll => retained
                .as_mut()
                .ok_or(RootfsOfferError::Unavailable)
                .and_then(RetainedOffer::poll),
        };
        let failed = outcome.is_err();
        if reply.send(outcome).is_err() || failed {
            break;
        }
    }
    // Closing a retained endpoint discards its inbound queue and local aliases.
    // The caller drops the attempt before returning its active-attempt permit.
    drop(retained);
}

impl RuntimeAttempt {
    async fn rootfs_offer_request(
        &mut self,
        request: Request,
    ) -> Result<RootfsOfferObservation, RootfsOfferError> {
        let (reply, receive) = oneshot::channel();
        let command = match request {
            Request::Begin(channel, max_backing_bytes) => {
                if max_backing_bytes == 0 || max_backing_bytes > isize::MAX as u64 {
                    self.state = RuntimeState::Terminal;
                    return Err(RootfsOfferError::InvalidLimit);
                }
                ActorCommand::Begin {
                    channel,
                    max_backing_bytes,
                    reply,
                }
            }
            Request::Retry => ActorCommand::Retry { reply },
            Request::Poll => ActorCommand::Poll { reply },
        };
        // The future owns the sole keepalive through dispatch and await. If it
        // is dropped, the attempt stays terminal and the worker sees closure;
        // a stale snapshot cannot outlive the actual preparation owner.
        let RuntimeState::Staged(retained) =
            std::mem::replace(&mut self.state, RuntimeState::Terminal)
        else {
            return Err(RootfsOfferError::Unavailable);
        };
        if retained._keepalive.try_send(command).is_err() {
            return Err(RootfsOfferError::Worker);
        }
        let result = match tokio::time::timeout(self.resources.workflow_timeout, receive).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(RootfsOfferError::Worker),
            Err(_) => Err(RootfsOfferError::Deadline),
        };
        if result.is_ok() {
            self.state = RuntimeState::Staged(retained);
        }
        result
    }
}

impl ErofsRuntimeAttempt {
    #[cfg(test)]
    pub(crate) fn set_offer_barrier(
        &mut self,
        reached: oneshot::Sender<()>,
        release: std::sync::mpsc::Receiver<()>,
    ) {
        self.0.offer_barrier = Some(StageBarrier { reached, release });
    }
    /// Begin once using the endpoint provisioned by trusted startup. The peer
    /// must independently verify admission, sealed bytes and its actual view.
    pub async fn begin_rootfs_offer(
        &mut self,
        channel: PrivateFdChannel,
        max_backing_bytes: u64,
    ) -> Result<RootfsOfferObservation, RootfsOfferError> {
        self.0
            .rootfs_offer_request(Request::Begin(channel, max_backing_bytes))
            .await
    }
    pub async fn retry_rootfs_offer(&mut self) -> Result<RootfsOfferObservation, RootfsOfferError> {
        self.0.rootfs_offer_request(Request::Retry).await
    }
    pub async fn poll_rootfs_offer(&mut self) -> Result<RootfsOfferObservation, RootfsOfferError> {
        self.0.rootfs_offer_request(Request::Poll).await
    }
}

#[cfg(feature = "launch-preparation-mount")]
impl MountedRuntimeAttempt {
    pub async fn begin_rootfs_offer(
        &mut self,
        channel: PrivateFdChannel,
        max_backing_bytes: u64,
    ) -> Result<RootfsOfferObservation, RootfsOfferError> {
        self.0
            .rootfs_offer_request(Request::Begin(channel, max_backing_bytes))
            .await
    }
    pub async fn retry_rootfs_offer(&mut self) -> Result<RootfsOfferObservation, RootfsOfferError> {
        self.0.rootfs_offer_request(Request::Retry).await
    }
    pub async fn poll_rootfs_offer(&mut self) -> Result<RootfsOfferObservation, RootfsOfferError> {
        self.0.rootfs_offer_request(Request::Poll).await
    }
}
