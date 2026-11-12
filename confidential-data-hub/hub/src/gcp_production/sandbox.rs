// SPDX-License-Identifier: Apache-2.0

use super::{
    checked, hash_syntax, public_bytes, raw48, receive_packet, send_packet, ControlIo,
    ManagementKey, ProductionRejected, Result, FRAME_TIMEOUT,
};
use execution_proof_contract::gcp_startup::{GcpAttemptPlanV1, MAX_SPEC_BYTES};
use execution_proof_handoff::{
    fd_transport::FdExpectation,
    gcp_startup::{self, EmbeddedRole, ManagementRelayOwner},
    sandbox_gateway::{self, ChildEvent, ParentCommand},
    startup::{LaunchedRole, StartupBoundChannel, StartupError},
};
use sha2::{Digest, Sha384};
use std::{os::fd::AsFd, time::Duration};
use tokio::time::{sleep, Instant};

const CONTROL_TIMEOUT: Duration = Duration::from_secs(10);
const DRAIN_TIMEOUT: Duration = Duration::from_secs(30);

/// Owns both management processes across the pending Create and protected app
/// phases. The relay is dropped first on errors to close external admission.
pub(super) struct EarlySandbox {
    relay: ManagementRelayOwner,
    channel: StartupBoundChannel,
    role: LaunchedRole,
    candidate_id: String,
}

impl EarlySandbox {
    pub(super) async fn start(
        embedded: &EmbeddedRole,
        management_key: ManagementKey,
        control: &mut ControlIo,
    ) -> Result<Self> {
        let (mut channel, role) = checked(sandbox_gateway::launch(embedded))?;
        let ready = receive_event(&mut channel, Instant::now() + CONTROL_TIMEOUT).await?;
        if !matches!(ready, ChildEvent::Ready) {
            return Err(ProductionRejected);
        }
        let relay = checked(gcp_startup::launch_management_relay(
            embedded,
            &management_key.0,
        ))?;
        drop(management_key);
        control
            .publish("sandbox-ready", &serde_json::json!({}))
            .await?;

        let ChildEvent::Candidate {
            container_id,
            wire_sha384,
        } = receive_event(&mut channel, Instant::now() + FRAME_TIMEOUT).await?
        else {
            return Err(ProductionRejected);
        };
        validate_candidate(&container_id, &wire_sha384)?;
        control
            .publish(
                "sandbox-candidate",
                &serde_json::json!({"container_id":container_id,"wire_sha384":wire_sha384}),
            )
            .await?;
        Ok(Self {
            relay,
            channel,
            role,
            candidate_id: container_id,
        })
    }

    pub(super) async fn bind(
        &mut self,
        plan: &GcpAttemptPlanV1,
        image_ref: String,
        effective_spec: &[u8],
    ) -> Result<()> {
        require_candidate_plan(
            &self.candidate_id,
            &plan.container_id,
            &plan.effective_spec_sha384,
            effective_spec,
        )?;
        let spec = checked(gcp_startup::sealed_public_file(
            effective_spec,
            MAX_SPEC_BYTES,
        ))?;
        let command = checked(serde_json::to_vec(&ParentCommand::Bind {
            container_id: plan.container_id.clone(),
            image_ref,
        }))?;
        let deadline = Instant::now() + CONTROL_TIMEOUT;
        send_packet(&mut self.channel, deadline, &command, Some(spec.as_fd())).await?;
        match receive_event(&mut self.channel, deadline).await? {
            ChildEvent::Bound => Ok(()),
            _ => Err(ProductionRejected),
        }
    }

    pub(super) async fn attach(&mut self) -> Result<()> {
        let command = checked(serde_json::to_vec(&ParentCommand::Attach))?;
        let deadline = Instant::now() + CONTROL_TIMEOUT;
        send_packet(&mut self.channel, deadline, &command, None).await?;
        match receive_event(&mut self.channel, deadline).await? {
            ChildEvent::Attached => Ok(()),
            _ => Err(ProductionRejected),
        }
    }

    /// No message is expected while the owner waits for the signed plan or
    /// protected readiness. An unexpected packet or closed peer ends the wait.
    pub(super) async fn ended_or_unexpected_event(&mut self) {
        while matches!(self.channel.try_receive(FdExpectation::None), Ok(None)) {
            sleep(Duration::from_millis(1)).await;
        }
    }

    pub(super) async fn finish_after_archive_ack(mut self) -> Result<()> {
        let command = checked(serde_json::to_vec(&ParentCommand::ReleaseExit {}))?;
        send_packet(
            &mut self.channel,
            Instant::now() + CONTROL_TIMEOUT,
            &command,
            None,
        )
        .await?;
        let deadline = Instant::now() + DRAIN_TIMEOUT;
        // Kata releases the app exit and drains worker teardown over this relay.
        let role = loop {
            if Instant::now() >= deadline {
                break Err(ProductionRejected);
            }
            // Poll the thread-bound role owner without moving it off this runtime.
            match self.role.wait(Duration::from_millis(1)) {
                Err(StartupError::Deadline) => sleep(Duration::from_millis(1)).await,
                result => break checked(result),
            }
        };
        let relay = checked(self.relay.stop_and_wait());
        role.and(relay)
    }
}

async fn receive_event(channel: &mut StartupBoundChannel, deadline: Instant) -> Result<ChildEvent> {
    let (wire, _) = receive_packet(channel, deadline, FdExpectation::None).await?;
    checked(serde_json::from_slice(&wire))
}

fn validate_candidate(container_id: &str, wire_sha384: &str) -> Result<()> {
    if container_id.is_empty()
        || container_id.len() > execution_proof_contract::MAX_ID_BYTES
        || !container_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
        || !hash_syntax(wire_sha384, 48)
    {
        return Err(ProductionRejected);
    }
    Ok(())
}

fn require_candidate_plan(
    candidate_id: &str,
    signed_id: &str,
    signed_spec_sha384: &str,
    effective_spec: &[u8],
) -> Result<()> {
    public_bytes(effective_spec, MAX_SPEC_BYTES)?;
    let actual: [u8; 48] = Sha384::digest(effective_spec).into();
    if candidate_id != signed_id || actual != raw48(signed_spec_sha384)? {
        return Err(ProductionRejected);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn early_candidate_only_publishes_bounded_identifiers_and_commitments() {
        let digest = "12".repeat(48);
        assert!(validate_candidate("app_id-1", &digest).is_ok());
        for invalid in ["", "app/new", "app\nwrong", &"x".repeat(129)] {
            assert!(validate_candidate(invalid, &digest).is_err());
        }
        for invalid in ["00".repeat(48), "AA".repeat(48), "ab".repeat(47)] {
            assert!(validate_candidate("app_id-1", &invalid).is_err());
        }
    }

    #[test]
    fn early_binding_requires_candidate_id_and_exact_signed_spec_bytes() {
        let spec = br#"{"args":["/app"]}"#;
        let signed_sha = concat!(
            "a37c72b06495ac70d1c6f6a0c11ee0c0918544980cf6eeeb3",
            "fc887d3172bff7b0d756d1ee5e5535b6591be1002b5c6d8"
        );
        assert!(require_candidate_plan("app-id", "app-id", signed_sha, spec).is_ok());
        assert!(require_candidate_plan("app-id", "other-id", signed_sha, spec).is_err());
        assert!(require_candidate_plan("app-id", "app-id", signed_sha, b"{}").is_err());
        assert!(require_candidate_plan("app-id", "app-id", signed_sha, b"").is_err());
    }
}
