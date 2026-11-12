// SPDX-License-Identifier: Apache-2.0

//! Closed GCP preparation owner. The only stdin inputs are bounded public
//! authenticated statements, a candidate spec bound by L, and a management TLS
//! private key whose identity is pinned separately. No supplied input selects
//! roots, policy, executable paths, registry addresses or KMS identity.
//! Inputs retain their four-byte length and strict JSON. Public responses use
//! the versioned ONB2 codec; generic Hub/AA/APF services are never initialized.

#[path = "gcp_public_serial.rs"]
pub mod public_serial;
mod sandbox;

use sandbox::EarlySandbox;

use crate::launch_preparation::{
    runtime::{
        CheckedRuntimeAttemptConfig, CustodyProducerError, CustodyProducerLimits,
        CustodyProducerStatus, CustodyRuntimeAttempt, ErofsRuntimeAttemptConfig,
        RuntimeAttemptConfig, RuntimeDelivery, RuntimeError, RuntimeFactory,
    },
    ImageContentLimits, PreparationLimits, PreparationProfile,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use execution_proof_client::gcp::https::{GcpHttpsTransport, GcpLaunchRoute};
use execution_proof_contract::{
    admission::gcp::GcpAdmissionOperation,
    gcp_artifact::{ClosedBootConfigV1, ProducerLeafKind},
    gcp_boot_binding::GcpBootBindingV1,
    gcp_bootstrap::GcpBootstrapChallenge,
    gcp_policy_receipt::{verify_policy_aggregate, GcpAggregateExpectations},
    gcp_startup::{verify_attempt_plan, GcpRoleCapsuleV1, CAPSULE_PURPOSE, MAX_SPEC_BYTES},
    policy_receipt::ResourcePolicyRequest,
    verify_launch_grant_historical, GrantExpectations, LaunchGrant, Signed, VerifiedLaunchGrant,
};
use execution_proof_handoff::{
    admission::gcp::GcpGuestAdmissionConfig,
    fd_transport::{FdExpectation, SendOutcome},
    gcp_startup::{self, EmbeddedRole, Publication, PublicationKind},
    startup::{launch_kata_role, PinnedRoleExecutable, Role, RoleCommand, StartupBoundChannel},
};
use image_rs::preparation::{
    erofs_builder::{ErofsBuildLimits, TrustedErofsBuilder},
    launch_spec::{EffectiveSpecLimits, EffectiveSpecPolicy},
    layer_content::LayerContentLimits,
    manifest_signature::{RequiredCosignPolicy, SignatureLimits},
    registry_ingress::{RegistryIngressLimits, TrustedRegistry, TrustedRegistryConfig},
    rootfs_staging::{BuilderInputLimits, PrivateStagingParent, RootfsStagingLimits},
    static_elf::StaticElfLimits,
};
use kbs_protocol::gcp_launch_recorder::{GcpLaunchKeys, GcpLaunchRecorder, GcpRecorderConfig};
use nix::libc;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{
    fs::{DirBuilder, File, OpenOptions},
    io,
    net::SocketAddr,
    os::{
        fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd},
        unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    },
    time::Duration,
};
use tokio::{
    io::unix::AsyncFd,
    time::{timeout, Instant},
};
use zeroize::Zeroizing;

const PREPARATION_CONFIG: &str = "/onb17/policy/preparation.json";
const STAGING_PARENT: &str = "/run/onb17/preparation";
const REQUEST_PURPOSE: &str = "qlad.execution-proof.gcp-preparation-control.v1";
const RESPONSE_PURPOSE: &str = "qlad.execution-proof.gcp-preparation-publication.v1";
const INPUT_BYTES: usize = 4 << 20;
const OUTPUT_BYTES: usize = 17 << 20;
const CONTROL_BYTES: usize = 32 << 10;
const IMAGE_BYTES: usize = 32 << 20;
const INODES: usize = 4096;
const PHASE_TIMEOUT: Duration = Duration::from_secs(300);
const FRAME_TIMEOUT: Duration = Duration::from_secs(60);
const DIAGNOSTIC_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProductionRejected;
impl std::fmt::Display for ProductionRejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("GCP production preparation rejected")
    }
}
impl std::error::Error for ProductionRejected {}
type Result<T> = std::result::Result<T, ProductionRejected>;
fn checked<T, E>(v: std::result::Result<T, E>) -> Result<T> {
    v.map_err(|_| ProductionRejected)
}

// Only fixed local operation names and error categories may cross this boundary.
// These diagnostics carry no error strings, HTTP bodies, keys or measurements.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum PostgrantStage {
    GrantVerify,
    RecorderInit,
    HttpsInit,
    Begin,
    Collect,
    Capture,
    Challenge,
    Decision,
    Aggregate,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum PostgrantErrorClass {
    Rejected,
    Transport,
    HttpStatus,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
struct PostgrantDiagnostic {
    stage: PostgrantStage,
    error_class: PostgrantErrorClass,
}
type PostgrantResult<T> = std::result::Result<T, PostgrantDiagnostic>;
fn postgrant_checked<T, E>(
    stage: PostgrantStage,
    value: std::result::Result<T, E>,
) -> PostgrantResult<T> {
    value.map_err(|_| PostgrantDiagnostic {
        stage,
        error_class: PostgrantErrorClass::Rejected,
    })
}
fn postgrant_client<T>(
    stage: PostgrantStage,
    value: std::result::Result<T, execution_proof_client::ClientError>,
) -> PostgrantResult<T> {
    value.map_err(|error| PostgrantDiagnostic {
        stage,
        error_class: match error {
            execution_proof_client::ClientError::Transport => PostgrantErrorClass::Transport,
            execution_proof_client::ClientError::HttpStatus => PostgrantErrorClass::HttpStatus,
            _ => PostgrantErrorClass::Rejected,
        },
    })
}
async fn diagnostic_outcome<T>(
    control: &mut ControlIo,
    value: std::result::Result<T, impl Serialize>,
) -> Result<T> {
    match value {
        Ok(value) => Ok(value),
        Err(diagnostic) => {
            // Call only before attempting the next primary publication. The
            // existing caller owns cancellation. This bounded diagnostic does
            // not retry or change the original rejection outcome.
            let _ = timeout(DIAGNOSTIC_TIMEOUT, control.publish("unproven", &diagnostic)).await;
            Err(ProductionRejected)
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ReadyStage {
    AdmissionInput,
    CredentialRequest,
    CredentialHttp,
    Prepare,
    CustodyProgress,
    KataReady,
    ManagementRelay,
    SandboxLifetime,
    SandboxAttach,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ReadyErrorClass {
    Rejected,
    Transport,
    HttpStatus,
    AdmissionRejected,
    CredentialRejected,
    RegistryRejected,
    PreparationRejected,
    Deadline,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
struct ReadyDiagnostic {
    stage: ReadyStage,
    error_class: ReadyErrorClass,
}

impl ReadyDiagnostic {
    fn rejected(stage: ReadyStage) -> Self {
        Self {
            stage,
            error_class: ReadyErrorClass::Rejected,
        }
    }

    fn deadline(stage: ReadyStage) -> Self {
        Self {
            stage,
            error_class: ReadyErrorClass::Deadline,
        }
    }

    fn credential_http(error: execution_proof_client::ClientError) -> Self {
        let error_class = match error {
            execution_proof_client::ClientError::Transport => ReadyErrorClass::Transport,
            execution_proof_client::ClientError::HttpStatus => ReadyErrorClass::HttpStatus,
            _ => ReadyErrorClass::Rejected,
        };
        Self {
            stage: ReadyStage::CredentialHttp,
            error_class,
        }
    }

    fn prepare(error: CustodyProducerError) -> Self {
        let error_class = match error {
            CustodyProducerError::Preparation(RuntimeError::AdmissionRejected) => {
                ReadyErrorClass::AdmissionRejected
            }
            CustodyProducerError::Preparation(RuntimeError::CredentialRejected) => {
                ReadyErrorClass::CredentialRejected
            }
            CustodyProducerError::Preparation(RuntimeError::RegistryRejected) => {
                ReadyErrorClass::RegistryRejected
            }
            CustodyProducerError::Preparation(RuntimeError::PreparationRejected) => {
                ReadyErrorClass::PreparationRejected
            }
            CustodyProducerError::Deadline
            | CustodyProducerError::Preparation(RuntimeError::Deadline) => {
                ReadyErrorClass::Deadline
            }
            _ => ReadyErrorClass::Rejected,
        };
        Self {
            stage: ReadyStage::Prepare,
            error_class,
        }
    }

    fn custody_progress(error: CustodyProducerError) -> Self {
        match error {
            CustodyProducerError::Deadline => Self::deadline(ReadyStage::CustodyProgress),
            _ => Self::rejected(ReadyStage::CustodyProgress),
        }
    }
}

/// Public D-leaf configuration. Every referenced file must itself be in D.
/// There are no ambient credentials, DNS addresses or configurable guard flags.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PreparationConfig {
    version: u16,
    purpose: String,
    aggregate_issuer: String,
    as_policy_id: String,
    as_data_sha384: Option<String>,
    kbs_policy_id: String,
    kbs_policy_sha384: String,
    delivery_audience: String,
    delivery_issuer: String,
    project_id: String,
    client_email: String,
    kms_key_version: String,
    kbs_addresses: Vec<SocketAddr>,
    registry_origin: String,
    registry_repository: String,
    registry_addresses: Vec<SocketAddr>,
    registry_tls_roots_path: String,
    signature_artifact_sha256: String,
    erofs_builder_path: String,
}
impl PreparationConfig {
    fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > CONTROL_BYTES {
            return Err(ProductionRejected);
        }
        let c: Self = checked(serde_json::from_slice(bytes))?;
        if c.version != 1
            || c.purpose != "qlad.execution-proof.gcp-preparation-config.v1"
            || !(1..=8).contains(&c.kbs_addresses.len())
            || !(1..=8).contains(&c.registry_addresses.len())
            || !hash_syntax(&c.kbs_policy_sha384, 48)
            || !hash_syntax(&c.signature_artifact_sha256, 32)
            || c.as_data_sha384
                .as_ref()
                .is_some_and(|h| !hash_syntax(h, 48))
        {
            return Err(ProductionRejected);
        }
        for s in [
            &c.aggregate_issuer,
            &c.as_policy_id,
            &c.kbs_policy_id,
            &c.delivery_audience,
            &c.delivery_issuer,
            &c.project_id,
            &c.client_email,
            &c.kms_key_version,
            &c.registry_origin,
            &c.registry_repository,
            &c.registry_tls_roots_path,
            &c.erofs_builder_path,
        ] {
            if s.is_empty()
                || s.len() > 1024
                || !s.is_ascii()
                || s.bytes().any(|b| b.is_ascii_control())
            {
                return Err(ProductionRejected);
            }
        }
        Ok(c)
    }
}

/// No Debug/Serialize implementation; deserialization moves the allocated secret
/// string directly into its zeroizing owner. The raw frame is zeroized too.
struct ManagementKey(Zeroizing<Vec<u8>>);
impl<'de> Deserialize<'de> for ManagementKey {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        let secret = Zeroizing::new(s.into_bytes());
        if secret.is_empty() || secret.len() > 16 << 10 {
            return Err(serde::de::Error::custom("management key rejected"));
        }
        Ok(Self(secret))
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request<T> {
    version: u16,
    purpose: String,
    request: T,
}
impl<T: DeserializeOwned> Request<T> {
    fn decode(bytes: &[u8]) -> Result<T> {
        if bytes.is_empty() || bytes.len() > INPUT_BYTES {
            return Err(ProductionRejected);
        }
        let r: Self = checked(serde_json::from_slice(bytes))?;
        if r.version != 1 || r.purpose != REQUEST_PURPOSE {
            return Err(ProductionRejected);
        }
        Ok(r.request)
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BootRequest {
    signed_manifest: Vec<u8>,
    signed_references: Vec<u8>,
    signed_bootstrap_challenge: Vec<u8>,
    management_tls_private_key_pem: ManagementKey,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GrantRequest {
    signed_grant: Vec<u8>,
}
struct PostgrantReady {
    grant_input: GrantRequest,
    grant: VerifiedLaunchGrant,
    signed: Signed<LaunchGrant>,
    recorder: GcpLaunchRecorder,
    kbs: GcpHttpsTransport,
    aggregate: Vec<u8>,
    aggregate_expect: GcpAggregateExpectations,
    publication: serde_json::Value,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PlanRequest {
    signed_plan: Vec<u8>,
    effective_spec: Vec<u8>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AdmissionRequest {
    signed_authorization: Vec<u8>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StopRequest {
    stop: bool,
}

enum ManagementTransport {
    Deferred(ManagementKey),
    Sandbox(EarlySandbox),
}

/// This process owns the async runtime and all children through shutdown. The
/// launching thread also owns PDEATHSIG-sensitive role handles.
pub fn run() -> Result<()> {
    // SAFETY: these prctl options take integer flags and no pointer arguments.
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
        return Err(ProductionRejected);
    }
    let limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: limit is a live, initialized rlimit for this process only.
    if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) } != 0 {
        return Err(ProductionRejected);
    }
    // Authenticate actual immutable self and full inventory before keys or I/O.
    let embedded = checked(gcp_startup::load_embedded(Role::Preparation))?;
    let runtime = checked(
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build(),
    )?;
    runtime.block_on(run_owned(embedded))
}

async fn run_owned(embedded: EmbeddedRole) -> Result<()> {
    let config = PreparationConfig::decode(&checked(
        embedded.read_leaf(PREPARATION_CONFIG, CONTROL_BYTES),
    )?)?;
    let mut control = ControlIo::stdio()?;
    // The PID1 boot marker precedes exec/readback/raw tty setup. Publish only
    // after echo is disabled so the operator knows when private input is safe.
    control
        .publish("control-ready", &serde_json::json!({}))
        .await?;
    let boot: BootRequest = control.request().await?;
    public_bytes(&boot.signed_bootstrap_challenge, CONTROL_BYTES)?;
    let (binding, _artifacts) =
        checked(embedded.authenticate_artifacts(&boot.signed_manifest, &boot.signed_references))?;
    let challenge: Signed<GcpBootstrapChallenge> =
        checked(serde_json::from_slice(&boot.signed_bootstrap_challenge))?;
    let c = embedded.config();
    if challenge.statement.boot_binding != binding
        || challenge.statement.authority != c.authority
        || challenge.statement.tenant != c.tenant
        || challenge.statement.audience != c.grant_audience
    {
        return Err(ProductionRejected);
    }
    let mut keys = checked(GcpLaunchKeys::generate(binding.clone()))?;
    let (bootstrap_binding, evidence) = {
        let capture = checked(keys.collect_bootstrap(
            &boot.signed_bootstrap_challenge,
            &challenge.statement,
            &c.roots.authority_public_key,
        ))?;
        (capture.binding.clone(), capture.evidence.clone())
    };
    control
        .publish(
            "bootstrap",
            &serde_json::json!({
                "challenge_id":challenge.statement.challenge_id,
                "submission":{
                    "binding":bootstrap_binding,"evidence":evidence,
                    "recorder_public_key":keys.recorder_public_key(),
                    "possession_signature_hex":checked(keys.bootstrap_possession_signature())?,
                    "keywrap_public_key":checked(keys.keywrap_public_key())?
                }
            }),
        )
        .await?;
    let prepared: PostgrantResult<_> = async {
        use PostgrantStage::*;
        let grant_input: GrantRequest = postgrant_checked(GrantVerify, control.request().await)?;
        postgrant_checked(
            GrantVerify,
            public_bytes(&grant_input.signed_grant, CONTROL_BYTES),
        )?;
        let grant_expect = postgrant_checked(GrantVerify, grant_expectations(c, &binding))?;
        let grant = postgrant_checked(
            GrantVerify,
            verify_launch_grant_historical(&grant_input.signed_grant, &grant_expect),
        )?;
        let signed: Signed<LaunchGrant> = postgrant_checked(
            GrantVerify,
            serde_json::from_slice(&grant_input.signed_grant),
        )?;
        let recorder_config =
            postgrant_checked(RecorderInit, recorder_config(c, &config, &binding))?;
        let mut recorder = postgrant_checked(
            RecorderInit,
            keys.into_recorder(grant_input.signed_grant.clone(), recorder_config),
        )?;
        let roots = postgrant_checked(
            HttpsInit,
            embedded.read_leaf(&c.kbs_tls_roots_path, 64 << 10),
        )?;
        let kbs = postgrant_client(
            HttpsInit,
            GcpHttpsTransport::with_trusted_roots(
                &c.kbs_https_origin,
                &roots,
                &config.kbs_addresses,
            ),
        )?;
        let begin_request = postgrant_checked(Begin, recorder.begin_request())?;
        let begin_response =
            postgrant_client(Begin, kbs.post(GcpLaunchRoute::Begin, &begin_request).await)?;
        postgrant_checked(Begin, recorder.accept_begin_response(&begin_response))?;
        let capture_request = postgrant_checked(Collect, recorder.collect_capture_request())?;
        let capture_response = postgrant_client(
            Capture,
            kbs.post(GcpLaunchRoute::Capture, &capture_request).await,
        )?;
        let challenge_request =
            postgrant_checked(Challenge, recorder.resource_challenge_request())?;
        let challenge_response = postgrant_client(
            Challenge,
            kbs.post(GcpLaunchRoute::ResourceChallenge, &challenge_request)
                .await,
        )?;
        postgrant_checked(
            Challenge,
            recorder.accept_resource_challenge_response(&challenge_response),
        )?;
        let request = ResourcePolicyRequest {
            method: "GET".into(),
            plugin: "resource".into(),
            resource_path: c.resource_path.clone(),
            workflow_id: c.workflow_id.clone(),
            request_nonce: postgrant_checked(
                Decision,
                recorder.request_nonce().ok_or(ProductionRejected),
            )?
            .into(),
        };
        let decision_request =
            postgrant_checked(Decision, recorder.resource_decision_request(&request))?;
        let decision_response = postgrant_client(
            Decision,
            kbs.post(GcpLaunchRoute::ResourceDecision, &decision_request)
                .await,
        )?;
        let aggregate = postgrant_checked(
            Aggregate,
            decode_aggregate_response(&decision_response, &binding),
        )?;
        let aggregate_expect =
            postgrant_checked(Aggregate, recorder.pin_signed_aggregate(&aggregate))?;
        let publication = serde_json::json!({"signed_aggregate":aggregate,
            "begin_response_base64":STANDARD.encode(begin_response),
            "capture_request_base64":STANDARD.encode(capture_request),
            "capture_response_base64":STANDARD.encode(capture_response),
            "resource_challenge_response_base64":STANDARD.encode(challenge_response),
            "resource_decision_response_base64":STANDARD.encode(decision_response)});
        Ok(PostgrantReady {
            grant_input,
            grant,
            signed,
            recorder,
            kbs,
            aggregate,
            aggregate_expect,
            publication,
        })
    }
    .await;
    let PostgrantReady {
        grant_input,
        grant,
        signed,
        recorder,
        kbs,
        aggregate,
        aggregate_expect,
        publication,
    } = diagnostic_outcome(&mut control, prepared).await?;
    // A failed/cancelled policy publication is terminal. Never append a
    // diagnostic frame to a possibly partial primary publication.
    control.publish("policy", &publication).await?;
    drop(publication);
    let verify_aggregate = || {
        checked(verify_policy_aggregate(
            &aggregate,
            &grant,
            &aggregate_expect,
        ))
    };
    let (mut management, early_aggregate) = if embedded.sandbox_gateway_enabled() {
        let verified = verify_aggregate()?;
        let sandbox =
            EarlySandbox::start(&embedded, boot.management_tls_private_key_pem, &mut control)
                .await?;
        (ManagementTransport::Sandbox(sandbox), Some(verified))
    } else {
        (
            ManagementTransport::Deferred(boot.management_tls_private_key_pem),
            None,
        )
    };
    let plan_input: PlanRequest = match &mut management {
        ManagementTransport::Deferred(_) => control.request().await?,
        ManagementTransport::Sandbox(sandbox) => tokio::select! {
            request = control.request() => request?,
            () = sandbox.ended_or_unexpected_event() => return Err(ProductionRejected),
        },
    };
    public_bytes(&plan_input.signed_plan, CONTROL_BYTES)?;
    public_bytes(&plan_input.effective_spec, MAX_SPEC_BYTES)?;
    let verified_aggregate = match early_aggregate {
        Some(verified) => verified,
        None => verify_aggregate()?,
    };
    let plan = checked(verify_attempt_plan(
        &plan_input.signed_plan,
        &c.roots.authority_public_key,
        &grant,
        &verified_aggregate,
        &binding,
    ))?;
    if let ManagementTransport::Sandbox(sandbox) = &mut management {
        let image_ref = format!(
            "{}@sha256:{}",
            config.registry_repository,
            grant.binding().selected_manifest_sha256
        );
        sandbox
            .bind(&plan, image_ref, &plan_input.effective_spec)
            .await?;
    }
    let capsule = GcpRoleCapsuleV1 {
        version: 1,
        purpose: CAPSULE_PURPOSE.into(),
        signed_manifest: boot.signed_manifest,
        signed_references: boot.signed_references,
        signed_grant: grant_input.signed_grant.clone(),
        signed_aggregate: aggregate.clone(),
        signed_plan: plan_input.signed_plan,
        effective_spec: plan_input.effective_spec.clone(),
    };
    let kata_leaf = embedded
        .core()
        .leaves
        .iter()
        .find(|l| l.path == c.kata_agent_path && l.kind == ProducerLeafKind::KataAgentBinary)
        .ok_or(ProductionRejected)?;
    let executable = checked(PinnedRoleExecutable::new(
        checked(File::open(&c.kata_agent_path))?,
        raw48(&kata_leaf.sha384)?,
        kata_leaf.size_bytes,
    ))?;
    let command = checked(
        checked(RoleCommand::new(executable, Vec::new()))?
            .with_gcp_capsule(&checked(capsule.encode())?),
    )?;
    let startup = embedded.expected_startup();
    let (channel, mut role) = checked(launch_kata_role(
        command,
        startup.own_executable_sha384,
        256 << 20,
        startup.boot_config_sha384,
        Duration::from_secs(30),
    ))?;
    let staging = StagingDirectory::create()?;
    let (factory, runtime_config) = runtime_config(
        &embedded,
        &config,
        &binding,
        &signed.statement,
        RuntimeInputs {
            aggregate: aggregate_expect,
            admission_policy_sha384: plan.admission_policy_sha384,
            effective_spec: plan_input.effective_spec,
            parent: staging.open()?,
        },
    )?;
    let mut owner = checked(factory.begin_gcp_custody_attempt(
        runtime_config,
        recorder,
        channel,
        CustodyProducerLimits {
            backing_bytes: IMAGE_BYTES as u64,
            provenance_bytes: 1 << 20,
            admission_bytes: 1 << 20,
        },
    ))?;
    let result = finish_attempt(
        &mut owner,
        &mut control,
        &kbs,
        &aggregate,
        &grant_input.signed_grant,
        &embedded,
        management,
    )
    .await;
    // Retain the preparation actor/backing until publication ends, then drain it
    // before reaping Kata and releasing the staging parent. Errors take this path.
    let cleanup = checked(owner.cancel_and_wait().await);
    // A queued Stop (or closed private channel) is not a joined Kata owner.
    // Allow its observer/task cleanup to complete before the kill/reap fallback.
    let child_exit = checked(role.wait(Duration::from_secs(30)));
    role.terminate_and_wait();
    result.and(cleanup).and(child_exit)
}

async fn finish_attempt(
    owner: &mut CustodyRuntimeAttempt,
    control: &mut ControlIo,
    kbs: &GcpHttpsTransport,
    aggregate: &[u8],
    grant: &[u8],
    embedded: &EmbeddedRole,
    mut management: ManagementTransport,
) -> Result<()> {
    checked(owner.enroll_receiver().await)?;
    let request = checked(owner.gcp_admission_request(aggregate, GcpAdmissionOperation::Redeem))?;
    control.publish("admission_request",&serde_json::json!({"guest_nonce":owner.challenge_nonce(),"recorder_request_json":request})).await?;
    // The admission-request frame was sent completely. A failure before the
    // next frame can now report a fixed diagnostic while preserving cleanup.
    let prepared: std::result::Result<_, ReadyDiagnostic> = async {
        let prepare = async {
            let admission: AdmissionRequest = control
                .request()
                .await
                .map_err(|_| ReadyDiagnostic::rejected(ReadyStage::AdmissionInput))?;
            public_bytes(&admission.signed_authorization, CONTROL_BYTES)
                .map_err(|_| ReadyDiagnostic::rejected(ReadyStage::AdmissionInput))?;
            // The owned gate checks admission before the recorder decrypts the
            // authenticated JWE returned by KBS.
            let credential_request = owner
                .gcp_credential_request(aggregate)
                .map_err(|_| ReadyDiagnostic::rejected(ReadyStage::CredentialRequest))?;
            let credential_response = kbs
                .post(GcpLaunchRoute::CredentialDelivery, &credential_request)
                .await
                .map_err(ReadyDiagnostic::credential_http)?;
            owner
                .prepare(RuntimeDelivery {
                    grant,
                    aggregate,
                    admission_receipt: &admission.signed_authorization,
                    credential_response: &credential_response,
                })
                .await
                .map_err(ReadyDiagnostic::prepare)?;
            let deadline = Instant::now() + PHASE_TIMEOUT;
            while owner.status() != CustodyProducerStatus::Finalized {
                if Instant::now() >= deadline {
                    return Err(ReadyDiagnostic::deadline(ReadyStage::CustodyProgress));
                }
                owner.advance().map_err(ReadyDiagnostic::custody_progress)?;
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            let mut channel = owner
                .take_completed_channel()
                .map_err(ReadyDiagnostic::custody_progress)?;
            let (ready, fd) = receive_publication(&mut channel, deadline)
                .await
                .map_err(|_| ReadyDiagnostic::rejected(ReadyStage::KataReady))?;
            if ready.kind != PublicationKind::Ready || fd.is_some() {
                return Err(ReadyDiagnostic::rejected(ReadyStage::KataReady));
            }
            Ok(channel)
        };
        let channel = match &mut management {
            ManagementTransport::Deferred(_) => prepare.await?,
            ManagementTransport::Sandbox(sandbox) => tokio::select! {
                ready = prepare => ready?,
                () = sandbox.ended_or_unexpected_event() => {
                    return Err(ReadyDiagnostic::rejected(ReadyStage::SandboxLifetime));
                }
            },
        };
        match management {
            ManagementTransport::Deferred(key) => {
                let relay = gcp_startup::launch_management_relay(embedded, &key.0)
                    .map_err(|_| ReadyDiagnostic::rejected(ReadyStage::ManagementRelay))?;
                Ok((channel, Some(relay), None))
            }
            ManagementTransport::Sandbox(mut sandbox) => {
                sandbox
                    .attach()
                    .await
                    .map_err(|_| ReadyDiagnostic::rejected(ReadyStage::SandboxAttach))?;
                Ok((channel, None, Some(sandbox)))
            }
        }
    }
    .await;
    let (mut channel, _relay, sandbox) = diagnostic_outcome(control, prepared).await?;
    // A failed ready write may already have emitted bytes. Propagate it
    // directly and never append a diagnostic to that stream.
    control.publish("ready", &serde_json::json!({})).await?;
    let deadline = Instant::now() + PHASE_TIMEOUT;
    let (publication, fd) = receive_publication(&mut channel, deadline).await?;
    match publication.kind {
        PublicationKind::Export => {
            let file: File = fd.ok_or(ProductionRejected)?.into();
            let bytes = checked(publication.read_export(&file))?;
            control
                .publish(
                    "export",
                    &serde_json::json!({"export_json_base64":STANDARD.encode(bytes)}),
                )
                .await?;
        }
        PublicationKind::Unproven if fd.is_none() => {
            control.publish("unproven", &serde_json::json!({})).await?
        }
        _ => return Err(ProductionRejected),
    }
    // The host sends Stop after archiving the terminal publication. For early
    // sandbox, it also authorizes delivery of the terminal app status.
    let stop: StopRequest = control.request().await?;
    if !stop.stop {
        return Err(ProductionRejected);
    }
    let (sandbox_stopped, stop_deadline) = match sandbox {
        Some(sandbox) => (
            sandbox.finish_after_archive_ack().await,
            Instant::now() + FRAME_TIMEOUT,
        ),
        None => (Ok(()), deadline),
    };
    let wire = checked(checked(Publication::control(PublicationKind::Stop))?.encode())?;
    send_packet(&mut channel, stop_deadline, &wire, None)
        .await
        .and(sandbox_stopped)
}

async fn send_packet(
    channel: &mut StartupBoundChannel,
    deadline: Instant,
    wire: &[u8],
    fd: Option<BorrowedFd<'_>>,
) -> Result<()> {
    loop {
        if Instant::now() >= deadline {
            return Err(ProductionRejected);
        }
        if checked(channel.try_send(wire, fd))? == SendOutcome::Sent {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
}

async fn receive_publication(
    channel: &mut StartupBoundChannel,
    deadline: Instant,
) -> Result<(Publication, Option<OwnedFd>)> {
    let (wire, fd) = receive_packet(channel, deadline, FdExpectation::Optional).await?;
    Ok((checked(Publication::decode(&wire))?, fd))
}

async fn receive_packet(
    channel: &mut StartupBoundChannel,
    deadline: Instant,
    expectation: FdExpectation,
) -> Result<(Vec<u8>, Option<OwnedFd>)> {
    loop {
        if Instant::now() >= deadline {
            return Err(ProductionRejected);
        }
        if let Some(packet) = checked(channel.try_receive(expectation))? {
            return Ok(packet.into_parts());
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
}

fn grant_expectations(c: &ClosedBootConfigV1, b: &GcpBootBindingV1) -> Result<GrantExpectations> {
    Ok(GrantExpectations {
        authority_public_key: c.roots.authority_public_key,
        audience: c.grant_audience.clone(),
        authority: c.authority.clone(),
        tenant: c.tenant.clone(),
        profile_sha384: checked(b.digest_sha384())?,
        launch_policy_sha384: c.launch_policy_sha384.clone(),
        image_policy_sha384: c.image_policy_sha384.clone(),
    })
}
fn recorder_config(
    c: &ClosedBootConfigV1,
    p: &PreparationConfig,
    b: &GcpBootBindingV1,
) -> Result<GcpRecorderConfig> {
    Ok(GcpRecorderConfig {
        grant: grant_expectations(c, b)?,
        expected_boot_binding: b.clone(),
        kbs_proof_public_key: c.roots.kbs_proof_public_key,
        aggregate_audience: c.aggregate_audience.clone(),
        aggregate_issuer: p.aggregate_issuer.clone(),
        as_policy_id: p.as_policy_id.clone(),
        as_policy_sha384: c.launch_policy_sha384.clone(),
        as_data_sha384: p.as_data_sha384.clone(),
        kbs_policy_id: p.kbs_policy_id.clone(),
        kbs_policy_sha384: p.kbs_policy_sha384.clone(),
        resource_path: c.resource_path.clone(),
        workflow_id: c.workflow_id.clone(),
        delivery_audience: p.delivery_audience.clone(),
        delivery_issuer: p.delivery_issuer.clone(),
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DecisionResponse {
    version: u16,
    purpose: String,
    boot_binding_sha384: String,
    outcome: String,
    signed_aggregate_b64: Option<String>,
    historical: bool,
}
fn decode_aggregate_response(bytes: &[u8], binding: &GcpBootBindingV1) -> Result<Vec<u8>> {
    let r: DecisionResponse = checked(serde_json::from_slice(bytes))?;
    checked(execution_proof_client::gcp::check_wire_domain(
        r.version,
        &r.purpose,
        &r.boot_binding_sha384,
        execution_proof_client::gcp::RESOURCE_DECISION_PURPOSE,
        &checked(binding.digest_sha384())?,
    ))?;
    if !matches!(
        (r.outcome.as_str(), r.historical),
        ("current", false) | ("historical", true)
    ) {
        return Err(ProductionRejected);
    }
    let text = r.signed_aggregate_b64.ok_or(ProductionRejected)?;
    if text.len() > CONTROL_BYTES * 2 {
        return Err(ProductionRejected);
    }
    let bytes = checked(STANDARD.decode(&text))?;
    public_bytes(&bytes, CONTROL_BYTES)?;
    if STANDARD.encode(&bytes) != text {
        return Err(ProductionRejected);
    }
    Ok(bytes)
}

struct RuntimeInputs {
    aggregate: GcpAggregateExpectations,
    admission_policy_sha384: String,
    effective_spec: Vec<u8>,
    parent: File,
}
fn runtime_config(
    embedded: &EmbeddedRole,
    p: &PreparationConfig,
    b: &GcpBootBindingV1,
    grant: &LaunchGrant,
    inputs: RuntimeInputs,
) -> Result<(
    RuntimeFactory,
    ErofsRuntimeAttemptConfig<GcpGuestAdmissionConfig>,
)> {
    let c = embedded.config();
    let RuntimeInputs {
        aggregate,
        admission_policy_sha384,
        effective_spec,
        parent,
    } = inputs;
    let registry = checked(TrustedRegistry::new(
        TrustedRegistryConfig {
            origin: p.registry_origin.clone(),
            repository: p.registry_repository.clone(),
            addresses: p.registry_addresses.clone(),
            tls_ca_pem: checked(embedded.read_leaf(&p.registry_tls_roots_path, 64 << 10))?,
            bearer_token: None,
        },
        RegistryIngressLimits {
            manifest_bytes: 1 << 20,
            blob_bytes: IMAGE_BYTES,
            signature_payload_bytes: 64 << 10,
            signature_bytes: 4096,
            connect_timeout: Duration::from_secs(5),
            read_timeout: Duration::from_secs(10),
            request_timeout: Duration::from_secs(30),
        },
    ))?;
    let signature_policy = checked(RequiredCosignPolicy::new(
        &checked(embedded.read_leaf(&c.image_policy_path, CONTROL_BYTES))?,
        &c.image_policy_sha384,
        &p.registry_repository,
        SignatureLimits {
            policy_bytes: CONTROL_BYTES,
            key_bytes: 4096,
            manifest_bytes: 1 << 20,
            payload_bytes: 64 << 10,
            signature_bytes: 4096,
            json_depth: 16,
        },
    ))?;
    let tool = embedded
        .core()
        .leaves
        .iter()
        .find(|l| l.path == p.erofs_builder_path && l.kind == ProducerLeafKind::HelperBinary)
        .ok_or(ProductionRejected)?;
    let builder = checked(TrustedErofsBuilder::new(
        checked(File::open(&tool.path))?,
        raw48(&tool.sha384)?,
        ErofsBuildLimits {
            input: BuilderInputLimits {
                tar_bytes: IMAGE_BYTES,
                inodes: INODES,
                live_file_bytes: IMAGE_BYTES,
            },
            output_bytes: IMAGE_BYTES,
            tool_bytes: 32 << 20,
            address_space_bytes: 512 << 20,
            cpu_seconds: 60,
            wall_time: Duration::from_secs(90),
        },
    ))?;
    let factory = checked(RuntimeFactory::new(registry, 1, PHASE_TIMEOUT))?;
    let base = RuntimeAttemptConfig {
        admission: GcpGuestAdmissionConfig {
            grant: grant_expectations(c, b)?,
            expected_grant: grant.clone(),
            aggregate,
            audience: c.admission_receipt_audience.clone(),
            issuer: c.authority.clone(),
            admission_policy_sha384,
        },
        preparation: PreparationProfile {
            authority_public_key: c.roots.authority_public_key,
            kbs_proof_public_key: c.roots.kbs_proof_public_key,
            binding: grant.binding.clone(),
            grant_sha384: checked(grant.digest_sha384())?,
            validity: grant.validity,
            workflow_id: c.workflow_id.clone(),
            resource_path: c.resource_path.clone(),
            project_id: p.project_id.clone(),
            client_email: p.client_email.clone(),
            kms_key_version: p.kms_key_version.clone(),
        },
        metadata_limits: PreparationLimits {
            manifest_bytes: 1 << 20,
            config_bytes: 256 << 10,
            layer_count: 8,
            packets_per_layer: 1,
            packet_bytes: 64 << 10,
            public_options_bytes: 64 << 10,
            kms_ciphertext_bytes: 64 << 10,
            operations: 8,
        },
        content_limits: ImageContentLimits {
            layer: LayerContentLimits {
                ciphertext_bytes: IMAGE_BYTES,
                private_options_bytes: 64 << 10,
                public_options_bytes: 64 << 10,
                plaintext_bytes: IMAGE_BYTES,
                tar_bytes: IMAGE_BYTES,
                tar_entries: INODES,
                path_bytes: 4096,
                file_bytes: IMAGE_BYTES,
            },
            total_ciphertext_bytes: IMAGE_BYTES,
            total_tar_bytes: IMAGE_BYTES,
        },
        staging_parent: checked(PrivateStagingParent::new(parent))?,
        staging_limits: RootfsStagingLimits {
            layers: 8,
            total_tar_bytes: IMAGE_BYTES,
            applied_entries: INODES,
            inodes: INODES,
            write_bytes: IMAGE_BYTES,
            live_file_bytes: IMAGE_BYTES,
            path_bytes: 4096,
            path_components: 64,
        },
        signature_policy,
        signature_artifact_sha256: p.signature_artifact_sha256.clone(),
    };
    Ok((
        factory,
        ErofsRuntimeAttemptConfig {
            checked: CheckedRuntimeAttemptConfig {
                base,
                effective_spec,
                spec_policy: EffectiveSpecPolicy {
                    uid: gcp_startup::WORKLOAD_UID,
                    gid: gcp_startup::WORKLOAD_GID,
                    seccomp_syscalls: gcp_startup::WORKLOAD_SYSCALLS
                        .iter()
                        .map(|v| (*v).into())
                        .collect(),
                },
                spec_limits: EffectiveSpecLimits {
                    spec_bytes: 256 << 10,
                    args: 64,
                    env: 64,
                    string_bytes: 4096,
                    total_string_bytes: 32 << 10,
                    path_bytes: 4096,
                    path_components: 64,
                    syscalls: 3,
                    json_depth: 32,
                },
                executable_limits: StaticElfLimits {
                    file_bytes: IMAGE_BYTES,
                    program_headers: 128,
                    mapped_bytes: IMAGE_BYTES as u64,
                    virtual_span_bytes: IMAGE_BYTES as u64,
                },
            },
            builder,
        },
    ))
}

struct StagingDirectory;
impl StagingDirectory {
    fn create() -> Result<Self> {
        checked(DirBuilder::new().mode(0o700).create(STAGING_PARENT))?;
        Ok(Self)
    }
    fn open(&self) -> Result<File> {
        let f = checked(
            OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(STAGING_PARENT),
        )?;
        let m = checked(f.metadata())?;
        // SAFETY: statfs is a C output structure initialized by fstatfs below.
        let mut fs: libc::statfs = unsafe { std::mem::zeroed() };
        // SAFETY: geteuid has no arguments; fstatfs writes to live fs for owned f.
        if !m.is_dir()
            || m.uid() != unsafe { libc::geteuid() }
            || m.mode() & 0o777 != 0o700
            || unsafe { libc::fstatfs(f.as_raw_fd(), &mut fs) } != 0
            || fs.f_type as u64 != 0x01021994
        {
            return Err(ProductionRejected);
        }
        Ok(f)
    }
}
impl Drop for StagingDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir(STAGING_PARENT);
    }
}

fn public_bytes(bytes: &[u8], max: usize) -> Result<()> {
    if bytes.is_empty() || bytes.len() > max {
        Err(ProductionRejected)
    } else {
        Ok(())
    }
}
fn hash_syntax(s: &str, n: usize) -> bool {
    s.len() == n * 2
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && s.bytes().any(|b| b != b'0')
}
fn raw48(s: &str) -> Result<[u8; 48]> {
    if !hash_syntax(s, 48) {
        return Err(ProductionRejected);
    }
    let mut b = [0; 48];
    for (i, v) in b.iter_mut().enumerate() {
        *v = checked(u8::from_str_radix(&s[i * 2..i * 2 + 2], 16))?;
    }
    Ok(b)
}

/// AsyncFd uses owned duplicated nonblocking stdio descriptors. There is no
/// Tokio stdin blocking thread to outlive cancellation or hold secret buffers.
struct ControlIo {
    input: AsyncFd<OwnedFd>,
    output: AsyncFd<OwnedFd>,
    _tty: TtyMode,
}
impl ControlIo {
    fn stdio() -> Result<Self> {
        // Disable echo before reading a TLS private key on the physical console.
        let tty = TtyMode::raw(0)?;
        Ok(Self {
            input: async_descriptor(0)?,
            output: async_descriptor(1)?,
            _tty: tty,
        })
    }
    async fn request<T: DeserializeOwned>(&mut self) -> Result<T> {
        let mut length = [0; 4];
        checked(timeout(FRAME_TIMEOUT, read_exact(&self.input, &mut length)).await)??;
        let size = u32::from_be_bytes(length) as usize;
        if size == 0 || size > INPUT_BYTES {
            return Err(ProductionRejected);
        }
        let mut bytes = Zeroizing::new(vec![0; size]);
        checked(timeout(FRAME_TIMEOUT, read_exact(&self.input, &mut bytes)).await)??;
        Request::decode(&bytes)
    }
    async fn publish<T: Serialize>(&mut self, phase: &str, publication: &T) -> Result<()> {
        let bytes = checked(serde_json::to_vec(
            &serde_json::json!({"version":1,"purpose":RESPONSE_PURPOSE,"phase":phase,"publication":publication}),
        ))?;
        if bytes.is_empty() || bytes.len() > OUTPUT_BYTES {
            return Err(ProductionRejected);
        }
        let frame = checked(public_serial::encode_public_json(&bytes))?;
        let budget = checked(public_serial::wire_budget(frame.wire.len()))?;
        checked(
            timeout(budget, async {
                write_all(&self.output, &frame.header).await?;
                write_all(&self.output, &frame.wire).await
            })
            .await,
        )??;
        Ok(())
    }
}
struct TtyMode {
    fd: i32,
    original: Option<libc::termios>,
}
impl TtyMode {
    fn raw(fd: i32) -> Result<Self> {
        // SAFETY: termios is a C output structure; tcgetattr initializes it.
        let mut original: libc::termios = unsafe { std::mem::zeroed() };
        // SAFETY: fd is an inherited stdio descriptor and original is writable.
        if unsafe { libc::tcgetattr(fd, &mut original) } != 0 {
            return if io::Error::last_os_error().raw_os_error() == Some(libc::ENOTTY) {
                Ok(Self { fd, original: None })
            } else {
                Err(ProductionRejected)
            };
        }
        let mut raw = original;
        // SAFETY: raw is an initialized termios owned by this function.
        unsafe { libc::cfmakeraw(&mut raw) };
        // SAFETY: raw remains live for the synchronous tty configuration call.
        if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &raw) } != 0 {
            return Err(ProductionRejected);
        }
        Ok(Self {
            fd,
            original: Some(original),
        })
    }
}
impl Drop for TtyMode {
    fn drop(&mut self) {
        if let Some(original) = &self.original {
            // SAFETY: original remains initialized and live; errors are ignored
            // during teardown, with no subsequent input accepted by this owner.
            let _ = unsafe { libc::tcsetattr(self.fd, libc::TCSANOW, original) };
        }
    }
}
fn async_descriptor(fd: i32) -> Result<AsyncFd<OwnedFd>> {
    // SAFETY: fcntl duplicates the inherited descriptor without taking ownership.
    let raw = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 128) };
    if raw < 0 {
        return Err(ProductionRejected);
    }
    // SAFETY: a successful F_DUPFD_CLOEXEC returns a new exclusively owned FD.
    let owned = unsafe { OwnedFd::from_raw_fd(raw) };
    // SAFETY: these fcntl operations use integer flags on the owned descriptor.
    let flags = unsafe { libc::fcntl(raw, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(raw, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(ProductionRejected);
    }
    checked(AsyncFd::new(owned))
}
async fn read_exact(fd: &AsyncFd<OwnedFd>, mut out: &mut [u8]) -> Result<()> {
    while !out.is_empty() {
        let mut ready = checked(fd.readable().await)?;
        match ready.try_io(|f| {
            // SAFETY: out is a writable live slice of exactly the supplied size;
            // read borrows the owned descriptor and cannot retain the pointer.
            let n = unsafe { libc::read(f.as_raw_fd(), out.as_mut_ptr().cast(), out.len()) };
            if n < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(n as usize)
            }
        }) {
            Ok(Ok(0)) => return Err(ProductionRejected),
            Ok(Ok(n)) => out = &mut out[n..],
            Ok(Err(e)) if e.kind() == io::ErrorKind::Interrupted => {}
            Ok(Err(_)) => return Err(ProductionRejected),
            Err(_) => {}
        }
    }
    Ok(())
}
async fn write_all(fd: &AsyncFd<OwnedFd>, mut bytes: &[u8]) -> Result<()> {
    while !bytes.is_empty() {
        let mut ready = checked(fd.writable().await)?;
        match ready.try_io(|f| {
            // SAFETY: bytes is a live immutable slice throughout this syscall;
            // write borrows the owned descriptor and cannot retain the pointer.
            let n = unsafe { libc::write(f.as_raw_fd(), bytes.as_ptr().cast(), bytes.len()) };
            if n < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(n as usize)
            }
        }) {
            Ok(Ok(0)) => return Err(ProductionRejected),
            Ok(Ok(n)) => bytes = &bytes[n..],
            Ok(Err(e)) if e.kind() == io::ErrorKind::Interrupted => {}
            Ok(Err(_)) => return Err(ProductionRejected),
            Err(_) => {}
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn config() -> serde_json::Value {
        json!({"version":1,"purpose":"qlad.execution-proof.gcp-preparation-config.v1",
            "aggregate_issuer":"kbs","as_policy_id":"launch_cpu","as_data_sha384":null,
            "kbs_policy_id":"resource","kbs_policy_sha384":"01".repeat(48),
            "delivery_audience":"delivery","delivery_issuer":"kbs-delivery",
            "project_id":"project","client_email":"issuer@project.iam.gserviceaccount.com",
            "kms_key_version":"projects/project/locations/global/keyRings/ring/cryptoKeys/key/cryptoKeyVersions/1",
            "kbs_addresses":["192.0.2.1:443"],"registry_origin":"https://registry.example",
            "registry_repository":"registry.example/team/app","registry_addresses":["192.0.2.2:443"],
            "registry_tls_roots_path":"/onb17/roots/registry.pem",
            "signature_artifact_sha256":"02".repeat(32),"erofs_builder_path":"/onb17/bin/mkfs.erofs"})
    }
    #[test]
    fn embedded_preparation_config_has_no_root_or_guard_override() {
        let valid = config();
        assert!(PreparationConfig::decode(&serde_json::to_vec(&valid).unwrap()).is_ok());
        for (field, value) in [
            ("version", json!(2)),
            ("kbs_addresses", json!([])),
            ("signature_artifact_sha256", json!("00".repeat(32))),
            ("kbs_policy_sha384", json!("AA".repeat(48))),
            ("allow_sample", json!(true)),
            ("authority_public_key", json!([1, 2, 3])),
        ] {
            let mut invalid = valid.clone();
            invalid[field] = value;
            assert!(PreparationConfig::decode(&serde_json::to_vec(&invalid).unwrap()).is_err());
        }
        assert!(PreparationConfig::decode(&vec![b' '; CONTROL_BYTES + 1]).is_err());
    }
    #[test]
    fn control_phase_schema_is_strict_and_secrets_have_no_publication_type() {
        let frame = |request| {
            serde_json::to_vec(&json!({"version":1,"purpose":REQUEST_PURPOSE,"request":request}))
                .unwrap()
        };
        assert!(
            Request::<StopRequest>::decode(&frame(json!({"stop":true})))
                .unwrap()
                .stop
        );
        assert!(Request::<StopRequest>::decode(&frame(json!({"stop":true,"roots":[]}))).is_err());
        assert!(Request::<StopRequest>::decode(&frame(json!({"signed_grant":[]}))).is_err());
        let boot = json!({"signed_manifest":[1],"signed_references":[2],"signed_bootstrap_challenge":[3],
            "management_tls_private_key_pem":"test-management-secret"});
        assert_eq!(
            Request::<BootRequest>::decode(&frame(boot.clone()))
                .unwrap()
                .management_tls_private_key_pem
                .0
                .as_slice(),
            b"test-management-secret"
        );
        let mut oversized = boot;
        oversized["management_tls_private_key_pem"] = json!("x".repeat((16 << 10) + 1));
        assert!(Request::<BootRequest>::decode(&frame(oversized)).is_err());
        assert!(Request::<BootRequest>::decode(&vec![b' '; INPUT_BYTES + 1]).is_err());
    }
    #[test]
    fn resource_decision_requires_selected_domain_canonical_bytes_and_current_outcome() {
        let binding = GcpBootBindingV1::new([1; 48], [2; 48], [3; 48], [4; 48]).unwrap();
        let valid = json!({"version":2,"purpose":execution_proof_client::gcp::RESOURCE_DECISION_PURPOSE,
            "boot_binding_sha384":binding.digest_sha384().unwrap(),"outcome":"current","signed_aggregate_b64":STANDARD.encode(b"signed"),"historical":false});
        assert_eq!(
            decode_aggregate_response(&serde_json::to_vec(&valid).unwrap(), &binding).unwrap(),
            b"signed"
        );
        for (field, value) in [
            ("boot_binding_sha384", json!("aa".repeat(48))),
            ("version", json!(1)),
            ("outcome", json!("pending")),
            ("historical", json!(true)),
            ("signed_aggregate_b64", json!("c2lnbmVk\n")),
            ("signed_aggregate_b64", json!("")),
        ] {
            let mut invalid = valid.clone();
            invalid[field] = value;
            assert!(
                decode_aggregate_response(&serde_json::to_vec(&invalid).unwrap(), &binding)
                    .is_err()
            );
        }
    }
    fn pipe() -> (OwnedFd, OwnedFd) {
        let mut fds = [-1; 2];
        // SAFETY: pipe2 writes exactly two new owned descriptors to this array.
        assert_eq!(
            unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) },
            0
        );
        // SAFETY: both descriptors were freshly created and are each owned once.
        unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) }
    }
    fn diagnostic_stages() -> [PostgrantStage; 9] {
        use PostgrantStage::*;
        [
            GrantVerify,
            RecorderInit,
            HttpsInit,
            Begin,
            Collect,
            Capture,
            Challenge,
            Decision,
            Aggregate,
        ]
    }
    #[test]
    fn postgrant_diagnostics_have_only_fixed_stage_and_error_class() {
        for stage in diagnostic_stages() {
            let diagnostic =
                postgrant_checked::<(), _>(stage, Err("untrusted-private-error-body")).unwrap_err();
            let encoded = serde_json::to_string(&diagnostic).unwrap();
            let value: serde_json::Value = serde_json::from_str(&encoded).unwrap();
            assert_eq!(value.as_object().unwrap().len(), 2);
            assert_eq!(value["error_class"], "rejected");
            assert!(!encoded.contains("untrusted"));
            assert!(!encoded.contains("private"));
            assert_eq!(
                postgrant_client::<()>(stage, Err(execution_proof_client::ClientError::Transport))
                    .unwrap_err()
                    .error_class,
                PostgrantErrorClass::Transport
            );
            assert_eq!(
                postgrant_client::<()>(stage, Err(execution_proof_client::ClientError::HttpStatus))
                    .unwrap_err()
                    .error_class,
                PostgrantErrorClass::HttpStatus
            );
            assert_eq!(
                postgrant_client::<()>(stage, Err(execution_proof_client::ClientError::Malformed))
                    .unwrap_err()
                    .error_class,
                PostgrantErrorClass::Rejected
            );
        }
    }

    async fn assert_one_unproven_frame(diagnostic: impl Serialize + Copy) {
        let (input, writer) = pipe();
        let (reader, output) = pipe();
        let mut io = ControlIo {
            input: AsyncFd::new(input).unwrap(),
            output: AsyncFd::new(output).unwrap(),
            _tty: TtyMode {
                fd: -1,
                original: None,
            },
        };
        let reader = AsyncFd::new(reader).unwrap();
        assert!(diagnostic_outcome::<()>(&mut io, Err(diagnostic))
            .await
            .is_err());
        drop(io);
        drop(writer);
        let mut header = [0; public_serial::HEADER_LEN];
        read_exact(&reader, &mut header).await.unwrap();
        let (size, _) = public_serial::lengths(&header).unwrap();
        assert!(size < 256);
        let mut body = vec![0; size];
        read_exact(&reader, &mut body).await.unwrap();
        let raw = public_serial::decode_public_json(&header, &body).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(
            value,
            json!({"version":1,"purpose":RESPONSE_PURPOSE,
            "phase":"unproven","publication":diagnostic})
        );
        let mut extra = [0];
        // EOF proves that no writer task/duplicate survived or appended a frame.
        assert!(read_exact(&reader, &mut extra).await.is_err());
    }

    #[tokio::test]
    async fn each_postgrant_failure_emits_one_bounded_unproven_frame_then_rejects() {
        for stage in diagnostic_stages() {
            assert_one_unproven_frame(PostgrantDiagnostic {
                stage,
                error_class: PostgrantErrorClass::Rejected,
            })
            .await;
        }
    }

    #[tokio::test]
    async fn each_ready_diagnostic_uses_only_fixed_stage_and_class() {
        use execution_proof_client::ClientError;
        let cases = [
            (
                ReadyDiagnostic::rejected(ReadyStage::AdmissionInput),
                "admission_input",
                "rejected",
            ),
            (
                ReadyDiagnostic::rejected(ReadyStage::CredentialRequest),
                "credential_request",
                "rejected",
            ),
            (
                ReadyDiagnostic::credential_http(ClientError::Transport),
                "credential_http",
                "transport",
            ),
            (
                ReadyDiagnostic::credential_http(ClientError::HttpStatus),
                "credential_http",
                "http_status",
            ),
            (
                ReadyDiagnostic::credential_http(ClientError::Malformed),
                "credential_http",
                "rejected",
            ),
            (
                ReadyDiagnostic::prepare(CustodyProducerError::Preparation(
                    RuntimeError::AdmissionRejected,
                )),
                "prepare",
                "admission_rejected",
            ),
            (
                ReadyDiagnostic::prepare(CustodyProducerError::Preparation(
                    RuntimeError::CredentialRejected,
                )),
                "prepare",
                "credential_rejected",
            ),
            (
                ReadyDiagnostic::prepare(CustodyProducerError::Preparation(
                    RuntimeError::RegistryRejected,
                )),
                "prepare",
                "registry_rejected",
            ),
            (
                ReadyDiagnostic::prepare(CustodyProducerError::Preparation(
                    RuntimeError::PreparationRejected,
                )),
                "prepare",
                "preparation_rejected",
            ),
            (
                ReadyDiagnostic::prepare(CustodyProducerError::Preparation(RuntimeError::Deadline)),
                "prepare",
                "deadline",
            ),
            (
                ReadyDiagnostic::prepare(CustodyProducerError::Deadline),
                "prepare",
                "deadline",
            ),
            (
                ReadyDiagnostic::prepare(CustodyProducerError::Worker),
                "prepare",
                "rejected",
            ),
            (
                ReadyDiagnostic::custody_progress(CustodyProducerError::Deadline),
                "custody_progress",
                "deadline",
            ),
            (
                ReadyDiagnostic::custody_progress(CustodyProducerError::Conflict),
                "custody_progress",
                "rejected",
            ),
            (
                ReadyDiagnostic::rejected(ReadyStage::KataReady),
                "kata_ready",
                "rejected",
            ),
            (
                ReadyDiagnostic::rejected(ReadyStage::ManagementRelay),
                "management_relay",
                "rejected",
            ),
            (
                ReadyDiagnostic::rejected(ReadyStage::SandboxAttach),
                "sandbox_attach",
                "rejected",
            ),
            (
                ReadyDiagnostic::rejected(ReadyStage::SandboxLifetime),
                "sandbox_lifetime",
                "rejected",
            ),
        ];
        for (diagnostic, stage, class) in cases {
            assert_eq!(
                serde_json::to_value(diagnostic).unwrap(),
                json!({"stage":stage,"error_class":class})
            );
            assert_one_unproven_frame(diagnostic).await;
        }
    }
    #[tokio::test]
    async fn cancelling_blocked_diagnostic_drops_the_only_writer_without_retry() {
        let (input, writer) = pipe();
        let (reader, output) = pipe();
        let mut io = ControlIo {
            input: AsyncFd::new(input).unwrap(),
            output: AsyncFd::new(output).unwrap(),
            _tty: TtyMode {
                fd: -1,
                original: None,
            },
        };
        let padding = [0x5au8; 4096];
        let mut padding_bytes = 0;
        loop {
            // SAFETY: the output FD and public padding are live; a full pipe
            // returns EAGAIN because this descriptor is nonblocking.
            let n = unsafe {
                libc::write(
                    io.output.as_raw_fd(),
                    padding.as_ptr().cast(),
                    padding.len(),
                )
            };
            if n < 0 {
                assert_eq!(io::Error::last_os_error().kind(), io::ErrorKind::WouldBlock);
                break;
            }
            padding_bytes += n as usize;
        }
        let failure = PostgrantDiagnostic {
            stage: PostgrantStage::Begin,
            error_class: PostgrantErrorClass::Transport,
        };
        assert!(timeout(
            Duration::from_millis(10),
            diagnostic_outcome::<()>(&mut io, Err(failure))
        )
        .await
        .is_err());
        drop(io);
        drop(writer);
        let mut bytes = [0; 65536];
        let mut received = Vec::new();
        loop {
            // SAFETY: the read FD is owned and this output buffer is live.
            let n =
                unsafe { libc::read(reader.as_raw_fd(), bytes.as_mut_ptr().cast(), bytes.len()) };
            assert!(n >= 0);
            if n == 0 {
                break;
            }
            received.extend_from_slice(&bytes[..n as usize]);
        }
        assert!(received[..padding_bytes].iter().all(|byte| *byte == 0x5a));
        let frame = public_serial::encode_public_json(
            &serde_json::to_vec(&json!({"version":1,"purpose":RESPONSE_PURPOSE,
                "phase":"unproven","publication":failure}))
            .unwrap(),
        )
        .unwrap();
        let expected: Vec<_> = frame.header.into_iter().chain(frame.wire).collect();
        let partial = &received[padding_bytes..];
        assert!(partial.len() < expected.len());
        assert_eq!(partial, &expected[..partial.len()]);
    }
    #[test]
    fn console_control_disables_echo_and_canonical_processing_before_secret_input() {
        let (mut master, mut slave) = (-1, -1);
        // SAFETY: openpty initializes two fresh descriptors; optional name and
        // termios/winsize inputs are null, selecting kernel defaults.
        assert_eq!(
            unsafe {
                libc::openpty(
                    &mut master,
                    &mut slave,
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    std::ptr::null(),
                )
            },
            0
        );
        // SAFETY: both successful openpty descriptors are exclusively owned.
        let (_master, slave) =
            unsafe { (OwnedFd::from_raw_fd(master), OwnedFd::from_raw_fd(slave)) };
        // SAFETY: tcgetattr initializes this live C output structure.
        let mut before: libc::termios = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { libc::tcgetattr(slave.as_raw_fd(), &mut before) },
            0
        );
        {
            let _raw = TtyMode::raw(slave.as_raw_fd()).unwrap();
            let mut actual = before;
            // SAFETY: actual is a live termios output for the owned pty slave.
            assert_eq!(
                unsafe { libc::tcgetattr(slave.as_raw_fd(), &mut actual) },
                0
            );
            assert_eq!(actual.c_lflag & (libc::ECHO | libc::ICANON | libc::ISIG), 0);
        }
        let mut restored = before;
        // SAFETY: restored is live and slave remains owned across this call.
        assert_eq!(
            unsafe { libc::tcgetattr(slave.as_raw_fd(), &mut restored) },
            0
        );
        assert_eq!(restored.c_lflag, before.c_lflag);
        assert_eq!(restored.c_iflag, before.c_iflag);
        assert_eq!(restored.c_oflag, before.c_oflag);
    }
    #[tokio::test]
    async fn actual_async_pipe_frames_bound_length_handle_eof_and_emit_only_public_json() {
        let (input, writer) = pipe();
        let (reader, output) = pipe();
        let mut io = ControlIo {
            input: AsyncFd::new(input).unwrap(),
            output: AsyncFd::new(output).unwrap(),
            _tty: TtyMode {
                fd: -1,
                original: None,
            },
        };
        let writer = AsyncFd::new(writer).unwrap();
        let reader = AsyncFd::new(reader).unwrap();
        let bytes = serde_json::to_vec(
            &json!({"version":1,"purpose":REQUEST_PURPOSE,"request":{"stop":true}}),
        )
        .unwrap();
        write_all(&writer, &(bytes.len() as u32).to_be_bytes())
            .await
            .unwrap();
        write_all(&writer, &bytes).await.unwrap();
        assert!(io.request::<StopRequest>().await.unwrap().stop);
        io.publish("ready", &json!({})).await.unwrap();
        let mut header = [0; public_serial::HEADER_LEN];
        read_exact(&reader, &mut header).await.unwrap();
        let (wire_len, _) = public_serial::lengths(&header).unwrap();
        let mut wire = vec![0; wire_len];
        read_exact(&reader, &mut wire).await.unwrap();
        let public = public_serial::decode_public_json(&header, &wire).unwrap();
        let result: serde_json::Value = serde_json::from_slice(&public).unwrap();
        assert_eq!(
            result,
            json!({"version":1,"purpose":RESPONSE_PURPOSE,"phase":"ready","publication":{}})
        );
        write_all(&writer, &((INPUT_BYTES + 1) as u32).to_be_bytes())
            .await
            .unwrap();
        assert!(io.request::<StopRequest>().await.is_err());
        drop(writer);
        assert!(io.request::<StopRequest>().await.is_err());
    }
    #[tokio::test]
    async fn cancelled_publication_drops_the_only_writer_without_retry() {
        let (input, writer) = pipe();
        let (reader, output) = pipe();
        let mut io = ControlIo {
            input: AsyncFd::new(input).unwrap(),
            output: AsyncFd::new(output).unwrap(),
            _tty: TtyMode {
                fd: -1,
                original: None,
            },
        };
        let mut state = 0x12345678u32;
        let data: Vec<u8> = (0..100000)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                state as u8
            })
            .collect();
        let value = json!({"public_test_bytes":data});
        assert!(
            timeout(Duration::from_millis(10), io.publish("export", &value))
                .await
                .is_err()
        );
        // Cancellation is fatal to this protocol owner; never reuse a partial
        // frame. Dropping it closes the sole output FD, with no spawned writer.
        drop(io);
        drop(writer);
        let mut count = 0;
        let mut bytes = [0; 65536];
        loop {
            // SAFETY: reader is owned and bytes is a live bounded output slice.
            let n =
                unsafe { libc::read(reader.as_raw_fd(), bytes.as_mut_ptr().cast(), bytes.len()) };
            assert!(n >= 0);
            if n == 0 {
                break;
            }
            count += n as usize;
        }
        assert!(count > 0 && count < 100000);
    }
}
