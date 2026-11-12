use super::*;
use crate::custody_fixture_config::{FixtureMode, FixtureReceiverWire, TaskCase};
use execution_proof_handoff::startup::{
    LaunchedRole, PinnedRoleExecutable, RoleCommand, launch_kata_role,
};
use image_rs::preparation::SealedImageBytes;
#[cfg(feature = "launch-preparation-mount-native")]
use std::fs::OpenOptions;
use std::{
    ffi::OsString,
    fs::{DirBuilder, File},
    os::{
        fd::{AsFd, AsRawFd},
        unix::fs::{DirBuilderExt, FileExt},
    },
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering as AtomicOrdering},
    time::Instant,
};

const IMAGE_BYTES: u64 = 1 << 20;
const ROLE_BYTES: u64 = 512 << 20;
const FLOW_TIME: Duration = Duration::from_secs(10);
static CONTROL_SEQUENCE: AtomicU64 = AtomicU64::new(0);

pub(super) struct ControlDirectory(PathBuf);
impl ControlDirectory {
    fn new() -> Self {
        for _ in 0..128 {
            let sequence = CONTROL_SEQUENCE.fetch_add(1, AtomicOrdering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "onb17-custody-flow-{}-{sequence}",
                std::process::id(),
            ));
            match DirBuilder::new().mode(0o700).create(&path) {
                Ok(()) => return Self(path),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => panic!("private custody fixture directory: {error}"),
            }
        }
        panic!("private custody fixture directory capacity");
    }
    fn contains(&self, name: &str) -> bool {
        self.0.join(name).is_file()
    }
    #[cfg(feature = "launch-preparation-mount-native")]
    pub(super) fn signal(&self, name: &str) {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(self.0.join(name))
            .unwrap();
    }
    fn result(&self) -> serde_json::Value {
        serde_json::from_slice(&std::fs::read(self.0.join("result.json")).unwrap()).unwrap()
    }
}
impl Drop for ControlDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn file_sha384(file: &File, maximum: u64) -> [u8; 48] {
    let metadata = file.metadata().unwrap();
    assert!(metadata.is_file() && metadata.len() > 0 && metadata.len() <= maximum);
    let mut hash = Sha384::new();
    let mut bytes = [0u8; 8192];
    let mut offset = 0;
    while offset < metadata.len() {
        let length = (metadata.len() - offset).min(bytes.len() as u64) as usize;
        file.read_exact_at(&mut bytes[..length], offset).unwrap();
        hash.update(&bytes[..length]);
        offset += length as u64;
    }
    hash.finalize().into()
}
fn hex_digest(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub(super) struct CustodyFixture {
    // The child is killed/reaped before config/control backing can disappear.
    role: LaunchedRole,
    pub(super) attempt: CustodyRuntimeAttempt,
    pub(super) server: Server,
    image: ContentFixture,
    pub(super) parent: StagingFixtureParent,
    factory: RuntimeFactory,
    signature: String,
    delivery: Delivery,
    #[cfg(feature = "launch-preparation-final-task-native")]
    pub(super) grant_sha384: String,
    pub(super) trace: Arc<Mutex<Trace>>,
    _configuration: SealedImageBytes,
    pub(super) control: ControlDirectory,
}
impl CustodyFixture {
    async fn new(mode: FixtureMode) -> Self {
        Self::new_with_elf(mode, None, elf()).await
    }
    #[cfg(feature = "launch-preparation-final-task-native")]
    pub(super) async fn new_with_case(case: TaskCase) -> Self {
        Self::new_with_elf(FixtureMode::NativeFinalTask, Some(case), task_elf(case)).await
    }
    async fn new_with_elf(
        mode: FixtureMode,
        task_case: Option<TaskCase>,
        payload: Vec<u8>,
    ) -> Self {
        let server = Server::new();
        let image =
            ContentFixture::new_with_tar(1, false, &server.repository(), tar(&payload, 0o755));
        let signature = server.image(&image);
        let parent = StagingFixtureParent::new();
        let raw_spec = spec("/");
        let (checked, recorder, signer) =
            checked_inputs(&image, &parent, signature.clone(), raw_spec.clone()).await;
        let control = ControlDirectory::new();
        let mut wire = FixtureReceiverWire::from_config(
            &checked.base.admission,
            &raw_spec,
            &checked.spec_policy,
            control.0.clone(),
            mode,
        );
        wire.task_case = task_case;
        #[cfg(feature = "launch-preparation-final-task-native")]
        let grant_sha384 = hash384(&wire.expected_grant.signing_bytes().unwrap());
        let public_configuration = wire.encode().unwrap();
        let configuration = SealedImageBytes::from_bytes(&public_configuration, 1 << 20).unwrap();
        let helper_path =
            PathBuf::from(std::env::var_os("ONB17_KATA_CUSTODY_HELPER").expect(
                "build the native Kata custody helper and provide its frozen executable path",
            ));
        let helper = File::open(helper_path).unwrap();
        let helper_sha = file_sha384(&helper, ROLE_BYTES);
        let preparation_sha = file_sha384(&File::open("/proc/self/exe").unwrap(), ROLE_BYTES);
        let arguments: Vec<OsString> = [
            "--fixture-config-fd".to_owned(),
            configuration.as_fd().as_raw_fd().to_string(),
            "--fixture-config-sha384".to_owned(),
            hex_digest(configuration.sha384()),
            "--preparation-sha384".to_owned(),
            hex_digest(&preparation_sha),
            "--kata-sha384".to_owned(),
            hex_digest(&helper_sha),
        ]
        .into_iter()
        .map(OsString::from)
        .collect();
        let command = RoleCommand::new(
            PinnedRoleExecutable::new(helper, helper_sha, ROLE_BYTES).unwrap(),
            arguments,
        )
        .unwrap();
        let (channel, role) = launch_kata_role(
            command,
            preparation_sha,
            ROLE_BYTES as usize,
            *configuration.sha384(),
            FLOW_TIME,
        )
        .unwrap();
        let workflow_time = Duration::from_secs(if mode == FixtureMode::NativeFinalTask {
            60
        } else {
            30
        });
        let factory = RuntimeFactory::new(server.client(), 1, workflow_time).unwrap();
        let mut attempt = factory
            .begin_custody_attempt(
                ErofsRuntimeAttemptConfig {
                    checked,
                    builder: builder(limits()),
                },
                recorder,
                channel,
                CustodyProducerLimits {
                    backing_bytes: IMAGE_BYTES,
                    provenance_bytes: 1 << 20,
                    admission_bytes: 1 << 20,
                },
            )
            .unwrap();
        attempt.enroll_receiver().await.unwrap();
        assert_eq!(attempt.status(), CustodyProducerStatus::Enrolled);
        let delivery = signer.delivery(attempt.challenge_nonce());
        let trace = Arc::new(Mutex::new(Trace::default()));
        assert_eq!(
            attempt
                .prepare_fixture(delivery.borrowed(), image.replies(), trace.clone())
                .await,
            Ok(ContentBinding::FirstChecked),
        );
        assert_eq!(parent.children(), 1);
        Self {
            role,
            attempt,
            server,
            image,
            parent,
            factory,
            signature,
            delivery,
            #[cfg(feature = "launch-preparation-final-task-native")]
            grant_sha384,
            trace,
            _configuration: configuration,
            control,
        }
    }
    #[cfg(feature = "launch-preparation-mount-native")]
    pub(super) async fn until_status(&mut self, expected: CustodyProducerStatus) {
        let deadline = Instant::now() + FLOW_TIME;
        while self.attempt.status() != expected {
            assert!(
                Instant::now() < deadline,
                "custody producer did not reach {expected:?}"
            );
            self.attempt.advance().unwrap();
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }
    #[cfg(feature = "launch-preparation-mount-native")]
    pub(super) async fn marker(&self, name: &str) {
        let deadline = Instant::now() + FLOW_TIME;
        while !self.control.contains(name) {
            if self.control.contains("result.json") {
                panic!(
                    "Kata helper ended before marker {name}: {}",
                    self.control.result()
                );
            }
            assert!(
                Instant::now() < deadline,
                "Kata helper marker {name} deadline"
            );
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }
    pub(super) async fn result(&mut self) -> serde_json::Value {
        let deadline = Instant::now() + FLOW_TIME;
        while !self.control.contains("result.json") {
            assert!(Instant::now() < deadline, "Kata helper result deadline");
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        let result = self.control.result();
        self.role
            .wait(FLOW_TIME)
            .unwrap_or_else(|error| panic!("Kata helper failed: {error:?}; {result}"));
        result
    }
    pub(super) async fn assert_capacity_returned(&self) {
        let (checked, recorder, _) =
            checked_inputs(&self.image, &self.parent, self.signature.clone(), spec("/")).await;
        let mut next = self
            .factory
            .begin_erofs_attempt(
                ErofsRuntimeAttemptConfig {
                    checked,
                    builder: builder(limits()),
                },
                recorder,
            )
            .unwrap();
        next.cancel_and_wait().await.unwrap();
    }
}

#[tokio::test]
async fn custody_receiver_rejects_before_mount_without_record_or_lease() {
    let mut fixture = CustodyFixture::new(FixtureMode::RejectBeforeMount).await;
    let requests = fixture.server.requests();
    let deadline = Instant::now() + FLOW_TIME;
    loop {
        assert!(
            Instant::now() < deadline,
            "receiver rejection did not close custody producer"
        );
        if fixture.attempt.advance().is_err() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    assert_eq!(fixture.attempt.status(), CustodyProducerStatus::Terminal);
    assert!(fixture.attempt.record().is_none());
    assert!(fixture.attempt.retry().is_err());
    fixture.attempt.cancel_and_wait().await.unwrap();
    assert_eq!(fixture.parent.children(), 0);
    assert_eq!(
        fixture.attempt.prepare(fixture.delivery.borrowed()).await,
        Err(CustodyProducerError::Unavailable)
    );
    let result = fixture.result().await;
    assert_eq!(result["status"], "EXPECTED_REJECT");
    assert_eq!(result["lease_published"], false);
    assert_eq!(result["active_after"], 0);
    assert_eq!(result["target_executed"], false);
    assert_eq!(fixture.trace.lock().unwrap().calls.len(), 1);
    assert_eq!(fixture.server.requests(), requests);
    fixture.assert_capacity_returned().await;
}

#[cfg(feature = "launch-preparation-mount-native")]
#[tokio::test]
async fn native_custody_cross_process_commits_one_lease_and_retries_without_remount() {
    let mut fixture = CustodyFixture::new(FixtureMode::NativePositive).await;
    let requests = fixture.server.requests();
    fixture
        .until_status(CustodyProducerStatus::AwaitingValidation)
        .await;
    fixture.marker("view-ready").await;
    // Leave the first valid receipt queued and resend the entire exact offer.
    // The receiver must validate/close the duplicate FDs without another mount.
    assert_eq!(
        fixture.attempt.retry().unwrap(),
        CustodyProducerStatus::SendingAdmission
    );
    fixture
        .until_status(CustodyProducerStatus::AwaitingValidation)
        .await;
    fixture.control.signal("allow-retry");
    fixture
        .until_status(CustodyProducerStatus::AwaitingFinalizedAck)
        .await;
    let first_record = fixture.attempt.record().unwrap().clone();
    fixture.marker("finalizing").await;
    // Retry PCommit while the first receiver ACK is explicitly held back.
    assert_eq!(
        fixture.attempt.retry().unwrap(),
        CustodyProducerStatus::SendingCommit
    );
    fixture
        .until_status(CustodyProducerStatus::AwaitingFinalizedAck)
        .await;
    fixture.control.signal("allow-ack");
    fixture.until_status(CustodyProducerStatus::Finalized).await;
    fixture.marker("ack-replayed").await;
    assert_eq!(fixture.attempt.record(), Some(&first_record));
    assert_eq!(
        fixture.attempt.prepare(fixture.delivery.borrowed()).await,
        Ok(ContentBinding::Historical),
    );
    assert_eq!(fixture.trace.lock().unwrap().calls.len(), 1);
    assert_eq!(fixture.server.requests(), requests);
    fixture.control.signal("finish");
    fixture.marker("owner-dropped").await;
    fixture.attempt.cancel_and_wait().await.unwrap();
    assert_eq!(fixture.parent.children(), 0);
    fixture.control.signal("producer-closed");
    let result = fixture.result().await;
    assert_eq!(result["status"], "PASS");
    let child_record: execution_proof_handoff::rootfs_custody::PreparationRecord =
        serde_json::from_value(result["record"].clone()).unwrap();
    assert_eq!(child_record, first_record);
    assert_eq!(child_record.candidate_spec_sha384, hash384(&spec("/")));
    assert_eq!(child_record.executable_sha384, hash384(&elf()));
    assert_eq!(result["active_after_owner_drop"], 1);
    assert_eq!(result["active_after_lease_drop"], 0);
    assert_eq!(result["take_twice_rejected"], true);
    assert_eq!(result["finalizing_not_ready"], true);
    assert_eq!(result["mountinfo_unchanged"], true);
    assert_eq!(result["descriptors_after"], 4);
    assert_eq!(result["target_executed"], false);
    fixture.assert_capacity_returned().await;
    println!("ONB17_CUSTODY_RESULT={result}");
}

#[cfg(feature = "launch-preparation-final-task-native")]
pub(super) fn task_elf(case: TaskCase) -> Vec<u8> {
    let mut bytes = elf();
    if case == TaskCase::PostExecFailure {
        return bytes;
    }
    // x86_64 ET_EXEC: write the marker to stdout, then exit_group(0). The
    // RIP-relative payload stays in the existing readonly executable segment.
    let code = [
        0xb8, 1, 0, 0, 0, 0xbf, 1, 0, 0, 0, 0x48, 0x8d, 0x35, 0x2f, 0, 0, 0, 0xba, 14, 0, 0, 0,
        0x0f, 0x05, 0xb8, 0xe7, 0, 0, 0, 0x31, 0xff, 0x0f, 0x05,
    ];
    bytes[256..256 + code.len()].copy_from_slice(&code);
    bytes[320..334].copy_from_slice(b"ONB17_APP_RAN\n");
    bytes
}
