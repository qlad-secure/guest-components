use super::custody_tests::{CustodyFixture, task_elf};
use super::*;
use crate::custody_fixture_config::TaskCase;
use execution_proof_contract::execution::ExecutionRecord;

fn expected_projection(
    preparation: &execution_proof_handoff::rootfs_custody::PreparationRecord,
) -> String {
    let mut value = spec_value("/");
    value
        .pointer_mut("/linux/namespaces")
        .unwrap()
        .as_array_mut()
        .unwrap()
        .sort_by_key(|entry| entry["type"].as_str().unwrap().to_owned());
    // The fixture's exact signed allowlist is known independently of the Kata
    // projection implementation. Rule grouping is semantically irrelevant.
    value["linux"]["seccomp"]["syscalls"] = json!([
        {"names":["execveat"],"action":"SCMP_ACT_ALLOW"},
        {"names":["exit_group"],"action":"SCMP_ACT_ALLOW"},
        {"names":["write"],"action":"SCMP_ACT_ALLOW"},
    ]);
    let mut projection = json!({
        "version":1,
        "purpose":"qlad.execution-proof.final-spec.v1",
        "profile":"static-elf-owned-view.v1",
        "candidate_spec_sha384":hash384(&spec("/")),
        "image_sha384":preparation.image_sha384,
        "executable_sha384":preparation.executable_sha384,
        "mount_id":preparation.mount_id,
        "spec":value,
    });
    fn sort(value: &mut serde_json::Value) {
        match value {
            serde_json::Value::Object(map) => {
                map.values_mut().for_each(sort);
                map.sort_keys();
            }
            serde_json::Value::Array(array) => array.iter_mut().for_each(sort),
            _ => (),
        }
    }
    sort(&mut projection);
    hash384(&serde_json::to_vec(&projection).unwrap())
}

#[tokio::test]
async fn native_final_task_cross_process_binds_spec_and_captures_before_resume() {
    let mut observations = Vec::new();
    for case in [
        TaskCase::Positive,
        TaskCase::CancelBeforeStart,
        TaskCase::SpecMismatch,
        TaskCase::PostExecFailure,
        TaskCase::CaptureRejected,
    ] {
        let mut fixture = CustodyFixture::new_with_case(case).await;
        let requests = fixture.server.requests();
        fixture.until_status(CustodyProducerStatus::Finalized).await;
        let preparation = fixture.attempt.record().unwrap().clone();
        if case == TaskCase::Positive {
            // The actual task is still stopped after its exec record capture.
            // Its view must survive closing the original CDH preparation.
            fixture.marker("r-captured").await;
            fixture.attempt.cancel_and_wait().await.unwrap();
            assert_eq!(fixture.parent.children(), 0);
            fixture.control.signal("producer-closed");
            fixture.control.signal("allow-resume");
        }
        let result = fixture.result().await;
        assert_eq!(result["status"], "PASS", "{case:?}: {result}");
        assert_eq!(result["case"], serde_json::to_value(case).unwrap());
        assert_eq!(result["mountinfo_unchanged"], true);
        assert_eq!(result["descriptor_cleanup"], true);
        assert_eq!(result["active_after_task_exit"], 0);
        let record_expected = matches!(case, TaskCase::Positive | TaskCase::PostExecFailure);
        let observed_expected = record_expected || case == TaskCase::CaptureRejected;
        assert_eq!(result["observed"], observed_expected);
        assert_eq!(result["captured"], record_expected);
        assert_eq!(result["marker_seen"], case == TaskCase::Positive);
        assert_eq!(
            result["failed_after_exec"],
            matches!(case, TaskCase::PostExecFailure | TaskCase::CaptureRejected)
        );
        if record_expected {
            assert_eq!(result["capture_before_resume"], true);
            let record =
                ExecutionRecord::decode(&serde_json::to_vec(&result["record"]).unwrap()).unwrap();
            let preparation_digest = preparation
                .sha384()
                .unwrap()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            assert_eq!(record.preparation_record_sha384, preparation_digest);
            assert_eq!(record.admission_context_sha384, preparation.context_sha384);
            assert_eq!(record.grant_sha384, fixture.grant_sha384);
            assert_eq!(
                record.startup_binding_sha384,
                preparation.startup_binding_sha384
            );
            assert_eq!(record.candidate_spec_sha384, hash384(&spec("/")));
            assert_eq!(record.final_spec_sha384, expected_projection(&preparation));
            assert_eq!(record.image_sha384, preparation.image_sha384);
            assert_eq!(record.executable_sha384, preparation.executable_sha384);
            assert_eq!(record.executable_sha384, hash384(&task_elf(case)));
            assert_eq!(record.mount_id, preparation.mount_id);
        } else {
            assert!(result["record"].is_null());
            assert_eq!(result["capture_before_resume"], false);
        }
        match case {
            TaskCase::Positive => assert_eq!(result["exit_code"], 0),
            TaskCase::PostExecFailure => assert_eq!(result["exit_code"], 139),
            TaskCase::CaptureRejected => assert_eq!(result["exit_code"], 137),
            _ => {}
        }
        assert_eq!(fixture.trace.lock().unwrap().calls.len(), 1);
        assert_eq!(fixture.server.requests(), requests);
        fixture.attempt.cancel_and_wait().await.unwrap();
        assert_eq!(fixture.parent.children(), 0);
        fixture.assert_capacity_returned().await;
        println!("ONB17_FINAL_TASK_CASE={result}");
        observations.push(result);
    }
    assert_eq!(observations.len(), 5);
    println!(
        "ONB17_FINAL_TASK_RESULT={}",
        json!({"status":"PASS", "cases":observations})
    );
}
