//! Guest Components source modules with private software evidence fixtures.
extern crate self as kbs_protocol;
#[cfg(all(test, feature = "launch-credential"))]
mod cdh_tests;
#[path = "../../../attestation-agent/kbs_protocol/src/keypair.rs"]
pub mod keypair;
#[cfg(feature = "launch-credential")]
#[path = "../../../confidential-data-hub/hub/src/launch_credential.rs"]
pub mod launch_credential;
#[cfg(feature = "launch-recorder")]
#[path = "../../../attestation-agent/kbs_protocol/src/launch_recorder.rs"]
pub mod launch_recorder;
