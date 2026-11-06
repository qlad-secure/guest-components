//! Guest Components source modules with private software evidence fixtures.
extern crate self as kbs_protocol;
#[cfg(feature = "launch-preparation-custody-native")]
#[path = "../../../../kata-launch-dev/src/agent/src/rootfs_custody.rs"]
pub mod kata_custody;
#[cfg(feature = "launch-preparation-custody-native")]
pub mod custody_fixture_config;
#[cfg(all(test, feature = "launch-credential"))]
mod cdh_tests;
#[cfg(all(test, feature = "launch-preparation-content"))]
mod content_tests;
#[path = "../../../attestation-agent/kbs_protocol/src/keypair.rs"]
pub mod keypair;
#[cfg(feature = "launch-credential")]
#[path = "../../../confidential-data-hub/hub/src/launch_credential.rs"]
pub mod launch_credential;
#[cfg(feature = "launch-preparation")]
#[path = "../../../confidential-data-hub/hub/src/launch_preparation.rs"]
pub mod launch_preparation;
#[cfg(feature = "launch-recorder")]
#[path = "../../../attestation-agent/kbs_protocol/src/launch_recorder.rs"]
pub mod launch_recorder;
#[cfg(all(test, feature = "launch-preparation"))]
mod preparation_tests;
#[cfg(all(test, feature = "launch-preparation-runtime"))]
mod runtime_tests;
