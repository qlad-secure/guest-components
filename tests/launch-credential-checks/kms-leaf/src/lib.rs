//! GCP provider, API, and error modules with their SDK implementation.
//! Other CDH/KMS workspace components are excluded.

#[path = "../../../../confidential-data-hub/kms/src/api.rs"]
// The imported API generates duplicate must_use annotations through async_trait.
#[allow(clippy::double_must_use)]
pub mod api;
pub use api::*;
#[path = "../../../../confidential-data-hub/kms/src/error.rs"]
pub mod error;
pub use error::*;
#[path = "../../../../confidential-data-hub/kms/src/plugins/gcp/mod.rs"]
pub mod gcp;

pub mod plugins {
    // Match the normal plugins module's path metadata. The memory credential
    // constructor does not read this legacy path.
    pub(crate) const _IN_GUEST_DEFAULT_KEY_PATH: &str =
        "/run/confidential-containers/cdh/kbs/kms-credential";
    pub use crate::gcp;
}
