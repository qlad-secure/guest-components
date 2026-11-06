// SPDX-License-Identifier: Apache-2.0

//! Default-off byte, verification, and staging primitives.
//!
//! Sealed bytes do not establish an image format, verified OCI provenance,
//! successful preparation, rootfs custody, admission, or observed execution.

#[cfg(not(target_os = "linux"))]
compile_error!("launch-preparation requires Linux memfd sealing");

pub mod sealed_image;

#[cfg(feature = "launch-preparation-signature")]
pub mod manifest_signature;

#[cfg(feature = "launch-preparation-content")]
pub mod layer_content;

#[cfg(feature = "launch-preparation-content")]
pub mod rootfs_staging;

#[cfg(feature = "launch-preparation-registry")]
pub mod registry_ingress;

#[cfg(feature = "launch-preparation-executable")]
pub mod launch_spec;

#[cfg(feature = "launch-preparation-executable")]
pub mod static_elf;

pub use sealed_image::{SealedImageBytes, SealedImageError};
