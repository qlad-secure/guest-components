// SPDX-License-Identifier: Apache-2.0

//! Receiver verification without the legacy image-pull/KBS dependency graph.
//! The source is shared with image-rs so both consumers validate the same bytes,
//! filesystem profile and executable rules. Producer lineage is not imported.

#[cfg(feature = "launch-preparation")]
#[path = "../../src/preparation/mod.rs"]
pub mod preparation;
