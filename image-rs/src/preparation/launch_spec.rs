// SPDX-License-Identifier: Apache-2.0

//! Exact signed-byte preflight for a restricted OCI launch candidate.
//!
//! The committed digest covers the supplied raw JSON, never a reserialization.
//! `rootfs` is a logical root role, not a received filesystem path. No mount,
//! privilege, namespace or seccomp setting is applied here. In particular this
//! does not establish which effective spec a future Kata final task will use;
//! that needs a defined post-transform projection and immutable-view binding.

use serde::Deserialize;
use sha2::{Digest, Sha384};
use std::collections::BTreeSet;

/// Trusted restrictions in addition to the grant's exact candidate commitment.
/// The nonroot identity and complete native seccomp allowlist are explicit.
pub struct EffectiveSpecPolicy {
    pub uid: u32,
    pub gid: u32,
    pub seccomp_syscalls: Vec<String>,
}

#[derive(Clone, Copy)]
pub struct EffectiveSpecLimits {
    pub spec_bytes: usize,
    pub args: usize,
    pub env: usize,
    pub string_bytes: usize,
    pub total_string_bytes: usize,
    pub path_bytes: usize,
    pub path_components: usize,
    pub syscalls: usize,
    pub json_depth: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum EffectiveSpecError {
    #[error("launch candidate limits are invalid")]
    InvalidLimits,
    #[error("launch candidate trusted policy is invalid")]
    InvalidPolicy,
    #[error("launch candidate exceeds configured bounds")]
    TooLarge,
    #[error("launch candidate exceeds the JSON depth budget")]
    TooDeep,
    #[error("launch candidate commitment encoding rejected")]
    InvalidDigest,
    #[error("launch candidate raw bytes differ from admission")]
    DigestMismatch,
    #[error("launch candidate JSON schema rejected")]
    Malformed,
    #[error("launch candidate uses an unsupported profile")]
    UnsupportedProfile,
    #[error("launch candidate process inputs rejected")]
    InvalidProcess,
    #[error("launch candidate path rejected")]
    InvalidPath,
    #[error("launch candidate environment rejected")]
    InvalidEnvironment,
    #[error("launch candidate privileges rejected")]
    InvalidPrivileges,
    #[error("launch candidate namespace profile rejected")]
    InvalidNamespaces,
    #[error("launch candidate seccomp profile rejected")]
    InvalidSeccomp,
}

/// Validated candidate data, not a final-task, rootfs or execution capability.
/// No raw Debug/serde/unchecked constructor is exposed.
pub struct BoundEffectiveSpec {
    bytes: Vec<u8>,
    sha384: String,
    args: Vec<String>,
    env: Vec<String>,
    cwd: String,
    uid: u32,
    gid: u32,
}

impl BoundEffectiveSpec {
    pub fn parse(
        raw: &[u8],
        expected_sha384: &str,
        policy: &EffectiveSpecPolicy,
        limits: EffectiveSpecLimits,
    ) -> Result<Self, EffectiveSpecError> {
        limits.validate()?;
        validate_policy(policy, limits)?;
        if raw.len() > limits.spec_bytes {
            return Err(EffectiveSpecError::TooLarge);
        }
        if expected_sha384.len() != 96
            || !expected_sha384
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(EffectiveSpecError::InvalidDigest);
        }
        let sha384: String = Sha384::digest(raw)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        if sha384 != expected_sha384 {
            return Err(EffectiveSpecError::DigestMismatch);
        }
        check_depth(raw, limits.json_depth)?;
        let document: LaunchDocument =
            serde_json::from_slice(raw).map_err(|_| EffectiveSpecError::Malformed)?;
        validate_document(&document, policy, limits)?;
        let process = document.process;
        Ok(Self {
            bytes: raw.to_vec(),
            sha384,
            args: process.args,
            env: process.env,
            cwd: process.cwd,
            uid: process.user.uid,
            gid: process.user.gid,
        })
    }

    pub fn sha384(&self) -> &str {
        &self.sha384
    }
    pub fn raw_bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn executable(&self) -> &str {
        &self.args[0]
    }
    pub fn args(&self) -> &[String] {
        &self.args
    }
    pub fn env(&self) -> &[String] {
        &self.env
    }
    pub fn cwd(&self) -> &str {
        &self.cwd
    }
    pub fn uid(&self) -> u32 {
        self.uid
    }
    pub fn gid(&self) -> u32 {
        self.gid
    }
}

impl EffectiveSpecLimits {
    pub fn validate(self) -> Result<(), EffectiveSpecError> {
        if [
            self.spec_bytes,
            self.args,
            self.env,
            self.string_bytes,
            self.total_string_bytes,
            self.path_bytes,
            self.path_components,
            self.syscalls,
            self.json_depth,
        ]
        .iter()
        .any(|v| *v == 0 || *v > isize::MAX as usize)
            || self.json_depth > 32
        {
            return Err(EffectiveSpecError::InvalidLimits);
        }
        Ok(())
    }
}

fn validate_policy(
    policy: &EffectiveSpecPolicy,
    limits: EffectiveSpecLimits,
) -> Result<(), EffectiveSpecError> {
    if policy.uid == 0
        || policy.gid == 0
        || policy.uid == u32::MAX
        || policy.gid == u32::MAX
        || policy.seccomp_syscalls.is_empty()
        || policy.seccomp_syscalls.len() > limits.syscalls
    {
        return Err(EffectiveSpecError::InvalidPolicy);
    }
    let mut unique = BTreeSet::new();
    for name in &policy.seccomp_syscalls {
        if name.len() > limits.string_bytes || !syscall_name(name) || !unique.insert(name) {
            return Err(EffectiveSpecError::InvalidPolicy);
        }
    }
    Ok(())
}

fn validate_document(
    document: &LaunchDocument,
    policy: &EffectiveSpecPolicy,
    limits: EffectiveSpecLimits,
) -> Result<(), EffectiveSpecError> {
    if document.oci_version != "1.2.1"
        || document.root.path != "rootfs"
        || !document.root.readonly
        || !document.mounts.is_empty()
    {
        return Err(EffectiveSpecError::UnsupportedProfile);
    }
    let process = &document.process;
    if process.terminal
        || !process.no_new_privileges
        || process.user.uid != policy.uid
        || process.user.gid != policy.gid
        || !process.user.additional_gids.is_empty()
        || !process.capabilities.bounding.is_empty()
        || !process.capabilities.effective.is_empty()
        || !process.capabilities.inheritable.is_empty()
        || !process.capabilities.permitted.is_empty()
        || !process.capabilities.ambient.is_empty()
    {
        return Err(EffectiveSpecError::InvalidPrivileges);
    }
    if process.args.is_empty() {
        return Err(EffectiveSpecError::InvalidProcess);
    }
    if process.args.len() > limits.args || process.env.len() > limits.env {
        return Err(EffectiveSpecError::TooLarge);
    }
    let mut total = 0usize;
    for text in process
        .args
        .iter()
        .chain(&process.env)
        .chain(std::iter::once(&process.cwd))
    {
        if text.len() > limits.string_bytes {
            return Err(EffectiveSpecError::TooLarge);
        }
        if text.contains('\0') {
            return Err(EffectiveSpecError::InvalidProcess);
        }
        // Include each future execve C-string terminator in the aggregate bound.
        total = total
            .checked_add(text.len())
            .and_then(|v| v.checked_add(1))
            .filter(|v| *v <= limits.total_string_bytes)
            .ok_or(EffectiveSpecError::TooLarge)?;
    }
    canonical_path(&process.args[0], false, limits)?;
    canonical_path(&process.cwd, true, limits)?;
    let mut names = BTreeSet::new();
    let mut home = false;
    for entry in &process.env {
        let (name, value) = entry
            .split_once('=')
            .ok_or(EffectiveSpecError::InvalidEnvironment)?;
        if !environment_name(name) || !names.insert(name) {
            return Err(EffectiveSpecError::InvalidEnvironment);
        }
        if name == "HOME" {
            if value != "/" {
                return Err(EffectiveSpecError::InvalidEnvironment);
            }
            home = true;
        }
    }
    // Current rustjail inserts HOME if missing. Explicitness avoids that hidden
    // transform, without claiming this candidate has reached that final task.
    if !home {
        return Err(EffectiveSpecError::InvalidEnvironment);
    }
    let required: BTreeSet<_> = ["mount", "pid", "ipc", "uts", "network"]
        .into_iter()
        .collect();
    let actual: BTreeSet<_> = document
        .linux
        .namespaces
        .iter()
        .map(|n| n.kind.as_str())
        .collect();
    if document.linux.namespaces.len() != required.len() || actual != required {
        return Err(EffectiveSpecError::InvalidNamespaces);
    }
    let seccomp = &document.linux.seccomp;
    if seccomp.default_action != "SCMP_ACT_ERRNO"
        || seccomp.default_errno_ret != 1
        || seccomp.architectures != ["SCMP_ARCH_X86_64"]
    {
        return Err(EffectiveSpecError::InvalidSeccomp);
    }
    if seccomp.syscalls.len() > limits.syscalls {
        return Err(EffectiveSpecError::TooLarge);
    }
    let mut allowed = BTreeSet::new();
    for rule in &seccomp.syscalls {
        if rule.action != "SCMP_ACT_ALLOW" || rule.names.is_empty() {
            return Err(EffectiveSpecError::InvalidSeccomp);
        }
        for name in &rule.names {
            if name.len() > limits.string_bytes
                || !syscall_name(name)
                || !allowed.insert(name.as_str())
            {
                return Err(EffectiveSpecError::InvalidSeccomp);
            }
            if allowed.len() > limits.syscalls {
                return Err(EffectiveSpecError::TooLarge);
            }
        }
    }
    if allowed != policy.seccomp_syscalls.iter().map(String::as_str).collect() {
        return Err(EffectiveSpecError::InvalidSeccomp);
    }
    Ok(())
}

fn canonical_path(
    path: &str,
    root_allowed: bool,
    limits: EffectiveSpecLimits,
) -> Result<(), EffectiveSpecError> {
    if path.len() > limits.path_bytes {
        return Err(EffectiveSpecError::TooLarge);
    }
    if root_allowed && path == "/" {
        return Ok(());
    }
    if !path.starts_with('/')
        || path.len() == 1
        || path.bytes().any(|b| b < 32 || b == 127 || b == b'\\')
        || path[1..]
            .split('/')
            .any(|p| p.is_empty() || p == "." || p == ".." || p.len() > 255)
    {
        return Err(EffectiveSpecError::InvalidPath);
    }
    if path[1..].split('/').count() > limits.path_components {
        return Err(EffectiveSpecError::TooLarge);
    }
    Ok(())
}
fn environment_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes
        .next()
        .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
        && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_')
}
fn syscall_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes
        .next()
        .is_some_and(|b| b.is_ascii_lowercase() || b == b'_')
        && bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}
fn check_depth(raw: &[u8], max: usize) -> Result<(), EffectiveSpecError> {
    let (mut depth, mut string, mut escape) = (0usize, false, false);
    for byte in raw {
        if string {
            if escape {
                escape = false;
            } else if *byte == b'\\' {
                escape = true;
            } else if *byte == b'"' {
                string = false;
            }
        } else {
            match byte {
                b'"' => string = true,
                b'{' | b'[' => {
                    depth += 1;
                    if depth > max {
                        return Err(EffectiveSpecError::TooDeep);
                    }
                }
                b'}' | b']' => depth = depth.saturating_sub(1),
                _ => (),
            }
        }
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LaunchDocument {
    #[serde(rename = "ociVersion")]
    oci_version: String,
    root: Root,
    process: Process,
    // No mount shape is supported. Retain bounded raw JSON values only to
    // reject a nonempty list, without interpreting paths/types/options.
    mounts: Vec<serde_json::Value>,
    linux: Linux,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Root {
    path: String,
    readonly: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Process {
    terminal: bool,
    user: User,
    args: Vec<String>,
    env: Vec<String>,
    cwd: String,
    no_new_privileges: bool,
    capabilities: Capabilities,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct User {
    uid: u32,
    gid: u32,
    additional_gids: Vec<u32>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Capabilities {
    bounding: Vec<String>,
    effective: Vec<String>,
    inheritable: Vec<String>,
    permitted: Vec<String>,
    ambient: Vec<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Linux {
    namespaces: Vec<Namespace>,
    seccomp: Seccomp,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Namespace {
    #[serde(rename = "type")]
    kind: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Seccomp {
    default_action: String,
    default_errno_ret: u16,
    architectures: Vec<String>,
    syscalls: Vec<Syscall>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Syscall {
    names: Vec<String>,
    action: String,
}

#[cfg(test)]
#[path = "launch_spec_tests.rs"]
pub(super) mod tests;
