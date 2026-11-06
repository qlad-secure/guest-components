// SPDX-License-Identifier: Apache-2.0

//! Bounded encrypted-layer integrity checks, without registry/KMS/signature
//! authority, filesystem extraction, rootfs custody, or launch permission.
//!
//! The caller supplies pinned metadata and the actual unwrapped private options.
//! This primitive never selects a key provider or attributes those options to
//! KMS. The owned raw options and temporary payload buffers are zeroized; the
//! existing ocicrypt cipher/parser may retain internal key copies with its own
//! lifetime. Complete erasure of those library-internal copies is not claimed.

use super::sealed_image::SealedImageBytes;
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{de, Deserialize, Deserializer};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fmt};
use tokio::io::{AsyncRead, AsyncReadExt, BufReader};
use zeroize::{Zeroize, Zeroizing};

const ENCRYPTED_TAR: &str = "application/vnd.oci.image.layer.v1.tar+encrypted";
const ENCRYPTED_GZIP: &str = "application/vnd.oci.image.layer.v1.tar+gzip+encrypted";
const READ_CHUNK: usize = 8192;
// Cooperative scheduling granularity, not an accepted-content/deployment limit.
const YIELD_BYTES: usize = 512 * 1024;
const TAR_BLOCK: usize = 512;

/// Expectations are metadata inputs, not an image-signature or origin witness.
pub struct LayerContentExpectation<'a> {
    pub original_index: u32,
    pub media_type: &'a str,
    /// Lowercase SHA256 hex without an algorithm prefix.
    pub blob_sha256: &'a str,
    pub descriptor_size: u64,
    /// The config's uncompressed tar digest, with a `sha256:` prefix.
    pub diff_id: &'a str,
    pub public_options_b64: &'a str,
}

/// Supplied by the trusted owner; there are no deployment default limits.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct LayerContentLimits {
    pub ciphertext_bytes: usize,
    pub private_options_bytes: usize,
    pub public_options_bytes: usize,
    pub plaintext_bytes: usize,
    pub tar_bytes: usize,
    pub tar_entries: usize,
    pub path_bytes: usize,
    pub file_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum LayerContentError {
    #[error("layer content limits are invalid")]
    InvalidLimits,
    #[error("layer content exceeds the configured bounds")]
    TooLarge,
    #[error("layer metadata is unsupported or malformed")]
    InvalidMetadata,
    #[error("actual ciphertext size or digest differs from its descriptor")]
    CiphertextMismatch,
    #[error("layer encryption options are malformed or unsupported")]
    InvalidOptions,
    #[error("layer decryption or integrity verification failed")]
    DecryptionFailed,
    #[error("decrypted compressed bytes differ from the private-options digest")]
    PlaintextDigestMismatch,
    #[error("layer decompression or trailer verification failed")]
    DecompressionFailed,
    #[error("actual uncompressed tar digest differs from the config DiffID")]
    DiffIdMismatch,
    #[error("layer archive is malformed, truncated or has invalid padding")]
    InvalidArchive,
    #[error("layer archive uses an unsupported entry or privileged metadata")]
    UnsupportedArchive,
    #[error("checked tar bytes could not be sealed")]
    SealingFailed,
}

/// Actual checked byte domains and an owned immutable TAR byte container.
/// This is not an unpacked rootfs, P, lease, image signature, or KMS receipt.
pub struct CheckedLayerContent {
    original_index: u32,
    blob_sha256: String,
    plaintext_sha256: String,
    diff_id: String,
    tar_entries: usize,
    sealed_tar: SealedImageBytes,
    limits: LayerContentLimits,
}

impl CheckedLayerContent {
    pub fn original_index(&self) -> u32 {
        self.original_index
    }
    pub fn blob_sha256(&self) -> &str {
        &self.blob_sha256
    }
    pub fn plaintext_sha256(&self) -> &str {
        &self.plaintext_sha256
    }
    pub fn diff_id(&self) -> &str {
        &self.diff_id
    }
    pub fn tar_entries(&self) -> usize {
        self.tar_entries
    }
    pub fn tar_byte_len(&self) -> u64 {
        self.sealed_tar.byte_len()
    }
    pub fn sealed_tar(&self) -> &SealedImageBytes {
        &self.sealed_tar
    }
    pub fn into_sealed_tar(self) -> SealedImageBytes {
        self.sealed_tar
    }

    pub(super) fn limits(&self) -> LayerContentLimits {
        self.limits
    }
}

/// No caller callback or success flag is used. Decryption is drained to actual
/// EOF, including HMAC verification, before a decoder is allowed to inspect it.
pub async fn check_layer_content(
    expected: LayerContentExpectation<'_>,
    ciphertext: &[u8],
    private_options: Zeroizing<Vec<u8>>,
    limits: LayerContentLimits,
) -> Result<CheckedLayerContent, LayerContentError> {
    validate_limits(limits)?;
    if ciphertext.len() > limits.ciphertext_bytes
        || private_options.len() > limits.private_options_bytes
    {
        return Err(LayerContentError::TooLarge);
    }
    if ciphertext.is_empty()
        || !is_sha256(expected.blob_sha256)
        || !matches!(expected.media_type, ENCRYPTED_TAR | ENCRYPTED_GZIP)
        || expected
            .diff_id
            .strip_prefix("sha256:")
            .is_none_or(|v| !is_sha256(v))
    {
        return Err(LayerContentError::InvalidMetadata);
    }
    let blob_sha256 = sha256(ciphertext);
    if expected.descriptor_size != ciphertext.len() as u64 || expected.blob_sha256 != blob_sha256 {
        return Err(LayerContentError::CiphertextMismatch);
    }

    let public_bytes = decode(expected.public_options_b64, limits.public_options_bytes)?;
    let public: PublicOptions =
        serde_json::from_slice(&public_bytes).map_err(|_| LayerContentError::InvalidOptions)?;
    let private: PrivateOptions =
        serde_json::from_slice(&private_options).map_err(|_| LayerContentError::InvalidOptions)?;
    validate_options(&private, &public)?;

    // This exact API consumes the supplied options, not a global keyprovider.
    // Its private digest is the decrypted compressed-domain digest, not DiffID.
    let annotations = BTreeMap::from([(
        "org.opencontainers.image.enc.pubopts".to_owned(),
        expected.public_options_b64.to_owned(),
    )]);
    let (reader, private_digest) = ocicrypt_rs::encryption::async_decrypt_layer(
        ciphertext,
        Some(&annotations),
        &private_options,
    )
    .map_err(|_| LayerContentError::DecryptionFailed)?;
    let plaintext = drain_bounded(
        Box::pin(reader),
        limits.plaintext_bytes,
        LayerContentError::DecryptionFailed,
    )
    .await?;
    let plaintext_sha256 = sha256(&plaintext);
    if private_digest != format!("sha256:{plaintext_sha256}") {
        return Err(LayerContentError::PlaintextDigestMismatch);
    }
    drop(private);
    drop(private_options);

    let tar = if expected.media_type == ENCRYPTED_GZIP {
        let mut decoder = async_compression::tokio::bufread::GzipDecoder::new(BufReader::new(
            plaintext.as_slice(),
        ));
        // A single-member decoder could hide a trailing member or garbage.
        decoder.multiple_members(true);
        drain_bounded(
            decoder,
            limits.tar_bytes,
            LayerContentError::DecompressionFailed,
        )
        .await?
    } else {
        if plaintext.len() > limits.tar_bytes {
            return Err(LayerContentError::TooLarge);
        }
        // Move the owned zeroizing buffer without another plaintext copy.
        plaintext
    };
    let diff_id = format!("sha256:{}", sha256(&tar));
    if diff_id != expected.diff_id {
        return Err(LayerContentError::DiffIdMismatch);
    }
    let tar_entries = inspect_ustar(&tar, limits)?;
    let sealed_tar = SealedImageBytes::from_bytes(&tar, limits.tar_bytes as u64)
        .map_err(|_| LayerContentError::SealingFailed)?;
    Ok(CheckedLayerContent {
        original_index: expected.original_index,
        blob_sha256,
        plaintext_sha256,
        diff_id,
        tar_entries,
        sealed_tar,
        limits,
    })
}

/// The buffer always has nonzero capacity, including an EOF probe at the exact
/// cap. An ocicrypt error is terminal: its reader is dropped, never polled again
/// (the existing cipher sets its internal done flag before checking the HMAC).
async fn drain_bounded(
    mut reader: impl AsyncRead + Unpin,
    max: usize,
    read_error: LayerContentError,
) -> Result<Zeroizing<Vec<u8>>, LayerContentError> {
    let mut out = Zeroizing::new(Vec::new());
    let mut buffer = Zeroizing::new([0u8; READ_CHUNK]);
    let mut since_yield = 0;
    loop {
        let remaining = max - out.len();
        let probe_len = READ_CHUNK.min(remaining + 1);
        let count = reader
            .read(&mut buffer[..probe_len])
            .await
            .map_err(|_| read_error)?;
        if count == 0 {
            return Ok(out);
        }
        if count > remaining {
            return Err(LayerContentError::TooLarge);
        }
        out.extend_from_slice(&buffer[..count]);
        since_yield += count;
        if since_yield >= YIELD_BYTES {
            since_yield = 0;
            tokio::task::yield_now().await;
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivateOptions {
    #[serde(rename = "symkey")]
    symmetric_key: String,
    #[serde(rename = "cipheroptions", deserialize_with = "unique_map")]
    cipher_options: BTreeMap<String, String>,
    digest: String,
}

impl Drop for PrivateOptions {
    fn drop(&mut self) {
        self.symmetric_key.zeroize();
        self.digest.zeroize();
        for value in self.cipher_options.values_mut() {
            value.zeroize();
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicOptions {
    cipher: String,
    #[serde(rename = "cipheroptions", deserialize_with = "unique_map")]
    cipher_options: BTreeMap<String, String>,
    hmac: String,
}

fn validate_options(
    private: &PrivateOptions,
    public: &PublicOptions,
) -> Result<(), LayerContentError> {
    if public.cipher != "AES_256_CTR_HMAC_SHA256"
        || private
            .digest
            .strip_prefix("sha256:")
            .is_none_or(|v| !is_sha256(v))
        || private.cipher_options.len() > 1
        || public.cipher_options.len() > 1
    {
        return Err(LayerContentError::InvalidOptions);
    }
    let key = decode(&private.symmetric_key, 32)?;
    if key.len() != 32 || decode(&public.hmac, 32)?.len() != 32 {
        return Err(LayerContentError::InvalidOptions);
    }
    for options in [&private.cipher_options, &public.cipher_options] {
        for (name, nonce) in options {
            if name != "nonce" || decode(nonce, 16)?.len() != 16 {
                return Err(LayerContentError::InvalidOptions);
            }
        }
    }
    if private.cipher_options.is_empty() && public.cipher_options.is_empty() {
        return Err(LayerContentError::InvalidOptions);
    }
    Ok(())
}

fn decode(value: &str, max: usize) -> Result<Zeroizing<Vec<u8>>, LayerContentError> {
    if value.len()
        > max
            .div_ceil(3)
            .checked_mul(4)
            .ok_or(LayerContentError::InvalidLimits)?
    {
        return Err(LayerContentError::TooLarge);
    }
    let bytes = Zeroizing::new(
        STANDARD
            .decode(value)
            .map_err(|_| LayerContentError::InvalidOptions)?,
    );
    if bytes.len() > max {
        return Err(LayerContentError::TooLarge);
    }
    if bytes.is_empty() {
        return Err(LayerContentError::InvalidOptions);
    }
    if STANDARD.encode(bytes.as_slice()) != value {
        return Err(LayerContentError::InvalidOptions);
    }
    Ok(bytes)
}

fn validate_limits(limits: LayerContentLimits) -> Result<(), LayerContentError> {
    if [
        limits.ciphertext_bytes,
        limits.private_options_bytes,
        limits.public_options_bytes,
        limits.plaintext_bytes,
        limits.tar_bytes,
        limits.tar_entries,
        limits.path_bytes,
        limits.file_bytes,
    ]
    .iter()
    .any(|v| *v == 0 || *v > isize::MAX as usize)
    {
        return Err(LayerContentError::InvalidLimits);
    }
    Ok(())
}

/// Intentionally narrow USTAR validation, not extraction or overlay application.
/// No PAX/GNU extensions (including capability xattrs), links, devices, whiteouts,
/// privileged mode bits, duplicate paths, or file/parent collisions are accepted.
fn inspect_ustar(tar: &[u8], limits: LayerContentLimits) -> Result<usize, LayerContentError> {
    Ok(parse_ustar(tar, limits)?.len())
}

/// Shared strict parser for byte checking and the non-authorizing staging path.
/// Metadata is retained for a future builder; staging does not apply ownership,
/// timestamps or archive permission bits to its mutable workspace.
pub(super) struct TarEntry<'a> {
    pub path: String,
    pub is_dir: bool,
    pub mode: u32,
    pub uid: u64,
    pub gid: u64,
    pub mtime: u64,
    pub payload: &'a [u8],
}

pub(super) fn parse_ustar(
    tar: &[u8],
    limits: LayerContentLimits,
) -> Result<Vec<TarEntry<'_>>, LayerContentError> {
    if !tar.len().is_multiple_of(TAR_BLOCK) {
        return Err(LayerContentError::InvalidArchive);
    }
    let mut offset = 0usize;
    let mut paths: BTreeMap<String, bool> = BTreeMap::new();
    let mut entries = Vec::new();
    loop {
        let header = tar
            .get(
                offset
                    ..offset
                        .checked_add(TAR_BLOCK)
                        .ok_or(LayerContentError::TooLarge)?,
            )
            .ok_or(LayerContentError::InvalidArchive)?;
        if header.iter().all(|b| *b == 0) {
            if tar.len() - offset < 2 * TAR_BLOCK || tar[offset..].iter().any(|b| *b != 0) {
                return Err(LayerContentError::InvalidArchive);
            }
            return Ok(entries);
        }
        if paths.len() >= limits.tar_entries {
            return Err(LayerContentError::TooLarge);
        }
        if &header[257..263] != b"ustar\0"
            || &header[263..265] != b"00"
            || header[157..257].iter().any(|b| *b != 0)
            || header[500..512].iter().any(|b| *b != 0)
        {
            return Err(LayerContentError::UnsupportedArchive);
        }
        let sum: u64 = header
            .iter()
            .enumerate()
            .map(|(i, b)| {
                if (148..156).contains(&i) {
                    32
                } else {
                    u64::from(*b)
                }
            })
            .sum();
        if octal(&header[148..156])? != sum {
            return Err(LayerContentError::InvalidArchive);
        }
        let is_dir = match header[156] {
            0 | b'0' => false,
            b'5' => true,
            _ => return Err(LayerContentError::UnsupportedArchive),
        };
        let mode = octal(&header[100..108])?;
        if mode & !0o777 != 0 || octal(&header[329..337])? != 0 || octal(&header[337..345])? != 0 {
            return Err(LayerContentError::UnsupportedArchive);
        }
        let uid = octal(&header[108..116])?;
        let gid = octal(&header[116..124])?;
        let mtime = octal(&header[136..148])?;
        let size =
            usize::try_from(octal(&header[124..136])?).map_err(|_| LayerContentError::TooLarge)?;
        if size > limits.file_bytes {
            return Err(LayerContentError::TooLarge);
        }
        if is_dir && size != 0 {
            return Err(LayerContentError::UnsupportedArchive);
        }
        let name = text_field(&header[..100])?;
        let prefix = text_field(&header[345..500])?;
        let path = if prefix.is_empty() {
            name.to_owned()
        } else {
            format!("{prefix}/{name}")
        };
        let path = path.strip_suffix('/').filter(|_| is_dir).unwrap_or(&path);
        if path.len() > limits.path_bytes {
            return Err(LayerContentError::TooLarge);
        }
        if path.is_empty()
            || path.starts_with('/')
            || path.bytes().any(|b| b < 32 || b == 127 || b == b'\\')
            || (path != "."
                && path
                    .split('/')
                    .any(|p| p.is_empty() || p == "." || p == ".." || p.starts_with(".wh.")))
            || (path == "." && !is_dir)
        {
            return Err(LayerContentError::UnsupportedArchive);
        }
        if paths.contains_key(path) {
            return Err(LayerContentError::UnsupportedArchive);
        }
        let mut ancestor = path;
        while let Some((parent, _)) = ancestor.rsplit_once('/') {
            if paths.get(parent) == Some(&false) {
                return Err(LayerContentError::UnsupportedArchive);
            }
            ancestor = parent;
        }
        let child_prefix = format!("{path}/");
        if !is_dir
            && paths
                .range(child_prefix.clone()..)
                .next()
                .is_some_and(|(p, _)| p.starts_with(&child_prefix))
        {
            return Err(LayerContentError::UnsupportedArchive);
        }
        paths.insert(path.to_owned(), is_dir);
        let payload_start = offset
            .checked_add(TAR_BLOCK)
            .ok_or(LayerContentError::TooLarge)?;
        let payload_end = payload_start
            .checked_add(size)
            .ok_or(LayerContentError::TooLarge)?;
        let padded_size = size
            .div_ceil(TAR_BLOCK)
            .checked_mul(TAR_BLOCK)
            .ok_or(LayerContentError::TooLarge)?;
        let next = payload_start
            .checked_add(padded_size)
            .ok_or(LayerContentError::TooLarge)?;
        if tar
            .get(payload_end..next)
            .is_none_or(|padding| padding.iter().any(|b| *b != 0))
        {
            return Err(LayerContentError::InvalidArchive);
        }
        entries.push(TarEntry {
            path: path.to_owned(),
            is_dir,
            mode: mode as u32,
            uid,
            gid,
            mtime,
            payload: &tar[payload_start..payload_end],
        });
        offset = next;
    }
}

fn text_field(field: &[u8]) -> Result<&str, LayerContentError> {
    let end = field.iter().position(|b| *b == 0).unwrap_or(field.len());
    if field[end..].iter().any(|b| *b != 0) {
        return Err(LayerContentError::InvalidArchive);
    }
    std::str::from_utf8(&field[..end]).map_err(|_| LayerContentError::UnsupportedArchive)
}
fn octal(field: &[u8]) -> Result<u64, LayerContentError> {
    let text = std::str::from_utf8(field).map_err(|_| LayerContentError::InvalidArchive)?;
    let text = text.trim_matches(['\0', ' ']);
    if text.is_empty() {
        return Ok(0);
    }
    if !text.bytes().all(|b| (b'0'..=b'7').contains(&b)) {
        return Err(LayerContentError::UnsupportedArchive);
    }
    u64::from_str_radix(text, 8).map_err(|_| LayerContentError::InvalidArchive)
}
fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn unique_map<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<BTreeMap<String, String>, D::Error> {
    struct UniqueMap;
    impl<'de> de::Visitor<'de> for UniqueMap {
        type Value = BTreeMap<String, String>;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("unique string option names")
        }
        fn visit_map<M: de::MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
            let mut result = BTreeMap::new();
            while let Some((key, value)) = map.next_entry::<String, String>()? {
                if result.insert(key, value).is_some() {
                    return Err(de::Error::custom("duplicate option name"));
                }
            }
            Ok(result)
        }
    }
    deserializer.deserialize_map(UniqueMap)
}

#[cfg(test)]
#[path = "layer_content_tests.rs"]
mod tests;
