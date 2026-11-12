// SPDX-License-Identifier: Apache-2.0

//! Default-off registry reads restricted to one origin and exact digests.
//!
//! This is transport byte consistency, not publisher authorization, admission,
//! KMS success or rootfs custody. Constructor-owned addresses and CA roots replace
//! ambient DNS, proxies and TLS roots. Redirects, challenge auth, descriptor URLs,
//! content decoding, discovery and HTTP retries are outside this narrow profile.
//! Connection attempts may use the finite constructor-owned address list.
//! Body accumulation is bounded; HTTP/TLS parser buffers have separate library
//! bounds and are not claimed to fit inside the application body limit.

use base64::{engine::general_purpose::STANDARD, Engine};
use oci_spec::distribution::Reference;
use reqwest::{header, Certificate, Client, Response, StatusCode, Url};
use serde::{de, Deserialize, Deserializer};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fmt,
    net::SocketAddr,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

const OCI_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
const OCI_CONFIG: &str = "application/vnd.oci.image.config.v1+json";
const OCI_EMPTY: &str = "application/vnd.oci.empty.v1+json";
const OCTET_STREAM: &str = "application/octet-stream";
const COSIGN_PAYLOAD: &str = "application/vnd.dev.cosign.simplesigning.v1+json";
const COSIGN_SIGNATURE: &str = "dev.cosignproject.cosign/signature";
const MAX_CONFIGURATION_BYTES: usize = 64 * 1024;
const MAX_ADDRESSES: usize = 16;

/// Trusted startup input, never selected by an image, challenge or host RPC.
/// `repository` is the full canonical OCI name, e.g. `registry.example/team/app`.
/// Address ports must equal the origin port. Keys/tokens are never serialized.
pub struct TrustedRegistryConfig {
    pub origin: String,
    pub repository: String,
    pub addresses: Vec<SocketAddr>,
    pub tls_ca_pem: Vec<u8>,
    pub bearer_token: Option<Zeroizing<String>>,
}

#[derive(Clone, Copy)]
pub struct RegistryIngressLimits {
    pub manifest_bytes: usize,
    pub blob_bytes: usize,
    pub signature_payload_bytes: usize,
    pub signature_bytes: usize,
    pub connect_timeout: Duration,
    pub read_timeout: Duration,
    pub request_timeout: Duration,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum RegistryIngressError {
    #[error("registry ingress configuration rejected")]
    InvalidConfiguration,
    #[error("registry ingress digest rejected")]
    InvalidDigest,
    #[error("registry ingress exceeds configured bounds")]
    TooLarge,
    #[error("registry ingress transport failed")]
    Transport,
    #[error("registry ingress response profile rejected")]
    ResponseRejected,
    #[error("registry ingress bytes differ from the expected size or digest")]
    ContentMismatch,
    #[error("registry signature artifact profile rejected")]
    SignatureArtifactRejected,
}

/// Public signature material remains untrusted until the requiring policy/key
/// verifies the payload against the admitted image and exact repository.
pub struct RegistrySignature {
    pub payload: Vec<u8>,
    pub signature: Vec<u8>,
}

pub struct TrustedRegistry {
    client: Client,
    origin: Url,
    repository: String,
    repository_path: String,
    authorization: Option<header::HeaderValue>,
    limits: RegistryIngressLimits,
}

impl TrustedRegistry {
    /// Network-free construction. There is no ambient CA, DNS or auth fallback.
    pub fn new(
        config: TrustedRegistryConfig,
        limits: RegistryIngressLimits,
    ) -> Result<Self, RegistryIngressError> {
        validate_limits(limits)?;
        if config.origin.len() > MAX_CONFIGURATION_BYTES
            || config.repository.len() > MAX_CONFIGURATION_BYTES
            || config.tls_ca_pem.is_empty()
            || config.tls_ca_pem.len() > MAX_CONFIGURATION_BYTES
            || config.addresses.is_empty()
            || config.addresses.len() > MAX_ADDRESSES
        {
            return Err(RegistryIngressError::InvalidConfiguration);
        }
        let origin =
            Url::parse(&config.origin).map_err(|_| RegistryIngressError::InvalidConfiguration)?;
        let host = match origin.host() {
            Some(url::Host::Domain(host)) => host,
            _ => return Err(RegistryIngressError::InvalidConfiguration),
        };
        if origin.scheme() != "https"
            || origin.path() != "/"
            || origin.query().is_some()
            || origin.fragment().is_some()
            || !origin.username().is_empty()
            || origin.password().is_some()
            || config.origin.trim_end_matches('/') != origin.origin().ascii_serialization()
        {
            return Err(RegistryIngressError::InvalidConfiguration);
        }
        let port = origin
            .port_or_known_default()
            .ok_or(RegistryIngressError::InvalidConfiguration)?;
        if config.addresses.iter().any(|address| {
            address.port() != port || address.ip().is_unspecified() || address.ip().is_multicast()
        }) {
            return Err(RegistryIngressError::InvalidConfiguration);
        }
        let pinned = format!("{}@sha256:{}", config.repository, "0".repeat(64));
        let reference = pinned
            .parse::<Reference>()
            .map_err(|_| RegistryIngressError::InvalidConfiguration)?;
        if reference.tag().is_some()
            || format!("{}/{}", reference.registry(), reference.repository()) != config.repository
            || format!("https://{}", reference.registry()) != origin.origin().ascii_serialization()
        {
            return Err(RegistryIngressError::InvalidConfiguration);
        }
        let roots = Certificate::from_pem_bundle(&config.tls_ca_pem)
            .map_err(|_| RegistryIngressError::InvalidConfiguration)?;
        if roots.is_empty() {
            return Err(RegistryIngressError::InvalidConfiguration);
        }
        let authorization = config
            .bearer_token
            .map(|token| {
                if token.is_empty()
                    || token.len() > MAX_CONFIGURATION_BYTES
                    || !token
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"-._~+/=".contains(&byte))
                {
                    return Err(RegistryIngressError::InvalidConfiguration);
                }
                let formatted = Zeroizing::new(format!("Bearer {}", token.as_str()));
                let mut value = header::HeaderValue::from_bytes(formatted.as_bytes())
                    .map_err(|_| RegistryIngressError::InvalidConfiguration)?;
                value.set_sensitive(true);
                Ok(value)
            })
            .transpose()?;
        let client = Client::builder()
            .tls_backend_rustls()
            .tls_certs_only(roots)
            .https_only(true)
            .http1_only()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .no_proxy()
            .referer(false)
            .pool_max_idle_per_host(0)
            .no_gzip()
            .no_brotli()
            .no_deflate()
            .no_zstd()
            .resolve_to_addrs(host, &config.addresses)
            .connect_timeout(limits.connect_timeout)
            .read_timeout(limits.read_timeout)
            .timeout(limits.request_timeout)
            .build()
            .map_err(|_| RegistryIngressError::InvalidConfiguration)?;
        Ok(Self {
            client,
            repository_path: reference.repository().into(),
            origin,
            repository: config.repository,
            authorization,
            limits,
        })
    }

    pub fn repository(&self) -> &str {
        &self.repository
    }

    /// `digest` is exactly 64 lowercase SHA256 hex characters, without a prefix.
    pub async fn fetch_manifest(
        &self,
        digest: &str,
        cap: usize,
    ) -> Result<Vec<u8>, RegistryIngressError> {
        self.fetch(
            "manifests",
            OCI_MANIFEST,
            digest,
            None,
            cap.min(self.limits.manifest_bytes),
        )
        .await
    }

    pub async fn fetch_blob(
        &self,
        digest: &str,
        expected_size: u64,
        cap: usize,
    ) -> Result<Vec<u8>, RegistryIngressError> {
        self.fetch(
            "blobs",
            OCTET_STREAM,
            digest,
            Some(expected_size),
            cap.min(self.limits.blob_bytes),
        )
        .await
    }

    /// One digest-pinned Cosign artifact and one digest-pinned payload; no tag or
    /// referrer discovery, certificate/key locations or extra graph traversal.
    pub async fn fetch_signature(
        &self,
        artifact_digest: &str,
    ) -> Result<RegistrySignature, RegistryIngressError> {
        let bytes = self
            .fetch_manifest(artifact_digest, self.limits.manifest_bytes)
            .await?;
        let artifact: SignatureManifest = serde_json::from_slice(&bytes)
            .map_err(|_| RegistryIngressError::SignatureArtifactRejected)?;
        if artifact.schema_version != 2
            || artifact.media_type != OCI_MANIFEST
            || artifact.layers.len() != 1
            || !artifact.annotations.is_empty()
            || !matches!(artifact.config.media_type.as_str(), OCI_CONFIG | OCI_EMPTY)
            || !artifact.config.annotations.is_empty()
            || artifact.config.size > self.limits.blob_bytes as u64
        {
            return Err(RegistryIngressError::SignatureArtifactRejected);
        }
        prefixed_digest(&artifact.config.digest)?;
        // The artifact config is unused profile metadata, not fetched or claimed
        // to be authenticated application configuration. Only the layer payload
        // and signature are returned to the requiring cryptographic verifier.
        let layer = artifact
            .layers
            .into_iter()
            .next()
            .ok_or(RegistryIngressError::SignatureArtifactRejected)?;
        if layer.media_type != COSIGN_PAYLOAD || layer.annotations.len() != 1 {
            return Err(RegistryIngressError::SignatureArtifactRejected);
        }
        let encoded = layer
            .annotations
            .get(COSIGN_SIGNATURE)
            .ok_or(RegistryIngressError::SignatureArtifactRejected)?;
        let encoded_cap = self
            .limits
            .signature_bytes
            .div_ceil(3)
            .checked_mul(4)
            .ok_or(RegistryIngressError::InvalidConfiguration)?;
        if encoded.len() > encoded_cap {
            return Err(RegistryIngressError::TooLarge);
        }
        let signature = STANDARD
            .decode(encoded)
            .map_err(|_| RegistryIngressError::SignatureArtifactRejected)?;
        if signature.is_empty() || signature.len() > self.limits.signature_bytes {
            return Err(RegistryIngressError::TooLarge);
        }
        if STANDARD.encode(&signature) != *encoded {
            return Err(RegistryIngressError::SignatureArtifactRejected);
        }
        let payload = self
            .fetch_blob(
                prefixed_digest(&layer.digest)?,
                layer.size,
                self.limits.signature_payload_bytes,
            )
            .await?;
        Ok(RegistrySignature { payload, signature })
    }

    async fn fetch(
        &self,
        kind: &str,
        mime: &str,
        digest: &str,
        expected_size: Option<u64>,
        cap: usize,
    ) -> Result<Vec<u8>, RegistryIngressError> {
        if !is_sha256(digest) {
            return Err(RegistryIngressError::InvalidDigest);
        }
        if cap == 0
            || cap > isize::MAX as usize
            || expected_size.is_some_and(|size| size == 0 || size > cap as u64)
        {
            return Err(RegistryIngressError::TooLarge);
        }
        let mut url = self.origin.clone();
        url.set_path(&format!(
            "/v2/{}/{kind}/sha256:{digest}",
            self.repository_path
        ));
        let mut request = self
            .client
            .get(url.clone())
            .header(header::ACCEPT, mime)
            .header(header::ACCEPT_ENCODING, "identity");
        if let Some(auth) = &self.authorization {
            request = request.header(header::AUTHORIZATION, auth.clone());
        }
        let mut response = request
            .send()
            .await
            .map_err(|_| RegistryIngressError::Transport)?;
        if response.status() != StatusCode::OK || response.url() != &url {
            return Err(RegistryIngressError::ResponseRejected);
        }
        validate_headers(&response, mime, digest, expected_size, cap)?;
        let mut output = Vec::new();
        let mut hash = Sha256::new();
        // Completion is HTTP framed-body EOF, not TCP connection closure.
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| RegistryIngressError::Transport)?
        {
            let next = output
                .len()
                .checked_add(chunk.len())
                .filter(|size| *size <= cap)
                .ok_or(RegistryIngressError::TooLarge)?;
            if expected_size.is_some_and(|size| next as u64 > size) {
                return Err(RegistryIngressError::ContentMismatch);
            }
            output
                .try_reserve_exact(chunk.len())
                .map_err(|_| RegistryIngressError::TooLarge)?;
            output.extend_from_slice(&chunk);
            hash.update(&chunk);
        }
        if expected_size.is_some_and(|size| size != output.len() as u64)
            || hash
                .finalize()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
                != digest
        {
            return Err(RegistryIngressError::ContentMismatch);
        }
        Ok(output)
    }
}

fn validate_limits(limits: RegistryIngressLimits) -> Result<(), RegistryIngressError> {
    if [
        limits.manifest_bytes,
        limits.blob_bytes,
        limits.signature_payload_bytes,
        limits.signature_bytes,
    ]
    .iter()
    .any(|value| *value == 0 || *value > isize::MAX as usize)
        || [
            limits.connect_timeout,
            limits.read_timeout,
            limits.request_timeout,
        ]
        .iter()
        .any(|duration| duration.is_zero() || Instant::now().checked_add(*duration).is_none())
    {
        return Err(RegistryIngressError::InvalidConfiguration);
    }
    Ok(())
}

fn validate_headers(
    response: &Response,
    mime: &str,
    digest: &str,
    expected_size: Option<u64>,
    cap: usize,
) -> Result<(), RegistryIngressError> {
    let one =
        |name: header::HeaderName| -> Result<Option<&header::HeaderValue>, RegistryIngressError> {
            let mut values = response.headers().get_all(name).iter();
            let first = values.next();
            if values.next().is_some() {
                return Err(RegistryIngressError::ResponseRejected);
            }
            Ok(first)
        };
    if one(header::CONTENT_TYPE)?.and_then(|value| value.to_str().ok()) != Some(mime)
        || one(header::CONTENT_ENCODING)?
            .is_some_and(|value| !value.as_bytes().eq_ignore_ascii_case(b"identity"))
    {
        return Err(RegistryIngressError::ResponseRejected);
    }
    if let Some(value) = one(header::CONTENT_LENGTH)? {
        let text = value
            .to_str()
            .map_err(|_| RegistryIngressError::ResponseRejected)?;
        if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(RegistryIngressError::ResponseRejected);
        }
        let length: u64 = text
            .parse()
            .map_err(|_| RegistryIngressError::ResponseRejected)?;
        if length > cap as u64 {
            return Err(RegistryIngressError::TooLarge);
        }
        if expected_size.is_some_and(|size| size != length) {
            return Err(RegistryIngressError::ContentMismatch);
        }
    }
    if one(header::HeaderName::from_static("docker-content-digest"))?
        .is_some_and(|value| value.as_bytes() != format!("sha256:{digest}").as_bytes())
    {
        return Err(RegistryIngressError::ContentMismatch);
    }
    Ok(())
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn prefixed_digest(value: &str) -> Result<&str, RegistryIngressError> {
    value
        .strip_prefix("sha256:")
        .filter(|digest| is_sha256(digest))
        .ok_or(RegistryIngressError::InvalidDigest)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SignatureManifest {
    #[serde(rename = "schemaVersion")]
    schema_version: u32,
    #[serde(rename = "mediaType")]
    media_type: String,
    config: SignatureDescriptor,
    layers: Vec<SignatureDescriptor>,
    #[serde(default, deserialize_with = "unique_map")]
    annotations: BTreeMap<String, String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SignatureDescriptor {
    #[serde(rename = "mediaType")]
    media_type: String,
    digest: String,
    size: u64,
    #[serde(default, deserialize_with = "unique_map")]
    annotations: BTreeMap<String, String>,
}

fn unique_map<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<BTreeMap<String, String>, D::Error> {
    struct UniqueMap;
    impl<'de> de::Visitor<'de> for UniqueMap {
        type Value = BTreeMap<String, String>;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("unique string annotation names")
        }
        fn visit_map<M: de::MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
            let mut values = BTreeMap::new();
            while let Some((key, value)) = map.next_entry::<String, String>()? {
                if values.insert(key, value).is_some() {
                    return Err(de::Error::custom("duplicate annotation name"));
                }
            }
            Ok(values)
        }
    }
    deserializer.deserialize_map(UniqueMap)
}

#[cfg(test)]
#[path = "registry_ingress_tests.rs"]
mod tests;
