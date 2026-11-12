use super::*;
use ocicrypt_rs::blockcipher::{
    EncryptionFinalizer, LayerBlockCipherHandler, LayerBlockCipherOptions, AES256CTR,
};
use std::{
    io::{Read, Write},
    os::{fd::AsFd, unix::fs::FileExt},
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::ReadBuf;

struct Fixture {
    ciphertext: Vec<u8>,
    private: Vec<u8>,
    public: String,
    blob: String,
    diff_id: String,
    media_type: &'static str,
    plain_len: usize,
    tar: Vec<u8>,
}

impl Fixture {
    fn new(tar: Vec<u8>, gzip: bool) -> Self {
        let plaintext = if gzip { compress(&tar) } else { tar.clone() };
        Self::from_plaintext(tar, plaintext, gzip)
    }
    fn from_plaintext(tar: Vec<u8>, plaintext: Vec<u8>, gzip: bool) -> Self {
        // Generate the key, nonce, ciphertext, and finalized HMAC with ocicrypt.
        // Synthetic private options bypass Google SDK/KMS resolution.
        let mut options = LayerBlockCipherOptions::default();
        options.private.digest = format!("sha256:{}", sha256(&plaintext));
        let mut cipher = LayerBlockCipherHandler::default();
        cipher
            .encrypt(plaintext.as_slice(), AES256CTR, &mut options)
            .unwrap();
        let mut ciphertext = Vec::new();
        Read::read_to_end(&mut cipher, &mut ciphertext).unwrap();
        cipher.finalized_lbco(&mut options).unwrap();
        Self {
            blob: sha256(&ciphertext),
            ciphertext,
            private: serde_json::to_vec(&options.private).unwrap(),
            public: STANDARD.encode(serde_json::to_vec(&options.public).unwrap()),
            diff_id: format!("sha256:{}", sha256(&tar)),
            tar,
            plain_len: plaintext.len(),
            media_type: if gzip { ENCRYPTED_GZIP } else { ENCRYPTED_TAR },
        }
    }
    fn expected(&self) -> LayerContentExpectation<'_> {
        LayerContentExpectation {
            original_index: 7,
            media_type: self.media_type,
            blob_sha256: &self.blob,
            descriptor_size: self.ciphertext.len() as u64,
            diff_id: &self.diff_id,
            public_options_b64: &self.public,
        }
    }
    fn limits(&self) -> LayerContentLimits {
        // Fixture-specific exact caps, never deployment defaults.
        LayerContentLimits {
            ciphertext_bytes: self.ciphertext.len(),
            private_options_bytes: self.private.len(),
            public_options_bytes: STANDARD.decode(&self.public).unwrap().len(),
            plaintext_bytes: self.plain_len,
            tar_bytes: self.tar.len(),
            tar_entries: 8,
            path_bytes: 256,
            file_bytes: 1024,
        }
    }
    async fn run(
        &self,
        limits: LayerContentLimits,
    ) -> Result<CheckedLayerContent, LayerContentError> {
        check_layer_content(
            self.expected(),
            &self.ciphertext,
            Zeroizing::new(self.private.clone()),
            limits,
        )
        .await
    }
    fn change_private(&mut self, name: &str, value: serde_json::Value) {
        let mut options: serde_json::Value = serde_json::from_slice(&self.private).unwrap();
        options[name] = value;
        self.private = serde_json::to_vec(&options).unwrap();
    }
    fn change_hmac(&mut self) {
        let mut public: serde_json::Value =
            serde_json::from_slice(&STANDARD.decode(&self.public).unwrap()).unwrap();
        let mut hmac = STANDARD.decode(public["hmac"].as_str().unwrap()).unwrap();
        hmac[0] ^= 1;
        public["hmac"] = STANDARD.encode(hmac).into();
        self.public = STANDARD.encode(serde_json::to_vec(&public).unwrap());
    }
}

fn compress(bytes: &[u8]) -> Vec<u8> {
    let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    gzip.write_all(bytes).unwrap();
    gzip.finish().unwrap()
}

fn archive(entries: &[(&str, &[u8], u8, u32)]) -> Vec<u8> {
    let mut result = Vec::new();
    for (name, data, kind, mode) in entries {
        let mut header = tokio_tar::Header::new_ustar();
        header.set_size(data.len() as u64);
        header.set_mode(*mode);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);
        header.set_entry_type(tokio_tar::EntryType::new(*kind));
        // Controlled invalid names cannot be built with safe set_path; mutate
        // only that field, then use the actual Header checksum implementation.
        assert!(name.len() <= 100);
        header.as_mut_bytes()[..100].fill(0);
        header.as_mut_bytes()[..name.len()].copy_from_slice(name.as_bytes());
        header.set_cksum();
        result.extend_from_slice(header.as_bytes());
        result.extend_from_slice(data);
        result.resize(result.len().div_ceil(TAR_BLOCK) * TAR_BLOCK, 0);
    }
    result.resize(result.len() + 2 * TAR_BLOCK, 0);
    result
}

fn valid_tar() -> Vec<u8> {
    archive(&[
        ("bin/", b"", b'5', 0o755),
        (
            "bin/app",
            b"public synthetic application bytes",
            b'0',
            0o755,
        ),
    ])
}

#[tokio::test]
async fn actual_tar_and_gzip_crypto_reach_all_integrity_boundaries_before_sealing() {
    for gzip in [false, true] {
        let fixture = Fixture::new(valid_tar(), gzip);
        let result = fixture.run(fixture.limits()).await.unwrap();
        assert_eq!(result.original_index(), 7);
        assert_eq!(result.blob_sha256(), fixture.blob);
        assert_eq!(result.diff_id(), fixture.diff_id);
        assert_eq!(result.tar_entries(), 2);
        assert_eq!(result.tar_byte_len(), fixture.tar.len() as u64);
        if gzip {
            assert_ne!(result.blob_sha256(), result.plaintext_sha256());
            assert_ne!(
                format!("sha256:{}", result.plaintext_sha256()),
                result.diff_id()
            );
        }
        let file = std::fs::File::from(result.sealed_tar().as_fd().try_clone_to_owned().unwrap());
        let mut bytes = vec![0; fixture.tar.len()];
        file.read_exact_at(&mut bytes, 0).unwrap();
        assert_eq!(bytes, fixture.tar);
        assert_eq!(result.into_sealed_tar().byte_len(), bytes.len() as u64);
    }
}

#[tokio::test]
async fn valid_multiple_gzip_members_must_all_contribute_to_diffid() {
    let tar = valid_tar();
    let half = tar.len() / 2;
    let mut plaintext = compress(&tar[..half]);
    plaintext.extend(compress(&tar[half..]));
    let fixture = Fixture::from_plaintext(tar, plaintext, true);
    let result = fixture.run(fixture.limits()).await.unwrap();
    assert_eq!(result.diff_id(), fixture.diff_id);
}

#[tokio::test]
async fn ciphertext_hash_size_hmac_and_both_plaintext_digest_domains_are_enforced() {
    let mut fixture = Fixture::new(valid_tar(), true);
    let mut expected = fixture.expected();
    expected.descriptor_size += 1;
    assert!(matches!(
        check_layer_content(
            expected,
            &fixture.ciphertext,
            Zeroizing::new(fixture.private.clone()),
            fixture.limits()
        )
        .await,
        Err(LayerContentError::CiphertextMismatch)
    ));
    fixture.ciphertext[0] ^= 1;
    assert!(matches!(
        fixture.run(fixture.limits()).await,
        Err(LayerContentError::CiphertextMismatch)
    ));
    fixture.ciphertext[0] ^= 1;
    fixture.change_hmac();
    // Exact plaintext cap still performs a nonempty EOF probe, which must not
    // turn the cipher's HMAC error/done flag into a successful truncated result.
    assert!(matches!(
        fixture.run(fixture.limits()).await,
        Err(LayerContentError::DecryptionFailed)
    ));
    let mut fixture = Fixture::new(valid_tar(), true);
    fixture.change_private("digest", format!("sha256:{}", "00".repeat(32)).into());
    assert!(matches!(
        fixture.run(fixture.limits()).await,
        Err(LayerContentError::PlaintextDigestMismatch)
    ));
    let mut fixture = Fixture::new(valid_tar(), true);
    fixture.diff_id = format!("sha256:{}", "00".repeat(32));
    assert!(matches!(
        fixture.run(fixture.limits()).await,
        Err(LayerContentError::DiffIdMismatch)
    ));
    let mut fixture = Fixture::new(valid_tar(), false);
    fixture.ciphertext.pop();
    fixture.blob = sha256(&fixture.ciphertext);
    assert!(matches!(
        fixture.run(fixture.limits()).await,
        Err(LayerContentError::DecryptionFailed)
    ));
}

#[tokio::test]
async fn gzip_trailer_truncation_and_trailing_garbage_cannot_be_hidden_by_a_decoder() {
    for case in ["crc", "truncated", "garbage"] {
        let tar = valid_tar();
        let mut plaintext = compress(&tar);
        match case {
            "crc" => {
                let end = plaintext.len();
                plaintext[end - 8] ^= 1;
            }
            "truncated" => {
                plaintext.truncate(plaintext.len() - 3);
            }
            "garbage" => plaintext.extend_from_slice(b"not a gzip member"),
            _ => unreachable!(),
        }
        let fixture = Fixture::from_plaintext(tar, plaintext, true);
        assert!(
            matches!(
                fixture.run(fixture.limits()).await,
                Err(LayerContentError::DecompressionFailed)
            ),
            "{case}"
        );
    }
}

#[tokio::test]
async fn malformed_or_unsupported_archives_are_rejected_after_actual_decryption() {
    for case in [
        "checksum",
        "one-zero",
        "nonzero-tail",
        "padding",
        "traversal",
        "absolute",
        "dot",
        "backslash",
        "duplicate",
        "file-parent",
        "setuid",
        "symlink",
        "hardlink",
        "device",
        "pax-caps",
        "gnu",
        "whiteout",
    ] {
        let tar = match case {
            "traversal" => archive(&[("../escape", b"x", b'0', 0o644)]),
            "absolute" => archive(&[("/absolute", b"x", b'0', 0o644)]),
            "dot" => archive(&[("./ambiguous", b"x", b'0', 0o644)]),
            "backslash" => archive(&[("a\\b", b"x", b'0', 0o644)]),
            "duplicate" => archive(&[("app", b"x", b'0', 0o644), ("app", b"y", b'0', 0o644)]),
            "file-parent" => archive(&[("a", b"x", b'0', 0o644), ("a/b", b"y", b'0', 0o644)]),
            "setuid" => archive(&[("app", b"x", b'0', 0o4755)]),
            "symlink" => archive(&[("app", b"", b'2', 0o644)]),
            "hardlink" => archive(&[("app", b"", b'1', 0o644)]),
            "device" => archive(&[("app", b"", b'3', 0o644)]),
            "pax-caps" => archive(&[("pax", b"security.capability", b'x', 0o644)]),
            "gnu" => archive(&[("gnu-long-name", b"path", b'L', 0o644)]),
            "whiteout" => archive(&[(".wh.app", b"", b'0', 0o644)]),
            "one-zero" => {
                let mut tar = valid_tar();
                tar.truncate(tar.len() - TAR_BLOCK);
                tar
            }
            "nonzero-tail" => {
                let mut tar = valid_tar();
                tar.extend([1; TAR_BLOCK]);
                tar
            }
            "padding" => {
                let mut tar = archive(&[("app", b"x", b'0', 0o644)]);
                tar[TAR_BLOCK + 1] = 1;
                tar
            }
            "checksum" => {
                let mut tar = valid_tar();
                tar[0] ^= 1;
                tar
            }
            _ => unreachable!(),
        };
        let fixture = Fixture::new(tar, false);
        assert!(
            matches!(
                fixture.run(fixture.limits()).await,
                Err(LayerContentError::InvalidArchive | LayerContentError::UnsupportedArchive)
            ),
            "{case}"
        );
    }
}

#[tokio::test]
async fn hard_caps_apply_to_actual_input_and_expansion_not_declared_lengths_only() {
    let fixture = Fixture::new(valid_tar(), true);
    for case in [
        "cipher",
        "private",
        "public",
        "plaintext",
        "tar",
        "entries",
        "path",
        "file",
    ] {
        let mut limits = fixture.limits();
        match case {
            "cipher" => limits.ciphertext_bytes -= 1,
            "private" => limits.private_options_bytes -= 1,
            "public" => limits.public_options_bytes -= 1,
            "plaintext" => limits.plaintext_bytes -= 1,
            "tar" => limits.tar_bytes -= 1,
            "entries" => limits.tar_entries = 1,
            "path" => limits.path_bytes = 2,
            "file" => limits.file_bytes = 1,
            _ => unreachable!(),
        }
        assert!(
            matches!(fixture.run(limits).await, Err(LayerContentError::TooLarge)),
            "{case}"
        );
    }
    let mut limits = fixture.limits();
    limits.tar_bytes = 0;
    assert!(matches!(
        fixture.run(limits).await,
        Err(LayerContentError::InvalidLimits)
    ));
    let mut limits = fixture.limits();
    limits.tar_bytes = usize::MAX;
    assert!(matches!(
        fixture.run(limits).await,
        Err(LayerContentError::InvalidLimits)
    ));
}

#[tokio::test]
async fn malformed_duplicate_or_noncanonical_options_do_not_enter_the_cipher() {
    for case in ["unknown", "duplicate", "key", "nonce", "digest", "padbits"] {
        let mut fixture = Fixture::new(valid_tar(), false);
        match case {
            "unknown" => fixture.change_private("extra", true.into()),
            "duplicate" => {
                let text = String::from_utf8(fixture.private).unwrap();
                fixture.private = text
                    .replacen("\"digest\":", "\"digest\":\"bad\",\"digest\":", 1)
                    .into_bytes();
            }
            "key" => fixture.change_private("symkey", STANDARD.encode([0; 31]).into()),
            "nonce" => fixture.change_private("cipheroptions", serde_json::json!({})),
            "digest" => fixture.change_private("digest", "sha512:unsupported".into()),
            "padbits" => fixture.change_private("symkey", "YR==".into()),
            _ => unreachable!(),
        }
        assert!(
            matches!(
                fixture.run(fixture.limits()).await,
                Err(LayerContentError::InvalidOptions)
            ),
            "{case}"
        );
    }
}

struct ProbeReader {
    bytes: &'static [u8],
    failed: bool,
    error_at_end: bool,
}
impl AsyncRead for ProbeReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        assert!(
            buf.remaining() > 0,
            "an empty read must not stand in for EOF"
        );
        assert!(!self.failed, "the failed reader must not be retried");
        let count = self.bytes.len().min(buf.remaining());
        buf.put_slice(&self.bytes[..count]);
        self.bytes = &self.bytes[count..];
        if count == 0 && self.error_at_end {
            self.failed = true;
            return Poll::Ready(Err(std::io::Error::other("controlled terminal failure")));
        }
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn exact_cap_probes_real_eof_and_a_terminal_reader_error_is_never_retried() {
    let reader = ProbeReader {
        bytes: b"abc",
        failed: false,
        error_at_end: false,
    };
    assert_eq!(
        drain_bounded(reader, 3, LayerContentError::DecryptionFailed)
            .await
            .unwrap()
            .as_slice(),
        b"abc"
    );
    let reader = ProbeReader {
        bytes: b"abc",
        failed: false,
        error_at_end: true,
    };
    assert!(matches!(
        drain_bounded(reader, 3, LayerContentError::DecryptionFailed).await,
        Err(LayerContentError::DecryptionFailed)
    ));
}

#[tokio::test]
async fn always_ready_actual_cipher_yields_and_can_be_dropped_before_content_is_published() {
    let payload = vec![b'x'; YIELD_BYTES + READ_CHUNK];
    let fixture = Fixture::new(archive(&[("app", &payload, b'0', 0o644)]), false);
    let mut limits = fixture.limits();
    limits.file_bytes = payload.len();
    let mut future = Box::pin(check_layer_content(
        fixture.expected(),
        &fixture.ciphertext,
        Zeroizing::new(fixture.private.clone()),
        limits,
    ));
    let mut context = Context::from_waker(std::task::Waker::noop());
    // The input slice is always ready. Pending therefore demonstrates an owned
    // cooperative boundary, before HMAC completion and before any sealed result.
    assert!(std::future::Future::poll(future.as_mut(), &mut context).is_pending());
    drop(future);
    // This primitive owns no admission state; a separate fresh invocation checks
    // that the cancelled fixture itself was valid, without minting a permission.
    assert!(fixture.run(limits).await.is_ok());
}
