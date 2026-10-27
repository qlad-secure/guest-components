//! Helpers for KMS-direct unwrap.
//!
//! The payload format is `<provider>:<base64-kms-ciphertext>`,
//! where provider is one of `aws`, `azure`, or `gcp`. The KMS ciphertext
//! decrypts directly to the layer key options.

use anyhow::{Result, anyhow, bail};
use base64::Engine;

/// Split a KMS payload into `(provider, kms_ciphertext)`.
pub fn parse_kms_ciphertext(wrapped_data: &[u8]) -> Result<(String, Vec<u8>)> {
    let text =
        std::str::from_utf8(wrapped_data).map_err(|_| anyhow!("invalid wrapped data format"))?;

    let parts: Vec<&str> = text.split(':').collect();
    if parts.len() != 2 {
        bail!("invalid wrapped data format, expected 'provider:kms_ciphertext'");
    }

    let provider = parts[0].to_string();
    if provider.is_empty() {
        bail!("provider must not be empty");
    }

    let ciphertext = base64::engine::general_purpose::STANDARD
        .decode(parts[1])
        .map_err(|e| anyhow!("failed to decode kms_ciphertext: {e:?}"))?;

    Ok((provider, ciphertext))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_payload() {
        let ciphertext = b"ciphertext";
        let payload = format!(
            "aws:{}",
            base64::engine::general_purpose::STANDARD.encode(ciphertext)
        );

        let (provider, got_ciphertext) = parse_kms_ciphertext(payload.as_bytes()).unwrap();
        assert_eq!(provider, "aws");
        assert_eq!(got_ciphertext, ciphertext);
    }

    #[test]
    fn reject_missing_separator() {
        let payload = base64::engine::general_purpose::STANDARD.encode(b"onlyonepart");
        assert!(parse_kms_ciphertext(payload.as_bytes()).is_err());
    }

    #[test]
    fn reject_invalid_base64() {
        let payload = "aws:not-b64!@#$";
        assert!(parse_kms_ciphertext(payload.as_bytes()).is_err());
    }
}
