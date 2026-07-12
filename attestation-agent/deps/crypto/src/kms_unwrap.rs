//! Helpers for KMS-asymmetric unwrap.
//!
//! The payload format is `<provider>:<base64-wrapped-data>:<base64-kms-ciphertext>`,
//! where provider is one of `aws`, `azure`, or `gcp`.

use anyhow::{anyhow, bail, Result};
use base64::Engine;

/// Split a KMS-asymmetric payload into `(provider, wrapped_data, kms_ciphertext)`.
pub fn parse_kms_ciphertext(wrapped_data: &[u8]) -> Result<(String, Vec<u8>, Vec<u8>)> {
    let text =
        std::str::from_utf8(wrapped_data).map_err(|_| anyhow!("invalid wrapped data format"))?;

    let parts: Vec<&str> = text.split(':').collect();
    if parts.len() != 3 {
        bail!("invalid wrapped data format, expected 'provider:wrapped_data:kms_ciphertext'");
    }

    let provider = parts[0].to_string();
    if provider.is_empty() {
        bail!("provider must not be empty");
    }

    let wrapped = base64::engine::general_purpose::STANDARD
        .decode(parts[1])
        .map_err(|e| anyhow!("failed to decode wrapped_data: {e:?}"))?;
    let ciphertext = base64::engine::general_purpose::STANDARD
        .decode(parts[2])
        .map_err(|e| anyhow!("failed to decode kms_ciphertext: {e:?}"))?;

    Ok((provider, wrapped, ciphertext))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_payload() {
        let wrapped = b"wrapped";
        let ciphertext = b"ciphertext";
        let payload = format!(
            "aws:{}:{}",
            base64::engine::general_purpose::STANDARD.encode(wrapped),
            base64::engine::general_purpose::STANDARD.encode(ciphertext)
        );

        let (provider, got_wrapped, got_ciphertext) =
            parse_kms_ciphertext(payload.as_bytes()).unwrap();
        assert_eq!(provider, "aws");
        assert_eq!(got_wrapped, wrapped);
        assert_eq!(got_ciphertext, ciphertext);
    }

    #[test]
    fn reject_missing_separator() {
        let payload = base64::engine::general_purpose::STANDARD.encode(b"onlyonepart");
        assert!(parse_kms_ciphertext(payload.as_bytes()).is_err());
    }

    #[test]
    fn reject_invalid_base64() {
        let payload = "aws:not-b64:!@#$";
        assert!(parse_kms_ciphertext(payload.as_bytes()).is_err());
    }
}
