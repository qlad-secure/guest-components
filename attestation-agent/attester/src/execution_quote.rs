// SPDX-License-Identifier: Apache-2.0

//! Fixed, bounded TDX collection for an execution-record exporter.
//!
//! The report data is public binding material, not a capture capability. The
//! caller must retain the protected record and restrict access to quote oracles
//! in the measured guest configuration.

use crate::{Attester, InitDataResult, tdx::TdxAttester, tsm_report::*};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::Serialize;
use thiserror::Error;

pub const MAX_EXECUTION_QUOTE_BYTES: usize = 512 * 1024;
pub const MAX_EXECUTION_EVIDENCE_BYTES: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ExecutionQuoteError {
    #[error("invalid execution quote binding")]
    InvalidBinding,
    #[error("TDX init data does not match")]
    InitDataMismatch,
    #[error("TDX execution quote is unavailable")]
    Unavailable,
    #[error("execution quote exceeds its bound")]
    Bounds,
    #[error("execution quote encoding failed")]
    Encoding,
}

/// Collect a quote from the fixed TDX TSM provider without platform detection
/// or sample fallback. Call on a dedicated, bounded worker, outside reaper and
/// task-registry locks: TSM and device operations are blocking kernel I/O.
pub async fn collect_tdx_execution_quote(
    expected_init: [u8; 48],
    report_data: [u8; 64],
) -> Result<Vec<u8>, ExecutionQuoteError> {
    validate_binding(&expected_init, &report_data)?;
    let provider =
        TsmReportPath::new(TsmReportProvider::Tdx).map_err(|_| ExecutionQuoteError::Unavailable)?;
    let attester = TdxAttester::new();
    match attester.bind_init_data(&expected_init).await {
        Ok(InitDataResult::Ok) => {}
        _ => return Err(ExecutionQuoteError::InitDataMismatch),
    }
    let quote = provider
        .execution_quote_bounded(&report_data, MAX_EXECUTION_QUOTE_BYTES)
        .map_err(|_| ExecutionQuoteError::Unavailable)?;
    encode_quote(&quote)
}

fn validate_binding(
    expected_init: &[u8; 48],
    report_data: &[u8; 64],
) -> Result<(), ExecutionQuoteError> {
    if expected_init.iter().all(|byte| *byte == 0)
        || report_data[..48].iter().all(|byte| *byte == 0)
        || report_data[48..].iter().any(|byte| *byte != 0)
    {
        return Err(ExecutionQuoteError::InvalidBinding);
    }
    Ok(())
}

fn encode_quote(quote: &[u8]) -> Result<Vec<u8>, ExecutionQuoteError> {
    if quote.is_empty() || quote.len() > MAX_EXECUTION_QUOTE_BYTES {
        return Err(ExecutionQuoteError::Bounds);
    }
    #[derive(Serialize)]
    struct Evidence {
        cc_eventlog: Option<String>,
        quote: String,
    }
    // This profile verifies raw quoted measurements against trusted pins; it
    // does not claim event-log replay. No unbounded CCEL read is needed.
    let evidence = serde_json::to_vec(&Evidence {
        cc_eventlog: None,
        quote: STANDARD.encode(quote),
    })
    .map_err(|_| ExecutionQuoteError::Encoding)?;
    if evidence.len() > MAX_EXECUTION_EVIDENCE_BYTES {
        return Err(ExecutionQuoteError::Bounds);
    }
    Ok(evidence)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requires_full_profile_binding_before_tdx_access() {
        let mut report = [0u8; 64];
        report[..48].fill(7);
        assert_eq!(validate_binding(&[8; 48], &report), Ok(()));
        assert_eq!(
            validate_binding(&[0; 48], &report),
            Err(ExecutionQuoteError::InvalidBinding)
        );
        assert_eq!(
            validate_binding(&[8; 48], &[0; 64]),
            Err(ExecutionQuoteError::InvalidBinding)
        );
        report[63] = 1;
        assert_eq!(
            validate_binding(&[8; 48], &report),
            Err(ExecutionQuoteError::InvalidBinding)
        );
    }

    #[test]
    fn quote_encoding_is_bounded_and_explicitly_omits_eventlog() {
        assert_eq!(encode_quote(&[]), Err(ExecutionQuoteError::Bounds));
        assert_eq!(
            encode_quote(&vec![0; MAX_EXECUTION_QUOTE_BYTES + 1]),
            Err(ExecutionQuoteError::Bounds)
        );
        let encoded = encode_quote(&[1, 2, 3]).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        assert!(value["cc_eventlog"].is_null());
        assert_eq!(value["quote"], "AQID");
        assert!(
            encode_quote(&vec![7; MAX_EXECUTION_QUOTE_BYTES])
                .unwrap()
                .len()
                <= MAX_EXECUTION_EVIDENCE_BYTES
        );
    }
}
