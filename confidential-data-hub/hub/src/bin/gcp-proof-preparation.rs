// SPDX-License-Identifier: Apache-2.0

fn main() -> std::process::ExitCode {
    // Failures expose a fixed code only, never operator input or secret material.
    std::panic::set_hook(Box::new(|_| {}));
    if std::env::args_os().len() != 1 {
        return std::process::ExitCode::FAILURE;
    }
    match std::panic::catch_unwind(confidential_data_hub::gcp_production::run) {
        Ok(Ok(())) => std::process::ExitCode::SUCCESS,
        _ => std::process::ExitCode::FAILURE,
    }
}
