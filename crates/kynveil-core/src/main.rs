//! Kynveil security-core process.

use std::process::ExitCode;

#[allow(
    dead_code,
    reason = "Stage 3 storage lifecycle wiring follows the identity foundation."
)]
mod identity;
mod ipc;
#[allow(
    dead_code,
    reason = "Stage 3 profile lifecycle wiring follows the profile-path security foundation."
)]
mod profile_path;
#[allow(
    dead_code,
    reason = "Stage 3 storage lifecycle wiring follows the identity/profile foundation"
)]
mod storage;

fn run() -> ExitCode {
    if profile_path::ProfilePaths::validate_process_arguments().is_err() {
        return ExitCode::FAILURE;
    }
    exit_code(ipc::run_stdio())
}

fn exit_code(result: Result<(), &'static str>) -> ExitCode {
    if result.is_ok() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn main() -> ExitCode {
    run()
}

#[cfg(test)]
mod tests {
    use std::process::ExitCode;

    use super::exit_code;

    #[test]
    fn maps_service_result_to_exit_code() {
        assert_eq!(exit_code(Ok(())), ExitCode::SUCCESS);
        assert_eq!(exit_code(Err("synthetic test failure")), ExitCode::FAILURE);
    }
}
