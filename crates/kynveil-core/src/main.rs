//! Kynveil security-core process.

use std::process::ExitCode;

#[allow(
    dead_code,
    reason = "Stage 3 storage lifecycle wiring follows the identity foundation."
)]
mod identity;
mod ipc;
mod keyring;
mod profile;
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
    let Ok(paths) = profile_path::ProfilePaths::from_sidecar_arguments(std::env::args_os().skip(1))
    else {
        return ExitCode::FAILURE;
    };
    let Some(paths) = paths else {
        return ExitCode::FAILURE;
    };
    let created_at = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(duration) => duration.as_secs(),
        Err(_) => return ExitCode::FAILURE,
    };
    let profile =
        profile::ProfileController::new(paths, keyring::NativeProfileMasterSecretStore, created_at);
    if ipc::run_stdio(profile).is_ok() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

#[cfg(test)]
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
