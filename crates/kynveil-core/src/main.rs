//! Kynveil security-core process.

use std::process::ExitCode;

mod ipc;

fn run() -> ExitCode {
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
