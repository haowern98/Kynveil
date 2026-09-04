//! Kynveil blind-relay process.

use std::process::ExitCode;

fn run() -> ExitCode {
    ExitCode::SUCCESS
}

fn main() -> ExitCode {
    run()
}

#[cfg(test)]
mod tests {
    use std::process::ExitCode;

    use super::run;

    #[test]
    fn exits_successfully() {
        assert_eq!(run(), ExitCode::SUCCESS);
    }
}
