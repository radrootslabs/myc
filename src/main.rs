#![forbid(unsafe_code)]

use std::process::ExitCode;

fn main() -> ExitCode {
    match myc::parse_myc_cli_v1_from(std::env::args_os()) {
        Ok(invocation) => {
            let _plan = myc::plan_myc_cli_v1(&invocation);
            eprintln!("myc: command execution is unavailable");
            ExitCode::FAILURE
        }
        Err(error) => {
            eprintln!("myc: {error}");
            ExitCode::from(2)
        }
    }
}
