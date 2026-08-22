#![forbid(unsafe_code)]

use std::process::ExitCode;

use myc::{MycLogRecord, MycProcessResult};

fn main() -> ExitCode {
    match myc::parse_myc_cli_v1_from(std::env::args_os()) {
        Ok(invocation) => {
            let _plan = myc::plan_myc_cli_v1(&invocation);
            let result = MycProcessResult::ServiceOrDependencyUnavailable;
            eprintln!("{}", MycLogRecord::process_result(result));
            result.exit_code()
        }
        Err(_) => {
            let result = MycProcessResult::InputOrConfiguration;
            eprintln!("{}", MycLogRecord::process_result(result));
            result.exit_code()
        }
    }
}
