#![forbid(unsafe_code)]

use std::process::ExitCode;

use myc::{MycLogRecord, MycProcessResult};

struct MycOsSignalSource {
    #[cfg(unix)]
    interrupt: tokio::signal::unix::Signal,
    #[cfg(unix)]
    terminate: tokio::signal::unix::Signal,
}

impl MycOsSignalSource {
    fn new() -> Option<Self> {
        #[cfg(unix)]
        {
            let interrupt =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt()).ok()?;
            let terminate =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).ok()?;
            Some(Self {
                interrupt,
                terminate,
            })
        }
        #[cfg(not(unix))]
        {
            Some(Self {})
        }
    }
}

impl myc::MycProcessSignalSource for MycOsSignalSource {
    fn next_signal(&mut self) -> myc::MycProcessSignalFuture<'_> {
        #[cfg(unix)]
        {
            Box::pin(async move {
                tokio::select! {
                    observed = self.interrupt.recv() => observed.map(|()| myc::MycProcessSignal::Interrupt),
                    observed = self.terminate.recv() => observed.map(|()| myc::MycProcessSignal::Terminate),
                }
            })
        }
        #[cfg(not(unix))]
        {
            Box::pin(async move {
                tokio::signal::ctrl_c()
                    .await
                    .ok()
                    .map(|()| myc::MycProcessSignal::Interrupt)
            })
        }
    }
}

fn main() -> ExitCode {
    match myc::parse_myc_cli_v1_from(std::env::args_os()) {
        Ok(invocation) => {
            let result =
                myc::execute_myc_cli_v1_with_signal_source(invocation, MycOsSignalSource::new);
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
