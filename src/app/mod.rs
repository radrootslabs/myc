pub mod runtime;

use crate::config::MycConfig;
use crate::error::MycError;

pub use runtime::{MycRuntime, MycRuntimePaths, MycStartupSnapshot};

#[derive(Debug, Clone)]
pub struct MycApp {
    runtime: MycRuntime,
}

impl MycApp {
    pub fn bootstrap(config: MycConfig) -> Result<Self, MycError> {
        Ok(Self {
            runtime: MycRuntime::bootstrap(config)?,
        })
    }

    pub fn runtime(&self) -> &MycRuntime {
        &self.runtime
    }

    pub fn snapshot(&self) -> MycStartupSnapshot {
        self.runtime.snapshot()
    }

    pub fn run(self) -> Result<(), MycError> {
        self.runtime.run()
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::config::MycConfig;

    use super::MycApp;

    #[test]
    fn app_bootstrap_preserves_runtime_snapshot() {
        let temp = tempfile::tempdir().expect("tempdir");
        let mut config = MycConfig::default();
        config.paths.state_dir = PathBuf::from(temp.path()).join("state");

        let app = MycApp::bootstrap(config).expect("bootstrap");
        let snapshot = app.snapshot();

        assert!(snapshot.state_dir.ends_with("state"));
        assert!(snapshot.audit_dir.ends_with("audit"));
        assert!(snapshot.signer_state_path.ends_with("signer-state.json"));
    }
}
