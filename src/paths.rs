use core::fmt;
use std::path::{Path, PathBuf};

use crate::{
    config::{MycIdentityBackend, MycIdentitySourceSpec},
    runtime_context::MycRuntimeContext,
};

const DEFAULT_SIGNER_IDENTITY_FILE_NAME: &str = "signer-identity.json";
const DEFAULT_USER_IDENTITY_FILE_NAME: &str = "user-identity.json";

/// Transitional prototype runtime inputs derived from a sealed Myc context.
///
/// The fields are crate-private so external callers cannot replace canonical
/// service-instance paths independently of the typed runtime context. Later
/// ordered state/provider checkpoints remove the remaining prototype provider
/// fields rather than promoting them into the hardened configuration contract.
///
/// ```compile_fail
/// use myc::MycPathsConfig;
///
/// let _ = MycPathsConfig {
///     runtime_context: todo!(),
///     signer_identity_backend: todo!(),
///     signer_identity_path: todo!(),
///     signer_identity_keyring_account_id: None,
///     signer_identity_keyring_service_name: String::new(),
///     signer_identity_profile_path: None,
///     user_identity_backend: todo!(),
///     user_identity_path: todo!(),
///     user_identity_keyring_account_id: None,
///     user_identity_keyring_service_name: String::new(),
///     user_identity_profile_path: None,
/// };
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct MycPathsConfig {
    pub(crate) runtime_context: MycRuntimeContext,
    pub(crate) signer_identity_backend: MycIdentityBackend,
    pub(crate) signer_identity_path: PathBuf,
    pub(crate) signer_identity_keyring_account_id: Option<String>,
    pub(crate) signer_identity_keyring_service_name: String,
    pub(crate) signer_identity_profile_path: Option<PathBuf>,
    pub(crate) user_identity_backend: MycIdentityBackend,
    pub(crate) user_identity_path: PathBuf,
    pub(crate) user_identity_keyring_account_id: Option<String>,
    pub(crate) user_identity_keyring_service_name: String,
    pub(crate) user_identity_profile_path: Option<PathBuf>,
}

impl fmt::Debug for MycPathsConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MycPathsConfig([redacted])")
    }
}

impl MycPathsConfig {
    pub(crate) fn from_runtime_context(runtime_context: MycRuntimeContext) -> Self {
        let secrets = runtime_context.context().paths().secrets();
        let signer_identity_path = secrets.join(DEFAULT_SIGNER_IDENTITY_FILE_NAME);
        let user_identity_path = secrets.join(DEFAULT_USER_IDENTITY_FILE_NAME);
        Self {
            runtime_context,
            signer_identity_backend: MycIdentityBackend::EncryptedFile,
            signer_identity_path,
            signer_identity_keyring_account_id: None,
            signer_identity_keyring_service_name: "org.radroots.myc.signer".to_owned(),
            signer_identity_profile_path: None,
            user_identity_backend: MycIdentityBackend::EncryptedFile,
            user_identity_path,
            user_identity_keyring_account_id: None,
            user_identity_keyring_service_name: "org.radroots.myc.user".to_owned(),
            user_identity_profile_path: None,
        }
    }

    #[must_use]
    pub fn runtime_context(&self) -> &MycRuntimeContext {
        &self.runtime_context
    }

    #[must_use]
    pub fn state_dir(&self) -> &Path {
        self.runtime_context.context().paths().state()
    }

    #[must_use]
    pub fn run_dir(&self) -> &Path {
        self.runtime_context.context().paths().run()
    }

    #[must_use]
    pub fn logs_dir(&self) -> &Path {
        self.runtime_context.context().paths().logs()
    }

    #[must_use]
    pub fn signer_identity_path(&self) -> &Path {
        &self.signer_identity_path
    }

    #[must_use]
    pub fn user_identity_path(&self) -> &Path {
        &self.user_identity_path
    }

    pub fn signer_identity_source(&self) -> MycIdentitySourceSpec {
        MycIdentitySourceSpec {
            backend: self.signer_identity_backend,
            path: match self.signer_identity_backend {
                MycIdentityBackend::EncryptedFile
                | MycIdentityBackend::PlaintextFile
                | MycIdentityBackend::ManagedAccount
                | MycIdentityBackend::ExternalCommand => Some(self.signer_identity_path.clone()),
                MycIdentityBackend::HostVault => None,
            },
            keyring_account_id: match self.signer_identity_backend {
                MycIdentityBackend::EncryptedFile
                | MycIdentityBackend::PlaintextFile
                | MycIdentityBackend::ManagedAccount
                | MycIdentityBackend::ExternalCommand => None,
                MycIdentityBackend::HostVault => self.signer_identity_keyring_account_id.clone(),
            },
            keyring_service_name: match self.signer_identity_backend {
                MycIdentityBackend::EncryptedFile
                | MycIdentityBackend::PlaintextFile
                | MycIdentityBackend::ExternalCommand => None,
                MycIdentityBackend::HostVault | MycIdentityBackend::ManagedAccount => {
                    Some(self.signer_identity_keyring_service_name.clone())
                }
            },
            profile_path: match self.signer_identity_backend {
                MycIdentityBackend::EncryptedFile
                | MycIdentityBackend::PlaintextFile
                | MycIdentityBackend::ManagedAccount
                | MycIdentityBackend::ExternalCommand => None,
                MycIdentityBackend::HostVault => self.signer_identity_profile_path.clone(),
            },
        }
    }

    pub fn user_identity_source(&self) -> MycIdentitySourceSpec {
        MycIdentitySourceSpec {
            backend: self.user_identity_backend,
            path: match self.user_identity_backend {
                MycIdentityBackend::EncryptedFile
                | MycIdentityBackend::PlaintextFile
                | MycIdentityBackend::ManagedAccount
                | MycIdentityBackend::ExternalCommand => Some(self.user_identity_path.clone()),
                MycIdentityBackend::HostVault => None,
            },
            keyring_account_id: match self.user_identity_backend {
                MycIdentityBackend::EncryptedFile
                | MycIdentityBackend::PlaintextFile
                | MycIdentityBackend::ManagedAccount
                | MycIdentityBackend::ExternalCommand => None,
                MycIdentityBackend::HostVault => self.user_identity_keyring_account_id.clone(),
            },
            keyring_service_name: match self.user_identity_backend {
                MycIdentityBackend::EncryptedFile
                | MycIdentityBackend::PlaintextFile
                | MycIdentityBackend::ExternalCommand => None,
                MycIdentityBackend::HostVault | MycIdentityBackend::ManagedAccount => {
                    Some(self.user_identity_keyring_service_name.clone())
                }
            },
            profile_path: match self.user_identity_backend {
                MycIdentityBackend::EncryptedFile
                | MycIdentityBackend::PlaintextFile
                | MycIdentityBackend::ManagedAccount
                | MycIdentityBackend::ExternalCommand => None,
                MycIdentityBackend::HostVault => self.user_identity_profile_path.clone(),
            },
        }
    }
}
