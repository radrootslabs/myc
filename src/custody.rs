use std::path::PathBuf;
use std::sync::Arc;

use radroots_identity::{RadrootsIdentity, RadrootsIdentityId};
use radroots_nostr_accounts::prelude::{
    RadrootsNostrSecretVault, RadrootsNostrSecretVaultOsKeyring,
};
use serde::Serialize;

use crate::config::{MycIdentityBackend, MycIdentitySourceSpec};
use crate::error::MycError;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MycIdentityStatusOutput {
    pub backend: MycIdentityBackend,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keyring_account_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keyring_service_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_path: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inherited_from: Option<String>,
    pub resolved: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Clone)]
pub struct MycIdentityProvider {
    role: String,
    source: MycIdentitySourceSpec,
    backend: MycIdentityProviderBackend,
}

#[derive(Clone)]
enum MycIdentityProviderBackend {
    Filesystem {
        path: PathBuf,
    },
    OsKeyring {
        account_id: RadrootsIdentityId,
        service_name: String,
        profile_path: Option<PathBuf>,
        vault: Arc<dyn RadrootsNostrSecretVault>,
    },
}

impl MycIdentityProvider {
    pub fn from_source(
        role: impl Into<String>,
        source: MycIdentitySourceSpec,
    ) -> Result<Self, MycError> {
        let role = role.into();
        let backend = match source.backend {
            MycIdentityBackend::Filesystem => {
                let path = source.path.clone().ok_or_else(|| {
                    MycError::InvalidConfig(format!(
                        "{role} identity filesystem backend requires a path"
                    ))
                })?;
                MycIdentityProviderBackend::Filesystem { path }
            }
            MycIdentityBackend::OsKeyring => {
                let account_id = RadrootsIdentityId::parse(
                    source.keyring_account_id.as_deref().ok_or_else(|| {
                        MycError::InvalidConfig(format!(
                            "{role} identity os_keyring backend requires keyring_account_id"
                        ))
                    })?,
                )
                .map_err(|_| {
                    MycError::InvalidConfig(format!(
                        "{role} identity os_keyring backend requires a valid keyring_account_id"
                    ))
                })?;
                let service_name = source.keyring_service_name.clone().ok_or_else(|| {
                    MycError::InvalidConfig(format!(
                        "{role} identity os_keyring backend requires keyring_service_name"
                    ))
                })?;
                Self::vault_provider(role.as_str(), &source, account_id, service_name)?
            }
        };

        Ok(Self {
            role,
            source,
            backend,
        })
    }

    pub fn load_identity(&self) -> Result<RadrootsIdentity, MycError> {
        match &self.backend {
            MycIdentityProviderBackend::Filesystem { path } => {
                RadrootsIdentity::load_from_path_auto(path).map_err(Into::into)
            }
            MycIdentityProviderBackend::OsKeyring {
                account_id,
                service_name,
                profile_path,
                vault,
            } => {
                let secret_key_hex = vault
                    .load_secret_hex(account_id)
                    .map_err(|source| MycError::CustodyVault {
                        role: self.role.clone(),
                        source,
                    })?
                    .ok_or_else(|| MycError::CustodySecretNotFound {
                        role: self.role.clone(),
                        service_name: service_name.clone(),
                        account_id: account_id.to_string(),
                    })?;
                let mut identity = RadrootsIdentity::from_secret_key_str(secret_key_hex.as_str())?;
                if identity.id() != *account_id {
                    return Err(MycError::CustodySecretIdentityMismatch {
                        role: self.role.clone(),
                        service_name: service_name.clone(),
                        account_id: account_id.to_string(),
                        resolved_identity_id: identity.id().to_string(),
                    });
                }
                if let Some(profile_path) = profile_path {
                    let profile_identity = RadrootsIdentity::load_from_path_auto(profile_path)?;
                    if profile_identity.id() != *account_id {
                        return Err(MycError::CustodyProfileIdentityMismatch {
                            role: self.role.clone(),
                            path: profile_path.clone(),
                            account_id: account_id.to_string(),
                            profile_identity_id: profile_identity.id().to_string(),
                        });
                    }
                    if let Some(profile) = profile_identity.profile().cloned() {
                        identity.set_profile(profile);
                    }
                }
                Ok(identity)
            }
        }
    }

    pub fn resolved_status(&self, identity: &RadrootsIdentity) -> MycIdentityStatusOutput {
        self.status_with_result(Ok(identity))
    }

    pub fn probe_status(&self) -> MycIdentityStatusOutput {
        self.status_with_result(self.load_identity().as_ref())
    }

    pub fn source(&self) -> &MycIdentitySourceSpec {
        &self.source
    }

    fn status_with_result(
        &self,
        result: Result<&RadrootsIdentity, &MycError>,
    ) -> MycIdentityStatusOutput {
        match result {
            Ok(identity) => MycIdentityStatusOutput {
                backend: self.source.backend,
                path: self.source.path.clone(),
                keyring_account_id: self.source.keyring_account_id.clone(),
                keyring_service_name: self.source.keyring_service_name.clone(),
                profile_path: self.source.profile_path.clone(),
                inherited_from: None,
                resolved: true,
                identity_id: Some(identity.id().to_string()),
                public_key_hex: Some(identity.public_key_hex()),
                error: None,
            },
            Err(error) => MycIdentityStatusOutput {
                backend: self.source.backend,
                path: self.source.path.clone(),
                keyring_account_id: self.source.keyring_account_id.clone(),
                keyring_service_name: self.source.keyring_service_name.clone(),
                profile_path: self.source.profile_path.clone(),
                inherited_from: None,
                resolved: false,
                identity_id: None,
                public_key_hex: None,
                error: Some(error.to_string()),
            },
        }
    }

    fn vault_provider(
        role: &str,
        source: &MycIdentitySourceSpec,
        account_id: RadrootsIdentityId,
        service_name: String,
    ) -> Result<MycIdentityProviderBackend, MycError> {
        if service_name.trim().is_empty() {
            return Err(MycError::InvalidConfig(format!(
                "{role} identity os_keyring backend requires a non-empty keyring_service_name"
            )));
        }
        Ok(MycIdentityProviderBackend::OsKeyring {
            account_id,
            service_name: service_name.clone(),
            profile_path: source.profile_path.clone(),
            vault: Arc::new(RadrootsNostrSecretVaultOsKeyring::new(service_name)),
        })
    }
}

impl MycIdentityStatusOutput {
    pub fn with_inherited_from(mut self, inherited_from: impl Into<String>) -> Self {
        self.inherited_from = Some(inherited_from.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use radroots_identity::RadrootsIdentity;
    use radroots_nostr_accounts::prelude::RadrootsNostrSecretVaultMemory;

    use super::*;

    fn write_identity(path: &Path, secret_key: &str) {
        RadrootsIdentity::from_secret_key_str(secret_key)
            .expect("identity")
            .save_json(path)
            .expect("save identity");
    }

    fn fixture_source(path: &Path) -> MycIdentitySourceSpec {
        MycIdentitySourceSpec {
            backend: MycIdentityBackend::Filesystem,
            path: Some(path.to_path_buf()),
            keyring_account_id: None,
            keyring_service_name: None,
            profile_path: None,
        }
    }

    #[test]
    fn filesystem_provider_loads_identity() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("signer.json");
        write_identity(
            &path,
            "1111111111111111111111111111111111111111111111111111111111111111",
        );

        let provider =
            MycIdentityProvider::from_source("signer", fixture_source(&path)).expect("provider");
        let identity = provider.load_identity().expect("identity");

        assert_eq!(
            identity.public_key_hex(),
            "4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa"
        );
    }

    #[test]
    fn vault_provider_loads_identity_and_merges_profile() {
        let temp = tempfile::tempdir().expect("tempdir");
        let profile_path = temp.path().join("profile.json");
        let identity = RadrootsIdentity::from_secret_key_str(
            "1111111111111111111111111111111111111111111111111111111111111111",
        )
        .expect("identity");
        identity.save_json(&profile_path).expect("save profile");

        let account_id = identity.id();
        let vault = Arc::new(RadrootsNostrSecretVaultMemory::new());
        vault
            .store_secret_hex(&account_id, identity.secret_key_hex().as_str())
            .expect("store");

        let provider = MycIdentityProvider {
            role: "signer".to_owned(),
            source: MycIdentitySourceSpec {
                backend: MycIdentityBackend::OsKeyring,
                path: None,
                keyring_account_id: Some(account_id.to_string()),
                keyring_service_name: Some("org.radroots.test".to_owned()),
                profile_path: Some(profile_path.clone()),
            },
            backend: MycIdentityProviderBackend::OsKeyring {
                account_id: account_id.clone(),
                service_name: "org.radroots.test".to_owned(),
                profile_path: Some(profile_path),
                vault,
            },
        };

        let loaded = provider.load_identity().expect("loaded");
        assert_eq!(loaded.id(), account_id);
        assert!(provider.probe_status().resolved);
    }

    #[test]
    fn vault_provider_reports_missing_secret() {
        let account_id = RadrootsIdentity::from_secret_key_str(
            "3333333333333333333333333333333333333333333333333333333333333333",
        )
        .expect("identity")
        .id();
        let provider = MycIdentityProvider {
            role: "user".to_owned(),
            source: MycIdentitySourceSpec {
                backend: MycIdentityBackend::OsKeyring,
                path: None,
                keyring_account_id: Some(account_id.to_string()),
                keyring_service_name: Some("org.radroots.test".to_owned()),
                profile_path: None,
            },
            backend: MycIdentityProviderBackend::OsKeyring {
                account_id: account_id.clone(),
                service_name: "org.radroots.test".to_owned(),
                profile_path: None,
                vault: Arc::new(RadrootsNostrSecretVaultMemory::new()),
            },
        };

        let err = provider.load_identity().expect_err("missing secret");
        assert!(matches!(err, MycError::CustodySecretNotFound { .. }));
        assert!(!provider.probe_status().resolved);
    }
}
