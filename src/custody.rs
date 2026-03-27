use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use nostr::nips::nip44::Version;
use nostr::nips::{nip04, nip44};
use radroots_identity::{RadrootsIdentity, RadrootsIdentityId};
use radroots_nostr::prelude::{
    RadrootsNostrClient, RadrootsNostrEvent, RadrootsNostrEventBuilder, RadrootsNostrPublicKey,
};
use radroots_nostr_accounts::prelude::{
    RadrootsNostrAccountRecord, RadrootsNostrAccountsManager, RadrootsNostrFileAccountStore,
    RadrootsNostrSecretVault, RadrootsNostrSecretVaultOsKeyring,
    RadrootsNostrSelectedAccountStatus,
};
use serde::Serialize;

use crate::config::{MycIdentityBackend, MycIdentitySourceSpec};
use crate::error::MycError;

#[derive(Clone)]
pub struct MycActiveIdentity {
    identity: Arc<RadrootsIdentity>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MycManagedAccountSelectionState {
    NotConfigured,
    PublicOnly,
    Ready,
}

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
    pub selected_account_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected_account_label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected_account_state: Option<MycManagedAccountSelectionState>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MycManagedAccountsOutput {
    pub role: String,
    pub backend: MycIdentityBackend,
    pub account_store_path: PathBuf,
    pub keyring_service_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected_account_id: Option<String>,
    pub selected_account_state: MycManagedAccountSelectionState,
    pub accounts: Vec<RadrootsNostrAccountRecord>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MycManagedAccountMutationOutput {
    pub role: String,
    pub action: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_id: Option<String>,
    pub state: MycManagedAccountsOutput,
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
    ManagedAccount {
        account_store_path: PathBuf,
        service_name: String,
        manager: RadrootsNostrAccountsManager,
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
            MycIdentityBackend::ManagedAccount => {
                let account_store_path = source.path.clone().ok_or_else(|| {
                    MycError::InvalidConfig(format!(
                        "{role} identity managed_account backend requires a path"
                    ))
                })?;
                let service_name = source.keyring_service_name.clone().ok_or_else(|| {
                    MycError::InvalidConfig(format!(
                        "{role} identity managed_account backend requires keyring_service_name"
                    ))
                })?;
                Self::managed_account_provider(role.as_str(), account_store_path, service_name)?
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
            MycIdentityProviderBackend::ManagedAccount {
                account_store_path,
                service_name,
                manager,
            } => match manager.selected_account_status().map_err(|source| {
                MycError::CustodyManager {
                    role: self.role.clone(),
                    source,
                }
            })? {
                RadrootsNostrSelectedAccountStatus::NotConfigured => {
                    Err(MycError::CustodyManagedAccountNotConfigured {
                        role: self.role.clone(),
                        path: account_store_path.clone(),
                    })
                }
                RadrootsNostrSelectedAccountStatus::PublicOnly { account } => {
                    Err(MycError::CustodyManagedAccountPublicOnly {
                        role: self.role.clone(),
                        path: account_store_path.clone(),
                        service_name: service_name.clone(),
                        account_id: account.account_id.to_string(),
                    })
                }
                RadrootsNostrSelectedAccountStatus::Ready { .. } => manager
                    .selected_signing_identity()
                    .map_err(|source| MycError::CustodyManager {
                        role: self.role.clone(),
                        source,
                    })?
                    .ok_or_else(|| MycError::CustodyManagedAccountNotConfigured {
                        role: self.role.clone(),
                        path: account_store_path.clone(),
                    }),
            },
        }
    }

    pub fn load_active_identity(&self) -> Result<MycActiveIdentity, MycError> {
        self.load_identity().map(MycActiveIdentity::new)
    }

    pub fn resolved_status(&self, identity: &MycActiveIdentity) -> MycIdentityStatusOutput {
        match &self.backend {
            MycIdentityProviderBackend::ManagedAccount { .. } => self.managed_account_status(
                Ok(identity.as_identity()),
                self.selected_managed_account_record_result(),
            ),
            _ => self.status_with_result(Ok(identity.as_identity())),
        }
    }

    pub fn probe_status(&self) -> MycIdentityStatusOutput {
        match &self.backend {
            MycIdentityProviderBackend::ManagedAccount { .. } => self.managed_account_status(
                self.load_identity().as_ref(),
                self.selected_managed_account_record_result(),
            ),
            _ => self.status_with_result(self.load_identity().as_ref()),
        }
    }

    pub fn source(&self) -> &MycIdentitySourceSpec {
        &self.source
    }

    pub fn list_managed_accounts(&self) -> Result<MycManagedAccountsOutput, MycError> {
        self.managed_accounts_output()
    }

    pub fn generate_managed_account(
        &self,
        label: Option<String>,
        make_selected: bool,
    ) -> Result<MycManagedAccountMutationOutput, MycError> {
        let account_id = {
            let manager = self.managed_accounts_manager()?;
            manager
                .generate_identity(label, make_selected)
                .map_err(|source| MycError::CustodyManager {
                    role: self.role.clone(),
                    source,
                })?
        };
        Ok(MycManagedAccountMutationOutput {
            role: self.role.clone(),
            action: "generate".to_owned(),
            account_id: Some(account_id.to_string()),
            state: self.managed_accounts_output()?,
        })
    }

    pub fn import_managed_account_file(
        &self,
        path: impl AsRef<std::path::Path>,
        label: Option<String>,
        make_selected: bool,
    ) -> Result<MycManagedAccountMutationOutput, MycError> {
        let account_id = {
            let manager = self.managed_accounts_manager()?;
            manager
                .migrate_legacy_identity_file(path, label, make_selected)
                .map_err(|source| MycError::CustodyManager {
                    role: self.role.clone(),
                    source,
                })?
        };
        Ok(MycManagedAccountMutationOutput {
            role: self.role.clone(),
            action: "import_file".to_owned(),
            account_id: Some(account_id.to_string()),
            state: self.managed_accounts_output()?,
        })
    }

    pub fn select_managed_account(
        &self,
        account_id: &str,
    ) -> Result<MycManagedAccountMutationOutput, MycError> {
        let account_id = RadrootsIdentityId::parse(account_id).map_err(|_| {
            MycError::InvalidOperation(format!("invalid managed account id `{account_id}`"))
        })?;
        {
            let manager = self.managed_accounts_manager()?;
            manager
                .select_account(&account_id)
                .map_err(|source| MycError::CustodyManager {
                    role: self.role.clone(),
                    source,
                })?;
        }
        Ok(MycManagedAccountMutationOutput {
            role: self.role.clone(),
            action: "select".to_owned(),
            account_id: Some(account_id.to_string()),
            state: self.managed_accounts_output()?,
        })
    }

    pub fn remove_managed_account(
        &self,
        account_id: &str,
    ) -> Result<MycManagedAccountMutationOutput, MycError> {
        let account_id = RadrootsIdentityId::parse(account_id).map_err(|_| {
            MycError::InvalidOperation(format!("invalid managed account id `{account_id}`"))
        })?;
        {
            let manager = self.managed_accounts_manager()?;
            manager
                .remove_account(&account_id)
                .map_err(|source| MycError::CustodyManager {
                    role: self.role.clone(),
                    source,
                })?;
        }
        Ok(MycManagedAccountMutationOutput {
            role: self.role.clone(),
            action: "remove".to_owned(),
            account_id: Some(account_id.to_string()),
            state: self.managed_accounts_output()?,
        })
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
                selected_account_id: None,
                selected_account_label: None,
                selected_account_state: None,
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
                selected_account_id: None,
                selected_account_label: None,
                selected_account_state: None,
                identity_id: None,
                public_key_hex: None,
                error: Some(error.to_string()),
            },
        }
    }

    fn selected_managed_account_record_result(
        &self,
    ) -> Result<Option<RadrootsNostrAccountRecord>, MycError> {
        let manager = self.managed_accounts_manager()?;
        manager
            .selected_account()
            .map_err(|source| MycError::CustodyManager {
                role: self.role.clone(),
                source,
            })
    }

    fn managed_account_status(
        &self,
        identity_result: Result<&RadrootsIdentity, &MycError>,
        account_result: Result<Option<RadrootsNostrAccountRecord>, MycError>,
    ) -> MycIdentityStatusOutput {
        let MycIdentityProviderBackend::ManagedAccount {
            account_store_path,
            service_name,
            manager,
        } = &self.backend
        else {
            return self.status_with_result(identity_result);
        };

        let (selected_account_id, selected_account_label, identity_id, public_key_hex) =
            match account_result {
                Ok(Some(account)) => (
                    Some(account.account_id.to_string()),
                    account.label.clone(),
                    Some(account.account_id.to_string()),
                    Some(account.public_identity.public_key_hex),
                ),
                Ok(None) => (None, None, None, None),
                Err(error) => {
                    return MycIdentityStatusOutput {
                        backend: self.source.backend,
                        path: Some(account_store_path.clone()),
                        keyring_account_id: None,
                        keyring_service_name: Some(service_name.clone()),
                        profile_path: None,
                        inherited_from: None,
                        resolved: false,
                        selected_account_id: None,
                        selected_account_label: None,
                        selected_account_state: None,
                        identity_id: None,
                        public_key_hex: None,
                        error: Some(error.to_string()),
                    };
                }
            };

        let (resolved, selected_account_state, error) = match manager
            .selected_account_status()
            .map_err(|source| MycError::CustodyManager {
                role: self.role.clone(),
                source,
            }) {
            Ok(RadrootsNostrSelectedAccountStatus::NotConfigured) => (
                false,
                Some(MycManagedAccountSelectionState::NotConfigured),
                Some(
                    MycError::CustodyManagedAccountNotConfigured {
                        role: self.role.clone(),
                        path: account_store_path.clone(),
                    }
                    .to_string(),
                ),
            ),
            Ok(RadrootsNostrSelectedAccountStatus::PublicOnly { account }) => (
                false,
                Some(MycManagedAccountSelectionState::PublicOnly),
                Some(
                    MycError::CustodyManagedAccountPublicOnly {
                        role: self.role.clone(),
                        path: account_store_path.clone(),
                        service_name: service_name.clone(),
                        account_id: account.account_id.to_string(),
                    }
                    .to_string(),
                ),
            ),
            Ok(RadrootsNostrSelectedAccountStatus::Ready { .. }) => match identity_result {
                Ok(_) => (true, Some(MycManagedAccountSelectionState::Ready), None),
                Err(error) => (
                    false,
                    Some(MycManagedAccountSelectionState::Ready),
                    Some(error.to_string()),
                ),
            },
            Err(error) => (false, None, Some(error.to_string())),
        };

        MycIdentityStatusOutput {
            backend: self.source.backend,
            path: Some(account_store_path.clone()),
            keyring_account_id: None,
            keyring_service_name: Some(service_name.clone()),
            profile_path: None,
            inherited_from: None,
            resolved,
            selected_account_id,
            selected_account_label,
            selected_account_state,
            identity_id,
            public_key_hex,
            error,
        }
    }

    fn managed_accounts_output(&self) -> Result<MycManagedAccountsOutput, MycError> {
        let MycIdentityProviderBackend::ManagedAccount {
            account_store_path,
            service_name,
            manager,
        } = &self.backend
        else {
            return Err(MycError::InvalidOperation(format!(
                "{} identity backend `{}` does not support managed account lifecycle commands",
                self.role,
                self.source.backend.as_str(),
            )));
        };

        let accounts = manager
            .list_accounts()
            .map_err(|source| MycError::CustodyManager {
                role: self.role.clone(),
                source,
            })?;
        let selected_account_id = manager
            .selected_account_id()
            .map_err(|source| MycError::CustodyManager {
                role: self.role.clone(),
                source,
            })?
            .map(|value| value.to_string());
        let selected_account_state =
            match manager
                .selected_account_status()
                .map_err(|source| MycError::CustodyManager {
                    role: self.role.clone(),
                    source,
                })? {
                RadrootsNostrSelectedAccountStatus::NotConfigured => {
                    MycManagedAccountSelectionState::NotConfigured
                }
                RadrootsNostrSelectedAccountStatus::PublicOnly { .. } => {
                    MycManagedAccountSelectionState::PublicOnly
                }
                RadrootsNostrSelectedAccountStatus::Ready { .. } => {
                    MycManagedAccountSelectionState::Ready
                }
            };

        Ok(MycManagedAccountsOutput {
            role: self.role.clone(),
            backend: self.source.backend,
            account_store_path: account_store_path.clone(),
            keyring_service_name: service_name.clone(),
            selected_account_id,
            selected_account_state,
            accounts,
        })
    }

    fn managed_accounts_manager(&self) -> Result<&RadrootsNostrAccountsManager, MycError> {
        match &self.backend {
            MycIdentityProviderBackend::ManagedAccount { manager, .. } => Ok(manager),
            _ => Err(MycError::InvalidOperation(format!(
                "{} identity backend `{}` does not support managed account lifecycle commands",
                self.role,
                self.source.backend.as_str(),
            ))),
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

    fn managed_account_provider(
        role: &str,
        account_store_path: PathBuf,
        service_name: String,
    ) -> Result<MycIdentityProviderBackend, MycError> {
        if account_store_path.as_os_str().is_empty() {
            return Err(MycError::InvalidConfig(format!(
                "{role} identity managed_account backend requires a non-empty path"
            )));
        }
        if service_name.trim().is_empty() {
            return Err(MycError::InvalidConfig(format!(
                "{role} identity managed_account backend requires a non-empty keyring_service_name"
            )));
        }
        if let Some(parent) = account_store_path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent).map_err(|source| MycError::CreateDir {
                path: parent.to_path_buf(),
                source,
            })?;
        }
        let manager = RadrootsNostrAccountsManager::new(
            Arc::new(RadrootsNostrFileAccountStore::new(
                account_store_path.as_path(),
            )),
            Arc::new(RadrootsNostrSecretVaultOsKeyring::new(service_name.clone())),
        )
        .map_err(|source| MycError::CustodyManager {
            role: role.to_owned(),
            source,
        })?;
        Ok(MycIdentityProviderBackend::ManagedAccount {
            account_store_path,
            service_name,
            manager,
        })
    }
}

impl MycActiveIdentity {
    pub fn new(identity: RadrootsIdentity) -> Self {
        Self {
            identity: Arc::new(identity),
        }
    }

    pub fn id(&self) -> RadrootsIdentityId {
        self.identity.id()
    }

    pub fn public_key(&self) -> RadrootsNostrPublicKey {
        self.identity.public_key()
    }

    pub fn public_key_hex(&self) -> String {
        self.identity.public_key_hex()
    }

    pub fn secret_key_hex(&self) -> String {
        self.identity.secret_key_hex()
    }

    pub fn to_public(&self) -> radroots_identity::RadrootsIdentityPublic {
        self.identity.to_public()
    }

    pub fn nostr_client(&self) -> RadrootsNostrClient {
        RadrootsNostrClient::from_identity(self.as_identity())
    }

    pub fn nostr_client_owned(&self) -> RadrootsNostrClient {
        RadrootsNostrClient::from_identity_owned((*self.identity).clone())
    }

    pub fn sign_event_builder(
        &self,
        builder: RadrootsNostrEventBuilder,
        operation: &str,
    ) -> Result<RadrootsNostrEvent, MycError> {
        builder
            .sign_with_keys(self.identity.keys())
            .map_err(|error| {
                MycError::InvalidOperation(format!("failed to sign {operation} event: {error}"))
            })
    }

    pub fn sign_unsigned_event(
        &self,
        unsigned_event: nostr::UnsignedEvent,
        operation: &str,
    ) -> Result<nostr::Event, MycError> {
        unsigned_event
            .sign_with_keys(self.identity.keys())
            .map_err(|error| {
                MycError::InvalidOperation(format!("failed to sign {operation}: {error}"))
            })
    }

    pub fn nip04_encrypt(
        &self,
        public_key: &RadrootsNostrPublicKey,
        plaintext: impl Into<String>,
    ) -> Result<String, MycError> {
        nip04::encrypt(
            self.identity.keys().secret_key(),
            public_key,
            plaintext.into(),
        )
        .map_err(|error| MycError::Nip46Encrypt(error.to_string()))
    }

    pub fn nip04_decrypt(
        &self,
        public_key: &RadrootsNostrPublicKey,
        ciphertext: impl AsRef<str>,
    ) -> Result<String, MycError> {
        nip04::decrypt(
            self.identity.keys().secret_key(),
            public_key,
            ciphertext.as_ref(),
        )
        .map_err(|error| MycError::Nip46Decrypt(error.to_string()))
    }

    pub fn nip44_encrypt(
        &self,
        public_key: &RadrootsNostrPublicKey,
        plaintext: impl Into<String>,
    ) -> Result<String, MycError> {
        nip44::encrypt(
            self.identity.keys().secret_key(),
            public_key,
            plaintext.into(),
            Version::V2,
        )
        .map_err(|error| MycError::Nip46Encrypt(error.to_string()))
    }

    pub fn nip44_decrypt(
        &self,
        public_key: &RadrootsNostrPublicKey,
        ciphertext: impl AsRef<str>,
    ) -> Result<String, MycError> {
        nip44::decrypt(
            self.identity.keys().secret_key(),
            public_key,
            ciphertext.as_ref(),
        )
        .map_err(|error| MycError::Nip46Decrypt(error.to_string()))
    }

    pub(crate) fn as_identity(&self) -> &RadrootsIdentity {
        self.identity.as_ref()
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
    use std::path::{Path, PathBuf};

    use radroots_identity::RadrootsIdentity;
    use radroots_nostr_accounts::prelude::{
        RadrootsNostrAccountsManager, RadrootsNostrMemoryAccountStore, RadrootsNostrSecretVault,
        RadrootsNostrSecretVaultMemory,
    };

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

    fn managed_account_provider(
        role: &str,
        service_name: &str,
    ) -> (MycIdentityProvider, Arc<RadrootsNostrSecretVaultMemory>) {
        let vault = Arc::new(RadrootsNostrSecretVaultMemory::new());
        let manager = RadrootsNostrAccountsManager::new(
            Arc::new(RadrootsNostrMemoryAccountStore::new()),
            vault.clone() as Arc<dyn RadrootsNostrSecretVault>,
        )
        .expect("manager");
        (
            MycIdentityProvider {
                role: role.to_owned(),
                source: MycIdentitySourceSpec {
                    backend: MycIdentityBackend::ManagedAccount,
                    path: Some(PathBuf::from(format!("/tmp/{role}-accounts.json"))),
                    keyring_account_id: None,
                    keyring_service_name: Some(service_name.to_owned()),
                    profile_path: None,
                },
                backend: MycIdentityProviderBackend::ManagedAccount {
                    account_store_path: PathBuf::from(format!("/tmp/{role}-accounts.json")),
                    service_name: service_name.to_owned(),
                    manager,
                },
            },
            vault,
        )
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

    #[test]
    fn managed_account_provider_loads_selected_identity() {
        let (provider, _vault) = managed_account_provider("signer", "org.radroots.test.signer");
        let generated = provider
            .generate_managed_account(Some("primary".to_owned()), true)
            .expect("generate");

        let identity = provider.load_identity().expect("identity");
        let identity_id = identity.id().to_string();
        assert_eq!(
            generated.state.selected_account_id.as_deref(),
            Some(identity_id.as_str())
        );
        let status = provider.probe_status();
        assert!(status.resolved);
        assert_eq!(
            status.selected_account_state,
            Some(MycManagedAccountSelectionState::Ready)
        );
    }

    #[test]
    fn managed_account_provider_reports_not_configured() {
        let (provider, _vault) = managed_account_provider("user", "org.radroots.test.user");

        let err = provider
            .load_identity()
            .expect_err("missing selected account");
        assert!(matches!(
            err,
            MycError::CustodyManagedAccountNotConfigured { .. }
        ));
        let status = provider.probe_status();
        assert!(!status.resolved);
        assert_eq!(
            status.selected_account_state,
            Some(MycManagedAccountSelectionState::NotConfigured)
        );
    }

    #[test]
    fn managed_account_provider_reports_public_only_selected_account() {
        let (provider, vault) = managed_account_provider("user", "org.radroots.test.user");
        let identity = RadrootsIdentity::from_secret_key_str(
            "3333333333333333333333333333333333333333333333333333333333333333",
        )
        .expect("identity");
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("legacy.json");
        identity.save_json(&path).expect("save");
        let record = provider
            .import_managed_account_file(&path, Some("legacy".to_owned()), true)
            .expect("import");
        let selected_account_id = record
            .state
            .selected_account_id
            .clone()
            .expect("selected account");
        vault
            .remove_secret(
                &RadrootsIdentityId::parse(selected_account_id.as_str()).expect("account id"),
            )
            .expect("remove secret");

        let err = provider.load_identity().expect_err("public only");
        assert!(matches!(
            err,
            MycError::CustodyManagedAccountPublicOnly { .. }
        ));
        let status = provider.probe_status();
        assert!(!status.resolved);
        assert_eq!(
            status.selected_account_state,
            Some(MycManagedAccountSelectionState::PublicOnly)
        );
    }
}
