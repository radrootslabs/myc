//! Myc-owned managed-account persistence and secret custody.
//!
//! Public account values come from `radroots_identity`; selection, persistence,
//! keyring access, and secret-bearing Nostr keys remain owned by the service.

use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use nostr::{Keys, SecretKey};
use radroots_identity::account::{Record, Status};
use radroots_identity::{AccountId, PublicIdentity, PublicKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroizing;

const STORE_VERSION: u32 = 1;

#[derive(Debug, Error)]
pub enum AccountsError {
    #[error("identity error: {0}")]
    Identity(String),
    #[error("store error: {0}")]
    Store(String),
    #[error("vault error: {0}")]
    Vault(String),
    #[error("account not found: {0}")]
    AccountNotFound(String),
    #[error("invalid account state: {0}")]
    InvalidState(String),
    #[error("public key does not match secret key")]
    PublicKeyMismatch,
}

#[derive(Debug, Error)]
pub enum SecretVaultError {
    #[error("secret backend failed")]
    Backend,
}

pub trait SecretVault: Send + Sync {
    fn store_secret(&self, slot: &str, secret: &str) -> Result<(), SecretVaultError>;
    fn load_secret(&self, slot: &str) -> Result<Option<String>, SecretVaultError>;
    fn remove_secret(&self, slot: &str) -> Result<(), SecretVaultError>;
}

#[derive(Debug, Clone, Default)]
pub struct MemorySecretVault {
    entries: Arc<RwLock<std::collections::BTreeMap<String, String>>>,
}

impl MemorySecretVault {
    pub fn new() -> Self {
        Self::default()
    }
}

impl SecretVault for MemorySecretVault {
    fn store_secret(&self, slot: &str, secret: &str) -> Result<(), SecretVaultError> {
        self.entries
            .write()
            .map_err(|_| SecretVaultError::Backend)?
            .insert(slot.to_owned(), secret.to_owned());
        Ok(())
    }

    fn load_secret(&self, slot: &str) -> Result<Option<String>, SecretVaultError> {
        Ok(self
            .entries
            .read()
            .map_err(|_| SecretVaultError::Backend)?
            .get(slot)
            .cloned())
    }

    fn remove_secret(&self, slot: &str) -> Result<(), SecretVaultError> {
        self.entries
            .write()
            .map_err(|_| SecretVaultError::Backend)?
            .remove(slot);
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct OsKeyringSecretVault {
    service_name: String,
}

impl OsKeyringSecretVault {
    pub fn new(service_name: impl Into<String>) -> Self {
        Self {
            service_name: service_name.into(),
        }
    }

    fn entry(&self, slot: &str) -> Result<keyring::Entry, SecretVaultError> {
        keyring::Entry::new(self.service_name.as_str(), slot).map_err(|_| SecretVaultError::Backend)
    }
}

impl SecretVault for OsKeyringSecretVault {
    fn store_secret(&self, slot: &str, secret: &str) -> Result<(), SecretVaultError> {
        self.entry(slot)?
            .set_password(secret)
            .map_err(|_| SecretVaultError::Backend)
    }

    fn load_secret(&self, slot: &str) -> Result<Option<String>, SecretVaultError> {
        match self.entry(slot)?.get_password() {
            Ok(secret) => Ok(Some(secret)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(_) => Err(SecretVaultError::Backend),
        }
    }

    fn remove_secret(&self, slot: &str) -> Result<(), SecretVaultError> {
        match self.entry(slot)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(_) => Err(SecretVaultError::Backend),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountStoreState {
    version: u32,
    default_account_id: Option<AccountId>,
    accounts: Vec<Record>,
}

impl Default for AccountStoreState {
    fn default() -> Self {
        Self {
            version: STORE_VERSION,
            default_account_id: None,
            accounts: Vec::new(),
        }
    }
}

pub trait AccountStore: Send + Sync {
    fn load(&self) -> Result<AccountStoreState, AccountsError>;
    fn save(&self, state: &AccountStoreState) -> Result<(), AccountsError>;
}

#[derive(Debug, Clone)]
pub struct FileAccountStore {
    path: PathBuf,
}

impl FileAccountStore {
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
        }
    }
}

impl AccountStore for FileAccountStore {
    fn load(&self) -> Result<AccountStoreState, AccountsError> {
        if !self.path.exists() {
            return Ok(AccountStoreState::default());
        }
        let bytes =
            std::fs::read(&self.path).map_err(|_| AccountsError::Store("read failed".into()))?;
        serde_json::from_slice(&bytes).map_err(|_| AccountsError::Store("invalid JSON".into()))
    }

    fn save(&self, state: &AccountStoreState) -> Result<(), AccountsError> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|_| AccountsError::Store("create directory failed".into()))?;
        }
        let bytes = serde_json::to_vec_pretty(state)
            .map_err(|_| AccountsError::Store("serialization failed".into()))?;
        let temporary = self.path.with_extension("json.tmp");
        std::fs::write(&temporary, bytes)
            .map_err(|_| AccountsError::Store("write failed".into()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o600))
                .map_err(|_| AccountsError::Store("permission update failed".into()))?;
        }
        std::fs::rename(&temporary, &self.path)
            .map_err(|_| AccountsError::Store("atomic replace failed".into()))
    }
}

#[derive(Debug, Clone, Default)]
pub struct MemoryAccountStore {
    state: Arc<RwLock<AccountStoreState>>,
}

impl MemoryAccountStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl AccountStore for MemoryAccountStore {
    fn load(&self) -> Result<AccountStoreState, AccountsError> {
        self.state
            .read()
            .map(|state| state.clone())
            .map_err(|_| AccountsError::Store("memory store lock poisoned".into()))
    }

    fn save(&self, state: &AccountStoreState) -> Result<(), AccountsError> {
        *self
            .state
            .write()
            .map_err(|_| AccountsError::Store("memory store lock poisoned".into()))? =
            state.clone();
        Ok(())
    }
}

#[derive(Clone)]
pub struct AccountsManager {
    store: Arc<dyn AccountStore>,
    vault: Arc<dyn SecretVault>,
    state: Arc<RwLock<AccountStoreState>>,
}

impl AccountsManager {
    pub fn new(
        store: Arc<dyn AccountStore>,
        vault: Arc<dyn SecretVault>,
    ) -> Result<Self, AccountsError> {
        let state = store.load()?;
        if state.version != STORE_VERSION {
            return Err(AccountsError::InvalidState(
                "unsupported account store version".into(),
            ));
        }
        Ok(Self {
            store,
            vault,
            state: Arc::new(RwLock::new(state)),
        })
    }

    pub fn new_file_backed_with_vault(
        path: impl AsRef<Path>,
        vault: impl SecretVault + 'static,
    ) -> Result<Self, AccountsError> {
        Self::new(Arc::new(FileAccountStore::new(path)), Arc::new(vault))
    }

    pub fn default_account(&self) -> Result<Option<Record>, AccountsError> {
        let state = self.read_state()?;
        Ok(state.default_account_id.and_then(|id| {
            state
                .accounts
                .iter()
                .find(|account| account.id() == id)
                .cloned()
        }))
    }

    pub fn default_account_id(&self) -> Result<Option<AccountId>, AccountsError> {
        Ok(self.read_state()?.default_account_id)
    }

    pub fn list_accounts(&self) -> Result<Vec<Record>, AccountsError> {
        Ok(self.read_state()?.accounts.clone())
    }

    pub fn default_account_status(&self) -> Result<Status, AccountsError> {
        let Some(account) = self.default_account()? else {
            return Ok(Status::NotConfigured);
        };
        if self.vault.load_secret(&account.id().to_string())?.is_some() {
            Ok(Status::Ready { account })
        } else {
            Ok(Status::PublicOnly { account })
        }
    }

    pub fn default_signing_keys(&self) -> Result<Option<Keys>, AccountsError> {
        let Some(account) = self.default_account()? else {
            return Ok(None);
        };
        let Some(secret) = self.vault.load_secret(&account.id().to_string())? else {
            return Ok(None);
        };
        let secret = Zeroizing::new(secret);
        let key = SecretKey::parse(secret.as_str())
            .map_err(|_| AccountsError::InvalidState("invalid stored secret".into()))?;
        let keys = Keys::new(key);
        if keys.public_key().to_hex() != account.public_identity().public_key().to_hex() {
            return Err(AccountsError::PublicKeyMismatch);
        }
        Ok(Some(keys))
    }

    pub fn upsert_keys(
        &self,
        keys: &Keys,
        label: Option<String>,
        make_default: bool,
    ) -> Result<AccountId, AccountsError> {
        let public_key = PublicKey::from_hex(&keys.public_key().to_hex())
            .map_err(|error| AccountsError::Identity(error.to_string()))?;
        let public_identity = PublicIdentity::new(public_key);
        let account_id = AccountId::from_public_identity(&public_identity);
        let secret = Zeroizing::new(keys.secret_key().to_secret_hex());
        self.vault
            .store_secret(&account_id.to_string(), secret.as_str())?;
        self.update_state(|state| {
            let now = now_unix_secs();
            if let Some(record) = state
                .accounts
                .iter_mut()
                .find(|record| record.id() == account_id)
            {
                let created = record.created_at_unix();
                *record = Record::try_from_parts(
                    account_id,
                    public_identity.clone(),
                    label.clone(),
                    created,
                    now,
                )
                .map_err(|error| AccountsError::Identity(error.to_string()))?;
            } else {
                state
                    .accounts
                    .push(Record::new(public_identity, label.clone(), now));
            }
            if state.default_account_id.is_none() || make_default {
                state.default_account_id = Some(account_id);
            }
            Ok(())
        })?;
        Ok(account_id)
    }

    pub fn generate_keys(
        &self,
        label: Option<String>,
        make_default: bool,
    ) -> Result<AccountId, AccountsError> {
        self.upsert_keys(&Keys::generate(), label, make_default)
    }

    pub fn set_default_account(&self, account_id: &AccountId) -> Result<(), AccountsError> {
        self.update_state(|state| {
            if !state
                .accounts
                .iter()
                .any(|record| record.id() == *account_id)
            {
                return Err(AccountsError::AccountNotFound(account_id.to_string()));
            }
            state.default_account_id = Some(*account_id);
            Ok(())
        })
    }

    pub fn remove_account(&self, account_id: &AccountId) -> Result<(), AccountsError> {
        self.update_state(|state| {
            let before = state.accounts.len();
            state.accounts.retain(|record| record.id() != *account_id);
            if before == state.accounts.len() {
                return Err(AccountsError::AccountNotFound(account_id.to_string()));
            }
            if state.default_account_id == Some(*account_id) {
                state.default_account_id = None;
            }
            Ok(())
        })?;
        self.vault.remove_secret(&account_id.to_string())?;
        Ok(())
    }

    fn read_state(
        &self,
    ) -> Result<std::sync::RwLockReadGuard<'_, AccountStoreState>, AccountsError> {
        self.state
            .read()
            .map_err(|_| AccountsError::Store("account state lock poisoned".into()))
    }

    fn update_state(
        &self,
        update: impl FnOnce(&mut AccountStoreState) -> Result<(), AccountsError>,
    ) -> Result<(), AccountsError> {
        let mut state = self
            .state
            .write()
            .map_err(|_| AccountsError::Store("account state lock poisoned".into()))?;
        let mut next = state.clone();
        update(&mut next)?;
        self.store.save(&next)?;
        *state = next;
        Ok(())
    }
}

impl From<SecretVaultError> for AccountsError {
    fn from(_: SecretVaultError) -> Self {
        Self::Vault("secret backend failed".into())
    }
}

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

pub type RadrootsNostrAccountsManager = AccountsManager;
pub type RadrootsNostrAccountsError = AccountsError;
pub type RadrootsNostrMemoryAccountStore = MemoryAccountStore;
pub type RadrootsNostrSecretVaultMemory = MemorySecretVault;
pub type RadrootsSecretVaultOsKeyring = OsKeyringSecretVault;
pub use SecretVault as RadrootsSecretVault;
