use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use nostr::nips::nip44::Version;
use nostr::nips::{nip04, nip44};
use radroots_identity::{RadrootsIdentity, RadrootsIdentityId, RadrootsIdentityPublic};
use radroots_nostr::prelude::{
    RadrootsNostrClient, RadrootsNostrEvent, RadrootsNostrEventBuilder, RadrootsNostrPublicKey,
};
use radroots_nostr_accounts::prelude::{
    RadrootsNostrAccountRecord, RadrootsNostrAccountsManager, RadrootsNostrSelectedAccountStatus,
};
use radroots_secret_vault::{RadrootsSecretVault, RadrootsSecretVaultOsKeyring};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::config::{MycConfig, MycIdentityBackend, MycIdentitySourceSpec};
use crate::error::MycError;
use crate::identity_files::{
    load_encrypted_identity, load_identity_profile, rotate_encrypted_identity,
    store_encrypted_identity, store_identity_profile,
};

#[derive(Clone)]
pub struct MycActiveIdentity {
    public_identity: RadrootsIdentityPublic,
    public_key: RadrootsNostrPublicKey,
    operations: Arc<dyn MycIdentityOperations>,
}

fn store_plaintext_identity(
    path: impl AsRef<Path>,
    identity: &RadrootsIdentity,
) -> Result<(), MycError> {
    identity.save_json(path).map_err(MycError::from)
}

fn store_secret_text(path: impl AsRef<Path>, value: &str) -> Result<(), MycError> {
    let path = path.as_ref();
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent).map_err(|source| MycError::CreateDir {
            path: parent.to_path_buf(),
            source,
        })?;
    }

    fs::write(path, value).map_err(|source| MycError::PersistenceIo {
        path: path.to_path_buf(),
        source,
    })?;
    set_secret_permissions(path)?;
    Ok(())
}

fn set_secret_permissions(path: &Path) -> Result<(), MycError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let permissions = std::fs::Permissions::from_mode(0o600);
        fs::set_permissions(path, permissions).map_err(|source| MycError::PersistenceIo {
            path: path.to_path_buf(),
            source,
        })?;
    }
    Ok(())
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
    pub default_shared_secret_backend: MycIdentityBackend,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_shared_secret_backends: Vec<MycIdentityBackend>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub runtime_specific_custody_modes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_vault_policy: Option<String>,
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

#[derive(Debug, Clone, Serialize)]
pub struct MycCustodyExportOutput {
    pub role: String,
    pub backend: MycIdentityBackend,
    pub format: String,
    pub out: PathBuf,
    pub identity_id: String,
    pub public_key_hex: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct MycCustodyImportOutput {
    pub role: String,
    pub backend: MycIdentityBackend,
    pub format: String,
    pub account_id: String,
    pub status: MycIdentityStatusOutput,
}

#[derive(Debug, Clone, Serialize)]
pub struct MycCustodyRotateOutput {
    pub role: String,
    pub backend: MycIdentityBackend,
    pub action: String,
    pub status: MycIdentityStatusOutput,
}

const MYC_CUSTODY_FORMAT_NIP49: &str = "nip49";

#[derive(Clone)]
pub struct MycIdentityProvider {
    role: String,
    source: MycIdentitySourceSpec,
    backend: MycIdentityProviderBackend,
}

#[derive(Clone)]
enum MycIdentityProviderBackend {
    EncryptedFile {
        path: PathBuf,
    },
    PlaintextFile {
        path: PathBuf,
    },
    HostVault {
        account_id: RadrootsIdentityId,
        service_name: String,
        profile_path: Option<PathBuf>,
        vault: Arc<dyn RadrootsSecretVault>,
    },
    ManagedAccount {
        account_store_path: PathBuf,
        service_name: String,
        manager: RadrootsNostrAccountsManager,
    },
    ExternalCommand {
        command_path: PathBuf,
        timeout: Duration,
        executor: Arc<dyn MycExternalCommandExecutor>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum MycExternalCommandOperation {
    Describe,
    SignEvent,
    Nip04Encrypt,
    Nip04Decrypt,
    Nip44Encrypt,
    Nip44Decrypt,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MycExternalCommandRequest {
    version: u8,
    operation: MycExternalCommandOperation,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    unsigned_event: Option<nostr::UnsignedEvent>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    public_key_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    content: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MycExternalCommandResponse {
    #[serde(default)]
    identity: Option<RadrootsIdentityPublic>,
    #[serde(default)]
    event: Option<nostr::Event>,
    #[serde(default)]
    content: Option<String>,
    #[serde(default)]
    error: Option<String>,
}

#[derive(Debug, Clone)]
struct MycExternalCommandOutput {
    success: bool,
    status: Option<i32>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

#[derive(Debug)]
enum MycExternalCommandExecuteError {
    Io(std::io::Error),
    TimedOut,
}

trait MycExternalCommandExecutor: Send + Sync {
    fn execute(
        &self,
        command_path: &PathBuf,
        request_json: &[u8],
        timeout: Duration,
    ) -> Result<MycExternalCommandOutput, MycExternalCommandExecuteError>;
}

#[derive(Debug, Default)]
struct MycProcessCommandExecutor;

impl MycExternalCommandExecutor for MycProcessCommandExecutor {
    fn execute(
        &self,
        command_path: &PathBuf,
        request_json: &[u8],
        timeout: Duration,
    ) -> Result<MycExternalCommandOutput, MycExternalCommandExecuteError> {
        let mut child = Command::new(command_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(MycExternalCommandExecuteError::Io)?;
        if let Some(mut stdin) = child.stdin.take() {
            use std::io::Write;
            stdin
                .write_all(request_json)
                .map_err(MycExternalCommandExecuteError::Io)?;
        }
        let deadline = Instant::now() + timeout;
        loop {
            match child
                .try_wait()
                .map_err(MycExternalCommandExecuteError::Io)?
            {
                Some(_) => break,
                None if Instant::now() >= deadline => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(MycExternalCommandExecuteError::TimedOut);
                }
                None => std::thread::sleep(Duration::from_millis(10)),
            }
        }
        let output = child
            .wait_with_output()
            .map_err(MycExternalCommandExecuteError::Io)?;
        Ok(MycExternalCommandOutput {
            success: output.status.success(),
            status: output.status.code(),
            stdout: output.stdout,
            stderr: output.stderr,
        })
    }
}

trait MycIdentityOperations: Send + Sync {
    fn nostr_client(&self) -> RadrootsNostrClient;
    fn nostr_client_owned(&self) -> RadrootsNostrClient;
    fn sign_event_builder(
        &self,
        builder: RadrootsNostrEventBuilder,
        operation: &str,
    ) -> Result<RadrootsNostrEvent, MycError>;
    fn sign_unsigned_event(
        &self,
        unsigned_event: nostr::UnsignedEvent,
        operation: &str,
    ) -> Result<nostr::Event, MycError>;
    fn nip04_encrypt(
        &self,
        public_key: &RadrootsNostrPublicKey,
        plaintext: String,
    ) -> Result<String, MycError>;
    fn nip04_decrypt(
        &self,
        public_key: &RadrootsNostrPublicKey,
        ciphertext: &str,
    ) -> Result<String, MycError>;
    fn nip44_encrypt(
        &self,
        public_key: &RadrootsNostrPublicKey,
        plaintext: String,
    ) -> Result<String, MycError>;
    fn nip44_decrypt(
        &self,
        public_key: &RadrootsNostrPublicKey,
        ciphertext: &str,
    ) -> Result<String, MycError>;
}

struct MycLoadedIdentityOperations {
    identity: Arc<RadrootsIdentity>,
}

impl MycLoadedIdentityOperations {
    fn new(identity: RadrootsIdentity) -> Self {
        Self {
            identity: Arc::new(identity),
        }
    }
}

impl MycIdentityOperations for MycLoadedIdentityOperations {
    fn nostr_client(&self) -> RadrootsNostrClient {
        RadrootsNostrClient::from_identity(self.identity.as_ref())
    }

    fn nostr_client_owned(&self) -> RadrootsNostrClient {
        RadrootsNostrClient::from_identity_owned((*self.identity).clone())
    }

    fn sign_event_builder(
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

    fn sign_unsigned_event(
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

    fn nip04_encrypt(
        &self,
        public_key: &RadrootsNostrPublicKey,
        plaintext: String,
    ) -> Result<String, MycError> {
        nip04::encrypt(self.identity.keys().secret_key(), public_key, plaintext)
            .map_err(|error| MycError::Nip46Encrypt(error.to_string()))
    }

    fn nip04_decrypt(
        &self,
        public_key: &RadrootsNostrPublicKey,
        ciphertext: &str,
    ) -> Result<String, MycError> {
        nip04::decrypt(self.identity.keys().secret_key(), public_key, ciphertext)
            .map_err(|error| MycError::Nip46Decrypt(error.to_string()))
    }

    fn nip44_encrypt(
        &self,
        public_key: &RadrootsNostrPublicKey,
        plaintext: String,
    ) -> Result<String, MycError> {
        nip44::encrypt(
            self.identity.keys().secret_key(),
            public_key,
            plaintext,
            Version::V2,
        )
        .map_err(|error| MycError::Nip46Encrypt(error.to_string()))
    }

    fn nip44_decrypt(
        &self,
        public_key: &RadrootsNostrPublicKey,
        ciphertext: &str,
    ) -> Result<String, MycError> {
        nip44::decrypt(self.identity.keys().secret_key(), public_key, ciphertext)
            .map_err(|error| MycError::Nip46Decrypt(error.to_string()))
    }
}

struct MycExternalCommandIdentityOperations {
    role: String,
    command_path: PathBuf,
    timeout: Duration,
    public_identity: RadrootsIdentityPublic,
    public_key: RadrootsNostrPublicKey,
    executor: Arc<dyn MycExternalCommandExecutor>,
}

impl MycExternalCommandIdentityOperations {
    fn new(
        role: String,
        command_path: PathBuf,
        timeout: Duration,
        public_identity: RadrootsIdentityPublic,
        public_key: RadrootsNostrPublicKey,
        executor: Arc<dyn MycExternalCommandExecutor>,
    ) -> Self {
        Self {
            role,
            command_path,
            timeout,
            public_identity,
            public_key,
            executor,
        }
    }

    fn execute(
        &self,
        request: &MycExternalCommandRequest,
    ) -> Result<MycExternalCommandResponse, MycError> {
        let request_json = serde_json::to_vec(request)?;
        let output = self
            .executor
            .execute(&self.command_path, &request_json, self.timeout)
            .map_err(|error| match error {
                MycExternalCommandExecuteError::Io(source) => MycError::CustodyExternalCommandIo {
                    role: self.role.clone(),
                    path: self.command_path.clone(),
                    source,
                },
                MycExternalCommandExecuteError::TimedOut => {
                    MycError::CustodyExternalCommandTimedOut {
                        role: self.role.clone(),
                        path: self.command_path.clone(),
                        timeout_secs: self.timeout.as_secs(),
                    }
                }
            })?;
        if !output.success {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
            return Err(MycError::CustodyExternalCommandFailed {
                role: self.role.clone(),
                path: self.command_path.clone(),
                status: output
                    .status
                    .map(|status| status.to_string())
                    .unwrap_or_else(|| "terminated by signal".to_owned()),
                stderr: if stderr.is_empty() {
                    "external signer command failed without stderr".to_owned()
                } else {
                    stderr
                },
            });
        }
        let response: MycExternalCommandResponse =
            serde_json::from_slice(&output.stdout).map_err(|source| {
                MycError::CustodyExternalCommandParse {
                    role: self.role.clone(),
                    path: self.command_path.clone(),
                    source,
                }
            })?;
        if let Some(error) = response.error.as_deref() {
            return Err(MycError::CustodyExternalCommandFailed {
                role: self.role.clone(),
                path: self.command_path.clone(),
                status: "0".to_owned(),
                stderr: error.to_owned(),
            });
        }
        Ok(response)
    }
}

impl MycIdentityOperations for MycExternalCommandIdentityOperations {
    fn nostr_client(&self) -> RadrootsNostrClient {
        RadrootsNostrClient::new_signerless()
    }

    fn nostr_client_owned(&self) -> RadrootsNostrClient {
        self.nostr_client()
    }

    fn sign_event_builder(
        &self,
        builder: RadrootsNostrEventBuilder,
        operation: &str,
    ) -> Result<RadrootsNostrEvent, MycError> {
        let unsigned_event = builder.build(self.public_key);
        self.sign_unsigned_event(unsigned_event, operation)
    }

    fn sign_unsigned_event(
        &self,
        unsigned_event: nostr::UnsignedEvent,
        operation: &str,
    ) -> Result<nostr::Event, MycError> {
        let response = self.execute(&MycExternalCommandRequest {
            version: 1,
            operation: MycExternalCommandOperation::SignEvent,
            unsigned_event: Some(unsigned_event),
            public_key_hex: None,
            content: None,
        })?;
        let event = response.event.ok_or_else(|| {
            MycError::InvalidOperation(format!(
                "external signer command did not return a signed event for {operation}"
            ))
        })?;
        if event.pubkey != self.public_key {
            return Err(MycError::InvalidOperation(format!(
                "external signer command returned a signed {operation} event for `{}` instead of `{}`",
                event.pubkey.to_hex(),
                self.public_identity.public_key_hex
            )));
        }
        Ok(event)
    }

    fn nip04_encrypt(
        &self,
        public_key: &RadrootsNostrPublicKey,
        plaintext: String,
    ) -> Result<String, MycError> {
        let response = self.execute(&MycExternalCommandRequest {
            version: 1,
            operation: MycExternalCommandOperation::Nip04Encrypt,
            unsigned_event: None,
            public_key_hex: Some(public_key.to_hex()),
            content: Some(plaintext),
        })?;
        response.content.ok_or_else(|| {
            MycError::InvalidOperation(
                "external signer command did not return NIP-04 ciphertext".to_owned(),
            )
        })
    }

    fn nip04_decrypt(
        &self,
        public_key: &RadrootsNostrPublicKey,
        ciphertext: &str,
    ) -> Result<String, MycError> {
        let response = self.execute(&MycExternalCommandRequest {
            version: 1,
            operation: MycExternalCommandOperation::Nip04Decrypt,
            unsigned_event: None,
            public_key_hex: Some(public_key.to_hex()),
            content: Some(ciphertext.to_owned()),
        })?;
        response.content.ok_or_else(|| {
            MycError::InvalidOperation(
                "external signer command did not return NIP-04 cleartext".to_owned(),
            )
        })
    }

    fn nip44_encrypt(
        &self,
        public_key: &RadrootsNostrPublicKey,
        plaintext: String,
    ) -> Result<String, MycError> {
        let response = self.execute(&MycExternalCommandRequest {
            version: 1,
            operation: MycExternalCommandOperation::Nip44Encrypt,
            unsigned_event: None,
            public_key_hex: Some(public_key.to_hex()),
            content: Some(plaintext),
        })?;
        response.content.ok_or_else(|| {
            MycError::InvalidOperation(
                "external signer command did not return NIP-44 ciphertext".to_owned(),
            )
        })
    }

    fn nip44_decrypt(
        &self,
        public_key: &RadrootsNostrPublicKey,
        ciphertext: &str,
    ) -> Result<String, MycError> {
        let response = self.execute(&MycExternalCommandRequest {
            version: 1,
            operation: MycExternalCommandOperation::Nip44Decrypt,
            unsigned_event: None,
            public_key_hex: Some(public_key.to_hex()),
            content: Some(ciphertext.to_owned()),
        })?;
        response.content.ok_or_else(|| {
            MycError::InvalidOperation(
                "external signer command did not return NIP-44 cleartext".to_owned(),
            )
        })
    }
}

impl MycIdentityProvider {
    pub fn from_source(
        role: impl Into<String>,
        source: MycIdentitySourceSpec,
        external_command_timeout: Duration,
    ) -> Result<Self, MycError> {
        let role = role.into();
        let backend = match source.backend {
            MycIdentityBackend::EncryptedFile => {
                let path = source.path.clone().ok_or_else(|| {
                    MycError::InvalidConfig(format!(
                        "{role} identity encrypted_file backend requires a path"
                    ))
                })?;
                MycIdentityProviderBackend::EncryptedFile { path }
            }
            MycIdentityBackend::PlaintextFile => {
                let path = source.path.clone().ok_or_else(|| {
                    MycError::InvalidConfig(format!(
                        "{role} identity plaintext_file backend requires a path"
                    ))
                })?;
                MycIdentityProviderBackend::PlaintextFile { path }
            }
            MycIdentityBackend::HostVault => {
                let account_id = RadrootsIdentityId::parse(
                    source.keyring_account_id.as_deref().ok_or_else(|| {
                        MycError::InvalidConfig(format!(
                            "{role} identity host_vault backend requires keyring_account_id"
                        ))
                    })?,
                )
                .map_err(|_| {
                    MycError::InvalidConfig(format!(
                        "{role} identity host_vault backend requires a valid keyring_account_id"
                    ))
                })?;
                let service_name = source.keyring_service_name.clone().ok_or_else(|| {
                    MycError::InvalidConfig(format!(
                        "{role} identity host_vault backend requires keyring_service_name"
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
            MycIdentityBackend::ExternalCommand => {
                let command_path = source.path.clone().ok_or_else(|| {
                    MycError::InvalidConfig(format!(
                        "{role} identity external_command backend requires a path"
                    ))
                })?;
                MycIdentityProviderBackend::ExternalCommand {
                    command_path,
                    timeout: external_command_timeout,
                    executor: Arc::new(MycProcessCommandExecutor),
                }
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
            MycIdentityProviderBackend::EncryptedFile { path } => {
                Ok(load_encrypted_identity(path)?)
            }
            MycIdentityProviderBackend::PlaintextFile { path } => {
                RadrootsIdentity::load_from_path_auto(path).map_err(Into::into)
            }
            MycIdentityProviderBackend::HostVault {
                account_id,
                service_name,
                profile_path,
                vault,
            } => {
                let secret_key_hex = vault
                    .load_secret(account_id.as_str())
                    .map_err(|source| MycError::CustodyVault {
                        role: self.role.clone(),
                        source: source.into(),
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
                    let profile_identity = load_identity_profile(profile_path)?;
                    if profile_identity.id != *account_id {
                        return Err(MycError::CustodyProfileIdentityMismatch {
                            role: self.role.clone(),
                            path: profile_path.clone(),
                            account_id: account_id.to_string(),
                            profile_identity_id: profile_identity.id.to_string(),
                        });
                    }
                    if let Some(profile) = profile_identity.profile {
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
            MycIdentityProviderBackend::ExternalCommand { command_path, .. } => {
                Err(MycError::InvalidOperation(format!(
                    "{} identity backend `external_command` at {} does not materialize secret-bearing identities in-process",
                    self.role,
                    command_path.display()
                )))
            }
        }
    }

    pub fn load_active_identity(&self) -> Result<MycActiveIdentity, MycError> {
        match &self.backend {
            MycIdentityProviderBackend::ExternalCommand {
                command_path,
                timeout,
                executor,
            } => {
                let (public_identity, public_key) =
                    self.load_external_command_identity(command_path, *timeout, executor.as_ref())?;
                Ok(MycActiveIdentity::from_operations(
                    public_identity.clone(),
                    public_key,
                    Arc::new(MycExternalCommandIdentityOperations::new(
                        self.role.clone(),
                        command_path.clone(),
                        *timeout,
                        public_identity,
                        public_key,
                        executor.clone(),
                    )),
                ))
            }
            _ => self.load_identity().map(MycActiveIdentity::new),
        }
    }

    pub fn resolved_status(&self, identity: &MycActiveIdentity) -> MycIdentityStatusOutput {
        match &self.backend {
            MycIdentityProviderBackend::ManagedAccount { .. } => {
                self.managed_account_status(Ok(()), self.selected_managed_account_record_result())
            }
            _ => self.status_with_public_identity(identity.public_identity()),
        }
    }

    pub fn probe_status(&self) -> MycIdentityStatusOutput {
        match &self.backend {
            MycIdentityProviderBackend::ManagedAccount { .. } => self.managed_account_status(
                self.load_identity_public().as_ref().map(|_| ()),
                self.selected_managed_account_record_result(),
            ),
            _ => match self.load_identity_public() {
                Ok(identity) => self.status_with_public_identity(&identity),
                Err(error) => self.status_with_error(&error),
            },
        }
    }

    pub fn source(&self) -> &MycIdentitySourceSpec {
        &self.source
    }

    pub fn status_output(&self) -> MycIdentityStatusOutput {
        self.probe_status()
    }

    pub fn export_nip49(
        &self,
        out: impl AsRef<std::path::Path>,
        password: &str,
    ) -> Result<MycCustodyExportOutput, MycError> {
        self.ensure_secret_materialized_operation("export NIP-49 secrets")?;
        let out = out.as_ref();
        let identity = self.load_identity()?;
        let payload = identity.encrypt_secret_key_ncryptsec(password)?;
        store_secret_text(out, payload.as_str())?;
        Ok(MycCustodyExportOutput {
            role: self.role.clone(),
            backend: self.source.backend,
            format: MYC_CUSTODY_FORMAT_NIP49.to_owned(),
            out: out.to_path_buf(),
            identity_id: identity.id().to_string(),
            public_key_hex: identity.public_key_hex(),
        })
    }

    pub fn import_nip49(
        &self,
        path: impl AsRef<std::path::Path>,
        password: &str,
        label: Option<String>,
    ) -> Result<MycCustodyImportOutput, MycError> {
        self.ensure_secret_materialized_operation("import NIP-49 secrets")?;
        let identity = load_identity_from_nip49_file(path.as_ref(), password)?;
        let account_id = identity.id().to_string();
        match &self.backend {
            MycIdentityProviderBackend::ManagedAccount { manager, .. } => {
                manager
                    .upsert_identity(&identity, label, true)
                    .map_err(|source| MycError::CustodyManager {
                        role: self.role.clone(),
                        source,
                    })?;
            }
            _ => {
                if let Some(label) = label {
                    return Err(MycError::InvalidOperation(format!(
                        "{} identity backend `{}` does not support --label for `import-nip49` (got `{label}`)",
                        self.role,
                        self.source.backend.as_str(),
                    )));
                }
                self.store_identity(&identity)?;
            }
        }
        Ok(MycCustodyImportOutput {
            role: self.role.clone(),
            backend: self.source.backend,
            format: MYC_CUSTODY_FORMAT_NIP49.to_owned(),
            account_id,
            status: self.probe_status(),
        })
    }

    pub fn rotate_secret_storage(&self) -> Result<MycCustodyRotateOutput, MycError> {
        match &self.backend {
            MycIdentityProviderBackend::EncryptedFile { path } => {
                rotate_encrypted_identity(path)?;
            }
            MycIdentityProviderBackend::PlaintextFile { .. } => {
                return Err(MycError::InvalidOperation(format!(
                    "{} identity backend `plaintext_file` does not support `custody rotate`; migrate to `encrypted_file`, `host_vault`, or `managed_account` first",
                    self.role
                )));
            }
            MycIdentityProviderBackend::HostVault { .. } => {
                return Err(MycError::InvalidOperation(format!(
                    "{} identity backend `host_vault` does not define an in-process `custody rotate` action; rotate or re-provision the secret through the host vault itself",
                    self.role
                )));
            }
            MycIdentityProviderBackend::ManagedAccount { .. } => {
                return Err(MycError::InvalidOperation(format!(
                    "{} identity backend `managed_account` does not define an in-process `custody rotate` action; rotate the selected account through the configured host vault policy",
                    self.role
                )));
            }
            MycIdentityProviderBackend::ExternalCommand { command_path, .. } => {
                return Err(MycError::InvalidOperation(format!(
                    "{} identity backend `external_command` at {} does not materialize secret-bearing identities in-process and cannot rotate local storage",
                    self.role,
                    command_path.display(),
                )));
            }
        }

        Ok(MycCustodyRotateOutput {
            role: self.role.clone(),
            backend: self.source.backend,
            action: "rotate".to_owned(),
            status: self.probe_status(),
        })
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

    fn store_identity(&self, identity: &RadrootsIdentity) -> Result<(), MycError> {
        match &self.backend {
            MycIdentityProviderBackend::EncryptedFile { path } => {
                Ok(store_encrypted_identity(path, identity)?)
            }
            MycIdentityProviderBackend::PlaintextFile { path } => {
                store_plaintext_identity(path, identity)
            }
            MycIdentityProviderBackend::HostVault {
                account_id,
                service_name,
                profile_path,
                vault,
            } => {
                let identity_id = identity.id();
                if identity_id != *account_id {
                    return Err(MycError::CustodySecretIdentityMismatch {
                        role: self.role.clone(),
                        service_name: service_name.clone(),
                        account_id: account_id.to_string(),
                        resolved_identity_id: identity_id.to_string(),
                    });
                }
                let secret_key_hex = Zeroizing::new(identity.secret_key_hex());
                vault
                    .store_secret(account_id.as_str(), secret_key_hex.as_str())
                    .map_err(|source| MycError::CustodyVault {
                        role: self.role.clone(),
                        source: source.into(),
                    })?;
                if let Some(profile_path) = profile_path {
                    store_identity_profile(profile_path, identity)?;
                }
                Ok(())
            }
            MycIdentityProviderBackend::ManagedAccount { .. } => {
                Err(MycError::InvalidOperation(format!(
                    "{} identity backend `managed_account` requires account-store lifecycle helpers instead of direct identity writes",
                    self.role
                )))
            }
            MycIdentityProviderBackend::ExternalCommand { command_path, .. } => {
                Err(MycError::InvalidOperation(format!(
                    "{} identity backend `external_command` at {} does not support direct secret writes",
                    self.role,
                    command_path.display(),
                )))
            }
        }
    }

    fn ensure_secret_materialized_operation(&self, operation: &str) -> Result<(), MycError> {
        if let MycIdentityProviderBackend::ExternalCommand { command_path, .. } = &self.backend {
            return Err(MycError::InvalidOperation(format!(
                "{} identity backend `external_command` at {} does not support `{operation}` because secret material never enters the myc process",
                self.role,
                command_path.display(),
            )));
        }
        Ok(())
    }

    fn load_identity_public(&self) -> Result<RadrootsIdentityPublic, MycError> {
        match &self.backend {
            MycIdentityProviderBackend::ExternalCommand {
                command_path,
                timeout,
                executor,
            } => self
                .load_external_command_identity(command_path, *timeout, executor.as_ref())
                .map(|(identity, _)| identity),
            _ => self.load_identity().map(|identity| identity.to_public()),
        }
    }

    fn load_external_command_identity(
        &self,
        command_path: &PathBuf,
        timeout: Duration,
        executor: &dyn MycExternalCommandExecutor,
    ) -> Result<(RadrootsIdentityPublic, RadrootsNostrPublicKey), MycError> {
        let request_json = serde_json::to_vec(&MycExternalCommandRequest {
            version: 1,
            operation: MycExternalCommandOperation::Describe,
            unsigned_event: None,
            public_key_hex: None,
            content: None,
        })?;
        let output = executor
            .execute(command_path, &request_json, timeout)
            .map_err(|error| match error {
                MycExternalCommandExecuteError::Io(source) => MycError::CustodyExternalCommandIo {
                    role: self.role.clone(),
                    path: command_path.clone(),
                    source,
                },
                MycExternalCommandExecuteError::TimedOut => {
                    MycError::CustodyExternalCommandTimedOut {
                        role: self.role.clone(),
                        path: command_path.clone(),
                        timeout_secs: timeout.as_secs(),
                    }
                }
            })?;
        if !output.success {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
            return Err(MycError::CustodyExternalCommandFailed {
                role: self.role.clone(),
                path: command_path.clone(),
                status: output
                    .status
                    .map(|status| status.to_string())
                    .unwrap_or_else(|| "terminated by signal".to_owned()),
                stderr: if stderr.is_empty() {
                    "external signer command failed without stderr".to_owned()
                } else {
                    stderr
                },
            });
        }
        let response: MycExternalCommandResponse =
            serde_json::from_slice(&output.stdout).map_err(|source| {
                MycError::CustodyExternalCommandParse {
                    role: self.role.clone(),
                    path: command_path.clone(),
                    source,
                }
            })?;
        if let Some(error) = response.error {
            return Err(MycError::CustodyExternalCommandFailed {
                role: self.role.clone(),
                path: command_path.clone(),
                status: "0".to_owned(),
                stderr: error,
            });
        }
        let identity =
            response
                .identity
                .ok_or_else(|| MycError::CustodyExternalCommandInvalidIdentity {
                    role: self.role.clone(),
                    path: command_path.clone(),
                    message: "missing `identity` in describe response".to_owned(),
                })?;
        validate_external_command_public_identity(&self.role, command_path, identity)
    }

    fn status_with_public_identity(
        &self,
        identity: &RadrootsIdentityPublic,
    ) -> MycIdentityStatusOutput {
        MycIdentityStatusOutput {
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
            default_shared_secret_backend: MycConfig::default_shared_secret_backend(),
            allowed_shared_secret_backends: MycConfig::allowed_shared_secret_backends(),
            runtime_specific_custody_modes: MycConfig::runtime_specific_custody_modes(),
            host_vault_policy: MycConfig::host_vault_policy(),
            identity_id: Some(identity.id.to_string()),
            public_key_hex: Some(identity.public_key_hex.clone()),
            error: None,
        }
    }

    fn status_with_error(&self, error: &MycError) -> MycIdentityStatusOutput {
        MycIdentityStatusOutput {
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
            default_shared_secret_backend: MycConfig::default_shared_secret_backend(),
            allowed_shared_secret_backends: MycConfig::allowed_shared_secret_backends(),
            runtime_specific_custody_modes: MycConfig::runtime_specific_custody_modes(),
            host_vault_policy: MycConfig::host_vault_policy(),
            identity_id: None,
            public_key_hex: None,
            error: Some(error.to_string()),
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
        identity_result: Result<(), &MycError>,
        account_result: Result<Option<RadrootsNostrAccountRecord>, MycError>,
    ) -> MycIdentityStatusOutput {
        let MycIdentityProviderBackend::ManagedAccount {
            account_store_path,
            service_name,
            manager,
        } = &self.backend
        else {
            return match self.load_identity_public() {
                Ok(identity) => self.status_with_public_identity(&identity),
                Err(error) => self.status_with_error(&error),
            };
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
                        default_shared_secret_backend: MycConfig::default_shared_secret_backend(),
                        allowed_shared_secret_backends: MycConfig::allowed_shared_secret_backends(),
                        runtime_specific_custody_modes: MycConfig::runtime_specific_custody_modes(),
                        host_vault_policy: MycConfig::host_vault_policy(),
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
            default_shared_secret_backend: MycConfig::default_shared_secret_backend(),
            allowed_shared_secret_backends: MycConfig::allowed_shared_secret_backends(),
            runtime_specific_custody_modes: MycConfig::runtime_specific_custody_modes(),
            host_vault_policy: MycConfig::host_vault_policy(),
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
                "{role} identity host_vault backend requires a non-empty keyring_service_name"
            )));
        }
        Ok(MycIdentityProviderBackend::HostVault {
            account_id,
            service_name: service_name.clone(),
            profile_path: source.profile_path.clone(),
            vault: Arc::new(RadrootsSecretVaultOsKeyring::new(service_name)),
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
        let manager = RadrootsNostrAccountsManager::new_file_backed_with_vault(
            account_store_path.as_path(),
            RadrootsSecretVaultOsKeyring::new(service_name.clone()),
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
        let public_identity = identity.to_public();
        let public_key = identity.public_key();
        Self::from_operations(
            public_identity,
            public_key,
            Arc::new(MycLoadedIdentityOperations::new(identity)),
        )
    }

    fn from_operations(
        public_identity: RadrootsIdentityPublic,
        public_key: RadrootsNostrPublicKey,
        operations: Arc<dyn MycIdentityOperations>,
    ) -> Self {
        Self {
            public_identity,
            public_key,
            operations,
        }
    }

    pub fn id(&self) -> RadrootsIdentityId {
        self.public_identity.id.clone()
    }

    pub fn public_key(&self) -> RadrootsNostrPublicKey {
        self.public_key
    }

    pub fn public_key_hex(&self) -> String {
        self.public_identity.public_key_hex.clone()
    }

    pub fn to_public(&self) -> RadrootsIdentityPublic {
        self.public_identity.clone()
    }

    pub fn public_identity(&self) -> &RadrootsIdentityPublic {
        &self.public_identity
    }

    pub fn nostr_client(&self) -> RadrootsNostrClient {
        self.operations.nostr_client()
    }

    pub fn nostr_client_owned(&self) -> RadrootsNostrClient {
        self.operations.nostr_client_owned()
    }

    pub fn sign_event_builder(
        &self,
        builder: RadrootsNostrEventBuilder,
        operation: &str,
    ) -> Result<RadrootsNostrEvent, MycError> {
        self.operations.sign_event_builder(builder, operation)
    }

    pub fn sign_unsigned_event(
        &self,
        unsigned_event: nostr::UnsignedEvent,
        operation: &str,
    ) -> Result<nostr::Event, MycError> {
        self.operations
            .sign_unsigned_event(unsigned_event, operation)
    }

    pub fn nip04_encrypt(
        &self,
        public_key: &RadrootsNostrPublicKey,
        plaintext: impl Into<String>,
    ) -> Result<String, MycError> {
        self.operations.nip04_encrypt(public_key, plaintext.into())
    }

    pub fn nip04_decrypt(
        &self,
        public_key: &RadrootsNostrPublicKey,
        ciphertext: impl AsRef<str>,
    ) -> Result<String, MycError> {
        self.operations
            .nip04_decrypt(public_key, ciphertext.as_ref())
    }

    pub fn nip44_encrypt(
        &self,
        public_key: &RadrootsNostrPublicKey,
        plaintext: impl Into<String>,
    ) -> Result<String, MycError> {
        self.operations.nip44_encrypt(public_key, plaintext.into())
    }

    pub fn nip44_decrypt(
        &self,
        public_key: &RadrootsNostrPublicKey,
        ciphertext: impl AsRef<str>,
    ) -> Result<String, MycError> {
        self.operations
            .nip44_decrypt(public_key, ciphertext.as_ref())
    }
}

fn load_identity_from_nip49_file(
    path: &std::path::Path,
    password: &str,
) -> Result<RadrootsIdentity, MycError> {
    let encoded = fs::read_to_string(path).map_err(|source| MycError::PersistenceIo {
        path: path.to_path_buf(),
        source,
    })?;
    let payload = encoded.trim();
    if payload.is_empty() {
        return Err(MycError::InvalidOperation(format!(
            "NIP-49 payload at {} was empty",
            path.display()
        )));
    }
    RadrootsIdentity::from_encrypted_secret_key_str(payload, password).map_err(MycError::from)
}

fn validate_external_command_public_identity(
    role: &str,
    command_path: &PathBuf,
    identity: RadrootsIdentityPublic,
) -> Result<(RadrootsIdentityPublic, RadrootsNostrPublicKey), MycError> {
    let public_key =
        RadrootsNostrPublicKey::parse(identity.public_key_hex.as_str()).map_err(|error| {
            MycError::CustodyExternalCommandInvalidIdentity {
                role: role.to_owned(),
                path: command_path.clone(),
                message: format!(
                    "invalid public_key_hex `{}`: {error}",
                    identity.public_key_hex
                ),
            }
        })?;
    let expected_id = RadrootsIdentityId::from(public_key);
    if identity.id != expected_id {
        return Err(MycError::CustodyExternalCommandInvalidIdentity {
            role: role.to_owned(),
            path: command_path.clone(),
            message: format!(
                "identity id `{}` does not match public_key_hex `{}`",
                identity.id, identity.public_key_hex
            ),
        });
    }
    Ok((identity, public_key))
}

impl MycIdentityStatusOutput {
    pub fn with_inherited_from(mut self, inherited_from: impl Into<String>) -> Self {
        self.inherited_from = Some(inherited_from.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::sync::Mutex;
    use std::time::Instant;

    use radroots_identity::RadrootsIdentity;
    use radroots_nostr_accounts::prelude::{
        RadrootsNostrAccountsManager, RadrootsNostrMemoryAccountStore,
        RadrootsNostrSecretVaultMemory,
    };
    use radroots_secret_vault::RadrootsSecretVault;

    use super::*;

    fn write_identity(path: &Path, secret_key: &str) {
        let identity = RadrootsIdentity::from_secret_key_str(secret_key).expect("identity");
        crate::identity_files::store_encrypted_identity(path, &identity).expect("save identity");
    }

    fn fixture_source(path: &Path) -> MycIdentitySourceSpec {
        MycIdentitySourceSpec {
            backend: MycIdentityBackend::EncryptedFile,
            path: Some(path.to_path_buf()),
            keyring_account_id: None,
            keyring_service_name: None,
            profile_path: None,
        }
    }

    #[cfg(unix)]
    fn shell_single_quote(value: &str) -> String {
        format!("'{}'", value.replace('\'', "'\"'\"'"))
    }

    #[cfg(unix)]
    fn write_timeout_helper(path: &Path, pid_path: &Path) {
        let script = format!(
            "#!/bin/sh\nprintf '%s\\n' \"$$\" > {}\nwhile :; do\n  :\ndone\n",
            shell_single_quote(&pid_path.display().to_string())
        );
        fs::write(path, script).expect("write helper");
        let mut permissions = fs::metadata(path).expect("helper metadata").permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(path, permissions).expect("helper permissions");
    }

    #[cfg(unix)]
    fn process_exists(pid: u32) -> bool {
        Command::new("kill")
            .arg("-0")
            .arg(pid.to_string())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("kill probe")
            .success()
    }

    #[derive(Debug)]
    struct FakeExternalCommandExecutor {
        identity: RadrootsIdentity,
        requests: Mutex<Vec<MycExternalCommandRequest>>,
    }

    impl FakeExternalCommandExecutor {
        fn new(secret_key: &str) -> Arc<Self> {
            Arc::new(Self {
                identity: RadrootsIdentity::from_secret_key_str(secret_key).expect("identity"),
                requests: Mutex::new(Vec::new()),
            })
        }
    }

    impl MycExternalCommandExecutor for FakeExternalCommandExecutor {
        fn execute(
            &self,
            _command_path: &PathBuf,
            request_json: &[u8],
            _timeout: Duration,
        ) -> Result<MycExternalCommandOutput, MycExternalCommandExecuteError> {
            let request: MycExternalCommandRequest =
                serde_json::from_slice(request_json).expect("request");
            self.requests
                .lock()
                .expect("requests lock")
                .push(request.clone());
            let response = match request.operation {
                MycExternalCommandOperation::Describe => MycExternalCommandResponse {
                    identity: Some(self.identity.to_public()),
                    event: None,
                    content: None,
                    error: None,
                },
                MycExternalCommandOperation::SignEvent => {
                    let unsigned_event = request.unsigned_event.expect("unsigned event");
                    let event = unsigned_event
                        .sign_with_keys(self.identity.keys())
                        .expect("sign event");
                    MycExternalCommandResponse {
                        identity: None,
                        event: Some(event),
                        content: None,
                        error: None,
                    }
                }
                MycExternalCommandOperation::Nip04Encrypt => {
                    let public_key = RadrootsNostrPublicKey::parse(
                        request.public_key_hex.as_deref().expect("public key hex"),
                    )
                    .expect("public key");
                    let ciphertext = nip04::encrypt(
                        self.identity.keys().secret_key(),
                        &public_key,
                        request.content.expect("plaintext"),
                    )
                    .expect("encrypt");
                    MycExternalCommandResponse {
                        identity: None,
                        event: None,
                        content: Some(ciphertext),
                        error: None,
                    }
                }
                MycExternalCommandOperation::Nip04Decrypt => {
                    let public_key = RadrootsNostrPublicKey::parse(
                        request.public_key_hex.as_deref().expect("public key hex"),
                    )
                    .expect("public key");
                    let plaintext = nip04::decrypt(
                        self.identity.keys().secret_key(),
                        &public_key,
                        request.content.as_deref().expect("ciphertext"),
                    )
                    .expect("decrypt");
                    MycExternalCommandResponse {
                        identity: None,
                        event: None,
                        content: Some(plaintext),
                        error: None,
                    }
                }
                MycExternalCommandOperation::Nip44Encrypt => {
                    let public_key = RadrootsNostrPublicKey::parse(
                        request.public_key_hex.as_deref().expect("public key hex"),
                    )
                    .expect("public key");
                    let ciphertext = nip44::encrypt(
                        self.identity.keys().secret_key(),
                        &public_key,
                        request.content.expect("plaintext"),
                        Version::V2,
                    )
                    .expect("encrypt");
                    MycExternalCommandResponse {
                        identity: None,
                        event: None,
                        content: Some(ciphertext),
                        error: None,
                    }
                }
                MycExternalCommandOperation::Nip44Decrypt => {
                    let public_key = RadrootsNostrPublicKey::parse(
                        request.public_key_hex.as_deref().expect("public key hex"),
                    )
                    .expect("public key");
                    let plaintext = nip44::decrypt(
                        self.identity.keys().secret_key(),
                        &public_key,
                        request.content.as_deref().expect("ciphertext"),
                    )
                    .expect("decrypt");
                    MycExternalCommandResponse {
                        identity: None,
                        event: None,
                        content: Some(plaintext),
                        error: None,
                    }
                }
            };

            Ok(MycExternalCommandOutput {
                success: true,
                status: Some(0),
                stdout: serde_json::to_vec(&response).expect("response"),
                stderr: Vec::new(),
            })
        }
    }

    fn managed_account_provider(
        role: &str,
        service_name: &str,
    ) -> (MycIdentityProvider, Arc<RadrootsNostrSecretVaultMemory>) {
        let vault = Arc::new(RadrootsNostrSecretVaultMemory::new());
        let manager = RadrootsNostrAccountsManager::new(
            Arc::new(RadrootsNostrMemoryAccountStore::new()),
            vault.clone() as Arc<dyn RadrootsSecretVault>,
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

    fn external_command_provider(
        role: &str,
        secret_key: &str,
    ) -> (MycIdentityProvider, Arc<FakeExternalCommandExecutor>) {
        let executor = FakeExternalCommandExecutor::new(secret_key);
        let command_path = PathBuf::from(format!("/tmp/{role}-identity-helper"));
        (
            MycIdentityProvider {
                role: role.to_owned(),
                source: MycIdentitySourceSpec {
                    backend: MycIdentityBackend::ExternalCommand,
                    path: Some(command_path.clone()),
                    keyring_account_id: None,
                    keyring_service_name: None,
                    profile_path: None,
                },
                backend: MycIdentityProviderBackend::ExternalCommand {
                    command_path,
                    timeout: Duration::from_secs(10),
                    executor: executor.clone(),
                },
            },
            executor,
        )
    }

    #[test]
    fn encrypted_file_provider_loads_identity() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("signer.json");
        write_identity(
            &path,
            "1111111111111111111111111111111111111111111111111111111111111111",
        );

        let provider = MycIdentityProvider::from_source(
            "signer",
            fixture_source(&path),
            Duration::from_secs(10),
        )
        .expect("provider");
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
        crate::identity_files::store_identity_profile(&profile_path, &identity)
            .expect("save profile");

        let account_id = identity.id();
        let vault = Arc::new(RadrootsNostrSecretVaultMemory::new());
        vault
            .store_secret(account_id.as_str(), identity.secret_key_hex().as_str())
            .expect("store");

        let provider = MycIdentityProvider {
            role: "signer".to_owned(),
            source: MycIdentitySourceSpec {
                backend: MycIdentityBackend::HostVault,
                path: None,
                keyring_account_id: Some(account_id.to_string()),
                keyring_service_name: Some("org.radroots.test".to_owned()),
                profile_path: Some(profile_path.clone()),
            },
            backend: MycIdentityProviderBackend::HostVault {
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
                backend: MycIdentityBackend::HostVault,
                path: None,
                keyring_account_id: Some(account_id.to_string()),
                keyring_service_name: Some("org.radroots.test".to_owned()),
                profile_path: None,
            },
            backend: MycIdentityProviderBackend::HostVault {
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
    fn managed_account_provider_supports_nip49_export_and_import() {
        let (provider, _vault) = managed_account_provider("signer", "org.radroots.test.signer");
        let generated = provider
            .generate_managed_account(Some("primary".to_owned()), true)
            .expect("generate");
        let selected_account_id = generated
            .state
            .selected_account_id
            .clone()
            .expect("selected account id");
        let temp = tempfile::tempdir().expect("tempdir");
        let export_path = temp.path().join("managed-account.ncryptsec");

        let export = provider
            .export_nip49(&export_path, "test password")
            .expect("export nip49");
        assert_eq!(export.format, "nip49");
        assert_eq!(export.identity_id, selected_account_id);

        provider
            .remove_managed_account(selected_account_id.as_str())
            .expect("remove account");
        let removed_status = provider.probe_status();
        assert!(!removed_status.resolved);

        let imported = provider
            .import_nip49(&export_path, "test password", Some("restored".to_owned()))
            .expect("import nip49");
        assert_eq!(imported.account_id, export.identity_id);
        assert!(imported.status.resolved);
        assert_eq!(
            imported.status.selected_account_label.as_deref(),
            Some("restored")
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
                RadrootsIdentityId::parse(selected_account_id.as_str())
                    .expect("account id")
                    .as_str(),
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

    #[test]
    fn external_command_provider_loads_identity_and_executes_signing_operations() {
        let (provider, executor) = external_command_provider(
            "signer",
            "1111111111111111111111111111111111111111111111111111111111111111",
        );
        let active = provider.load_active_identity().expect("active identity");
        let expected_identity = RadrootsIdentity::from_secret_key_str(
            "1111111111111111111111111111111111111111111111111111111111111111",
        )
        .expect("identity");
        assert_eq!(active.id(), expected_identity.id());
        assert_eq!(active.public_key_hex(), expected_identity.public_key_hex());

        let peer_identity = RadrootsIdentity::from_secret_key_str(
            "2222222222222222222222222222222222222222222222222222222222222222",
        )
        .expect("peer identity");
        let signed_event = active
            .sign_event_builder(
                RadrootsNostrEventBuilder::text_note("hello from external command"),
                "test event",
            )
            .expect("signed event");
        assert_eq!(signed_event.pubkey, expected_identity.public_key());

        let nip04_ciphertext = active
            .nip04_encrypt(&peer_identity.public_key(), "hello nip04")
            .expect("nip04 encrypt");
        assert_eq!(
            nip04::decrypt(
                peer_identity.keys().secret_key(),
                &expected_identity.public_key(),
                &nip04_ciphertext,
            )
            .expect("decrypt with peer"),
            "hello nip04"
        );

        let nip44_ciphertext = active
            .nip44_encrypt(&peer_identity.public_key(), "hello nip44")
            .expect("nip44 encrypt");
        assert_eq!(
            nip44::decrypt(
                peer_identity.keys().secret_key(),
                &expected_identity.public_key(),
                &nip44_ciphertext,
            )
            .expect("decrypt with peer"),
            "hello nip44"
        );

        let status = provider.probe_status();
        assert!(status.resolved);
        assert_eq!(
            status.path,
            Some(PathBuf::from("/tmp/signer-identity-helper"))
        );
        assert_eq!(status.identity_id, Some(expected_identity.id().to_string()));

        let operations = executor
            .requests
            .lock()
            .expect("requests lock")
            .iter()
            .map(|request| request.operation)
            .collect::<Vec<_>>();
        assert!(operations.contains(&MycExternalCommandOperation::Describe));
        assert!(operations.contains(&MycExternalCommandOperation::SignEvent));
        assert!(operations.contains(&MycExternalCommandOperation::Nip04Encrypt));
        assert!(operations.contains(&MycExternalCommandOperation::Nip44Encrypt));
    }

    #[tokio::test]
    async fn external_command_provider_uses_signerless_relay_client() {
        let (provider, _executor) = external_command_provider(
            "signer",
            "1111111111111111111111111111111111111111111111111111111111111111",
        );
        let active = provider.load_active_identity().expect("active identity");

        assert!(!active.nostr_client().has_signer().await);
        assert!(!active.nostr_client_owned().has_signer().await);
    }

    #[derive(Debug, Default)]
    struct TimeoutExternalCommandExecutor;

    impl MycExternalCommandExecutor for TimeoutExternalCommandExecutor {
        fn execute(
            &self,
            _command_path: &PathBuf,
            _request_json: &[u8],
            _timeout: Duration,
        ) -> Result<MycExternalCommandOutput, MycExternalCommandExecuteError> {
            Err(MycExternalCommandExecuteError::TimedOut)
        }
    }

    #[test]
    fn external_command_provider_maps_describe_timeout() {
        let provider = MycIdentityProvider {
            role: "signer".to_owned(),
            source: MycIdentitySourceSpec {
                backend: MycIdentityBackend::ExternalCommand,
                path: Some(PathBuf::from("/tmp/signer-helper")),
                keyring_account_id: None,
                keyring_service_name: None,
                profile_path: None,
            },
            backend: MycIdentityProviderBackend::ExternalCommand {
                command_path: PathBuf::from("/tmp/signer-helper"),
                timeout: Duration::from_secs(7),
                executor: Arc::new(TimeoutExternalCommandExecutor),
            },
        };

        let err = provider.load_active_identity().err().expect("timeout");
        assert!(matches!(
            err,
            MycError::CustodyExternalCommandTimedOut {
                ref role,
                ref path,
                timeout_secs: 7,
            } if role == "signer" && path == &PathBuf::from("/tmp/signer-helper")
        ));
    }

    #[test]
    fn external_command_provider_maps_operation_timeout() {
        let identity = RadrootsIdentity::from_secret_key_str(
            "1111111111111111111111111111111111111111111111111111111111111111",
        )
        .expect("identity");
        let public_identity = identity.to_public();
        let public_key = identity.public_key();
        let active = MycActiveIdentity::from_operations(
            public_identity.clone(),
            public_key,
            Arc::new(MycExternalCommandIdentityOperations::new(
                "signer".to_owned(),
                PathBuf::from("/tmp/signer-helper"),
                Duration::from_secs(11),
                public_identity,
                public_key,
                Arc::new(TimeoutExternalCommandExecutor),
            )),
        );

        let err = active
            .sign_event_builder(
                RadrootsNostrEventBuilder::text_note("timeout"),
                "timeout event",
            )
            .expect_err("timeout");
        assert!(matches!(
            err,
            MycError::CustodyExternalCommandTimedOut {
                ref role,
                ref path,
                timeout_secs: 11,
            } if role == "signer" && path == &PathBuf::from("/tmp/signer-helper")
        ));
    }

    #[cfg(unix)]
    #[test]
    fn process_executor_times_out_and_kills_real_helper() {
        let timeout = Duration::from_secs(2);
        let temp = tempfile::tempdir().expect("tempdir");
        let helper_path = temp.path().join("timeout-helper.sh");
        let pid_path = temp.path().join("timeout-helper.pid");
        write_timeout_helper(&helper_path, &pid_path);

        let helper_path_for_thread = helper_path.clone();
        let handle = std::thread::spawn(move || {
            let executor = MycProcessCommandExecutor;
            let started_at = Instant::now();
            let err = executor
                .execute(
                    &helper_path_for_thread,
                    b"{\"operation\":\"describe\"}",
                    timeout,
                )
                .expect_err("timeout");
            (started_at.elapsed(), err)
        });

        // Give the real helper a little slack to create its pid file under a busy full-test run
        // before we conclude the timeout path never launched it.
        let pid_deadline = Instant::now() + timeout + Duration::from_secs(5);
        let pid = loop {
            match fs::read_to_string(&pid_path) {
                Ok(value) => break value.trim().parse::<u32>().expect("pid"),
                Err(error)
                    if error.kind() == std::io::ErrorKind::NotFound
                        && Instant::now() < pid_deadline =>
                {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("helper pid: {error}"),
            }
        };

        let (elapsed, err) = handle.join().expect("executor thread");

        assert!(matches!(err, MycExternalCommandExecuteError::TimedOut));
        assert!(
            elapsed < timeout + Duration::from_secs(2),
            "timeout path should stay bounded"
        );
        assert!(!process_exists(pid), "helper process should be terminated");
    }
}
