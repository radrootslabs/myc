use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use crate::nostr_contract::RadrootsNostrRelayUrl;
use crate::paths::{RadrootsPathResolver, RadrootsRuntimePathPolicyContract};
use crate::signer::prelude::RadrootsNostrSignerApprovalRequirement;
use nostr::PublicKey;
use radroots_nostr_connect::permission::Permissions;
use serde::{Deserialize, Serialize};
use tracing_subscriber::EnvFilter;

use crate::error::MycError;
use crate::paths::MycPathOverrideFlags;
pub use crate::paths::{MycPathProfile, MycPathsConfig};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MycConfig {
    pub service: MycServiceConfig,
    pub logging: MycLoggingConfig,
    pub custody: MycCustodyConfig,
    pub paths: MycPathsConfig,
    pub persistence: MycPersistenceConfig,
    pub audit: MycAuditConfig,
    pub observability: MycObservabilityConfig,
    pub discovery: MycDiscoveryConfig,
    pub policy: MycPolicyConfig,
    pub transport: MycTransportConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MycServiceConfig {
    pub instance_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MycLoggingConfig {
    pub filter: String,
    pub output_dir: Option<PathBuf>,
    pub stdout: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MycCustodyConfig {
    pub external_command_timeout_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MycPersistenceConfig {
    pub signer_state_backend: MycSignerStateBackend,
    pub runtime_audit_backend: MycRuntimeAuditBackend,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MycAuditConfig {
    pub default_read_limit: usize,
    pub max_active_file_bytes: u64,
    pub max_archived_files: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MycObservabilityConfig {
    pub enabled: bool,
    pub bind_addr: SocketAddr,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MycDiscoveryConfig {
    pub enabled: bool,
    pub domain: Option<String>,
    pub handler_identifier: String,
    pub app_identity_backend: Option<MycIdentityBackend>,
    pub app_identity_path: Option<PathBuf>,
    pub app_identity_keyring_account_id: Option<String>,
    pub app_identity_keyring_service_name: Option<String>,
    pub app_identity_profile_path: Option<PathBuf>,
    pub public_relays: Vec<String>,
    pub publish_relays: Vec<String>,
    pub nostrconnect_url_template: Option<String>,
    pub nip05_output_path: Option<PathBuf>,
    pub metadata: MycDiscoveryMetadataConfig,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MycDiscoveryMetadataConfig {
    pub name: Option<String>,
    pub display_name: Option<String>,
    pub about: Option<String>,
    pub website: Option<String>,
    pub picture: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MycTransportConfig {
    pub enabled: bool,
    pub connect_timeout_secs: u64,
    pub relays: Vec<String>,
    pub delivery_policy: MycTransportDeliveryPolicy,
    pub delivery_quorum: Option<usize>,
    pub publish_max_attempts: usize,
    pub publish_initial_backoff_millis: u64,
    pub publish_max_backoff_millis: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MycConnectionApproval {
    NotRequired,
    ExplicitUser,
    Deny,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MycIdentityBackend {
    #[default]
    EncryptedFile,
    HostVault,
    ManagedAccount,
    ExternalCommand,
    PlaintextFile,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MycSignerStateBackend {
    JsonFile,
    Sqlite,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MycRuntimeAuditBackend {
    JsonlFile,
    Sqlite,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MycIdentitySourceSpec {
    pub backend: MycIdentityBackend,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keyring_account_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keyring_service_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_path: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MycRuntimeContractOutput {
    pub active_profile: MycPathProfile,
    pub allowed_profiles: Vec<MycPathProfile>,
    pub default_shared_secret_backend: MycIdentityBackend,
    pub allowed_shared_secret_backends: Vec<MycIdentityBackend>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub runtime_specific_custody_modes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_vault_policy: Option<String>,
    pub path_overrides: MycRuntimePathOverrideContractOutput,
}

pub type MycRuntimePathOverrideContractOutput = RadrootsRuntimePathPolicyContract;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MycTransportDeliveryPolicy {
    Any,
    Quorum,
    All,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MycPolicyConfig {
    pub connection_approval: MycConnectionApproval,
    pub trusted_client_pubkeys: Vec<String>,
    pub denied_client_pubkeys: Vec<String>,
    pub permission_ceiling: Permissions,
    pub allowed_sign_event_kinds: Vec<u16>,
    pub auth_url: Option<String>,
    pub auth_pending_ttl_secs: u64,
    pub auth_authorized_ttl_secs: Option<u64>,
    pub reauth_after_inactivity_secs: Option<u64>,
    pub connect_rate_limit_window_secs: Option<u64>,
    pub connect_rate_limit_max_attempts: Option<usize>,
    pub auth_challenge_rate_limit_window_secs: Option<u64>,
    pub auth_challenge_rate_limit_max_attempts: Option<usize>,
}

impl Default for MycConfig {
    fn default() -> Self {
        Self::default_with_path_selection(
            &RadrootsPathResolver::current(),
            MycPathProfile::InteractiveUser,
            None,
        )
        .expect("current process should resolve myc runtime paths")
    }
}

impl Default for MycServiceConfig {
    fn default() -> Self {
        Self {
            instance_name: "myc".to_owned(),
        }
    }
}

impl Default for MycLoggingConfig {
    fn default() -> Self {
        Self {
            filter: "info,myc=info".to_owned(),
            output_dir: None,
            stdout: true,
        }
    }
}

impl Default for MycCustodyConfig {
    fn default() -> Self {
        Self {
            external_command_timeout_secs: 10,
        }
    }
}

impl Default for MycTransportConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            connect_timeout_secs: 10,
            relays: Vec::new(),
            delivery_policy: MycTransportDeliveryPolicy::Any,
            delivery_quorum: None,
            publish_max_attempts: 1,
            publish_initial_backoff_millis: 250,
            publish_max_backoff_millis: 2_000,
        }
    }
}

impl Default for MycPersistenceConfig {
    fn default() -> Self {
        Self {
            signer_state_backend: MycSignerStateBackend::JsonFile,
            runtime_audit_backend: MycRuntimeAuditBackend::JsonlFile,
        }
    }
}

impl Default for MycAuditConfig {
    fn default() -> Self {
        Self {
            default_read_limit: 200,
            max_active_file_bytes: 262_144,
            max_archived_files: 8,
        }
    }
}

impl Default for MycObservabilityConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind_addr: "127.0.0.1:9460"
                .parse()
                .expect("default observability bind addr"),
        }
    }
}

impl Default for MycDiscoveryConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            domain: None,
            handler_identifier: "myc".to_owned(),
            app_identity_backend: None,
            app_identity_path: None,
            app_identity_keyring_account_id: None,
            app_identity_keyring_service_name: None,
            app_identity_profile_path: None,
            public_relays: Vec::new(),
            publish_relays: Vec::new(),
            nostrconnect_url_template: None,
            nip05_output_path: None,
            metadata: MycDiscoveryMetadataConfig::default(),
        }
    }
}

impl Default for MycPolicyConfig {
    fn default() -> Self {
        Self {
            connection_approval: MycConnectionApproval::ExplicitUser,
            trusted_client_pubkeys: Vec::new(),
            denied_client_pubkeys: Vec::new(),
            permission_ceiling: Permissions::default(),
            allowed_sign_event_kinds: Vec::new(),
            auth_url: None,
            auth_pending_ttl_secs: 900,
            auth_authorized_ttl_secs: None,
            reauth_after_inactivity_secs: None,
            connect_rate_limit_window_secs: None,
            connect_rate_limit_max_attempts: None,
            auth_challenge_rate_limit_window_secs: None,
            auth_challenge_rate_limit_max_attempts: None,
        }
    }
}

impl MycConnectionApproval {
    pub fn into_signer_approval_requirement(self) -> RadrootsNostrSignerApprovalRequirement {
        match self {
            Self::NotRequired => RadrootsNostrSignerApprovalRequirement::NotRequired,
            Self::ExplicitUser | Self::Deny => RadrootsNostrSignerApprovalRequirement::ExplicitUser,
        }
    }
}

impl MycTransportDeliveryPolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Any => "any",
            Self::Quorum => "quorum",
            Self::All => "all",
        }
    }
}

impl MycIdentityBackend {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EncryptedFile => "encrypted_file",
            Self::HostVault => "host_vault",
            Self::ManagedAccount => "managed_account",
            Self::ExternalCommand => "external_command",
            Self::PlaintextFile => "plaintext_file",
        }
    }
}

const MYC_ALLOWED_PROFILES: [MycPathProfile; 3] = [
    MycPathProfile::InteractiveUser,
    MycPathProfile::ServiceHost,
    MycPathProfile::RepoLocal,
];
const MYC_ALLOWED_SHARED_SECRET_BACKENDS: [MycIdentityBackend; 4] = [
    MycIdentityBackend::EncryptedFile,
    MycIdentityBackend::HostVault,
    MycIdentityBackend::ExternalCommand,
    MycIdentityBackend::PlaintextFile,
];
const MYC_RUNTIME_SPECIFIC_CUSTODY_MODES: [&str; 1] = ["managed_account"];
const MYC_DEFAULT_SHARED_SECRET_BACKEND: MycIdentityBackend = MycIdentityBackend::EncryptedFile;
const MYC_HOST_VAULT_POLICY: &str = "desktop";
const MYC_CANONICAL_ROOT_SELECTION: &str = "bootstrap_cli";
const MYC_CANONICAL_SUBORDINATE_PATH_OVERRIDE: &str = "config_document_cli_only";
const MYC_LEAF_PATH_ENV_POSTURE: &str = "forbidden";

impl MycRuntimeContractOutput {
    pub fn for_active_profile(active_profile: MycPathProfile) -> Self {
        Self {
            active_profile,
            allowed_profiles: MYC_ALLOWED_PROFILES.to_vec(),
            default_shared_secret_backend: MYC_DEFAULT_SHARED_SECRET_BACKEND,
            allowed_shared_secret_backends: MYC_ALLOWED_SHARED_SECRET_BACKENDS.to_vec(),
            runtime_specific_custody_modes: MYC_RUNTIME_SPECIFIC_CUSTODY_MODES
                .into_iter()
                .map(str::to_owned)
                .collect(),
            host_vault_policy: Some(MYC_HOST_VAULT_POLICY.to_owned()),
            path_overrides: RadrootsRuntimePathPolicyContract::new(
                MYC_CANONICAL_ROOT_SELECTION,
                MYC_CANONICAL_SUBORDINATE_PATH_OVERRIDE,
                MYC_LEAF_PATH_ENV_POSTURE,
            ),
        }
    }
}

impl MycSignerStateBackend {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::JsonFile => "json_file",
            Self::Sqlite => "sqlite",
        }
    }
}

impl MycRuntimeAuditBackend {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::JsonlFile => "jsonl_file",
            Self::Sqlite => "sqlite",
        }
    }
}

impl MycConfig {
    pub fn allowed_profiles() -> Vec<MycPathProfile> {
        MYC_ALLOWED_PROFILES.to_vec()
    }

    pub fn default_shared_secret_backend() -> MycIdentityBackend {
        MYC_DEFAULT_SHARED_SECRET_BACKEND
    }

    pub fn allowed_shared_secret_backends() -> Vec<MycIdentityBackend> {
        MYC_ALLOWED_SHARED_SECRET_BACKENDS.to_vec()
    }

    pub fn runtime_specific_custody_modes() -> Vec<String> {
        MYC_RUNTIME_SPECIFIC_CUSTODY_MODES
            .into_iter()
            .map(str::to_owned)
            .collect()
    }

    pub fn host_vault_policy() -> Option<String> {
        Some(MYC_HOST_VAULT_POLICY.to_owned())
    }

    pub fn runtime_contract_output(&self) -> MycRuntimeContractOutput {
        MycRuntimeContractOutput::for_active_profile(self.paths.profile)
    }

    fn default_with_path_selection(
        resolver: &RadrootsPathResolver,
        profile: MycPathProfile,
        repo_local_root: Option<&Path>,
    ) -> Result<Self, MycError> {
        let mut config = Self {
            service: MycServiceConfig::default(),
            logging: MycLoggingConfig::default(),
            custody: MycCustodyConfig::default(),
            paths: MycPathsConfig::default_with_path_selection(resolver, profile, repo_local_root)?,
            persistence: MycPersistenceConfig::default(),
            audit: MycAuditConfig::default(),
            observability: MycObservabilityConfig::default(),
            discovery: MycDiscoveryConfig::default(),
            policy: MycPolicyConfig::default(),
            transport: MycTransportConfig::default(),
        };
        crate::paths::apply_path_defaults(&mut config, resolver, &MycPathOverrideFlags::default())?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), MycError> {
        if self.service.instance_name.trim().is_empty() {
            return Err(MycError::InvalidConfig(
                "service.instance_name must not be empty".to_owned(),
            ));
        }

        if self.logging.filter.trim().is_empty() {
            return Err(MycError::InvalidConfig(
                "logging.filter must not be empty".to_owned(),
            ));
        }

        EnvFilter::try_new(self.logging.filter.clone()).map_err(|source| {
            MycError::InvalidLogFilter {
                filter: self.logging.filter.clone(),
                source,
            }
        })?;

        if let Some(output_dir) = self.logging.output_dir.as_ref()
            && output_dir.as_os_str().is_empty()
        {
            return Err(MycError::InvalidConfig(
                "logging.output_dir must not be empty when set".to_owned(),
            ));
        }

        if self.paths.state_dir.as_os_str().is_empty() {
            return Err(MycError::InvalidConfig(
                "paths.state_dir must not be empty".to_owned(),
            ));
        }

        if self.custody.external_command_timeout_secs == 0 {
            return Err(MycError::InvalidConfig(
                "custody.external_command_timeout_secs must be greater than zero".to_owned(),
            ));
        }

        validate_identity_source_config(
            "paths.signer_identity",
            &self.paths.signer_identity_source(),
        )?;
        validate_identity_source_config("paths.user_identity", &self.paths.user_identity_source())?;

        if self.audit.default_read_limit == 0 {
            return Err(MycError::InvalidConfig(
                "audit.default_read_limit must be greater than zero".to_owned(),
            ));
        }

        if self.audit.max_active_file_bytes == 0 {
            return Err(MycError::InvalidConfig(
                "audit.max_active_file_bytes must be greater than zero".to_owned(),
            ));
        }

        if !self.observability.bind_addr.ip().is_loopback() {
            return Err(MycError::InvalidConfig(
                "observability.bind_addr must use a loopback address".to_owned(),
            ));
        }

        self.discovery.validate(&self.transport)?;

        if self.transport.connect_timeout_secs == 0 {
            return Err(MycError::InvalidConfig(
                "transport.connect_timeout_secs must be greater than zero".to_owned(),
            ));
        }

        if self.transport.publish_max_attempts == 0 {
            return Err(MycError::InvalidConfig(
                "transport.publish_max_attempts must be greater than zero".to_owned(),
            ));
        }

        if self.transport.publish_initial_backoff_millis == 0 {
            return Err(MycError::InvalidConfig(
                "transport.publish_initial_backoff_millis must be greater than zero".to_owned(),
            ));
        }

        if self.transport.publish_max_backoff_millis == 0 {
            return Err(MycError::InvalidConfig(
                "transport.publish_max_backoff_millis must be greater than zero".to_owned(),
            ));
        }

        if self.transport.publish_initial_backoff_millis > self.transport.publish_max_backoff_millis
        {
            return Err(MycError::InvalidConfig(
                "transport.publish_max_backoff_millis must be greater than or equal to transport.publish_initial_backoff_millis"
                    .to_owned(),
            ));
        }

        if self.policy.auth_pending_ttl_secs == 0 {
            return Err(MycError::InvalidConfig(
                "policy.auth_pending_ttl_secs must be greater than zero".to_owned(),
            ));
        }
        if self
            .policy
            .auth_authorized_ttl_secs
            .is_some_and(|ttl| ttl == 0)
        {
            return Err(MycError::InvalidConfig(
                "policy.auth_authorized_ttl_secs must be greater than zero when set".to_owned(),
            ));
        }
        if self
            .policy
            .reauth_after_inactivity_secs
            .is_some_and(|ttl| ttl == 0)
        {
            return Err(MycError::InvalidConfig(
                "policy.reauth_after_inactivity_secs must be greater than zero when set".to_owned(),
            ));
        }
        if (self.policy.auth_authorized_ttl_secs.is_some()
            || self.policy.reauth_after_inactivity_secs.is_some())
            && self.policy.auth_url.is_none()
        {
            return Err(MycError::InvalidConfig(
                "policy.auth_url must be set when automatic auth TTL policy is configured"
                    .to_owned(),
            ));
        }
        validate_optional_rate_limit(
            "policy.connect_rate_limit",
            self.policy.connect_rate_limit_window_secs,
            self.policy.connect_rate_limit_max_attempts,
        )?;
        validate_optional_rate_limit(
            "policy.auth_challenge_rate_limit",
            self.policy.auth_challenge_rate_limit_window_secs,
            self.policy.auth_challenge_rate_limit_max_attempts,
        )?;

        let trusted_client_pubkeys =
            normalize_policy_client_pubkeys(&self.policy.trusted_client_pubkeys)?;
        let denied_client_pubkeys =
            normalize_policy_client_pubkeys(&self.policy.denied_client_pubkeys)?;
        let overlap = trusted_client_pubkeys
            .intersection(&denied_client_pubkeys)
            .cloned()
            .collect::<Vec<_>>();
        if !overlap.is_empty() {
            return Err(MycError::InvalidConfig(format!(
                "policy trusted and denied client pubkeys overlap: {}",
                overlap.join(", ")
            )));
        }

        match self.transport.delivery_policy {
            MycTransportDeliveryPolicy::Quorum => {
                let Some(delivery_quorum) = self.transport.delivery_quorum else {
                    return Err(MycError::InvalidConfig(
                        "transport.delivery_quorum must be set when transport.delivery_policy is `quorum`"
                            .to_owned(),
                    ));
                };
                if delivery_quorum == 0 {
                    return Err(MycError::InvalidConfig(
                        "transport.delivery_quorum must be greater than zero".to_owned(),
                    ));
                }
            }
            MycTransportDeliveryPolicy::Any | MycTransportDeliveryPolicy::All => {
                if self.transport.delivery_quorum.is_some() {
                    return Err(MycError::InvalidConfig(
                        "transport.delivery_quorum is only valid when transport.delivery_policy is `quorum`"
                            .to_owned(),
                    ));
                }
            }
        }

        let parsed_relays = self.transport.parse_relays()?;
        if self.transport.enabled && parsed_relays.is_empty() {
            return Err(MycError::InvalidConfig(
                "transport.relays must not be empty when transport.enabled is true".to_owned(),
            ));
        }

        Ok(())
    }
}

fn validate_optional_rate_limit(
    label: &str,
    window_secs: Option<u64>,
    max_attempts: Option<usize>,
) -> Result<(), MycError> {
    match (window_secs, max_attempts) {
        (None, None) => Ok(()),
        (Some(window_secs), Some(max_attempts)) => {
            if window_secs == 0 {
                return Err(MycError::InvalidConfig(format!(
                    "{label}.window_secs must be greater than zero when set"
                )));
            }
            if max_attempts == 0 {
                return Err(MycError::InvalidConfig(format!(
                    "{label}.max_attempts must be greater than zero when set"
                )));
            }
            Ok(())
        }
        _ => Err(MycError::InvalidConfig(format!(
            "{label}.window_secs and {label}.max_attempts must be set together"
        ))),
    }
}

fn normalize_policy_client_pubkeys(values: &[String]) -> Result<BTreeSet<String>, MycError> {
    values
        .iter()
        .map(|value| {
            let public_key = PublicKey::parse(value)
                .or_else(|_| PublicKey::from_hex(value))
                .map_err(|_| {
                    MycError::InvalidConfig(format!(
                        "policy client pubkey `{value}` is not a valid nostr public key"
                    ))
                })?;
            Ok(public_key.to_hex())
        })
        .collect()
}

fn validate_identity_source_config(
    label: &str,
    source: &MycIdentitySourceSpec,
) -> Result<(), MycError> {
    match source.backend {
        MycIdentityBackend::EncryptedFile | MycIdentityBackend::PlaintextFile => {
            let Some(path) = source.path.as_ref() else {
                return Err(MycError::InvalidConfig(format!(
                    "{label}.path must be set when backend is `{}`",
                    source.backend.as_str()
                )));
            };
            if path.as_os_str().is_empty() {
                return Err(MycError::InvalidConfig(format!(
                    "{label}.path must not be empty when backend is `{}`",
                    source.backend.as_str()
                )));
            }
            if source.keyring_account_id.is_some() {
                return Err(MycError::InvalidConfig(format!(
                    "{label}.keyring_account_id must not be set when backend is `{}`",
                    source.backend.as_str()
                )));
            }
            if source.keyring_service_name.is_some() {
                return Err(MycError::InvalidConfig(format!(
                    "{label}.keyring_service_name must not be set when backend is `{}`",
                    source.backend.as_str()
                )));
            }
            if source.profile_path.is_some() {
                return Err(MycError::InvalidConfig(format!(
                    "{label}.profile_path must not be set when backend is `{}`",
                    source.backend.as_str()
                )));
            }
        }
        MycIdentityBackend::ExternalCommand => {
            let Some(path) = source.path.as_ref() else {
                return Err(MycError::InvalidConfig(format!(
                    "{label}.path must be set when backend is `external_command`"
                )));
            };
            if path.as_os_str().is_empty() {
                return Err(MycError::InvalidConfig(format!(
                    "{label}.path must not be empty when backend is `external_command`"
                )));
            }
            if source.keyring_account_id.is_some() {
                return Err(MycError::InvalidConfig(format!(
                    "{label}.keyring_account_id must not be set when backend is `external_command`"
                )));
            }
            if source.keyring_service_name.is_some() {
                return Err(MycError::InvalidConfig(format!(
                    "{label}.keyring_service_name must not be set when backend is `external_command`"
                )));
            }
            if source.profile_path.is_some() {
                return Err(MycError::InvalidConfig(format!(
                    "{label}.profile_path must not be set when backend is `external_command`"
                )));
            }
        }
        MycIdentityBackend::HostVault => {
            let Some(account_id) = source.keyring_account_id.as_deref() else {
                return Err(MycError::InvalidConfig(format!(
                    "{label}.keyring_account_id must be set when backend is `host_vault`"
                )));
            };
            let _ = crate::host_identity::RadrootsIdentityId::parse(account_id).map_err(|_| {
                MycError::InvalidConfig(format!(
                    "{label}.keyring_account_id must be a valid nostr public identity id"
                ))
            })?;
            let Some(service_name) = source.keyring_service_name.as_deref() else {
                return Err(MycError::InvalidConfig(format!(
                    "{label}.keyring_service_name must be set when backend is `host_vault`"
                )));
            };
            if service_name.trim().is_empty() {
                return Err(MycError::InvalidConfig(format!(
                    "{label}.keyring_service_name must not be empty when backend is `host_vault`"
                )));
            }
            if let Some(profile_path) = source.profile_path.as_ref()
                && profile_path.as_os_str().is_empty()
            {
                return Err(MycError::InvalidConfig(format!(
                    "{label}.profile_path must not be empty when set"
                )));
            }
        }
        MycIdentityBackend::ManagedAccount => {
            let Some(path) = source.path.as_ref() else {
                return Err(MycError::InvalidConfig(format!(
                    "{label}.path must be set when backend is `managed_account`"
                )));
            };
            if path.as_os_str().is_empty() {
                return Err(MycError::InvalidConfig(format!(
                    "{label}.path must not be empty when backend is `managed_account`"
                )));
            }
            let Some(service_name) = source.keyring_service_name.as_deref() else {
                return Err(MycError::InvalidConfig(format!(
                    "{label}.keyring_service_name must be set when backend is `managed_account`"
                )));
            };
            if service_name.trim().is_empty() {
                return Err(MycError::InvalidConfig(format!(
                    "{label}.keyring_service_name must not be empty when backend is `managed_account`"
                )));
            }
            if source.keyring_account_id.is_some() {
                return Err(MycError::InvalidConfig(format!(
                    "{label}.keyring_account_id must not be set when backend is `managed_account`"
                )));
            }
            if source.profile_path.is_some() {
                return Err(MycError::InvalidConfig(format!(
                    "{label}.profile_path must not be set when backend is `managed_account`"
                )));
            }
        }
    }

    Ok(())
}

impl MycTransportConfig {
    pub fn parse_relays(&self) -> Result<Vec<RadrootsNostrRelayUrl>, MycError> {
        self.relays
            .iter()
            .map(|value| {
                RadrootsNostrRelayUrl::parse(value).map_err(|source| {
                    MycError::InvalidConfig(format!(
                        "transport.relays contains invalid relay url `{value}`: {source}"
                    ))
                })
            })
            .collect()
    }
}

impl MycDiscoveryConfig {
    pub fn app_identity_source(&self) -> Option<MycIdentitySourceSpec> {
        let backend = match (self.app_identity_backend, self.app_identity_path.as_ref()) {
            (Some(backend), _) => Some(backend),
            (None, Some(_)) => Some(MycIdentityBackend::EncryptedFile),
            (None, None) => None,
        }?;

        Some(MycIdentitySourceSpec {
            backend,
            path: match backend {
                MycIdentityBackend::EncryptedFile
                | MycIdentityBackend::PlaintextFile
                | MycIdentityBackend::ManagedAccount
                | MycIdentityBackend::ExternalCommand => self.app_identity_path.clone(),
                MycIdentityBackend::HostVault => None,
            },
            keyring_account_id: match backend {
                MycIdentityBackend::EncryptedFile
                | MycIdentityBackend::PlaintextFile
                | MycIdentityBackend::ManagedAccount
                | MycIdentityBackend::ExternalCommand => None,
                MycIdentityBackend::HostVault => self.app_identity_keyring_account_id.clone(),
            },
            keyring_service_name: match backend {
                MycIdentityBackend::EncryptedFile
                | MycIdentityBackend::PlaintextFile
                | MycIdentityBackend::ExternalCommand => None,
                MycIdentityBackend::HostVault | MycIdentityBackend::ManagedAccount => {
                    self.app_identity_keyring_service_name.clone()
                }
            },
            profile_path: match backend {
                MycIdentityBackend::EncryptedFile
                | MycIdentityBackend::PlaintextFile
                | MycIdentityBackend::ManagedAccount
                | MycIdentityBackend::ExternalCommand => None,
                MycIdentityBackend::HostVault => self.app_identity_profile_path.clone(),
            },
        })
    }

    pub fn parse_public_relays(&self) -> Result<Vec<RadrootsNostrRelayUrl>, MycError> {
        parse_discovery_relays(&self.public_relays, "discovery.public_relays")
    }

    pub fn parse_publish_relays(&self) -> Result<Vec<RadrootsNostrRelayUrl>, MycError> {
        parse_discovery_relays(&self.publish_relays, "discovery.publish_relays")
    }

    pub fn resolved_public_relays(
        &self,
        transport: &MycTransportConfig,
    ) -> Result<Vec<RadrootsNostrRelayUrl>, MycError> {
        let relays = if self.public_relays.is_empty() {
            transport.parse_relays()?
        } else {
            self.parse_public_relays()?
        };
        Ok(normalize_discovery_relays(relays))
    }

    pub fn resolved_publish_relays(
        &self,
        transport: &MycTransportConfig,
    ) -> Result<Vec<RadrootsNostrRelayUrl>, MycError> {
        let relays = if self.publish_relays.is_empty() {
            self.resolved_public_relays(transport)?
        } else {
            self.parse_publish_relays()?
        };
        Ok(normalize_discovery_relays(relays))
    }

    fn validate(&self, transport: &MycTransportConfig) -> Result<(), MycError> {
        if !self.enabled {
            return Ok(());
        }

        let domain = self.domain.as_deref().ok_or_else(|| {
            MycError::InvalidConfig(
                "discovery.domain must be set when discovery.enabled is true".to_owned(),
            )
        })?;
        validate_discovery_domain(domain)?;

        if self.handler_identifier.trim().is_empty() {
            return Err(MycError::InvalidConfig(
                "discovery.handler_identifier must not be empty when discovery.enabled is true"
                    .to_owned(),
            ));
        }

        if let Some(source) = self.app_identity_source() {
            validate_identity_source_config("discovery.app_identity", &source)?;
        }

        if let Some(template) = self.nostrconnect_url_template.as_deref() {
            validate_nostrconnect_url_template(template)?;
        }

        if let Some(path) = self.nip05_output_path.as_ref()
            && path.as_os_str().is_empty()
        {
            return Err(MycError::InvalidConfig(
                "discovery.nip05_output_path must not be empty".to_owned(),
            ));
        }

        if self.resolved_public_relays(transport)?.is_empty() {
            return Err(MycError::InvalidConfig(
                "discovery requires at least one public relay hint via discovery.public_relays or transport.relays".to_owned(),
            ));
        }

        let _ = self.resolved_publish_relays(transport)?;
        Ok(())
    }
}

fn parse_discovery_relays(
    values: &[String],
    field_name: &str,
) -> Result<Vec<RadrootsNostrRelayUrl>, MycError> {
    values
        .iter()
        .map(|value| {
            RadrootsNostrRelayUrl::parse(value).map_err(|source| {
                MycError::InvalidConfig(format!(
                    "{field_name} contains invalid relay url `{value}`: {source}"
                ))
            })
        })
        .collect()
}

fn normalize_discovery_relays(
    mut relays: Vec<RadrootsNostrRelayUrl>,
) -> Vec<RadrootsNostrRelayUrl> {
    relays.sort_by(|left, right| left.as_str().cmp(right.as_str()));
    relays.dedup_by(|left, right| left.as_str() == right.as_str());
    relays
}

fn validate_discovery_domain(domain: &str) -> Result<(), MycError> {
    let trimmed = domain.trim();
    if trimmed.is_empty()
        || trimmed.contains("://")
        || trimmed.contains('/')
        || trimmed.contains('?')
        || trimmed.contains('#')
        || trimmed.chars().any(char::is_whitespace)
    {
        return Err(MycError::InvalidConfig(format!(
            "discovery.domain must be a bare host name without scheme or path: `{domain}`"
        )));
    }
    Ok(())
}

fn validate_nostrconnect_url_template(template: &str) -> Result<(), MycError> {
    let trimmed = template.trim();
    if trimmed.is_empty() {
        return Err(MycError::InvalidConfig(
            "discovery.nostrconnect_url_template must not be empty when set".to_owned(),
        ));
    }
    if !trimmed.contains("<nostrconnect>") {
        return Err(MycError::InvalidConfig(
            "discovery.nostrconnect_url_template must contain the `<nostrconnect>` placeholder"
                .to_owned(),
        ));
    }
    let candidate = trimmed.replace("<nostrconnect>", "nostrconnect%3A%2F%2Fclient");
    let url = nostr::Url::parse(&candidate).map_err(|source| {
        MycError::InvalidConfig(format!(
            "discovery.nostrconnect_url_template is invalid: {source}"
        ))
    })?;

    match url.scheme() {
        "https" => Ok(()),
        "http" if discovery_host_is_local(url.host_str()) => Ok(()),
        _ => Err(MycError::InvalidConfig(
            "discovery.nostrconnect_url_template must use `https://`, except loopback hosts may use `http://`".to_owned(),
        )),
    }
}

fn discovery_host_is_local(host: Option<&str>) -> bool {
    matches!(host, Some("localhost" | "127.0.0.1" | "::1"))
}

#[cfg(test)]
mod tests {
    use crate::paths::{RadrootsHostEnvironment, RadrootsPathResolver, RadrootsPlatform};

    use super::*;

    fn linux_resolver(home: &str) -> RadrootsPathResolver {
        RadrootsPathResolver::new(
            RadrootsPlatform::Linux,
            RadrootsHostEnvironment {
                home_dir: Some(PathBuf::from(home)),
                ..RadrootsHostEnvironment::default()
            },
        )
    }

    #[test]
    fn default_config_is_stable() {
        let resolver = linux_resolver("/home/treesap");
        let config = MycConfig::default_with_path_selection(
            &resolver,
            MycPathProfile::InteractiveUser,
            None,
        )
        .expect("default config");
        assert_eq!(config.service.instance_name, "myc");
        assert_eq!(config.logging.filter, "info,myc=info");
        assert_eq!(config.paths.profile, MycPathProfile::InteractiveUser);
        assert_eq!(config.paths.repo_local_root, None);
        assert_eq!(
            config.paths.run_dir,
            PathBuf::from("/home/treesap/.radroots/run/services/myc")
        );
        assert_eq!(
            config.logging.output_dir,
            Some(PathBuf::from("/home/treesap/.radroots/logs/services/myc"))
        );
        assert!(config.logging.stdout);
        assert_eq!(
            config.paths.state_dir,
            PathBuf::from("/home/treesap/.radroots/data/services/myc/state")
        );
        assert_eq!(
            config.paths.signer_identity_backend,
            MycIdentityBackend::EncryptedFile
        );
        assert_eq!(
            config.paths.signer_identity_path,
            PathBuf::from("/home/treesap/.radroots/secrets/services/myc/signer-identity.json")
        );
        assert_eq!(config.paths.signer_identity_keyring_account_id, None);
        assert_eq!(
            config.paths.signer_identity_keyring_service_name,
            "org.radroots.myc.signer"
        );
        assert_eq!(config.paths.signer_identity_profile_path, None);
        assert_eq!(
            config.paths.user_identity_backend,
            MycIdentityBackend::EncryptedFile
        );
        assert_eq!(
            config.paths.user_identity_path,
            PathBuf::from("/home/treesap/.radroots/secrets/services/myc/user-identity.json")
        );
        assert_eq!(config.paths.user_identity_keyring_account_id, None);
        assert_eq!(
            config.paths.user_identity_keyring_service_name,
            "org.radroots.myc.user"
        );
        assert_eq!(config.paths.user_identity_profile_path, None);
        assert_eq!(
            config.persistence.signer_state_backend,
            MycSignerStateBackend::JsonFile
        );
        assert_eq!(
            config.persistence.runtime_audit_backend,
            MycRuntimeAuditBackend::JsonlFile
        );
        assert_eq!(
            config.policy.connection_approval,
            MycConnectionApproval::ExplicitUser
        );
        assert!(config.policy.trusted_client_pubkeys.is_empty());
        assert!(config.policy.denied_client_pubkeys.is_empty());
        assert!(config.policy.permission_ceiling.is_empty());
        assert!(config.policy.allowed_sign_event_kinds.is_empty());
        assert!(config.policy.auth_url.is_none());
        assert_eq!(config.policy.auth_pending_ttl_secs, 900);
        assert_eq!(config.policy.auth_authorized_ttl_secs, None);
        assert_eq!(config.policy.reauth_after_inactivity_secs, None);
        assert_eq!(config.policy.connect_rate_limit_window_secs, None);
        assert_eq!(config.policy.connect_rate_limit_max_attempts, None);
        assert_eq!(config.policy.auth_challenge_rate_limit_window_secs, None);
        assert_eq!(config.policy.auth_challenge_rate_limit_max_attempts, None);
        assert_eq!(config.audit.default_read_limit, 200);
        assert_eq!(config.audit.max_active_file_bytes, 262_144);
        assert_eq!(config.audit.max_archived_files, 8);
        assert!(!config.observability.enabled);
        assert_eq!(
            config.observability.bind_addr,
            "127.0.0.1:9460"
                .parse()
                .expect("default observability bind addr")
        );
        assert!(!config.discovery.enabled);
        assert_eq!(config.discovery.handler_identifier, "myc");
        assert!(config.discovery.domain.is_none());
        assert_eq!(config.discovery.app_identity_backend, None);
        assert!(config.discovery.app_identity_path.is_none());
        assert!(config.discovery.public_relays.is_empty());
        assert!(config.discovery.publish_relays.is_empty());
        assert!(config.discovery.nostrconnect_url_template.is_none());
        assert_eq!(
            config.discovery.nip05_output_path,
            Some(PathBuf::from(
                "/home/treesap/.radroots/data/services/myc/public/.well-known/nostr.json"
            ))
        );
        assert!(!config.transport.enabled);
        assert_eq!(config.transport.connect_timeout_secs, 10);
        assert!(config.transport.relays.is_empty());
        assert_eq!(
            config.transport.delivery_policy,
            MycTransportDeliveryPolicy::Any
        );
        assert_eq!(config.transport.delivery_quorum, None);
        assert_eq!(config.transport.publish_max_attempts, 1);
        assert_eq!(config.transport.publish_initial_backoff_millis, 250);
        assert_eq!(config.transport.publish_max_backoff_millis, 2_000);
    }

    #[test]
    fn service_host_profile_uses_canonical_defaults() {
        let resolver = linux_resolver("/home/treesap");
        let config =
            MycConfig::default_with_path_selection(&resolver, MycPathProfile::ServiceHost, None)
                .expect("service-host config");

        assert_eq!(config.paths.profile, MycPathProfile::ServiceHost);
        assert_eq!(
            config.logging.output_dir,
            Some(PathBuf::from("/var/log/radroots/services/myc"))
        );
        assert_eq!(
            config.paths.run_dir,
            PathBuf::from("/run/radroots/services/myc")
        );
        assert_eq!(
            config.paths.state_dir,
            PathBuf::from("/var/lib/radroots/services/myc/state")
        );
        assert_eq!(
            config.paths.signer_identity_path,
            PathBuf::from("/etc/radroots/secrets/services/myc/signer-identity.json")
        );
        assert_eq!(
            config.paths.user_identity_path,
            PathBuf::from("/etc/radroots/secrets/services/myc/user-identity.json")
        );
        assert_eq!(
            config.discovery.nip05_output_path,
            Some(PathBuf::from(
                "/var/lib/radroots/services/myc/public/.well-known/nostr.json"
            ))
        );
    }

    #[test]
    fn repo_local_profile_uses_explicit_repo_local_root() {
        let resolver = linux_resolver("/home/treesap");
        let repo_local_root = PathBuf::from("/repo/.local/radroots/dev/myc");
        let config = MycConfig::default_with_path_selection(
            &resolver,
            MycPathProfile::RepoLocal,
            Some(repo_local_root.as_path()),
        )
        .expect("repo-local config");

        assert_eq!(config.paths.profile, MycPathProfile::RepoLocal);
        assert_eq!(config.paths.repo_local_root, Some(repo_local_root.clone()));
        assert_eq!(
            config.logging.output_dir,
            Some(repo_local_root.join("logs/services/myc"))
        );
        assert_eq!(
            config.paths.run_dir,
            repo_local_root.join("run/services/myc")
        );
        assert_eq!(
            config.paths.state_dir,
            repo_local_root.join("data/services/myc/state")
        );
        assert_eq!(
            config.paths.signer_identity_path,
            repo_local_root.join("secrets/services/myc/signer-identity.json")
        );
        assert_eq!(
            config.paths.user_identity_path,
            repo_local_root.join("secrets/services/myc/user-identity.json")
        );
        assert_eq!(
            config.discovery.nip05_output_path,
            Some(repo_local_root.join("data/services/myc/public/.well-known/nostr.json"))
        );
    }

    #[test]
    fn validate_rejects_enabled_transport_without_relays() {
        let mut config = MycConfig::default();
        config.transport.enabled = true;

        let err = config.validate().expect_err("missing relays");
        assert!(err.to_string().contains("transport.relays"));
    }

    #[test]
    fn validate_rejects_zero_audit_read_limit() {
        let mut config = MycConfig::default();
        config.audit.default_read_limit = 0;

        let err = config.validate().expect_err("invalid audit read limit");
        assert!(err.to_string().contains("audit.default_read_limit"));
    }

    #[test]
    fn validate_rejects_zero_external_command_timeout() {
        let mut config = MycConfig::default();
        config.custody.external_command_timeout_secs = 0;

        let err = config.validate().expect_err("invalid custody timeout");
        assert!(
            err.to_string()
                .contains("custody.external_command_timeout_secs")
        );
    }

    #[test]
    fn validate_rejects_non_loopback_observability_bind_addr() {
        let mut config = MycConfig::default();
        config.observability.enabled = true;
        config.observability.bind_addr = "0.0.0.0:9460"
            .parse()
            .expect("non-loopback observability bind addr");

        let err = config
            .validate()
            .expect_err("non-loopback observability bind addr should be rejected");
        assert!(
            err.to_string()
                .contains("observability.bind_addr must use a loopback address")
        );
    }

    #[test]
    fn discovery_validation_requires_domain_and_relays_when_enabled() {
        let mut config = MycConfig::default();
        config.discovery.enabled = true;
        config.transport.enabled = true;
        config.transport.relays = vec!["wss://relay.example.com".to_owned()];

        let err = config.validate().expect_err("missing discovery domain");
        assert!(err.to_string().contains("discovery.domain"));

        config.discovery.domain = Some("myc.example.com".to_owned());
        config.transport.relays.clear();
        let err = config.validate().expect_err("missing relay hints");
        assert!(err.to_string().contains("at least one public relay hint"));
    }

    #[test]
    fn discovery_validation_allows_localhost_http_nostrconnect_template() {
        let mut config = MycConfig::default();
        config.discovery.enabled = true;
        config.discovery.domain = Some("localhost".to_owned());
        config.discovery.public_relays = vec!["ws://localhost:8080".to_owned()];
        config.discovery.nostrconnect_url_template =
            Some("http://localhost/connect?uri=<nostrconnect>".to_owned());

        config.validate().expect("localhost http template");
    }

    #[test]
    fn discovery_validation_rejects_invalid_nostrconnect_template() {
        let mut config = MycConfig::default();
        config.discovery.enabled = true;
        config.discovery.domain = Some("myc.example.com".to_owned());
        config.discovery.public_relays = vec!["wss://relay.example.com".to_owned()];
        config.discovery.nostrconnect_url_template = Some("http://bad.example.com".to_owned());

        let err = config.validate().expect_err("invalid discovery template");
        assert!(
            err.to_string()
                .contains("discovery.nostrconnect_url_template")
        );
    }

    #[test]
    fn validate_rejects_invalid_delivery_policy_settings() {
        let mut config = MycConfig::default();
        config.transport.enabled = true;
        config.transport.relays = vec!["wss://relay.example.com".to_owned()];
        config.transport.delivery_policy = MycTransportDeliveryPolicy::Quorum;

        let err = config
            .validate()
            .expect_err("missing quorum should be rejected");
        assert!(err.to_string().contains("transport.delivery_quorum"));

        config.transport.delivery_quorum = Some(0);
        let err = config
            .validate()
            .expect_err("zero quorum should be rejected");
        assert!(err.to_string().contains("greater than zero"));

        config.transport.delivery_policy = MycTransportDeliveryPolicy::Any;
        config.transport.delivery_quorum = Some(1);
        let err = config
            .validate()
            .expect_err("quorum on non-quorum policy should be rejected");
        assert!(err.to_string().contains("only valid"));
    }

    #[test]
    fn validate_rejects_invalid_publish_retry_settings() {
        let mut config = MycConfig::default();
        config.transport.publish_max_attempts = 0;
        let err = config.validate().expect_err("zero attempts");
        assert!(err.to_string().contains("publish_max_attempts"));

        config.transport.publish_max_attempts = 1;
        config.transport.publish_initial_backoff_millis = 0;
        let err = config.validate().expect_err("zero initial backoff");
        assert!(err.to_string().contains("publish_initial_backoff_millis"));

        config.transport.publish_initial_backoff_millis = 10;
        config.transport.publish_max_backoff_millis = 0;
        let err = config.validate().expect_err("zero max backoff");
        assert!(err.to_string().contains("publish_max_backoff_millis"));

        config.transport.publish_max_backoff_millis = 5;
        let err = config
            .validate()
            .expect_err("max backoff less than initial");
        assert!(err.to_string().contains("greater than or equal"));
    }

    #[test]
    fn validate_rejects_overlapping_policy_client_lists() {
        let mut config = MycConfig::default();
        config.policy.trusted_client_pubkeys =
            vec!["1111111111111111111111111111111111111111111111111111111111111111".to_owned()];
        config.policy.denied_client_pubkeys =
            vec!["1111111111111111111111111111111111111111111111111111111111111111".to_owned()];

        let err = config
            .validate()
            .expect_err("overlapping policy client lists");
        assert!(err.to_string().contains("overlap"));
    }

    #[test]
    fn validate_requires_auth_url_for_auth_ttl_policy() {
        let mut config = MycConfig::default();
        config.policy.auth_authorized_ttl_secs = Some(60);

        let err = config.validate().expect_err("missing auth url");
        assert!(err.to_string().contains("policy.auth_url"));
    }

    #[test]
    fn validate_requires_complete_rate_limit_pairs() {
        let mut config = MycConfig::default();
        config.policy.connect_rate_limit_window_secs = Some(60);

        let err = config
            .validate()
            .expect_err("incomplete connect rate limit");
        assert!(err.to_string().contains("policy.connect_rate_limit"));

        let mut config = MycConfig::default();
        config.policy.auth_challenge_rate_limit_max_attempts = Some(2);

        let err = config
            .validate()
            .expect_err("incomplete auth challenge rate limit");
        assert!(err.to_string().contains("policy.auth_challenge_rate_limit"));
    }

    #[test]
    fn runtime_contract_output_matches_shared_runtime_contract() {
        let config = MycConfig::default();
        let contract = config.runtime_contract_output();

        assert_eq!(contract.active_profile, MycPathProfile::InteractiveUser);
        assert_eq!(contract.allowed_profiles, MycConfig::allowed_profiles());
        assert_eq!(
            contract.default_shared_secret_backend,
            MycConfig::default_shared_secret_backend()
        );
        assert_eq!(
            contract.allowed_shared_secret_backends,
            MycConfig::allowed_shared_secret_backends()
        );
        assert_eq!(
            contract.runtime_specific_custody_modes,
            MycConfig::runtime_specific_custody_modes()
        );
        assert_eq!(contract.host_vault_policy, MycConfig::host_vault_policy());
        assert_eq!(
            contract.path_overrides.canonical_root_selection,
            "bootstrap_cli"
        );
        assert_eq!(
            contract.path_overrides.canonical_subordinate_path_override,
            "config_document_cli_only"
        );
        assert_eq!(contract.path_overrides.leaf_path_env_posture, "forbidden");
    }
}
