use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::{
    config::{
        MycConfig, MycIdentityBackend, MycIdentitySourceSpec, config_parse_error,
        parse_optional_path_env,
    },
    error::MycError,
};

pub const DEFAULT_ENV_PATH: &str = "config.env";
const DEFAULT_STATE_DIR_NAME: &str = "state";
const DEFAULT_CUSTODY_DIR_NAME: &str = "custody";
const DEFAULT_SIGNER_IDENTITY_FILE_NAME: &str = "signer-identity.json";
const DEFAULT_USER_IDENTITY_FILE_NAME: &str = "user-identity.json";
const DEFAULT_DISCOVERY_APP_IDENTITY_FILE_NAME: &str = "discovery-app-identity.json";
const DEFAULT_SIGNER_MANAGED_ACCOUNT_FILE_NAME: &str = "signer-accounts.json";
const DEFAULT_USER_MANAGED_ACCOUNT_FILE_NAME: &str = "user-accounts.json";
const DEFAULT_DISCOVERY_MANAGED_ACCOUNT_FILE_NAME: &str = "discovery-accounts.json";
const DEFAULT_DISCOVERY_PUBLIC_DIR_NAME: &str = "public";
const DEFAULT_DISCOVERY_NIP05_RELATIVE_PATH: &str = ".well-known/nostr.json";
const MYC_PATHS_PROFILE_ENV: &str = "MYC_PATHS_PROFILE";
const MYC_PATHS_REPO_LOCAL_ROOT_ENV: &str = "MYC_PATHS_REPO_LOCAL_ROOT";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum RadrootsPlatform {
    Linux,
    Macos,
    Windows,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RadrootsHostEnvironment {
    pub home_dir: Option<PathBuf>,
    pub appdata_dir: Option<PathBuf>,
    pub localappdata_dir: Option<PathBuf>,
    pub programdata_dir: Option<PathBuf>,
}

impl RadrootsHostEnvironment {
    fn current() -> Self {
        Self {
            home_dir: std::env::var_os("HOME").map(PathBuf::from),
            appdata_dir: std::env::var_os("APPDATA").map(PathBuf::from),
            localappdata_dir: std::env::var_os("LOCALAPPDATA").map(PathBuf::from),
            programdata_dir: std::env::var_os("PROGRAMDATA").map(PathBuf::from),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum RadrootsPathProfile {
    InteractiveUser,
    ServiceHost,
    RepoLocal,
    MobileNative,
}

#[derive(Debug, Clone)]
pub struct RadrootsPathResolver {
    platform: RadrootsPlatform,
    environment: RadrootsHostEnvironment,
}

impl RadrootsPathResolver {
    pub const fn new(platform: RadrootsPlatform, environment: RadrootsHostEnvironment) -> Self {
        Self {
            platform,
            environment,
        }
    }

    pub fn current() -> Self {
        #[cfg(target_os = "windows")]
        let platform = RadrootsPlatform::Windows;
        #[cfg(target_os = "macos")]
        let platform = RadrootsPlatform::Macos;
        #[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
        let platform = RadrootsPlatform::Linux;
        Self::new(platform, RadrootsHostEnvironment::current())
    }

    fn roots(
        &self,
        profile: RadrootsPathProfile,
        repo_local_root: Option<&Path>,
    ) -> Result<RuntimeRoots, String> {
        match profile {
            RadrootsPathProfile::RepoLocal => repo_local_root
                .map(RuntimeRoots::from_base)
                .ok_or_else(|| "repo_local requires an explicit root".to_owned()),
            RadrootsPathProfile::ServiceHost => match self.platform {
                RadrootsPlatform::Linux | RadrootsPlatform::Macos => Ok(RuntimeRoots {
                    config: PathBuf::from("/etc/radroots"),
                    data: PathBuf::from("/var/lib/radroots"),
                    logs: PathBuf::from("/var/log/radroots"),
                    run: PathBuf::from("/run/radroots"),
                    secrets: PathBuf::from("/etc/radroots/secrets"),
                }),
                RadrootsPlatform::Windows => {
                    let base = self
                        .environment
                        .programdata_dir
                        .as_deref()
                        .ok_or_else(|| "PROGRAMDATA is required".to_owned())?
                        .join("Radroots");
                    Ok(RuntimeRoots::from_base(&base))
                }
            },
            RadrootsPathProfile::InteractiveUser | RadrootsPathProfile::MobileNative => {
                match self.platform {
                    RadrootsPlatform::Linux | RadrootsPlatform::Macos => {
                        let base = self
                            .environment
                            .home_dir
                            .as_deref()
                            .ok_or_else(|| "HOME is required".to_owned())?
                            .join(".radroots");
                        Ok(RuntimeRoots::from_base(&base))
                    }
                    RadrootsPlatform::Windows => {
                        let roaming = self
                            .environment
                            .appdata_dir
                            .as_deref()
                            .ok_or_else(|| "APPDATA is required".to_owned())?
                            .join("Radroots");
                        let local = self
                            .environment
                            .localappdata_dir
                            .as_deref()
                            .ok_or_else(|| "LOCALAPPDATA is required".to_owned())?
                            .join("Radroots");
                        Ok(RuntimeRoots {
                            config: roaming.join("config"),
                            data: local.join("data"),
                            logs: local.join("logs"),
                            run: local.join("run"),
                            secrets: roaming.join("secrets"),
                        })
                    }
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
struct RuntimeRoots {
    config: PathBuf,
    data: PathBuf,
    logs: PathBuf,
    run: PathBuf,
    secrets: PathBuf,
}

impl RuntimeRoots {
    fn from_base(base: &Path) -> Self {
        Self {
            config: base.join("config"),
            data: base.join("data"),
            logs: base.join("logs"),
            run: base.join("run"),
            secrets: base.join("secrets"),
        }
    }

    fn service(self, service: &str) -> Self {
        Self {
            config: self.config.join("services").join(service),
            data: self.data.join("services").join(service),
            logs: self.logs.join("services").join(service),
            run: self.run.join("services").join(service),
            secrets: self.secrets.join("services").join(service),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RadrootsRuntimePathSelection {
    pub profile: RadrootsPathProfile,
    pub repo_local_root: Option<PathBuf>,
}

impl RadrootsRuntimePathSelection {
    pub fn caller(profile: RadrootsPathProfile, repo_local_root: Option<PathBuf>) -> Self {
        Self {
            profile,
            repo_local_root,
        }
    }

    pub fn from_env(
        profile_env: &str,
        root_env: &str,
        default_profile: RadrootsPathProfile,
    ) -> Result<Self, String> {
        let profile = match std::env::var(profile_env).ok().as_deref() {
            None => default_profile,
            Some("interactive_user") => RadrootsPathProfile::InteractiveUser,
            Some("service_host") => RadrootsPathProfile::ServiceHost,
            Some("repo_local") => RadrootsPathProfile::RepoLocal,
            Some(value) => return Err(format!("unknown path profile `{value}`")),
        };
        let repo_local_root = std::env::var_os(root_env)
            .filter(|value| !value.is_empty())
            .map(PathBuf::from);
        if profile == RadrootsPathProfile::RepoLocal && repo_local_root.is_none() {
            return Err(format!("{root_env} is required for repo_local"));
        }
        Ok(Self {
            profile,
            repo_local_root,
        })
    }

    fn resolve_service_roots(
        &self,
        resolver: &RadrootsPathResolver,
        service: &str,
        _profile_env: &str,
        _root_env: &str,
    ) -> Result<RuntimeRoots, String> {
        Ok(resolver
            .roots(self.profile, self.repo_local_root.as_deref())?
            .service(service))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RadrootsRuntimePathPolicyContract {
    pub canonical_root_selection: String,
    pub canonical_subordinate_path_override: String,
    pub leaf_path_env_posture: String,
}

impl RadrootsRuntimePathPolicyContract {
    pub fn new(root: &str, subordinate: &str, leaf: &str) -> Self {
        Self {
            canonical_root_selection: root.to_owned(),
            canonical_subordinate_path_override: subordinate.to_owned(),
            leaf_path_env_posture: leaf.to_owned(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MycPathsConfig {
    pub profile: MycPathProfile,
    pub repo_local_root: Option<PathBuf>,
    pub config_env_path: PathBuf,
    pub run_dir: PathBuf,
    pub state_dir: PathBuf,
    pub signer_identity_backend: MycIdentityBackend,
    pub signer_identity_path: PathBuf,
    pub signer_identity_keyring_account_id: Option<String>,
    pub signer_identity_keyring_service_name: String,
    pub signer_identity_profile_path: Option<PathBuf>,
    pub user_identity_backend: MycIdentityBackend,
    pub user_identity_path: PathBuf,
    pub user_identity_keyring_account_id: Option<String>,
    pub user_identity_keyring_service_name: String,
    pub user_identity_profile_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MycPathProfile {
    #[default]
    InteractiveUser,
    ServiceHost,
    RepoLocal,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MycResolvedRuntimePaths {
    config_env_path: PathBuf,
    logs_dir: PathBuf,
    run_dir: PathBuf,
    state_dir: PathBuf,
    signer_identity_path: PathBuf,
    user_identity_path: PathBuf,
    signer_managed_account_path: PathBuf,
    user_managed_account_path: PathBuf,
    discovery_app_identity_path: PathBuf,
    discovery_managed_account_path: PathBuf,
    discovery_nip05_output_path: PathBuf,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct MycPathOverrideFlags {
    pub(crate) logging_output_dir: bool,
    pub(crate) state_dir: bool,
    pub(crate) signer_identity_path: bool,
    pub(crate) user_identity_path: bool,
    pub(crate) discovery_app_identity_path: bool,
    pub(crate) discovery_nip05_output_path: bool,
}

impl Default for MycPathsConfig {
    fn default() -> Self {
        Self::default_with_path_selection(
            &RadrootsPathResolver::current(),
            MycPathProfile::InteractiveUser,
            None,
        )
        .expect("current process should resolve myc runtime paths")
    }
}

impl MycPathProfile {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InteractiveUser => "interactive_user",
            Self::ServiceHost => "service_host",
            Self::RepoLocal => "repo_local",
        }
    }

    fn into_radroots_profile(self) -> RadrootsPathProfile {
        match self {
            Self::InteractiveUser => RadrootsPathProfile::InteractiveUser,
            Self::ServiceHost => RadrootsPathProfile::ServiceHost,
            Self::RepoLocal => RadrootsPathProfile::RepoLocal,
        }
    }
}

impl MycResolvedRuntimePaths {
    fn resolve(
        resolver: &RadrootsPathResolver,
        profile: MycPathProfile,
        repo_local_root: Option<&Path>,
    ) -> Result<Self, MycError> {
        let selection = RadrootsRuntimePathSelection::caller(
            profile.into_radroots_profile(),
            repo_local_root.map(Path::to_path_buf),
        );
        let namespaced = selection
            .resolve_service_roots(
                resolver,
                "myc",
                MYC_PATHS_PROFILE_ENV,
                MYC_PATHS_REPO_LOCAL_ROOT_ENV,
            )
            .map_err(|error| {
                MycError::InvalidConfig(format!("resolve myc runtime paths: {error}"))
            })?;
        let custody_dir = namespaced.data.join(DEFAULT_CUSTODY_DIR_NAME);
        Ok(Self {
            config_env_path: namespaced.config.join(DEFAULT_ENV_PATH),
            logs_dir: namespaced.logs,
            run_dir: namespaced.run,
            state_dir: namespaced.data.join(DEFAULT_STATE_DIR_NAME),
            signer_identity_path: namespaced.secrets.join(DEFAULT_SIGNER_IDENTITY_FILE_NAME),
            user_identity_path: namespaced.secrets.join(DEFAULT_USER_IDENTITY_FILE_NAME),
            signer_managed_account_path: custody_dir.join(DEFAULT_SIGNER_MANAGED_ACCOUNT_FILE_NAME),
            user_managed_account_path: custody_dir.join(DEFAULT_USER_MANAGED_ACCOUNT_FILE_NAME),
            discovery_app_identity_path: namespaced
                .secrets
                .join(DEFAULT_DISCOVERY_APP_IDENTITY_FILE_NAME),
            discovery_managed_account_path: custody_dir
                .join(DEFAULT_DISCOVERY_MANAGED_ACCOUNT_FILE_NAME),
            discovery_nip05_output_path: namespaced
                .data
                .join(DEFAULT_DISCOVERY_PUBLIC_DIR_NAME)
                .join(DEFAULT_DISCOVERY_NIP05_RELATIVE_PATH),
        })
    }
}

impl MycPathsConfig {
    pub(crate) fn default_with_path_selection(
        resolver: &RadrootsPathResolver,
        profile: MycPathProfile,
        repo_local_root: Option<&Path>,
    ) -> Result<Self, MycError> {
        let resolved = MycResolvedRuntimePaths::resolve(resolver, profile, repo_local_root)?;
        Ok(Self {
            profile,
            repo_local_root: repo_local_root.map(Path::to_path_buf),
            config_env_path: resolved.config_env_path,
            run_dir: resolved.run_dir,
            state_dir: resolved.state_dir,
            signer_identity_backend: MycIdentityBackend::EncryptedFile,
            signer_identity_path: resolved.signer_identity_path,
            signer_identity_keyring_account_id: None,
            signer_identity_keyring_service_name: "org.radroots.myc.signer".to_owned(),
            signer_identity_profile_path: None,
            user_identity_backend: MycIdentityBackend::EncryptedFile,
            user_identity_path: resolved.user_identity_path,
            user_identity_keyring_account_id: None,
            user_identity_keyring_service_name: "org.radroots.myc.user".to_owned(),
            user_identity_profile_path: None,
        })
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

pub(crate) fn process_path_selection() -> Result<(MycPathProfile, Option<PathBuf>), MycError> {
    let selection = RadrootsRuntimePathSelection::from_env(
        MYC_PATHS_PROFILE_ENV,
        MYC_PATHS_REPO_LOCAL_ROOT_ENV,
        RadrootsPathProfile::InteractiveUser,
    )
    .map_err(|error| MycError::InvalidConfig(error.to_string()))?;
    Ok((
        from_radroots_profile(selection.profile),
        selection.repo_local_root,
    ))
}

fn from_radroots_profile(profile: RadrootsPathProfile) -> MycPathProfile {
    match profile {
        RadrootsPathProfile::InteractiveUser => MycPathProfile::InteractiveUser,
        RadrootsPathProfile::ServiceHost => MycPathProfile::ServiceHost,
        RadrootsPathProfile::RepoLocal => MycPathProfile::RepoLocal,
        RadrootsPathProfile::MobileNative => MycPathProfile::InteractiveUser,
    }
}

pub(crate) fn default_env_path_with_path_selection(
    resolver: &RadrootsPathResolver,
    profile: MycPathProfile,
    repo_local_root: Option<&Path>,
) -> Result<PathBuf, MycError> {
    Ok(MycResolvedRuntimePaths::resolve(resolver, profile, repo_local_root)?.config_env_path)
}

pub(crate) fn apply_path_defaults(
    config: &mut MycConfig,
    resolver: &RadrootsPathResolver,
    overrides: &MycPathOverrideFlags,
) -> Result<(), MycError> {
    let resolved = MycResolvedRuntimePaths::resolve(
        resolver,
        config.paths.profile,
        config.paths.repo_local_root.as_deref(),
    )?;
    config.paths.config_env_path = resolved.config_env_path;
    config.paths.run_dir = resolved.run_dir;
    if !overrides.logging_output_dir {
        config.logging.output_dir = Some(resolved.logs_dir);
    }
    if !overrides.state_dir {
        config.paths.state_dir = resolved.state_dir;
    }
    if !overrides.signer_identity_path {
        config.paths.signer_identity_path = match config.paths.signer_identity_backend {
            MycIdentityBackend::EncryptedFile | MycIdentityBackend::PlaintextFile => {
                resolved.signer_identity_path
            }
            MycIdentityBackend::ManagedAccount => resolved.signer_managed_account_path,
            MycIdentityBackend::HostVault => PathBuf::new(),
            MycIdentityBackend::ExternalCommand => PathBuf::new(),
        };
    }
    if !overrides.user_identity_path {
        config.paths.user_identity_path = match config.paths.user_identity_backend {
            MycIdentityBackend::EncryptedFile | MycIdentityBackend::PlaintextFile => {
                resolved.user_identity_path
            }
            MycIdentityBackend::ManagedAccount => resolved.user_managed_account_path,
            MycIdentityBackend::HostVault => PathBuf::new(),
            MycIdentityBackend::ExternalCommand => PathBuf::new(),
        };
    }
    if !overrides.discovery_app_identity_path {
        config.discovery.app_identity_path = match config.discovery.app_identity_backend {
            Some(MycIdentityBackend::EncryptedFile) | Some(MycIdentityBackend::PlaintextFile) => {
                Some(resolved.discovery_app_identity_path)
            }
            Some(MycIdentityBackend::ManagedAccount) => {
                Some(resolved.discovery_managed_account_path)
            }
            Some(MycIdentityBackend::HostVault) | None => None,
            Some(MycIdentityBackend::ExternalCommand) => None,
        };
    }
    if !overrides.discovery_nip05_output_path {
        config.discovery.nip05_output_path = Some(resolved.discovery_nip05_output_path);
    }
    Ok(())
}

pub(crate) fn path_selection_from_entries(
    entries: &[(String, String, usize)],
    path: &Path,
) -> Result<(MycPathProfile, Option<PathBuf>), MycError> {
    let mut profile = MycPathProfile::InteractiveUser;
    let mut repo_local_root = None;
    for (key, value, line_number) in entries {
        match key.as_str() {
            MYC_PATHS_PROFILE_ENV => {
                profile = parse_path_profile_env(key, value, path, *line_number)?;
            }
            MYC_PATHS_REPO_LOCAL_ROOT_ENV => {
                repo_local_root = parse_optional_path_env(value);
            }
            _ => {}
        }
    }
    Ok((profile, repo_local_root))
}

pub(crate) fn parse_path_profile_env(
    key: &str,
    value: &str,
    path: &Path,
    line_number: usize,
) -> Result<MycPathProfile, MycError> {
    match value {
        "interactive_user" => Ok(MycPathProfile::InteractiveUser),
        "service_host" => Ok(MycPathProfile::ServiceHost),
        "repo_local" => Ok(MycPathProfile::RepoLocal),
        _ => Err(config_parse_error(
            path,
            line_number,
            format!("{key} must be `interactive_user`, `service_host`, or `repo_local`"),
        )),
    }
}
