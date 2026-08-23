//! One-pass command-line admission for the hardened Myc command contract.

use std::error::Error;
use std::ffi::OsString;
use std::fmt;
use std::num::NonZeroU64;
use std::path::{Component, Path, PathBuf};

use clap::{Parser, Subcommand, ValueEnum};
use radroots_runtime_paths::InstanceId;
use radroots_service_host::AdminOperationId;
use radroots_service_sqlite::BackupManifestSha256;

/// The exact bootstrap profile selected by the operator.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MycBootstrapProfileV1 {
    ServiceHost,
    Interactive,
    RepoLocal,
}

/// The only two governed command-result encodings.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MycCliOutputModeV1 {
    #[default]
    Human,
    Json,
}

/// The exact governed top-level Myc command inventory.
#[derive(PartialEq, Eq)]
pub enum MycCommandV1 {
    Run,
    Config(MycConfigCommandV1),
    State(MycStateCommandV1),
    Identity(MycIdentityCommandV1),
    Status,
    Doctor,
}

/// Governed configuration commands.
#[derive(PartialEq, Eq)]
pub enum MycConfigCommandV1 {
    Init,
    Validate,
    Show,
    Schema,
    Apply(MycConfigApplyArgsV1),
}

/// Governed state commands.
#[derive(PartialEq, Eq)]
pub enum MycStateCommandV1 {
    Init,
    Status,
    Backup(MycStateBackupArgsV1),
    Restore(MycStateRestoreArgsV1),
    Verify,
    Migrate,
}

/// Governed identity commands.
#[derive(PartialEq, Eq)]
pub enum MycIdentityCommandV1 {
    Init(MycIdentityCommandArgsV1),
    Status(MycIdentityCommandArgsV1),
    ExportPublic(MycIdentityCommandArgsV1),
}

/// Exact offline configuration-apply input.
#[derive(PartialEq, Eq)]
pub struct MycConfigApplyArgsV1 {
    candidate_config: PathBuf,
}

impl MycConfigApplyArgsV1 {
    #[must_use]
    pub fn candidate_config(&self) -> &Path {
        &self.candidate_config
    }
}

impl fmt::Debug for MycConfigApplyArgsV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MycConfigApplyArgsV1([redacted])")
    }
}

/// Exact online-or-offline state-backup input.
#[derive(PartialEq, Eq)]
pub struct MycStateBackupArgsV1 {
    operation_id: Box<str>,
    target: PathBuf,
    expected_generation: u64,
}

impl MycStateBackupArgsV1 {
    #[must_use]
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    #[must_use]
    pub fn target(&self) -> &Path {
        &self.target
    }

    #[must_use]
    pub const fn expected_generation(&self) -> u64 {
        self.expected_generation
    }
}

impl fmt::Debug for MycStateBackupArgsV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MycStateBackupArgsV1")
            .field("operation_id", &"[redacted]")
            .field("target", &"[redacted]")
            .field("expected_generation", &self.expected_generation)
            .finish()
    }
}

/// Exact offline restore-verification input.
#[derive(PartialEq, Eq)]
pub struct MycStateRestoreArgsV1 {
    manifest: PathBuf,
    manifest_sha256: BackupManifestSha256,
    bundle: PathBuf,
    maximum_state_bytes: NonZeroU64,
}

impl MycStateRestoreArgsV1 {
    #[must_use]
    pub fn manifest(&self) -> &Path {
        &self.manifest
    }

    #[must_use]
    pub const fn manifest_sha256(&self) -> BackupManifestSha256 {
        self.manifest_sha256
    }

    #[must_use]
    pub fn bundle(&self) -> &Path {
        &self.bundle
    }

    #[must_use]
    pub const fn maximum_state_bytes(&self) -> NonZeroU64 {
        self.maximum_state_bytes
    }
}

impl fmt::Debug for MycStateRestoreArgsV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MycStateRestoreArgsV1([redacted])")
    }
}

/// Role input required by every identity command.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MycIdentityCommandArgsV1 {
    role: crate::MycProviderRole,
}

impl MycIdentityCommandArgsV1 {
    #[must_use]
    pub const fn role(self) -> crate::MycProviderRole {
        self.role
    }
}

impl fmt::Debug for MycCommandV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Run => "MycCommandV1::Run",
            Self::Config(_) => "MycCommandV1::Config([redacted])",
            Self::State(_) => "MycCommandV1::State([redacted])",
            Self::Identity(_) => "MycCommandV1::Identity([redacted])",
            Self::Status => "MycCommandV1::Status",
            Self::Doctor => "MycCommandV1::Doctor",
        })
    }
}

/// The only three process authorities selected by the hardened CLI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MycCliPrimaryAuthorityV1 {
    Daemon,
    Offline,
    LiveUnixAdmin,
}

/// The closed offline operation classes selected before any state access.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MycCliOfflineOperationV1 {
    Config,
    StateExclusive,
    StateReadOnly,
    IdentityExclusive,
    IdentityReadOnly,
    Doctor,
}

/// The closed Unix-admin operations reachable from the command inventory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MycCliAdminOperationV1 {
    Status,
    StateStatus,
    StateBackup,
    IdentityStatus,
    IdentityPublic,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl MycCliAdminOperationV1 {
    /// Returns the exact native Unix-admin route selected by this operation.
    #[must_use]
    pub const fn route(self) -> crate::MycAdminRoute {
        match self {
            Self::Status => crate::MycAdminRoute::Status,
            Self::StateStatus => crate::MycAdminRoute::StateStatus,
            Self::StateBackup => crate::MycAdminRoute::StateBackup,
            Self::IdentityStatus => crate::MycAdminRoute::IdentityStatus,
            Self::IdentityPublic => crate::MycAdminRoute::IdentityPublic,
        }
    }
}

/// A sealed, side-effect-free execution plan for one admitted CLI invocation.
///
/// Construction is owned by [`plan_myc_cli_v1`]. A live mutation never carries
/// an offline fallback, while explicitly read-only status, backup, and public
/// identity operations may fall back only after later execution proves the
/// daemon writer lock is free.
///
/// ```compile_fail
/// use myc::{MycCliExecutionPlanV1, MycCliPrimaryAuthorityV1};
///
/// let _ = MycCliExecutionPlanV1 {
///     primary_authority: MycCliPrimaryAuthorityV1::Offline,
///     offline_operation: None,
///     admin_operation: None,
///     daemon_unavailable_offline_fallback: true,
/// };
/// ```
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MycCliExecutionPlanV1 {
    primary_authority: MycCliPrimaryAuthorityV1,
    offline_operation: Option<MycCliOfflineOperationV1>,
    admin_operation: Option<MycCliAdminOperationV1>,
    daemon_unavailable_offline_fallback: bool,
}

impl MycCliExecutionPlanV1 {
    /// Returns the authority that must be attempted first.
    #[must_use]
    pub const fn primary_authority(&self) -> MycCliPrimaryAuthorityV1 {
        self.primary_authority
    }

    /// Returns the bounded offline operation, when the plan admits one.
    #[must_use]
    pub const fn offline_operation(&self) -> Option<MycCliOfflineOperationV1> {
        self.offline_operation
    }

    /// Returns the bounded Unix-admin operation, when the plan admits one.
    #[must_use]
    pub const fn admin_operation(&self) -> Option<MycCliAdminOperationV1> {
        self.admin_operation
    }

    /// Returns whether a missing daemon may fall back to read-only offline work.
    #[must_use]
    pub const fn allows_daemon_unavailable_offline_fallback(&self) -> bool {
        self.daemon_unavailable_offline_fallback
    }
}

impl fmt::Debug for MycCliExecutionPlanV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MycCliExecutionPlanV1")
            .field("primary_authority", &self.primary_authority)
            .field("offline_operation", &self.offline_operation)
            .field("admin_operation", &self.admin_operation)
            .field(
                "daemon_unavailable_offline_fallback",
                &self.daemon_unavailable_offline_fallback,
            )
            .finish()
    }
}

/// Stable source-free classification for command-line admission failures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MycCliV1ErrorKind {
    InvalidArguments,
    InvalidInstance,
    InvalidRepoLocalRoot,
    UnexpectedRepoLocalRoot,
    InvalidConfigPath,
    InvalidCommandInput,
}

impl MycCliV1ErrorKind {
    const fn message(self) -> &'static str {
        match self {
            Self::InvalidArguments => "command-line arguments are invalid",
            Self::InvalidInstance => "instance identifier is invalid",
            Self::InvalidRepoLocalRoot => "repo-local profile requires a valid absolute root",
            Self::UnexpectedRepoLocalRoot => {
                "repo-local root is forbidden outside the repo-local profile"
            }
            Self::InvalidConfigPath => "configuration path must be absolute without traversal",
            Self::InvalidCommandInput => "command input is invalid",
        }
    }
}

/// One safe command-line admission failure.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MycCliV1Error {
    kind: MycCliV1ErrorKind,
}

impl MycCliV1Error {
    const fn new(kind: MycCliV1ErrorKind) -> Self {
        Self { kind }
    }

    /// Returns the stable failure classification.
    #[must_use]
    pub const fn kind(self) -> MycCliV1ErrorKind {
        self.kind
    }
}

impl fmt::Debug for MycCliV1Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MycCliV1Error")
            .field("kind", &self.kind)
            .finish()
    }
}

impl fmt::Display for MycCliV1Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.kind.message())
    }
}

impl Error for MycCliV1Error {}

/// A validated one-pass Myc bootstrap and command selection.
pub struct MycCliInvocationV1 {
    profile: MycBootstrapProfileV1,
    instance: InstanceId,
    repo_local_root: Option<PathBuf>,
    config_path: Option<PathBuf>,
    output_mode: MycCliOutputModeV1,
    command: MycCommandV1,
}

impl MycCliInvocationV1 {
    /// Returns the explicitly selected bootstrap profile.
    #[must_use]
    pub const fn profile(&self) -> MycBootstrapProfileV1 {
        self.profile
    }

    /// Returns the validated instance identifier.
    #[must_use]
    pub fn instance(&self) -> &InstanceId {
        &self.instance
    }

    /// Returns the explicit repo-local root, when selected.
    #[must_use]
    pub fn repo_local_root(&self) -> Option<&Path> {
        self.repo_local_root.as_deref()
    }

    /// Returns the optional explicit configuration path.
    #[must_use]
    pub fn config_path(&self) -> Option<&Path> {
        self.config_path.as_deref()
    }

    /// Returns the exact result encoding selected once at admission.
    #[must_use]
    pub const fn output_mode(&self) -> MycCliOutputModeV1 {
        self.output_mode
    }

    /// Returns the exact governed command selection.
    #[must_use]
    pub const fn command(&self) -> &MycCommandV1 {
        &self.command
    }
}

impl fmt::Debug for MycCliInvocationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MycCliInvocationV1")
            .field("profile", &self.profile)
            .field("instance", &"[redacted]")
            .field(
                "repo_local_root",
                &self.repo_local_root.as_ref().map(|_| "[redacted]"),
            )
            .field(
                "config_path",
                &self.config_path.as_ref().map(|_| "[redacted]"),
            )
            .field("output_mode", &self.output_mode)
            .field("command", &self.command)
            .finish()
    }
}

/// Parses the exact hardened Myc bootstrap and command tree once.
///
/// The iterator must include the program name as its first element. Clap's
/// dependency-owned diagnostic is deliberately discarded so caller-controlled
/// argument text cannot escape through this crate's stable error boundary.
pub fn parse_myc_cli_v1_from<I, T>(arguments: I) -> Result<MycCliInvocationV1, MycCliV1Error>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let parsed = RawMycCliV1::try_parse_from(arguments)
        .map_err(|_| MycCliV1Error::new(MycCliV1ErrorKind::InvalidArguments))?;
    let profile = parsed
        .profile
        .ok_or_else(|| MycCliV1Error::new(MycCliV1ErrorKind::InvalidArguments))?
        .into();
    let instance = parsed
        .instance
        .ok_or_else(|| MycCliV1Error::new(MycCliV1ErrorKind::InvalidArguments))?;
    let instance = InstanceId::new(instance)
        .map_err(|_| MycCliV1Error::new(MycCliV1ErrorKind::InvalidInstance))?;
    validate_bootstrap_paths(
        profile,
        parsed.repo_local_root.as_deref(),
        parsed.config.as_deref(),
    )?;

    Ok(MycCliInvocationV1 {
        profile,
        instance,
        repo_local_root: parsed.repo_local_root,
        config_path: parsed.config,
        output_mode: parsed.output.into(),
        command: admit_command(parsed.command)?,
    })
}

/// Selects the sole permitted execution authority for an admitted command.
///
/// This function performs no filesystem, database, socket, environment, task,
/// or process work. Later executors consume the plan without reparsing process
/// arguments. In particular, no live command receives direct SQLite authority.
#[must_use]
pub const fn plan_myc_cli_v1(invocation: &MycCliInvocationV1) -> MycCliExecutionPlanV1 {
    match &invocation.command {
        MycCommandV1::Run => daemon_plan(),
        MycCommandV1::Config(_) => offline_plan(MycCliOfflineOperationV1::Config),
        MycCommandV1::State(MycStateCommandV1::Init)
        | MycCommandV1::State(MycStateCommandV1::Restore(_))
        | MycCommandV1::State(MycStateCommandV1::Verify)
        | MycCommandV1::State(MycStateCommandV1::Migrate) => {
            offline_plan(MycCliOfflineOperationV1::StateExclusive)
        }
        MycCommandV1::State(MycStateCommandV1::Status) => read_only_admin_plan(
            MycCliAdminOperationV1::StateStatus,
            MycCliOfflineOperationV1::StateReadOnly,
        ),
        MycCommandV1::State(MycStateCommandV1::Backup(_)) => read_only_admin_plan(
            MycCliAdminOperationV1::StateBackup,
            MycCliOfflineOperationV1::StateReadOnly,
        ),
        MycCommandV1::Identity(MycIdentityCommandV1::Init(_)) => {
            offline_plan(MycCliOfflineOperationV1::IdentityExclusive)
        }
        MycCommandV1::Identity(MycIdentityCommandV1::Status(_)) => read_only_admin_plan(
            MycCliAdminOperationV1::IdentityStatus,
            MycCliOfflineOperationV1::IdentityReadOnly,
        ),
        MycCommandV1::Identity(MycIdentityCommandV1::ExportPublic(_)) => read_only_admin_plan(
            MycCliAdminOperationV1::IdentityPublic,
            MycCliOfflineOperationV1::IdentityReadOnly,
        ),
        MycCommandV1::Status => read_only_admin_plan(
            MycCliAdminOperationV1::Status,
            MycCliOfflineOperationV1::StateReadOnly,
        ),
        MycCommandV1::Doctor => offline_plan(MycCliOfflineOperationV1::Doctor),
    }
}

const fn daemon_plan() -> MycCliExecutionPlanV1 {
    MycCliExecutionPlanV1 {
        primary_authority: MycCliPrimaryAuthorityV1::Daemon,
        offline_operation: None,
        admin_operation: None,
        daemon_unavailable_offline_fallback: false,
    }
}

const fn offline_plan(operation: MycCliOfflineOperationV1) -> MycCliExecutionPlanV1 {
    MycCliExecutionPlanV1 {
        primary_authority: MycCliPrimaryAuthorityV1::Offline,
        offline_operation: Some(operation),
        admin_operation: None,
        daemon_unavailable_offline_fallback: false,
    }
}

const fn read_only_admin_plan(
    admin_operation: MycCliAdminOperationV1,
    offline_operation: MycCliOfflineOperationV1,
) -> MycCliExecutionPlanV1 {
    MycCliExecutionPlanV1 {
        primary_authority: MycCliPrimaryAuthorityV1::LiveUnixAdmin,
        offline_operation: Some(offline_operation),
        admin_operation: Some(admin_operation),
        daemon_unavailable_offline_fallback: true,
    }
}

fn validate_bootstrap_paths(
    profile: MycBootstrapProfileV1,
    repo_local_root: Option<&Path>,
    config_path: Option<&Path>,
) -> Result<(), MycCliV1Error> {
    match (profile, repo_local_root) {
        (MycBootstrapProfileV1::RepoLocal, Some(root)) if valid_absolute_path(root, true) => {}
        (MycBootstrapProfileV1::RepoLocal, _) => {
            return Err(MycCliV1Error::new(MycCliV1ErrorKind::InvalidRepoLocalRoot));
        }
        (_, Some(_)) => {
            return Err(MycCliV1Error::new(
                MycCliV1ErrorKind::UnexpectedRepoLocalRoot,
            ));
        }
        (_, None) => {}
    }

    if config_path.is_some_and(|path| !valid_absolute_path(path, true)) {
        return Err(MycCliV1Error::new(MycCliV1ErrorKind::InvalidConfigPath));
    }
    Ok(())
}

fn valid_absolute_path(path: &Path, require_non_root: bool) -> bool {
    path.is_absolute()
        && (!require_non_root || path.parent().is_some())
        && path
            .to_str()
            .is_some_and(|value| !value.is_empty() && value.len() <= 4_096)
        && !path
            .components()
            .any(|component| matches!(component, Component::ParentDir))
}

#[derive(Parser)]
#[command(name = "myc", disable_help_subcommand = true)]
struct RawMycCliV1 {
    #[arg(long, global = true, value_enum)]
    profile: Option<RawProfile>,
    #[arg(long, global = true)]
    instance: Option<String>,
    #[arg(long = "repo-local-root", global = true)]
    repo_local_root: Option<PathBuf>,
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    #[arg(long, global = true, value_enum, default_value_t = RawOutputMode::Human)]
    output: RawOutputMode,
    #[command(subcommand)]
    command: RawCommand,
}

#[derive(Clone, Copy, ValueEnum)]
enum RawProfile {
    ServiceHost,
    Interactive,
    RepoLocal,
}

#[derive(Clone, Copy, Default, ValueEnum)]
enum RawOutputMode {
    #[default]
    Human,
    Json,
}

impl From<RawOutputMode> for MycCliOutputModeV1 {
    fn from(value: RawOutputMode) -> Self {
        match value {
            RawOutputMode::Human => Self::Human,
            RawOutputMode::Json => Self::Json,
        }
    }
}

impl From<RawProfile> for MycBootstrapProfileV1 {
    fn from(value: RawProfile) -> Self {
        match value {
            RawProfile::ServiceHost => Self::ServiceHost,
            RawProfile::Interactive => Self::Interactive,
            RawProfile::RepoLocal => Self::RepoLocal,
        }
    }
}

#[derive(Subcommand)]
enum RawCommand {
    Run,
    Config {
        #[command(subcommand)]
        command: RawConfigCommand,
    },
    State {
        #[command(subcommand)]
        command: RawStateCommand,
    },
    Identity {
        #[command(subcommand)]
        command: RawIdentityCommand,
    },
    Status,
    Doctor,
}

#[derive(Subcommand)]
enum RawConfigCommand {
    Init,
    Validate,
    Show,
    Schema,
    Apply {
        #[arg(long = "candidate-config")]
        candidate_config: PathBuf,
    },
}

#[derive(Subcommand)]
enum RawStateCommand {
    Init,
    Status,
    Backup {
        #[arg(long = "operation-id")]
        operation_id: String,
        #[arg(long)]
        target: PathBuf,
        #[arg(long = "expected-generation")]
        expected_generation: u64,
        #[arg(long, required = true)]
        confirm: bool,
    },
    Restore {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long = "manifest-sha256")]
        manifest_sha256: String,
        #[arg(long)]
        bundle: PathBuf,
        #[arg(long = "maximum-state-bytes")]
        maximum_state_bytes: u64,
        #[arg(long, required = true)]
        confirm: bool,
    },
    Verify,
    Migrate,
}

#[derive(Subcommand)]
enum RawIdentityCommand {
    Init {
        #[arg(long, value_enum)]
        role: RawIdentityRole,
    },
    Status {
        #[arg(long, value_enum)]
        role: RawIdentityRole,
    },
    ExportPublic {
        #[arg(long, value_enum)]
        role: RawIdentityRole,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum RawIdentityRole {
    Transport,
    User,
    Discovery,
}

impl From<RawIdentityRole> for crate::MycProviderRole {
    fn from(value: RawIdentityRole) -> Self {
        match value {
            RawIdentityRole::Transport => Self::Transport,
            RawIdentityRole::User => Self::User,
            RawIdentityRole::Discovery => Self::Discovery,
        }
    }
}

fn admit_command(command: RawCommand) -> Result<MycCommandV1, MycCliV1Error> {
    let invalid = || MycCliV1Error::new(MycCliV1ErrorKind::InvalidCommandInput);
    Ok(match command {
        RawCommand::Run => MycCommandV1::Run,
        RawCommand::Config { command } => MycCommandV1::Config(match command {
            RawConfigCommand::Init => MycConfigCommandV1::Init,
            RawConfigCommand::Validate => MycConfigCommandV1::Validate,
            RawConfigCommand::Show => MycConfigCommandV1::Show,
            RawConfigCommand::Schema => MycConfigCommandV1::Schema,
            RawConfigCommand::Apply { candidate_config } => {
                if !valid_absolute_path(&candidate_config, true) {
                    return Err(invalid());
                }
                MycConfigCommandV1::Apply(MycConfigApplyArgsV1 { candidate_config })
            }
        }),
        RawCommand::State { command } => MycCommandV1::State(match command {
            RawStateCommand::Init => MycStateCommandV1::Init,
            RawStateCommand::Status => MycStateCommandV1::Status,
            RawStateCommand::Backup {
                operation_id,
                target,
                expected_generation,
                confirm,
            } => {
                if !confirm || !valid_absolute_path(&target, true) {
                    return Err(invalid());
                }
                let operation_id = AdminOperationId::new(operation_id).map_err(|_| invalid())?;
                MycStateCommandV1::Backup(MycStateBackupArgsV1 {
                    operation_id: operation_id.as_str().into(),
                    target,
                    expected_generation,
                })
            }
            RawStateCommand::Restore {
                manifest,
                manifest_sha256,
                bundle,
                maximum_state_bytes,
                confirm,
            } => {
                if !confirm
                    || !valid_absolute_path(&manifest, true)
                    || !valid_absolute_path(&bundle, true)
                {
                    return Err(invalid());
                }
                if manifest_sha256.len() != 64
                    || manifest_sha256
                        .bytes()
                        .any(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
                {
                    return Err(invalid());
                }
                let mut digest = [0_u8; 32];
                hex::decode_to_slice(manifest_sha256, &mut digest).map_err(|_| invalid())?;
                let maximum_state_bytes =
                    NonZeroU64::new(maximum_state_bytes).ok_or_else(invalid)?;
                MycStateCommandV1::Restore(MycStateRestoreArgsV1 {
                    manifest,
                    manifest_sha256: BackupManifestSha256::from_bytes(digest),
                    bundle,
                    maximum_state_bytes,
                })
            }
            RawStateCommand::Verify => MycStateCommandV1::Verify,
            RawStateCommand::Migrate => MycStateCommandV1::Migrate,
        }),
        RawCommand::Identity { command } => MycCommandV1::Identity(match command {
            RawIdentityCommand::Init { role } => {
                MycIdentityCommandV1::Init(MycIdentityCommandArgsV1 { role: role.into() })
            }
            RawIdentityCommand::Status { role } => {
                MycIdentityCommandV1::Status(MycIdentityCommandArgsV1 { role: role.into() })
            }
            RawIdentityCommand::ExportPublic { role } => {
                MycIdentityCommandV1::ExportPublic(MycIdentityCommandArgsV1 { role: role.into() })
            }
        }),
        RawCommand::Status => MycCommandV1::Status,
        RawCommand::Doctor => MycCommandV1::Doctor,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(command: &[&str]) -> Result<MycCliInvocationV1, MycCliV1Error> {
        let mut arguments = vec!["myc", "--profile", "service-host", "--instance", "primary"];
        arguments.extend_from_slice(command);
        parse_myc_cli_v1_from(arguments)
    }

    #[test]
    fn exact_command_inventory_parses() {
        let vectors = [
            (&["run"][..], "run"),
            (&["config", "init"][..], "config_init"),
            (&["config", "validate"][..], "config_validate"),
            (&["config", "show"][..], "config_show"),
            (&["config", "schema"][..], "config_schema"),
            (
                &["config", "apply", "--candidate-config", "/candidate.toml"][..],
                "config_apply",
            ),
            (&["state", "init"][..], "state_init"),
            (&["state", "status"][..], "state_status"),
            (
                &[
                    "state",
                    "backup",
                    "--operation-id",
                    "backup-01",
                    "--target",
                    "/backup/new",
                    "--expected-generation",
                    "7",
                    "--confirm",
                ][..],
                "state_backup",
            ),
            (
                &[
                    "state",
                    "restore",
                    "--manifest",
                    "/backup/manifest.json",
                    "--manifest-sha256",
                    "1111111111111111111111111111111111111111111111111111111111111111",
                    "--bundle",
                    "/backup/bundle",
                    "--maximum-state-bytes",
                    "1048576",
                    "--confirm",
                ][..],
                "state_restore",
            ),
            (&["state", "verify"][..], "state_verify"),
            (&["state", "migrate"][..], "state_migrate"),
            (
                &["identity", "init", "--role", "transport"][..],
                "identity_init",
            ),
            (
                &["identity", "status", "--role", "user"][..],
                "identity_status",
            ),
            (
                &["identity", "export-public", "--role", "discovery"][..],
                "identity_export_public",
            ),
            (&["status"][..], "status"),
            (&["doctor"][..], "doctor"),
        ];
        for (arguments, expected) in vectors {
            assert_eq!(
                command_name(parse(arguments).expect("command").command()),
                expected
            );
        }
    }

    fn command_name(command: &MycCommandV1) -> &'static str {
        match command {
            MycCommandV1::Run => "run",
            MycCommandV1::Config(MycConfigCommandV1::Init) => "config_init",
            MycCommandV1::Config(MycConfigCommandV1::Validate) => "config_validate",
            MycCommandV1::Config(MycConfigCommandV1::Show) => "config_show",
            MycCommandV1::Config(MycConfigCommandV1::Schema) => "config_schema",
            MycCommandV1::Config(MycConfigCommandV1::Apply(_)) => "config_apply",
            MycCommandV1::State(MycStateCommandV1::Init) => "state_init",
            MycCommandV1::State(MycStateCommandV1::Status) => "state_status",
            MycCommandV1::State(MycStateCommandV1::Backup(_)) => "state_backup",
            MycCommandV1::State(MycStateCommandV1::Restore(_)) => "state_restore",
            MycCommandV1::State(MycStateCommandV1::Verify) => "state_verify",
            MycCommandV1::State(MycStateCommandV1::Migrate) => "state_migrate",
            MycCommandV1::Identity(MycIdentityCommandV1::Init(_)) => "identity_init",
            MycCommandV1::Identity(MycIdentityCommandV1::Status(_)) => "identity_status",
            MycCommandV1::Identity(MycIdentityCommandV1::ExportPublic(_)) => {
                "identity_export_public"
            }
            MycCommandV1::Status => "status",
            MycCommandV1::Doctor => "doctor",
        }
    }

    #[test]
    fn profiles_and_paths_are_cross_bound() {
        for profile in ["service-host", "interactive"] {
            let invocation = parse_myc_cli_v1_from([
                "myc",
                "--profile",
                profile,
                "--instance",
                "north-01",
                "--config",
                "/etc/radroots/myc.toml",
                "run",
            ])
            .expect("production profile");
            assert_eq!(invocation.instance().as_str(), "north-01");
            assert_eq!(
                invocation.config_path(),
                Some(Path::new("/etc/radroots/myc.toml"))
            );
            assert!(invocation.repo_local_root().is_none());
        }

        let repo_local = parse_myc_cli_v1_from([
            "myc",
            "--profile",
            "repo-local",
            "--instance",
            "dev",
            "--repo-local-root",
            "/repo/radroots",
            "config",
            "validate",
        ])
        .expect("repo local");
        assert_eq!(repo_local.profile(), MycBootstrapProfileV1::RepoLocal);
        assert_eq!(
            repo_local.repo_local_root(),
            Some(Path::new("/repo/radroots"))
        );
    }

    #[test]
    fn invalid_bootstrap_values_fail_with_stable_kinds() {
        for value in ["Upper", "north-", "north.west"] {
            let error = parse_myc_cli_v1_from([
                "myc",
                "--profile",
                "service-host",
                "--instance",
                value,
                "run",
            ])
            .expect_err("invalid instance");
            assert_eq!(error.kind(), MycCliV1ErrorKind::InvalidInstance);
        }
        assert_eq!(
            parse_myc_cli_v1_from([
                "myc",
                "--profile",
                "service-host",
                "--instance=-north",
                "run",
            ])
            .expect_err("invalid instance boundary")
            .kind(),
            MycCliV1ErrorKind::InvalidInstance
        );
        assert_eq!(
            parse_myc_cli_v1_from(["myc", "--profile", "service-host", "--instance=", "run",])
                .expect_err("empty instance")
                .kind(),
            MycCliV1ErrorKind::InvalidInstance
        );
        let exact = "a".repeat(radroots_runtime_paths::INSTANCE_ID_MAX_BYTES);
        assert!(
            parse_myc_cli_v1_from([
                "myc",
                "--profile",
                "service-host",
                "--instance",
                exact.as_str(),
                "run",
            ])
            .is_ok()
        );
        let overlong = "a".repeat(radroots_runtime_paths::INSTANCE_ID_MAX_BYTES + 1);
        assert_eq!(
            parse_myc_cli_v1_from([
                "myc",
                "--profile",
                "service-host",
                "--instance",
                overlong.as_str(),
                "run",
            ])
            .expect_err("overlong instance")
            .kind(),
            MycCliV1ErrorKind::InvalidInstance
        );

        let missing_root =
            parse_myc_cli_v1_from(["myc", "--profile", "repo-local", "--instance", "dev", "run"])
                .expect_err("missing root");
        assert_eq!(missing_root.kind(), MycCliV1ErrorKind::InvalidRepoLocalRoot);

        let unexpected_root = parse_myc_cli_v1_from([
            "myc",
            "--profile",
            "interactive",
            "--instance",
            "dev",
            "--repo-local-root",
            "/repo/radroots",
            "run",
        ])
        .expect_err("unexpected root");
        assert_eq!(
            unexpected_root.kind(),
            MycCliV1ErrorKind::UnexpectedRepoLocalRoot
        );

        for invalid in ["relative", "/", "/repo/../escape"] {
            let error = parse_myc_cli_v1_from([
                "myc",
                "--profile",
                "repo-local",
                "--instance",
                "dev",
                "--repo-local-root",
                invalid,
                "run",
            ])
            .expect_err("invalid root");
            assert_eq!(error.kind(), MycCliV1ErrorKind::InvalidRepoLocalRoot);
        }

        for invalid in ["relative.toml", "/", "/etc/../secret.toml"] {
            let error = parse_myc_cli_v1_from([
                "myc",
                "--profile",
                "service-host",
                "--instance",
                "primary",
                "--config",
                invalid,
                "run",
            ])
            .expect_err("invalid config path");
            assert_eq!(error.kind(), MycCliV1ErrorKind::InvalidConfigPath);
        }
    }

    #[test]
    fn restore_digest_is_exact_lowercase_hex_before_decode() {
        for digest in [
            "1".repeat(63),
            "1".repeat(65),
            "A".repeat(64),
            "g".repeat(64),
            "1".repeat(1_048_576),
        ] {
            let error = parse_myc_cli_v1_from([
                "myc",
                "--profile",
                "service-host",
                "--instance",
                "primary",
                "state",
                "restore",
                "--manifest",
                "/backup/manifest.json",
                "--manifest-sha256",
                digest.as_str(),
                "--bundle",
                "/backup/bundle",
                "--maximum-state-bytes",
                "1048576",
                "--confirm",
            ])
            .expect_err("invalid digest");
            assert_eq!(error.kind(), MycCliV1ErrorKind::InvalidCommandInput);
        }
    }

    #[test]
    fn missing_unknown_and_prototype_arguments_fail_without_sources() {
        for arguments in [
            vec!["myc", "run"],
            vec!["myc", "--profile", "service-host", "run"],
            vec!["myc", "--profile", "service-host", "--instance", "primary"],
            vec![
                "myc",
                "--profile",
                "production",
                "--instance",
                "primary",
                "run",
            ],
            vec![
                "myc",
                "--profile",
                "service-host",
                "--instance",
                "primary",
                "--env-file",
                "secret.env",
                "run",
            ],
            vec![
                "myc",
                "--profile",
                "service-host",
                "--instance",
                "primary",
                "persistence",
                "backup",
            ],
        ] {
            let failure = parse_myc_cli_v1_from(arguments).expect_err("arguments must fail");
            assert_eq!(failure.kind(), MycCliV1ErrorKind::InvalidArguments);
            assert!(Error::source(&failure).is_none());
        }
    }

    #[test]
    fn debug_and_errors_do_not_render_caller_values() {
        let instance = "sensitive-instance";
        let config = "/sensitive/config.toml";
        let invocation = parse_myc_cli_v1_from([
            "myc",
            "--profile",
            "service-host",
            "--instance",
            instance,
            "--config",
            config,
            "doctor",
        ])
        .expect("invocation");
        let debug = format!("{invocation:?}");
        assert!(!debug.contains(instance));
        assert!(!debug.contains(config));

        let secret = "secret-cli-value";
        let failure =
            parse_myc_cli_v1_from(["myc", "--profile", secret, "--instance", "primary", "run"])
                .expect_err("invalid profile");
        let rendered = format!("{failure} {failure:?}");
        assert!(!rendered.contains(secret));
        assert!(Error::source(&failure).is_none());
    }
}
