//! One-pass command-line admission for the hardened Myc command contract.

use std::error::Error;
use std::ffi::OsString;
use std::fmt;
use std::path::{Component, Path, PathBuf};

use clap::{Parser, Subcommand, ValueEnum};
use radroots_runtime_paths::InstanceId;

/// The exact bootstrap profile selected by the operator.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MycBootstrapProfileV1 {
    ServiceHost,
    Interactive,
    RepoLocal,
}

/// The exact governed top-level Myc command inventory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MycCommandV1 {
    Run,
    Config(MycConfigCommandV1),
    State(MycStateCommandV1),
    Identity(MycIdentityCommandV1),
    Status,
    Doctor,
}

/// Governed configuration commands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MycConfigCommandV1 {
    Init,
    Validate,
    Show,
    Schema,
}

/// Governed state commands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MycStateCommandV1 {
    Init,
    Status,
    Backup,
    Restore,
    Verify,
    Migrate,
}

/// Governed identity commands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MycIdentityCommandV1 {
    Init,
    Status,
    Rekey,
    Replace,
    ExportPublic,
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
    IdentityRekey,
    IdentityReplace,
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
            Self::IdentityRekey => crate::MycAdminRoute::IdentityRekey,
            Self::IdentityReplace => crate::MycAdminRoute::IdentityReplace,
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

    /// Returns the exact governed command selection.
    #[must_use]
    pub const fn command(&self) -> MycCommandV1 {
        self.command
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
        command: parsed.command.into(),
    })
}

/// Selects the sole permitted execution authority for an admitted command.
///
/// This function performs no filesystem, database, socket, environment, task,
/// or process work. Later executors consume the plan without reparsing process
/// arguments. In particular, no live command receives direct SQLite authority.
#[must_use]
pub const fn plan_myc_cli_v1(invocation: &MycCliInvocationV1) -> MycCliExecutionPlanV1 {
    match invocation.command {
        MycCommandV1::Run => daemon_plan(),
        MycCommandV1::Config(_) => offline_plan(MycCliOfflineOperationV1::Config),
        MycCommandV1::State(MycStateCommandV1::Init)
        | MycCommandV1::State(MycStateCommandV1::Restore)
        | MycCommandV1::State(MycStateCommandV1::Verify)
        | MycCommandV1::State(MycStateCommandV1::Migrate) => {
            offline_plan(MycCliOfflineOperationV1::StateExclusive)
        }
        MycCommandV1::State(MycStateCommandV1::Status) => read_only_admin_plan(
            MycCliAdminOperationV1::StateStatus,
            MycCliOfflineOperationV1::StateReadOnly,
        ),
        MycCommandV1::State(MycStateCommandV1::Backup) => read_only_admin_plan(
            MycCliAdminOperationV1::StateBackup,
            MycCliOfflineOperationV1::StateReadOnly,
        ),
        MycCommandV1::Identity(MycIdentityCommandV1::Init) => {
            offline_plan(MycCliOfflineOperationV1::IdentityExclusive)
        }
        MycCommandV1::Identity(MycIdentityCommandV1::Status) => read_only_admin_plan(
            MycCliAdminOperationV1::IdentityStatus,
            MycCliOfflineOperationV1::IdentityReadOnly,
        ),
        MycCommandV1::Identity(MycIdentityCommandV1::ExportPublic) => read_only_admin_plan(
            MycCliAdminOperationV1::IdentityPublic,
            MycCliOfflineOperationV1::IdentityReadOnly,
        ),
        MycCommandV1::Identity(MycIdentityCommandV1::Rekey) => {
            admin_plan(MycCliAdminOperationV1::IdentityRekey)
        }
        MycCommandV1::Identity(MycIdentityCommandV1::Replace) => {
            admin_plan(MycCliAdminOperationV1::IdentityReplace)
        }
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

const fn admin_plan(operation: MycCliAdminOperationV1) -> MycCliExecutionPlanV1 {
    MycCliExecutionPlanV1 {
        primary_authority: MycCliPrimaryAuthorityV1::LiveUnixAdmin,
        offline_operation: None,
        admin_operation: Some(operation),
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
    #[command(subcommand)]
    command: RawCommand,
}

#[derive(Clone, Copy, ValueEnum)]
enum RawProfile {
    ServiceHost,
    Interactive,
    RepoLocal,
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

impl From<RawCommand> for MycCommandV1 {
    fn from(value: RawCommand) -> Self {
        match value {
            RawCommand::Run => Self::Run,
            RawCommand::Config { command } => Self::Config(command.into()),
            RawCommand::State { command } => Self::State(command.into()),
            RawCommand::Identity { command } => Self::Identity(command.into()),
            RawCommand::Status => Self::Status,
            RawCommand::Doctor => Self::Doctor,
        }
    }
}

#[derive(Subcommand)]
enum RawConfigCommand {
    Init,
    Validate,
    Show,
    Schema,
}

impl From<RawConfigCommand> for MycConfigCommandV1 {
    fn from(value: RawConfigCommand) -> Self {
        match value {
            RawConfigCommand::Init => Self::Init,
            RawConfigCommand::Validate => Self::Validate,
            RawConfigCommand::Show => Self::Show,
            RawConfigCommand::Schema => Self::Schema,
        }
    }
}

#[derive(Subcommand)]
enum RawStateCommand {
    Init,
    Status,
    Backup,
    Restore,
    Verify,
    Migrate,
}

impl From<RawStateCommand> for MycStateCommandV1 {
    fn from(value: RawStateCommand) -> Self {
        match value {
            RawStateCommand::Init => Self::Init,
            RawStateCommand::Status => Self::Status,
            RawStateCommand::Backup => Self::Backup,
            RawStateCommand::Restore => Self::Restore,
            RawStateCommand::Verify => Self::Verify,
            RawStateCommand::Migrate => Self::Migrate,
        }
    }
}

#[derive(Subcommand)]
enum RawIdentityCommand {
    Init,
    Status,
    Rekey,
    Replace,
    ExportPublic,
}

impl From<RawIdentityCommand> for MycIdentityCommandV1 {
    fn from(value: RawIdentityCommand) -> Self {
        match value {
            RawIdentityCommand::Init => Self::Init,
            RawIdentityCommand::Status => Self::Status,
            RawIdentityCommand::Rekey => Self::Rekey,
            RawIdentityCommand::Replace => Self::Replace,
            RawIdentityCommand::ExportPublic => Self::ExportPublic,
        }
    }
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
            (&["run"][..], MycCommandV1::Run),
            (
                &["config", "init"][..],
                MycCommandV1::Config(MycConfigCommandV1::Init),
            ),
            (
                &["config", "validate"][..],
                MycCommandV1::Config(MycConfigCommandV1::Validate),
            ),
            (
                &["config", "show"][..],
                MycCommandV1::Config(MycConfigCommandV1::Show),
            ),
            (
                &["config", "schema"][..],
                MycCommandV1::Config(MycConfigCommandV1::Schema),
            ),
            (
                &["state", "init"][..],
                MycCommandV1::State(MycStateCommandV1::Init),
            ),
            (
                &["state", "status"][..],
                MycCommandV1::State(MycStateCommandV1::Status),
            ),
            (
                &["state", "backup"][..],
                MycCommandV1::State(MycStateCommandV1::Backup),
            ),
            (
                &["state", "restore"][..],
                MycCommandV1::State(MycStateCommandV1::Restore),
            ),
            (
                &["state", "verify"][..],
                MycCommandV1::State(MycStateCommandV1::Verify),
            ),
            (
                &["state", "migrate"][..],
                MycCommandV1::State(MycStateCommandV1::Migrate),
            ),
            (
                &["identity", "init"][..],
                MycCommandV1::Identity(MycIdentityCommandV1::Init),
            ),
            (
                &["identity", "status"][..],
                MycCommandV1::Identity(MycIdentityCommandV1::Status),
            ),
            (
                &["identity", "rekey"][..],
                MycCommandV1::Identity(MycIdentityCommandV1::Rekey),
            ),
            (
                &["identity", "replace"][..],
                MycCommandV1::Identity(MycIdentityCommandV1::Replace),
            ),
            (
                &["identity", "export-public"][..],
                MycCommandV1::Identity(MycIdentityCommandV1::ExportPublic),
            ),
            (&["status"][..], MycCommandV1::Status),
            (&["doctor"][..], MycCommandV1::Doctor),
        ];
        for (arguments, expected) in vectors {
            assert_eq!(parse(arguments).expect("command").command(), expected);
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
