//! Sealed lifecycle boundary for the canonical Myc SQLite state catalog.

use core::fmt;
use std::{
    error::Error,
    path::{Path, PathBuf},
};

use radroots_service_sqlite::{
    BackupCreatedAtUnixMs, ExistingServiceDatabaseIntent, IntegrityCheckedAtUnixMs,
    MigrationApplicationOutcome, MigrationAppliedAtUnixSeconds, MigrationBuildIdentity, OpenMode,
    ServiceBackupManifest, ServiceSqliteApplicationId, ServiceSqliteConnectionOptions,
    ServiceSqliteHost, ServiceSqliteIntegrityReport, ServiceSqlitePaths, initialize_database,
};
use sqlx::{ConnectOptions, Connection, SqliteConnection, sqlite::SqliteConnectOptions};

use crate::{
    MYC_STATE_APPLICATION_ID, MYC_STATE_BASE_SCHEMA_VERSION, MYC_STATE_SCHEMA_VERSION,
    MycConfigDocumentV1, MycRuntimeContext, MycStateMaintenanceError, MycStateMaintenanceErrorKind,
    MycStateMetadata, MycStateRepository, myc_migration_catalog, myc_schema_catalog,
    validate_myc_state_catalogs,
};

/// Stable lifecycle mode of one opened Myc state host.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MycStateHostMode {
    ReadWriteExisting,
    ReadOnlyInspection,
}

/// Stable source-free class for a Myc state-host lifecycle failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MycStateHostErrorKind {
    InvalidPaths,
    InvalidEvidence,
    Catalog,
    Initialize,
    ReadWriteOpen,
    InspectionOpen,
    Repository,
    Close,
}

impl MycStateHostErrorKind {
    /// Returns the stable machine-readable failure code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidPaths => "state_paths_invalid",
            Self::InvalidEvidence => "state_evidence_invalid",
            Self::Catalog => "state_catalog_invalid",
            Self::Initialize => "state_initialize_failed",
            Self::ReadWriteOpen => "state_read_write_open_failed",
            Self::InspectionOpen => "state_inspection_open_failed",
            Self::Repository => "state_repository_failed",
            Self::Close => "state_close_failed",
        }
    }
}

/// Redacted Myc state-host lifecycle failure.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MycStateHostError {
    kind: MycStateHostErrorKind,
}

impl MycStateHostError {
    const fn new(kind: MycStateHostErrorKind) -> Self {
        Self { kind }
    }

    /// Returns the stable failure class.
    #[must_use]
    pub const fn kind(self) -> MycStateHostErrorKind {
        self.kind
    }

    /// Returns the stable machine-readable failure code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        self.kind.code()
    }
}

impl fmt::Display for MycStateHostError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            MycStateHostErrorKind::InvalidPaths => "Myc state paths are invalid",
            MycStateHostErrorKind::InvalidEvidence => "Myc state identity evidence is invalid",
            MycStateHostErrorKind::Catalog => "Myc state catalogs are invalid",
            MycStateHostErrorKind::Initialize => "Myc state initialization failed",
            MycStateHostErrorKind::ReadWriteOpen => "Myc writable state could not be opened",
            MycStateHostErrorKind::InspectionOpen => "Myc inspection state could not be opened",
            MycStateHostErrorKind::Repository => "Myc state repository binding failed",
            MycStateHostErrorKind::Close => "Myc state host could not be closed",
        })
    }
}

impl fmt::Debug for MycStateHostError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MycStateHostError")
            .field("kind", &self.kind)
            .finish()
    }
}

impl Error for MycStateHostError {}

/// One opened Myc state catalog whose raw SQLite authority remains sealed.
///
/// Callers cannot construct the wrapper or extract the shared host:
///
/// ```compile_fail
/// use myc::{MycStateHost, MycStateHostMode};
///
/// let _ = MycStateHost {
///     host: todo!(),
///     mode: MycStateHostMode::ReadWriteExisting,
/// };
/// ```
///
/// The wrapper intentionally exposes no transaction or connection escape:
///
/// ```compile_fail
/// use myc::MycStateHost;
///
/// fn bypass(host: &MycStateHost) {
///     let _ = host.transaction(|_| async { Ok::<_, ()>(()) });
/// }
/// ```
pub struct MycStateHost {
    host: ServiceSqliteHost,
    mode: MycStateHostMode,
    metadata: MycStateMetadata,
}

impl MycStateHost {
    /// Returns the lifecycle mode selected when this host was opened.
    #[must_use]
    pub const fn mode(&self) -> MycStateHostMode {
        self.mode
    }

    /// Returns the immutable Myc metadata bound to this host session.
    #[must_use]
    pub const fn metadata(&self) -> &MycStateMetadata {
        &self.metadata
    }

    /// Returns sealed typed repository access bound to this host and metadata.
    #[must_use]
    pub const fn repository(&self) -> MycStateRepository<'_> {
        MycStateRepository::new(
            &self.host,
            &self.metadata,
            matches!(self.mode, MycStateHostMode::ReadWriteExisting),
        )
    }

    /// Captures one governed point-in-time backup from a writable Myc host.
    ///
    /// The staging directory must be a new absolute path. The returned
    /// manifest remains in memory and contains no protected identity material.
    pub async fn capture_online_backup(
        &self,
        staging_directory: &Path,
        created_at: BackupCreatedAtUnixMs,
    ) -> Result<ServiceBackupManifest, MycStateMaintenanceError> {
        if self.mode != MycStateHostMode::ReadWriteExisting {
            return Err(MycStateMaintenanceError::new(
                MycStateMaintenanceErrorKind::InvalidMode,
            ));
        }
        self.host
            .capture_online_backup(staging_directory, created_at)
            .await
            .map_err(MycStateMaintenanceError::from_sqlite)
    }

    /// Runs one explicit bounded integrity inspection over this host.
    pub async fn inspect_integrity(
        &self,
        checked_at: IntegrityCheckedAtUnixMs,
    ) -> Result<ServiceSqliteIntegrityReport, MycStateMaintenanceError> {
        self.host
            .inspect_integrity(checked_at)
            .await
            .map_err(MycStateMaintenanceError::from_sqlite)
    }

    /// Drains the shared host and explicitly releases retained authority.
    pub async fn close(&self) -> Result<(), MycStateHostError> {
        self.host
            .close()
            .await
            .map_err(|_| MycStateHostError::new(MycStateHostErrorKind::Close))
    }
}

impl fmt::Debug for MycStateHost {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MycStateHost")
            .field("mode", &self.mode)
            .field("state", &"[sealed]")
            .finish()
    }
}

/// Creates a missing Myc catalog exactly once and releases initialization authority.
///
/// This function never opens an existing database as initialization. The caller
/// injects the shared metadata evidence; the Myc metadata-binding layer owns
/// its exact application and configuration bindings.
pub async fn initialize_myc_state(
    runtime: &MycRuntimeContext,
    metadata: &MycStateMetadata,
    applied_at: MigrationAppliedAtUnixSeconds,
    build: &MigrationBuildIdentity,
) -> Result<(), MycStateHostError> {
    let paths = state_paths(runtime)?;
    require_metadata(runtime, metadata)?;
    require_migration_build(metadata, build)?;
    let (migrations, schema) = catalogs()?;
    let authority = initialize_database(
        &paths,
        OpenMode::Initialize,
        metadata.initial_database_metadata(),
        &schema,
        initialize_empty_catalog,
    )
    .await
    .map_err(|_| MycStateHostError::new(MycStateHostErrorKind::Initialize))?;
    let identity = metadata.database_identity();
    let (host, outcome) = ServiceSqliteHost::open_initialized(
        &paths,
        &identity,
        &migrations,
        &schema,
        ServiceSqliteConnectionOptions::reviewed(),
        authority,
        applied_at,
        build,
        &[],
    )
    .await
    .map_err(|_| MycStateHostError::new(MycStateHostErrorKind::Initialize))?;
    let state = MycStateHost {
        host,
        mode: MycStateHostMode::ReadWriteExisting,
        metadata: metadata.clone(),
    };
    if !exact_initialization_outcome(outcome) {
        return Err(close_error(&state.host, MycStateHostErrorKind::Catalog).await);
    }
    if state.repository().bind_or_verify().await.is_err() {
        return Err(close_error(&state.host, MycStateHostErrorKind::Repository).await);
    }
    state
        .close()
        .await
        .map_err(|_| MycStateHostError::new(MycStateHostErrorKind::Initialize))
}

/// Opens an already initialized Myc catalog with exclusive writer authority.
///
/// Missing state is never created. Migration time and build identity remain
/// explicit injected evidence even while the baseline migration catalog is
/// empty.
pub async fn open_myc_state_read_write(
    runtime: &MycRuntimeContext,
    metadata: &MycStateMetadata,
    applied_at: MigrationAppliedAtUnixSeconds,
    build: &MigrationBuildIdentity,
) -> Result<MycStateHost, MycStateHostError> {
    let paths = state_paths(runtime)?;
    require_metadata(runtime, metadata)?;
    require_migration_build(metadata, build)?;
    let identity = metadata.database_identity();
    let (migrations, schema) = catalogs()?;
    let (host, outcome) = ServiceSqliteHost::open_read_write_existing(
        &paths,
        &identity,
        &migrations,
        &schema,
        ServiceSqliteConnectionOptions::reviewed(),
        applied_at,
        build,
        &[],
    )
    .await
    .map_err(|_| MycStateHostError::new(MycStateHostErrorKind::ReadWriteOpen))?;
    if !exact_existing_outcome(outcome) {
        return Err(close_error(&host, MycStateHostErrorKind::Catalog).await);
    }
    let state = MycStateHost {
        host,
        mode: MycStateHostMode::ReadWriteExisting,
        metadata: metadata.clone(),
    };
    if state.repository().bind_or_verify().await.is_err() {
        return Err(close_error(&state.host, MycStateHostErrorKind::Repository).await);
    }
    Ok(state)
}

/// Opens existing state from a sealed intent and discovers actual source metadata.
///
/// The caller supplies configuration policy but no source generation or
/// creation-time guess. Those values are discovered from the same retained
/// authority that is returned in the host.
pub async fn open_myc_state_read_write_from_config(
    runtime: &MycRuntimeContext,
    configuration: &MycConfigDocumentV1,
    applied_at: MigrationAppliedAtUnixSeconds,
    build: &MigrationBuildIdentity,
) -> Result<MycStateHost, MycStateHostError> {
    let paths = state_paths(runtime)?;
    let (migrations, schema) = catalogs()?;
    let intent = existing_intent(&paths)?;
    let (opened, outcome) = ServiceSqliteHost::open_read_write_existing_with_intent(
        &paths,
        &intent,
        &migrations,
        &schema,
        ServiceSqliteConnectionOptions::reviewed(),
        applied_at,
        build,
        &[],
    )
    .await
    .map_err(|_| MycStateHostError::new(MycStateHostErrorKind::ReadWriteOpen))?;
    if !exact_existing_outcome(outcome) {
        let (host, _) = opened.into_parts();
        return Err(close_error(&host, MycStateHostErrorKind::Catalog).await);
    }
    let (host, actual) = opened.into_parts();
    let metadata = match MycStateMetadata::from_existing_database(runtime, configuration, &actual) {
        Ok(metadata) => metadata,
        Err(_) => {
            return Err(close_error(&host, MycStateHostErrorKind::InvalidEvidence).await);
        }
    };
    if require_migration_build(&metadata, build).is_err() {
        return Err(close_error(&host, MycStateHostErrorKind::InvalidEvidence).await);
    }
    let state = MycStateHost {
        host,
        mode: MycStateHostMode::ReadWriteExisting,
        metadata,
    };
    if state.repository().bind_or_verify().await.is_err() {
        return Err(close_error(&state.host, MycStateHostErrorKind::Repository).await);
    }
    Ok(state)
}

/// Opens an already initialized Myc catalog for immutable inspection.
pub async fn open_myc_state_inspection(
    runtime: &MycRuntimeContext,
    metadata: &MycStateMetadata,
) -> Result<MycStateHost, MycStateHostError> {
    let paths = state_paths(runtime)?;
    require_metadata(runtime, metadata)?;
    let identity = metadata.database_identity();
    let (migrations, schema) = catalogs()?;
    let host = ServiceSqliteHost::open_read_only_inspection(
        &paths,
        &identity,
        &migrations,
        &schema,
        ServiceSqliteConnectionOptions::reviewed(),
    )
    .await
    .map_err(|_| MycStateHostError::new(MycStateHostErrorKind::InspectionOpen))?;
    let state = MycStateHost {
        host,
        mode: MycStateHostMode::ReadOnlyInspection,
        metadata: metadata.clone(),
    };
    if state.repository().verify_binding().await.is_err() {
        return Err(close_error(&state.host, MycStateHostErrorKind::Repository).await);
    }
    Ok(state)
}

/// Opens existing inspection state from a sealed intent and actual metadata.
pub async fn open_myc_state_inspection_from_config(
    runtime: &MycRuntimeContext,
    configuration: &MycConfigDocumentV1,
) -> Result<MycStateHost, MycStateHostError> {
    let paths = state_paths(runtime)?;
    let (migrations, schema) = catalogs()?;
    let intent = existing_intent(&paths)?;
    let opened = ServiceSqliteHost::open_read_only_inspection_with_intent(
        &paths,
        &intent,
        &migrations,
        &schema,
        ServiceSqliteConnectionOptions::reviewed(),
    )
    .await
    .map_err(|_| MycStateHostError::new(MycStateHostErrorKind::InspectionOpen))?;
    let (host, actual) = opened.into_parts();
    let metadata = match MycStateMetadata::from_existing_database(runtime, configuration, &actual) {
        Ok(metadata) => metadata,
        Err(_) => {
            return Err(close_error(&host, MycStateHostErrorKind::InvalidEvidence).await);
        }
    };
    let state = MycStateHost {
        host,
        mode: MycStateHostMode::ReadOnlyInspection,
        metadata,
    };
    if state.repository().verify_binding().await.is_err() {
        return Err(close_error(&state.host, MycStateHostErrorKind::Repository).await);
    }
    Ok(state)
}

async fn close_error(
    host: &ServiceSqliteHost,
    fallback: MycStateHostErrorKind,
) -> MycStateHostError {
    if host.close().await.is_err() {
        MycStateHostError::new(MycStateHostErrorKind::Close)
    } else {
        MycStateHostError::new(fallback)
    }
}

fn existing_intent(
    paths: &ServiceSqlitePaths,
) -> Result<ExistingServiceDatabaseIntent, MycStateHostError> {
    let schema = core::num::NonZeroU32::new(MYC_STATE_SCHEMA_VERSION)
        .ok_or_else(|| MycStateHostError::new(MycStateHostErrorKind::InvalidEvidence))?;
    let application = ServiceSqliteApplicationId::new(MYC_STATE_APPLICATION_ID)
        .map_err(|_| MycStateHostError::new(MycStateHostErrorKind::InvalidEvidence))?;
    Ok(ExistingServiceDatabaseIntent::new(
        paths,
        schema,
        application,
    ))
}

pub(crate) fn state_paths(
    runtime: &MycRuntimeContext,
) -> Result<ServiceSqlitePaths, MycStateHostError> {
    ServiceSqlitePaths::from_runtime_context(runtime.context())
        .map_err(|_| MycStateHostError::new(MycStateHostErrorKind::InvalidPaths))
}

pub(crate) fn require_metadata(
    runtime: &MycRuntimeContext,
    metadata: &MycStateMetadata,
) -> Result<(), MycStateHostError> {
    let database = metadata.initial_database_metadata();
    let identity = metadata.database_identity();
    let matches = metadata.matches_runtime(runtime)
        && database.service() == runtime.context().service()
        && database.instance() == runtime.context().instance()
        && database.state_schema_version().get() == MYC_STATE_BASE_SCHEMA_VERSION
        && identity.service() == runtime.context().service()
        && identity.instance() == runtime.context().instance()
        && identity.supported_state_schema_version().get() == MYC_STATE_SCHEMA_VERSION;
    matches
        .then_some(())
        .ok_or_else(|| MycStateHostError::new(MycStateHostErrorKind::InvalidEvidence))
}

fn require_migration_build(
    metadata: &MycStateMetadata,
    build: &MigrationBuildIdentity,
) -> Result<(), MycStateHostError> {
    let versions = metadata.policy_versions();
    let matches = build.config_contract_version() == versions.configuration()
        && build.state_contract_version() == versions.state()
        && build.admin_contract_version() == versions.operator()
        && build.status_contract_version() == versions.status();
    matches
        .then_some(())
        .ok_or_else(|| MycStateHostError::new(MycStateHostErrorKind::InvalidEvidence))
}

fn exact_initialization_outcome(outcome: MigrationApplicationOutcome) -> bool {
    outcome.initial_version() == MYC_STATE_BASE_SCHEMA_VERSION
        && outcome.final_version() == MYC_STATE_SCHEMA_VERSION
        && outcome.applied_count() == 11
}

fn exact_existing_outcome(outcome: MigrationApplicationOutcome) -> bool {
    outcome.final_version() == MYC_STATE_SCHEMA_VERSION
        && matches!(
            (outcome.initial_version(), outcome.applied_count()),
            (MYC_STATE_BASE_SCHEMA_VERSION, 11)
                | (2, 10)
                | (3, 9)
                | (4, 8)
                | (5, 7)
                | (6, 6)
                | (7, 5)
                | (8, 4)
                | (9, 3)
                | (10, 2)
                | (11, 1)
                | (MYC_STATE_SCHEMA_VERSION, 0)
        )
}

pub(crate) fn catalogs() -> Result<
    (
        radroots_service_sqlite::MigrationCatalog,
        radroots_service_sqlite::SchemaCatalog,
    ),
    MycStateHostError,
> {
    let migrations = myc_migration_catalog()
        .map_err(|_| MycStateHostError::new(MycStateHostErrorKind::Catalog))?;
    let schema =
        myc_schema_catalog().map_err(|_| MycStateHostError::new(MycStateHostErrorKind::Catalog))?;
    validate_myc_state_catalogs(&migrations, &schema)
        .map_err(|_| MycStateHostError::new(MycStateHostErrorKind::Catalog))?;
    Ok((migrations, schema))
}

#[derive(Debug)]
struct EmptyCatalogInitializationError;

impl fmt::Display for EmptyCatalogInitializationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Myc baseline database reservation could not be opened")
    }
}

impl Error for EmptyCatalogInitializationError {}

async fn initialize_empty_catalog(path: PathBuf) -> Result<(), EmptyCatalogInitializationError> {
    let options = SqliteConnectOptions::new()
        .filename(path)
        .create_if_missing(false)
        .disable_statement_logging();
    let connection = SqliteConnection::connect_with(&options)
        .await
        .map_err(|_| EmptyCatalogInitializationError)?;
    connection
        .close()
        .await
        .map_err(|_| EmptyCatalogInitializationError)
}
