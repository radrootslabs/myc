//! Sealed lifecycle boundary for the canonical Myc SQLite state catalog.

use core::fmt;
use std::{error::Error, path::PathBuf};

use radroots_service_sqlite::{
    MigrationAppliedAtUnixSeconds, MigrationBuildIdentity, OpenMode, ServiceDatabaseIdentity,
    ServiceDatabaseMetadata, ServiceSqliteConnectionOptions, ServiceSqliteHost, ServiceSqlitePaths,
    initialize_database,
};
use sqlx::{ConnectOptions, Connection, SqliteConnection, sqlite::SqliteConnectOptions};

use crate::{
    MYC_STATE_SCHEMA_VERSION, MycRuntimeContext, myc_migration_catalog, myc_schema_catalog,
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
}

impl MycStateHost {
    /// Returns the lifecycle mode selected when this host was opened.
    #[must_use]
    pub const fn mode(&self) -> MycStateHostMode {
        self.mode
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
    metadata: &ServiceDatabaseMetadata,
) -> Result<(), MycStateHostError> {
    let paths = state_paths(runtime)?;
    require_metadata(runtime, metadata)?;
    let (migrations, schema) = catalogs()?;
    let mut authority = initialize_database(
        &paths,
        OpenMode::Initialize,
        metadata,
        &schema,
        initialize_empty_catalog,
    )
    .await
    .map_err(|_| MycStateHostError::new(MycStateHostErrorKind::Initialize))?;
    authority
        .release()
        .map_err(|_| MycStateHostError::new(MycStateHostErrorKind::Initialize))?;
    drop(migrations);
    Ok(())
}

/// Opens an already initialized Myc catalog with exclusive writer authority.
///
/// Missing state is never created. Migration time and build identity remain
/// explicit injected evidence even while the baseline migration catalog is
/// empty.
pub async fn open_myc_state_read_write(
    runtime: &MycRuntimeContext,
    identity: &ServiceDatabaseIdentity,
    applied_at: MigrationAppliedAtUnixSeconds,
    build: &MigrationBuildIdentity,
) -> Result<MycStateHost, MycStateHostError> {
    let paths = state_paths(runtime)?;
    require_identity(runtime, identity)?;
    let (migrations, schema) = catalogs()?;
    let (host, outcome) = ServiceSqliteHost::open_read_write_existing(
        &paths,
        identity,
        &migrations,
        &schema,
        ServiceSqliteConnectionOptions::reviewed(),
        applied_at,
        build,
        &[],
    )
    .await
    .map_err(|_| MycStateHostError::new(MycStateHostErrorKind::ReadWriteOpen))?;
    if outcome.initial_version() != MYC_STATE_SCHEMA_VERSION
        || outcome.final_version() != MYC_STATE_SCHEMA_VERSION
        || outcome.applied_count() != 0
    {
        let _ = host.close().await;
        return Err(MycStateHostError::new(MycStateHostErrorKind::Catalog));
    }
    Ok(MycStateHost {
        host,
        mode: MycStateHostMode::ReadWriteExisting,
    })
}

/// Opens an already initialized Myc catalog for immutable inspection.
pub async fn open_myc_state_inspection(
    runtime: &MycRuntimeContext,
    identity: &ServiceDatabaseIdentity,
) -> Result<MycStateHost, MycStateHostError> {
    let paths = state_paths(runtime)?;
    require_identity(runtime, identity)?;
    let (migrations, schema) = catalogs()?;
    let host = ServiceSqliteHost::open_read_only_inspection(
        &paths,
        identity,
        &migrations,
        &schema,
        ServiceSqliteConnectionOptions::reviewed(),
    )
    .await
    .map_err(|_| MycStateHostError::new(MycStateHostErrorKind::InspectionOpen))?;
    Ok(MycStateHost {
        host,
        mode: MycStateHostMode::ReadOnlyInspection,
    })
}

fn state_paths(runtime: &MycRuntimeContext) -> Result<ServiceSqlitePaths, MycStateHostError> {
    ServiceSqlitePaths::from_runtime_context(runtime.context())
        .map_err(|_| MycStateHostError::new(MycStateHostErrorKind::InvalidPaths))
}

fn require_metadata(
    runtime: &MycRuntimeContext,
    metadata: &ServiceDatabaseMetadata,
) -> Result<(), MycStateHostError> {
    let matches = metadata.service() == runtime.context().service()
        && metadata.instance() == runtime.context().instance()
        && metadata.state_schema_version().get() == MYC_STATE_SCHEMA_VERSION;
    matches
        .then_some(())
        .ok_or_else(|| MycStateHostError::new(MycStateHostErrorKind::InvalidEvidence))
}

fn require_identity(
    runtime: &MycRuntimeContext,
    identity: &ServiceDatabaseIdentity,
) -> Result<(), MycStateHostError> {
    let matches = identity.service() == runtime.context().service()
        && identity.instance() == runtime.context().instance()
        && identity.supported_state_schema_version().get() == MYC_STATE_SCHEMA_VERSION;
    matches
        .then_some(())
        .ok_or_else(|| MycStateHostError::new(MycStateHostErrorKind::InvalidEvidence))
}

fn catalogs() -> Result<
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
