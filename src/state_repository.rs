//! Sealed typed access to Myc-owned SQLite state.

use core::fmt;
use std::error::Error;

use radroots_service_sqlite::{
    ServiceSqliteHost, ServiceSqliteTransaction, ServiceSqliteTransactionError,
    ServiceSqliteTransactionErrorKind,
};
use sqlx::Row;

use crate::MycStateMetadata;

const READ_METADATA_SQL: &str = r#"SELECT
    singleton,
    CASE
        WHEN typeof(normalized_config_sha256) = 'blob'
            AND length(normalized_config_sha256) = 32
        THEN normalized_config_sha256
        ELSE NULL
    END AS normalized_config_sha256,
    CASE
        WHEN typeof(transport_public_key) = 'text'
            AND length(CAST(transport_public_key AS BLOB)) = 64
        THEN transport_public_key
        ELSE NULL
    END AS transport_public_key,
    CASE
        WHEN typeof(user_public_key) = 'text'
            AND length(CAST(user_public_key AS BLOB)) = 64
        THEN user_public_key
        ELSE NULL
    END AS user_public_key,
    typeof(discovery_public_key) AS discovery_public_key_type,
    CASE
        WHEN typeof(discovery_public_key) = 'text'
            AND length(CAST(discovery_public_key AS BLOB)) = 64
        THEN discovery_public_key
        ELSE NULL
    END AS discovery_public_key,
    config_contract_version,
    state_contract_version,
    operator_contract_version,
    status_contract_version
FROM myc_state_metadata
LIMIT 2"#;

const INSERT_METADATA_SQL: &str = r#"INSERT INTO myc_state_metadata (
    singleton,
    normalized_config_sha256,
    transport_public_key,
    user_public_key,
    discovery_public_key,
    config_contract_version,
    state_contract_version,
    operator_contract_version,
    status_contract_version
) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?)"#;

/// Stable failure classes for typed Myc state-repository operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MycStateRepositoryErrorKind {
    Binding,
    Transaction,
    CommitOutcomeUnknown,
}

impl MycStateRepositoryErrorKind {
    /// Returns the stable machine-readable failure code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Binding => "state_repository_binding_invalid",
            Self::Transaction => "state_repository_transaction_failed",
            Self::CommitOutcomeUnknown => "state_repository_commit_outcome_unknown",
        }
    }
}

/// Source-free typed repository failure.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MycStateRepositoryError {
    kind: MycStateRepositoryErrorKind,
}

impl MycStateRepositoryError {
    pub(crate) const fn new(kind: MycStateRepositoryErrorKind) -> Self {
        Self { kind }
    }

    /// Returns the stable failure class.
    #[must_use]
    pub const fn kind(self) -> MycStateRepositoryErrorKind {
        self.kind
    }

    /// Returns the stable machine-readable failure code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        self.kind.code()
    }
}

impl fmt::Display for MycStateRepositoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            MycStateRepositoryErrorKind::Binding => "Myc state repository binding is invalid",
            MycStateRepositoryErrorKind::Transaction => "Myc state repository transaction failed",
            MycStateRepositoryErrorKind::CommitOutcomeUnknown => {
                "Myc state repository commit outcome is unknown"
            }
        })
    }
}

impl fmt::Debug for MycStateRepositoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MycStateRepositoryError")
            .field("kind", &self.kind)
            .finish()
    }
}

impl Error for MycStateRepositoryError {}

/// Borrowed typed access to one already-opened Myc state host.
///
/// Construction is sealed to [`crate::MycStateHost::repository`]:
///
/// ```compile_fail
/// use myc::MycStateRepository;
///
/// let _ = MycStateRepository { host: todo!(), expected: todo!() };
/// ```
pub struct MycStateRepository<'host> {
    host: &'host ServiceSqliteHost,
    expected: &'host MycStateMetadata,
}

impl<'host> MycStateRepository<'host> {
    pub(crate) const fn new(
        host: &'host ServiceSqliteHost,
        expected: &'host MycStateMetadata,
    ) -> Self {
        Self { host, expected }
    }

    pub(crate) const fn host(&self) -> &'host ServiceSqliteHost {
        self.host
    }

    pub(crate) const fn expected(&self) -> &'host MycStateMetadata {
        self.expected
    }

    /// Re-verifies the immutable Myc binding through the sealed transaction executor.
    pub async fn verify_binding(&self) -> Result<(), MycStateRepositoryError> {
        self.transact(false).await
    }

    pub(crate) async fn bind_or_verify(&self) -> Result<(), MycStateRepositoryError> {
        self.transact(true).await
    }

    async fn transact(&self, initialize_missing: bool) -> Result<(), MycStateRepositoryError> {
        let expected = PersistedMetadata::from(self.expected);
        self.host
            .transaction(move |transaction| {
                Box::pin(async move {
                    let actual = read_metadata(transaction).await?;
                    match actual {
                        Some(actual) if actual == expected => Ok(()),
                        Some(_) => Err(RepositoryOperationError::Binding),
                        None if initialize_missing => {
                            insert_metadata(transaction, &expected).await?;
                            match read_metadata(transaction).await? {
                                Some(actual) if actual == expected => Ok(()),
                                Some(_) | None => Err(RepositoryOperationError::Binding),
                            }
                        }
                        None => Err(RepositoryOperationError::Binding),
                    }
                })
            })
            .await
            .map_err(map_transaction_error)
    }
}

impl fmt::Debug for MycStateRepository<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MycStateRepository")
            .field("state", &"[sealed]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct PersistedMetadata {
    normalized_config_sha256: [u8; 32],
    transport_public_key: Box<str>,
    user_public_key: Box<str>,
    discovery_public_key: Option<Box<str>>,
    config_contract_version: u32,
    state_contract_version: u32,
    operator_contract_version: u32,
    status_contract_version: u32,
}

impl From<&MycStateMetadata> for PersistedMetadata {
    fn from(metadata: &MycStateMetadata) -> Self {
        let identities = metadata.expected_identities();
        let versions = metadata.policy_versions();
        Self {
            normalized_config_sha256: *metadata.configuration_digest().as_bytes(),
            transport_public_key: identities.transport().as_hex().into(),
            user_public_key: identities.user().as_hex().into(),
            discovery_public_key: identities.discovery().map(|value| value.as_hex().into()),
            config_contract_version: versions.configuration(),
            state_contract_version: versions.state(),
            operator_contract_version: versions.operator(),
            status_contract_version: versions.status(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RepositoryOperationError {
    Binding,
    Storage,
}

pub(crate) async fn require_expected_metadata(
    transaction: &mut ServiceSqliteTransaction<'_>,
    expected: &PersistedMetadata,
) -> Result<(), RepositoryOperationError> {
    match read_metadata(transaction).await? {
        Some(actual) if actual == *expected => Ok(()),
        Some(_) | None => Err(RepositoryOperationError::Binding),
    }
}

async fn read_metadata(
    transaction: &mut ServiceSqliteTransaction<'_>,
) -> Result<Option<PersistedMetadata>, RepositoryOperationError> {
    let rows = sqlx::query(READ_METADATA_SQL)
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| RepositoryOperationError::Storage)?;
    if rows.len() > 1 {
        return Err(RepositoryOperationError::Binding);
    }
    let Some(row) = rows.first() else {
        return Ok(None);
    };
    let singleton = row
        .try_get::<i64, _>("singleton")
        .map_err(|_| RepositoryOperationError::Binding)?;
    let normalized = row
        .try_get::<Option<Vec<u8>>, _>("normalized_config_sha256")
        .map_err(|_| RepositoryOperationError::Binding)?
        .ok_or(RepositoryOperationError::Binding)?;
    let normalized_config_sha256 = normalized
        .try_into()
        .map_err(|_| RepositoryOperationError::Binding)?;
    let transport_public_key = bounded_public_key(row, "transport_public_key")?;
    let user_public_key = bounded_public_key(row, "user_public_key")?;
    let discovery_type = row
        .try_get::<&str, _>("discovery_public_key_type")
        .map_err(|_| RepositoryOperationError::Binding)?;
    let discovery_public_key = match discovery_type {
        "null" => None,
        "text" => Some(bounded_public_key(row, "discovery_public_key")?),
        _ => return Err(RepositoryOperationError::Binding),
    };
    let actual = PersistedMetadata {
        normalized_config_sha256,
        transport_public_key,
        user_public_key,
        discovery_public_key,
        config_contract_version: bounded_version(row, "config_contract_version")?,
        state_contract_version: bounded_version(row, "state_contract_version")?,
        operator_contract_version: bounded_version(row, "operator_contract_version")?,
        status_contract_version: bounded_version(row, "status_contract_version")?,
    };
    (singleton == 1)
        .then_some(Some(actual))
        .ok_or(RepositoryOperationError::Binding)
}

fn bounded_public_key(
    row: &sqlx::sqlite::SqliteRow,
    column: &str,
) -> Result<Box<str>, RepositoryOperationError> {
    let value = row
        .try_get::<Option<String>, _>(column)
        .map_err(|_| RepositoryOperationError::Binding)?
        .ok_or(RepositoryOperationError::Binding)?;
    let valid = value.len() == 64
        && value.as_bytes().iter().all(u8::is_ascii_hexdigit)
        && !value.as_bytes().iter().any(u8::is_ascii_uppercase);
    valid
        .then(|| value.into_boxed_str())
        .ok_or(RepositoryOperationError::Binding)
}

fn bounded_version(
    row: &sqlx::sqlite::SqliteRow,
    column: &str,
) -> Result<u32, RepositoryOperationError> {
    let value = row
        .try_get::<i64, _>(column)
        .map_err(|_| RepositoryOperationError::Binding)?;
    u32::try_from(value)
        .ok()
        .filter(|value| *value != 0)
        .ok_or(RepositoryOperationError::Binding)
}

async fn insert_metadata(
    transaction: &mut ServiceSqliteTransaction<'_>,
    expected: &PersistedMetadata,
) -> Result<(), RepositoryOperationError> {
    let result = sqlx::query(INSERT_METADATA_SQL)
        .bind(expected.normalized_config_sha256.as_slice())
        .bind(expected.transport_public_key.as_ref())
        .bind(expected.user_public_key.as_ref())
        .bind(expected.discovery_public_key.as_deref())
        .bind(i64::from(expected.config_contract_version))
        .bind(i64::from(expected.state_contract_version))
        .bind(i64::from(expected.operator_contract_version))
        .bind(i64::from(expected.status_contract_version))
        .execute(&mut *transaction)
        .await
        .map_err(|_| RepositoryOperationError::Storage)?;
    (result.rows_affected() == 1)
        .then_some(())
        .ok_or(RepositoryOperationError::Storage)
}

fn map_transaction_error(
    error: ServiceSqliteTransactionError<RepositoryOperationError>,
) -> MycStateRepositoryError {
    if error.kind() == ServiceSqliteTransactionErrorKind::CommitOutcomeUnknown {
        return MycStateRepositoryError::new(MycStateRepositoryErrorKind::CommitOutcomeUnknown);
    }
    let kind = match error.operation_error() {
        Some(RepositoryOperationError::Binding) => MycStateRepositoryErrorKind::Binding,
        Some(RepositoryOperationError::Storage) | None => MycStateRepositoryErrorKind::Transaction,
    };
    MycStateRepositoryError::new(kind)
}
