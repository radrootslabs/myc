//! Offline append-only configuration-binding lifecycle.

use core::fmt;
use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
};

use radroots_service_sqlite::{
    MigrationAppliedAtUnixSeconds, MigrationBuildIdentity, ServiceSqliteTransaction,
    ServiceSqliteTransactionError, ServiceSqliteTransactionErrorKind,
};
use serde_json::Value;
use sqlx::{QueryBuilder, Row, Sqlite};

use crate::{
    MYC_PROVIDER_CONTRACT_VERSION, MycConfigDocumentV1, MycStateRepository,
    state_repository::{
        PersistedMetadata, RepositoryOperationError, read_latest_config_binding,
        require_expected_metadata,
    },
};

/// Maximum number of immutable configuration generations retained by one instance.
pub const MYC_CONFIG_BINDING_MAX_GENERATIONS: u16 = 1024;

const READ_LATEST_HEADER_SQL: &str = r#"SELECT generation, applied_at_unix_s
FROM myc_config_bindings
ORDER BY generation DESC
LIMIT 1"#;

const RELAY_HAS_NONTERMINAL_JOB_SQL: &str = r#"SELECT EXISTS (
    SELECT 1
    FROM delivery_targets AS target
    JOIN delivery_jobs AS job ON job.job_id = target.job_id
    WHERE target.relay_id = ? AND job.status IN ('pending', 'active')
    LIMIT 1
) AS is_blocked"#;

const REVOKE_ACTIVE_CONNECTIONS_SQL: &str = r#"UPDATE connections
SET status = 'expired', updated_at_unix_ms = MAX(updated_at_unix_ms, ?),
    authorized_until_unix_ms = NULL
WHERE status = 'active'"#;

const DENY_PENDING_CONNECTIONS_SQL: &str = r#"UPDATE connections
SET status = 'denied', updated_at_unix_ms = MAX(updated_at_unix_ms, ?),
    authorized_until_unix_ms = NULL
WHERE status = 'pending'"#;

const EXPIRE_ALL_PENDING_CHALLENGES_SQL: &str = r#"UPDATE connection_auth_challenges
SET state = 'expired',
    resolved_at_unix_ms = MAX(issued_at_unix_ms, ?)
WHERE state = 'pending'"#;

const INSERT_CONFIG_BINDING_SQL: &str = r#"INSERT INTO myc_config_bindings (
    generation, normalized_config_sha256, transport_public_key, user_public_key,
    discovery_public_key, config_contract_version, state_contract_version,
    operator_contract_version, status_contract_version, applied_at_unix_s,
    service_version, service_commit, lib_revision, rust_version, target,
    feature_profile, provider_contract_version
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"#;

/// Stable offline configuration-application failure classes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MycConfigApplyErrorKind {
    InvalidMode,
    InvalidInput,
    Binding,
    PolicyConflict,
    ResourceExhausted,
    Transaction,
    CommitOutcomeUnknown,
}

impl MycConfigApplyErrorKind {
    /// Returns the stable machine-readable failure code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidMode => "config_apply_mode_invalid",
            Self::InvalidInput => "config_apply_input_invalid",
            Self::Binding => "config_apply_binding_invalid",
            Self::PolicyConflict => "config_apply_policy_conflict",
            Self::ResourceExhausted => "resource_exhausted",
            Self::Transaction => "config_apply_transaction_failed",
            Self::CommitOutcomeUnknown => "config_apply_commit_outcome_unknown",
        }
    }
}

/// Source-free offline configuration-application failure.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MycConfigApplyError {
    kind: MycConfigApplyErrorKind,
}

impl MycConfigApplyError {
    const fn new(kind: MycConfigApplyErrorKind) -> Self {
        Self { kind }
    }

    /// Returns the stable failure class.
    #[must_use]
    pub const fn kind(self) -> MycConfigApplyErrorKind {
        self.kind
    }

    /// Returns the stable machine-readable failure code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        self.kind.code()
    }
}

impl fmt::Display for MycConfigApplyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            MycConfigApplyErrorKind::InvalidMode => {
                "Myc configuration apply requires an offline writable state host"
            }
            MycConfigApplyErrorKind::InvalidInput => "Myc configuration apply evidence is invalid",
            MycConfigApplyErrorKind::Binding => "Myc configuration history binding is invalid",
            MycConfigApplyErrorKind::PolicyConflict => {
                "Myc configuration change conflicts with retained work"
            }
            MycConfigApplyErrorKind::ResourceExhausted => {
                "Myc configuration history capacity is exhausted"
            }
            MycConfigApplyErrorKind::Transaction => "Myc configuration apply transaction failed",
            MycConfigApplyErrorKind::CommitOutcomeUnknown => {
                "Myc configuration apply commit outcome is unknown"
            }
        })
    }
}

impl fmt::Debug for MycConfigApplyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MycConfigApplyError")
            .field("kind", &self.kind)
            .finish()
    }
}

impl Error for MycConfigApplyError {}

/// Committed immutable configuration-generation evidence.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MycConfigApplyOutcome {
    generation: u16,
    revoked_connections: u64,
    revoked_challenges: u64,
}

impl MycConfigApplyOutcome {
    /// Returns the committed consecutive configuration generation.
    #[must_use]
    pub const fn generation(self) -> u16 {
        self.generation
    }

    /// Returns the number of connection records revoked by the apply.
    #[must_use]
    pub const fn revoked_connection_count(self) -> u64 {
        self.revoked_connections
    }

    /// Returns the number of pending challenges revoked by the apply.
    #[must_use]
    pub const fn revoked_challenge_count(self) -> u64 {
        self.revoked_challenges
    }
}

impl fmt::Debug for MycConfigApplyOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MycConfigApplyOutcome")
            .field("generation", &self.generation)
            .field("revoked_connections", &self.revoked_connections)
            .field("revoked_challenges", &self.revoked_challenges)
            .finish()
    }
}

impl MycStateRepository<'_> {
    /// Atomically applies one complete candidate configuration while offline.
    ///
    /// The current document must match the latest durable binding. The candidate
    /// is already structurally and semantically admitted by its sealed type.
    /// Unsafe relay changes are rejected while nonterminal jobs retain the relay.
    pub async fn apply_configuration(
        &self,
        current: &MycConfigDocumentV1,
        candidate: &MycConfigDocumentV1,
        applied_at: MigrationAppliedAtUnixSeconds,
        build: &MigrationBuildIdentity,
    ) -> Result<MycConfigApplyOutcome, MycConfigApplyError> {
        if !self.is_writable() {
            return Err(MycConfigApplyError::new(
                MycConfigApplyErrorKind::InvalidMode,
            ));
        }
        if current.profile() != candidate.profile()
            || candidate.provider_contract().bindings().is_empty()
            || !valid_build(candidate, build)
        {
            return Err(MycConfigApplyError::new(
                MycConfigApplyErrorKind::InvalidInput,
            ));
        }
        let current_binding = PersistedMetadata::from_configuration(current)
            .map_err(|_| MycConfigApplyError::new(MycConfigApplyErrorKind::InvalidInput))?;
        if current_binding != PersistedMetadata::from(self.expected()) {
            return Err(MycConfigApplyError::new(MycConfigApplyErrorKind::Binding));
        }
        let candidate_binding = PersistedMetadata::from_configuration(candidate)
            .map_err(|_| MycConfigApplyError::new(MycConfigApplyErrorKind::InvalidInput))?;
        let exact_replay = candidate_binding == current_binding;
        let changed_relays = changed_existing_relays(current, candidate)?;
        let candidate_permissions = permission_ceiling(candidate)?;
        let permissions_narrowed = permission_ceiling(current)?
            .iter()
            .any(|permission| !candidate_permissions.contains(permission));
        let identities_changed = identities_changed(&current_binding, &candidate_binding);
        let applied_at_unix_s = applied_at.get();
        let applied_at_unix_ms =
            i64::try_from(applied_at_unix_s.saturating_mul(1000)).unwrap_or(i64::MAX);
        let build = build.clone();

        self.host()
            .transaction(move |transaction| {
                Box::pin(async move {
                    require_expected_metadata(transaction, &current_binding).await?;
                    let (generation, latest_applied_at) = read_latest_header(transaction).await?;
                    if exact_replay {
                        return Ok(MycConfigApplyOutcome {
                            generation,
                            revoked_connections: 0,
                            revoked_challenges: 0,
                        });
                    }
                    if generation >= MYC_CONFIG_BINDING_MAX_GENERATIONS {
                        return Err(ConfigOperationError::ResourceExhausted);
                    }
                    if applied_at_unix_s < latest_applied_at {
                        return Err(ConfigOperationError::InvalidInput);
                    }
                    for relay_id in &changed_relays {
                        if relay_has_nonterminal_job(transaction, relay_id).await? {
                            return Err(ConfigOperationError::PolicyConflict);
                        }
                    }
                    let (revoked_connections, revoked_challenges) = if identities_changed {
                        revoke_for_identity_change(transaction, applied_at_unix_ms).await?
                    } else if permissions_narrowed {
                        revoke_for_permission_narrowing(
                            transaction,
                            applied_at_unix_ms,
                            &candidate_permissions,
                        )
                        .await?
                    } else {
                        (0, 0)
                    };
                    let next_generation = generation + 1;
                    insert_binding(
                        transaction,
                        next_generation,
                        &candidate_binding,
                        applied_at_unix_s,
                        &build,
                    )
                    .await?;
                    match read_latest_config_binding(transaction).await? {
                        Some(actual) if actual == candidate_binding => {}
                        Some(_) | None => return Err(ConfigOperationError::Binding),
                    }
                    let (actual_generation, actual_applied_at) =
                        read_latest_header(transaction).await?;
                    if actual_generation != next_generation
                        || actual_applied_at != applied_at_unix_s
                    {
                        return Err(ConfigOperationError::Binding);
                    }
                    Ok(MycConfigApplyOutcome {
                        generation: next_generation,
                        revoked_connections,
                        revoked_challenges,
                    })
                })
            })
            .await
            .map_err(map_apply_transaction_error)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ConfigOperationError {
    InvalidInput,
    Binding,
    PolicyConflict,
    ResourceExhausted,
    Storage,
}

impl From<RepositoryOperationError> for ConfigOperationError {
    fn from(error: RepositoryOperationError) -> Self {
        match error {
            RepositoryOperationError::Binding => Self::Binding,
            RepositoryOperationError::Storage => Self::Storage,
        }
    }
}

fn valid_build(configuration: &MycConfigDocumentV1, build: &MigrationBuildIdentity) -> bool {
    build.config_contract_version() == configuration.schema_version()
        && build.state_contract_version() == crate::MYC_STATE_SCHEMA_VERSION
        && build.admin_contract_version() == crate::MYC_OPERATOR_CONTRACT_VERSION
        && build.status_contract_version() == crate::MYC_SIGNER_STATUS_CONTRACT_VERSION
        && build.provider_contract_version() == MYC_PROVIDER_CONTRACT_VERSION
}

fn identities_changed(current: &PersistedMetadata, candidate: &PersistedMetadata) -> bool {
    current.transport_public_key != candidate.transport_public_key
        || current.user_public_key != candidate.user_public_key
        || current.discovery_public_key != candidate.discovery_public_key
}

#[derive(PartialEq, Eq)]
struct RelayBinding<'a> {
    url: &'a str,
    read: bool,
    write: bool,
    required: bool,
    authentication: &'a str,
}

fn relay_bindings(
    configuration: &MycConfigDocumentV1,
) -> Result<BTreeMap<&str, RelayBinding<'_>>, MycConfigApplyError> {
    configuration
        .normalized()
        .pointer("/relays")
        .and_then(Value::as_array)
        .ok_or_else(|| MycConfigApplyError::new(MycConfigApplyErrorKind::InvalidInput))?
        .iter()
        .map(|relay| {
            let id = relay
                .pointer("/id")
                .and_then(Value::as_str)
                .ok_or_else(|| MycConfigApplyError::new(MycConfigApplyErrorKind::InvalidInput))?;
            let value = RelayBinding {
                url: relay
                    .pointer("/url")
                    .and_then(Value::as_str)
                    .ok_or_else(|| {
                        MycConfigApplyError::new(MycConfigApplyErrorKind::InvalidInput)
                    })?,
                read: relay
                    .pointer("/read")
                    .and_then(Value::as_bool)
                    .ok_or_else(|| {
                        MycConfigApplyError::new(MycConfigApplyErrorKind::InvalidInput)
                    })?,
                write: relay
                    .pointer("/write")
                    .and_then(Value::as_bool)
                    .ok_or_else(|| {
                        MycConfigApplyError::new(MycConfigApplyErrorKind::InvalidInput)
                    })?,
                required: relay
                    .pointer("/required")
                    .and_then(Value::as_bool)
                    .ok_or_else(|| {
                        MycConfigApplyError::new(MycConfigApplyErrorKind::InvalidInput)
                    })?,
                authentication: relay
                    .pointer("/authentication")
                    .and_then(Value::as_str)
                    .ok_or_else(|| {
                        MycConfigApplyError::new(MycConfigApplyErrorKind::InvalidInput)
                    })?,
            };
            Ok((id, value))
        })
        .collect()
}

fn changed_existing_relays(
    current: &MycConfigDocumentV1,
    candidate: &MycConfigDocumentV1,
) -> Result<Vec<Box<str>>, MycConfigApplyError> {
    let current = relay_bindings(current)?;
    let candidate = relay_bindings(candidate)?;
    Ok(current
        .into_iter()
        .filter(|(id, binding)| candidate.get(id).is_none_or(|next| next != binding))
        .map(|(id, _)| id.into())
        .collect())
}

fn permission_ceiling(
    configuration: &MycConfigDocumentV1,
) -> Result<BTreeSet<Box<str>>, MycConfigApplyError> {
    configuration
        .normalized()
        .pointer("/policy/permission_ceiling")
        .and_then(Value::as_array)
        .ok_or_else(|| MycConfigApplyError::new(MycConfigApplyErrorKind::InvalidInput))?
        .iter()
        .map(|permission| {
            permission
                .as_str()
                .map(Into::into)
                .ok_or_else(|| MycConfigApplyError::new(MycConfigApplyErrorKind::InvalidInput))
        })
        .collect()
}

async fn read_latest_header(
    transaction: &mut ServiceSqliteTransaction<'_>,
) -> Result<(u16, u64), ConfigOperationError> {
    let rows = sqlx::query(READ_LATEST_HEADER_SQL)
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| ConfigOperationError::Storage)?;
    let [row] = rows.as_slice() else {
        return Err(ConfigOperationError::Binding);
    };
    let generation = row
        .try_get::<i64, _>("generation")
        .ok()
        .and_then(|value| u16::try_from(value).ok())
        .filter(|value| (1..=MYC_CONFIG_BINDING_MAX_GENERATIONS).contains(value))
        .ok_or(ConfigOperationError::Binding)?;
    let applied_at = row
        .try_get::<i64, _>("applied_at_unix_s")
        .ok()
        .and_then(|value| u64::try_from(value).ok())
        .ok_or(ConfigOperationError::Binding)?;
    Ok((generation, applied_at))
}

async fn relay_has_nonterminal_job(
    transaction: &mut ServiceSqliteTransaction<'_>,
    relay_id: &str,
) -> Result<bool, ConfigOperationError> {
    let row = sqlx::query(RELAY_HAS_NONTERMINAL_JOB_SQL)
        .bind(relay_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| ConfigOperationError::Storage)?;
    match row.try_get::<i64, _>("is_blocked") {
        Ok(0) => Ok(false),
        Ok(1) => Ok(true),
        _ => Err(ConfigOperationError::Binding),
    }
}

async fn revoke_for_identity_change(
    transaction: &mut ServiceSqliteTransaction<'_>,
    observed_at_unix_ms: i64,
) -> Result<(u64, u64), ConfigOperationError> {
    let active = sqlx::query(REVOKE_ACTIVE_CONNECTIONS_SQL)
        .bind(observed_at_unix_ms)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ConfigOperationError::Storage)?
        .rows_affected();
    let pending = sqlx::query(DENY_PENDING_CONNECTIONS_SQL)
        .bind(observed_at_unix_ms)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ConfigOperationError::Storage)?
        .rows_affected();
    let challenges = sqlx::query(EXPIRE_ALL_PENDING_CHALLENGES_SQL)
        .bind(observed_at_unix_ms)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ConfigOperationError::Storage)?
        .rows_affected();
    Ok((active.saturating_add(pending), challenges))
}

async fn revoke_for_permission_narrowing(
    transaction: &mut ServiceSqliteTransaction<'_>,
    observed_at_unix_ms: i64,
    permissions: &BTreeSet<Box<str>>,
) -> Result<(u64, u64), ConfigOperationError> {
    let connections =
        update_affected_connections(transaction, observed_at_unix_ms, permissions).await?;
    let challenges =
        update_affected_challenges(transaction, observed_at_unix_ms, permissions).await?;
    Ok((connections, challenges))
}

async fn update_affected_connections(
    transaction: &mut ServiceSqliteTransaction<'_>,
    observed_at_unix_ms: i64,
    permissions: &BTreeSet<Box<str>>,
) -> Result<u64, ConfigOperationError> {
    let mut query = QueryBuilder::<Sqlite>::new(
        "UPDATE connections SET status = 'expired', updated_at_unix_ms = \
         MAX(updated_at_unix_ms, ",
    );
    query.push_bind(observed_at_unix_ms).push(
        "), authorized_until_unix_ms = NULL WHERE status = 'active' AND EXISTS (\
         SELECT 1 FROM connection_permissions AS permission \
         WHERE permission.connection_id = connections.connection_id \
         AND permission.permission_scope = 'granted'",
    );
    push_not_in(&mut query, permissions);
    query.push(")");
    query
        .build()
        .execute(&mut *transaction)
        .await
        .map(|result| result.rows_affected())
        .map_err(|_| ConfigOperationError::Storage)
}

async fn update_affected_challenges(
    transaction: &mut ServiceSqliteTransaction<'_>,
    observed_at_unix_ms: i64,
    permissions: &BTreeSet<Box<str>>,
) -> Result<u64, ConfigOperationError> {
    let mut query = QueryBuilder::<Sqlite>::new(
        "UPDATE connection_auth_challenges SET state = 'expired', \
         resolved_at_unix_ms = MAX(issued_at_unix_ms, ",
    );
    query.push_bind(observed_at_unix_ms).push(
        ") WHERE state = 'pending' AND EXISTS (\
         SELECT 1 FROM connection_permissions AS permission \
         WHERE permission.connection_id = connection_auth_challenges.connection_id \
         AND permission.permission_scope = 'requested'",
    );
    push_not_in(&mut query, permissions);
    query.push(")");
    query
        .build()
        .execute(&mut *transaction)
        .await
        .map(|result| result.rows_affected())
        .map_err(|_| ConfigOperationError::Storage)
}

fn push_not_in(query: &mut QueryBuilder<Sqlite>, permissions: &BTreeSet<Box<str>>) {
    if permissions.is_empty() {
        return;
    }
    query.push(" AND permission.permission_code NOT IN (");
    let mut separated = query.separated(", ");
    for permission in permissions {
        separated.push_bind(permission.as_ref());
    }
    separated.push_unseparated(")");
}

async fn insert_binding(
    transaction: &mut ServiceSqliteTransaction<'_>,
    generation: u16,
    binding: &PersistedMetadata,
    applied_at_unix_s: u64,
    build: &MigrationBuildIdentity,
) -> Result<(), ConfigOperationError> {
    let result = sqlx::query(INSERT_CONFIG_BINDING_SQL)
        .bind(i64::from(generation))
        .bind(binding.normalized_config_sha256.as_slice())
        .bind(binding.transport_public_key.as_ref())
        .bind(binding.user_public_key.as_ref())
        .bind(binding.discovery_public_key.as_deref())
        .bind(i64::from(binding.config_contract_version))
        .bind(i64::from(binding.state_contract_version))
        .bind(i64::from(binding.operator_contract_version))
        .bind(i64::from(binding.status_contract_version))
        .bind(i64::try_from(applied_at_unix_s).map_err(|_| ConfigOperationError::InvalidInput)?)
        .bind(build.service_version())
        .bind(build.service_commit())
        .bind(build.lib_revision())
        .bind(build.rust_version())
        .bind(build.target())
        .bind(build.feature_profile())
        .bind(i64::from(build.provider_contract_version()))
        .execute(&mut *transaction)
        .await
        .map_err(|_| ConfigOperationError::Storage)?;
    (result.rows_affected() == 1)
        .then_some(())
        .ok_or(ConfigOperationError::Storage)
}

fn map_apply_transaction_error(
    error: ServiceSqliteTransactionError<ConfigOperationError>,
) -> MycConfigApplyError {
    if error.kind() == ServiceSqliteTransactionErrorKind::CommitOutcomeUnknown {
        return MycConfigApplyError::new(MycConfigApplyErrorKind::CommitOutcomeUnknown);
    }
    let kind = match error.operation_error() {
        Some(ConfigOperationError::InvalidInput) => MycConfigApplyErrorKind::InvalidInput,
        Some(ConfigOperationError::Binding) => MycConfigApplyErrorKind::Binding,
        Some(ConfigOperationError::PolicyConflict) => MycConfigApplyErrorKind::PolicyConflict,
        Some(ConfigOperationError::ResourceExhausted) => MycConfigApplyErrorKind::ResourceExhausted,
        Some(ConfigOperationError::Storage) | None => MycConfigApplyErrorKind::Transaction,
    };
    MycConfigApplyError::new(kind)
}
