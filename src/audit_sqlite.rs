use std::path::{Path, PathBuf};

use radroots_nostr_signer::prelude::RadrootsNostrSignerConnectionId;
use radroots_sql_core::migrations::{Migration, migrations_run_all_up};
use radroots_sql_core::{SqlExecutor, SqliteExecutor};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

use crate::audit::{
    MycOperationAuditKind, MycOperationAuditOutcome, MycOperationAuditRecord,
    MycOperationAuditStore,
};
use crate::config::{MycAuditConfig, MycTransportDeliveryPolicy};
use crate::error::MycError;

const MYC_OPERATION_AUDIT_SQLITE_FILE_NAME: &str = "operations.sqlite";
#[cfg(test)]
const MYC_OPERATION_AUDIT_MEMORY_PATH: &str = ":memory:";

static MYC_OPERATION_AUDIT_MIGRATIONS: &[Migration] = &[Migration {
    name: "0000_runtime_audit_init",
    up_sql: include_str!("../migrations/0000_runtime_audit_init.up.sql"),
    down_sql: include_str!("../migrations/0000_runtime_audit_init.down.sql"),
}];

pub struct MycSqliteOperationAuditStore {
    db: MycOperationAuditSqliteDb,
    config: MycAuditConfig,
}

struct MycOperationAuditSqliteDb {
    path: PathBuf,
    executor: SqliteExecutor,
    file_backed: bool,
}

#[derive(Debug, Deserialize)]
struct MycOperationAuditRow {
    audit_record_id: i64,
    recorded_at_unix: u64,
    operation: String,
    outcome: String,
    relay_url: Option<String>,
    connection_id: Option<String>,
    request_id: Option<String>,
    attempt_id: Option<String>,
    planned_repair_relays_json: String,
    blocked_relays_json: String,
    blocked_reason: Option<String>,
    delivery_policy: Option<String>,
    required_acknowledged_relay_count: Option<i64>,
    publish_attempt_count: Option<i64>,
    relay_count: i64,
    acknowledged_relay_count: i64,
    relay_outcome_summary: String,
}

#[derive(Debug, Deserialize)]
struct MycLatestAttemptRow {
    attempt_id: String,
}

impl MycSqliteOperationAuditStore {
    pub fn open(audit_dir: impl AsRef<Path>, config: MycAuditConfig) -> Result<Self, MycError> {
        let db = MycOperationAuditSqliteDb::open(
            audit_dir
                .as_ref()
                .join(MYC_OPERATION_AUDIT_SQLITE_FILE_NAME),
        )?;
        Ok(Self { db, config })
    }

    #[cfg(test)]
    pub fn open_memory(config: MycAuditConfig) -> Result<Self, MycError> {
        let db = MycOperationAuditSqliteDb::open_memory()?;
        Ok(Self { db, config })
    }

    pub fn path(&self) -> &Path {
        self.db.path()
    }

    pub fn config(&self) -> &MycAuditConfig {
        &self.config
    }

    pub fn append(&self, record: &MycOperationAuditRecord) -> Result<(), MycError> {
        let planned_repair_relays_json =
            serialize_json_field(self.db.path(), &record.planned_repair_relays)?;
        let blocked_relays_json = serialize_json_field(self.db.path(), &record.blocked_relays)?;
        exec_json(
            self.db.path(),
            self.db.executor(),
            "INSERT INTO myc_operation_audit(recorded_at_unix, operation, outcome, relay_url, connection_id, request_id, attempt_id, planned_repair_relays_json, blocked_relays_json, blocked_reason, delivery_policy, required_acknowledged_relay_count, publish_attempt_count, relay_count, acknowledged_relay_count, relay_outcome_summary) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            json!([
                record.recorded_at_unix,
                operation_kind_label(record.operation),
                operation_outcome_label(record.outcome),
                record.relay_url.clone(),
                record.connection_id.clone(),
                record.request_id.clone(),
                record.attempt_id.clone(),
                planned_repair_relays_json,
                blocked_relays_json,
                record.blocked_reason.clone(),
                record
                    .delivery_policy
                    .map(MycTransportDeliveryPolicy::as_str),
                record.required_acknowledged_relay_count,
                record.publish_attempt_count,
                record.relay_count,
                record.acknowledged_relay_count,
                record.relay_outcome_summary.clone(),
            ]),
        )
    }

    pub fn list_all(&self) -> Result<Vec<MycOperationAuditRecord>, MycError> {
        self.query_records(
            "SELECT audit_record_id, recorded_at_unix, operation, outcome, relay_url, connection_id, request_id, attempt_id, planned_repair_relays_json, blocked_relays_json, blocked_reason, delivery_policy, required_acknowledged_relay_count, publish_attempt_count, relay_count, acknowledged_relay_count, relay_outcome_summary FROM myc_operation_audit ORDER BY recorded_at_unix ASC, audit_record_id ASC",
            json!([]),
        )
    }

    pub fn list_with_limit(&self, limit: usize) -> Result<Vec<MycOperationAuditRecord>, MycError> {
        if limit == 0 {
            return Ok(Vec::new());
        }

        let mut records = self.query_records_with_limit(
            "SELECT audit_record_id, recorded_at_unix, operation, outcome, relay_url, connection_id, request_id, attempt_id, planned_repair_relays_json, blocked_relays_json, blocked_reason, delivery_policy, required_acknowledged_relay_count, publish_attempt_count, relay_count, acknowledged_relay_count, relay_outcome_summary FROM myc_operation_audit ORDER BY recorded_at_unix DESC, audit_record_id DESC",
            json!([]),
            limit,
        )?;
        records.reverse();
        Ok(records)
    }

    pub fn list_for_connection_with_limit(
        &self,
        connection_id: &RadrootsNostrSignerConnectionId,
        limit: usize,
    ) -> Result<Vec<MycOperationAuditRecord>, MycError> {
        if limit == 0 {
            return Ok(Vec::new());
        }

        let mut records = self.query_records_with_limit(
            "SELECT audit_record_id, recorded_at_unix, operation, outcome, relay_url, connection_id, request_id, attempt_id, planned_repair_relays_json, blocked_relays_json, blocked_reason, delivery_policy, required_acknowledged_relay_count, publish_attempt_count, relay_count, acknowledged_relay_count, relay_outcome_summary FROM myc_operation_audit WHERE connection_id = ? ORDER BY recorded_at_unix DESC, audit_record_id DESC",
            json!([connection_id.as_str()]),
            limit,
        )?;
        records.reverse();
        Ok(records)
    }

    pub fn list_for_attempt_id_with_limit(
        &self,
        attempt_id: &str,
        limit: usize,
    ) -> Result<Vec<MycOperationAuditRecord>, MycError> {
        if limit == 0 {
            return Ok(Vec::new());
        }

        let mut records = self.query_records_with_limit(
            "SELECT audit_record_id, recorded_at_unix, operation, outcome, relay_url, connection_id, request_id, attempt_id, planned_repair_relays_json, blocked_relays_json, blocked_reason, delivery_policy, required_acknowledged_relay_count, publish_attempt_count, relay_count, acknowledged_relay_count, relay_outcome_summary FROM myc_operation_audit WHERE attempt_id = ? ORDER BY recorded_at_unix DESC, audit_record_id DESC",
            json!([attempt_id]),
            limit,
        )?;
        records.reverse();
        Ok(records)
    }

    pub fn latest_attempt_id_for_operation(
        &self,
        operation: MycOperationAuditKind,
    ) -> Result<Option<String>, MycError> {
        let rows: Vec<MycLatestAttemptRow> = query_rows(
            self.db.path(),
            self.db.executor(),
            "SELECT attempt_id FROM myc_operation_audit WHERE operation = ? AND attempt_id IS NOT NULL ORDER BY recorded_at_unix DESC, audit_record_id DESC LIMIT 1",
            json!([operation_kind_label(operation)]),
        )?;
        Ok(rows.into_iter().next().map(|row| row.attempt_id))
    }

    fn query_records(
        &self,
        sql: &str,
        params: Value,
    ) -> Result<Vec<MycOperationAuditRecord>, MycError> {
        let rows: Vec<MycOperationAuditRow> =
            query_rows(self.db.path(), self.db.executor(), sql, params)?;
        rows.into_iter()
            .map(|row| row.into_record(self.db.path()))
            .collect()
    }

    fn query_records_with_limit(
        &self,
        base_sql: &str,
        params: Value,
        limit: usize,
    ) -> Result<Vec<MycOperationAuditRecord>, MycError> {
        if limit == usize::MAX {
            return self.query_records(base_sql, params);
        }

        let limit = i64::try_from(limit).map_err(|_| {
            MycError::InvalidOperation("audit read limit exceeds sqlite range".to_owned())
        })?;
        let mut params = params.as_array().cloned().unwrap_or_default();
        params.push(Value::from(limit));
        let sql = format!("{base_sql} LIMIT ?");
        self.query_records(sql.as_str(), Value::Array(params))
    }
}

impl MycOperationAuditStore for MycSqliteOperationAuditStore {
    fn config(&self) -> &MycAuditConfig {
        &self.config
    }

    fn append(&self, record: &MycOperationAuditRecord) -> Result<(), MycError> {
        MycSqliteOperationAuditStore::append(self, record)
    }

    fn list_all(&self) -> Result<Vec<MycOperationAuditRecord>, MycError> {
        MycSqliteOperationAuditStore::list_all(self)
    }

    fn list_with_limit(&self, limit: usize) -> Result<Vec<MycOperationAuditRecord>, MycError> {
        MycSqliteOperationAuditStore::list_with_limit(self, limit)
    }

    fn list_for_connection_with_limit(
        &self,
        connection_id: &RadrootsNostrSignerConnectionId,
        limit: usize,
    ) -> Result<Vec<MycOperationAuditRecord>, MycError> {
        MycSqliteOperationAuditStore::list_for_connection_with_limit(self, connection_id, limit)
    }

    fn list_for_attempt_id_with_limit(
        &self,
        attempt_id: &str,
        limit: usize,
    ) -> Result<Vec<MycOperationAuditRecord>, MycError> {
        MycSqliteOperationAuditStore::list_for_attempt_id_with_limit(self, attempt_id, limit)
    }

    fn latest_attempt_id_for_operation(
        &self,
        operation: MycOperationAuditKind,
    ) -> Result<Option<String>, MycError> {
        MycSqliteOperationAuditStore::latest_attempt_id_for_operation(self, operation)
    }
}

impl MycOperationAuditSqliteDb {
    fn open(path: impl AsRef<Path>) -> Result<Self, MycError> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent).map_err(|source| MycError::CreateDir {
                path: parent.to_path_buf(),
                source,
            })?;
        }
        let executor = SqliteExecutor::open(&path).map_err(|source| MycError::AuditSql {
            path: path.clone(),
            source,
        })?;
        let db = Self {
            path,
            executor,
            file_backed: true,
        };
        db.configure()?;
        db.migrate_up()?;
        Ok(db)
    }

    #[cfg(test)]
    fn open_memory() -> Result<Self, MycError> {
        let path = PathBuf::from(MYC_OPERATION_AUDIT_MEMORY_PATH);
        let executor = SqliteExecutor::open_memory().map_err(|source| MycError::AuditSql {
            path: path.clone(),
            source,
        })?;
        let db = Self {
            path,
            executor,
            file_backed: false,
        };
        db.configure()?;
        db.migrate_up()?;
        Ok(db)
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn executor(&self) -> &SqliteExecutor {
        &self.executor
    }

    fn migrate_up(&self) -> Result<(), MycError> {
        migrations_run_all_up(&self.executor, MYC_OPERATION_AUDIT_MIGRATIONS).map_err(|source| {
            MycError::AuditSql {
                path: self.path.clone(),
                source,
            }
        })
    }

    #[cfg(test)]
    fn migrate_down(&self) -> Result<(), MycError> {
        use radroots_sql_core::migrations::migrations_run_all_down;

        migrations_run_all_down(&self.executor, MYC_OPERATION_AUDIT_MIGRATIONS).map_err(|source| {
            MycError::AuditSql {
                path: self.path.clone(),
                source,
            }
        })
    }

    fn configure(&self) -> Result<(), MycError> {
        let pragma_batch = if self.file_backed {
            "PRAGMA foreign_keys = ON;
             PRAGMA synchronous = FULL;
             PRAGMA wal_autocheckpoint = 1000;
             PRAGMA busy_timeout = 5000;
             PRAGMA temp_store = MEMORY;"
        } else {
            "PRAGMA foreign_keys = ON;
             PRAGMA synchronous = NORMAL;
             PRAGMA busy_timeout = 5000;
             PRAGMA temp_store = MEMORY;"
        };
        let _ = self
            .executor
            .exec(pragma_batch, "[]")
            .map_err(|source| MycError::AuditSql {
                path: self.path.clone(),
                source,
            })?;
        let journal_mode_sql = if self.file_backed {
            "PRAGMA journal_mode = WAL"
        } else {
            "PRAGMA journal_mode = MEMORY"
        };
        let _ = self
            .executor
            .query_raw(journal_mode_sql, "[]")
            .map_err(|source| MycError::AuditSql {
                path: self.path.clone(),
                source,
            })?;
        Ok(())
    }
}

impl MycOperationAuditRow {
    fn into_record(self, path: &Path) -> Result<MycOperationAuditRecord, MycError> {
        let _audit_record_id = self.audit_record_id;
        Ok(MycOperationAuditRecord {
            recorded_at_unix: self.recorded_at_unix,
            operation: parse_operation_kind(self.operation.as_str())?,
            outcome: parse_operation_outcome(self.outcome.as_str())?,
            relay_url: self.relay_url,
            connection_id: self.connection_id,
            request_id: self.request_id,
            attempt_id: self.attempt_id,
            planned_repair_relays: parse_json_field(
                path,
                self.planned_repair_relays_json.as_str(),
            )?,
            blocked_relays: parse_json_field(path, self.blocked_relays_json.as_str())?,
            blocked_reason: self.blocked_reason,
            delivery_policy: self
                .delivery_policy
                .as_deref()
                .map(parse_delivery_policy)
                .transpose()?,
            required_acknowledged_relay_count: self
                .required_acknowledged_relay_count
                .map(parse_optional_usize)
                .transpose()?,
            publish_attempt_count: self
                .publish_attempt_count
                .map(parse_optional_usize)
                .transpose()?,
            relay_count: parse_required_usize(self.relay_count, "relay_count")?,
            acknowledged_relay_count: parse_required_usize(
                self.acknowledged_relay_count,
                "acknowledged_relay_count",
            )?,
            relay_outcome_summary: self.relay_outcome_summary,
        })
    }
}

fn query_rows<T: DeserializeOwned>(
    path: &Path,
    executor: &impl SqlExecutor,
    sql: &str,
    params: Value,
) -> Result<Vec<T>, MycError> {
    let raw = executor
        .query_raw(sql, params.to_string().as_str())
        .map_err(|source| MycError::AuditSql {
            path: path.to_path_buf(),
            source,
        })?;
    serde_json::from_str(&raw).map_err(|source| MycError::AuditSqlDecode {
        path: path.to_path_buf(),
        source,
    })
}

fn exec_json(
    path: &Path,
    executor: &impl SqlExecutor,
    sql: &str,
    params: Value,
) -> Result<(), MycError> {
    let _ = executor
        .exec(sql, params.to_string().as_str())
        .map_err(|source| MycError::AuditSql {
            path: path.to_path_buf(),
            source,
        })?;
    Ok(())
}

fn parse_json_field<T: DeserializeOwned>(path: &Path, value: &str) -> Result<T, MycError> {
    serde_json::from_str(value).map_err(|source| MycError::AuditSqlDecode {
        path: path.to_path_buf(),
        source,
    })
}

fn serialize_json_field<T: serde::Serialize>(path: &Path, value: &T) -> Result<String, MycError> {
    serde_json::to_string(value).map_err(|source| MycError::AuditSerialize {
        path: path.to_path_buf(),
        source,
    })
}

fn parse_required_usize(value: i64, field: &str) -> Result<usize, MycError> {
    usize::try_from(value).map_err(|_| {
        MycError::InvalidOperation(format!(
            "sqlite runtime audit field `{field}` is out of range for usize"
        ))
    })
}

fn parse_optional_usize(value: i64) -> Result<usize, MycError> {
    usize::try_from(value).map_err(|_| {
        MycError::InvalidOperation(
            "sqlite runtime audit optional integer field is out of range for usize".to_owned(),
        )
    })
}

fn operation_kind_label(value: MycOperationAuditKind) -> &'static str {
    match value {
        MycOperationAuditKind::DeliveryRecovery => "delivery_recovery",
        MycOperationAuditKind::ListenerResponsePublish => "listener_response_publish",
        MycOperationAuditKind::ConnectAcceptPublish => "connect_accept_publish",
        MycOperationAuditKind::AuthReplayPublish => "auth_replay_publish",
        MycOperationAuditKind::AuthReplayRestore => "auth_replay_restore",
        MycOperationAuditKind::DiscoveryHandlerFetch => "discovery_handler_fetch",
        MycOperationAuditKind::DiscoveryHandlerPublish => "discovery_handler_publish",
        MycOperationAuditKind::DiscoveryHandlerCompare => "discovery_handler_compare",
        MycOperationAuditKind::DiscoveryHandlerRefresh => "discovery_handler_refresh",
        MycOperationAuditKind::DiscoveryHandlerRepair => "discovery_handler_repair",
    }
}

fn parse_operation_kind(value: &str) -> Result<MycOperationAuditKind, MycError> {
    match value {
        "delivery_recovery" => Ok(MycOperationAuditKind::DeliveryRecovery),
        "listener_response_publish" => Ok(MycOperationAuditKind::ListenerResponsePublish),
        "connect_accept_publish" => Ok(MycOperationAuditKind::ConnectAcceptPublish),
        "auth_replay_publish" => Ok(MycOperationAuditKind::AuthReplayPublish),
        "auth_replay_restore" => Ok(MycOperationAuditKind::AuthReplayRestore),
        "discovery_handler_fetch" => Ok(MycOperationAuditKind::DiscoveryHandlerFetch),
        "discovery_handler_publish" => Ok(MycOperationAuditKind::DiscoveryHandlerPublish),
        "discovery_handler_compare" => Ok(MycOperationAuditKind::DiscoveryHandlerCompare),
        "discovery_handler_refresh" => Ok(MycOperationAuditKind::DiscoveryHandlerRefresh),
        "discovery_handler_repair" => Ok(MycOperationAuditKind::DiscoveryHandlerRepair),
        other => Err(MycError::InvalidOperation(format!(
            "unknown sqlite runtime audit operation `{other}`"
        ))),
    }
}

fn operation_outcome_label(value: MycOperationAuditOutcome) -> &'static str {
    match value {
        MycOperationAuditOutcome::Succeeded => "succeeded",
        MycOperationAuditOutcome::Rejected => "rejected",
        MycOperationAuditOutcome::Restored => "restored",
        MycOperationAuditOutcome::Unavailable => "unavailable",
        MycOperationAuditOutcome::Missing => "missing",
        MycOperationAuditOutcome::Matched => "matched",
        MycOperationAuditOutcome::Drifted => "drifted",
        MycOperationAuditOutcome::Conflicted => "conflicted",
        MycOperationAuditOutcome::Skipped => "skipped",
    }
}

fn parse_operation_outcome(value: &str) -> Result<MycOperationAuditOutcome, MycError> {
    match value {
        "succeeded" => Ok(MycOperationAuditOutcome::Succeeded),
        "rejected" => Ok(MycOperationAuditOutcome::Rejected),
        "restored" => Ok(MycOperationAuditOutcome::Restored),
        "unavailable" => Ok(MycOperationAuditOutcome::Unavailable),
        "missing" => Ok(MycOperationAuditOutcome::Missing),
        "matched" => Ok(MycOperationAuditOutcome::Matched),
        "drifted" => Ok(MycOperationAuditOutcome::Drifted),
        "conflicted" => Ok(MycOperationAuditOutcome::Conflicted),
        "skipped" => Ok(MycOperationAuditOutcome::Skipped),
        other => Err(MycError::InvalidOperation(format!(
            "unknown sqlite runtime audit outcome `{other}`"
        ))),
    }
}

fn parse_delivery_policy(value: &str) -> Result<MycTransportDeliveryPolicy, MycError> {
    match value {
        "any" => Ok(MycTransportDeliveryPolicy::Any),
        "quorum" => Ok(MycTransportDeliveryPolicy::Quorum),
        "all" => Ok(MycTransportDeliveryPolicy::All),
        other => Err(MycError::InvalidOperation(format!(
            "unknown sqlite runtime audit delivery policy `{other}`"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use radroots_nostr_signer::prelude::RadrootsNostrSignerConnectionId;
    use radroots_sql_core::SqlExecutor;
    use serde_json::Value;

    use crate::audit::{
        MycOperationAuditKind, MycOperationAuditOutcome, MycOperationAuditRecord,
        MycOperationAuditStore,
    };
    use crate::config::MycAuditConfig;

    use super::{MycOperationAuditSqliteDb, MycSqliteOperationAuditStore};

    fn config() -> MycAuditConfig {
        MycAuditConfig {
            default_read_limit: 10,
            max_active_file_bytes: 512,
            max_archived_files: 2,
        }
    }

    fn query_values(
        store: &MycSqliteOperationAuditStore,
        sql: &str,
    ) -> Vec<serde_json::Map<String, Value>> {
        let raw = store.db.executor().query_raw(sql, "[]").expect("query");
        serde_json::from_str(&raw).expect("rows")
    }

    #[test]
    fn open_memory_bootstraps_runtime_audit_schema() {
        let db = MycOperationAuditSqliteDb::open_memory().expect("open memory db");
        db.migrate_up().expect("rerun migrations");

        let raw = db
            .executor()
            .query_raw(
                "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name",
                "[]",
            )
            .expect("query");
        let tables: Vec<serde_json::Map<String, Value>> =
            serde_json::from_str(&raw).expect("table rows");
        let table_names = tables
            .into_iter()
            .filter_map(|row| {
                row.get("name")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned)
            })
            .collect::<Vec<_>>();
        assert!(table_names.iter().any(|name| name == "__migrations"));
        assert!(table_names.iter().any(|name| name == "myc_operation_audit"));
    }

    #[test]
    fn append_and_list_records_roundtrip_through_sqlite() {
        let store = MycSqliteOperationAuditStore::open_memory(config()).expect("sqlite store");
        let connection_id =
            RadrootsNostrSignerConnectionId::parse("connection-1").expect("connection id");

        store
            .append(
                &MycOperationAuditRecord::new(
                    MycOperationAuditKind::ConnectAcceptPublish,
                    MycOperationAuditOutcome::Rejected,
                    Some(&connection_id),
                    Some("request-1"),
                    2,
                    0,
                    "0/2 relays acknowledged publish; failures: relay-a: rejected",
                )
                .with_attempt_id("attempt-1"),
            )
            .expect("append rejected record");
        store
            .append(&MycOperationAuditRecord::new(
                MycOperationAuditKind::AuthReplayRestore,
                MycOperationAuditOutcome::Restored,
                Some(&connection_id),
                Some("request-1"),
                0,
                0,
                "restored pending auth challenge after replay publish rejection",
            ))
            .expect("append restored record");

        let records = store.list().expect("list records");
        assert_eq!(records.len(), 2);
        assert_eq!(
            records[0].operation,
            MycOperationAuditKind::ConnectAcceptPublish
        );
        assert_eq!(records[0].outcome, MycOperationAuditOutcome::Rejected);
        assert_eq!(records[0].attempt_id.as_deref(), Some("attempt-1"));

        let connection_records = store
            .list_for_connection(&connection_id)
            .expect("list connection records");
        assert_eq!(connection_records, records);
    }

    #[test]
    fn list_for_attempt_and_latest_attempt_work_with_sqlite() {
        let store = MycSqliteOperationAuditStore::open_memory(config()).expect("sqlite store");

        store
            .append(
                &MycOperationAuditRecord::new(
                    MycOperationAuditKind::DiscoveryHandlerRefresh,
                    MycOperationAuditOutcome::Rejected,
                    None,
                    None,
                    2,
                    0,
                    "first attempt rejected",
                )
                .with_attempt_id("attempt-1"),
            )
            .expect("append first attempt");
        store
            .append(
                &MycOperationAuditRecord::new(
                    MycOperationAuditKind::DiscoveryHandlerRefresh,
                    MycOperationAuditOutcome::Succeeded,
                    None,
                    None,
                    1,
                    1,
                    "second attempt succeeded",
                )
                .with_attempt_id("attempt-2"),
            )
            .expect("append second attempt");

        let attempt_records = store
            .list_for_attempt_id("attempt-1")
            .expect("list attempt records");
        assert_eq!(attempt_records.len(), 1);
        assert_eq!(
            store
                .latest_attempt_id_for_operation(MycOperationAuditKind::DiscoveryHandlerRefresh)
                .expect("latest attempt"),
            Some("attempt-2".to_owned())
        );
    }

    #[test]
    fn file_backed_store_reopens_existing_audit_records() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("audit");
        {
            let store = MycSqliteOperationAuditStore::open(&path, config()).expect("open store");
            store
                .append(
                    &MycOperationAuditRecord::new(
                        MycOperationAuditKind::ListenerResponsePublish,
                        MycOperationAuditOutcome::Succeeded,
                        None,
                        Some("request-1"),
                        1,
                        1,
                        "relay acknowledged publish",
                    )
                    .with_attempt_id("attempt-1"),
                )
                .expect("append");
        }

        let reopened = MycSqliteOperationAuditStore::open(&path, config()).expect("reopen store");
        assert_eq!(reopened.list().expect("reopened list").len(), 1);
        assert!(reopened.path().ends_with("operations.sqlite"));
        assert_eq!(
            reopened
                .latest_attempt_id_for_operation(MycOperationAuditKind::ListenerResponsePublish)
                .expect("latest attempt"),
            Some("attempt-1".to_owned())
        );
    }

    #[test]
    fn file_database_uses_wal_mode() {
        let temp = tempfile::tempdir().expect("tempdir");
        let store =
            MycSqliteOperationAuditStore::open(temp.path().join("audit"), config()).expect("open");

        let rows = query_values(&store, "PRAGMA journal_mode");
        assert_eq!(
            rows.into_iter()
                .next()
                .and_then(|row| row.get("journal_mode").cloned())
                .and_then(|value| value.as_str().map(ToOwned::to_owned))
                .expect("journal mode"),
            "wal"
        );
    }

    #[test]
    fn migrate_down_and_up_roundtrip_restores_schema() {
        let db = MycOperationAuditSqliteDb::open_memory().expect("open memory db");
        db.migrate_down().expect("migrate down");

        let raw = db
            .executor()
            .query_raw(
                "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name",
                "[]",
            )
            .expect("query");
        let tables: Vec<serde_json::Map<String, Value>> =
            serde_json::from_str(&raw).expect("table rows");
        let table_names = tables
            .into_iter()
            .filter_map(|row| {
                row.get("name")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned)
            })
            .collect::<Vec<_>>();
        assert_eq!(table_names, vec!["__migrations".to_owned()]);

        db.migrate_up().expect("migrate up");
        let raw = db
            .executor()
            .query_raw("SELECT COUNT(*) AS row_count FROM __migrations", "[]")
            .expect("migration count");
        let rows: Vec<serde_json::Map<String, Value>> =
            serde_json::from_str(&raw).expect("migration rows");
        assert_eq!(
            rows.into_iter()
                .next()
                .and_then(|row| row.get("row_count").cloned())
                .and_then(|value| value.as_i64())
                .expect("migration row count"),
            1
        );
    }
}
