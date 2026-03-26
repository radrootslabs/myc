use std::path::{Path, PathBuf};

use radroots_sql_core::migrations::{Migration, migrations_run_all_up};
use radroots_sql_core::{SqlExecutor, SqliteExecutor};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

use crate::error::MycError;
use crate::outbox::{
    MycDeliveryOutboxJobId, MycDeliveryOutboxKind, MycDeliveryOutboxRecord,
    MycDeliveryOutboxStatus, MycDeliveryOutboxStore, now_unix_secs,
};

const MYC_DELIVERY_OUTBOX_SQLITE_FILE_NAME: &str = "delivery-outbox.sqlite";
#[cfg(test)]
const MYC_DELIVERY_OUTBOX_MEMORY_PATH: &str = ":memory:";

static MYC_DELIVERY_OUTBOX_MIGRATIONS: &[Migration] = &[Migration {
    name: "0000_delivery_outbox_init",
    up_sql: include_str!("../migrations/0000_delivery_outbox_init.up.sql"),
    down_sql: include_str!("../migrations/0000_delivery_outbox_init.down.sql"),
}];

pub struct MycSqliteDeliveryOutboxStore {
    db: MycDeliveryOutboxSqliteDb,
}

struct MycDeliveryOutboxSqliteDb {
    path: PathBuf,
    executor: SqliteExecutor,
    file_backed: bool,
}

#[derive(Debug, Deserialize)]
struct MycDeliveryOutboxRow {
    job_id: String,
    kind: String,
    status: String,
    event_json: String,
    relay_urls_json: String,
    connection_id: Option<String>,
    request_id: Option<String>,
    attempt_id: Option<String>,
    signer_publish_workflow_id: Option<String>,
    publish_attempt_count: i64,
    last_error: Option<String>,
    created_at_unix: u64,
    updated_at_unix: u64,
    published_at_unix: Option<u64>,
    finalized_at_unix: Option<u64>,
}

impl MycSqliteDeliveryOutboxStore {
    pub fn open(state_dir: impl AsRef<Path>) -> Result<Self, MycError> {
        let db = MycDeliveryOutboxSqliteDb::open(
            state_dir
                .as_ref()
                .join(MYC_DELIVERY_OUTBOX_SQLITE_FILE_NAME),
        )?;
        Ok(Self { db })
    }

    #[cfg(test)]
    pub fn open_memory() -> Result<Self, MycError> {
        Ok(Self {
            db: MycDeliveryOutboxSqliteDb::open_memory()?,
        })
    }

    pub fn path(&self) -> &Path {
        self.db.path()
    }

    fn update_record(
        &self,
        job_id: &MycDeliveryOutboxJobId,
        update: impl FnOnce(&mut MycDeliveryOutboxRecord) -> Result<(), MycError>,
    ) -> Result<MycDeliveryOutboxRecord, MycError> {
        let mut record = self
            .get(job_id)?
            .ok_or_else(|| MycError::DeliveryOutboxJobNotFound(job_id.to_string()))?;
        update(&mut record)?;
        exec_json(
            self.db.path(),
            self.db.executor(),
            "UPDATE myc_delivery_outbox SET kind = ?, status = ?, event_json = ?, relay_urls_json = ?, connection_id = ?, request_id = ?, attempt_id = ?, signer_publish_workflow_id = ?, publish_attempt_count = ?, last_error = ?, created_at_unix = ?, updated_at_unix = ?, published_at_unix = ?, finalized_at_unix = ? WHERE job_id = ?",
            serialize_record_update_params(self.db.path(), &record, job_id.as_str())?,
        )?;
        Ok(record)
    }
}

impl MycDeliveryOutboxStore for MycSqliteDeliveryOutboxStore {
    fn enqueue(&self, record: &MycDeliveryOutboxRecord) -> Result<(), MycError> {
        exec_json(
            self.db.path(),
            self.db.executor(),
            "INSERT INTO myc_delivery_outbox(job_id, kind, status, event_json, relay_urls_json, connection_id, request_id, attempt_id, signer_publish_workflow_id, publish_attempt_count, last_error, created_at_unix, updated_at_unix, published_at_unix, finalized_at_unix) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            serialize_record_params(self.db.path(), record)?,
        )
    }

    fn get(
        &self,
        job_id: &MycDeliveryOutboxJobId,
    ) -> Result<Option<MycDeliveryOutboxRecord>, MycError> {
        let rows: Vec<MycDeliveryOutboxRow> = query_rows(
            self.db.path(),
            self.db.executor(),
            "SELECT job_id, kind, status, event_json, relay_urls_json, connection_id, request_id, attempt_id, signer_publish_workflow_id, publish_attempt_count, last_error, created_at_unix, updated_at_unix, published_at_unix, finalized_at_unix FROM myc_delivery_outbox WHERE job_id = ? LIMIT 1",
            json!([job_id.as_str()]),
        )?;
        rows.into_iter()
            .next()
            .map(|row| row.into_record(self.db.path()))
            .transpose()
    }

    fn list_all(&self) -> Result<Vec<MycDeliveryOutboxRecord>, MycError> {
        let rows: Vec<MycDeliveryOutboxRow> = query_rows(
            self.db.path(),
            self.db.executor(),
            "SELECT job_id, kind, status, event_json, relay_urls_json, connection_id, request_id, attempt_id, signer_publish_workflow_id, publish_attempt_count, last_error, created_at_unix, updated_at_unix, published_at_unix, finalized_at_unix FROM myc_delivery_outbox ORDER BY created_at_unix ASC, job_id ASC",
            json!([]),
        )?;
        rows.into_iter()
            .map(|row| row.into_record(self.db.path()))
            .collect()
    }

    fn list_by_status(
        &self,
        status: MycDeliveryOutboxStatus,
    ) -> Result<Vec<MycDeliveryOutboxRecord>, MycError> {
        let rows: Vec<MycDeliveryOutboxRow> = query_rows(
            self.db.path(),
            self.db.executor(),
            "SELECT job_id, kind, status, event_json, relay_urls_json, connection_id, request_id, attempt_id, signer_publish_workflow_id, publish_attempt_count, last_error, created_at_unix, updated_at_unix, published_at_unix, finalized_at_unix FROM myc_delivery_outbox WHERE status = ? ORDER BY created_at_unix ASC, job_id ASC",
            json!([status_label(status)]),
        )?;
        rows.into_iter()
            .map(|row| row.into_record(self.db.path()))
            .collect()
    }

    fn mark_published_pending_finalize(
        &self,
        job_id: &MycDeliveryOutboxJobId,
        publish_attempt_count: usize,
    ) -> Result<MycDeliveryOutboxRecord, MycError> {
        self.update_record(job_id, |record| {
            record.mark_published_pending_finalize(publish_attempt_count, now_unix_secs())
        })
    }

    fn mark_failed(
        &self,
        job_id: &MycDeliveryOutboxJobId,
        publish_attempt_count: usize,
        error: &str,
    ) -> Result<MycDeliveryOutboxRecord, MycError> {
        self.update_record(job_id, |record| {
            record.mark_failed(publish_attempt_count, error, now_unix_secs())
        })
    }

    fn mark_finalized(
        &self,
        job_id: &MycDeliveryOutboxJobId,
    ) -> Result<MycDeliveryOutboxRecord, MycError> {
        self.update_record(job_id, |record| record.mark_finalized(now_unix_secs()))
    }
}

impl MycDeliveryOutboxRow {
    fn into_record(self, path: &Path) -> Result<MycDeliveryOutboxRecord, MycError> {
        Ok(MycDeliveryOutboxRecord {
            job_id: self.job_id.parse()?,
            kind: parse_kind(self.kind.as_str())?,
            status: parse_status(self.status.as_str())?,
            event: parse_json_field(path, self.event_json.as_str(), "event_json")?,
            relay_urls: parse_json_field(path, self.relay_urls_json.as_str(), "relay_urls_json")?,
            connection_id: self.connection_id.as_deref().map(str::parse).transpose()?,
            request_id: self.request_id,
            attempt_id: self.attempt_id,
            signer_publish_workflow_id: self
                .signer_publish_workflow_id
                .as_deref()
                .map(str::parse)
                .transpose()?,
            publish_attempt_count: usize_from_i64(
                path,
                self.publish_attempt_count,
                "publish_attempt_count",
            )?,
            last_error: self.last_error,
            created_at_unix: self.created_at_unix,
            updated_at_unix: self.updated_at_unix,
            published_at_unix: self.published_at_unix,
            finalized_at_unix: self.finalized_at_unix,
        })
    }
}

impl MycDeliveryOutboxSqliteDb {
    fn open(path: PathBuf) -> Result<Self, MycError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|source| MycError::CreateDir {
                path: parent.to_path_buf(),
                source,
            })?;
        }
        let executor =
            SqliteExecutor::open(path.as_path()).map_err(|source| MycError::DeliveryOutboxSql {
                path: path.clone(),
                source,
            })?;
        let db = Self {
            path,
            executor,
            file_backed: true,
        };
        db.configure()?;
        db.run_migrations()?;
        Ok(db)
    }

    #[cfg(test)]
    fn open_memory() -> Result<Self, MycError> {
        let executor =
            SqliteExecutor::open_memory().map_err(|source| MycError::DeliveryOutboxSql {
                path: PathBuf::from(MYC_DELIVERY_OUTBOX_MEMORY_PATH),
                source,
            })?;
        let db = Self {
            path: PathBuf::from(MYC_DELIVERY_OUTBOX_MEMORY_PATH),
            executor,
            file_backed: false,
        };
        db.configure()?;
        db.run_migrations()?;
        Ok(db)
    }

    fn path(&self) -> &Path {
        self.path.as_path()
    }

    fn executor(&self) -> &SqliteExecutor {
        &self.executor
    }

    fn configure(&self) -> Result<(), MycError> {
        exec_json(
            self.path(),
            self.executor(),
            "PRAGMA foreign_keys = ON",
            json!([]),
        )?;
        if self.file_backed {
            exec_json(
                self.path(),
                self.executor(),
                "PRAGMA journal_mode = WAL",
                json!([]),
            )?;
        }
        Ok(())
    }

    fn run_migrations(&self) -> Result<(), MycError> {
        migrations_run_all_up(self.executor(), MYC_DELIVERY_OUTBOX_MIGRATIONS).map_err(|source| {
            MycError::DeliveryOutboxSql {
                path: self.path.clone(),
                source,
            }
        })
    }
}

fn serialize_record_params(
    path: &Path,
    record: &MycDeliveryOutboxRecord,
) -> Result<Value, MycError> {
    Ok(Value::Array(vec![
        Value::from(record.job_id.as_str()),
        Value::from(kind_label(record.kind)),
        Value::from(status_label(record.status)),
        Value::from(serialize_json_field(path, &record.event)?),
        Value::from(serialize_json_field(path, &record.relay_urls)?),
        record
            .connection_id
            .as_ref()
            .map(|value| Value::from(value.as_str()))
            .unwrap_or(Value::Null),
        record
            .request_id
            .clone()
            .map(Value::from)
            .unwrap_or(Value::Null),
        record
            .attempt_id
            .clone()
            .map(Value::from)
            .unwrap_or(Value::Null),
        record
            .signer_publish_workflow_id
            .as_ref()
            .map(|value| Value::from(value.as_str()))
            .unwrap_or(Value::Null),
        Value::from(i64::try_from(record.publish_attempt_count).map_err(|_| {
            MycError::InvalidOperation(
                "delivery outbox publish_attempt_count exceeds sqlite range".to_owned(),
            )
        })?),
        record
            .last_error
            .clone()
            .map(Value::from)
            .unwrap_or(Value::Null),
        Value::from(record.created_at_unix),
        Value::from(record.updated_at_unix),
        record
            .published_at_unix
            .map(Value::from)
            .unwrap_or(Value::Null),
        record
            .finalized_at_unix
            .map(Value::from)
            .unwrap_or(Value::Null),
    ]))
}

fn serialize_record_update_params(
    path: &Path,
    record: &MycDeliveryOutboxRecord,
    trailing_job_id: &str,
) -> Result<Value, MycError> {
    Ok(Value::Array(vec![
        Value::from(kind_label(record.kind)),
        Value::from(status_label(record.status)),
        Value::from(serialize_json_field(path, &record.event)?),
        Value::from(serialize_json_field(path, &record.relay_urls)?),
        record
            .connection_id
            .as_ref()
            .map(|value| Value::from(value.as_str()))
            .unwrap_or(Value::Null),
        record
            .request_id
            .clone()
            .map(Value::from)
            .unwrap_or(Value::Null),
        record
            .attempt_id
            .clone()
            .map(Value::from)
            .unwrap_or(Value::Null),
        record
            .signer_publish_workflow_id
            .as_ref()
            .map(|value| Value::from(value.as_str()))
            .unwrap_or(Value::Null),
        Value::from(i64::try_from(record.publish_attempt_count).map_err(|_| {
            MycError::InvalidOperation(
                "delivery outbox publish_attempt_count exceeds sqlite range".to_owned(),
            )
        })?),
        record
            .last_error
            .clone()
            .map(Value::from)
            .unwrap_or(Value::Null),
        Value::from(record.created_at_unix),
        Value::from(record.updated_at_unix),
        record
            .published_at_unix
            .map(Value::from)
            .unwrap_or(Value::Null),
        record
            .finalized_at_unix
            .map(Value::from)
            .unwrap_or(Value::Null),
        Value::from(trailing_job_id),
    ]))
}

fn exec_json(
    path: &Path,
    executor: &impl SqlExecutor,
    sql: &str,
    params: Value,
) -> Result<(), MycError> {
    executor
        .exec(sql, params.to_string().as_str())
        .map_err(|source| MycError::DeliveryOutboxSql {
            path: path.to_path_buf(),
            source,
        })?;
    Ok(())
}

fn query_rows<T: DeserializeOwned>(
    path: &Path,
    executor: &impl SqlExecutor,
    sql: &str,
    params: Value,
) -> Result<Vec<T>, MycError> {
    let raw = executor
        .query_raw(sql, params.to_string().as_str())
        .map_err(|source| MycError::DeliveryOutboxSql {
            path: path.to_path_buf(),
            source,
        })?;
    serde_json::from_str(&raw).map_err(|source| MycError::DeliveryOutboxSqlDecode {
        path: path.to_path_buf(),
        source,
    })
}

fn serialize_json_field(path: &Path, value: &impl serde::Serialize) -> Result<String, MycError> {
    serde_json::to_string(value).map_err(|source| MycError::DeliveryOutboxSerialize {
        path: path.to_path_buf(),
        source,
    })
}

fn parse_json_field<T: DeserializeOwned>(
    path: &Path,
    value: &str,
    _field: &str,
) -> Result<T, MycError> {
    serde_json::from_str(value).map_err(|source| MycError::DeliveryOutboxSqlDecode {
        path: path.to_path_buf(),
        source,
    })
}

fn kind_label(kind: MycDeliveryOutboxKind) -> &'static str {
    match kind {
        MycDeliveryOutboxKind::ListenerResponsePublish => "listener_response_publish",
        MycDeliveryOutboxKind::ConnectAcceptPublish => "connect_accept_publish",
        MycDeliveryOutboxKind::AuthReplayPublish => "auth_replay_publish",
        MycDeliveryOutboxKind::DiscoveryHandlerPublish => "discovery_handler_publish",
    }
}

fn parse_kind(value: &str) -> Result<MycDeliveryOutboxKind, MycError> {
    match value {
        "listener_response_publish" => Ok(MycDeliveryOutboxKind::ListenerResponsePublish),
        "connect_accept_publish" => Ok(MycDeliveryOutboxKind::ConnectAcceptPublish),
        "auth_replay_publish" => Ok(MycDeliveryOutboxKind::AuthReplayPublish),
        "discovery_handler_publish" => Ok(MycDeliveryOutboxKind::DiscoveryHandlerPublish),
        other => Err(MycError::InvalidOperation(format!(
            "unknown delivery outbox kind `{other}`"
        ))),
    }
}

fn status_label(status: MycDeliveryOutboxStatus) -> &'static str {
    match status {
        MycDeliveryOutboxStatus::Queued => "queued",
        MycDeliveryOutboxStatus::PublishedPendingFinalize => "published_pending_finalize",
        MycDeliveryOutboxStatus::Finalized => "finalized",
        MycDeliveryOutboxStatus::Failed => "failed",
    }
}

fn parse_status(value: &str) -> Result<MycDeliveryOutboxStatus, MycError> {
    match value {
        "queued" => Ok(MycDeliveryOutboxStatus::Queued),
        "published_pending_finalize" => Ok(MycDeliveryOutboxStatus::PublishedPendingFinalize),
        "finalized" => Ok(MycDeliveryOutboxStatus::Finalized),
        "failed" => Ok(MycDeliveryOutboxStatus::Failed),
        other => Err(MycError::InvalidOperation(format!(
            "unknown delivery outbox status `{other}`"
        ))),
    }
}

fn usize_from_i64(path: &Path, value: i64, field: &str) -> Result<usize, MycError> {
    usize::try_from(value).map_err(|_| {
        MycError::InvalidOperation(format!(
            "delivery outbox field `{field}` at {} is out of range for usize",
            path.display()
        ))
    })
}

#[cfg(test)]
mod tests {
    use radroots_identity::RadrootsIdentity;
    use radroots_nostr::prelude::{RadrootsNostrEventBuilder, RadrootsNostrKind};
    use radroots_nostr_signer::prelude::{
        RadrootsNostrSignerConnectionId, RadrootsNostrSignerWorkflowId,
    };

    use crate::outbox::{
        MycDeliveryOutboxKind, MycDeliveryOutboxRecord, MycDeliveryOutboxStatus,
        MycDeliveryOutboxStore,
    };

    use super::MycSqliteDeliveryOutboxStore;

    fn sample_record() -> MycDeliveryOutboxRecord {
        let identity = RadrootsIdentity::from_secret_key_str(
            "1111111111111111111111111111111111111111111111111111111111111111",
        )
        .expect("identity");
        let event = RadrootsNostrEventBuilder::new(RadrootsNostrKind::Custom(24133), "hello")
            .sign_with_keys(identity.keys())
            .expect("sign event");
        MycDeliveryOutboxRecord::new(
            MycDeliveryOutboxKind::AuthReplayPublish,
            event,
            vec!["wss://relay.example.com".parse().expect("relay")],
        )
        .expect("record")
        .with_connection_id(
            &RadrootsNostrSignerConnectionId::parse("conn-sqlite-outbox").expect("id"),
        )
        .with_request_id("req-sqlite-outbox")
        .with_attempt_id("attempt-sqlite-outbox")
        .with_signer_publish_workflow_id(
            &RadrootsNostrSignerWorkflowId::parse("wf-sqlite-outbox").expect("id"),
        )
    }

    #[test]
    fn sqlite_outbox_store_round_trips_and_updates_status() {
        let store = MycSqliteDeliveryOutboxStore::open_memory().expect("open store");
        let record = sample_record();

        store.enqueue(&record).expect("enqueue");
        assert_eq!(
            store.get(&record.job_id).expect("get"),
            Some(record.clone())
        );
        assert_eq!(store.list_all().expect("list all"), vec![record.clone()]);
        assert_eq!(
            store
                .list_by_status(MycDeliveryOutboxStatus::Queued)
                .expect("list queued"),
            vec![record.clone()]
        );

        let published = store
            .mark_published_pending_finalize(&record.job_id, 1)
            .expect("mark published");
        assert_eq!(
            published.status,
            MycDeliveryOutboxStatus::PublishedPendingFinalize
        );
        assert_eq!(published.publish_attempt_count, 1);

        let failed = store
            .mark_failed(&record.job_id, 2, "relay rejected")
            .expect("mark failed");
        assert_eq!(failed.status, MycDeliveryOutboxStatus::Failed);
        assert_eq!(failed.last_error.as_deref(), Some("relay rejected"));

        let republished = store
            .mark_published_pending_finalize(&record.job_id, 3)
            .expect("republish");
        assert_eq!(
            republished.status,
            MycDeliveryOutboxStatus::PublishedPendingFinalize
        );

        let finalized = store
            .mark_finalized(&record.job_id)
            .expect("mark finalized");
        assert_eq!(finalized.status, MycDeliveryOutboxStatus::Finalized);
        assert_eq!(
            store
                .list_by_status(MycDeliveryOutboxStatus::Finalized)
                .expect("list finalized"),
            vec![finalized]
        );
    }

    #[test]
    fn sqlite_outbox_store_reopens_file_backed_state() {
        let temp = tempfile::tempdir().expect("tempdir");
        let record = sample_record();

        let store = MycSqliteDeliveryOutboxStore::open(temp.path()).expect("open store");
        store.enqueue(&record).expect("enqueue");

        let reopened = MycSqliteDeliveryOutboxStore::open(temp.path()).expect("reopen store");
        assert_eq!(
            reopened.get(&record.job_id).expect("get reopened"),
            Some(record)
        );
        assert!(reopened.path().ends_with("delivery-outbox.sqlite"));
    }
}
