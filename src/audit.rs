use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use radroots_nostr_signer::prelude::RadrootsNostrSignerConnectionId;
use serde::{Deserialize, Serialize};

use crate::error::MycError;

const MYC_OPERATION_AUDIT_FILE_NAME: &str = "operations.jsonl";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MycOperationAuditKind {
    ListenerResponsePublish,
    ConnectAcceptPublish,
    AuthReplayPublish,
    AuthReplayRestore,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MycOperationAuditOutcome {
    Succeeded,
    Rejected,
    Restored,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MycOperationAuditRecord {
    pub recorded_at_unix: u64,
    pub operation: MycOperationAuditKind,
    pub outcome: MycOperationAuditOutcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connection_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    pub relay_count: usize,
    pub acknowledged_relay_count: usize,
    pub relay_outcome_summary: String,
}

#[derive(Debug, Clone)]
pub struct MycOperationAuditStore {
    path: PathBuf,
}

impl MycOperationAuditRecord {
    pub fn new(
        operation: MycOperationAuditKind,
        outcome: MycOperationAuditOutcome,
        connection_id: Option<&RadrootsNostrSignerConnectionId>,
        request_id: Option<&str>,
        relay_count: usize,
        acknowledged_relay_count: usize,
        relay_outcome_summary: impl Into<String>,
    ) -> Self {
        Self {
            recorded_at_unix: now_unix_secs(),
            operation,
            outcome,
            connection_id: connection_id.map(ToString::to_string),
            request_id: request_id.map(ToOwned::to_owned),
            relay_count,
            acknowledged_relay_count,
            relay_outcome_summary: relay_outcome_summary.into(),
        }
    }
}

impl MycOperationAuditStore {
    pub fn new(audit_dir: impl AsRef<Path>) -> Self {
        Self {
            path: audit_dir.as_ref().join(MYC_OPERATION_AUDIT_FILE_NAME),
        }
    }

    pub fn path(&self) -> &Path {
        self.path.as_path()
    }

    pub fn append(&self, record: &MycOperationAuditRecord) -> Result<(), MycError> {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|source| MycError::AuditIo {
                path: self.path.clone(),
                source,
            })?;
        serde_json::to_writer(&mut file, record).map_err(|source| MycError::AuditSerialize {
            path: self.path.clone(),
            source,
        })?;
        file.write_all(b"\n").map_err(|source| MycError::AuditIo {
            path: self.path.clone(),
            source,
        })?;
        Ok(())
    }

    pub fn list(&self) -> Result<Vec<MycOperationAuditRecord>, MycError> {
        self.list_matching(|_| true)
    }

    pub fn list_for_connection(
        &self,
        connection_id: &RadrootsNostrSignerConnectionId,
    ) -> Result<Vec<MycOperationAuditRecord>, MycError> {
        self.list_matching(|record| record.connection_id.as_deref() == Some(connection_id.as_str()))
    }

    fn list_matching<F>(&self, predicate: F) -> Result<Vec<MycOperationAuditRecord>, MycError>
    where
        F: Fn(&MycOperationAuditRecord) -> bool,
    {
        if !self.path.exists() {
            return Ok(Vec::new());
        }

        let file = fs::File::open(&self.path).map_err(|source| MycError::AuditIo {
            path: self.path.clone(),
            source,
        })?;
        let reader = BufReader::new(file);
        let mut records = Vec::new();

        for (line_number, line) in reader.lines().enumerate() {
            let line = line.map_err(|source| MycError::AuditIo {
                path: self.path.clone(),
                source,
            })?;
            if line.trim().is_empty() {
                continue;
            }
            let record =
                serde_json::from_str::<MycOperationAuditRecord>(&line).map_err(|source| {
                    MycError::AuditParse {
                        path: self.path.clone(),
                        line_number: line_number + 1,
                        source,
                    }
                })?;
            if predicate(&record) {
                records.push(record);
            }
        }

        Ok(records)
    }
}

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before unix epoch")
        .as_secs()
}

#[cfg(test)]
mod tests {
    use radroots_nostr_signer::prelude::RadrootsNostrSignerConnectionId;

    use super::{
        MycOperationAuditKind, MycOperationAuditOutcome, MycOperationAuditRecord,
        MycOperationAuditStore,
    };

    #[test]
    fn append_and_list_operation_audit_records() {
        let temp = tempfile::tempdir().expect("tempdir");
        let store = MycOperationAuditStore::new(temp.path());
        let connection_id =
            RadrootsNostrSignerConnectionId::parse("connection-1").expect("connection id");

        store
            .append(&MycOperationAuditRecord::new(
                MycOperationAuditKind::ConnectAcceptPublish,
                MycOperationAuditOutcome::Rejected,
                Some(&connection_id),
                Some("request-1"),
                2,
                0,
                "0/2 relays acknowledged publish; failures: relay-a: rejected",
            ))
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
        assert_eq!(records[0].connection_id.as_deref(), Some("connection-1"));
        assert_eq!(records[0].request_id.as_deref(), Some("request-1"));
        assert_eq!(records[0].relay_count, 2);
        assert_eq!(records[0].acknowledged_relay_count, 0);

        let connection_records = store
            .list_for_connection(&connection_id)
            .expect("list connection records");
        assert_eq!(connection_records, records);
    }

    #[test]
    fn list_returns_empty_when_audit_file_is_missing() {
        let temp = tempfile::tempdir().expect("tempdir");
        let store = MycOperationAuditStore::new(temp.path());

        assert!(store.list().expect("list missing records").is_empty());
    }
}
