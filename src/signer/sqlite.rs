use crate::signer::error::RadrootsNostrSignerError;
use crate::signer::migrations;
use crate::sql::{SqlExecutor, SqlxSqliteExecutor};
use serde::Deserialize;
use std::path::Path;

#[derive(Deserialize)]
struct SqliteJournalModeRow {
    journal_mode: String,
}

pub struct RadrootsNostrSignerSqliteDb {
    executor: SqlxSqliteExecutor,
    file_backed: bool,
}

impl RadrootsNostrSignerSqliteDb {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, RadrootsNostrSignerError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)
                .map_err(|error| RadrootsNostrSignerError::Store(error.to_string()))?;
        }
        let executor = SqlxSqliteExecutor::open(path)?;
        let db = Self {
            executor,
            file_backed: true,
        };
        db.configure()?;
        db.migrate_up()?;
        Ok(db)
    }

    pub fn open_memory() -> Result<Self, RadrootsNostrSignerError> {
        let executor = SqlxSqliteExecutor::open_memory()?;
        let db = Self {
            executor,
            file_backed: false,
        };
        db.configure()?;
        db.migrate_up()?;
        Ok(db)
    }

    pub fn executor(&self) -> &SqlxSqliteExecutor {
        &self.executor
    }

    pub fn migrate_up(&self) -> Result<(), RadrootsNostrSignerError> {
        migrations::run_all_up(&self.executor)?;
        Ok(())
    }

    pub fn migrate_down(&self) -> Result<(), RadrootsNostrSignerError> {
        migrations::run_all_down(&self.executor)?;
        Ok(())
    }

    fn configure(&self) -> Result<(), RadrootsNostrSignerError> {
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
        let _ = self.executor.exec(pragma_batch, "[]")?;
        let (journal_mode_sql, expected_journal_mode) = if self.file_backed {
            ("PRAGMA main.journal_mode = WAL", "wal")
        } else {
            ("PRAGMA main.journal_mode = MEMORY", "memory")
        };
        let result = self.executor.query_raw(journal_mode_sql, "[]")?;
        validate_journal_mode_result(&result, expected_journal_mode)
    }
}

fn validate_journal_mode_result(
    result: &str,
    expected: &'static str,
) -> Result<(), RadrootsNostrSignerError> {
    let rows: Vec<SqliteJournalModeRow> = serde_json::from_str(result)?;
    let [row] = rows.as_slice() else {
        return Err(
            RadrootsNostrSignerError::SqliteJournalModeResultCardinality {
                actual_rows: rows.len(),
            },
        );
    };
    if row.journal_mode != expected {
        return Err(RadrootsNostrSignerError::SqliteJournalModeMismatch {
            expected,
            actual: row.journal_mode.clone(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{RadrootsNostrSignerSqliteDb, validate_journal_mode_result};
    use crate::signer::error::RadrootsNostrSignerError;
    use crate::sql::SqlExecutor;
    use serde_json::Value;

    fn query_values(
        db: &RadrootsNostrSignerSqliteDb,
        sql: &str,
    ) -> Vec<serde_json::Map<String, Value>> {
        let raw = db.executor().query_raw(sql, "[]").expect("query");
        serde_json::from_str::<Vec<serde_json::Map<String, Value>>>(&raw).expect("rows")
    }

    fn query_single_text(db: &RadrootsNostrSignerSqliteDb, sql: &str, field: &str) -> String {
        query_values(db, sql)
            .into_iter()
            .next()
            .and_then(|row| row.get(field).cloned())
            .and_then(|value| value.as_str().map(ToOwned::to_owned))
            .expect("single text row")
    }

    fn query_single_i64(db: &RadrootsNostrSignerSqliteDb, sql: &str, field: &str) -> i64 {
        query_values(db, sql)
            .into_iter()
            .next()
            .and_then(|row| row.get(field).cloned())
            .and_then(|value| value.as_i64())
            .expect("single integer row")
    }

    #[test]
    fn open_memory_bootstraps_schema_and_migrations_idempotently() {
        let db = RadrootsNostrSignerSqliteDb::open_memory().expect("open memory db");
        db.migrate_up().expect("rerun migrations");
        assert_eq!(
            query_single_text(&db, "PRAGMA main.journal_mode", "journal_mode"),
            "memory"
        );

        let tables = query_values(
            &db,
            "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name",
        );
        let table_names = tables
            .into_iter()
            .filter_map(|row| {
                row.get("name")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned)
            })
            .collect::<Vec<_>>();
        assert!(table_names.iter().any(|name| name == "__migrations"));
        assert!(
            table_names
                .iter()
                .any(|name| name == "signer_store_metadata")
        );
        assert!(table_names.iter().any(|name| name == "signer_connection"));
        assert!(
            table_names
                .iter()
                .any(|name| name == "signer_connection_permission_grant")
        );
        assert!(
            table_names
                .iter()
                .any(|name| name == "signer_connection_relay")
        );
        assert!(
            table_names
                .iter()
                .any(|name| name == "signer_connection_auth_challenge")
        );
        assert!(
            table_names
                .iter()
                .any(|name| name == "signer_connection_pending_request")
        );
        assert!(
            table_names
                .iter()
                .any(|name| name == "signer_request_audit")
        );
        assert!(
            table_names
                .iter()
                .any(|name| name == "signer_publish_workflow")
        );

        let migration_count = query_single_i64(
            &db,
            "SELECT COUNT(*) AS applied_count FROM __migrations",
            "applied_count",
        );
        assert_eq!(migration_count, 3);

        let connection_columns = query_values(&db, "PRAGMA table_info(signer_connection)");
        assert!(connection_columns.iter().any(|row| {
            row.get("name").and_then(Value::as_str) == Some("client_metadata_json")
        }));

        let store_version = query_single_i64(
            &db,
            "SELECT store_version FROM signer_store_metadata WHERE singleton_id = 1",
            "store_version",
        );
        assert_eq!(store_version, 1);
    }

    #[test]
    fn file_database_uses_wal_and_foreign_keys() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("signer.sqlite");
        {
            let db = RadrootsNostrSignerSqliteDb::open(&path).expect("open sqlite file db");

            assert_eq!(
                query_single_text(&db, "PRAGMA main.journal_mode", "journal_mode"),
                "wal"
            );
            assert_eq!(
                query_single_i64(&db, "PRAGMA foreign_keys", "foreign_keys"),
                1
            );
        }

        let reopened = RadrootsNostrSignerSqliteDb::open(&path).expect("reopen sqlite file db");
        assert_eq!(
            query_single_text(&reopened, "PRAGMA main.journal_mode", "journal_mode"),
            "wal"
        );
    }

    #[test]
    fn journal_mode_result_validation_fails_closed() {
        assert!(matches!(
            validate_journal_mode_result(r#"[{"journal_mode":"delete"}]"#, "wal"),
            Err(RadrootsNostrSignerError::SqliteJournalModeMismatch {
                expected: "wal",
                actual,
            }) if actual == "delete"
        ));
        assert!(matches!(
            validate_journal_mode_result("[]", "wal"),
            Err(RadrootsNostrSignerError::SqliteJournalModeResultCardinality { actual_rows: 0 })
        ));
        assert!(matches!(
            validate_journal_mode_result(
                r#"[{"journal_mode":"wal"},{"journal_mode":"delete"}]"#,
                "wal"
            ),
            Err(RadrootsNostrSignerError::SqliteJournalModeResultCardinality { actual_rows: 2 })
        ));
    }

    #[test]
    fn migrate_down_and_up_roundtrip_restores_schema() {
        let db = RadrootsNostrSignerSqliteDb::open_memory().expect("open memory db");
        db.migrate_down().expect("migrate down");

        let tables = query_values(
            &db,
            "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name",
        );
        let table_names = tables
            .into_iter()
            .filter_map(|row| {
                row.get("name")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned)
            })
            .collect::<Vec<_>>();
        assert_eq!(table_names, vec!["__migrations".to_owned()]);

        db.migrate_up().expect("migrate up again");
        let migration_count = query_single_i64(
            &db,
            "SELECT COUNT(*) AS applied_count FROM __migrations",
            "applied_count",
        );
        assert_eq!(migration_count, 3);
    }
}
