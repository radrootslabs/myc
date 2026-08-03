//! Myc-owned synchronous SQLite adapter for service persistence.

use std::path::Path;
use std::sync::{Arc, Mutex};

use serde::Serialize;
use serde_json::{Map, Value, json};
use sqlx::sqlite::{SqliteArguments, SqliteConnectOptions, SqliteConnection, SqliteRow};
use sqlx::{Column, Connection, Row, TypeInfo, ValueRef};

#[derive(Debug, Clone, Serialize)]
pub enum SqlError {
    InvalidArgument(String),
    NotFound(String),
    SerializationError(String),
    InvalidQuery(String),
    Internal,
    UnsupportedPlatform,
}

impl std::fmt::Display for SqlError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidArgument(value) => write!(formatter, "invalid argument: {value}"),
            Self::NotFound(value) => write!(formatter, "{value} not found"),
            Self::SerializationError(value) => write!(formatter, "serialization error: {value}"),
            Self::InvalidQuery(value) => write!(formatter, "invalid query: {value}"),
            Self::Internal => formatter.write_str("internal error"),
            Self::UnsupportedPlatform => formatter.write_str("unsupported on this platform"),
        }
    }
}

impl std::error::Error for SqlError {}

impl From<serde_json::Error> for SqlError {
    fn from(error: serde_json::Error) -> Self {
        Self::SerializationError(error.to_string())
    }
}

impl From<sqlx::Error> for SqlError {
    fn from(error: sqlx::Error) -> Self {
        Self::InvalidQuery(error.to_string())
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ExecOutcome {
    pub changes: i64,
    pub last_insert_id: i64,
}

pub trait SqlExecutor: Send + Sync {
    fn exec(&self, sql: &str, params_json: &str) -> Result<ExecOutcome, SqlError>;
    fn query_raw(&self, sql: &str, params_json: &str) -> Result<String, SqlError>;
    fn begin(&self) -> Result<(), SqlError>;
    fn commit(&self) -> Result<(), SqlError>;
    fn rollback(&self) -> Result<(), SqlError>;
}

impl<T> SqlExecutor for &T
where
    T: SqlExecutor + ?Sized,
{
    fn exec(&self, sql: &str, params_json: &str) -> Result<ExecOutcome, SqlError> {
        (**self).exec(sql, params_json)
    }

    fn query_raw(&self, sql: &str, params_json: &str) -> Result<String, SqlError> {
        (**self).query_raw(sql, params_json)
    }

    fn begin(&self) -> Result<(), SqlError> {
        (**self).begin()
    }

    fn commit(&self) -> Result<(), SqlError> {
        (**self).commit()
    }

    fn rollback(&self) -> Result<(), SqlError> {
        (**self).rollback()
    }
}

pub struct SqlxSqliteExecutor {
    connection: Arc<Mutex<SqliteConnection>>,
}

impl SqlxSqliteExecutor {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, SqlError> {
        Self::connect(
            SqliteConnectOptions::new()
                .filename(path)
                .create_if_missing(true),
        )
    }

    pub fn open_memory() -> Result<Self, SqlError> {
        Self::connect(SqliteConnectOptions::new().in_memory(true))
    }

    fn connect(options: SqliteConnectOptions) -> Result<Self, SqlError> {
        let connection = futures_executor::block_on(SqliteConnection::connect_with(&options))?;
        Ok(Self {
            connection: Arc::new(Mutex::new(connection)),
        })
    }
}

impl SqlExecutor for SqlxSqliteExecutor {
    fn exec(&self, sql: &str, params_json: &str) -> Result<ExecOutcome, SqlError> {
        let binds = parse_params(params_json)?;
        let mut connection = self.connection.lock().map_err(|_| SqlError::Internal)?;
        if binds.is_empty() {
            let result = futures_executor::block_on(
                sqlx::raw_sql(sqlx::AssertSqlSafe(sql)).execute(&mut *connection),
            )?;
            return Ok(ExecOutcome {
                changes: i64::try_from(result.rows_affected()).map_err(|_| SqlError::Internal)?,
                last_insert_id: result.last_insert_rowid(),
            });
        }
        let query = bind_params(sqlx::query(sqlx::AssertSqlSafe(sql)), binds);
        let result = futures_executor::block_on(query.execute(&mut *connection))?;
        Ok(ExecOutcome {
            changes: i64::try_from(result.rows_affected()).map_err(|_| SqlError::Internal)?,
            last_insert_id: result.last_insert_rowid(),
        })
    }

    fn query_raw(&self, sql: &str, params_json: &str) -> Result<String, SqlError> {
        let query = bind_params(
            sqlx::query(sqlx::AssertSqlSafe(sql)),
            parse_params(params_json)?,
        );
        let rows = {
            let mut connection = self.connection.lock().map_err(|_| SqlError::Internal)?;
            futures_executor::block_on(query.fetch_all(&mut *connection))?
        };
        let rows = rows
            .iter()
            .map(row_to_json)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Value::from(rows).to_string())
    }

    fn begin(&self) -> Result<(), SqlError> {
        self.exec_transaction("BEGIN")
    }

    fn commit(&self) -> Result<(), SqlError> {
        self.exec_transaction("COMMIT")
    }

    fn rollback(&self) -> Result<(), SqlError> {
        self.exec_transaction("ROLLBACK")
    }
}

impl SqlxSqliteExecutor {
    fn exec_transaction(&self, statement: &str) -> Result<(), SqlError> {
        let mut connection = self.connection.lock().map_err(|_| SqlError::Internal)?;
        futures_executor::block_on(
            sqlx::query(sqlx::AssertSqlSafe(statement)).execute(&mut *connection),
        )?;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Migration {
    pub name: &'static str,
    pub up_sql: &'static str,
    pub down_sql: &'static str,
}

pub fn migrations_run_all_up(
    executor: &impl SqlExecutor,
    migrations: &[Migration],
) -> Result<(), SqlError> {
    ensure_migrations_table(executor)?;
    for migration in migrations {
        let rows: Vec<Value> = serde_json::from_str(&executor.query_raw(
            "select 1 as applied from __migrations where name = ? limit 1",
            &json!([migration.name]).to_string(),
        )?)?;
        if rows.is_empty() {
            executor.begin()?;
            let result = (|| {
                executor.exec(migration.up_sql, "[]")?;
                executor.exec(
                    "insert or ignore into __migrations(name) values(?)",
                    &json!([migration.name]).to_string(),
                )?;
                Ok::<_, SqlError>(())
            })();
            if let Err(error) = result {
                let _ = executor.rollback();
                return Err(error);
            }
            executor.commit()?;
        }
    }
    Ok(())
}

pub fn migrations_run_all_down(
    executor: &impl SqlExecutor,
    migrations: &[Migration],
) -> Result<(), SqlError> {
    ensure_migrations_table(executor)?;
    executor.begin()?;
    for migration in migrations.iter().rev() {
        executor.exec(
            "delete from __migrations where name = ?",
            &json!([migration.name]).to_string(),
        )?;
        executor.exec(migration.down_sql, "[]")?;
    }
    executor.commit()
}

fn ensure_migrations_table(executor: &impl SqlExecutor) -> Result<(), SqlError> {
    executor.exec(
        "create table if not exists __migrations(id integer primary key, name text not null unique, applied_at text not null default (datetime('now')))",
        "[]",
    )?;
    Ok(())
}

#[derive(Debug)]
enum BindValue {
    Null,
    Integer(i64),
    Real(f64),
    Text(String),
}

fn parse_params(params_json: &str) -> Result<Vec<BindValue>, SqlError> {
    serde_json::from_str::<Vec<Value>>(params_json)?
        .into_iter()
        .map(|value| match value {
            Value::Null => Ok(BindValue::Null),
            Value::Bool(value) => Ok(BindValue::Integer(i64::from(value))),
            Value::Number(value) if value.is_i64() => {
                Ok(BindValue::Integer(value.as_i64().expect("checked")))
            }
            Value::Number(value) if value.is_u64() => value
                .as_u64()
                .and_then(|value| i64::try_from(value).ok())
                .map(BindValue::Integer)
                .ok_or_else(|| SqlError::InvalidArgument("integer bind exceeds i64".into())),
            Value::Number(value) => value
                .as_f64()
                .map(BindValue::Real)
                .ok_or_else(|| SqlError::InvalidArgument("unsupported number".into())),
            Value::String(value) => Ok(BindValue::Text(value)),
            _ => Err(SqlError::InvalidArgument("unsupported bind value".into())),
        })
        .collect()
}

fn bind_params<'q>(
    mut query: sqlx::query::Query<'q, sqlx::Sqlite, SqliteArguments>,
    params: Vec<BindValue>,
) -> sqlx::query::Query<'q, sqlx::Sqlite, SqliteArguments> {
    for param in params {
        query = match param {
            BindValue::Null => query.bind(Option::<String>::None),
            BindValue::Integer(value) => query.bind(value),
            BindValue::Real(value) => query.bind(value),
            BindValue::Text(value) => query.bind(value),
        };
    }
    query
}

fn row_to_json(row: &SqliteRow) -> Result<Value, SqlError> {
    let mut object = Map::new();
    for (index, column) in row.columns().iter().enumerate() {
        let raw = row.try_get_raw(index)?;
        let value = if raw.is_null() {
            Value::Null
        } else {
            match raw.type_info().name() {
                "INTEGER" | "BOOLEAN" => Value::from(row.try_get::<i64, _>(index)?),
                "REAL" => Value::from(row.try_get::<f64, _>(index)?),
                "TEXT" | "DATE" | "TIME" | "DATETIME" => {
                    Value::from(row.try_get::<String, _>(index)?)
                }
                "BLOB" => Value::Null,
                other => return Err(SqlError::InvalidQuery(other.to_owned())),
            }
        };
        object.insert(column.name().to_owned(), value);
    }
    Ok(Value::Object(object))
}

pub mod error {
    pub use super::SqlError;
}

pub mod migrations {
    pub use super::{Migration, migrations_run_all_down, migrations_run_all_up};
}
