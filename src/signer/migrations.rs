use crate::sql::SqlExecutor;
use crate::sql::error::SqlError;
use crate::sql::migrations::{Migration, migrations_run_all_down, migrations_run_all_up};

pub static MIGRATIONS: &[Migration] = &[
    Migration {
        name: "0000_init",
        up_sql: include_str!("../../migrations/signer/0000_init.up.sql"),
        down_sql: include_str!("../../migrations/signer/0000_init.down.sql"),
    },
    Migration {
        name: "0001_publish_workflows",
        up_sql: include_str!("../../migrations/signer/0001_publish_workflows.up.sql"),
        down_sql: include_str!("../../migrations/signer/0001_publish_workflows.down.sql"),
    },
    Migration {
        name: "0002_client_metadata",
        up_sql: include_str!("../../migrations/signer/0002_client_metadata.up.sql"),
        down_sql: include_str!("../../migrations/signer/0002_client_metadata.down.sql"),
    },
];

pub fn run_all_up<E>(executor: &E) -> Result<(), SqlError>
where
    E: SqlExecutor,
{
    migrations_run_all_up(executor, MIGRATIONS)
}

pub fn run_all_down<E>(executor: &E) -> Result<(), SqlError>
where
    E: SqlExecutor,
{
    migrations_run_all_down(executor, MIGRATIONS)
}
