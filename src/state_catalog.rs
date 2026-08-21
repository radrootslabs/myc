//! Immutable Myc schema and migration catalog identity.

use core::fmt;
use std::error::Error;

use radroots_service_sqlite::{
    MigrationCatalog, MigrationChecksum, MigrationDescriptor, SchemaCatalog, SchemaDigest,
    SchemaObject, SchemaObjectKind, SchemaVersionCatalog,
};

/// The shared create-new baseline written before service migrations run.
pub const MYC_STATE_BASE_SCHEMA_VERSION: u32 = 1;

/// The newest governed Myc state schema understood by this binary.
pub const MYC_STATE_SCHEMA_VERSION: u32 = 3;

/// The shared metadata and migration-ledger objects present at schema v1.
pub const MYC_STATE_SCHEMA_VERSION_1_OBJECT_COUNT: u32 = 6;

/// The shared objects plus the three immutable Myc metadata objects at schema v2.
pub const MYC_STATE_SCHEMA_VERSION_2_OBJECT_COUNT: u32 = 9;

/// The shared objects plus Myc metadata and request-admission objects at schema v3.
pub const MYC_STATE_SCHEMA_VERSION_3_OBJECT_COUNT: u32 = 13;

/// SHA-256 identity of the exact schema-v1 object snapshot.
pub const MYC_STATE_SCHEMA_VERSION_1_SHA256: [u8; 32] = [
    0x94, 0xdc, 0x66, 0xfb, 0xca, 0x60, 0x16, 0x79, 0x61, 0x5c, 0x05, 0x52, 0x29, 0xdc, 0x0d, 0xb6,
    0x11, 0x9f, 0x5b, 0xd9, 0x2b, 0x04, 0x39, 0x0c, 0x67, 0xf6, 0x98, 0xa0, 0x36, 0xfa, 0x78, 0xae,
];

/// SHA-256 identity of the schema-v2 object snapshot.
pub const MYC_STATE_SCHEMA_VERSION_2_SHA256: [u8; 32] = [
    0x94, 0x73, 0x9b, 0x5a, 0x34, 0xca, 0x8e, 0xd1, 0x30, 0xb9, 0x46, 0xd0, 0x92, 0x73, 0x1b, 0x59,
    0xbf, 0x15, 0x48, 0xfe, 0x54, 0x1d, 0x9a, 0x92, 0x69, 0xa3, 0x3d, 0x0a, 0xed, 0x1e, 0xa0, 0x9e,
];

/// SHA-256 identity of the ordered Myc migration catalog.
pub const MYC_MIGRATION_CATALOG_SHA256: [u8; 32] = [
    0x3d, 0x79, 0xb7, 0x19, 0xea, 0x3f, 0xe4, 0x63, 0xe2, 0x66, 0xf5, 0xed, 0x0d, 0x1f, 0x09, 0x1e,
    0x3c, 0x33, 0x17, 0x7c, 0x17, 0x82, 0x0d, 0x21, 0xbd, 0x85, 0x96, 0xdf, 0xbd, 0x31, 0xaa, 0x9e,
];

/// SHA-256 identity of the schema catalog bound to the migration catalog.
pub const MYC_STATE_SCHEMA_CATALOG_SHA256: [u8; 32] = [
    0x26, 0x55, 0x64, 0xd0, 0x95, 0x67, 0x72, 0x4f, 0xac, 0x62, 0x1d, 0x1e, 0x00, 0xc3, 0x7d, 0xbc,
    0xcb, 0xe3, 0xcc, 0x24, 0xa9, 0xfa, 0xb0, 0x0e, 0x59, 0xae, 0x70, 0xc6, 0xfe, 0x89, 0x87, 0x2b,
];

/// SHA-256 identity of the schema-v2 migration content.
pub const MYC_STATE_SCHEMA_VERSION_2_MIGRATION_SHA256: [u8; 32] = [
    0xc5, 0xeb, 0x97, 0x8b, 0xda, 0x1b, 0xc7, 0x0c, 0x70, 0xbd, 0x9b, 0xd4, 0x4d, 0x8c, 0xba, 0x70,
    0xcb, 0x28, 0x57, 0xd2, 0x6a, 0x9d, 0xce, 0x74, 0x96, 0x1f, 0x4b, 0x78, 0x1e, 0x71, 0x00, 0x37,
];

/// SHA-256 identity of the schema-v3 migration content.
pub const MYC_STATE_SCHEMA_VERSION_3_MIGRATION_SHA256: [u8; 32] = [
    0x75, 0x31, 0x65, 0x13, 0x6b, 0x3d, 0xac, 0xe0, 0x09, 0x1d, 0x78, 0x2f, 0x33, 0xf6, 0xb1, 0x0c,
    0xa1, 0xa2, 0x82, 0x33, 0x14, 0x15, 0x8d, 0x80, 0xa4, 0x77, 0x5e, 0x0a, 0xf6, 0x28, 0xed, 0xf9,
];

/// SHA-256 identity of the schema-v3 object snapshot.
pub const MYC_STATE_SCHEMA_VERSION_3_SHA256: [u8; 32] = [
    0x57, 0x2f, 0xe6, 0xa4, 0xd3, 0x6c, 0x04, 0x76, 0xec, 0x40, 0x53, 0x6f, 0x48, 0x02, 0x8e, 0x15,
    0x58, 0x48, 0x8f, 0xb8, 0xab, 0xeb, 0xa0, 0xa3, 0x4b, 0xa6, 0x9b, 0x4b, 0x70, 0x80, 0xba, 0x08,
];

/// SHA-256 identity of the Myc metadata table definition.
const MYC_STATE_METADATA_TABLE_SHA256: [u8; 32] = [
    0x16, 0x17, 0x46, 0xa2, 0x26, 0x42, 0x46, 0x2f, 0x2b, 0xdb, 0x08, 0x5b, 0xae, 0xde, 0xb2, 0x3b,
    0xb2, 0x83, 0xee, 0xbe, 0x8b, 0xcc, 0x95, 0x72, 0x38, 0xad, 0xaa, 0x30, 0x78, 0xc0, 0x29, 0x1a,
];

/// SHA-256 identity of the Myc metadata update guard.
const MYC_STATE_METADATA_NO_UPDATE_SHA256: [u8; 32] = [
    0xf0, 0xe3, 0x30, 0xf2, 0x19, 0x63, 0xd4, 0x94, 0xf8, 0x02, 0xf3, 0x55, 0x78, 0x4b, 0x45, 0x1c,
    0xde, 0x2b, 0xd2, 0xc8, 0x0d, 0x90, 0x22, 0x33, 0x0e, 0x61, 0x03, 0x97, 0xd4, 0x3c, 0xbe, 0x08,
];

/// SHA-256 identity of the Myc metadata delete guard.
const MYC_STATE_METADATA_NO_DELETE_SHA256: [u8; 32] = [
    0x05, 0x32, 0x87, 0x93, 0x6d, 0xbb, 0xae, 0x52, 0x0b, 0xff, 0x25, 0xfe, 0x87, 0xd5, 0xd2, 0xd1,
    0xa3, 0xcc, 0xf2, 0x81, 0xc3, 0x5b, 0x14, 0xa0, 0x24, 0xa7, 0x74, 0xa5, 0x67, 0x50, 0x3d, 0x4c,
];

const NIP46_REQUESTS_TABLE_SHA256: [u8; 32] = [
    0x7a, 0x62, 0x77, 0xaa, 0xa9, 0x71, 0x62, 0x2c, 0x1c, 0x7e, 0x0c, 0x0f, 0xab, 0x62, 0xe7, 0xfc,
    0xfa, 0xea, 0x1b, 0x1d, 0x6f, 0x20, 0xda, 0x14, 0x7a, 0x93, 0xc7, 0x80, 0x6d, 0xd4, 0xaa, 0x54,
];
const NIP46_REQUEST_DEDUP_TABLE_SHA256: [u8; 32] = [
    0x1d, 0xe1, 0x60, 0xcb, 0x35, 0xd1, 0x84, 0x66, 0x60, 0xda, 0xfc, 0xa4, 0xae, 0x26, 0x51, 0x12,
    0xd1, 0x4a, 0xa9, 0x19, 0x7e, 0xf3, 0x7f, 0x2a, 0x5a, 0xd7, 0xdf, 0x3d, 0xfe, 0x36, 0xd7, 0x65,
];
const NIP46_REQUESTS_NO_UPDATE_SHA256: [u8; 32] = [
    0x26, 0xfb, 0x6f, 0x52, 0x78, 0x7e, 0x07, 0x8a, 0x4a, 0xb9, 0x2f, 0xa1, 0x19, 0xf4, 0x65, 0x42,
    0x18, 0xea, 0x3d, 0x61, 0xad, 0x58, 0xb2, 0x01, 0x3a, 0x99, 0x0e, 0xbc, 0xc9, 0xd7, 0x6b, 0x35,
];
const NIP46_REQUEST_DEDUP_GUARD_UPDATE_SHA256: [u8; 32] = [
    0x47, 0x57, 0x86, 0x7c, 0x88, 0xe8, 0xec, 0x05, 0x0c, 0xa5, 0x3d, 0x64, 0x79, 0xae, 0x22, 0xb4,
    0x9a, 0x11, 0xa4, 0xff, 0x39, 0x32, 0xd9, 0xa3, 0x88, 0x80, 0xd3, 0x1d, 0x7e, 0x7a, 0x94, 0x6c,
];

macro_rules! myc_state_metadata_table_sql {
    () => {
        r#"CREATE TABLE myc_state_metadata (
    singleton INTEGER NOT NULL PRIMARY KEY CHECK (singleton = 1),
    normalized_config_sha256 BLOB NOT NULL CHECK (length(normalized_config_sha256) = 32),
    transport_public_key TEXT NOT NULL
        CHECK (length(CAST(transport_public_key AS BLOB)) = 64)
        CHECK (transport_public_key NOT GLOB '*[^0-9a-f]*'),
    user_public_key TEXT NOT NULL
        CHECK (length(CAST(user_public_key AS BLOB)) = 64)
        CHECK (user_public_key NOT GLOB '*[^0-9a-f]*'),
    discovery_public_key TEXT
        CHECK (discovery_public_key IS NULL OR (
            length(CAST(discovery_public_key AS BLOB)) = 64
            AND discovery_public_key NOT GLOB '*[^0-9a-f]*'
        )),
    config_contract_version INTEGER NOT NULL
        CHECK (config_contract_version BETWEEN 1 AND 4294967295),
    state_contract_version INTEGER NOT NULL
        CHECK (state_contract_version BETWEEN 1 AND 4294967295),
    operator_contract_version INTEGER NOT NULL
        CHECK (operator_contract_version BETWEEN 1 AND 4294967295),
    status_contract_version INTEGER NOT NULL
        CHECK (status_contract_version BETWEEN 1 AND 4294967295)
) STRICT"#
    };
}

macro_rules! myc_state_metadata_no_update_sql {
    () => {
        r#"CREATE TRIGGER myc_state_metadata_no_update
BEFORE UPDATE ON myc_state_metadata
BEGIN
    SELECT RAISE(ABORT, 'Myc state metadata is immutable');
END"#
    };
}

macro_rules! myc_state_metadata_no_delete_sql {
    () => {
        r#"CREATE TRIGGER myc_state_metadata_no_delete
BEFORE DELETE ON myc_state_metadata
BEGIN
    SELECT RAISE(ABORT, 'Myc state metadata is immutable');
END"#
    };
}

const CREATE_MYC_STATE_METADATA_TABLE_SQL: &str = myc_state_metadata_table_sql!();
const CREATE_MYC_STATE_METADATA_NO_UPDATE_SQL: &str = myc_state_metadata_no_update_sql!();
const CREATE_MYC_STATE_METADATA_NO_DELETE_SQL: &str = myc_state_metadata_no_delete_sql!();

const CREATE_MYC_STATE_METADATA_MIGRATION_SQL: &str = concat!(
    myc_state_metadata_table_sql!(),
    ";\n",
    myc_state_metadata_no_update_sql!(),
    ";\n",
    myc_state_metadata_no_delete_sql!(),
);

macro_rules! nip46_requests_table_sql {
    () => {
        r#"CREATE TABLE nip46_requests (
    operation_id BLOB NOT NULL PRIMARY KEY CHECK (length(operation_id) = 32),
    correlation_id BLOB NOT NULL UNIQUE CHECK (length(correlation_id) = 32),
    operation_nonce BLOB NOT NULL CHECK (length(operation_nonce) = 32),
    request_identity_sha256 BLOB NOT NULL UNIQUE CHECK (length(request_identity_sha256) = 32),
    client_public_key TEXT NOT NULL
        CHECK (length(CAST(client_public_key AS BLOB)) = 64)
        CHECK (client_public_key NOT GLOB '*[^0-9a-f]*'),
    request_id TEXT NOT NULL
        CHECK (length(CAST(request_id AS BLOB)) BETWEEN 1 AND 128),
    first_event_id BLOB NOT NULL CHECK (length(first_event_id) = 32),
    method TEXT NOT NULL CHECK (method IN (
        'connect',
        'get_public_key',
        'get_session_capability',
        'sign_event',
        'nip04_encrypt',
        'nip04_decrypt',
        'nip44_encrypt',
        'nip44_decrypt',
        'ping',
        'switch_relays',
        'logout'
    )),
    request_sha256 BLOB NOT NULL CHECK (length(request_sha256) = 32),
    received_at_unix_ms INTEGER NOT NULL
        CHECK (received_at_unix_ms BETWEEN 1 AND 9223372036854775807)
) STRICT"#
    };
}

macro_rules! nip46_request_dedup_table_sql {
    () => {
        r#"CREATE TABLE nip46_request_dedup (
    dedup_kind TEXT NOT NULL CHECK (dedup_kind IN ('request', 'event')),
    identity_sha256 BLOB NOT NULL CHECK (length(identity_sha256) = 32),
    request_sha256 BLOB NOT NULL CHECK (length(request_sha256) = 32),
    operation_id BLOB NOT NULL CHECK (length(operation_id) = 32)
        REFERENCES nip46_requests(operation_id),
    replay_count INTEGER NOT NULL CHECK (replay_count BETWEEN 0 AND 9223372036854775807),
    conflict_count INTEGER NOT NULL CHECK (conflict_count BETWEEN 0 AND 9223372036854775807),
    first_seen_at_unix_ms INTEGER NOT NULL
        CHECK (first_seen_at_unix_ms BETWEEN 1 AND 9223372036854775807),
    last_seen_at_unix_ms INTEGER NOT NULL
        CHECK (last_seen_at_unix_ms BETWEEN first_seen_at_unix_ms AND 9223372036854775807),
    PRIMARY KEY (dedup_kind, identity_sha256)
) STRICT"#
    };
}

macro_rules! nip46_requests_no_update_sql {
    () => {
        r#"CREATE TRIGGER nip46_requests_no_update
BEFORE UPDATE ON nip46_requests
BEGIN
    SELECT RAISE(ABORT, 'NIP-46 request identity is immutable');
END"#
    };
}

macro_rules! nip46_request_dedup_guard_update_sql {
    () => {
        r#"CREATE TRIGGER nip46_request_dedup_guard_update
BEFORE UPDATE ON nip46_request_dedup
WHEN NEW.dedup_kind != OLD.dedup_kind
    OR NEW.identity_sha256 != OLD.identity_sha256
    OR NEW.request_sha256 != OLD.request_sha256
    OR NEW.operation_id != OLD.operation_id
    OR NEW.first_seen_at_unix_ms != OLD.first_seen_at_unix_ms
    OR NEW.last_seen_at_unix_ms < OLD.last_seen_at_unix_ms
    OR NOT (
        (
            OLD.replay_count < 9223372036854775807
            AND NEW.replay_count = OLD.replay_count + 1
            AND NEW.conflict_count = OLD.conflict_count
        ) OR (
            OLD.conflict_count < 9223372036854775807
            AND NEW.conflict_count = OLD.conflict_count + 1
            AND NEW.replay_count = OLD.replay_count
        )
    )
BEGIN
    SELECT RAISE(ABORT, 'NIP-46 request evidence is append-only');
END"#
    };
}

const CREATE_NIP46_REQUESTS_TABLE_SQL: &str = nip46_requests_table_sql!();
const CREATE_NIP46_REQUEST_DEDUP_TABLE_SQL: &str = nip46_request_dedup_table_sql!();
const CREATE_NIP46_REQUESTS_NO_UPDATE_SQL: &str = nip46_requests_no_update_sql!();
const CREATE_NIP46_REQUEST_DEDUP_GUARD_UPDATE_SQL: &str = nip46_request_dedup_guard_update_sql!();

const CREATE_NIP46_REQUEST_ADMISSION_MIGRATION_SQL: &str = concat!(
    "DROP TRIGGER myc_state_metadata_no_update;\n",
    "UPDATE myc_state_metadata SET state_contract_version = CASE ",
    "WHEN state_contract_version = 2 THEN 3 ELSE 0 END WHERE singleton = 1;\n",
    myc_state_metadata_no_update_sql!(),
    ";\n",
    nip46_requests_table_sql!(),
    ";\n",
    nip46_request_dedup_table_sql!(),
    ";\n",
    nip46_requests_no_update_sql!(),
    ";\n",
    nip46_request_dedup_guard_update_sql!(),
);

/// Stable classes for invalid embedded Myc catalog definitions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MycStateCatalogErrorKind {
    MigrationCatalog,
    SchemaCatalog,
    CatalogMismatch,
}

impl MycStateCatalogErrorKind {
    /// Returns the stable machine-readable classification.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::MigrationCatalog => "migration_catalog_invalid",
            Self::SchemaCatalog => "schema_catalog_invalid",
            Self::CatalogMismatch => "state_catalog_mismatch",
        }
    }
}

/// Source-free failure to construct or validate the embedded Myc catalogs.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MycStateCatalogError {
    kind: MycStateCatalogErrorKind,
}

impl MycStateCatalogError {
    const fn new(kind: MycStateCatalogErrorKind) -> Self {
        Self { kind }
    }

    /// Returns the stable failure class.
    #[must_use]
    pub const fn kind(self) -> MycStateCatalogErrorKind {
        self.kind
    }

    /// Returns the stable machine-readable failure code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        self.kind.code()
    }
}

impl fmt::Display for MycStateCatalogError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            MycStateCatalogErrorKind::MigrationCatalog => {
                "Myc migration catalog definition is invalid"
            }
            MycStateCatalogErrorKind::SchemaCatalog => "Myc schema catalog definition is invalid",
            MycStateCatalogErrorKind::CatalogMismatch => {
                "Myc state catalogs do not match the governed identity"
            }
        })
    }
}

impl fmt::Debug for MycStateCatalogError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MycStateCatalogError")
            .field("kind", &self.kind)
            .finish()
    }
}

impl Error for MycStateCatalogError {}

/// Constructs the exact ordered Myc migration catalog.
pub fn myc_migration_catalog() -> Result<MigrationCatalog, MycStateCatalogError> {
    let metadata = MigrationDescriptor::sql(
        2,
        "create_myc_state_metadata",
        CREATE_MYC_STATE_METADATA_MIGRATION_SQL,
        MigrationChecksum::from_bytes(MYC_STATE_SCHEMA_VERSION_2_MIGRATION_SHA256),
    )
    .map_err(|_| MycStateCatalogError::new(MycStateCatalogErrorKind::MigrationCatalog))?;
    let requests = MigrationDescriptor::sql(
        3,
        "create_nip46_request_admission",
        CREATE_NIP46_REQUEST_ADMISSION_MIGRATION_SQL,
        MigrationChecksum::from_bytes(MYC_STATE_SCHEMA_VERSION_3_MIGRATION_SHA256),
    )
    .map_err(|_| MycStateCatalogError::new(MycStateCatalogErrorKind::MigrationCatalog))?;
    let catalog = MigrationCatalog::new([metadata, requests])
        .map_err(|_| MycStateCatalogError::new(MycStateCatalogErrorKind::MigrationCatalog))?;
    if catalog.current_version() != MYC_STATE_SCHEMA_VERSION
        || catalog.descriptors().len() != 2
        || catalog.digest().as_bytes() != &MYC_MIGRATION_CATALOG_SHA256
    {
        return Err(MycStateCatalogError::new(
            MycStateCatalogErrorKind::CatalogMismatch,
        ));
    }
    Ok(catalog)
}

/// Constructs the exact Myc schema catalog bound to the migration catalog.
pub fn myc_schema_catalog() -> Result<SchemaCatalog, MycStateCatalogError> {
    let migrations = myc_migration_catalog()?;
    let version_one = SchemaVersionCatalog::new(
        MYC_STATE_BASE_SCHEMA_VERSION,
        [],
        SchemaDigest::from_bytes(MYC_STATE_SCHEMA_VERSION_1_SHA256),
    )
    .map_err(|_| MycStateCatalogError::new(MycStateCatalogErrorKind::SchemaCatalog))?;
    let version_two = SchemaVersionCatalog::new(
        2,
        myc_state_metadata_objects()?,
        SchemaDigest::from_bytes(MYC_STATE_SCHEMA_VERSION_2_SHA256),
    )
    .map_err(|_| MycStateCatalogError::new(MycStateCatalogErrorKind::SchemaCatalog))?;
    let version_three = SchemaVersionCatalog::new(
        3,
        myc_state_request_objects()?,
        SchemaDigest::from_bytes(MYC_STATE_SCHEMA_VERSION_3_SHA256),
    )
    .map_err(|_| MycStateCatalogError::new(MycStateCatalogErrorKind::SchemaCatalog))?;
    let catalog = SchemaCatalog::new(&migrations, [version_one, version_two, version_three])
        .map_err(|_| MycStateCatalogError::new(MycStateCatalogErrorKind::SchemaCatalog))?;
    validate_myc_state_catalogs(&migrations, &catalog)?;
    Ok(catalog)
}

fn myc_state_metadata_objects() -> Result<[SchemaObject; 3], MycStateCatalogError> {
    let table = SchemaObject::new(
        SchemaObjectKind::Table,
        "myc_state_metadata",
        "myc_state_metadata",
        CREATE_MYC_STATE_METADATA_TABLE_SQL,
        SchemaDigest::from_bytes(MYC_STATE_METADATA_TABLE_SHA256),
    )
    .map_err(|_| MycStateCatalogError::new(MycStateCatalogErrorKind::SchemaCatalog))?;
    let update = SchemaObject::new(
        SchemaObjectKind::Trigger,
        "myc_state_metadata_no_update",
        "myc_state_metadata",
        CREATE_MYC_STATE_METADATA_NO_UPDATE_SQL,
        SchemaDigest::from_bytes(MYC_STATE_METADATA_NO_UPDATE_SHA256),
    )
    .map_err(|_| MycStateCatalogError::new(MycStateCatalogErrorKind::SchemaCatalog))?;
    let delete = SchemaObject::new(
        SchemaObjectKind::Trigger,
        "myc_state_metadata_no_delete",
        "myc_state_metadata",
        CREATE_MYC_STATE_METADATA_NO_DELETE_SQL,
        SchemaDigest::from_bytes(MYC_STATE_METADATA_NO_DELETE_SHA256),
    )
    .map_err(|_| MycStateCatalogError::new(MycStateCatalogErrorKind::SchemaCatalog))?;
    Ok([table, update, delete])
}

fn myc_state_request_objects() -> Result<[SchemaObject; 7], MycStateCatalogError> {
    let [metadata_table, metadata_update, metadata_delete] = myc_state_metadata_objects()?;
    Ok([
        metadata_table,
        metadata_update,
        metadata_delete,
        SchemaObject::new(
            SchemaObjectKind::Table,
            "nip46_requests",
            "nip46_requests",
            CREATE_NIP46_REQUESTS_TABLE_SQL,
            SchemaDigest::from_bytes(NIP46_REQUESTS_TABLE_SHA256),
        )
        .map_err(|_| MycStateCatalogError::new(MycStateCatalogErrorKind::SchemaCatalog))?,
        SchemaObject::new(
            SchemaObjectKind::Table,
            "nip46_request_dedup",
            "nip46_request_dedup",
            CREATE_NIP46_REQUEST_DEDUP_TABLE_SQL,
            SchemaDigest::from_bytes(NIP46_REQUEST_DEDUP_TABLE_SHA256),
        )
        .map_err(|_| MycStateCatalogError::new(MycStateCatalogErrorKind::SchemaCatalog))?,
        SchemaObject::new(
            SchemaObjectKind::Trigger,
            "nip46_requests_no_update",
            "nip46_requests",
            CREATE_NIP46_REQUESTS_NO_UPDATE_SQL,
            SchemaDigest::from_bytes(NIP46_REQUESTS_NO_UPDATE_SHA256),
        )
        .map_err(|_| MycStateCatalogError::new(MycStateCatalogErrorKind::SchemaCatalog))?,
        SchemaObject::new(
            SchemaObjectKind::Trigger,
            "nip46_request_dedup_guard_update",
            "nip46_request_dedup",
            CREATE_NIP46_REQUEST_DEDUP_GUARD_UPDATE_SQL,
            SchemaDigest::from_bytes(NIP46_REQUEST_DEDUP_GUARD_UPDATE_SHA256),
        )
        .map_err(|_| MycStateCatalogError::new(MycStateCatalogErrorKind::SchemaCatalog))?,
    ])
}

/// Independently validates exact catalog versions, counts, and digests.
pub fn validate_myc_state_catalogs(
    migrations: &MigrationCatalog,
    schema: &SchemaCatalog,
) -> Result<(), MycStateCatalogError> {
    let versions = schema.versions();
    let descriptors = migrations.descriptors();
    let valid = migrations.current_version() == MYC_STATE_SCHEMA_VERSION
        && descriptors.len() == 2
        && descriptors[0].target_version() == 2
        && descriptors[0].name().as_str() == "create_myc_state_metadata"
        && descriptors[0].checksum().as_bytes() == &MYC_STATE_SCHEMA_VERSION_2_MIGRATION_SHA256
        && descriptors[1].target_version() == 3
        && descriptors[1].name().as_str() == "create_nip46_request_admission"
        && descriptors[1].checksum().as_bytes() == &MYC_STATE_SCHEMA_VERSION_3_MIGRATION_SHA256
        && migrations.digest().as_bytes() == &MYC_MIGRATION_CATALOG_SHA256
        && schema.migration_catalog_digest() == migrations.digest()
        && versions.len() == 3
        && versions[0].version() == MYC_STATE_BASE_SCHEMA_VERSION
        && versions[0].object_count() == MYC_STATE_SCHEMA_VERSION_1_OBJECT_COUNT
        && versions[0].digest().as_bytes() == &MYC_STATE_SCHEMA_VERSION_1_SHA256
        && versions[1].version() == 2
        && versions[1].object_count() == MYC_STATE_SCHEMA_VERSION_2_OBJECT_COUNT
        && versions[1].digest().as_bytes() == &MYC_STATE_SCHEMA_VERSION_2_SHA256
        && versions[2].version() == 3
        && versions[2].object_count() == MYC_STATE_SCHEMA_VERSION_3_OBJECT_COUNT
        && versions[2].digest().as_bytes() == &MYC_STATE_SCHEMA_VERSION_3_SHA256
        && schema.digest().as_bytes() == &MYC_STATE_SCHEMA_CATALOG_SHA256;
    if valid {
        Ok(())
    } else {
        Err(MycStateCatalogError::new(
            MycStateCatalogErrorKind::CatalogMismatch,
        ))
    }
}
