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
pub const MYC_STATE_SCHEMA_VERSION: u32 = 2;

/// The shared metadata and migration-ledger objects present at schema v1.
pub const MYC_STATE_SCHEMA_VERSION_1_OBJECT_COUNT: u32 = 6;

/// The shared objects plus the three immutable Myc metadata objects at schema v2.
pub const MYC_STATE_SCHEMA_VERSION_2_OBJECT_COUNT: u32 = 9;

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
    0xbe, 0x15, 0x58, 0x4e, 0x4e, 0x6f, 0xe1, 0xf5, 0xb8, 0x02, 0x09, 0xe8, 0xf6, 0x12, 0x5e, 0xcc,
    0x92, 0x81, 0xfc, 0x22, 0xe9, 0x76, 0x9a, 0x79, 0xf2, 0x10, 0xc3, 0x0c, 0x43, 0x1f, 0xf4, 0x62,
];

/// SHA-256 identity of the schema catalog bound to the migration catalog.
pub const MYC_STATE_SCHEMA_CATALOG_SHA256: [u8; 32] = [
    0x67, 0x3f, 0x8b, 0xa2, 0x09, 0x5e, 0xe0, 0x2e, 0x80, 0x48, 0xaf, 0x85, 0x0d, 0x29, 0x44, 0x36,
    0xcb, 0x7b, 0x81, 0x50, 0xe9, 0x16, 0x93, 0xb7, 0x72, 0x7f, 0xae, 0x05, 0x81, 0x2e, 0x83, 0x1c,
];

/// SHA-256 identity of the schema-v2 migration content.
pub const MYC_STATE_SCHEMA_VERSION_2_MIGRATION_SHA256: [u8; 32] = [
    0xc5, 0xeb, 0x97, 0x8b, 0xda, 0x1b, 0xc7, 0x0c, 0x70, 0xbd, 0x9b, 0xd4, 0x4d, 0x8c, 0xba, 0x70,
    0xcb, 0x28, 0x57, 0xd2, 0x6a, 0x9d, 0xce, 0x74, 0x96, 0x1f, 0x4b, 0x78, 0x1e, 0x71, 0x00, 0x37,
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
    let migration = MigrationDescriptor::sql(
        MYC_STATE_SCHEMA_VERSION,
        "create_myc_state_metadata",
        CREATE_MYC_STATE_METADATA_MIGRATION_SQL,
        MigrationChecksum::from_bytes(MYC_STATE_SCHEMA_VERSION_2_MIGRATION_SHA256),
    )
    .map_err(|_| MycStateCatalogError::new(MycStateCatalogErrorKind::MigrationCatalog))?;
    let catalog = MigrationCatalog::new([migration])
        .map_err(|_| MycStateCatalogError::new(MycStateCatalogErrorKind::MigrationCatalog))?;
    if catalog.current_version() != MYC_STATE_SCHEMA_VERSION
        || catalog.descriptors().len() != 1
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
        MYC_STATE_SCHEMA_VERSION,
        myc_state_metadata_objects()?,
        SchemaDigest::from_bytes(MYC_STATE_SCHEMA_VERSION_2_SHA256),
    )
    .map_err(|_| MycStateCatalogError::new(MycStateCatalogErrorKind::SchemaCatalog))?;
    let catalog = SchemaCatalog::new(&migrations, [version_one, version_two])
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

/// Independently validates exact catalog versions, counts, and digests.
pub fn validate_myc_state_catalogs(
    migrations: &MigrationCatalog,
    schema: &SchemaCatalog,
) -> Result<(), MycStateCatalogError> {
    let versions = schema.versions();
    let descriptors = migrations.descriptors();
    let valid = migrations.current_version() == MYC_STATE_SCHEMA_VERSION
        && descriptors.len() == 1
        && descriptors[0].target_version() == MYC_STATE_SCHEMA_VERSION
        && descriptors[0].name().as_str() == "create_myc_state_metadata"
        && descriptors[0].checksum().as_bytes() == &MYC_STATE_SCHEMA_VERSION_2_MIGRATION_SHA256
        && migrations.digest().as_bytes() == &MYC_MIGRATION_CATALOG_SHA256
        && schema.migration_catalog_digest() == migrations.digest()
        && versions.len() == 2
        && versions[0].version() == MYC_STATE_BASE_SCHEMA_VERSION
        && versions[0].object_count() == MYC_STATE_SCHEMA_VERSION_1_OBJECT_COUNT
        && versions[0].digest().as_bytes() == &MYC_STATE_SCHEMA_VERSION_1_SHA256
        && versions[1].version() == MYC_STATE_SCHEMA_VERSION
        && versions[1].object_count() == MYC_STATE_SCHEMA_VERSION_2_OBJECT_COUNT
        && versions[1].digest().as_bytes() == &MYC_STATE_SCHEMA_VERSION_2_SHA256
        && schema.digest().as_bytes() == &MYC_STATE_SCHEMA_CATALOG_SHA256;
    if valid {
        Ok(())
    } else {
        Err(MycStateCatalogError::new(
            MycStateCatalogErrorKind::CatalogMismatch,
        ))
    }
}
