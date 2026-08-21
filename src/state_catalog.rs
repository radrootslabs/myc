//! Immutable Myc schema and migration catalog identity.

use core::fmt;
use std::error::Error;

use radroots_service_sqlite::{
    MigrationCatalog, SchemaCatalog, SchemaDigest, SchemaVersionCatalog,
};

/// The clean-slate Myc baseline schema version.
pub const MYC_STATE_SCHEMA_VERSION: u32 = 1;

/// The shared metadata and migration-ledger objects present at schema v1.
pub const MYC_STATE_SCHEMA_VERSION_1_OBJECT_COUNT: u32 = 6;

/// SHA-256 identity of the empty schema-v1 migration catalog.
pub const MYC_MIGRATION_CATALOG_SHA256: [u8; 32] = [
    0xec, 0x89, 0xdc, 0x8f, 0x7b, 0x6c, 0x2a, 0x11, 0xb9, 0x67, 0xe3, 0x38, 0x08, 0xe4, 0x03, 0x1e,
    0x29, 0xb3, 0x97, 0x0f, 0xfe, 0xe4, 0x95, 0x9b, 0xff, 0x9b, 0xad, 0x35, 0x28, 0x77, 0xee, 0x9b,
];

/// SHA-256 identity of the exact schema-v1 object snapshot.
pub const MYC_STATE_SCHEMA_VERSION_1_SHA256: [u8; 32] = [
    0x94, 0xdc, 0x66, 0xfb, 0xca, 0x60, 0x16, 0x79, 0x61, 0x5c, 0x05, 0x52, 0x29, 0xdc, 0x0d, 0xb6,
    0x11, 0x9f, 0x5b, 0xd9, 0x2b, 0x04, 0x39, 0x0c, 0x67, 0xf6, 0x98, 0xa0, 0x36, 0xfa, 0x78, 0xae,
];

/// SHA-256 identity of the schema catalog bound to the migration catalog.
pub const MYC_STATE_SCHEMA_CATALOG_SHA256: [u8; 32] = [
    0x23, 0x09, 0x15, 0x3f, 0x3b, 0x49, 0x75, 0x48, 0x87, 0xc5, 0x48, 0xa7, 0x45, 0x9b, 0x3e, 0x09,
    0x09, 0x9c, 0x60, 0xf7, 0x14, 0x6b, 0x37, 0x3c, 0x8f, 0x96, 0x70, 0x6c, 0x67, 0x68, 0xd7, 0x91,
];

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

    /// Returns the stable machine-readable code.
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

/// Constructs the exact schema-v1 migration catalog.
pub fn myc_migration_catalog() -> Result<MigrationCatalog, MycStateCatalogError> {
    let catalog = MigrationCatalog::new([])
        .map_err(|_| MycStateCatalogError::new(MycStateCatalogErrorKind::MigrationCatalog))?;
    if catalog.current_version() != MYC_STATE_SCHEMA_VERSION
        || !catalog.descriptors().is_empty()
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
    let version = SchemaVersionCatalog::new(
        MYC_STATE_SCHEMA_VERSION,
        [],
        SchemaDigest::from_bytes(MYC_STATE_SCHEMA_VERSION_1_SHA256),
    )
    .map_err(|_| MycStateCatalogError::new(MycStateCatalogErrorKind::SchemaCatalog))?;
    let catalog = SchemaCatalog::new(&migrations, [version])
        .map_err(|_| MycStateCatalogError::new(MycStateCatalogErrorKind::SchemaCatalog))?;
    validate_myc_state_catalogs(&migrations, &catalog)?;
    Ok(catalog)
}

/// Independently validates exact catalog versions, counts, and digests.
pub fn validate_myc_state_catalogs(
    migrations: &MigrationCatalog,
    schema: &SchemaCatalog,
) -> Result<(), MycStateCatalogError> {
    let versions = schema.versions();
    let valid = migrations.current_version() == MYC_STATE_SCHEMA_VERSION
        && migrations.descriptors().is_empty()
        && migrations.digest().as_bytes() == &MYC_MIGRATION_CATALOG_SHA256
        && schema.migration_catalog_digest() == migrations.digest()
        && versions.len() == 1
        && versions[0].version() == MYC_STATE_SCHEMA_VERSION
        && versions[0].object_count() == MYC_STATE_SCHEMA_VERSION_1_OBJECT_COUNT
        && versions[0].digest().as_bytes() == &MYC_STATE_SCHEMA_VERSION_1_SHA256
        && schema.digest().as_bytes() == &MYC_STATE_SCHEMA_CATALOG_SHA256;
    if valid {
        Ok(())
    } else {
        Err(MycStateCatalogError::new(
            MycStateCatalogErrorKind::CatalogMismatch,
        ))
    }
}
