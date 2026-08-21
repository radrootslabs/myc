#![forbid(unsafe_code)]

use std::error::Error;

use myc::{
    MYC_MIGRATION_CATALOG_SHA256, MYC_STATE_SCHEMA_CATALOG_SHA256, MYC_STATE_SCHEMA_VERSION,
    MYC_STATE_SCHEMA_VERSION_1_OBJECT_COUNT, MYC_STATE_SCHEMA_VERSION_1_SHA256,
    MycStateCatalogErrorKind, myc_migration_catalog, myc_schema_catalog,
    validate_myc_state_catalogs,
};
use radroots_service_sqlite::{
    MigrationCatalog, MigrationChecksum, MigrationDescriptor, SchemaCatalog, SchemaObject,
    SchemaObjectKind, SchemaVersionCatalog,
};

const CATALOG_SOURCE: &str = include_str!("../src/state_catalog.rs");
const LIB_SOURCE: &str = include_str!("../src/lib.rs");
const MANIFEST: &str = include_str!("../Cargo.toml");

#[test]
fn schema_v1_and_empty_migration_catalog_have_exact_literal_identities() {
    let migrations = myc_migration_catalog().expect("Myc migration catalog");
    let schema = myc_schema_catalog().expect("Myc schema catalog");

    assert_eq!(MYC_STATE_SCHEMA_VERSION, 1);
    assert!(migrations.descriptors().is_empty());
    assert_eq!(migrations.current_version(), 1);
    assert_eq!(
        migrations.digest().as_bytes(),
        &MYC_MIGRATION_CATALOG_SHA256
    );

    assert_eq!(schema.versions().len(), 1);
    let version = schema.versions()[0];
    assert_eq!(version.version(), 1);
    assert_eq!(
        version.object_count(),
        MYC_STATE_SCHEMA_VERSION_1_OBJECT_COUNT
    );
    assert_eq!(version.object_count(), 6);
    assert_eq!(
        version.digest().as_bytes(),
        &MYC_STATE_SCHEMA_VERSION_1_SHA256
    );
    assert_eq!(schema.digest().as_bytes(), &MYC_STATE_SCHEMA_CATALOG_SHA256);
    assert_eq!(schema.migration_catalog_digest(), migrations.digest());
    validate_myc_state_catalogs(&migrations, &schema).expect("exact catalogs");

    assert_eq!(
        hex::encode(MYC_MIGRATION_CATALOG_SHA256),
        "ec89dc8f7b6c2a11b967e33808e4031e29b3970ffee4959bff9bad352877ee9b"
    );
    assert_eq!(
        hex::encode(MYC_STATE_SCHEMA_VERSION_1_SHA256),
        "94dc66fbca601679615c055229dc0db6119f5bd92b04390c67f698a036fa78ae"
    );
    assert_eq!(
        hex::encode(MYC_STATE_SCHEMA_CATALOG_SHA256),
        "2309153f3b49754887c548a7459b3e09099c60f7146b373c8f96706c6768d791"
    );
}

#[test]
fn independent_validator_rejects_migration_or_schema_drift() {
    const SQL: &str = "CREATE TABLE unexpected (value INTEGER NOT NULL) STRICT";
    let migration =
        MigrationDescriptor::sql(2, "unexpected_schema", SQL, MigrationChecksum::for_sql(SQL))
            .expect("valid drift fixture");
    let migrations = MigrationCatalog::new([migration]).expect("drift migration catalog");
    let expected_schema = myc_schema_catalog().expect("expected schema");
    assert_eq!(
        validate_myc_state_catalogs(&migrations, &expected_schema)
            .expect_err("migration drift")
            .kind(),
        MycStateCatalogErrorKind::CatalogMismatch
    );

    let empty_migrations = myc_migration_catalog().expect("empty migrations");
    let object_digest =
        SchemaObject::computed_digest(SchemaObjectKind::Table, "unexpected", "unexpected", SQL)
            .expect("object digest");
    let object = SchemaObject::new(
        SchemaObjectKind::Table,
        "unexpected",
        "unexpected",
        SQL,
        object_digest,
    )
    .expect("schema object");
    let snapshot_digest =
        SchemaVersionCatalog::computed_digest(1, [object.clone()]).expect("snapshot digest");
    let version = SchemaVersionCatalog::new(1, [object], snapshot_digest).expect("version");
    let schema = SchemaCatalog::new(&empty_migrations, [version]).expect("drift schema catalog");
    assert_eq!(
        validate_myc_state_catalogs(&empty_migrations, &schema)
            .expect_err("schema drift")
            .kind(),
        MycStateCatalogErrorKind::CatalogMismatch
    );
}

#[test]
fn catalog_errors_are_stable_source_free_and_redacted() {
    let migrations = myc_migration_catalog().expect("migration catalog");
    let object_digest = SchemaObject::computed_digest(
        SchemaObjectKind::Table,
        "secret_table",
        "secret_table",
        "secret SQL text",
    )
    .expect("object digest");
    let object = SchemaObject::new(
        SchemaObjectKind::Table,
        "secret_table",
        "secret_table",
        "secret SQL text",
        object_digest,
    )
    .expect("object");
    let snapshot =
        SchemaVersionCatalog::computed_digest(1, [object.clone()]).expect("snapshot digest");
    let version = SchemaVersionCatalog::new(1, [object], snapshot).expect("version");
    let schema = SchemaCatalog::new(&migrations, [version]).expect("schema catalog");
    let error = validate_myc_state_catalogs(&migrations, &schema).expect_err("mismatch");

    assert_eq!(error.kind(), MycStateCatalogErrorKind::CatalogMismatch);
    assert_eq!(error.code(), "state_catalog_mismatch");
    assert!(Error::source(&error).is_none());
    let rendered = format!("{error} {error:?}");
    assert!(!rendered.contains("secret"));
    assert!(!rendered.contains(&hex::encode(snapshot.as_bytes())));
}

#[test]
fn catalog_source_is_pure_pinned_and_uses_only_the_shared_authority() {
    assert!(MANIFEST.contains(
        "radroots_service_sqlite = { git = \"https://github.com/radrootslabs/lib\", rev = \"b44119fbac5985be8127ad1bf56d2950e6399427\", version = \"=0.1.0-alpha\" }"
    ));
    assert!(LIB_SOURCE.contains("mod state_catalog;"));
    assert!(!LIB_SOURCE.contains("pub mod state_catalog;"));
    assert!(CATALOG_SOURCE.contains("MigrationCatalog::new([])"));
    assert!(CATALOG_SOURCE.contains("SchemaDigest::from_bytes("));
    assert!(!CATALOG_SOURCE.contains("computed_digest"));
    for forbidden in [
        "sqlx::",
        "rusqlite",
        "libsqlite3_sys",
        "CREATE TABLE",
        "raw_sql",
        "std::fs",
        "std::path",
        "Connection",
        "Transaction",
        "MigrationDescriptor",
    ] {
        assert!(
            !CATALOG_SOURCE.contains(forbidden),
            "found forbidden catalog authority `{forbidden}`"
        );
    }
}
