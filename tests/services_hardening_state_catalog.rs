#![forbid(unsafe_code)]

use std::error::Error;

use myc::{
    MYC_MIGRATION_CATALOG_SHA256, MYC_STATE_BASE_SCHEMA_VERSION, MYC_STATE_SCHEMA_CATALOG_SHA256,
    MYC_STATE_SCHEMA_VERSION, MYC_STATE_SCHEMA_VERSION_1_OBJECT_COUNT,
    MYC_STATE_SCHEMA_VERSION_1_SHA256, MYC_STATE_SCHEMA_VERSION_2_MIGRATION_SHA256,
    MYC_STATE_SCHEMA_VERSION_2_OBJECT_COUNT, MYC_STATE_SCHEMA_VERSION_2_SHA256,
    MycStateCatalogErrorKind, myc_migration_catalog, myc_schema_catalog,
    validate_myc_state_catalogs,
};
use radroots_service_sqlite::{
    MigrationCatalog, MigrationChecksum, MigrationDescriptor, SchemaCatalog, SchemaDigest,
    SchemaObject, SchemaObjectKind, SchemaVersionCatalog,
};

const CATALOG_SOURCE: &str = include_str!("../src/state_catalog.rs");
const LIB_SOURCE: &str = include_str!("../src/lib.rs");
const MANIFEST: &str = include_str!("../Cargo.toml");

#[test]
fn schema_v1_v2_and_single_migration_have_exact_literal_identities() {
    let migrations = myc_migration_catalog().expect("Myc migration catalog");
    let schema = myc_schema_catalog().expect("Myc schema catalog");

    assert_eq!(MYC_STATE_BASE_SCHEMA_VERSION, 1);
    assert_eq!(MYC_STATE_SCHEMA_VERSION, 2);
    assert_eq!(migrations.descriptors().len(), 1);
    let migration = &migrations.descriptors()[0];
    assert_eq!(migration.target_version(), 2);
    assert_eq!(migration.name().as_str(), "create_myc_state_metadata");
    assert_eq!(
        migration.checksum().as_bytes(),
        &MYC_STATE_SCHEMA_VERSION_2_MIGRATION_SHA256
    );
    assert_eq!(migrations.current_version(), 2);
    assert_eq!(
        migrations.digest().as_bytes(),
        &MYC_MIGRATION_CATALOG_SHA256
    );

    assert_eq!(schema.versions().len(), 2);
    assert_eq!(schema.versions()[0].version(), 1);
    assert_eq!(
        schema.versions()[0].object_count(),
        MYC_STATE_SCHEMA_VERSION_1_OBJECT_COUNT
    );
    assert_eq!(
        schema.versions()[0].digest().as_bytes(),
        &MYC_STATE_SCHEMA_VERSION_1_SHA256
    );
    assert_eq!(schema.versions()[1].version(), 2);
    assert_eq!(
        schema.versions()[1].object_count(),
        MYC_STATE_SCHEMA_VERSION_2_OBJECT_COUNT
    );
    assert_eq!(schema.versions()[1].object_count(), 9);
    assert_eq!(
        schema.versions()[1].digest().as_bytes(),
        &MYC_STATE_SCHEMA_VERSION_2_SHA256
    );
    assert_eq!(schema.digest().as_bytes(), &MYC_STATE_SCHEMA_CATALOG_SHA256);
    assert_eq!(schema.migration_catalog_digest(), migrations.digest());
    validate_myc_state_catalogs(&migrations, &schema).expect("exact catalogs");

    assert_eq!(
        hex::encode(MYC_STATE_SCHEMA_VERSION_2_MIGRATION_SHA256),
        "c5eb978bda1bc70c70bd9bd44d8cba70cb2857d26a9dce74961f4b781e710037"
    );
    assert_eq!(
        hex::encode(MYC_MIGRATION_CATALOG_SHA256),
        "be15584e4e6fe1f5b80209e8f6125ecc9281fc22e9769a79f210c30c431ff462"
    );
    assert_eq!(
        hex::encode(MYC_STATE_SCHEMA_VERSION_1_SHA256),
        "94dc66fbca601679615c055229dc0db6119f5bd92b04390c67f698a036fa78ae"
    );
    assert_eq!(
        hex::encode(MYC_STATE_SCHEMA_VERSION_2_SHA256),
        "94739b5a34ca8ed130b946d092731b59bf1548fe541d9a9269a33d0aed1ea09e"
    );
    assert_eq!(
        hex::encode(MYC_STATE_SCHEMA_CATALOG_SHA256),
        "673f8ba2095ee02e8048af850d294436cb7b8150e91693b7727fae05812e831c"
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

    let expected_migrations = myc_migration_catalog().expect("expected migrations");
    let v1 = SchemaVersionCatalog::new(
        1,
        [],
        SchemaDigest::from_bytes(MYC_STATE_SCHEMA_VERSION_1_SHA256),
    )
    .expect("schema v1");
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
        SchemaVersionCatalog::computed_digest(2, [object.clone()]).expect("snapshot digest");
    let v2 = SchemaVersionCatalog::new(2, [object], snapshot_digest).expect("schema v2");
    let schema = SchemaCatalog::new(&expected_migrations, [v1, v2]).expect("drift schema catalog");
    assert_eq!(
        validate_myc_state_catalogs(&expected_migrations, &schema)
            .expect_err("schema drift")
            .kind(),
        MycStateCatalogErrorKind::CatalogMismatch
    );
}

#[test]
fn catalog_errors_are_stable_source_free_and_redacted() {
    const SQL: &str = "CREATE TABLE secret_table (value INTEGER NOT NULL) STRICT";
    let migration =
        MigrationDescriptor::sql(2, "secret_schema", SQL, MigrationChecksum::for_sql(SQL))
            .expect("migration");
    let migrations = MigrationCatalog::new([migration]).expect("migration catalog");
    let expected_schema = myc_schema_catalog().expect("expected schema");
    let error = validate_myc_state_catalogs(&migrations, &expected_schema).expect_err("mismatch");

    assert_eq!(error.kind(), MycStateCatalogErrorKind::CatalogMismatch);
    assert_eq!(error.code(), "state_catalog_mismatch");
    assert!(Error::source(&error).is_none());
    let rendered = format!("{error} {error:?}");
    assert!(!rendered.contains("secret"));
    assert!(!rendered.contains(&hex::encode(MigrationChecksum::for_sql(SQL).as_bytes())));
}

#[test]
fn catalog_source_is_pure_pinned_and_uses_only_the_shared_authority() {
    assert!(MANIFEST.contains(
        "radroots_service_sqlite = { git = \"https://github.com/radrootslabs/lib\", rev = \"b44119fbac5985be8127ad1bf56d2950e6399427\", version = \"=0.1.0-alpha\" }"
    ));
    assert!(LIB_SOURCE.contains("mod state_catalog;"));
    assert!(!LIB_SOURCE.contains("pub mod state_catalog;"));
    assert!(CATALOG_SOURCE.contains("MigrationDescriptor::sql("));
    assert!(CATALOG_SOURCE.contains("MigrationChecksum::from_bytes("));
    assert!(CATALOG_SOURCE.contains("SchemaDigest::from_bytes("));
    assert!(!CATALOG_SOURCE.contains("computed_digest"));
    for forbidden in [
        "sqlx::",
        "rusqlite",
        "libsqlite3_sys",
        "raw_sql",
        "std::fs",
        "std::path",
        "SqliteConnection",
        "Transaction",
    ] {
        assert!(
            !CATALOG_SOURCE.contains(forbidden),
            "found forbidden catalog authority `{forbidden}`"
        );
    }
}
