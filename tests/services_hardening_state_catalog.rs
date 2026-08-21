#![forbid(unsafe_code)]

use std::error::Error;

use myc::{
    MYC_MIGRATION_CATALOG_SHA256, MYC_STATE_BASE_SCHEMA_VERSION, MYC_STATE_SCHEMA_CATALOG_SHA256,
    MYC_STATE_SCHEMA_VERSION, MYC_STATE_SCHEMA_VERSION_1_OBJECT_COUNT,
    MYC_STATE_SCHEMA_VERSION_1_SHA256, MYC_STATE_SCHEMA_VERSION_2_MIGRATION_SHA256,
    MYC_STATE_SCHEMA_VERSION_2_OBJECT_COUNT, MYC_STATE_SCHEMA_VERSION_2_SHA256,
    MYC_STATE_SCHEMA_VERSION_3_MIGRATION_SHA256, MYC_STATE_SCHEMA_VERSION_3_OBJECT_COUNT,
    MYC_STATE_SCHEMA_VERSION_3_SHA256, MYC_STATE_SCHEMA_VERSION_4_MIGRATION_SHA256,
    MYC_STATE_SCHEMA_VERSION_4_OBJECT_COUNT, MYC_STATE_SCHEMA_VERSION_4_SHA256,
    MYC_STATE_SCHEMA_VERSION_5_MIGRATION_SHA256, MYC_STATE_SCHEMA_VERSION_5_OBJECT_COUNT,
    MYC_STATE_SCHEMA_VERSION_5_SHA256, MYC_STATE_SCHEMA_VERSION_6_MIGRATION_SHA256,
    MYC_STATE_SCHEMA_VERSION_6_OBJECT_COUNT, MYC_STATE_SCHEMA_VERSION_6_SHA256,
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
fn schema_v1_through_v6_and_all_migrations_have_exact_literal_identities() {
    let migrations = myc_migration_catalog().expect("Myc migration catalog");
    let schema = myc_schema_catalog().expect("Myc schema catalog");

    assert_eq!(MYC_STATE_BASE_SCHEMA_VERSION, 1);
    assert_eq!(MYC_STATE_SCHEMA_VERSION, 6);
    assert_eq!(migrations.descriptors().len(), 5);
    let metadata = &migrations.descriptors()[0];
    assert_eq!(metadata.target_version(), 2);
    assert_eq!(metadata.name().as_str(), "create_myc_state_metadata");
    assert_eq!(
        metadata.checksum().as_bytes(),
        &MYC_STATE_SCHEMA_VERSION_2_MIGRATION_SHA256
    );
    let request = &migrations.descriptors()[1];
    assert_eq!(request.target_version(), 3);
    assert_eq!(request.name().as_str(), "create_nip46_request_admission");
    assert_eq!(
        request.checksum().as_bytes(),
        &MYC_STATE_SCHEMA_VERSION_3_MIGRATION_SHA256
    );
    let connection = &migrations.descriptors()[2];
    assert_eq!(connection.target_version(), 4);
    assert_eq!(
        connection.name().as_str(),
        "create_connection_authorization_state"
    );
    assert_eq!(
        connection.checksum().as_bytes(),
        &MYC_STATE_SCHEMA_VERSION_4_MIGRATION_SHA256
    );
    let governance = &migrations.descriptors()[3];
    assert_eq!(governance.target_version(), 5);
    assert_eq!(
        governance.name().as_str(),
        "create_bounded_governance_state"
    );
    assert_eq!(
        governance.checksum().as_bytes(),
        &MYC_STATE_SCHEMA_VERSION_5_MIGRATION_SHA256
    );
    let delivery = &migrations.descriptors()[4];
    assert_eq!(delivery.target_version(), 6);
    assert_eq!(delivery.name().as_str(), "create_delivery_evidence_state");
    assert_eq!(
        delivery.checksum().as_bytes(),
        &MYC_STATE_SCHEMA_VERSION_6_MIGRATION_SHA256
    );
    assert_eq!(migrations.current_version(), 6);
    assert_eq!(
        migrations.digest().as_bytes(),
        &MYC_MIGRATION_CATALOG_SHA256
    );

    assert_eq!(schema.versions().len(), 6);
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
    assert_eq!(schema.versions()[2].version(), 3);
    assert_eq!(
        schema.versions()[2].object_count(),
        MYC_STATE_SCHEMA_VERSION_3_OBJECT_COUNT
    );
    assert_eq!(schema.versions()[2].object_count(), 13);
    assert_eq!(
        schema.versions()[2].digest().as_bytes(),
        &MYC_STATE_SCHEMA_VERSION_3_SHA256
    );
    assert_eq!(schema.versions()[3].version(), 4);
    assert_eq!(
        schema.versions()[3].object_count(),
        MYC_STATE_SCHEMA_VERSION_4_OBJECT_COUNT
    );
    assert_eq!(schema.versions()[3].object_count(), 25);
    assert_eq!(
        schema.versions()[3].digest().as_bytes(),
        &MYC_STATE_SCHEMA_VERSION_4_SHA256
    );
    assert_eq!(schema.versions()[4].version(), 5);
    assert_eq!(
        schema.versions()[4].object_count(),
        MYC_STATE_SCHEMA_VERSION_5_OBJECT_COUNT
    );
    assert_eq!(schema.versions()[4].object_count(), 34);
    assert_eq!(
        schema.versions()[4].digest().as_bytes(),
        &MYC_STATE_SCHEMA_VERSION_5_SHA256
    );
    assert_eq!(schema.versions()[5].version(), 6);
    assert_eq!(
        schema.versions()[5].object_count(),
        MYC_STATE_SCHEMA_VERSION_6_OBJECT_COUNT
    );
    assert_eq!(schema.versions()[5].object_count(), 43);
    assert_eq!(
        schema.versions()[5].digest().as_bytes(),
        &MYC_STATE_SCHEMA_VERSION_6_SHA256
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
        "a69bbc7f3c22750ddda55f36db125622c49f26b44cdc47210fadb7b5fc4f31e5"
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
        "94f7adfbd62be03e6f3af9c9754bf2f47cc704a87b2708f6826c4432556b6f06"
    );
    assert_eq!(
        hex::encode(MYC_STATE_SCHEMA_VERSION_3_MIGRATION_SHA256),
        "753165136b3dace0091d782f33f6b10ca1a2823314158d80a4775e0af628edf9"
    );
    assert_eq!(
        hex::encode(MYC_STATE_SCHEMA_VERSION_3_SHA256),
        "572fe6a4d36c0476ec40536f48028e1558488fb8abeba0a34ba69b4b7080ba08"
    );
    assert_eq!(
        hex::encode(MYC_STATE_SCHEMA_VERSION_4_MIGRATION_SHA256),
        "939c0ed07cd15cc0c794bf6c2af7192261409305c2876f3be363e8e4fe4a1abb"
    );
    assert_eq!(
        hex::encode(MYC_STATE_SCHEMA_VERSION_4_SHA256),
        "479863d37d91e6c269fa3573db6c2e767cdd3b24a93ab482d774bcec0218c174"
    );
    assert_eq!(
        hex::encode(MYC_STATE_SCHEMA_VERSION_5_MIGRATION_SHA256),
        "0e004fcb5d0bc7c951b16f4334533d10efcb18a826f624de0922d86dc8504b33"
    );
    assert_eq!(
        hex::encode(MYC_STATE_SCHEMA_VERSION_5_SHA256),
        "fe89d4af7de4eded78a3f062dc9d300f06cf0f4cfca5fa5cffc93af1146f21c5"
    );
    assert_eq!(
        hex::encode(MYC_STATE_SCHEMA_VERSION_6_MIGRATION_SHA256),
        "4649b9afd03fc07f89fe184f027925675a0265951ea7cf75e06a4312c55a82bd"
    );
    assert_eq!(
        hex::encode(MYC_STATE_SCHEMA_VERSION_6_SHA256),
        "557273306e68e9306dc1d7c7009e1cb7c9d15b8d52e07db7d0bd51e83f054492"
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
    let v2 = SchemaVersionCatalog::new(2, [object.clone()], snapshot_digest).expect("schema v2");
    let v3_digest =
        SchemaVersionCatalog::computed_digest(3, [object.clone()]).expect("schema-v3 digest");
    let v3 = SchemaVersionCatalog::new(3, [object.clone()], v3_digest).expect("schema v3");
    let v4_digest =
        SchemaVersionCatalog::computed_digest(4, [object.clone()]).expect("schema-v4 digest");
    let v4 = SchemaVersionCatalog::new(4, [object.clone()], v4_digest).expect("schema v4");
    let v5_digest =
        SchemaVersionCatalog::computed_digest(5, [object.clone()]).expect("schema-v5 digest");
    let v5 = SchemaVersionCatalog::new(5, [object.clone()], v5_digest).expect("schema v5");
    let v6_digest =
        SchemaVersionCatalog::computed_digest(6, [object.clone()]).expect("schema-v6 digest");
    let v6 = SchemaVersionCatalog::new(6, [object], v6_digest).expect("schema v6");
    let schema = SchemaCatalog::new(&expected_migrations, [v1, v2, v3, v4, v5, v6])
        .expect("drift schema catalog");
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
