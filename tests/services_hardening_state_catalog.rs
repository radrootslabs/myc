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
    MYC_STATE_SCHEMA_VERSION_7_MIGRATION_SHA256, MYC_STATE_SCHEMA_VERSION_7_OBJECT_COUNT,
    MYC_STATE_SCHEMA_VERSION_7_SHA256, MYC_STATE_SCHEMA_VERSION_8_MIGRATION_SHA256,
    MYC_STATE_SCHEMA_VERSION_8_OBJECT_COUNT, MYC_STATE_SCHEMA_VERSION_8_SHA256,
    MYC_STATE_SCHEMA_VERSION_9_MIGRATION_SHA256, MYC_STATE_SCHEMA_VERSION_9_OBJECT_COUNT,
    MYC_STATE_SCHEMA_VERSION_9_SHA256, MYC_STATE_SCHEMA_VERSION_10_MIGRATION_SHA256,
    MYC_STATE_SCHEMA_VERSION_10_OBJECT_COUNT, MYC_STATE_SCHEMA_VERSION_10_SHA256,
    MYC_STATE_SCHEMA_VERSION_11_MIGRATION_SHA256, MYC_STATE_SCHEMA_VERSION_11_OBJECT_COUNT,
    MYC_STATE_SCHEMA_VERSION_11_SHA256, MYC_STATE_SCHEMA_VERSION_12_MIGRATION_SHA256,
    MYC_STATE_SCHEMA_VERSION_12_OBJECT_COUNT, MYC_STATE_SCHEMA_VERSION_12_SHA256,
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
fn schema_v1_through_v12_and_all_migrations_have_exact_literal_identities() {
    let migrations = myc_migration_catalog().expect("Myc migration catalog");
    let schema = myc_schema_catalog().expect("Myc schema catalog");

    assert_eq!(MYC_STATE_BASE_SCHEMA_VERSION, 1);
    assert_eq!(MYC_STATE_SCHEMA_VERSION, 12);
    assert_eq!(migrations.descriptors().len(), 11);
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
    let discovery = &migrations.descriptors()[5];
    assert_eq!(discovery.target_version(), 7);
    assert_eq!(discovery.name().as_str(), "create_discovery_desired_state");
    assert_eq!(
        discovery.checksum().as_bytes(),
        &MYC_STATE_SCHEMA_VERSION_7_MIGRATION_SHA256
    );
    let completion = &migrations.descriptors()[6];
    assert_eq!(completion.target_version(), 8);
    assert_eq!(
        completion.name().as_str(),
        "create_nip46_operation_completion"
    );
    assert_eq!(
        completion.checksum().as_bytes(),
        &MYC_STATE_SCHEMA_VERSION_8_MIGRATION_SHA256
    );
    let response = &migrations.descriptors()[7];
    assert_eq!(response.target_version(), 9);
    assert_eq!(response.name().as_str(), "create_nip46_atomic_response");
    assert_eq!(
        response.checksum().as_bytes(),
        &MYC_STATE_SCHEMA_VERSION_9_MIGRATION_SHA256
    );
    let configuration = &migrations.descriptors()[8];
    assert_eq!(configuration.target_version(), 10);
    assert_eq!(
        configuration.name().as_str(),
        "create_configuration_binding_history"
    );
    assert_eq!(
        configuration.checksum().as_bytes(),
        &MYC_STATE_SCHEMA_VERSION_10_MIGRATION_SHA256
    );
    let admin_operations = &migrations.descriptors()[9];
    assert_eq!(admin_operations.target_version(), 11);
    assert_eq!(
        admin_operations.name().as_str(),
        "create_admin_operation_journal"
    );
    assert_eq!(
        admin_operations.checksum().as_bytes(),
        &MYC_STATE_SCHEMA_VERSION_11_MIGRATION_SHA256
    );
    let pending_responses = &migrations.descriptors()[10];
    assert_eq!(pending_responses.target_version(), 12);
    assert_eq!(
        pending_responses.name().as_str(),
        "create_nip46_pending_response_authority"
    );
    assert_eq!(
        pending_responses.checksum().as_bytes(),
        &MYC_STATE_SCHEMA_VERSION_12_MIGRATION_SHA256
    );
    assert_eq!(migrations.current_version(), 12);
    assert_eq!(
        migrations.digest().as_bytes(),
        &MYC_MIGRATION_CATALOG_SHA256
    );

    assert_eq!(schema.versions().len(), 12);
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
    assert_eq!(schema.versions()[6].version(), 7);
    assert_eq!(
        schema.versions()[6].object_count(),
        MYC_STATE_SCHEMA_VERSION_7_OBJECT_COUNT
    );
    assert_eq!(schema.versions()[6].object_count(), 53);
    assert_eq!(
        schema.versions()[6].digest().as_bytes(),
        &MYC_STATE_SCHEMA_VERSION_7_SHA256
    );
    assert_eq!(schema.versions()[7].version(), 8);
    assert_eq!(
        schema.versions()[7].object_count(),
        MYC_STATE_SCHEMA_VERSION_8_OBJECT_COUNT
    );
    assert_eq!(schema.versions()[7].object_count(), 56);
    assert_eq!(
        schema.versions()[7].digest().as_bytes(),
        &MYC_STATE_SCHEMA_VERSION_8_SHA256
    );
    assert_eq!(schema.versions()[8].version(), 9);
    assert_eq!(
        schema.versions()[8].object_count(),
        MYC_STATE_SCHEMA_VERSION_9_OBJECT_COUNT
    );
    assert_eq!(schema.versions()[8].object_count(), 59);
    assert_eq!(
        schema.versions()[8].digest().as_bytes(),
        &MYC_STATE_SCHEMA_VERSION_9_SHA256
    );
    assert_eq!(schema.versions()[9].version(), 10);
    assert_eq!(
        schema.versions()[9].object_count(),
        MYC_STATE_SCHEMA_VERSION_10_OBJECT_COUNT
    );
    assert_eq!(schema.versions()[9].object_count(), 63);
    assert_eq!(
        schema.versions()[9].digest().as_bytes(),
        &MYC_STATE_SCHEMA_VERSION_10_SHA256
    );
    assert_eq!(schema.versions()[10].version(), 11);
    assert_eq!(
        schema.versions()[10].object_count(),
        MYC_STATE_SCHEMA_VERSION_11_OBJECT_COUNT
    );
    assert_eq!(schema.versions()[10].object_count(), 65);
    assert_eq!(
        schema.versions()[10].digest().as_bytes(),
        &MYC_STATE_SCHEMA_VERSION_11_SHA256
    );
    assert_eq!(schema.versions()[11].version(), 12);
    assert_eq!(
        schema.versions()[11].object_count(),
        MYC_STATE_SCHEMA_VERSION_12_OBJECT_COUNT
    );
    assert_eq!(schema.versions()[11].object_count(), 70);
    assert_eq!(
        schema.versions()[11].digest().as_bytes(),
        &MYC_STATE_SCHEMA_VERSION_12_SHA256
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
        "b1d6458245e6dfc4661aa6146b8ce8ab55f7c29bf36099d261c07f5f5167561d"
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
        "b52721d85c1eb8cddc28256c21179a10d5f32bcb33e9d2a6bb8fe49ecbc49a68"
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
    assert_eq!(
        hex::encode(MYC_STATE_SCHEMA_VERSION_7_MIGRATION_SHA256),
        "6097c40776a57dd4bddc04e652987217d6f5991f2d5e94d322d1208619254e6c"
    );
    assert_eq!(
        hex::encode(MYC_STATE_SCHEMA_VERSION_7_SHA256),
        "3b3528911a293499d9721da71b6ad07a5e723e97b6ebf5b40a19b9058958bf79"
    );
    assert_eq!(
        hex::encode(MYC_STATE_SCHEMA_VERSION_8_MIGRATION_SHA256),
        "b81f980c91acd98b91ecd5cb248e4027c9f47c1dc8d0134a61af5c38238315bc"
    );
    assert_eq!(
        hex::encode(MYC_STATE_SCHEMA_VERSION_8_SHA256),
        "50158cb093ed70b3d5783762b18d21b7809665c89fde925d872365909d28f06e"
    );
    assert_eq!(
        hex::encode(MYC_STATE_SCHEMA_VERSION_9_MIGRATION_SHA256),
        "fdb039d472cd62e7da46c40a9786c3a9a7ec55f2ae7db689d0f855fbbf8a9566"
    );
    assert_eq!(
        hex::encode(MYC_STATE_SCHEMA_VERSION_9_SHA256),
        "eee76f4ff0bd2dc2c061ae384e00de16c5f5efc4b6edd0ac7f73cad83a991ff7"
    );
    assert_eq!(
        hex::encode(MYC_STATE_SCHEMA_VERSION_10_MIGRATION_SHA256),
        "28423ebb59f4b26223307b74a7e12905ca4818c01a655203ee8d63c911f44489"
    );
    assert_eq!(
        hex::encode(MYC_STATE_SCHEMA_VERSION_10_SHA256),
        "b77ed23afa39ff45dda250faa1ebfc0587c34462658fc49fb7b2fbc8909ba303"
    );
    assert_eq!(
        hex::encode(MYC_STATE_SCHEMA_VERSION_11_MIGRATION_SHA256),
        "16385368aa4ee40ea7002a0ab42645bc68b546a4ba6afdfede565fe026576c96"
    );
    assert_eq!(
        hex::encode(MYC_STATE_SCHEMA_VERSION_11_SHA256),
        "0de7fe176ea7da6030424addc29b9a91363e88b04dc78ddab480fd0f0af94e5a"
    );
    assert_eq!(
        hex::encode(MYC_STATE_SCHEMA_VERSION_12_MIGRATION_SHA256),
        "388ee51de599f37b7bb1956cebd518461f3eb193535ffe6bb9eac2d82bbe3e37"
    );
    assert_eq!(
        hex::encode(MYC_STATE_SCHEMA_VERSION_12_SHA256),
        "d893a23ba68e463489ad7ef1e6a80ea4e88089381c73decc3243a4ce6f64da8f"
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
    let v6 = SchemaVersionCatalog::new(6, [object.clone()], v6_digest).expect("schema v6");
    let v7_digest =
        SchemaVersionCatalog::computed_digest(7, [object.clone()]).expect("schema-v7 digest");
    let v7 = SchemaVersionCatalog::new(7, [object.clone()], v7_digest).expect("schema v7");
    let v8_digest =
        SchemaVersionCatalog::computed_digest(8, [object.clone()]).expect("schema-v8 digest");
    let v8 = SchemaVersionCatalog::new(8, [object.clone()], v8_digest).expect("schema v8");
    let v9_digest =
        SchemaVersionCatalog::computed_digest(9, [object.clone()]).expect("schema-v9 digest");
    let v9 = SchemaVersionCatalog::new(9, [object.clone()], v9_digest).expect("schema v9");
    let v10_digest =
        SchemaVersionCatalog::computed_digest(10, [object.clone()]).expect("schema-v10 digest");
    let v10 = SchemaVersionCatalog::new(10, [object.clone()], v10_digest).expect("schema v10");
    let v11_digest =
        SchemaVersionCatalog::computed_digest(11, [object.clone()]).expect("schema-v11 digest");
    let v11 = SchemaVersionCatalog::new(11, [object.clone()], v11_digest).expect("schema v11");
    let v12_digest =
        SchemaVersionCatalog::computed_digest(12, [object.clone()]).expect("schema-v12 digest");
    let v12 = SchemaVersionCatalog::new(12, [object], v12_digest).expect("schema v12");
    let schema = SchemaCatalog::new(
        &expected_migrations,
        [v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12],
    )
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
        "radroots_service_sqlite = { git = \"https://github.com/radrootslabs/lib\", rev = \"055096853fca95e15d0f813d33a14aca13be3881\", version = \"=0.1.0-alpha\" }"
    ));
    assert!(LIB_SOURCE.contains("mod state_catalog;"));
    assert!(!LIB_SOURCE.contains("pub mod state_catalog;"));
    assert!(CATALOG_SOURCE.contains("MigrationDescriptor::sql("));
    assert!(CATALOG_SOURCE.contains("MigrationChecksum::from_bytes("));
    assert!(CATALOG_SOURCE.contains("SchemaDigest::from_bytes("));
    assert!(CATALOG_SOURCE.contains("FROM publication_outbox;"));
    assert!(
        CATALOG_SOURCE.contains("INSERT INTO delivery_targets SELECT * FROM publication_targets;")
    );
    assert!(
        CATALOG_SOURCE
            .contains("INSERT INTO delivery_attempts SELECT * FROM publication_attempts;")
    );
    assert!(CATALOG_SOURCE.contains("delivery_jobs_guard_insert"));
    assert!(!CATALOG_SOURCE.contains("computed_digest"));
    assert!(!CATALOG_SOURCE.contains("ALTER TABLE"));
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
