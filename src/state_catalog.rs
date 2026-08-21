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
pub const MYC_STATE_SCHEMA_VERSION: u32 = 5;

/// The shared metadata and migration-ledger objects present at schema v1.
pub const MYC_STATE_SCHEMA_VERSION_1_OBJECT_COUNT: u32 = 6;

/// The shared objects plus the three immutable Myc metadata objects at schema v2.
pub const MYC_STATE_SCHEMA_VERSION_2_OBJECT_COUNT: u32 = 9;

/// The shared objects plus Myc metadata and request-admission objects at schema v3.
pub const MYC_STATE_SCHEMA_VERSION_3_OBJECT_COUNT: u32 = 13;

/// The shared objects plus Myc metadata, request, and connection objects at schema v4.
pub const MYC_STATE_SCHEMA_VERSION_4_OBJECT_COUNT: u32 = 25;

/// The shared objects plus all Myc metadata, request, connection, and governance objects at v5.
pub const MYC_STATE_SCHEMA_VERSION_5_OBJECT_COUNT: u32 = 34;

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
    0x1d, 0x06, 0x99, 0x96, 0x43, 0x55, 0x60, 0x21, 0x7d, 0xbd, 0x36, 0x92, 0xd5, 0x43, 0x06, 0x12,
    0xad, 0x3a, 0x56, 0x67, 0xee, 0x0b, 0x12, 0xb1, 0x91, 0x9f, 0x0b, 0x5e, 0xdf, 0x2c, 0xbe, 0x7d,
];

/// SHA-256 identity of the schema catalog bound to the migration catalog.
pub const MYC_STATE_SCHEMA_CATALOG_SHA256: [u8; 32] = [
    0x21, 0x19, 0xef, 0xef, 0xcf, 0xd4, 0xac, 0x54, 0x77, 0x60, 0x96, 0x55, 0x34, 0x1a, 0xa4, 0xc5,
    0xb9, 0xb9, 0xa1, 0xbe, 0xfb, 0x88, 0xcc, 0x16, 0x8a, 0x2b, 0x93, 0x73, 0xe9, 0x9e, 0xbb, 0xd5,
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

/// SHA-256 identity of the schema-v4 migration content.
pub const MYC_STATE_SCHEMA_VERSION_4_MIGRATION_SHA256: [u8; 32] = [
    0x93, 0x9c, 0x0e, 0xd0, 0x7c, 0xd1, 0x5c, 0xc0, 0xc7, 0x94, 0xbf, 0x6c, 0x2a, 0xf7, 0x19, 0x22,
    0x61, 0x40, 0x93, 0x05, 0xc2, 0x87, 0x6f, 0x3b, 0xe3, 0x63, 0xe8, 0xe4, 0xfe, 0x4a, 0x1a, 0xbb,
];

/// SHA-256 identity of the schema-v4 object snapshot.
pub const MYC_STATE_SCHEMA_VERSION_4_SHA256: [u8; 32] = [
    0x47, 0x98, 0x63, 0xd3, 0x7d, 0x91, 0xe6, 0xc2, 0x69, 0xfa, 0x35, 0x73, 0xdb, 0x6c, 0x2e, 0x76,
    0x7c, 0xdd, 0x3b, 0x24, 0xa9, 0x3a, 0xb4, 0x82, 0xd7, 0x74, 0xbc, 0xec, 0x02, 0x18, 0xc1, 0x74,
];

/// SHA-256 identity of the schema-v5 migration content.
pub const MYC_STATE_SCHEMA_VERSION_5_MIGRATION_SHA256: [u8; 32] = [
    0x0e, 0x00, 0x4f, 0xcb, 0x5d, 0x0b, 0xc7, 0xc9, 0x51, 0xb1, 0x6f, 0x43, 0x34, 0x53, 0x3d, 0x10,
    0xef, 0xcb, 0x18, 0xa8, 0x26, 0xf6, 0x24, 0xde, 0x09, 0x22, 0xd8, 0x6d, 0xc8, 0x50, 0x4b, 0x33,
];

/// SHA-256 identity of the schema-v5 object snapshot.
pub const MYC_STATE_SCHEMA_VERSION_5_SHA256: [u8; 32] = [
    0xfe, 0x89, 0xd4, 0xaf, 0x7d, 0xe4, 0xed, 0xed, 0x78, 0xa3, 0xf0, 0x62, 0xdc, 0x9d, 0x30, 0x0f,
    0x06, 0xcf, 0x0f, 0x4c, 0xfc, 0xa5, 0xfa, 0x5c, 0xff, 0xc9, 0x3a, 0xf1, 0x14, 0x6f, 0x21, 0xc5,
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

macro_rules! connections_table_sql {
    () => {
        r#"CREATE TABLE connections (
    connection_id BLOB NOT NULL PRIMARY KEY CHECK (length(connection_id) = 32),
    connection_nonce BLOB NOT NULL CHECK (length(connection_nonce) = 32),
    client_public_key TEXT NOT NULL
        CHECK (length(CAST(client_public_key AS BLOB)) = 64)
        CHECK (client_public_key NOT GLOB '*[^0-9a-f]*'),
    requested_permissions_sha256 BLOB NOT NULL
        CHECK (length(requested_permissions_sha256) = 32),
    policy_generation INTEGER NOT NULL
        CHECK (policy_generation BETWEEN 1 AND 9223372036854775807),
    status TEXT NOT NULL CHECK (status IN ('pending', 'active', 'denied', 'expired')),
    created_at_unix_ms INTEGER NOT NULL
        CHECK (created_at_unix_ms BETWEEN 1 AND 9223372036854775807),
    updated_at_unix_ms INTEGER NOT NULL
        CHECK (updated_at_unix_ms BETWEEN created_at_unix_ms AND 9223372036854775807),
    authorized_until_unix_ms INTEGER
        CHECK (authorized_until_unix_ms IS NULL OR
            authorized_until_unix_ms BETWEEN created_at_unix_ms + 1 AND 9223372036854775807),
    CHECK ((status = 'active') OR authorized_until_unix_ms IS NULL)
) STRICT"#
    };
}

macro_rules! connection_permissions_table_sql {
    () => {
        r#"CREATE TABLE connection_permissions (
    connection_id BLOB NOT NULL CHECK (length(connection_id) = 32)
        REFERENCES connections(connection_id),
    permission_scope TEXT NOT NULL CHECK (permission_scope IN ('requested', 'granted')),
    permission_code TEXT NOT NULL
        CHECK (length(CAST(permission_code AS BLOB)) BETWEEN 1 AND 64),
    PRIMARY KEY (connection_id, permission_scope, permission_code)
) STRICT"#
    };
}

macro_rules! nip46_request_decisions_table_sql {
    () => {
        r#"CREATE TABLE nip46_request_decisions (
    operation_id BLOB NOT NULL PRIMARY KEY CHECK (length(operation_id) = 32)
        REFERENCES nip46_requests(operation_id),
    connection_id BLOB CHECK (connection_id IS NULL OR length(connection_id) = 32)
        REFERENCES connections(connection_id),
    decision TEXT NOT NULL
        CHECK (decision IN ('pending_approval', 'challenged', 'allowed', 'denied')),
    reason_code TEXT NOT NULL CHECK (reason_code IN (
        'explicit_approval_required',
        'trusted_client',
        'policy_denied',
        'operator_approved',
        'operator_denied',
        'authorization_challenge_required',
        'authorization_challenge_authorized',
        'authorization_challenge_expired'
    )),
    policy_generation INTEGER NOT NULL
        CHECK (policy_generation BETWEEN 1 AND 9223372036854775807),
    requested_permissions_sha256 BLOB NOT NULL
        CHECK (length(requested_permissions_sha256) = 32),
    challenge_id BLOB UNIQUE CHECK (challenge_id IS NULL OR length(challenge_id) = 32)
        REFERENCES connection_auth_challenges(challenge_id),
    decided_at_unix_ms INTEGER NOT NULL
        CHECK (decided_at_unix_ms BETWEEN 1 AND 9223372036854775807),
    CHECK (
        (decision = 'denied' AND reason_code = 'policy_denied'
            AND connection_id IS NULL AND challenge_id IS NULL)
        OR (decision = 'pending_approval' AND reason_code = 'explicit_approval_required'
            AND connection_id IS NOT NULL AND challenge_id IS NULL)
        OR (decision = 'allowed' AND reason_code IN ('trusted_client', 'operator_approved')
            AND connection_id IS NOT NULL AND challenge_id IS NULL)
        OR (decision = 'denied' AND reason_code = 'operator_denied'
            AND connection_id IS NOT NULL AND challenge_id IS NULL)
        OR (decision = 'challenged' AND reason_code = 'authorization_challenge_required'
            AND connection_id IS NOT NULL AND challenge_id IS NOT NULL)
        OR (decision = 'allowed' AND reason_code = 'authorization_challenge_authorized'
            AND connection_id IS NOT NULL AND challenge_id IS NOT NULL)
        OR (decision = 'denied' AND reason_code = 'authorization_challenge_expired'
            AND connection_id IS NOT NULL AND challenge_id IS NOT NULL)
    )
) STRICT"#
    };
}

macro_rules! connection_auth_challenges_table_sql {
    () => {
        r#"CREATE TABLE connection_auth_challenges (
    challenge_id BLOB NOT NULL PRIMARY KEY CHECK (length(challenge_id) = 32),
    challenge_nonce BLOB NOT NULL CHECK (length(challenge_nonce) = 32),
    connection_id BLOB NOT NULL CHECK (length(connection_id) = 32)
        REFERENCES connections(connection_id),
    operation_id BLOB NOT NULL UNIQUE CHECK (length(operation_id) = 32)
        REFERENCES nip46_requests(operation_id),
    policy_generation INTEGER NOT NULL
        CHECK (policy_generation BETWEEN 1 AND 9223372036854775807),
    challenge_url TEXT NOT NULL
        CHECK (length(CAST(challenge_url AS BLOB)) BETWEEN 1 AND 2048),
    state TEXT NOT NULL CHECK (state IN ('pending', 'authorized', 'expired')),
    issued_at_unix_ms INTEGER NOT NULL
        CHECK (issued_at_unix_ms BETWEEN 1 AND 9223372036854775807),
    expires_at_unix_ms INTEGER NOT NULL
        CHECK (expires_at_unix_ms BETWEEN issued_at_unix_ms + 1 AND 9223372036854775807),
    resolved_at_unix_ms INTEGER
        CHECK (resolved_at_unix_ms IS NULL OR
            resolved_at_unix_ms BETWEEN issued_at_unix_ms AND 9223372036854775807),
    CHECK ((state = 'pending' AND resolved_at_unix_ms IS NULL)
        OR (state IN ('authorized', 'expired') AND resolved_at_unix_ms IS NOT NULL))
) STRICT"#
    };
}

macro_rules! connections_guard_update_sql {
    () => {
        r#"CREATE TRIGGER connections_guard_update
BEFORE UPDATE ON connections
WHEN NEW.connection_id != OLD.connection_id
    OR NEW.connection_nonce != OLD.connection_nonce
    OR NEW.client_public_key != OLD.client_public_key
    OR NEW.requested_permissions_sha256 != OLD.requested_permissions_sha256
    OR NEW.policy_generation != OLD.policy_generation
    OR NEW.created_at_unix_ms != OLD.created_at_unix_ms
    OR NEW.updated_at_unix_ms < OLD.updated_at_unix_ms
    OR NOT (
        (OLD.status = 'pending' AND NEW.status = 'active'
            AND (NEW.authorized_until_unix_ms IS NULL
                OR NEW.authorized_until_unix_ms > NEW.updated_at_unix_ms))
        OR (OLD.status = 'pending' AND NEW.status = 'denied'
            AND NEW.authorized_until_unix_ms IS NULL)
        OR (OLD.status = 'active' AND NEW.status = 'expired'
            AND NEW.authorized_until_unix_ms IS NULL)
    )
BEGIN
    SELECT RAISE(ABORT, 'connection transition is invalid');
END"#
    };
}

macro_rules! connections_no_delete_sql {
    () => {
        r#"CREATE TRIGGER connections_no_delete
BEFORE DELETE ON connections
BEGIN
    SELECT RAISE(ABORT, 'connection evidence is retained');
END"#
    };
}

macro_rules! connection_permissions_no_update_sql {
    () => {
        r#"CREATE TRIGGER connection_permissions_no_update
BEFORE UPDATE ON connection_permissions
BEGIN
    SELECT RAISE(ABORT, 'connection permission evidence is immutable');
END"#
    };
}

macro_rules! connection_permissions_no_delete_sql {
    () => {
        r#"CREATE TRIGGER connection_permissions_no_delete
BEFORE DELETE ON connection_permissions
BEGIN
    SELECT RAISE(ABORT, 'connection permission evidence is retained');
END"#
    };
}

macro_rules! nip46_request_decisions_guard_update_sql {
    () => {
        r#"CREATE TRIGGER nip46_request_decisions_guard_update
BEFORE UPDATE ON nip46_request_decisions
WHEN NEW.operation_id != OLD.operation_id
    OR NEW.connection_id IS NOT OLD.connection_id
    OR NEW.policy_generation != OLD.policy_generation
    OR NEW.requested_permissions_sha256 != OLD.requested_permissions_sha256
    OR NEW.challenge_id IS NOT OLD.challenge_id
    OR NEW.decided_at_unix_ms < OLD.decided_at_unix_ms
    OR NOT (
        (OLD.decision = 'pending_approval' AND NEW.decision = 'allowed'
            AND NEW.reason_code = 'operator_approved')
        OR (OLD.decision = 'pending_approval' AND NEW.decision = 'denied'
            AND NEW.reason_code = 'operator_denied')
        OR (OLD.decision = 'challenged' AND NEW.decision = 'allowed'
            AND NEW.reason_code = 'authorization_challenge_authorized')
        OR (OLD.decision = 'challenged' AND NEW.decision = 'denied'
            AND NEW.reason_code = 'authorization_challenge_expired')
    )
BEGIN
    SELECT RAISE(ABORT, 'request decision transition is invalid');
END"#
    };
}

macro_rules! nip46_request_decisions_no_delete_sql {
    () => {
        r#"CREATE TRIGGER nip46_request_decisions_no_delete
BEFORE DELETE ON nip46_request_decisions
BEGIN
    SELECT RAISE(ABORT, 'request decision evidence is retained');
END"#
    };
}

macro_rules! connection_auth_challenges_guard_update_sql {
    () => {
        r#"CREATE TRIGGER connection_auth_challenges_guard_update
BEFORE UPDATE ON connection_auth_challenges
WHEN NEW.challenge_id != OLD.challenge_id
    OR NEW.challenge_nonce != OLD.challenge_nonce
    OR NEW.connection_id != OLD.connection_id
    OR NEW.operation_id != OLD.operation_id
    OR NEW.policy_generation != OLD.policy_generation
    OR NEW.challenge_url != OLD.challenge_url
    OR NEW.issued_at_unix_ms != OLD.issued_at_unix_ms
    OR NEW.expires_at_unix_ms != OLD.expires_at_unix_ms
    OR NOT (OLD.state = 'pending'
        AND NEW.state IN ('authorized', 'expired')
        AND NEW.resolved_at_unix_ms IS NOT NULL
        AND NEW.resolved_at_unix_ms >= OLD.issued_at_unix_ms)
BEGIN
    SELECT RAISE(ABORT, 'authorization challenge transition is invalid');
END"#
    };
}

macro_rules! connection_auth_challenges_no_delete_sql {
    () => {
        r#"CREATE TRIGGER connection_auth_challenges_no_delete
BEFORE DELETE ON connection_auth_challenges
BEGIN
    SELECT RAISE(ABORT, 'authorization challenge evidence is retained');
END"#
    };
}

const CREATE_CONNECTIONS_TABLE_SQL: &str = connections_table_sql!();
const CREATE_CONNECTION_PERMISSIONS_TABLE_SQL: &str = connection_permissions_table_sql!();
const CREATE_NIP46_REQUEST_DECISIONS_TABLE_SQL: &str = nip46_request_decisions_table_sql!();
const CREATE_CONNECTION_AUTH_CHALLENGES_TABLE_SQL: &str = connection_auth_challenges_table_sql!();
const CREATE_CONNECTIONS_GUARD_UPDATE_SQL: &str = connections_guard_update_sql!();
const CREATE_CONNECTIONS_NO_DELETE_SQL: &str = connections_no_delete_sql!();
const CREATE_CONNECTION_PERMISSIONS_NO_UPDATE_SQL: &str = connection_permissions_no_update_sql!();
const CREATE_CONNECTION_PERMISSIONS_NO_DELETE_SQL: &str = connection_permissions_no_delete_sql!();
const CREATE_NIP46_REQUEST_DECISIONS_GUARD_UPDATE_SQL: &str =
    nip46_request_decisions_guard_update_sql!();
const CREATE_NIP46_REQUEST_DECISIONS_NO_DELETE_SQL: &str = nip46_request_decisions_no_delete_sql!();
const CREATE_CONNECTION_AUTH_CHALLENGES_GUARD_UPDATE_SQL: &str =
    connection_auth_challenges_guard_update_sql!();
const CREATE_CONNECTION_AUTH_CHALLENGES_NO_DELETE_SQL: &str =
    connection_auth_challenges_no_delete_sql!();

const CREATE_CONNECTION_STATE_MIGRATION_SQL: &str = concat!(
    "DROP TRIGGER myc_state_metadata_no_update;\n",
    "UPDATE myc_state_metadata SET state_contract_version = CASE ",
    "WHEN state_contract_version = 3 THEN 4 ELSE 0 END WHERE singleton = 1;\n",
    myc_state_metadata_no_update_sql!(),
    ";\n",
    connections_table_sql!(),
    ";\n",
    connection_permissions_table_sql!(),
    ";\n",
    nip46_request_decisions_table_sql!(),
    ";\n",
    connection_auth_challenges_table_sql!(),
    ";\n",
    connections_guard_update_sql!(),
    ";\n",
    connections_no_delete_sql!(),
    ";\n",
    connection_permissions_no_update_sql!(),
    ";\n",
    connection_permissions_no_delete_sql!(),
    ";\n",
    nip46_request_decisions_guard_update_sql!(),
    ";\n",
    nip46_request_decisions_no_delete_sql!(),
    ";\n",
    connection_auth_challenges_guard_update_sql!(),
    ";\n",
    connection_auth_challenges_no_delete_sql!(),
);

macro_rules! myc_audit_state_table_sql {
    () => {
        r#"CREATE TABLE myc_audit_state (
    singleton INTEGER NOT NULL PRIMARY KEY CHECK (singleton = 1),
    next_sequence INTEGER NOT NULL CHECK (next_sequence BETWEEN 0 AND 9223372036854775807)
) STRICT"#
    };
}

macro_rules! operation_audit_table_sql {
    () => {
        r#"CREATE TABLE operation_audit (
    audit_sequence INTEGER NOT NULL PRIMARY KEY
        CHECK (audit_sequence BETWEEN 1 AND 9223372036854775807),
    audit_id BLOB NOT NULL UNIQUE CHECK (length(audit_id) = 32),
    correlation_id BLOB NOT NULL CHECK (length(correlation_id) = 32),
    audit_kind TEXT NOT NULL CHECK (audit_kind IN (
        'connection_admission',
        'connection_operator_decision',
        'connection_expiry',
        'challenge_creation',
        'challenge_authorization',
        'governance_compaction'
    )),
    outcome TEXT NOT NULL CHECK (outcome IN ('succeeded', 'rejected', 'failed')),
    reason_code TEXT NOT NULL CHECK (reason_code IN (
        'trusted',
        'approval_required',
        'policy_denied',
        'operator_approved',
        'operator_denied',
        'connection_expired',
        'challenge_required',
        'challenge_authorized',
        'challenge_expired',
        'rate_limited',
        'compacted'
    )),
    occurred_at_unix_ms INTEGER NOT NULL
        CHECK (occurred_at_unix_ms BETWEEN 1 AND 9223372036854775807),
    UNIQUE (correlation_id, audit_kind)
) STRICT"#
    };
}

macro_rules! nip46_request_audit_table_sql {
    () => {
        r#"CREATE TABLE nip46_request_audit (
    operation_id BLOB NOT NULL CHECK (length(operation_id) = 32)
        REFERENCES nip46_requests(operation_id),
    audit_kind TEXT NOT NULL CHECK (audit_kind IN (
        'connection_admission', 'challenge_creation', 'challenge_authorization'
    )),
    audit_sequence INTEGER NOT NULL UNIQUE
        CHECK (audit_sequence BETWEEN 1 AND 9223372036854775807)
        REFERENCES operation_audit(audit_sequence),
    PRIMARY KEY (operation_id, audit_kind)
) STRICT"#
    };
}

macro_rules! connection_rate_windows_table_sql {
    () => {
        r#"CREATE TABLE connection_rate_windows (
    rate_kind TEXT NOT NULL CHECK (rate_kind IN (
        'connection_admission', 'challenge_creation', 'challenge_authorization'
    )),
    subject_scope TEXT NOT NULL CHECK (subject_scope IN ('global', 'relay', 'connection')),
    subject_sha256 BLOB NOT NULL CHECK (length(subject_sha256) = 32),
    window_started_at_unix_ms INTEGER NOT NULL
        CHECK (window_started_at_unix_ms BETWEEN 1 AND 9223372036854775807),
    window_ends_at_unix_ms INTEGER NOT NULL
        CHECK (window_ends_at_unix_ms BETWEEN window_started_at_unix_ms AND 9223372036854775807),
    accepted_count INTEGER NOT NULL CHECK (accepted_count BETWEEN 0 AND 10000),
    rejected_count INTEGER NOT NULL CHECK (rejected_count BETWEEN 0 AND 9223372036854775807),
    lifetime_accepted_count INTEGER NOT NULL
        CHECK (lifetime_accepted_count BETWEEN accepted_count AND 9223372036854775807),
    lifetime_rejected_count INTEGER NOT NULL
        CHECK (lifetime_rejected_count BETWEEN rejected_count AND 9223372036854775807),
    last_observed_at_unix_ms INTEGER NOT NULL
        CHECK (last_observed_at_unix_ms BETWEEN window_started_at_unix_ms AND 9223372036854775807),
    retention_expires_at_unix_ms INTEGER NOT NULL
        CHECK (retention_expires_at_unix_ms BETWEEN last_observed_at_unix_ms AND 9223372036854775807),
    CHECK (
        (rate_kind = 'connection_admission' AND subject_scope IN ('global', 'relay'))
        OR (rate_kind IN ('challenge_creation', 'challenge_authorization')
            AND subject_scope = 'connection')
    ),
    PRIMARY KEY (rate_kind, subject_scope, subject_sha256)
) STRICT"#
    };
}

macro_rules! myc_audit_state_guard_update_sql {
    () => {
        r#"CREATE TRIGGER myc_audit_state_guard_update
BEFORE UPDATE ON myc_audit_state
WHEN NEW.singleton != OLD.singleton
    OR OLD.next_sequence = 9223372036854775807
    OR NEW.next_sequence != OLD.next_sequence + 1
BEGIN
    SELECT RAISE(ABORT, 'audit sequence transition is invalid');
END"#
    };
}

macro_rules! myc_audit_state_no_delete_sql {
    () => {
        r#"CREATE TRIGGER myc_audit_state_no_delete
BEFORE DELETE ON myc_audit_state
BEGIN
    SELECT RAISE(ABORT, 'audit sequence authority is retained');
END"#
    };
}

macro_rules! operation_audit_no_update_sql {
    () => {
        r#"CREATE TRIGGER operation_audit_no_update
BEFORE UPDATE ON operation_audit
BEGIN
    SELECT RAISE(ABORT, 'operation audit is immutable');
END"#
    };
}

macro_rules! nip46_request_audit_no_update_sql {
    () => {
        r#"CREATE TRIGGER nip46_request_audit_no_update
BEFORE UPDATE ON nip46_request_audit
BEGIN
    SELECT RAISE(ABORT, 'request audit binding is immutable');
END"#
    };
}

macro_rules! connection_rate_windows_guard_update_sql {
    () => {
        r#"CREATE TRIGGER connection_rate_windows_guard_update
BEFORE UPDATE ON connection_rate_windows
WHEN NEW.rate_kind != OLD.rate_kind
    OR NEW.subject_scope != OLD.subject_scope
    OR NEW.subject_sha256 != OLD.subject_sha256
    OR NEW.window_started_at_unix_ms < OLD.window_started_at_unix_ms
    OR NEW.window_ends_at_unix_ms < NEW.window_started_at_unix_ms
    OR NEW.lifetime_accepted_count < OLD.lifetime_accepted_count
    OR NEW.lifetime_rejected_count < OLD.lifetime_rejected_count
    OR NEW.last_observed_at_unix_ms < OLD.last_observed_at_unix_ms
    OR NEW.retention_expires_at_unix_ms < NEW.last_observed_at_unix_ms
    OR NOT (
        (NEW.window_started_at_unix_ms = OLD.window_started_at_unix_ms
            AND NEW.window_ends_at_unix_ms = OLD.window_ends_at_unix_ms
            AND (
                (NEW.accepted_count = OLD.accepted_count + 1
                    AND NEW.rejected_count = OLD.rejected_count
                    AND NEW.lifetime_accepted_count = OLD.lifetime_accepted_count + 1
                    AND NEW.lifetime_rejected_count = OLD.lifetime_rejected_count)
                OR (NEW.accepted_count = OLD.accepted_count
                    AND NEW.rejected_count = OLD.rejected_count + 1
                    AND NEW.lifetime_accepted_count = OLD.lifetime_accepted_count
                    AND NEW.lifetime_rejected_count = OLD.lifetime_rejected_count + 1)
            ))
        OR (NEW.window_started_at_unix_ms > OLD.window_ends_at_unix_ms
            AND NEW.window_ends_at_unix_ms > NEW.window_started_at_unix_ms
            AND ((NEW.accepted_count = 1 AND NEW.rejected_count = 0)
                OR (NEW.accepted_count = 0 AND NEW.rejected_count = 1))
            AND NEW.lifetime_accepted_count = OLD.lifetime_accepted_count + NEW.accepted_count
            AND NEW.lifetime_rejected_count = OLD.lifetime_rejected_count + NEW.rejected_count)
    )
BEGIN
    SELECT RAISE(ABORT, 'rate-window transition is invalid');
END"#
    };
}

const CREATE_MYC_AUDIT_STATE_TABLE_SQL: &str = myc_audit_state_table_sql!();
const CREATE_OPERATION_AUDIT_TABLE_SQL: &str = operation_audit_table_sql!();
const CREATE_NIP46_REQUEST_AUDIT_TABLE_SQL: &str = nip46_request_audit_table_sql!();
const CREATE_CONNECTION_RATE_WINDOWS_TABLE_SQL: &str = connection_rate_windows_table_sql!();
const CREATE_MYC_AUDIT_STATE_GUARD_UPDATE_SQL: &str = myc_audit_state_guard_update_sql!();
const CREATE_MYC_AUDIT_STATE_NO_DELETE_SQL: &str = myc_audit_state_no_delete_sql!();
const CREATE_OPERATION_AUDIT_NO_UPDATE_SQL: &str = operation_audit_no_update_sql!();
const CREATE_NIP46_REQUEST_AUDIT_NO_UPDATE_SQL: &str = nip46_request_audit_no_update_sql!();
const CREATE_CONNECTION_RATE_WINDOWS_GUARD_UPDATE_SQL: &str =
    connection_rate_windows_guard_update_sql!();

const CREATE_GOVERNANCE_STATE_MIGRATION_SQL: &str = concat!(
    "DROP TRIGGER myc_state_metadata_no_update;\n",
    "UPDATE myc_state_metadata SET state_contract_version = CASE ",
    "WHEN state_contract_version = 4 THEN 5 ELSE 0 END WHERE singleton = 1;\n",
    myc_state_metadata_no_update_sql!(),
    ";\n",
    myc_audit_state_table_sql!(),
    ";\n",
    "INSERT INTO myc_audit_state (singleton, next_sequence) VALUES (1, 0);\n",
    operation_audit_table_sql!(),
    ";\n",
    nip46_request_audit_table_sql!(),
    ";\n",
    connection_rate_windows_table_sql!(),
    ";\n",
    myc_audit_state_guard_update_sql!(),
    ";\n",
    myc_audit_state_no_delete_sql!(),
    ";\n",
    operation_audit_no_update_sql!(),
    ";\n",
    nip46_request_audit_no_update_sql!(),
    ";\n",
    connection_rate_windows_guard_update_sql!(),
);

const CONNECTIONS_TABLE_SHA256: [u8; 32] = [
    0x72, 0xd5, 0xd8, 0xba, 0x24, 0x68, 0x9c, 0x93, 0x34, 0xb3, 0x8f, 0xbf, 0x64, 0x21, 0xe1, 0x65,
    0xfd, 0xc3, 0x80, 0x46, 0xf1, 0x3f, 0x56, 0x49, 0x3a, 0xef, 0xd7, 0x42, 0xc4, 0xe6, 0x49, 0x85,
];
const CONNECTION_PERMISSIONS_TABLE_SHA256: [u8; 32] = [
    0xc0, 0x84, 0xe6, 0x03, 0xa3, 0xb8, 0xa3, 0x78, 0xeb, 0x58, 0x00, 0x6f, 0x1c, 0x1c, 0xdd, 0x76,
    0x7f, 0x67, 0xc7, 0xf4, 0xc8, 0x9d, 0x4c, 0x58, 0x02, 0x57, 0x2d, 0xca, 0x1e, 0x7d, 0x83, 0x02,
];
const NIP46_REQUEST_DECISIONS_TABLE_SHA256: [u8; 32] = [
    0xe8, 0x53, 0x1d, 0xed, 0xad, 0x22, 0xfd, 0xfe, 0x96, 0xd4, 0x17, 0x04, 0xea, 0x05, 0x6d, 0xf1,
    0x2f, 0xc2, 0x99, 0xac, 0x1a, 0xbf, 0x73, 0xff, 0xcc, 0x6f, 0x2c, 0x5f, 0xdc, 0x27, 0xd9, 0x80,
];
const CONNECTION_AUTH_CHALLENGES_TABLE_SHA256: [u8; 32] = [
    0x65, 0x09, 0x11, 0x3c, 0x4b, 0xfa, 0x30, 0x16, 0x7e, 0x0b, 0xc8, 0xf6, 0x67, 0xf5, 0x38, 0xc5,
    0x5a, 0xd9, 0x4e, 0x0e, 0xb7, 0x18, 0x22, 0x94, 0x73, 0xea, 0x11, 0x74, 0x9c, 0x8e, 0xa4, 0x37,
];
const CONNECTIONS_GUARD_UPDATE_SHA256: [u8; 32] = [
    0x66, 0x61, 0xb0, 0xc6, 0x78, 0x3a, 0x0d, 0x4a, 0x01, 0xb9, 0x7e, 0x7e, 0xd0, 0x8e, 0x2b, 0x6e,
    0xdb, 0xd5, 0x3a, 0x28, 0x56, 0x11, 0x88, 0x80, 0x16, 0xf3, 0x2e, 0x5a, 0x42, 0xf0, 0xf9, 0xfe,
];
const CONNECTIONS_NO_DELETE_SHA256: [u8; 32] = [
    0xb0, 0xcf, 0x50, 0x22, 0x23, 0x2a, 0xab, 0x23, 0x62, 0x1f, 0xfc, 0x54, 0x8c, 0xc5, 0x88, 0xdb,
    0x8c, 0x6e, 0x4a, 0xe0, 0x91, 0x48, 0x0d, 0xda, 0xc8, 0x79, 0x4b, 0x6c, 0x0c, 0x06, 0x3f, 0xaa,
];
const CONNECTION_PERMISSIONS_NO_UPDATE_SHA256: [u8; 32] = [
    0x5e, 0x11, 0x4c, 0xa4, 0x28, 0x69, 0x0e, 0xa7, 0x64, 0x3d, 0x67, 0xbc, 0x30, 0x0f, 0x3f, 0xf1,
    0xe9, 0x7e, 0xfe, 0x2f, 0x8d, 0xbd, 0x7b, 0x79, 0x47, 0x18, 0x56, 0x3d, 0xb6, 0x64, 0x70, 0x1f,
];
const CONNECTION_PERMISSIONS_NO_DELETE_SHA256: [u8; 32] = [
    0xd0, 0x27, 0x41, 0x8e, 0x03, 0x72, 0x87, 0x09, 0x16, 0x49, 0x1d, 0x83, 0x28, 0x98, 0xb9, 0x47,
    0xe1, 0x1f, 0xf8, 0xe6, 0x57, 0xbd, 0x89, 0x2c, 0x90, 0xa5, 0x5c, 0x30, 0x51, 0xfe, 0x2b, 0xd7,
];
const NIP46_REQUEST_DECISIONS_GUARD_UPDATE_SHA256: [u8; 32] = [
    0x1b, 0xf7, 0xe9, 0xb9, 0x52, 0x64, 0x95, 0x6b, 0x43, 0xf2, 0xc8, 0xdd, 0x73, 0x82, 0xc8, 0xbf,
    0x0a, 0xc3, 0xcc, 0x91, 0xa2, 0x95, 0xd7, 0xe2, 0x25, 0xc1, 0xcb, 0xc2, 0xc3, 0xa8, 0x1b, 0x26,
];
const NIP46_REQUEST_DECISIONS_NO_DELETE_SHA256: [u8; 32] = [
    0xab, 0xd0, 0x76, 0xca, 0xe9, 0x17, 0x53, 0x6d, 0xdc, 0x9d, 0x03, 0x23, 0x1e, 0xc4, 0xdc, 0xc8,
    0xab, 0x8e, 0x7a, 0xc4, 0x23, 0x4e, 0x64, 0x39, 0xaa, 0x58, 0x8b, 0x54, 0x15, 0x7a, 0x2d, 0x34,
];
const CONNECTION_AUTH_CHALLENGES_GUARD_UPDATE_SHA256: [u8; 32] = [
    0xb3, 0x24, 0x1e, 0x29, 0x5b, 0x29, 0x68, 0x9b, 0x73, 0x72, 0x5d, 0xe2, 0xce, 0x7c, 0x8c, 0x2b,
    0x85, 0xd0, 0xd2, 0xe1, 0xd8, 0xd0, 0x24, 0x6d, 0x35, 0x68, 0x23, 0x2b, 0x9e, 0x87, 0xe4, 0xa8,
];
const CONNECTION_AUTH_CHALLENGES_NO_DELETE_SHA256: [u8; 32] = [
    0xf3, 0xf8, 0xd1, 0x48, 0xbc, 0xde, 0x89, 0xd3, 0x34, 0xcd, 0xde, 0x51, 0x4b, 0x83, 0xa2, 0x19,
    0x16, 0xe5, 0xd6, 0x72, 0xb7, 0xc3, 0x1e, 0x59, 0xcb, 0xdf, 0x3a, 0x3c, 0x33, 0x80, 0x21, 0x4f,
];
const MYC_AUDIT_STATE_TABLE_SHA256: [u8; 32] = [
    0xc8, 0x6b, 0x49, 0xf6, 0x55, 0xac, 0x2c, 0xa4, 0xcb, 0x13, 0xed, 0x31, 0xff, 0x9e, 0xce, 0xe3,
    0x2f, 0xd4, 0x2a, 0x3e, 0xb0, 0xf1, 0xc8, 0x52, 0x9d, 0x92, 0xae, 0x5b, 0x48, 0x63, 0x38, 0x3b,
];
const OPERATION_AUDIT_TABLE_SHA256: [u8; 32] = [
    0xc1, 0x8d, 0x0b, 0x72, 0x34, 0xff, 0x8b, 0x21, 0x9f, 0x54, 0x20, 0x7f, 0x6c, 0x0b, 0x64, 0xae,
    0xd6, 0x8d, 0xd6, 0x1b, 0x48, 0xb3, 0x5b, 0xbe, 0x13, 0x2c, 0x0d, 0xb0, 0x9b, 0xea, 0x16, 0x2d,
];
const NIP46_REQUEST_AUDIT_TABLE_SHA256: [u8; 32] = [
    0xe2, 0x42, 0x82, 0x0b, 0xbb, 0xb2, 0x31, 0xa3, 0x8e, 0x9e, 0x7d, 0xf3, 0xf0, 0xe4, 0xd3, 0xc6,
    0x85, 0x93, 0x19, 0xe1, 0x2e, 0x47, 0x84, 0x48, 0x98, 0x8b, 0xc0, 0xdf, 0xdf, 0x96, 0xc6, 0xe3,
];
const CONNECTION_RATE_WINDOWS_TABLE_SHA256: [u8; 32] = [
    0x57, 0x53, 0xdf, 0x7b, 0x74, 0x44, 0x96, 0x9d, 0x88, 0x56, 0xe6, 0x1f, 0x15, 0x36, 0xdc, 0xab,
    0xa0, 0x02, 0x0a, 0x78, 0x77, 0x8e, 0x48, 0xa2, 0x80, 0x97, 0xc6, 0x37, 0xa6, 0x31, 0x17, 0xfc,
];
const MYC_AUDIT_STATE_GUARD_UPDATE_SHA256: [u8; 32] = [
    0xda, 0xba, 0xc9, 0x86, 0x0f, 0x2a, 0xd8, 0xa0, 0x60, 0x75, 0x4b, 0x87, 0x78, 0xc8, 0xd8, 0xce,
    0x78, 0xa3, 0x57, 0x6e, 0xea, 0x08, 0x2b, 0x0c, 0x9c, 0x56, 0x5d, 0xa2, 0xb5, 0x6c, 0x68, 0xad,
];
const MYC_AUDIT_STATE_NO_DELETE_SHA256: [u8; 32] = [
    0x0a, 0x88, 0xa1, 0xbe, 0xe8, 0x23, 0x1f, 0xf0, 0xaf, 0x41, 0x91, 0xd7, 0x38, 0x64, 0x67, 0xb6,
    0xa8, 0xac, 0xda, 0xf0, 0x38, 0x8e, 0xd4, 0xb0, 0xac, 0x2c, 0xb6, 0xf2, 0x0a, 0xa1, 0xf5, 0x5c,
];
const OPERATION_AUDIT_NO_UPDATE_SHA256: [u8; 32] = [
    0xd8, 0xe4, 0x39, 0x63, 0x67, 0x74, 0x97, 0x4c, 0xa7, 0x97, 0x54, 0x6c, 0xed, 0x39, 0x9a, 0x7b,
    0xbc, 0x6c, 0x36, 0xc5, 0xd7, 0x8e, 0xf4, 0x08, 0xbd, 0xfd, 0xb7, 0x9b, 0xd0, 0x36, 0x74, 0x40,
];
const NIP46_REQUEST_AUDIT_NO_UPDATE_SHA256: [u8; 32] = [
    0x8a, 0x4a, 0x99, 0x4c, 0x13, 0x5f, 0x8d, 0x4d, 0x85, 0xd1, 0x25, 0x1d, 0x65, 0x47, 0x4d, 0x23,
    0x37, 0x62, 0xb7, 0x27, 0xb6, 0x7f, 0x31, 0xd4, 0x9c, 0x93, 0xe5, 0xce, 0x18, 0x43, 0xba, 0x81,
];
const CONNECTION_RATE_WINDOWS_GUARD_UPDATE_SHA256: [u8; 32] = [
    0x59, 0x3c, 0xfb, 0xff, 0x20, 0x95, 0x32, 0x4e, 0x61, 0xdc, 0xd6, 0x09, 0xea, 0x7b, 0x1b, 0x1d,
    0xc4, 0xb9, 0xb7, 0x38, 0xcf, 0x80, 0x56, 0x00, 0xa5, 0x3b, 0xb4, 0xcd, 0x02, 0xcd, 0xe1, 0xef,
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
    let connections = MigrationDescriptor::sql(
        4,
        "create_connection_authorization_state",
        CREATE_CONNECTION_STATE_MIGRATION_SQL,
        MigrationChecksum::from_bytes(MYC_STATE_SCHEMA_VERSION_4_MIGRATION_SHA256),
    )
    .map_err(|_| MycStateCatalogError::new(MycStateCatalogErrorKind::MigrationCatalog))?;
    let governance = MigrationDescriptor::sql(
        5,
        "create_bounded_governance_state",
        CREATE_GOVERNANCE_STATE_MIGRATION_SQL,
        MigrationChecksum::from_bytes(MYC_STATE_SCHEMA_VERSION_5_MIGRATION_SHA256),
    )
    .map_err(|_| MycStateCatalogError::new(MycStateCatalogErrorKind::MigrationCatalog))?;
    let catalog = MigrationCatalog::new([metadata, requests, connections, governance])
        .map_err(|_| MycStateCatalogError::new(MycStateCatalogErrorKind::MigrationCatalog))?;
    if catalog.current_version() != MYC_STATE_SCHEMA_VERSION
        || catalog.descriptors().len() != 4
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
    let version_four = SchemaVersionCatalog::new(
        4,
        myc_state_connection_objects()?,
        SchemaDigest::from_bytes(MYC_STATE_SCHEMA_VERSION_4_SHA256),
    )
    .map_err(|_| MycStateCatalogError::new(MycStateCatalogErrorKind::SchemaCatalog))?;
    let version_five = SchemaVersionCatalog::new(
        5,
        myc_state_governance_objects()?,
        SchemaDigest::from_bytes(MYC_STATE_SCHEMA_VERSION_5_SHA256),
    )
    .map_err(|_| MycStateCatalogError::new(MycStateCatalogErrorKind::SchemaCatalog))?;
    let catalog = SchemaCatalog::new(
        &migrations,
        [
            version_one,
            version_two,
            version_three,
            version_four,
            version_five,
        ],
    )
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

fn myc_state_connection_objects() -> Result<[SchemaObject; 19], MycStateCatalogError> {
    let [
        metadata_table,
        metadata_update,
        metadata_delete,
        request_table,
        request_dedup,
        request_update,
        request_dedup_update,
    ] = myc_state_request_objects()?;
    let object = |kind, name, table, sql, digest| {
        SchemaObject::new(kind, name, table, sql, SchemaDigest::from_bytes(digest))
            .map_err(|_| MycStateCatalogError::new(MycStateCatalogErrorKind::SchemaCatalog))
    };
    Ok([
        metadata_table,
        metadata_update,
        metadata_delete,
        request_table,
        request_dedup,
        request_update,
        request_dedup_update,
        object(
            SchemaObjectKind::Table,
            "connections",
            "connections",
            CREATE_CONNECTIONS_TABLE_SQL,
            CONNECTIONS_TABLE_SHA256,
        )?,
        object(
            SchemaObjectKind::Table,
            "connection_permissions",
            "connection_permissions",
            CREATE_CONNECTION_PERMISSIONS_TABLE_SQL,
            CONNECTION_PERMISSIONS_TABLE_SHA256,
        )?,
        object(
            SchemaObjectKind::Table,
            "nip46_request_decisions",
            "nip46_request_decisions",
            CREATE_NIP46_REQUEST_DECISIONS_TABLE_SQL,
            NIP46_REQUEST_DECISIONS_TABLE_SHA256,
        )?,
        object(
            SchemaObjectKind::Table,
            "connection_auth_challenges",
            "connection_auth_challenges",
            CREATE_CONNECTION_AUTH_CHALLENGES_TABLE_SQL,
            CONNECTION_AUTH_CHALLENGES_TABLE_SHA256,
        )?,
        object(
            SchemaObjectKind::Trigger,
            "connections_guard_update",
            "connections",
            CREATE_CONNECTIONS_GUARD_UPDATE_SQL,
            CONNECTIONS_GUARD_UPDATE_SHA256,
        )?,
        object(
            SchemaObjectKind::Trigger,
            "connections_no_delete",
            "connections",
            CREATE_CONNECTIONS_NO_DELETE_SQL,
            CONNECTIONS_NO_DELETE_SHA256,
        )?,
        object(
            SchemaObjectKind::Trigger,
            "connection_permissions_no_update",
            "connection_permissions",
            CREATE_CONNECTION_PERMISSIONS_NO_UPDATE_SQL,
            CONNECTION_PERMISSIONS_NO_UPDATE_SHA256,
        )?,
        object(
            SchemaObjectKind::Trigger,
            "connection_permissions_no_delete",
            "connection_permissions",
            CREATE_CONNECTION_PERMISSIONS_NO_DELETE_SQL,
            CONNECTION_PERMISSIONS_NO_DELETE_SHA256,
        )?,
        object(
            SchemaObjectKind::Trigger,
            "nip46_request_decisions_guard_update",
            "nip46_request_decisions",
            CREATE_NIP46_REQUEST_DECISIONS_GUARD_UPDATE_SQL,
            NIP46_REQUEST_DECISIONS_GUARD_UPDATE_SHA256,
        )?,
        object(
            SchemaObjectKind::Trigger,
            "nip46_request_decisions_no_delete",
            "nip46_request_decisions",
            CREATE_NIP46_REQUEST_DECISIONS_NO_DELETE_SQL,
            NIP46_REQUEST_DECISIONS_NO_DELETE_SHA256,
        )?,
        object(
            SchemaObjectKind::Trigger,
            "connection_auth_challenges_guard_update",
            "connection_auth_challenges",
            CREATE_CONNECTION_AUTH_CHALLENGES_GUARD_UPDATE_SQL,
            CONNECTION_AUTH_CHALLENGES_GUARD_UPDATE_SHA256,
        )?,
        object(
            SchemaObjectKind::Trigger,
            "connection_auth_challenges_no_delete",
            "connection_auth_challenges",
            CREATE_CONNECTION_AUTH_CHALLENGES_NO_DELETE_SQL,
            CONNECTION_AUTH_CHALLENGES_NO_DELETE_SHA256,
        )?,
    ])
}

fn myc_state_governance_objects() -> Result<Vec<SchemaObject>, MycStateCatalogError> {
    let mut objects = Vec::from(myc_state_connection_objects()?);
    let object = |kind, name, table, sql, digest| {
        SchemaObject::new(kind, name, table, sql, SchemaDigest::from_bytes(digest))
            .map_err(|_| MycStateCatalogError::new(MycStateCatalogErrorKind::SchemaCatalog))
    };
    objects.extend([
        object(
            SchemaObjectKind::Table,
            "myc_audit_state",
            "myc_audit_state",
            CREATE_MYC_AUDIT_STATE_TABLE_SQL,
            MYC_AUDIT_STATE_TABLE_SHA256,
        )?,
        object(
            SchemaObjectKind::Table,
            "operation_audit",
            "operation_audit",
            CREATE_OPERATION_AUDIT_TABLE_SQL,
            OPERATION_AUDIT_TABLE_SHA256,
        )?,
        object(
            SchemaObjectKind::Table,
            "nip46_request_audit",
            "nip46_request_audit",
            CREATE_NIP46_REQUEST_AUDIT_TABLE_SQL,
            NIP46_REQUEST_AUDIT_TABLE_SHA256,
        )?,
        object(
            SchemaObjectKind::Table,
            "connection_rate_windows",
            "connection_rate_windows",
            CREATE_CONNECTION_RATE_WINDOWS_TABLE_SQL,
            CONNECTION_RATE_WINDOWS_TABLE_SHA256,
        )?,
        object(
            SchemaObjectKind::Trigger,
            "myc_audit_state_guard_update",
            "myc_audit_state",
            CREATE_MYC_AUDIT_STATE_GUARD_UPDATE_SQL,
            MYC_AUDIT_STATE_GUARD_UPDATE_SHA256,
        )?,
        object(
            SchemaObjectKind::Trigger,
            "myc_audit_state_no_delete",
            "myc_audit_state",
            CREATE_MYC_AUDIT_STATE_NO_DELETE_SQL,
            MYC_AUDIT_STATE_NO_DELETE_SHA256,
        )?,
        object(
            SchemaObjectKind::Trigger,
            "operation_audit_no_update",
            "operation_audit",
            CREATE_OPERATION_AUDIT_NO_UPDATE_SQL,
            OPERATION_AUDIT_NO_UPDATE_SHA256,
        )?,
        object(
            SchemaObjectKind::Trigger,
            "nip46_request_audit_no_update",
            "nip46_request_audit",
            CREATE_NIP46_REQUEST_AUDIT_NO_UPDATE_SQL,
            NIP46_REQUEST_AUDIT_NO_UPDATE_SHA256,
        )?,
        object(
            SchemaObjectKind::Trigger,
            "connection_rate_windows_guard_update",
            "connection_rate_windows",
            CREATE_CONNECTION_RATE_WINDOWS_GUARD_UPDATE_SQL,
            CONNECTION_RATE_WINDOWS_GUARD_UPDATE_SHA256,
        )?,
    ]);
    Ok(objects)
}

/// Independently validates exact catalog versions, counts, and digests.
pub fn validate_myc_state_catalogs(
    migrations: &MigrationCatalog,
    schema: &SchemaCatalog,
) -> Result<(), MycStateCatalogError> {
    let versions = schema.versions();
    let descriptors = migrations.descriptors();
    let valid = migrations.current_version() == MYC_STATE_SCHEMA_VERSION
        && descriptors.len() == 4
        && descriptors[0].target_version() == 2
        && descriptors[0].name().as_str() == "create_myc_state_metadata"
        && descriptors[0].checksum().as_bytes() == &MYC_STATE_SCHEMA_VERSION_2_MIGRATION_SHA256
        && descriptors[1].target_version() == 3
        && descriptors[1].name().as_str() == "create_nip46_request_admission"
        && descriptors[1].checksum().as_bytes() == &MYC_STATE_SCHEMA_VERSION_3_MIGRATION_SHA256
        && descriptors[2].target_version() == 4
        && descriptors[2].name().as_str() == "create_connection_authorization_state"
        && descriptors[2].checksum().as_bytes() == &MYC_STATE_SCHEMA_VERSION_4_MIGRATION_SHA256
        && descriptors[3].target_version() == 5
        && descriptors[3].name().as_str() == "create_bounded_governance_state"
        && descriptors[3].checksum().as_bytes() == &MYC_STATE_SCHEMA_VERSION_5_MIGRATION_SHA256
        && migrations.digest().as_bytes() == &MYC_MIGRATION_CATALOG_SHA256
        && schema.migration_catalog_digest() == migrations.digest()
        && versions.len() == 5
        && versions[0].version() == MYC_STATE_BASE_SCHEMA_VERSION
        && versions[0].object_count() == MYC_STATE_SCHEMA_VERSION_1_OBJECT_COUNT
        && versions[0].digest().as_bytes() == &MYC_STATE_SCHEMA_VERSION_1_SHA256
        && versions[1].version() == 2
        && versions[1].object_count() == MYC_STATE_SCHEMA_VERSION_2_OBJECT_COUNT
        && versions[1].digest().as_bytes() == &MYC_STATE_SCHEMA_VERSION_2_SHA256
        && versions[2].version() == 3
        && versions[2].object_count() == MYC_STATE_SCHEMA_VERSION_3_OBJECT_COUNT
        && versions[2].digest().as_bytes() == &MYC_STATE_SCHEMA_VERSION_3_SHA256
        && versions[3].version() == 4
        && versions[3].object_count() == MYC_STATE_SCHEMA_VERSION_4_OBJECT_COUNT
        && versions[3].digest().as_bytes() == &MYC_STATE_SCHEMA_VERSION_4_SHA256
        && versions[4].version() == 5
        && versions[4].object_count() == MYC_STATE_SCHEMA_VERSION_5_OBJECT_COUNT
        && versions[4].digest().as_bytes() == &MYC_STATE_SCHEMA_VERSION_5_SHA256
        && schema.digest().as_bytes() == &MYC_STATE_SCHEMA_CATALOG_SHA256;
    if valid {
        Ok(())
    } else {
        Err(MycStateCatalogError::new(
            MycStateCatalogErrorKind::CatalogMismatch,
        ))
    }
}
