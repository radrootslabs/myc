CREATE TABLE IF NOT EXISTS signer_store_metadata (
  singleton_id INTEGER PRIMARY KEY CHECK (singleton_id = 1),
  store_version INTEGER NOT NULL,
  signer_identity_id TEXT,
  signer_identity_public_key_hex TEXT,
  signer_identity_json TEXT,
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

INSERT OR IGNORE INTO signer_store_metadata (singleton_id, store_version)
VALUES (1, 1);

CREATE TABLE IF NOT EXISTS signer_connection (
  connection_id TEXT PRIMARY KEY,
  client_public_key_hex TEXT NOT NULL,
  signer_identity_id TEXT NOT NULL,
  signer_identity_public_key_hex TEXT NOT NULL,
  signer_identity_json TEXT NOT NULL,
  user_identity_id TEXT NOT NULL,
  user_identity_public_key_hex TEXT NOT NULL,
  user_identity_json TEXT NOT NULL,
  connect_secret_hash_algorithm TEXT,
  connect_secret_hash_digest_hex TEXT,
  connect_secret_consumed_at_unix INTEGER,
  requested_permissions_json TEXT NOT NULL,
  approval_requirement TEXT NOT NULL,
  approval_state TEXT NOT NULL,
  auth_state TEXT NOT NULL,
  status TEXT NOT NULL,
  status_reason TEXT,
  created_at_unix INTEGER NOT NULL,
  updated_at_unix INTEGER NOT NULL,
  last_authenticated_at_unix INTEGER,
  last_request_at_unix INTEGER
);

CREATE INDEX IF NOT EXISTS signer_connection_client_public_key_idx
ON signer_connection (client_public_key_hex);

CREATE INDEX IF NOT EXISTS signer_connection_user_identity_idx
ON signer_connection (user_identity_id);

CREATE INDEX IF NOT EXISTS signer_connection_connect_secret_digest_idx
ON signer_connection (connect_secret_hash_digest_hex)
WHERE connect_secret_hash_digest_hex IS NOT NULL;

CREATE INDEX IF NOT EXISTS signer_connection_status_idx
ON signer_connection (status);

CREATE TABLE IF NOT EXISTS signer_connection_permission_grant (
  connection_id TEXT NOT NULL REFERENCES signer_connection (connection_id) ON DELETE CASCADE,
  permission TEXT NOT NULL,
  granted_at_unix INTEGER NOT NULL,
  PRIMARY KEY (connection_id, permission)
);

CREATE INDEX IF NOT EXISTS signer_connection_permission_grant_permission_idx
ON signer_connection_permission_grant (permission);

CREATE TABLE IF NOT EXISTS signer_connection_relay (
  connection_id TEXT NOT NULL REFERENCES signer_connection (connection_id) ON DELETE CASCADE,
  ordinal INTEGER NOT NULL,
  relay_url TEXT NOT NULL,
  PRIMARY KEY (connection_id, ordinal),
  UNIQUE (connection_id, relay_url)
);

CREATE INDEX IF NOT EXISTS signer_connection_relay_url_idx
ON signer_connection_relay (relay_url);

CREATE TABLE IF NOT EXISTS signer_connection_auth_challenge (
  connection_id TEXT PRIMARY KEY REFERENCES signer_connection (connection_id) ON DELETE CASCADE,
  auth_url TEXT NOT NULL,
  required_at_unix INTEGER NOT NULL,
  authorized_at_unix INTEGER
);

CREATE TABLE IF NOT EXISTS signer_connection_pending_request (
  connection_id TEXT PRIMARY KEY REFERENCES signer_connection (connection_id) ON DELETE CASCADE,
  request_message_json TEXT NOT NULL,
  created_at_unix INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS signer_request_audit (
  request_id TEXT PRIMARY KEY,
  connection_id TEXT NOT NULL REFERENCES signer_connection (connection_id) ON DELETE CASCADE,
  method TEXT NOT NULL,
  decision TEXT NOT NULL,
  message TEXT,
  created_at_unix INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS signer_request_audit_connection_id_idx
ON signer_request_audit (connection_id);

CREATE INDEX IF NOT EXISTS signer_request_audit_created_at_idx
ON signer_request_audit (created_at_unix);
