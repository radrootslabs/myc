CREATE TABLE IF NOT EXISTS signer_publish_workflow (
  workflow_id TEXT PRIMARY KEY,
  connection_id TEXT NOT NULL REFERENCES signer_connection (connection_id) ON DELETE CASCADE,
  kind TEXT NOT NULL,
  state TEXT NOT NULL,
  pending_request_json TEXT,
  authorized_at_unix INTEGER,
  created_at_unix INTEGER NOT NULL,
  updated_at_unix INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS signer_publish_workflow_connection_id_idx
ON signer_publish_workflow (connection_id);

CREATE INDEX IF NOT EXISTS signer_publish_workflow_state_idx
ON signer_publish_workflow (state);
