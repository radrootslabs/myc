CREATE TABLE myc_delivery_outbox (
    job_id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    status TEXT NOT NULL,
    event_json TEXT NOT NULL,
    relay_urls_json TEXT NOT NULL,
    connection_id TEXT,
    request_id TEXT,
    attempt_id TEXT,
    signer_publish_workflow_id TEXT,
    publish_attempt_count INTEGER NOT NULL,
    last_error TEXT,
    created_at_unix INTEGER NOT NULL,
    updated_at_unix INTEGER NOT NULL,
    published_at_unix INTEGER,
    finalized_at_unix INTEGER
);

CREATE INDEX idx_myc_delivery_outbox_status
    ON myc_delivery_outbox(status, created_at_unix, job_id);

CREATE INDEX idx_myc_delivery_outbox_connection_id
    ON myc_delivery_outbox(connection_id, created_at_unix, job_id);

CREATE INDEX idx_myc_delivery_outbox_request_id
    ON myc_delivery_outbox(request_id, created_at_unix, job_id);

CREATE INDEX idx_myc_delivery_outbox_attempt_id
    ON myc_delivery_outbox(attempt_id, created_at_unix, job_id);

CREATE INDEX idx_myc_delivery_outbox_signer_workflow_id
    ON myc_delivery_outbox(signer_publish_workflow_id, created_at_unix, job_id);
