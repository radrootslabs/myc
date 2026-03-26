CREATE TABLE myc_operation_audit (
    audit_record_id INTEGER PRIMARY KEY,
    recorded_at_unix INTEGER NOT NULL,
    operation TEXT NOT NULL,
    outcome TEXT NOT NULL,
    relay_url TEXT,
    connection_id TEXT,
    request_id TEXT,
    attempt_id TEXT,
    planned_repair_relays_json TEXT NOT NULL,
    blocked_relays_json TEXT NOT NULL,
    blocked_reason TEXT,
    delivery_policy TEXT,
    required_acknowledged_relay_count INTEGER,
    publish_attempt_count INTEGER,
    relay_count INTEGER NOT NULL,
    acknowledged_relay_count INTEGER NOT NULL,
    relay_outcome_summary TEXT NOT NULL
);

CREATE INDEX idx_myc_operation_audit_recorded_at
    ON myc_operation_audit(recorded_at_unix, audit_record_id);

CREATE INDEX idx_myc_operation_audit_connection_id
    ON myc_operation_audit(connection_id, recorded_at_unix, audit_record_id);

CREATE INDEX idx_myc_operation_audit_attempt_id
    ON myc_operation_audit(attempt_id, recorded_at_unix, audit_record_id);

CREATE INDEX idx_myc_operation_audit_operation_attempt
    ON myc_operation_audit(operation, recorded_at_unix, audit_record_id);
