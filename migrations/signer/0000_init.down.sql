DROP TABLE IF EXISTS signer_request_audit;
DROP TABLE IF EXISTS signer_connection_pending_request;
DROP TABLE IF EXISTS signer_connection_auth_challenge;
DROP TABLE IF EXISTS signer_connection_relay;
DROP TABLE IF EXISTS signer_connection_permission_grant;
DROP TABLE IF EXISTS signer_connection;
DELETE FROM signer_store_metadata WHERE singleton_id = 1;
DROP TABLE IF EXISTS signer_store_metadata;
