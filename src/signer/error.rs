use thiserror::Error;

#[derive(Debug, Error)]
pub enum RadrootsNostrSignerError {
    #[error("store error: {0}")]
    Store(String),

    #[error("sign error: {0}")]
    Sign(String),

    #[error("missing signer identity")]
    MissingSignerIdentity,

    #[error("connection not found: {0}")]
    ConnectionNotFound(String),

    #[error(
        "connection already exists for client `{client_public_key}` and user `{user_identity_id}`"
    )]
    ConnectionAlreadyExists {
        client_public_key: String,
        user_identity_id: String,
    },

    #[error("connect secret already in use")]
    ConnectSecretAlreadyInUse,

    #[error("invalid auth url `{0}`")]
    InvalidAuthUrl(String),

    #[error("invalid signer state: {0}")]
    InvalidState(String),

    #[error("invalid granted permission `{0}`")]
    InvalidGrantedPermission(String),

    #[error("invalid connection id `{0}`")]
    InvalidConnectionId(String),

    #[error("invalid request id `{0}`")]
    InvalidRequestId(String),

    #[error("invalid workflow id `{0}`")]
    InvalidWorkflowId(String),

    #[error("publish workflow not found: {0}")]
    PublishWorkflowNotFound(String),

    #[error("SQLite signer journal-mode query returned {actual_rows} rows; expected exactly one")]
    SqliteJournalModeResultCardinality { actual_rows: usize },

    #[error(
        "SQLite signer connection did not enter `{expected}` journal mode; reported `{actual}`"
    )]
    SqliteJournalModeMismatch {
        expected: &'static str,
        actual: String,
    },
}

impl From<serde_json::Error> for RadrootsNostrSignerError {
    fn from(value: serde_json::Error) -> Self {
        Self::Store(value.to_string())
    }
}

impl From<nostr::event::Error> for RadrootsNostrSignerError {
    fn from(value: nostr::event::Error) -> Self {
        Self::Sign(value.to_string())
    }
}

impl From<radroots_nostr::Error> for RadrootsNostrSignerError {
    fn from(value: radroots_nostr::Error) -> Self {
        Self::InvalidState(value.to_string())
    }
}

impl From<radroots_nostr_connect::Error> for RadrootsNostrSignerError {
    fn from(value: radroots_nostr_connect::Error) -> Self {
        Self::InvalidState(value.to_string())
    }
}

impl From<crate::sql::SqlError> for RadrootsNostrSignerError {
    fn from(value: crate::sql::SqlError) -> Self {
        Self::Store(value.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn converts_serde_json_error() {
        let source =
            serde_json::from_str::<serde_json::Value>("{not-json").expect_err("serde error");
        let converted: RadrootsNostrSignerError = source.into();
        assert!(converted.to_string().starts_with("store error:"));
    }

    #[test]
    fn converts_nostr_event_error() {
        let converted: RadrootsNostrSignerError = nostr::event::Error::InvalidId.into();
        assert!(converted.to_string().starts_with("sign error:"));
    }

    #[test]
    fn converts_nostr_filter_error() {
        let converted: RadrootsNostrSignerError =
            radroots_nostr::Error::FilterTagError("bad tag".to_string()).into();
        assert!(converted.to_string().starts_with("invalid signer state:"));
    }

    #[test]
    fn converts_nostr_connect_error() {
        let converted: RadrootsNostrSignerError =
            radroots_nostr_connect::Error::InvalidMethod("bad".to_string()).into();
        assert!(converted.to_string().starts_with("invalid signer state:"));
    }

    #[test]
    fn converts_sql_error() {
        let converted: RadrootsNostrSignerError = crate::sql::SqlError::Internal.into();
        assert!(converted.to_string().starts_with("store error:"));
    }
}
