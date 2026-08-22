//! Exact Myc v1 Unix-admin route and model boundary.

use core::{fmt, future::Future, pin::Pin};
use std::{
    collections::BTreeSet,
    error::Error,
    path::Path,
    sync::{Arc, OnceLock},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use radroots_service_host::{
    AdminCorrelationId, AdminError, AdminErrorCode, AdminErrorMessage, AdminHttpMethod,
    AdminMutationRequest, AdminOperationId, AdminRequest, AdminRouteFailure,
    AdminRouteFailureStatus, AdminRouteOutcome, AdminRouter,
};
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};

// Original model admission is never permitted to exceed the complete response
// body cap enforced again by the shared host after envelope encoding.
const MYC_ADMIN_RESPONSE_BODY_MAX_UTF8_BYTES: usize = 1_048_576;

const OPERATOR_CONTRACT: &str =
    include_str!("../contracts/services_hardening/operator_contract.v1.json");

/// Closed Myc v1 admin method vocabulary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MycAdminMethod {
    Get,
    Post,
}

/// Closed Myc v1 Unix-admin route inventory.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MycAdminRoute {
    Status,
    EffectiveConfig,
    IdentityStatus,
    IdentityRekey,
    IdentityReplace,
    IdentityPublic,
    StateStatus,
    StateBackup,
    MetricsSnapshot,
    ConnectionsList,
    ConnectionApprove,
    ConnectionReject,
    ConnectionRevoke,
    ChallengeRequire,
    ChallengeAuthorize,
    AuditEvents,
    AuditSummary,
    DiscoveryDesired,
    DiscoveryRender,
    DiscoveryRefresh,
    DiscoveryPublish,
}

impl MycAdminRoute {
    pub const ALL: [Self; 21] = [
        Self::Status,
        Self::EffectiveConfig,
        Self::IdentityStatus,
        Self::IdentityRekey,
        Self::IdentityReplace,
        Self::IdentityPublic,
        Self::StateStatus,
        Self::StateBackup,
        Self::MetricsSnapshot,
        Self::ConnectionsList,
        Self::ConnectionApprove,
        Self::ConnectionReject,
        Self::ConnectionRevoke,
        Self::ChallengeRequire,
        Self::ChallengeAuthorize,
        Self::AuditEvents,
        Self::AuditSummary,
        Self::DiscoveryDesired,
        Self::DiscoveryRender,
        Self::DiscoveryRefresh,
        Self::DiscoveryPublish,
    ];

    #[must_use]
    pub const fn method(self) -> MycAdminMethod {
        match self {
            Self::Status
            | Self::EffectiveConfig
            | Self::IdentityStatus
            | Self::IdentityPublic
            | Self::StateStatus
            | Self::MetricsSnapshot
            | Self::ConnectionsList
            | Self::AuditEvents
            | Self::AuditSummary
            | Self::DiscoveryDesired => MycAdminMethod::Get,
            Self::IdentityRekey
            | Self::IdentityReplace
            | Self::StateBackup
            | Self::ConnectionApprove
            | Self::ConnectionReject
            | Self::ConnectionRevoke
            | Self::ChallengeRequire
            | Self::ChallengeAuthorize
            | Self::DiscoveryRender
            | Self::DiscoveryRefresh
            | Self::DiscoveryPublish => MycAdminMethod::Post,
        }
    }

    #[must_use]
    pub const fn path(self) -> &'static str {
        match self {
            Self::Status => "/v1/status",
            Self::EffectiveConfig => "/v1/config/effective",
            Self::IdentityStatus => "/v1/identity/status",
            Self::IdentityRekey => "/v1/identity/rekey",
            Self::IdentityReplace => "/v1/identity/replace",
            Self::IdentityPublic => "/v1/identity/public",
            Self::StateStatus => "/v1/state/status",
            Self::StateBackup => "/v1/state/backup",
            Self::MetricsSnapshot => "/v1/metrics/snapshot",
            Self::ConnectionsList => "/v1/connections",
            Self::ConnectionApprove => "/v1/connections/{connection_id}/approve",
            Self::ConnectionReject => "/v1/connections/{connection_id}/reject",
            Self::ConnectionRevoke => "/v1/connections/{connection_id}/revoke",
            Self::ChallengeRequire => "/v1/authorization/challenges/require",
            Self::ChallengeAuthorize => "/v1/authorization/challenges/{challenge_id}/authorize",
            Self::AuditEvents => "/v1/audit/events",
            Self::AuditSummary => "/v1/audit/summary",
            Self::DiscoveryDesired => "/v1/discovery/desired",
            Self::DiscoveryRender => "/v1/discovery/render",
            Self::DiscoveryRefresh => "/v1/discovery/refresh",
            Self::DiscoveryPublish => "/v1/discovery/publish",
        }
    }

    #[must_use]
    pub const fn operation_id(self) -> &'static str {
        match self {
            Self::Status => "radroots.myc.status.get.v1",
            Self::EffectiveConfig => "radroots.myc.config.effective.get.v1",
            Self::IdentityStatus => "radroots.myc.identity.status.get.v1",
            Self::IdentityRekey => "radroots.myc.identity.rekey.v1",
            Self::IdentityReplace => "radroots.myc.identity.replace.v1",
            Self::IdentityPublic => "radroots.myc.identity.public.get.v1",
            Self::StateStatus => "radroots.myc.state.status.get.v1",
            Self::StateBackup => "radroots.myc.state.backup.create.v1",
            Self::MetricsSnapshot => "radroots.myc.metrics.snapshot.get.v1",
            Self::ConnectionsList => "radroots.myc.connections.list.v1",
            Self::ConnectionApprove => "radroots.myc.connection.approve.v1",
            Self::ConnectionReject => "radroots.myc.connection.reject.v1",
            Self::ConnectionRevoke => "radroots.myc.connection.revoke.v1",
            Self::ChallengeRequire => "radroots.myc.authorization.challenge.require.v1",
            Self::ChallengeAuthorize => "radroots.myc.authorization.challenge.authorize.v1",
            Self::AuditEvents => "radroots.myc.audit.events.list.v1",
            Self::AuditSummary => "radroots.myc.audit.summary.get.v1",
            Self::DiscoveryDesired => "radroots.myc.discovery.desired.get.v1",
            Self::DiscoveryRender => "radroots.myc.discovery.render.v1",
            Self::DiscoveryRefresh => "radroots.myc.discovery.refresh.v1",
            Self::DiscoveryPublish => "radroots.myc.discovery.publish.v1",
        }
    }

    #[must_use]
    pub const fn request_model(self) -> &'static str {
        match self {
            Self::Status
            | Self::EffectiveConfig
            | Self::StateStatus
            | Self::MetricsSnapshot
            | Self::DiscoveryDesired => "empty",
            Self::IdentityStatus => "identity_status_query_v1",
            Self::IdentityRekey => "identity_rekey_request_v1",
            Self::IdentityReplace => "identity_replace_request_v1",
            Self::IdentityPublic => "identity_public_query_v1",
            Self::StateBackup => "state_backup_request_v1",
            Self::ConnectionsList => "connections_query_v1",
            Self::ConnectionApprove => "connection_approve_request_v1",
            Self::ConnectionReject => "connection_reject_request_v1",
            Self::ConnectionRevoke => "connection_revoke_request_v1",
            Self::ChallengeRequire => "challenge_require_request_v1",
            Self::ChallengeAuthorize => "challenge_authorize_request_v1",
            Self::AuditEvents => "audit_events_query_v1",
            Self::AuditSummary => "audit_summary_query_v1",
            Self::DiscoveryRender => "discovery_render_request_v1",
            Self::DiscoveryRefresh => "discovery_refresh_request_v1",
            Self::DiscoveryPublish => "discovery_publish_request_v1",
        }
    }

    #[must_use]
    pub const fn response_model(self) -> &'static str {
        match self {
            Self::Status => "service_status_v1",
            Self::EffectiveConfig => "effective_config_v1",
            Self::IdentityStatus => "identity_status_v1",
            Self::IdentityRekey | Self::IdentityReplace => "identity_mutation_receipt_v1",
            Self::IdentityPublic => "identity_public_v1",
            Self::StateStatus => "state_status_v1",
            Self::StateBackup => "state_backup_receipt_v1",
            Self::MetricsSnapshot => "metrics_snapshot_v1",
            Self::ConnectionsList => "connections_page_v1",
            Self::ConnectionApprove | Self::ConnectionReject | Self::ConnectionRevoke => {
                "connection_mutation_receipt_v1"
            }
            Self::ChallengeRequire => "challenge_v1",
            Self::ChallengeAuthorize => "challenge_authorization_receipt_v1",
            Self::AuditEvents => "audit_events_page_v1",
            Self::AuditSummary => "audit_summary_v1",
            Self::DiscoveryDesired => "discovery_desired_v1",
            Self::DiscoveryRender => "discovery_render_receipt_v1",
            Self::DiscoveryRefresh => "discovery_refresh_receipt_v1",
            Self::DiscoveryPublish => "discovery_publish_receipt_v1",
        }
    }

    #[must_use]
    pub const fn is_mutation(self) -> bool {
        matches!(self.method(), MycAdminMethod::Post)
    }

    const fn host_method(self) -> AdminHttpMethod {
        match self.method() {
            MycAdminMethod::Get => AdminHttpMethod::Get,
            MycAdminMethod::Post => AdminHttpMethod::Post,
        }
    }

    const fn parameter_name(self) -> Option<&'static str> {
        match self {
            Self::ConnectionApprove | Self::ConnectionReject | Self::ConnectionRevoke => {
                Some("connection_id")
            }
            Self::ChallengeAuthorize => Some("challenge_id"),
            _ => None,
        }
    }
}

/// One route-bound, already validated Myc admin request.
pub struct MycAdminRequestDocument {
    route: MycAdminRoute,
    operation_id: Option<AdminOperationId>,
    correlation_id: AdminCorrelationId,
    parameter: Option<(&'static str, Box<str>)>,
    model_bytes: Box<[u8]>,
}

impl MycAdminRequestDocument {
    #[must_use]
    pub const fn route(&self) -> MycAdminRoute {
        self.route
    }

    /// Returns the caller's durable idempotency identity for a mutation.
    #[must_use]
    pub fn operation_id(&self) -> Option<&str> {
        self.operation_id.as_ref().map(AdminOperationId::as_str)
    }

    #[must_use]
    pub fn correlation_id(&self) -> &str {
        self.correlation_id.as_str()
    }

    /// Returns a validated percent-decoded path parameter when this route has one.
    #[must_use]
    pub fn parameter(&self, name: &str) -> Option<&str> {
        self.parameter
            .as_ref()
            .filter(|(parameter_name, _)| *parameter_name == name)
            .map(|(_, value)| value.as_ref())
    }

    /// Returns compact canonical JSON for the route's exact request model.
    #[must_use]
    pub fn model_bytes(&self) -> &[u8] {
        &self.model_bytes
    }
}

impl fmt::Debug for MycAdminRequestDocument {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MycAdminRequestDocument")
            .field("route", &self.route)
            .field("mutation", &self.operation_id.is_some())
            .field("has_parameter", &self.parameter.is_some())
            .field("model", &"[redacted]")
            .finish()
    }
}

/// One exact validated response model for a fixed route.
pub struct MycAdminResponseDocument {
    route: MycAdminRoute,
    canonical_bytes: Box<[u8]>,
    value: Value,
}

impl MycAdminResponseDocument {
    /// Admits only compact canonical JSON matching the route's response model.
    pub fn from_canonical_bytes(
        route: MycAdminRoute,
        bytes: &[u8],
    ) -> Result<Self, MycAdminDocumentError> {
        if bytes.is_empty() {
            return Err(MycAdminDocumentError::new(
                MycAdminDocumentErrorKind::Malformed,
            ));
        }
        if bytes.len() > MYC_ADMIN_RESPONSE_BODY_MAX_UTF8_BYTES {
            return Err(MycAdminDocumentError::new(
                MycAdminDocumentErrorKind::TooLarge,
            ));
        }
        let value = strict_json(bytes)?;
        validate_model(route.response_model(), &value)?;
        let canonical = serde_json::to_vec(&value)
            .map_err(|_| MycAdminDocumentError::new(MycAdminDocumentErrorKind::Malformed))?;
        if canonical.as_slice() != bytes {
            return Err(MycAdminDocumentError::new(
                MycAdminDocumentErrorKind::NonCanonical,
            ));
        }
        Ok(Self {
            route,
            canonical_bytes: canonical.into_boxed_slice(),
            value,
        })
    }

    #[must_use]
    pub const fn route(&self) -> MycAdminRoute {
        self.route
    }

    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }
}

impl fmt::Debug for MycAdminResponseDocument {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MycAdminResponseDocument")
            .field("route", &self.route)
            .field("model", &"[redacted]")
            .finish()
    }
}

/// Stable classification for a rejected Myc admin document.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MycAdminDocumentErrorKind {
    TooLarge,
    Malformed,
    DuplicateField,
    NullForbidden,
    NonCanonical,
    InvalidModel,
}

/// Source-free and content-free Myc admin document error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MycAdminDocumentError {
    kind: MycAdminDocumentErrorKind,
}

impl MycAdminDocumentError {
    const fn new(kind: MycAdminDocumentErrorKind) -> Self {
        Self { kind }
    }

    #[must_use]
    pub const fn kind(self) -> MycAdminDocumentErrorKind {
        self.kind
    }
}

impl fmt::Display for MycAdminDocumentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Myc admin document is invalid")
    }
}

impl Error for MycAdminDocumentError {}

/// Stable route-handler failure mapped to a bounded safe admin response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MycAdminHandlerErrorKind {
    InvalidCursor,
    OperationIdConflict,
    NotFound,
    Conflict,
    Unavailable,
    Internal,
}

/// Source-free route-handler error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MycAdminHandlerError {
    kind: MycAdminHandlerErrorKind,
}

impl MycAdminHandlerError {
    #[must_use]
    pub const fn new(kind: MycAdminHandlerErrorKind) -> Self {
        Self { kind }
    }

    #[must_use]
    pub const fn kind(self) -> MycAdminHandlerErrorKind {
        self.kind
    }
}

impl fmt::Display for MycAdminHandlerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Myc admin operation failed")
    }
}

impl Error for MycAdminHandlerError {}

/// Boxed route future used by the sealed Myc admin adapter.
pub type MycAdminFuture<'a> = Pin<
    Box<dyn Future<Output = Result<MycAdminResponseDocument, MycAdminHandlerError>> + Send + 'a>,
>;

/// Domain port behind the exact Myc admin transport.
///
/// Implementations own authoritative local commit, durable operation-ID
/// replay/conflict handling, and any provider or outbox orchestration. Returning
/// success means that the operation's contract-defined local effect is already
/// committed; relay submission or delivery is not implied. Pagination cursors
/// must be authenticated and bound to the same route, filters, and snapshot;
/// mismatched or invalid cursors return [`MycAdminHandlerErrorKind::InvalidCursor`].
/// Reusing an operation ID with identical canonical request bytes returns the
/// original committed response; reuse with different bytes returns
/// [`MycAdminHandlerErrorKind::OperationIdConflict`].
pub trait MycAdminHandler: Send + Sync + 'static {
    fn handle<'a>(&'a self, request: MycAdminRequestDocument) -> MycAdminFuture<'a>;
}

/// Source-free router-construction failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MycAdminRouterError;

impl fmt::Display for MycAdminRouterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Myc admin router could not be constructed")
    }
}

impl Error for MycAdminRouterError {}

/// Opaque, fully registered Myc v1 router capability.
///
/// The underlying shared-host router remains an implementation detail. The
/// later runtime-composition checkpoint consumes this capability without
/// exposing raw listener or transport authority.
pub struct MycAdminRouter {
    inner: AdminRouter,
}

impl fmt::Debug for MycAdminRouter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self { inner } = self;
        let _ = inner;
        formatter.write_str("MycAdminRouter")
    }
}

/// Registers the complete closed Myc v1 route inventory on the hardened Lib router.
pub fn build_myc_admin_router<H>(handler: Arc<H>) -> Result<MycAdminRouter, MycAdminRouterError>
where
    H: MycAdminHandler,
{
    if !operator_route_inventory_is_exact() {
        return Err(MycAdminRouterError);
    }
    let mut router = AdminRouter::new();
    for route in MycAdminRoute::ALL {
        let handler = Arc::clone(&handler);
        router
            .route(route.host_method(), route.path(), move |request| {
                let handler = Arc::clone(&handler);
                async move { dispatch_route(route, handler, request).await }
            })
            .map_err(|_| MycAdminRouterError)?;
    }
    Ok(MycAdminRouter { inner: router })
}

async fn dispatch_route<H>(
    route: MycAdminRoute,
    handler: Arc<H>,
    request: AdminRequest,
) -> AdminRouteOutcome
where
    H: MycAdminHandler,
{
    let document = match request_document(route, &request) {
        Ok(document) => document,
        Err(_) => return failure(MycAdminHandlerErrorKind::Conflict, true),
    };
    match handler.handle(document).await {
        Ok(response) if response.route == route => match request.success(&response.value) {
            Ok(outcome) => outcome,
            Err(_) => failure(MycAdminHandlerErrorKind::Internal, false),
        },
        Ok(_) => failure(MycAdminHandlerErrorKind::Internal, false),
        Err(error) => failure(error.kind, false),
    }
}

fn failure(kind: MycAdminHandlerErrorKind, invalid_request: bool) -> AdminRouteOutcome {
    let (status, code, message) = if invalid_request {
        (
            AdminRouteFailureStatus::BadRequest,
            "invalid_request",
            "admin request does not match the route model",
        )
    } else {
        match kind {
            MycAdminHandlerErrorKind::InvalidCursor => (
                AdminRouteFailureStatus::BadRequest,
                "invalid_cursor",
                "admin pagination cursor is invalid",
            ),
            MycAdminHandlerErrorKind::OperationIdConflict => (
                AdminRouteFailureStatus::Conflict,
                "operation_id_conflict",
                "admin operation identity conflicts with retained state",
            ),
            MycAdminHandlerErrorKind::NotFound => (
                AdminRouteFailureStatus::NotFound,
                "not_found",
                "admin resource was not found",
            ),
            MycAdminHandlerErrorKind::Conflict => (
                AdminRouteFailureStatus::Conflict,
                "operation_conflict",
                "admin operation conflicts with current state",
            ),
            MycAdminHandlerErrorKind::Unavailable => (
                AdminRouteFailureStatus::Unavailable,
                "service_unavailable",
                "admin operation is temporarily unavailable",
            ),
            MycAdminHandlerErrorKind::Internal => (
                AdminRouteFailureStatus::Internal,
                "internal_error",
                "admin operation failed internally",
            ),
        }
    };
    let code = AdminErrorCode::new(code).expect("fixed admin error code");
    let message = AdminErrorMessage::new(message).expect("fixed admin error message");
    AdminRouteOutcome::failure(AdminRouteFailure::new(
        status,
        AdminError::new(code, message),
    ))
}

fn request_document(
    route: MycAdminRoute,
    request: &AdminRequest,
) -> Result<MycAdminRequestDocument, MycAdminDocumentError> {
    let (operation_id, value) = match route.method() {
        MycAdminMethod::Get => (None, query_model(route, request.query())?),
        MycAdminMethod::Post => {
            let envelope = request
                .decode_json::<AdminMutationRequest<Value>>()
                .map_err(|_| MycAdminDocumentError::new(MycAdminDocumentErrorKind::Malformed))?;
            (
                Some(envelope.operation_id().clone()),
                envelope.into_request(),
            )
        }
    };
    validate_model(route.request_model(), &value)?;
    let model_bytes = serde_json::to_vec(&value)
        .map_err(|_| MycAdminDocumentError::new(MycAdminDocumentErrorKind::Malformed))?;
    let parameter = route
        .parameter_name()
        .map(|name| {
            let value = request
                .parameter(name)
                .ok_or_else(|| MycAdminDocumentError::new(MycAdminDocumentErrorKind::InvalidModel))?
                .to_owned()
                .into_boxed_str();
            validate_type("bounded_id", &Value::String(value.to_string()), 0)?;
            Ok((name, value))
        })
        .transpose()?;
    Ok(MycAdminRequestDocument {
        route,
        operation_id,
        correlation_id: request.correlation_id().clone(),
        parameter,
        model_bytes: model_bytes.into_boxed_slice(),
    })
}

fn query_model(route: MycAdminRoute, query: Option<&str>) -> Result<Value, MycAdminDocumentError> {
    let Some(query) = query else {
        return Ok(Value::Object(Map::new()));
    };
    if query.is_empty() {
        return Err(MycAdminDocumentError::new(
            MycAdminDocumentErrorKind::InvalidModel,
        ));
    }
    let fields = model_fields(route.request_model())?;
    let mut output = Map::new();
    for item in query.split('&') {
        let (raw_key, raw_value) = item
            .split_once('=')
            .ok_or_else(|| MycAdminDocumentError::new(MycAdminDocumentErrorKind::InvalidModel))?;
        if raw_key.is_empty()
            || !valid_percent_encoding(raw_key)
            || !valid_percent_encoding(raw_value)
        {
            return Err(MycAdminDocumentError::new(
                MycAdminDocumentErrorKind::InvalidModel,
            ));
        }
        let key = percent_decode(raw_key)?;
        let value = percent_decode(raw_value)?;
        if output.contains_key(&key) {
            return Err(MycAdminDocumentError::new(
                MycAdminDocumentErrorKind::DuplicateField,
            ));
        }
        let descriptor = fields
            .get(&key)
            .ok_or_else(|| MycAdminDocumentError::new(MycAdminDocumentErrorKind::InvalidModel))?;
        let type_name = descriptor
            .get("type")
            .and_then(Value::as_str)
            .ok_or_else(|| MycAdminDocumentError::new(MycAdminDocumentErrorKind::InvalidModel))?;
        output.insert(key, query_scalar(type_name, value)?);
    }
    Ok(Value::Object(output))
}

fn query_scalar(type_name: &str, value: String) -> Result<Value, MycAdminDocumentError> {
    let descriptor = type_descriptor(type_name)?;
    match descriptor.get("kind").and_then(Value::as_str) {
        Some("integer") => {
            let canonical = value == "0"
                || (value.as_bytes().first().is_some_and(u8::is_ascii_digit)
                    && !value.starts_with('0')
                    && value.bytes().all(|byte| byte.is_ascii_digit()));
            if !canonical {
                return Err(MycAdminDocumentError::new(
                    MycAdminDocumentErrorKind::InvalidModel,
                ));
            }
            value
                .parse::<u64>()
                .map(Value::from)
                .map_err(|_| MycAdminDocumentError::new(MycAdminDocumentErrorKind::InvalidModel))
        }
        Some("boolean") => match value.as_str() {
            "true" => Ok(Value::Bool(true)),
            "false" => Ok(Value::Bool(false)),
            _ => Err(MycAdminDocumentError::new(
                MycAdminDocumentErrorKind::InvalidModel,
            )),
        },
        _ => Ok(Value::String(value)),
    }
}

fn percent_decode(value: &str) -> Result<String, MycAdminDocumentError> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'%' => {
                let high = hex_nibble(bytes[index + 1]).ok_or_else(invalid_model_error)?;
                let low = hex_nibble(bytes[index + 2]).ok_or_else(invalid_model_error)?;
                decoded.push((high << 4) | low);
                index += 3;
            }
            b'+' => {
                decoded.push(b' ');
                index += 1;
            }
            byte => {
                decoded.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8(decoded).map_err(|_| invalid_model_error())
}

const fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn valid_percent_encoding(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len()
                || !bytes[index + 1].is_ascii_hexdigit()
                || !bytes[index + 2].is_ascii_hexdigit()
            {
                return false;
            }
            index += 3;
        } else {
            index += 1;
        }
    }
    true
}

fn operator_contract() -> &'static Value {
    static CONTRACT: OnceLock<Value> = OnceLock::new();
    CONTRACT.get_or_init(|| {
        serde_json::from_str(OPERATOR_CONTRACT).expect("checked-in Myc operator contract")
    })
}

fn operator_route_inventory_is_exact() -> bool {
    let Some(admin) = operator_contract().get("admin") else {
        return false;
    };
    let Some(routes) = admin.get("routes").and_then(Value::as_array) else {
        return false;
    };
    let Some(models) = admin.get("models").and_then(Value::as_object) else {
        return false;
    };
    routes.len() == MycAdminRoute::ALL.len()
        && models.len() == 35
        && admin
            .pointer("/model_wire_contract/response_body_max_utf8_bytes")
            .and_then(Value::as_u64)
            == Some(MYC_ADMIN_RESPONSE_BODY_MAX_UTF8_BYTES as u64)
        && routes.iter().zip(MycAdminRoute::ALL).all(|(wire, route)| {
            wire.get("method").and_then(Value::as_str)
                == Some(match route.method() {
                    MycAdminMethod::Get => "GET",
                    MycAdminMethod::Post => "POST",
                })
                && wire.get("path").and_then(Value::as_str) == Some(route.path())
                && wire.get("operation_id").and_then(Value::as_str) == Some(route.operation_id())
                && wire.get("request_model").and_then(Value::as_str) == Some(route.request_model())
                && wire.get("response_model").and_then(Value::as_str)
                    == Some(route.response_model())
                && wire.get("mutation").and_then(Value::as_bool) == Some(route.is_mutation())
        })
}

fn model_fields(model_name: &str) -> Result<&'static Map<String, Value>, MycAdminDocumentError> {
    operator_contract()
        .pointer(&format!("/admin/models/{model_name}/fields"))
        .and_then(Value::as_object)
        .ok_or_else(|| MycAdminDocumentError::new(MycAdminDocumentErrorKind::InvalidModel))
}

fn type_descriptor(type_name: &str) -> Result<&'static Value, MycAdminDocumentError> {
    operator_contract()
        .pointer(&format!("/admin/types/{type_name}"))
        .ok_or_else(|| MycAdminDocumentError::new(MycAdminDocumentErrorKind::InvalidModel))
}

fn validate_model(model_name: &str, value: &Value) -> Result<(), MycAdminDocumentError> {
    let object = value
        .as_object()
        .ok_or_else(|| MycAdminDocumentError::new(MycAdminDocumentErrorKind::InvalidModel))?;
    let fields = model_fields(model_name)?;
    for key in object.keys() {
        if !fields.contains_key(key) {
            return Err(MycAdminDocumentError::new(
                MycAdminDocumentErrorKind::InvalidModel,
            ));
        }
    }
    for (name, field) in fields {
        let required = field.get("presence").and_then(Value::as_str) == Some("required");
        let type_name = field
            .get("type")
            .and_then(Value::as_str)
            .ok_or_else(|| MycAdminDocumentError::new(MycAdminDocumentErrorKind::InvalidModel))?;
        match object.get(name) {
            Some(value) => validate_type(type_name, value, 0)?,
            None if required => {
                return Err(MycAdminDocumentError::new(
                    MycAdminDocumentErrorKind::InvalidModel,
                ));
            }
            None => {}
        }
    }
    Ok(())
}

fn validate_type(
    type_name: &str,
    value: &Value,
    depth: usize,
) -> Result<(), MycAdminDocumentError> {
    if depth > 24 || value.is_null() {
        return Err(MycAdminDocumentError::new(if value.is_null() {
            MycAdminDocumentErrorKind::NullForbidden
        } else {
            MycAdminDocumentErrorKind::InvalidModel
        }));
    }
    let descriptor = type_descriptor(type_name)?;
    match descriptor.get("kind").and_then(Value::as_str) {
        Some("literal") => {
            if descriptor.get("value") != Some(value) {
                return invalid_model();
            }
        }
        Some("boolean") => {
            if !value.is_boolean() {
                return invalid_model();
            }
        }
        Some("integer") => validate_integer(descriptor, value)?,
        Some("string") => validate_string(descriptor, value)?,
        Some("enum") => {
            if !descriptor
                .get("values")
                .and_then(Value::as_array)
                .is_some_and(|values| values.contains(value))
            {
                return invalid_model();
            }
        }
        Some("string_union") => validate_string_union(descriptor, value)?,
        Some("array") => validate_array(descriptor, value, depth + 1)?,
        Some("canonical_delimited_set") => {
            validate_delimited_set(descriptor, value, depth + 1)?;
        }
        Some("map") => validate_map(descriptor, value, depth + 1)?,
        Some("closed_object") => validate_closed_object(descriptor, value, depth + 1)?,
        Some("tagged_union") => validate_tagged_union(descriptor, value, depth + 1)?,
        Some("alias") => validate_type(
            descriptor
                .get("target")
                .and_then(Value::as_str)
                .ok_or_else(invalid_model_error)?,
            value,
            depth + 1,
        )?,
        Some("optional") => validate_type(
            descriptor
                .get("value")
                .and_then(Value::as_str)
                .ok_or_else(invalid_model_error)?,
            value,
            depth + 1,
        )?,
        Some("canonical_json_object") => {
            if !value.is_object()
                || serde_json::to_vec(value).ok().is_none_or(|bytes| {
                    bytes.len()
                        > descriptor
                            .get("maximum_utf8_bytes")
                            .and_then(Value::as_u64)
                            .and_then(|value| usize::try_from(value).ok())
                            .unwrap_or(0)
                })
            {
                return invalid_model();
            }
        }
        _ => return invalid_model(),
    }
    Ok(())
}

fn validate_integer(descriptor: &Value, value: &Value) -> Result<(), MycAdminDocumentError> {
    let number = value.as_u64().ok_or_else(invalid_model_error)?;
    let minimum = descriptor
        .get("minimum")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let maximum = descriptor
        .get("maximum")
        .and_then(Value::as_u64)
        .unwrap_or(u64::MAX);
    if !(minimum..=maximum).contains(&number) {
        return invalid_model();
    }
    Ok(())
}

fn validate_string(descriptor: &Value, value: &Value) -> Result<(), MycAdminDocumentError> {
    let string = value.as_str().ok_or_else(invalid_model_error)?;
    let exact = descriptor
        .get("utf8_bytes")
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok());
    let minimum = descriptor
        .get("minimum_utf8_bytes")
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .unwrap_or(0);
    let maximum = descriptor
        .get("maximum_utf8_bytes")
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .unwrap_or(usize::MAX);
    if exact.is_some_and(|exact| string.len() != exact)
        || !(minimum..=maximum).contains(&string.len())
        || string.chars().any(char::is_control)
    {
        return invalid_model();
    }
    if let Some(pattern) = descriptor.get("pattern").and_then(Value::as_str) {
        let valid = match pattern {
            "^[A-Za-z0-9][A-Za-z0-9._:-]*$" => bounded_id(string),
            "^[a-z][a-z0-9_]*$" => safe_code(string),
            "^[0-9a-f]{64}$" => lower_hex(string, 64),
            "^[0-9a-f]{40}$" => lower_hex(string, 40),
            "^/" => Path::new(string).is_absolute(),
            _ => false,
        };
        if !valid {
            return invalid_model();
        }
    }
    if descriptor.get("encoding").and_then(Value::as_str) == Some("canonical_base64url_no_padding")
    {
        let decoded = URL_SAFE_NO_PAD
            .decode(string)
            .map_err(|_| invalid_model_error())?;
        if URL_SAFE_NO_PAD.encode(decoded) != string {
            return invalid_model();
        }
    }
    if let Some(schemes) = descriptor.get("allowed_schemes").and_then(Value::as_array) {
        let parsed = url::Url::parse(string).map_err(|_| invalid_model_error())?;
        if !schemes
            .iter()
            .any(|scheme| scheme.as_str() == Some(parsed.scheme()))
        {
            return invalid_model();
        }
    }
    Ok(())
}

fn validate_string_union(descriptor: &Value, value: &Value) -> Result<(), MycAdminDocumentError> {
    let string = value.as_str().ok_or_else(invalid_model_error)?;
    if descriptor
        .get("simple_values")
        .and_then(Value::as_array)
        .is_some_and(|values| values.iter().any(|value| value.as_str() == Some(string)))
    {
        return Ok(());
    }
    let kind = string
        .strip_prefix("sign_event:kind:")
        .ok_or_else(invalid_model_error)?;
    if kind.is_empty()
        || (kind.len() > 1 && kind.starts_with('0'))
        || !kind.bytes().all(|byte| byte.is_ascii_digit())
        || kind.parse::<u32>().is_err()
        || string.len()
            > descriptor
                .get("maximum_utf8_bytes")
                .and_then(Value::as_u64)
                .and_then(|value| usize::try_from(value).ok())
                .unwrap_or(0)
    {
        return invalid_model();
    }
    Ok(())
}

fn validate_array(
    descriptor: &Value,
    value: &Value,
    depth: usize,
) -> Result<(), MycAdminDocumentError> {
    let values = value.as_array().ok_or_else(invalid_model_error)?;
    let maximum = descriptor
        .get("maximum_items")
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .unwrap_or(0);
    if values.len() > maximum {
        return invalid_model();
    }
    let item_type = descriptor
        .get("items")
        .and_then(Value::as_str)
        .ok_or_else(invalid_model_error)?;
    for item in values {
        validate_type(item_type, item, depth)?;
    }
    if descriptor.get("unique").and_then(Value::as_bool) == Some(true) {
        let mut unique = BTreeSet::new();
        for item in values {
            let encoded = serde_json::to_vec(item).map_err(|_| invalid_model_error())?;
            if !unique.insert(encoded) {
                return invalid_model();
            }
        }
    }
    if descriptor.get("canonical_sort").is_some() {
        let rendered = values
            .iter()
            .map(|value| value.as_str().ok_or_else(invalid_model_error))
            .collect::<Result<Vec<_>, _>>()?;
        if !rendered.windows(2).all(|pair| pair[0] < pair[1]) {
            return invalid_model();
        }
    }
    Ok(())
}

fn validate_delimited_set(
    descriptor: &Value,
    value: &Value,
    depth: usize,
) -> Result<(), MycAdminDocumentError> {
    let rendered = value.as_str().ok_or_else(invalid_model_error)?;
    let maximum_bytes = descriptor
        .get("maximum_utf8_bytes")
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .unwrap_or(0);
    if rendered.len() > maximum_bytes {
        return invalid_model();
    }
    if rendered.is_empty() {
        return if descriptor.get("empty_allowed").and_then(Value::as_bool) == Some(true) {
            Ok(())
        } else {
            invalid_model()
        };
    }
    let delimiter = descriptor
        .get("delimiter")
        .and_then(Value::as_str)
        .filter(|delimiter| delimiter.len() == 1)
        .ok_or_else(invalid_model_error)?;
    let items = rendered.split(delimiter).collect::<Vec<_>>();
    let maximum_items = descriptor
        .get("maximum_items")
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .unwrap_or(0);
    if items.is_empty()
        || items.len() > maximum_items
        || items.iter().any(|item| item.is_empty())
        || !items.windows(2).all(|pair| pair[0] < pair[1])
    {
        return invalid_model();
    }
    let item_type = descriptor
        .get("items")
        .and_then(Value::as_str)
        .ok_or_else(invalid_model_error)?;
    for item in items {
        validate_type(item_type, &Value::String(item.to_owned()), depth)?;
    }
    Ok(())
}

fn validate_map(
    descriptor: &Value,
    value: &Value,
    depth: usize,
) -> Result<(), MycAdminDocumentError> {
    let values = value.as_object().ok_or_else(invalid_model_error)?;
    let maximum_entries = descriptor
        .get("maximum_entries")
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .unwrap_or(0);
    if values.len() > maximum_entries {
        return invalid_model();
    }
    let key_type = descriptor
        .get("key")
        .and_then(Value::as_str)
        .ok_or_else(invalid_model_error)?;
    let value_type = descriptor
        .get("value")
        .and_then(Value::as_str)
        .ok_or_else(invalid_model_error)?;
    for (key, value) in values {
        validate_type(key_type, &Value::String(key.clone()), depth)?;
        validate_type(value_type, value, depth)?;
    }
    Ok(())
}

fn validate_closed_object(
    descriptor: &Value,
    value: &Value,
    depth: usize,
) -> Result<(), MycAdminDocumentError> {
    let values = value.as_object().ok_or_else(invalid_model_error)?;
    let fields = descriptor
        .get("fields")
        .and_then(Value::as_object)
        .ok_or_else(invalid_model_error)?;
    if values.keys().any(|key| !fields.contains_key(key)) {
        return invalid_model();
    }
    for (field, type_name) in fields {
        let type_name = type_name.as_str().ok_or_else(invalid_model_error)?;
        match values.get(field) {
            Some(value) => validate_type(type_name, value, depth)?,
            None if type_descriptor(type_name)?
                .get("kind")
                .and_then(Value::as_str)
                == Some("optional") => {}
            None => return invalid_model(),
        }
    }
    Ok(())
}

fn validate_tagged_union(
    descriptor: &Value,
    value: &Value,
    depth: usize,
) -> Result<(), MycAdminDocumentError> {
    let object = value.as_object().ok_or_else(invalid_model_error)?;
    let discriminator = descriptor
        .get("discriminator")
        .and_then(Value::as_str)
        .ok_or_else(invalid_model_error)?;
    let selected = object.get(discriminator).ok_or_else(invalid_model_error)?;
    let variants = descriptor
        .get("variants")
        .and_then(Value::as_array)
        .ok_or_else(invalid_model_error)?;
    let mut matched = None;
    for variant in variants {
        let variant = variant.as_str().ok_or_else(invalid_model_error)?;
        let fields = type_descriptor(variant)?
            .get("fields")
            .and_then(Value::as_object)
            .ok_or_else(invalid_model_error)?;
        let discriminator_type = fields
            .get(discriminator)
            .and_then(Value::as_str)
            .ok_or_else(invalid_model_error)?;
        if type_descriptor(discriminator_type)?.get("value") == Some(selected)
            && matched.replace(variant).is_some()
        {
            return invalid_model();
        }
    }
    validate_type(matched.ok_or_else(invalid_model_error)?, value, depth)
}

fn bounded_id(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

fn safe_code(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

fn lower_hex(value: &str, exact: usize) -> bool {
    value.len() == exact
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn invalid_model<T>() -> Result<T, MycAdminDocumentError> {
    Err(invalid_model_error())
}

const fn invalid_model_error() -> MycAdminDocumentError {
    MycAdminDocumentError::new(MycAdminDocumentErrorKind::InvalidModel)
}

const DUPLICATE_MARKER: &str = "myc_admin_duplicate_field";
const NULL_MARKER: &str = "myc_admin_null_forbidden";

fn strict_json(bytes: &[u8]) -> Result<Value, MycAdminDocumentError> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = StrictValueSeed
        .deserialize(&mut deserializer)
        .map_err(|error| {
            let message = error.to_string();
            if message.contains(DUPLICATE_MARKER) {
                MycAdminDocumentError::new(MycAdminDocumentErrorKind::DuplicateField)
            } else if message.contains(NULL_MARKER) {
                MycAdminDocumentError::new(MycAdminDocumentErrorKind::NullForbidden)
            } else {
                MycAdminDocumentError::new(MycAdminDocumentErrorKind::Malformed)
            }
        })?;
    deserializer
        .end()
        .map_err(|_| MycAdminDocumentError::new(MycAdminDocumentErrorKind::Malformed))?;
    Ok(value)
}

struct StrictValueSeed;

impl<'de> DeserializeSeed<'de> for StrictValueSeed {
    type Value = Value;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictValueVisitor)
    }
}

struct StrictValueVisitor;

impl<'de> Visitor<'de> for StrictValueVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a non-null JSON value")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(Value::from(value))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(Value::from(value))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        serde_json::Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("invalid JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(Value::String(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(Value::String(value))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Err(E::custom(NULL_MARKER))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Err(E::custom(NULL_MARKER))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(StrictValueSeed)? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A>(self, mut object: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = Map::new();
        while let Some(key) = object.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(de::Error::custom(DUPLICATE_MARKER));
            }
            let value = object.next_value_seed(StrictValueSeed)?;
            values.insert(key, value);
        }
        Ok(Value::Object(values))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_model(model_name: &str) -> Value {
        let fields = model_fields(model_name).expect("governed model");
        let mut object = Map::new();
        for (name, field) in fields {
            if field.get("presence").and_then(Value::as_str) == Some("required") {
                let type_name = field
                    .get("type")
                    .and_then(Value::as_str)
                    .expect("field type");
                object.insert(name.clone(), sample_type(type_name).expect("required type"));
            }
        }
        Value::Object(object)
    }

    fn sample_type(type_name: &str) -> Option<Value> {
        let descriptor = type_descriptor(type_name).expect("governed type");
        match descriptor
            .get("kind")
            .and_then(Value::as_str)
            .expect("type kind")
        {
            "literal" => Some(descriptor.get("value").expect("literal value").clone()),
            "boolean" => Some(Value::Bool(false)),
            "integer" => Some(Value::from(
                descriptor
                    .get("minimum")
                    .and_then(Value::as_u64)
                    .unwrap_or(0),
            )),
            "string" => {
                let value = if descriptor.get("encoding").is_some() {
                    "AA".to_owned()
                } else if descriptor.get("allowed_schemes").is_some() {
                    "https://example.test/".to_owned()
                } else if descriptor.get("pattern").and_then(Value::as_str) == Some("^/") {
                    "/tmp/myc".to_owned()
                } else if let Some(length) = descriptor.get("utf8_bytes").and_then(Value::as_u64) {
                    "0".repeat(usize::try_from(length).expect("bounded sample length"))
                } else {
                    "x".to_owned()
                };
                Some(Value::String(value))
            }
            "enum" => descriptor
                .get("values")
                .and_then(Value::as_array)
                .and_then(|values| values.first())
                .cloned(),
            "string_union" => descriptor
                .get("simple_values")
                .and_then(Value::as_array)
                .and_then(|values| values.first())
                .cloned(),
            "array" => Some(Value::Array(Vec::new())),
            "canonical_delimited_set" => Some(Value::String(String::new())),
            "map" | "canonical_json_object" => Some(Value::Object(Map::new())),
            "closed_object" => {
                let mut object = Map::new();
                for (field, field_type) in descriptor
                    .get("fields")
                    .and_then(Value::as_object)
                    .expect("closed fields")
                {
                    if let Some(value) = sample_type(field_type.as_str().expect("closed type")) {
                        object.insert(field.clone(), value);
                    }
                }
                Some(Value::Object(object))
            }
            "tagged_union" => descriptor
                .get("variants")
                .and_then(Value::as_array)
                .and_then(|variants| variants.first())
                .and_then(Value::as_str)
                .and_then(sample_type),
            "alias" => descriptor
                .get("target")
                .and_then(Value::as_str)
                .and_then(sample_type),
            "optional" => None,
            kind => panic!("unsupported governed kind {kind}"),
        }
    }

    fn response_document(route: MycAdminRoute) -> MycAdminResponseDocument {
        let value = sample_model(route.response_model());
        validate_model(route.response_model(), &value).expect("generated response model");
        let bytes = serde_json::to_vec(&value).expect("canonical response bytes");
        MycAdminResponseDocument::from_canonical_bytes(route, &bytes)
            .expect("admitted response document")
    }

    #[test]
    fn complete_route_and_model_inventory_matches_the_machine_contract() {
        assert!(operator_route_inventory_is_exact());
        assert_eq!(MycAdminRoute::ALL.len(), 21);
        let referenced = MycAdminRoute::ALL
            .into_iter()
            .flat_map(|route| [route.request_model(), route.response_model()])
            .collect::<BTreeSet<_>>();
        let governed = operator_contract()["admin"]["models"]
            .as_object()
            .expect("model inventory")
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        assert_eq!(referenced, governed);
        assert_eq!(governed.len(), 35);
        for model in governed {
            let value = sample_model(model);
            validate_model(model, &value).expect("minimum exact model");
        }
    }

    #[test]
    fn strict_response_admission_rejects_duplicates_null_and_noncanonical_bytes() {
        let route = MycAdminRoute::IdentityPublic;
        let valid = response_document(route);
        assert_eq!(valid.route(), route);
        assert!(!valid.canonical_bytes().is_empty());

        let duplicate = br#"{"generation":0,"generation":1,"public_key":"0000000000000000000000000000000000000000000000000000000000000000","role":"transport"}"#;
        assert_eq!(
            MycAdminResponseDocument::from_canonical_bytes(route, duplicate)
                .expect_err("duplicate key")
                .kind(),
            MycAdminDocumentErrorKind::DuplicateField
        );
        let nested_null = br#"{"generation":0,"public_key":null,"role":"transport"}"#;
        assert_eq!(
            MycAdminResponseDocument::from_canonical_bytes(route, nested_null)
                .expect_err("nested null")
                .kind(),
            MycAdminDocumentErrorKind::NullForbidden
        );
        let noncanonical = format!(" {}", String::from_utf8_lossy(valid.canonical_bytes()));
        assert_eq!(
            MycAdminResponseDocument::from_canonical_bytes(route, noncanonical.as_bytes())
                .expect_err("whitespace")
                .kind(),
            MycAdminDocumentErrorKind::NonCanonical
        );
        let invalid = br#"{"generation":0,"public_key":"0000000000000000000000000000000000000000000000000000000000000000","role":"administrator"}"#;
        assert_eq!(
            MycAdminResponseDocument::from_canonical_bytes(route, invalid)
                .expect_err("invalid model")
                .kind(),
            MycAdminDocumentErrorKind::InvalidModel
        );
        assert_eq!(
            MycAdminResponseDocument::from_canonical_bytes(route, b"")
                .expect_err("empty response")
                .kind(),
            MycAdminDocumentErrorKind::Malformed
        );
        let oversized = vec![b' '; MYC_ADMIN_RESPONSE_BODY_MAX_UTF8_BYTES + 1];
        assert_eq!(
            MycAdminResponseDocument::from_canonical_bytes(route, &oversized)
                .expect_err("oversized response")
                .kind(),
            MycAdminDocumentErrorKind::TooLarge
        );
        assert_eq!(
            format!("{valid:?}"),
            "MycAdminResponseDocument { route: IdentityPublic, model: \"[redacted]\" }"
        );
    }

    #[test]
    fn query_and_nested_type_admission_is_exact_and_bounded() {
        let connections = query_model(
            MycAdminRoute::ConnectionsList,
            Some("cursor=AA&limit=200&state=approved"),
        )
        .expect("canonical query");
        validate_model("connections_query_v1", &connections).expect("query model");
        for invalid in [
            "limit=01",
            "limit=201",
            "limit=1&limit=2",
            "unknown=x",
            "cursor=%",
            "state=administrator",
        ] {
            let result = query_model(MycAdminRoute::ConnectionsList, Some(invalid))
                .and_then(|value| validate_model("connections_query_v1", &value));
            assert!(result.is_err(), "query `{invalid}` unexpectedly passed");
        }
        for valid in [
            "",
            "nip04_decrypt",
            "sign_event:kind:0",
            "nip04_decrypt,sign_event:kind:1",
        ] {
            validate_type("permission_set", &Value::String(valid.to_owned()), 0)
                .expect("permission set");
        }
        for invalid in [
            "sign_event:kind:00",
            "sign_event:kind:4294967296",
            "sign_event:kind:1,nip04_decrypt",
            "nip04_decrypt,nip04_decrypt",
        ] {
            assert!(
                validate_type("permission_set", &Value::String(invalid.to_owned()), 0).is_err()
            );
        }
        assert!(
            validate_type(
                "safe_url",
                &Value::String("http://example.test/".to_owned()),
                0
            )
            .is_err()
        );
        assert!(validate_type("bounded_id", &Value::String("../escape".to_owned()), 0).is_err());
    }

    #[test]
    fn public_diagnostics_are_source_free_and_content_free() {
        let document = MycAdminDocumentError::new(MycAdminDocumentErrorKind::InvalidModel);
        let handler = MycAdminHandlerError::new(MycAdminHandlerErrorKind::Internal);
        for rendered in [
            format!("{document}"),
            format!("{document:?}"),
            format!("{handler}"),
            format!("{handler:?}"),
        ] {
            assert!(!rendered.contains("/tmp/protected"));
            assert!(!rendered.contains("credential"));
        }
        assert!(Error::source(&document).is_none());
        assert!(Error::source(&handler).is_none());
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    mod native {
        use core::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Mutex;

        use radroots_service_host::{
            AdminClient, AdminClientTarget, AdminServer, AdminTransportLimits, CancellationToken,
            EntropyError, EntropySource, UnixAdminSocketBinding, UnixAdminSocketWriterAuthority,
        };

        use super::*;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        #[derive(Clone, Copy)]
        struct FixedEntropy;

        impl EntropySource for FixedEntropy {
            fn fill_bytes(&self, destination: &mut [u8]) -> Result<(), EntropyError> {
                destination.fill(0x51);
                Ok(())
            }
        }

        type FixtureCall = (MycAdminRoute, Option<String>, Box<[u8]>);

        struct FixtureHandler {
            calls: Mutex<Vec<FixtureCall>>,
            invalid_cursor: AtomicUsize,
            decoded_parameter: AtomicUsize,
        }

        impl FixtureHandler {
            fn new() -> Self {
                Self {
                    calls: Mutex::new(Vec::new()),
                    invalid_cursor: AtomicUsize::new(0),
                    decoded_parameter: AtomicUsize::new(0),
                }
            }
        }

        impl MycAdminHandler for FixtureHandler {
            fn handle<'a>(&'a self, request: MycAdminRequestDocument) -> MycAdminFuture<'a> {
                Box::pin(async move {
                    if request.route() == MycAdminRoute::ConnectionsList
                        && request
                            .model_bytes()
                            .windows(4)
                            .any(|window| window == b"\"eA\"")
                    {
                        self.invalid_cursor.fetch_add(1, Ordering::SeqCst);
                        return Err(MycAdminHandlerError::new(
                            MycAdminHandlerErrorKind::InvalidCursor,
                        ));
                    }
                    if request.operation_id() == Some("conflict") {
                        return Err(MycAdminHandlerError::new(
                            MycAdminHandlerErrorKind::OperationIdConflict,
                        ));
                    }
                    if request.parameter("connection_id") == Some("connection-encoded") {
                        self.decoded_parameter.fetch_add(1, Ordering::SeqCst);
                        return Ok(response_document(request.route()));
                    }
                    self.calls.lock().expect("calls").push((
                        request.route(),
                        request.operation_id().map(str::to_owned),
                        request.model_bytes().into(),
                    ));
                    Ok(response_document(request.route()))
                })
            }
        }

        fn runtime_directory() -> tempfile::TempDir {
            tempfile::Builder::new()
                .prefix("myc-admin-")
                .tempdir_in("/tmp")
                .expect("short runtime directory")
        }

        fn target_for(route: MycAdminRoute, request: &Value) -> AdminClientTarget {
            let path = route
                .path()
                .replace("{connection_id}", "connection-1")
                .replace("{challenge_id}", "challenge-1");
            if !matches!(route.method(), MycAdminMethod::Get)
                || request.as_object().is_some_and(Map::is_empty)
            {
                return AdminClientTarget::new(path).expect("route target");
            }
            let mut serializer = url::form_urlencoded::Serializer::new(String::new());
            for (name, value) in request.as_object().expect("query object") {
                let rendered = value
                    .as_str()
                    .map(str::to_owned)
                    .unwrap_or_else(|| value.to_string());
                serializer.append_pair(name, &rendered);
            }
            AdminClientTarget::new(format!("{path}?{}", serializer.finish())).expect("query target")
        }

        async fn raw_post(socket: &Path, body: &str) -> String {
            let mut stream = tokio::net::UnixStream::connect(socket)
                .await
                .expect("raw connection");
            let request = format!(
                "POST /v1/discovery/render HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream
                .write_all(request.as_bytes())
                .await
                .expect("raw request");
            let mut response = Vec::new();
            stream
                .read_to_end(&mut response)
                .await
                .expect("raw response");
            String::from_utf8(response).expect("HTTP response")
        }

        #[tokio::test]
        async fn all_twenty_one_routes_round_trip_over_the_hardened_unix_boundary() {
            let directory = runtime_directory();
            let socket = directory.path().join("admin.sock");
            let authority = UnixAdminSocketWriterAuthority::acquire(directory.path())
                .expect("writer authority");
            let binding = UnixAdminSocketBinding::bind(authority, &socket)
                .await
                .expect("socket binding");
            let handler = Arc::new(FixtureHandler::new());
            let MycAdminRouter { inner } =
                build_myc_admin_router(Arc::clone(&handler)).expect("exact router");
            let server = AdminServer::new(inner, AdminTransportLimits::DEFAULT, FixedEntropy)
                .expect("admin server");
            let cancellation = CancellationToken::new();
            let server_cancellation = cancellation.clone();
            let task = tokio::spawn(async move {
                server
                    .serve(binding, server_cancellation)
                    .await
                    .expect("serve Myc admin");
            });
            let client =
                AdminClient::new(&socket, AdminTransportLimits::DEFAULT).expect("admin client");

            for (index, route) in MycAdminRoute::ALL.into_iter().enumerate() {
                let request = sample_model(route.request_model());
                let target = target_for(route, &request);
                let response = match route.method() {
                    MycAdminMethod::Get => client.get::<Value>(&target).await.expect("GET route"),
                    MycAdminMethod::Post => {
                        let operation_id = AdminOperationId::new(format!("operation-{index}"))
                            .expect("operation ID");
                        client
                            .mutate::<_, Value>(&target, operation_id, None, &request)
                            .await
                            .expect("POST route")
                    }
                };
                validate_model(route.response_model(), response.result())
                    .expect("route response model");
            }

            let cursor_target =
                AdminClientTarget::new("/v1/connections?cursor=eA&limit=1").expect("cursor target");
            let cursor_error = client
                .get::<Value>(&cursor_target)
                .await
                .expect_err("handler rejects unbound cursor");
            assert_eq!(
                cursor_error
                    .failure()
                    .expect("failure envelope")
                    .error()
                    .code()
                    .as_str(),
                "invalid_cursor"
            );
            assert_eq!(handler.invalid_cursor.load(Ordering::SeqCst), 1);

            let conflict_target =
                AdminClientTarget::new("/v1/discovery/render").expect("mutation target");
            let conflict_error = client
                .mutate::<_, Value>(
                    &conflict_target,
                    AdminOperationId::new("conflict").expect("operation ID"),
                    None,
                    sample_model("discovery_render_request_v1"),
                )
                .await
                .expect_err("operation conflict");
            assert_eq!(
                conflict_error
                    .failure()
                    .expect("failure envelope")
                    .error()
                    .code()
                    .as_str(),
                "operation_id_conflict"
            );

            for body in [
                r#"{"contract_version":1,"operation_id":"duplicate","request":{"expected_generation":0,"expected_generation":1}}"#,
                r#"{"contract_version":1,"operation_id":"null","request":{"expected_generation":null}}"#,
            ] {
                let response = raw_post(&socket, body).await;
                assert!(response.starts_with("HTTP/1.1 400 "), "{response}");
            }

            let encoded_target =
                AdminClientTarget::new("/v1/connections/connection%2Dencoded/approve")
                    .expect("encoded parameter target");
            client
                .mutate::<_, Value>(
                    &encoded_target,
                    AdminOperationId::new("encoded-parameter").expect("operation ID"),
                    None,
                    sample_model("connection_approve_request_v1"),
                )
                .await
                .expect("percent-decoded path parameter");
            assert_eq!(handler.decoded_parameter.load(Ordering::SeqCst), 1);

            {
                let calls = handler.calls.lock().expect("calls");
                assert_eq!(calls.len(), 21);
                for (index, (route, operation_id, request)) in calls.iter().enumerate() {
                    assert_eq!(*route, MycAdminRoute::ALL[index]);
                    assert_eq!(operation_id.is_some(), route.is_mutation());
                    validate_model(
                        route.request_model(),
                        &serde_json::from_slice(request).expect("retained request model"),
                    )
                    .expect("retained exact model");
                }
            }
            cancellation.cancel();
            task.await.expect("server task");
        }
    }
}
