//! Myc-owned adapter for the exact passive TCP operations surface.

use core::{fmt, time::Duration};
use std::{error::Error, net::SocketAddr};

use radroots_service_host::{
    BoundOperationsServer as HostBoundOperationsServer, CancellationToken as HostCancellationToken,
    OperationsBindPolicy as HostOperationsBindPolicy,
    OperationsListenAddress as HostOperationsListenAddress,
    OperationsListenerConfig as HostOperationsListenerConfig,
    OperationsServer as HostOperationsServer, OperationsServerError as HostOperationsServerError,
    OperationsTransportLimitValues as HostOperationsTransportLimitValues,
    OperationsTransportLimits as HostOperationsTransportLimits,
};
use serde_json::Value;

use crate::{MycConfigDocumentV1, MycStatusReader};

/// Exact Myc TCP operations contract version.
pub const MYC_OPERATIONS_CONTRACT_VERSION: u32 = 1;

/// Exact liveness route exposed by the optional TCP listener.
pub const MYC_LIVEZ_PATH: &str = "/livez";

/// Exact readiness route exposed by the optional TCP listener.
pub const MYC_READYZ_PATH: &str = "/readyz";

/// Exact bounded metrics route exposed by the optional TCP listener.
pub const MYC_METRICS_PATH: &str = "/metrics";

/// Cloneable cooperative cancellation owned by the Myc runtime supervisor.
#[derive(Clone, Default)]
pub struct MycOperationsCancellationToken {
    inner: HostCancellationToken,
}

impl MycOperationsCancellationToken {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Requests cancellation. Repeated requests have no additional effect.
    pub fn cancel(&self) {
        self.inner.cancel();
    }

    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.inner.is_cancelled()
    }
}

impl fmt::Debug for MycOperationsCancellationToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MycOperationsCancellationToken")
            .field("cancelled", &self.is_cancelled())
            .finish()
    }
}

/// Unbound exact-route Myc TCP operations server.
pub struct MycOperationsServer {
    inner: HostOperationsServer,
}

impl MycOperationsServer {
    /// Projects the already-validated Myc configuration and passive status cache.
    pub fn new(
        config: &MycConfigDocumentV1,
        status: &MycStatusReader,
    ) -> Result<Self, MycOperationsError> {
        let listener = listener_config(config)?;
        HostOperationsServer::new(listener, status.operations_cache())
            .map(|inner| Self { inner })
            .map_err(map_server_error)
    }

    /// Binds the exact configured address without starting admission.
    pub async fn bind(self) -> Result<MycBoundOperationsServer, MycOperationsError> {
        self.inner
            .bind()
            .await
            .map(|inner| MycBoundOperationsServer { inner })
            .map_err(map_server_error)
    }
}

impl fmt::Debug for MycOperationsServer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MycOperationsServer([sealed])")
    }
}

/// Successfully bound exact-route Myc TCP operations server.
pub struct MycBoundOperationsServer {
    inner: HostBoundOperationsServer,
}

impl MycBoundOperationsServer {
    #[must_use]
    pub fn local_address(&self) -> SocketAddr {
        self.inner.local_address()
    }

    /// Serves until explicit supervisor cancellation, then drains owned work.
    pub async fn serve(
        self,
        cancellation: MycOperationsCancellationToken,
    ) -> Result<(), MycOperationsError> {
        self.inner
            .serve(cancellation.inner)
            .await
            .map_err(map_server_error)
    }
}

impl fmt::Debug for MycBoundOperationsServer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MycBoundOperationsServer([sealed])")
    }
}

/// Stable source-free Myc operations failure classification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MycOperationsErrorKind {
    Disabled,
    InvalidConfiguration,
    Bind,
    LocalAddress,
    Accept,
    ConnectionTaskPanicked,
}

impl MycOperationsErrorKind {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Disabled => "operations_disabled",
            Self::InvalidConfiguration => "operations_configuration_invalid",
            Self::Bind => "operations_bind_failed",
            Self::LocalAddress => "operations_local_address_failed",
            Self::Accept => "operations_accept_failed",
            Self::ConnectionTaskPanicked => "operations_connection_task_panicked",
        }
    }
}

/// One redacted source-free Myc operations failure.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MycOperationsError {
    kind: MycOperationsErrorKind,
}

impl MycOperationsError {
    const fn new(kind: MycOperationsErrorKind) -> Self {
        Self { kind }
    }

    #[must_use]
    pub const fn kind(self) -> MycOperationsErrorKind {
        self.kind
    }

    #[must_use]
    pub const fn code(self) -> &'static str {
        self.kind.code()
    }
}

impl fmt::Debug for MycOperationsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MycOperationsError")
            .field("kind", &self.kind)
            .finish()
    }
}

impl fmt::Display for MycOperationsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Myc TCP operations failed")
    }
}

impl Error for MycOperationsError {}

fn listener_config(
    config: &MycConfigDocumentV1,
) -> Result<HostOperationsListenerConfig, MycOperationsError> {
    let operations = config
        .normalized()
        .pointer("/operations")
        .ok_or_else(invalid_configuration)?;
    if !boolean(operations, "/enabled")? {
        return Err(MycOperationsError::new(MycOperationsErrorKind::Disabled));
    }
    let listen = string(operations, "/listen")?
        .parse::<SocketAddr>()
        .map_err(|_| invalid_configuration())?;
    let listen = HostOperationsListenAddress::new(listen).map_err(|_| invalid_configuration())?;
    let bind_policy = match string(operations, "/bind_policy")? {
        "loopback_only" => HostOperationsBindPolicy::LoopbackOnly,
        "public" => HostOperationsBindPolicy::Public,
        _ => return Err(invalid_configuration()),
    };
    let values = HostOperationsTransportLimitValues {
        header_count: unsigned_u32(operations, "/limits/header_count")?,
        header_bytes: unsigned_u32(operations, "/limits/header_bytes")?,
        response_body_utf8_bytes: unsigned_u32(operations, "/limits/response_body_utf8_bytes")?,
        concurrent_connections: unsigned_u32(operations, "/limits/concurrent_connections")?,
        request_deadline: Duration::from_millis(unsigned(
            operations,
            "/limits/request_deadline_ms",
        )?),
        idle_timeout: Duration::from_millis(unsigned(operations, "/limits/idle_timeout_ms")?),
    };
    let limits = HostOperationsTransportLimits::new(values).map_err(|_| invalid_configuration())?;
    HostOperationsListenerConfig::enabled(listen, bind_policy, limits)
        .map_err(|_| invalid_configuration())
}

fn boolean(value: &Value, pointer: &str) -> Result<bool, MycOperationsError> {
    value
        .pointer(pointer)
        .and_then(Value::as_bool)
        .ok_or_else(invalid_configuration)
}

fn string<'a>(value: &'a Value, pointer: &str) -> Result<&'a str, MycOperationsError> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .ok_or_else(invalid_configuration)
}

fn unsigned(value: &Value, pointer: &str) -> Result<u64, MycOperationsError> {
    value
        .pointer(pointer)
        .and_then(Value::as_u64)
        .ok_or_else(invalid_configuration)
}

fn unsigned_u32(value: &Value, pointer: &str) -> Result<u32, MycOperationsError> {
    u32::try_from(unsigned(value, pointer)?).map_err(|_| invalid_configuration())
}

const fn invalid_configuration() -> MycOperationsError {
    MycOperationsError::new(MycOperationsErrorKind::InvalidConfiguration)
}

const fn map_server_error(error: HostOperationsServerError) -> MycOperationsError {
    let kind = match error {
        HostOperationsServerError::Disabled => MycOperationsErrorKind::Disabled,
        HostOperationsServerError::HeaderLimitBelowParserFloor => {
            MycOperationsErrorKind::InvalidConfiguration
        }
        HostOperationsServerError::Bind { .. } => MycOperationsErrorKind::Bind,
        HostOperationsServerError::LocalAddress { .. } => MycOperationsErrorKind::LocalAddress,
        HostOperationsServerError::Accept { .. } => MycOperationsErrorKind::Accept,
        HostOperationsServerError::ConnectionTaskPanicked => {
            MycOperationsErrorKind::ConnectionTaskPanicked
        }
    };
    MycOperationsError::new(kind)
}
