use axum::extract::State;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use tokio::net::TcpListener;

use crate::app::MycRuntime;
use crate::error::MycError;

use super::{MycRuntimeStatus, collect_metrics, collect_status_full, render_metrics_text};

#[derive(Clone)]
struct MycObservabilityState {
    runtime: MycRuntime,
}

pub async fn run_observability_server<F>(runtime: MycRuntime, shutdown: F) -> Result<(), MycError>
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    let bind_addr = runtime.config().observability.bind_addr;
    let listener = TcpListener::bind(bind_addr)
        .await
        .map_err(|source| MycError::ObservabilityBind { bind_addr, source })?;
    let state = MycObservabilityState { runtime };
    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/status", get(status))
        .route("/metrics", get(metrics))
        .with_state(state);

    tracing::info!(bind_addr = %bind_addr, "observability server listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await
        .map_err(|source| MycError::ObservabilityServe { bind_addr, source })
}

async fn healthz(State(state): State<MycObservabilityState>) -> Response {
    match collect_status_full(&state.runtime).await {
        Ok(status) => {
            let code = match status.status {
                MycRuntimeStatus::Healthy | MycRuntimeStatus::Degraded => StatusCode::OK,
                MycRuntimeStatus::Unready => StatusCode::SERVICE_UNAVAILABLE,
            };
            (code, status.status.status_label()).into_response()
        }
        Err(error) => internal_error_response(error),
    }
}

async fn readyz(State(state): State<MycObservabilityState>) -> Response {
    match collect_status_full(&state.runtime).await {
        Ok(status) => {
            let code = if status.ready {
                StatusCode::OK
            } else {
                StatusCode::SERVICE_UNAVAILABLE
            };
            let body = if status.ready { "ready" } else { "unready" };
            (code, body).into_response()
        }
        Err(error) => internal_error_response(error),
    }
}

async fn status(State(state): State<MycObservabilityState>) -> Response {
    match collect_status_full(&state.runtime).await {
        Ok(status) => Json(status).into_response(),
        Err(error) => internal_error_response(error),
    }
}

async fn metrics(State(state): State<MycObservabilityState>) -> Response {
    match collect_metrics(&state.runtime) {
        Ok(metrics) => {
            let body = render_metrics_text(&metrics);
            let mut response = body.into_response();
            response.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
            );
            response
        }
        Err(error) => internal_error_response(error),
    }
}

impl super::MycRuntimeStatus {
    fn status_label(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Degraded => "degraded",
            Self::Unready => "unready",
        }
    }
}

fn internal_error_response(error: MycError) -> Response {
    (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response()
}
