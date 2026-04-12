use std::net::{SocketAddr, TcpListener as StdTcpListener};
use std::path::{Path, PathBuf};
use std::time::Duration;

use myc::{MycConfig, MycRuntime, MycTransportDeliveryPolicy};
use radroots_identity::RadrootsIdentity;
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::time::{sleep, timeout};

type TestResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

const HTTP_READY_TIMEOUT: Duration = Duration::from_secs(15);

struct TestRelay {
    url: String,
    shutdown_tx: Option<oneshot::Sender<()>>,
}

impl TestRelay {
    async fn spawn() -> TestResult<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let url = format!("ws://{addr}");
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => break,
                    accept = listener.accept() => {
                        let Ok((stream, _)) = accept else {
                            break;
                        };
                        tokio::spawn(async move {
                            let _ = tokio_tungstenite::accept_async(stream).await;
                        });
                    }
                }
            }
        });

        Ok(Self {
            url,
            shutdown_tx: Some(shutdown_tx),
        })
    }

    fn url(&self) -> &str {
        self.url.as_str()
    }
}

impl Drop for TestRelay {
    fn drop(&mut self) {
        if let Some(shutdown_tx) = self.shutdown_tx.take() {
            let _ = shutdown_tx.send(());
        }
    }
}

struct HangingRelay {
    url: String,
    shutdown_tx: Option<oneshot::Sender<()>>,
}

impl HangingRelay {
    async fn spawn(hold_open_for: Duration) -> TestResult<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let url = format!("ws://{addr}");
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => break,
                    accept = listener.accept() => {
                        let Ok((stream, _)) = accept else {
                            break;
                        };
                        tokio::spawn(async move {
                            sleep(hold_open_for).await;
                            drop(stream);
                        });
                    }
                }
            }
        });

        Ok(Self {
            url,
            shutdown_tx: Some(shutdown_tx),
        })
    }

    fn url(&self) -> &str {
        self.url.as_str()
    }
}

impl Drop for HangingRelay {
    fn drop(&mut self) {
        if let Some(shutdown_tx) = self.shutdown_tx.take() {
            let _ = shutdown_tx.send(());
        }
    }
}

fn write_test_identity(path: &Path, secret_key: &str) {
    let identity = RadrootsIdentity::from_secret_key_str(secret_key).expect("identity from secret");
    myc::identity_files::store_encrypted_identity(path, &identity).expect("write identity");
}

fn free_loopback_addr() -> SocketAddr {
    let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind free loopback addr");
    let addr = listener.local_addr().expect("local addr");
    drop(listener);
    addr
}

fn build_runtime<F>(configure: F) -> (MycRuntime, SocketAddr)
where
    F: FnOnce(&mut MycConfig),
{
    let temp = tempfile::tempdir().expect("tempdir").keep();
    let bind_addr = free_loopback_addr();
    let mut config = MycConfig::default();
    config.paths.state_dir = PathBuf::from(&temp).join("state");
    config.paths.signer_identity_path = PathBuf::from(&temp).join("signer.json");
    config.paths.user_identity_path = PathBuf::from(&temp).join("user.json");
    config.transport.connect_timeout_secs = 1;
    config.observability.enabled = true;
    config.observability.bind_addr = bind_addr;
    write_test_identity(
        &config.paths.signer_identity_path,
        "1111111111111111111111111111111111111111111111111111111111111111",
    );
    write_test_identity(
        &config.paths.user_identity_path,
        "2222222222222222222222222222222222222222222222222222222222222222",
    );
    configure(&mut config);
    (MycRuntime::bootstrap(config).expect("runtime"), bind_addr)
}

async fn spawn_runtime(runtime: MycRuntime) -> oneshot::Sender<()> {
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    tokio::spawn(async move {
        let _ = runtime
            .run_until(async move {
                let _ = shutdown_rx.await;
            })
            .await;
    });
    shutdown_tx
}

async fn wait_for_http(addr: SocketAddr) -> TestResult<()> {
    timeout(HTTP_READY_TIMEOUT, async {
        loop {
            match TcpStream::connect(addr).await {
                Ok(mut stream) => {
                    let _ = stream.shutdown().await;
                    return;
                }
                Err(_) => sleep(Duration::from_millis(50)).await,
            }
        }
    })
    .await?;
    Ok(())
}

struct SimpleHttpResponse {
    status: u16,
    content_type: Option<String>,
    body: String,
}

async fn http_get(addr: SocketAddr, path: &str) -> TestResult<SimpleHttpResponse> {
    let mut stream = TcpStream::connect(addr).await?;
    let request = format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).await?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await?;
    let response = String::from_utf8(response)?;
    let (head, body) = response
        .split_once("\r\n\r\n")
        .ok_or("missing http body separator")?;
    let mut lines = head.lines();
    let status_line = lines.next().ok_or("missing status line")?;
    let status = status_line
        .split_whitespace()
        .nth(1)
        .ok_or("missing status code")?
        .parse::<u16>()?;
    let content_type = lines.find_map(|line| {
        let (key, value) = line.split_once(':')?;
        if key.eq_ignore_ascii_case("content-type") {
            Some(value.trim().to_owned())
        } else {
            None
        }
    });
    Ok(SimpleHttpResponse {
        status,
        content_type,
        body: body.to_owned(),
    })
}

#[tokio::test]
async fn observability_server_reports_unready_when_transport_is_disabled() -> TestResult<()> {
    let (runtime, bind_addr) = build_runtime(|_| {});
    let shutdown_tx = spawn_runtime(runtime).await;
    wait_for_http(bind_addr).await?;

    let health = http_get(bind_addr, "/healthz").await?;
    assert_eq!(health.status, 503);
    assert_eq!(health.body, "unready");

    let ready = http_get(bind_addr, "/readyz").await?;
    assert_eq!(ready.status, 503);
    assert_eq!(ready.body, "unready");

    let status = http_get(bind_addr, "/status").await?;
    assert_eq!(status.status, 200);
    let body: Value = serde_json::from_str(status.body.as_str())?;
    assert_eq!(body["status"], "unready");
    assert_eq!(body["ready"], false);

    let metrics = http_get(bind_addr, "/metrics").await?;
    assert_eq!(metrics.status, 200);
    assert!(
        metrics
            .content_type
            .as_deref()
            .unwrap_or_default()
            .starts_with("text/plain")
    );
    assert!(metrics.body.contains("myc_runtime_operation_total"));

    let _ = shutdown_tx.send(());
    Ok(())
}

#[tokio::test]
async fn observability_server_reports_degraded_but_ready_partial_outage() -> TestResult<()> {
    let relay = TestRelay::spawn().await?;
    let hanging = HangingRelay::spawn(Duration::from_secs(5)).await?;
    let (runtime, bind_addr) = build_runtime(|config| {
        config.transport.enabled = true;
        config.transport.relays = vec![relay.url().to_owned(), hanging.url().to_owned()];
        config.transport.delivery_policy = MycTransportDeliveryPolicy::Any;
    });
    let shutdown_tx = spawn_runtime(runtime).await;
    wait_for_http(bind_addr).await?;

    let health = http_get(bind_addr, "/healthz").await?;
    assert_eq!(health.status, 200);
    assert_eq!(health.body, "degraded");

    let ready = http_get(bind_addr, "/readyz").await?;
    assert_eq!(ready.status, 200);
    assert_eq!(ready.body, "ready");

    let status = http_get(bind_addr, "/status").await?;
    let body: Value = serde_json::from_str(status.body.as_str())?;
    assert_eq!(body["status"], "degraded");
    assert_eq!(body["ready"], true);
    assert_eq!(body["transport"]["available_relay_count"], 1);
    assert_eq!(body["transport"]["unavailable_relay_count"], 1);

    let _ = shutdown_tx.send(());
    Ok(())
}
