use http::StatusCode;
use mtp_webserver::{MTPWebServer, WebServerConfig, WebServerError, WebServerMetrics};
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

fn generate_self_signed_cert() -> (Vec<u8>, Vec<u8>) {
    let key_pair = rcgen::KeyPair::generate().expect("failed to generate self-signed key pair");
    let params = rcgen::CertificateParams::new(vec!["localhost".into(), "127.0.0.1".into()])
        .expect("failed to build self-signed certificate params");
    let cert = params
        .self_signed(&key_pair)
        .expect("failed to self-sign certificate");
    (
        cert.pem().into_bytes(),
        key_pair.serialize_pem().into_bytes(),
    )
}

#[test]
fn config_builder_defaults() {
    let config = WebServerConfig::new();
    assert_eq!(config.max_request_body, 4 * 1024 * 1024);
    assert_eq!(config.max_connections, 256);
    assert_eq!(config.request_timeout, Duration::from_secs(30));
}

#[test]
fn config_builder_chain() {
    let config = WebServerConfig::new()
        .max_connections(64)
        .max_request_body(1024)
        .request_timeout(Duration::from_secs(5))
        .mtp_path("/ws");
    assert_eq!(config.max_connections, 64);
    assert_eq!(config.max_request_body, 1024);
    assert_eq!(config.request_timeout, Duration::from_secs(5));
}

#[test]
fn config_builder_routes() {
    let config = WebServerConfig::new()
        .route(
            "/health",
            |_, resp| async move { resp.status(StatusCode::OK) },
        )
        .unwrap()
        .route("/data", |_, resp| async move {
            resp.status(StatusCode::NO_CONTENT)
        })
        .unwrap();
    let config = config.mtp_path("/");
    drop(config);
}

#[test]
fn config_duplicate_route_errors() {
    let result = WebServerConfig::new()
        .route("/dup", |_, resp| async move { resp })
        .unwrap()
        .route("/dup", |_, resp| async move { resp });
    assert!(result.is_err());
}

#[test]
fn error_display() {
    let err = WebServerError::WebTransport("session rejected".into());
    assert_eq!(err.to_string(), "webtransport error: session rejected");

    let err = WebServerError::NotFound("/api".into());
    assert_eq!(err.to_string(), "route not found: /api");

    let err = WebServerError::Http("body too large".into());
    assert_eq!(err.to_string(), "HTTP error: body too large");

    let err = WebServerError::Transport(mtp_common::CommunicationError::StreamClosed);
    assert_eq!(err.to_string(), "transport error: Stream Closed");
}

#[test]
fn error_from_communication_error() {
    let comm_err = mtp_common::CommunicationError::StreamError;
    let web_err: WebServerError = comm_err.into();
    assert!(matches!(web_err, WebServerError::Transport(_)));
}

#[test]
fn error_source_chain() {
    let inner = mtp_common::CommunicationError::StreamClosed;
    let err = WebServerError::Transport(inner);
    let source = std::error::Error::source(&err);
    assert!(source.is_some());
}

struct TestMetrics {
    connections_accepted: AtomicUsize,
    connections_closed: AtomicUsize,
    requests_started: AtomicUsize,
    requests_completed: AtomicUsize,
    errors: AtomicUsize,
}

impl TestMetrics {
    fn new() -> Self {
        Self {
            connections_accepted: AtomicUsize::new(0),
            connections_closed: AtomicUsize::new(0),
            requests_started: AtomicUsize::new(0),
            requests_completed: AtomicUsize::new(0),
            errors: AtomicUsize::new(0),
        }
    }
}

impl WebServerMetrics for TestMetrics {
    fn connection_accepted(&self) {
        self.connections_accepted.fetch_add(1, Ordering::SeqCst);
    }
    fn connection_closed(&self, _duration: Duration, _reason: &str) {
        self.connections_closed.fetch_add(1, Ordering::SeqCst);
    }
    fn request_started(&self, _path: &str) {
        self.requests_started.fetch_add(1, Ordering::SeqCst);
    }
    fn request_completed(&self, _path: &str, _status: u16, _duration: Duration) {
        self.requests_completed.fetch_add(1, Ordering::SeqCst);
    }
    fn error_occurred(&self, _error: &WebServerError) {
        self.errors.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn metrics_trait_defaults_compile() {
    struct NoopMetrics;
    impl WebServerMetrics for NoopMetrics {}
    let m = NoopMetrics;
    m.connection_accepted();
    m.connection_closed(Duration::from_secs(1), "test");
    m.request_started("/test");
    m.request_completed("/test", 200, Duration::from_millis(50));
    m.error_occurred(&WebServerError::NotFound("x".into()));
}

#[test]
fn config_with_metrics() {
    let metrics: Arc<dyn WebServerMetrics> = Arc::new(TestMetrics::new());
    let config = WebServerConfig::new().with_metrics(metrics);
    let metrics: Arc<dyn WebServerMetrics> = Arc::new(TestMetrics::new());
    let config = config.with_metrics(metrics);
    drop(config);
}

#[tokio::test]
async fn server_constructs_with_self_signed_cert() {
    let (cert_pem, key_pem) = generate_self_signed_cert();
    let host_config = mtp_host::HostConfig::new(
        IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        0,
        cert_pem,
        key_pem,
    );
    let web_config = WebServerConfig::new();
    let server = MTPWebServer::new(host_config, web_config).await;
    assert!(server.is_ok());
    let server = server.unwrap();
    let addr = server.local_addr();
    assert!(addr.port() > 0);
    server.close().await;
}

#[tokio::test]
async fn server_with_metrics_constructs() {
    let (cert_pem, key_pem) = generate_self_signed_cert();
    let host_config = mtp_host::HostConfig::new(
        IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        0,
        cert_pem,
        key_pem,
    );
    let metrics: Arc<dyn WebServerMetrics> = Arc::new(TestMetrics::new());
    let web_config = WebServerConfig::new()
        .max_connections(10)
        .request_timeout(Duration::from_secs(10))
        .with_metrics(metrics);
    let server = MTPWebServer::new(host_config, web_config).await;
    assert!(server.is_ok());
    server.unwrap().close().await;
}

#[tokio::test]
async fn graceful_shutdown_completes() {
    let (cert_pem, key_pem) = generate_self_signed_cert();
    let host_config = mtp_host::HostConfig::new(
        IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        0,
        cert_pem,
        key_pem,
    );
    let server = MTPWebServer::new(host_config, WebServerConfig::new())
        .await
        .unwrap();
    server.shutdown().await;
}
