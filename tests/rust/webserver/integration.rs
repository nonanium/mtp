use http::{Method, StatusCode};
use mtp_webserver::{MTPWebServer, WebServerConfig, WebServerError, WebServerMetrics};
use rustls::pki_types::{CertificateDer, ServerName, pem::PemObject};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

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

fn host_config(port: u16, cert: Vec<u8>, key: Vec<u8>) -> mtp_host::HostConfig {
    mtp_host::HostConfig::new(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), port, cert, key)
}

async fn tls_connect(
    addr: SocketAddr,
    cert_pem: &[u8],
    alpn: Vec<Vec<u8>>,
) -> tokio_rustls::client::TlsStream<tokio::net::TcpStream> {
    let certs = CertificateDer::pem_slice_iter(cert_pem)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let mut roots = rustls::RootCertStore::empty();
    for cert in certs {
        roots.add(cert).unwrap();
    }
    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = alpn;
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    connector
        .connect(
            ServerName::try_from("localhost").unwrap().to_owned(),
            tokio::net::TcpStream::connect(addr).await.unwrap(),
        )
        .await
        .unwrap()
}

async fn http1_request(addr: SocketAddr, cert_pem: &[u8], request: &str) -> Vec<u8> {
    let mut stream = tls_connect(addr, cert_pem, vec![b"http/1.1".to_vec()]).await;
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    response
}

#[test]
fn config_builder_defaults() {
    let config = WebServerConfig::new();
    assert_eq!(config.max_request_body, 4 * 1024 * 1024);
    assert_eq!(config.max_connections, 256);
    assert!(config.serve_tcp_https);
    assert_eq!(config.max_tcp_connections, 256);
    assert_eq!(config.tls_handshake_timeout, Duration::from_secs(10));
    assert_eq!(config.request_timeout, Duration::from_secs(30));
}

#[test]
fn config_builder_chain() {
    let config = WebServerConfig::new()
        .max_connections(64)
        .max_tcp_connections(32)
        .tls_handshake_timeout(Duration::from_secs(2))
        .max_request_body(1024)
        .request_timeout(Duration::from_secs(5))
        .mtp_path("/ws");
    assert_eq!(config.max_connections, 64);
    assert_eq!(config.max_tcp_connections, 32);
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

    let err = WebServerError::Transport(mtp_common::CommunicationError::ClosedByPeer);
    assert_eq!(
        err.to_string(),
        "transport error: Connection closed by peer"
    );
}

#[test]
fn error_from_communication_error() {
    let comm_err = mtp_common::CommunicationError::transport(
        mtp_common::TransportPhase::OpenStream,
        "stream opening failed",
    );
    let web_err: WebServerError = comm_err.into();
    assert!(matches!(web_err, WebServerError::Transport(_)));
}

#[test]
fn error_source_chain() {
    let inner = mtp_common::CommunicationError::ClosedByPeer;
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
    let addr = server.local_addr();
    server.shutdown().await;
    assert!(tokio::net::TcpStream::connect(addr).await.is_err());
    assert!(std::net::UdpSocket::bind(addr).is_ok());
}

#[tokio::test]
async fn tcp_and_udp_share_port_zero_assignment() {
    let (cert, key) = generate_self_signed_cert();
    let server = MTPWebServer::new(host_config(0, cert, key), WebServerConfig::new())
        .await
        .unwrap();
    let addr = server.local_addr();
    assert!(addr.port() > 0);
    assert!(tokio::net::TcpStream::connect(addr).await.is_ok());
    assert!(std::net::UdpSocket::bind(addr).is_err());
    server.close().await;
}

#[tokio::test]
async fn tcp_conflict_fails_and_udp_only_does_not_claim_tcp() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (cert, key) = generate_self_signed_cert();
    assert!(
        MTPWebServer::new(host_config(addr.port(), cert, key), WebServerConfig::new())
            .await
            .is_err()
    );
    drop(listener);

    let (cert, key) = generate_self_signed_cert();
    let server = MTPWebServer::new(
        host_config(addr.port(), cert, key),
        WebServerConfig::new().serve_tcp_https(false),
    )
    .await
    .unwrap();
    let tcp = tokio::net::TcpListener::bind(addr).await.unwrap();
    drop(tcp);
    server.close().await;
}

#[tokio::test]
async fn close_and_drop_release_tcp_listener() {
    let (cert, key) = generate_self_signed_cert();
    let server = MTPWebServer::new(host_config(0, cert, key), WebServerConfig::new())
        .await
        .unwrap();
    let addr = server.local_addr();
    server.close().await;
    assert!(tokio::net::TcpListener::bind(addr).await.is_ok());

    let (cert, key) = generate_self_signed_cert();
    let server = MTPWebServer::new(host_config(0, cert, key), WebServerConfig::new())
        .await
        .unwrap();
    let addr = server.local_addr();
    drop(server);
    tokio::task::yield_now().await;
    assert!(tokio::net::TcpListener::bind(addr).await.is_ok());
}

#[tokio::test]
async fn http1_routes_bodies_chunks_and_timeout() {
    let (cert, key) = generate_self_signed_cert();
    let config = WebServerConfig::new()
        .max_request_body(8)
        .request_timeout(Duration::from_millis(20))
        .route_method(Method::POST, "/exact", |request, response| async move {
            response.body(request.body.unwrap()).body("-tail")
        })
        .unwrap()
        .route_pattern("/users/{user}", |request, response, params| async move {
            response.body(format!(
                "{}:{}",
                params["user"],
                request.uri.query().unwrap_or("")
            ))
        })
        .unwrap()
        .route("/slow", |_, response| async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            response
        })
        .unwrap()
        .fallback(|_, response| async move { response.status(StatusCode::IM_A_TEAPOT) })
        .unwrap();
    let server = MTPWebServer::new(host_config(0, cert.clone(), key), config)
        .await
        .unwrap();
    let addr = server.local_addr();

    let response = http1_request(addr, &cert, "POST /exact HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\nConnection: close\r\n\r\ndata").await;
    assert!(String::from_utf8_lossy(&response).ends_with("data-tail"));
    let response = http1_request(
        addr,
        &cert,
        "GET /users/alice%2Dsmith?full=1 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(String::from_utf8_lossy(&response).ends_with("alice-smith:full=1"));
    let response = http1_request(
        addr,
        &cert,
        "GET /exact HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 418"));
    let response = http1_request(addr, &cert, "POST /exact HTTP/1.1\r\nHost: localhost\r\nContent-Length: 9\r\nConnection: close\r\n\r\n123456789").await;
    assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 413"));
    let response = http1_request(
        addr,
        &cert,
        "GET /slow HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 504"));
    server.close().await;
}

#[tokio::test]
async fn tls_negotiates_h2() {
    let (cert, key) = generate_self_signed_cert();
    let config = WebServerConfig::new()
        .route("/h2", |_, response| async move { response.body("over-h2") })
        .unwrap();
    let server = MTPWebServer::new(host_config(0, cert.clone(), key), config)
        .await
        .unwrap();
    let stream = tls_connect(server.local_addr(), &cert, vec![b"h2".to_vec()]).await;
    assert_eq!(stream.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
    let (mut sender, connection) = hyper::client::conn::http2::handshake(
        hyper_util::rt::TokioExecutor::new(),
        hyper_util::rt::TokioIo::new(stream),
    )
    .await
    .unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = http::Request::builder()
        .uri("https://localhost/h2")
        .body(http_body_util::Empty::<bytes::Bytes>::new())
        .unwrap();
    let response = sender.send_request(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = http_body_util::BodyExt::collect(response.into_body())
        .await
        .unwrap()
        .to_bytes();
    assert_eq!(body, "over-h2");
    server.close().await;
}

#[tokio::test]
async fn tcp_metrics_report_completion_and_errors() {
    let (cert, key) = generate_self_signed_cert();
    let metrics = Arc::new(TestMetrics::new());
    let config = WebServerConfig::new()
        .request_timeout(Duration::from_millis(10))
        .with_metrics(metrics.clone())
        .route("/slow", |_, response| async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            response
        })
        .unwrap();
    let server = MTPWebServer::new(host_config(0, cert.clone(), key), config)
        .await
        .unwrap();
    let response = http1_request(
        server.local_addr(),
        &cert,
        "GET /slow HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 504"));
    assert_eq!(metrics.requests_started.load(Ordering::SeqCst), 1);
    assert_eq!(metrics.requests_completed.load(Ordering::SeqCst), 1);
    assert_eq!(metrics.errors.load(Ordering::SeqCst), 1);
    server.close().await;
}

#[tokio::test]
async fn http1_keep_alive_and_streaming_work() {
    let (cert, key) = generate_self_signed_cert();
    let config = WebServerConfig::new()
        .route("/one", |_, response| async move { response.body("one") })
        .unwrap()
        .route("/stream", |_, response| async move {
            let (tx, rx) = tokio::sync::mpsc::channel(1);
            tokio::spawn(async move {
                tx.send(bytes::Bytes::from_static(b"first-")).await.unwrap();
                tokio::time::sleep(Duration::from_millis(10)).await;
                let _ = tx.send(bytes::Bytes::from_static(b"second")).await;
            });
            response.stream(rx)
        })
        .unwrap();
    let server = MTPWebServer::new(host_config(0, cert.clone(), key), config)
        .await
        .unwrap();
    let addr = server.local_addr();
    let mut stream = tls_connect(addr, &cert, vec![b"http/1.1".to_vec()]).await;
    stream.write_all(b"GET /one HTTP/1.1\r\nHost: localhost\r\n\r\nGET /one HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").await.unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    assert_eq!(
        String::from_utf8_lossy(&response)
            .matches("HTTP/1.1 200")
            .count(),
        2
    );

    let response = http1_request(
        addr,
        &cert,
        "GET /stream HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await;
    let response = String::from_utf8_lossy(&response);
    assert!(response.contains("first-"));
    assert!(response.contains("second"));
    assert!(!response.to_ascii_lowercase().contains("content-length:"));
    server.close().await;
}

#[tokio::test]
async fn shutdown_allows_active_request_within_drain_period() {
    let (cert, key) = generate_self_signed_cert();
    let entered = Arc::new(tokio::sync::Notify::new());
    let handler_entered = Arc::clone(&entered);
    let config = WebServerConfig::new()
        .drain_timeout(Duration::from_millis(250))
        .route("/work", move |_, response| {
            let entered = Arc::clone(&handler_entered);
            async move {
                entered.notify_one();
                tokio::time::sleep(Duration::from_millis(30)).await;
                response.body("done")
            }
        })
        .unwrap();
    let server = MTPWebServer::new(host_config(0, cert.clone(), key), config)
        .await
        .unwrap();
    let addr = server.local_addr();
    let request = tokio::spawn(async move {
        http1_request(
            addr,
            &cert,
            "GET /work HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await
    });
    entered.notified().await;
    server.shutdown().await;
    assert!(String::from_utf8_lossy(&request.await.unwrap()).ends_with("done"));
}

#[tokio::test]
async fn shutdown_terminates_request_after_drain_period() {
    let (cert, key) = generate_self_signed_cert();
    let entered = Arc::new(tokio::sync::Notify::new());
    let handler_entered = Arc::clone(&entered);
    let config = WebServerConfig::new()
        .drain_timeout(Duration::from_millis(20))
        .route("/stuck", move |_, response| {
            let entered = Arc::clone(&handler_entered);
            async move {
                entered.notify_one();
                std::future::pending::<()>().await;
                response
            }
        })
        .unwrap();
    let server = MTPWebServer::new(host_config(0, cert.clone(), key), config)
        .await
        .unwrap();
    let addr = server.local_addr();
    let request = tokio::spawn(async move {
        let mut stream = tls_connect(addr, &cert, vec![b"http/1.1".to_vec()]).await;
        stream
            .write_all(b"GET /stuck HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut response = Vec::new();
        let _ = stream.read_to_end(&mut response).await;
        response
    });
    entered.notified().await;
    server.shutdown().await;
    let response = tokio::time::timeout(Duration::from_millis(250), request)
        .await
        .expect("connection task survived drain timeout")
        .unwrap();
    assert!(!String::from_utf8_lossy(&response).contains("HTTP/1.1 200"));
}
