use crate::{
    Http3Request, Http3Response, Router, RouterError, WebMTPConnection, WebServerError,
    transport::accept_web_connection,
};
use bytes::{Buf, Bytes};
use http::{Method, Request, Response, StatusCode};
use mtp_common::CommunicationError;
use mtp_host::HostConfig;
use rustls::pki_types::{PrivateKeyDer, pem::PemObject};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::sync::{Semaphore, watch};

/// Observability hooks for the web server.
///
/// Implement this trait to receive metrics about connections, requests, and
/// errors.  All methods have default no-op implementations so callers only
/// need to override the hooks they care about.
pub trait WebServerMetrics: Send + Sync {
    fn connection_accepted(&self) {}
    fn connection_closed(&self, _duration: Duration, _reason: &str) {}
    fn request_started(&self, _path: &str) {}
    fn request_completed(&self, _path: &str, _status: u16, _duration: Duration) {}
    fn error_occurred(&self, _error: &WebServerError) {}
}

/// Configuration for the HTTP/3 server and MTP routing.
///
/// Use the builder methods to customise behaviour.  All fields have sensible
/// defaults so `WebServerConfig::new()` gives a usable production-ready
/// configuration.
#[derive(Clone)]
pub struct WebServerConfig {
    pub(crate) router: Router,
    pub(crate) mtp_path: String,
    pub max_request_body: usize,
    pub max_connections: usize,
    pub request_timeout: Duration,
    pub drain_timeout: Duration,
    pub(crate) metrics: Option<Arc<dyn WebServerMetrics>>,
}

impl Default for WebServerConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl WebServerConfig {
    pub fn new() -> Self {
        Self {
            router: Router::new(),
            mtp_path: "/".to_string(),
            max_request_body: 4 * 1024 * 1024,
            max_connections: 256,
            request_timeout: Duration::from_secs(30),
            drain_timeout: Duration::from_secs(5),
            metrics: None,
        }
    }

    pub fn route<F, Fut>(mut self, path: impl Into<String>, handler: F) -> Result<Self, RouterError>
    where
        F: Fn(Http3Request, Http3Response) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = Http3Response> + Send + 'static,
    {
        self.router = self.router.route(path, handler)?;
        Ok(self)
    }

    pub fn route_method<F, Fut>(
        mut self,
        method: Method,
        path: impl Into<String>,
        handler: F,
    ) -> Result<Self, RouterError>
    where
        F: Fn(Http3Request, Http3Response) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = Http3Response> + Send + 'static,
    {
        self.router = self.router.route_method(method, path, handler)?;
        Ok(self)
    }

    pub fn fallback<F, Fut>(mut self, handler: F) -> Result<Self, RouterError>
    where
        F: Fn(Http3Request, Http3Response) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = Http3Response> + Send + 'static,
    {
        self.router = self.router.fallback(handler)?;
        Ok(self)
    }

    pub fn mtp_path(mut self, path: impl Into<String>) -> Self {
        self.mtp_path = path.into();
        self
    }

    pub fn max_request_body(mut self, bytes: usize) -> Self {
        self.max_request_body = bytes;
        self
    }

    pub fn max_connections(mut self, max: usize) -> Self {
        self.max_connections = max;
        self
    }

    pub fn request_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;
        self
    }

    pub fn drain_timeout(mut self, timeout: Duration) -> Self {
        self.drain_timeout = timeout;
        self
    }

    pub fn with_metrics(mut self, metrics: Arc<dyn WebServerMetrics>) -> Self {
        self.metrics = Some(metrics);
        self
    }
}

/// An HTTP/3 server bound to MTP's configured address and certificate.
///
/// One task owns the Quinn endpoint and dispatches all HTTP/3 requests.  This
/// is the required ownership model for adding WebTransport MTP sessions on the
/// same UDP socket without competing endpoint accept loops.
pub struct MTPWebServer {
    endpoint: quinn::Endpoint,
    mtp_incoming: tokio::sync::mpsc::Receiver<Result<WebMTPConnection, mtp_host::AcceptError>>,
    shutdown_tx: watch::Sender<()>,
    _driver: Option<tokio::task::JoinHandle<()>>,
}

impl MTPWebServer {
    pub async fn new(
        host_config: HostConfig,
        web_config: WebServerConfig,
    ) -> Result<Self, CommunicationError> {
        let host_config = Arc::new(host_config);
        let endpoint = build_endpoint(&host_config)?;
        let driver_endpoint = endpoint.clone();
        // A completed MTP handshake must never block the endpoint driver just
        // because the application is briefly slow to call `accept()`.
        let (mtp_tx, mtp_incoming) = tokio::sync::mpsc::channel(web_config.max_connections.max(1));
        let (shutdown_tx, shutdown_rx) = watch::channel(());
        let connection_semaphore = Arc::new(Semaphore::new(web_config.max_connections));
        let driver_config = DriverConfig {
            router: web_config.router,
            mtp_path: web_config.mtp_path,
            max_request_body: web_config.max_request_body,
            request_timeout: web_config.request_timeout,
            drain_timeout: web_config.drain_timeout,
            send_pongs: host_config.send_pongs,
            policy: host_config.policy,
            host_config,
            metrics: web_config.metrics,
        };
        let driver = tokio::spawn(run_driver(
            driver_endpoint,
            driver_config,
            mtp_tx,
            connection_semaphore,
            shutdown_rx,
        ));
        Ok(Self {
            endpoint,
            mtp_incoming,
            shutdown_tx,
            _driver: Some(driver),
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.endpoint
            .local_addr()
            .expect("endpoint has a local address")
    }

    pub async fn accept(&mut self) -> Result<Option<WebMTPConnection>, mtp_host::AcceptError> {
        match self.mtp_incoming.recv().await {
            Some(result) => result.map(Some),
            None => Ok(None),
        }
    }

    /// Signal the server to shut down gracefully.
    ///
    /// Stops accepting new QUIC connections, waits for the driver task to
    /// finish its accept loop, then allows a configurable drain period for
    /// in-flight requests to complete before closing the endpoint.
    pub async fn shutdown(mut self) {
        let _ = self.shutdown_tx.send(());
        if let Some(driver) = self._driver.take() {
            let _ = driver.await;
        }
        self.endpoint
            .close(quinn::VarInt::from_u32(0), b"mtp-webserver shutdown");
    }

    /// Stop accepting new QUIC connections and wait briefly for the driver to stop.
    pub async fn close(mut self) {
        self.endpoint
            .close(quinn::VarInt::from_u32(0), b"mtp-webserver shutdown");
        if let Some(driver) = self._driver.take() {
            driver.abort();
        }
    }
}

impl Drop for MTPWebServer {
    fn drop(&mut self) {
        if let Some(driver) = self._driver.take() {
            driver.abort();
        }
    }
}

struct DriverConfig {
    router: Router,
    mtp_path: String,
    max_request_body: usize,
    request_timeout: Duration,
    drain_timeout: Duration,
    send_pongs: bool,
    policy: mtp_transport::Policy,
    host_config: Arc<HostConfig>,
    metrics: Option<Arc<dyn WebServerMetrics>>,
}

fn build_endpoint(config: &HostConfig) -> Result<quinn::Endpoint, CommunicationError> {
    mtp_crypto::ensure_crypto_provider();
    let certificates = rustls::pki_types::CertificateDer::pem_slice_iter(&config.tls_fullchain)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| CommunicationError::CertificateLoadFailed)?;
    let key = PrivateKeyDer::from_pem_slice(&config.tls_key)
        .map_err(|_| CommunicationError::CertificateParseFailed)?;

    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certificates, key)
        .map_err(|_| CommunicationError::CertificateLoadFailed)?;
    tls.alpn_protocols = vec![b"h3".to_vec()];

    let server = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls)
            .map_err(|error| CommunicationError::Other(error.to_string()))?,
    ));
    quinn::Endpoint::server(server, SocketAddr::new(config.ip, config.port))
        .map_err(|error| CommunicationError::Other(error.to_string()))
}

async fn run_driver(
    endpoint: quinn::Endpoint,
    config: DriverConfig,
    mtp_tx: tokio::sync::mpsc::Sender<Result<WebMTPConnection, mtp_host::AcceptError>>,
    connection_semaphore: Arc<Semaphore>,
    mut shutdown_rx: watch::Receiver<()>,
) {
    let DriverConfig {
        router,
        mtp_path,
        max_request_body,
        request_timeout,
        drain_timeout,
        send_pongs,
        policy,
        host_config,
        metrics,
    } = config;
    let mut connection_tasks = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            biased;
            _ = shutdown_rx.changed() => {
                break;
            }
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else {
                    break;
                };
                // Do not await capacity here: doing so would prevent this loop
                // from observing shutdown while all connection slots are in use.
                let permit = match connection_semaphore.clone().try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        tracing::debug!("rejecting QUIC connection at configured connection limit");
                        continue;
                    }
                };
                let router = router.clone();
                let mtp_path = mtp_path.clone();
                let mtp_tx = mtp_tx.clone();
                let metrics = metrics.clone();
                let host_config = host_config.clone();
                connection_tasks.spawn(async move {
                    let _permit = permit;
                    let connect_start = std::time::Instant::now();
                    let connection = match incoming.await {
                        Ok(connection) => connection,
                        Err(error) => {
                            tracing::debug!(%error, "QUIC connection failed during handshake");
                            return;
                        }
                    };
                    let mut builder = h3::server::builder();
                    builder.enable_extended_connect(true);
                    builder.enable_webtransport(true);
                    builder.enable_datagram(true);
                    builder.max_webtransport_sessions(16);
                    let mut h3 = match builder
                        .build(h3_quinn::Connection::new(connection.clone()))
                        .await
                    {
                        Ok(connection) => connection,
                        Err(error) => {
                            tracing::debug!(%error, "HTTP/3 connection setup failed");
                            return;
                        }
                    };

                    if let Some(ref m) = metrics {
                        m.connection_accepted();
                    }

                    let mut tasks = tokio::task::JoinSet::new();
                    loop {
                        let resolver = match h3.accept().await {
                            Ok(Some(resolver)) => resolver,
                            Ok(None) => break,
                            Err(error) => {
                                tracing::debug!(%error, "HTTP/3 request accept failed");
                                break;
                            }
                        };
                        let (request, mut stream) = match resolver.resolve_request().await {
                            Ok(request) => request,
                            Err(error) => {
                                tracing::debug!(%error, "HTTP/3 request parse failed");
                                continue;
                            }
                        };
                        if request.method() == http::Method::CONNECT && request.uri().path() == mtp_path {
                            if request.extensions().get::<h3::ext::Protocol>()
                                != Some(&h3::ext::Protocol::WEB_TRANSPORT)
                            {
                                let _ = stream
                                    .send_response(
                                        Response::builder()
                                            .status(StatusCode::METHOD_NOT_ALLOWED)
                                            .body(())
                                            .unwrap(),
                                    )
                                    .await;
                                let _ = stream.finish().await;
                                continue;
                            }
                            let session = match h3_webtransport::server::WebTransportSession::accept(
                                request, stream, h3,
                            )
                            .await
                            {
                                Ok(session) => Arc::new(session),
                                Err(error) => {
                                    tracing::debug!(%error, "WebTransport session accept failed");
                                    return;
                                }
                            };
                            // The WebTransport session request driver must outlive this
                            // endpoint request task. Keep it detached so handing the MTP
                            // connection to the application does not wait for the session
                            // (which is intentionally an open-ended accept loop).
                            tokio::spawn(run_session_requests(
                                session.clone(),
                                router.clone(),
                                max_request_body,
                                request_timeout,
                                metrics.clone(),
                            ));
                            let result =
                                accept_web_connection(session, mtp_path, connection, send_pongs, policy, host_config.clone())
                                    .await;
                            match mtp_tx.try_send(result) {
                                Ok(()) => {
                                    // The detached session driver remains active while the
                                    // delivered MTP connection keeps the session alive.
                                }
                                Err(tokio::sync::mpsc::error::TrySendError::Full(result)) => {
                                    tracing::warn!("MTP connection backlog is full; dropping connection");
                                    if let Ok(connection) = result {
                                        connection.sender.close();
                                    }
                                }
                                Err(tokio::sync::mpsc::error::TrySendError::Closed(result)) => {
                                    if let Ok(connection) = result {
                                        connection.sender.close();
                                    }
                                }
                            }
                            return;
                        }
                        let router = router.clone();
                        let metrics = metrics.clone();
                        tasks.spawn(async move {
                            let path = request.uri().path().to_string();
                            if let Some(ref m) = metrics {
                                m.request_started(&path);
                            }
                            let req_start = std::time::Instant::now();
                            let (response, status) = match tokio::time::timeout(
                                request_timeout,
                                handle_http_request(request, &mut stream, &router, max_request_body),
                            )
                            .await
                            {
                                Ok(Ok((resp, status))) => (resp, status),
                                Ok(Err(_)) => (
                                    Http3Response::new(StatusCode::BAD_GATEWAY),
                                    StatusCode::BAD_GATEWAY,
                                ),
                                Err(_) => (
                                    Http3Response::new(StatusCode::REQUEST_TIMEOUT),
                                    StatusCode::REQUEST_TIMEOUT,
                                ),
                            };
                            let _ = write_response(&mut stream, response).await;
                            if let Some(ref m) = metrics {
                                m.request_completed(&path, status.as_u16(), req_start.elapsed());
                            }
                        });
                    }
                    tasks.join_all().await;
                    if let Some(ref m) = metrics {
                        m.connection_closed(connect_start.elapsed(), "normal");
                    }
                });
            }
        }
    }

    // --- Drain phase: wait for in-flight connections ---

    endpoint.close(quinn::VarInt::from_u32(0), b"mtp-webserver shutdown");

    let drain_start = std::time::Instant::now();
    while !connection_tasks.is_empty() {
        tokio::select! {
            Some(result) = connection_tasks.join_next() => {
                if let Err(e) = result {
                    tracing::warn!("Connection task panicked: {}", e);
                }
            }
            _ = tokio::time::sleep(drain_timeout.saturating_sub(drain_start.elapsed())) => {
                tracing::warn!(
                    "Drain timeout expired with {} connections still in flight",
                    connection_tasks.len()
                );
                break;
            }
        }
    }

    connection_tasks.shutdown().await;
}

async fn handle_http_request<S>(
    request: Request<()>,
    stream: &mut h3::server::RequestStream<S, Bytes>,
    router: &Router,
    max_request_body: usize,
) -> Result<(Http3Response, StatusCode), WebServerError>
where
    S: h3::quic::BidiStream<Bytes>,
{
    let (request, too_large) = read_request(request, stream, max_request_body)
        .await
        .map_err(|e| WebServerError::Http(format!("request body read failed: {e}")))?;
    if too_large {
        return Ok((
            Http3Response::new(StatusCode::PAYLOAD_TOO_LARGE),
            StatusCode::PAYLOAD_TOO_LARGE,
        ));
    }
    let path = request.uri.path().to_string();
    let handler = router
        .handler(&request.method, &path)
        .or_else(|| router.fallback_handler());
    match handler {
        Some(handler) => {
            let response = handler(request, Http3Response::default()).await;
            let status = response.status;
            Ok((response, status))
        }
        None => Ok((
            Http3Response::new(StatusCode::NOT_FOUND),
            StatusCode::NOT_FOUND,
        )),
    }
}

async fn run_session_requests(
    session: Arc<h3_webtransport::server::WebTransportSession<h3_quinn::Connection, Bytes>>,
    router: Router,
    max_request_body: usize,
    request_timeout: Duration,
    metrics: Option<Arc<dyn WebServerMetrics>>,
) {
    loop {
        match session.accept_bi().await {
            Ok(Some(h3_webtransport::server::AcceptedBi::Request(request, mut stream))) => {
                let router = router.clone();
                let metrics = metrics.clone();
                tokio::spawn(async move {
                    let path = request.uri().path().to_string();
                    if let Some(ref m) = metrics {
                        m.request_started(&path);
                    }
                    let req_start = std::time::Instant::now();
                    let (response, status) = match tokio::time::timeout(
                        request_timeout,
                        handle_http_request(request, &mut stream, &router, max_request_body),
                    )
                    .await
                    {
                        Ok(Ok((resp, status))) => (resp, status),
                        Ok(Err(_)) => (
                            Http3Response::new(StatusCode::BAD_GATEWAY),
                            StatusCode::BAD_GATEWAY,
                        ),
                        Err(_) => (
                            Http3Response::new(StatusCode::REQUEST_TIMEOUT),
                            StatusCode::REQUEST_TIMEOUT,
                        ),
                    };
                    let _ = write_response(&mut stream, response).await;
                    if let Some(ref m) = metrics {
                        m.request_completed(&path, status.as_u16(), req_start.elapsed());
                    }
                });
            }
            Ok(Some(h3_webtransport::server::AcceptedBi::BidiStream(_, _))) => {}
            Ok(None) | Err(_) => break,
        }
    }
}

async fn read_request<S>(
    request: Request<()>,
    stream: &mut h3::server::RequestStream<S, Bytes>,
    max_body: usize,
) -> Result<(Http3Request, bool), h3::error::StreamError>
where
    S: h3::quic::BidiStream<Bytes>,
{
    let (parts, _) = request.into_parts();
    let mut body = Vec::new();
    let mut too_large = false;
    while let Some(chunk) = stream.recv_data().await? {
        if body.len().saturating_add(chunk.remaining()) > max_body {
            too_large = true;
            break;
        }
        body.extend_from_slice(chunk.chunk());
    }
    Ok((
        Http3Request {
            method: parts.method,
            uri: parts.uri,
            headers: parts.headers,
            body: (!body.is_empty()).then(|| Bytes::from(body)),
        },
        too_large,
    ))
}

async fn write_response<S>(
    stream: &mut h3::server::RequestStream<S, Bytes>,
    response: Http3Response,
) -> Result<(), h3::error::StreamError>
where
    S: h3::quic::BidiStream<Bytes>,
{
    let mut builder = Response::builder().status(response.status);
    for (name, value) in &response.headers {
        builder = builder.header(name, value);
    }
    stream
        .send_response(builder.body(()).expect("valid HTTP response"))
        .await?;
    for chunk in response.body {
        stream.send_data(chunk).await?;
    }
    if let Some(mut chunks) = response.stream {
        while let Some(chunk) = chunks.recv().await {
            stream.send_data(chunk).await?;
        }
    }
    stream.finish().await
}
