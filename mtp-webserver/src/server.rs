use crate::{
    HttpRequest, HttpResponse, Router, RouterError, WebMTPConnection, WebServerError,
    h3::{DriverConfig, run_driver},
    tcp::{TcpDriverConfig, run_driver as run_tcp_driver},
};
use http::Method;
use mtp_common::CommunicationError;
use mtp_host::HostConfig;
use rustls::pki_types::{PrivateKeyDer, pem::PemObject};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    net::TcpListener,
    sync::{Semaphore, watch},
};

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

/// Configuration for the HTTPS/HTTP/3 server and MTP routing.
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
    pub serve_tcp_https: bool,
    pub max_tcp_connections: usize,
    pub tls_handshake_timeout: Duration,
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
            serve_tcp_https: true,
            max_tcp_connections: 256,
            tls_handshake_timeout: Duration::from_secs(10),
            request_timeout: Duration::from_secs(30),
            drain_timeout: Duration::from_secs(5),
            metrics: None,
        }
    }

    pub fn route<F, Fut>(mut self, path: impl Into<String>, handler: F) -> Result<Self, RouterError>
    where
        F: Fn(HttpRequest, HttpResponse) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = HttpResponse> + Send + 'static,
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
        F: Fn(HttpRequest, HttpResponse) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = HttpResponse> + Send + 'static,
    {
        self.router = self.router.route_method(method, path, handler)?;
        Ok(self)
    }

    /// Register a route containing named single-segment parameters, such as
    /// `/api/get/{userid}/profile.json`.
    pub fn route_pattern<F, Fut>(
        mut self,
        pattern: impl Into<String>,
        handler: F,
    ) -> Result<Self, RouterError>
    where
        F: Fn(HttpRequest, HttpResponse, crate::RouteParams) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = HttpResponse> + Send + 'static,
    {
        self.router = self.router.route_pattern(pattern, handler)?;
        Ok(self)
    }

    /// Register a method-specific parameterized route.
    pub fn route_pattern_method<F, Fut>(
        mut self,
        method: Method,
        pattern: impl Into<String>,
        handler: F,
    ) -> Result<Self, RouterError>
    where
        F: Fn(HttpRequest, HttpResponse, crate::RouteParams) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = HttpResponse> + Send + 'static,
    {
        self.router = self.router.route_pattern_method(method, pattern, handler)?;
        Ok(self)
    }

    pub fn fallback<F, Fut>(mut self, handler: F) -> Result<Self, RouterError>
    where
        F: Fn(HttpRequest, HttpResponse) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = HttpResponse> + Send + 'static,
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

    pub fn serve_tcp_https(mut self, enabled: bool) -> Self {
        self.serve_tcp_https = enabled;
        self
    }

    pub fn max_tcp_connections(mut self, max: usize) -> Self {
        self.max_tcp_connections = max;
        self
    }

    pub fn tls_handshake_timeout(mut self, timeout: Duration) -> Self {
        self.tls_handshake_timeout = timeout;
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

/// A combined HTTPS, HTTP/3, and WebTransport server.
///
/// One task owns the Quinn endpoint and dispatches all HTTP/3 requests.  This
/// is the required ownership model for adding WebTransport MTP sessions on the
/// same UDP socket without competing endpoint accept loops.
pub struct MTPWebServer {
    endpoint: quinn::Endpoint,
    mtp_incoming: tokio::sync::mpsc::Receiver<Result<WebMTPConnection, mtp_host::AcceptError>>,
    shutdown_tx: watch::Sender<()>,
    quic_driver: Option<tokio::task::JoinHandle<()>>,
    tcp_driver: Option<tokio::task::JoinHandle<()>>,
    local_addr: SocketAddr,
}

impl MTPWebServer {
    pub async fn new(
        mut host_config: HostConfig,
        web_config: WebServerConfig,
    ) -> Result<Self, CommunicationError> {
        mtp_crypto::ensure_crypto_provider();
        let certificates =
            rustls::pki_types::CertificateDer::pem_slice_iter(&host_config.tls_fullchain)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| CommunicationError::CertificateLoadFailed)?;
        let key = PrivateKeyDer::from_pem_slice(&host_config.tls_key)
            .map_err(|_| CommunicationError::CertificateParseFailed)?;
        let tcp_listener = if web_config.serve_tcp_https {
            let listener = TcpListener::bind(SocketAddr::new(host_config.ip, host_config.port))
                .await
                .map_err(|error| CommunicationError::Other(error.to_string()))?;
            host_config.port = listener
                .local_addr()
                .map_err(|error| CommunicationError::Other(error.to_string()))?
                .port();
            Some(listener)
        } else {
            None
        };
        let tcp_tls = tcp_listener
            .as_ref()
            .map(|_| build_tcp_tls(&certificates, key.clone_key()))
            .transpose()?;
        let endpoint = build_endpoint(&host_config, certificates, key)?;
        let local_addr = endpoint
            .local_addr()
            .map_err(|error| CommunicationError::Other(error.to_string()))?;
        let host_config = Arc::new(host_config);
        let driver_endpoint = endpoint.clone();
        // A completed MTP handshake must never block the endpoint driver just
        // because the application is briefly slow to call `accept()`.
        let (mtp_tx, mtp_incoming) = tokio::sync::mpsc::channel(web_config.max_connections.max(1));
        let (shutdown_tx, shutdown_rx) = watch::channel(());
        let connection_semaphore = Arc::new(Semaphore::new(web_config.max_connections));
        let auth_semaphore = Arc::new(Semaphore::new(web_config.max_connections));
        let router = web_config.router.clone();
        let metrics = web_config.metrics.clone();
        let driver_config = DriverConfig {
            router: web_config.router.clone(),
            mtp_path: web_config.mtp_path.clone(),
            max_request_body: web_config.max_request_body,
            request_timeout: web_config.request_timeout,
            drain_timeout: web_config.drain_timeout,
            send_pongs: host_config.send_pongs,
            policy: host_config.policy,
            host_config,
            metrics: web_config.metrics.clone(),
            auth_semaphore,
        };
        let quic_driver = tokio::spawn(run_driver(
            driver_endpoint,
            driver_config,
            mtp_tx,
            connection_semaphore,
            shutdown_rx.clone(),
        ));
        let tcp_driver = tcp_listener.zip(tcp_tls).map(|(listener, tls)| {
            tokio::spawn(run_tcp_driver(
                listener,
                tls,
                TcpDriverConfig {
                    router,
                    max_request_body: web_config.max_request_body,
                    request_timeout: web_config.request_timeout,
                    tls_handshake_timeout: web_config.tls_handshake_timeout,
                    drain_timeout: web_config.drain_timeout,
                    max_connections: web_config.max_tcp_connections,
                    metrics,
                },
                shutdown_rx,
            ))
        });
        Ok(Self {
            endpoint,
            mtp_incoming,
            shutdown_tx,
            quic_driver: Some(quic_driver),
            tcp_driver,
            local_addr,
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
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
        if let Some(driver) = self.quic_driver.take() {
            let _ = driver.await;
        }
        if let Some(driver) = self.tcp_driver.take() {
            let _ = driver.await;
        }
        self.endpoint
            .close(quinn::VarInt::from_u32(0), b"mtp-webserver shutdown");
    }

    /// Stop accepting new QUIC connections and wait briefly for the driver to stop.
    pub async fn close(mut self) {
        self.endpoint
            .close(quinn::VarInt::from_u32(0), b"mtp-webserver shutdown");
        if let Some(driver) = self.quic_driver.take() {
            driver.abort();
            let _ = driver.await;
        }
        if let Some(driver) = self.tcp_driver.take() {
            driver.abort();
            let _ = driver.await;
        }
    }
}

impl Drop for MTPWebServer {
    fn drop(&mut self) {
        if let Some(driver) = self.quic_driver.take() {
            driver.abort();
        }
        if let Some(driver) = self.tcp_driver.take() {
            driver.abort();
        }
    }
}

fn build_endpoint(
    config: &HostConfig,
    certificates: Vec<rustls::pki_types::CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<quinn::Endpoint, CommunicationError> {
    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certificates, key)
        .map_err(|_| CommunicationError::CertificateLoadFailed)?;
    tls.alpn_protocols = vec![b"h3".to_vec()];

    let mut server = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls)
            .map_err(|error| CommunicationError::Other(error.to_string()))?,
    ));
    // Apply policy keepalive and idle timeout settings to Quinn
    server.transport_config({
        let mut transport = quinn::TransportConfig::default();
        if let Some(keep_alive) = config.policy.keep_alive_interval {
            transport.keep_alive_interval(Some(keep_alive));
        }
        if let Some(idle_timeout) = config.policy.max_idle_timeout {
            transport.max_idle_timeout(Some(
                idle_timeout
                    .try_into()
                    .map_err(|error| CommunicationError::Other(format!("{error}")))?,
            ));
        }
        Arc::new(transport)
    });
    quinn::Endpoint::server(server, SocketAddr::new(config.ip, config.port))
        .map_err(|error| CommunicationError::Other(error.to_string()))
}

fn build_tcp_tls(
    certificates: &[rustls::pki_types::CertificateDer<'static>],
    key: PrivateKeyDer<'static>,
) -> Result<Arc<rustls::ServerConfig>, CommunicationError> {
    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certificates.to_vec(), key)
        .map_err(|_| CommunicationError::CertificateLoadFailed)?;
    tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(tls))
}
