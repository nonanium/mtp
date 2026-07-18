use crate::{ConnectionHandle, Policy, Receiver, Sender};
use mtp_common::CommunicationError;
use rustls::pki_types::{PrivateKeyDer, pem::PemObject};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;
use tracing::debug;
use wtransport::{Connection as WTConnection, Endpoint, ServerConfig};

fn generate_self_signed_cert() -> Result<(Vec<u8>, Vec<u8>), CommunicationError> {
    let key_pair = rcgen::KeyPair::generate().map_err(|e| {
        CommunicationError::Other(format!("failed to generate self-signed key pair: {e}"))
    })?;
    let params = rcgen::CertificateParams::new(vec!["localhost".into(), "127.0.0.1".into()])
        .map_err(|e| {
            CommunicationError::Other(format!(
                "failed to build self-signed certificate params: {e}"
            ))
        })?;
    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| CommunicationError::Other(format!("failed to self-sign certificate: {e}")))?;
    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();
    Ok((cert_pem.into_bytes(), key_pem.into_bytes()))
}

enum HostCredentials {
    Pem { cert_pem: Vec<u8>, key_pem: Vec<u8> },
    SelfSigned,
}

/// TLS and transport settings for a native host.
pub struct HostConfig {
    credentials: HostCredentials,
    policy: Policy,
}

impl HostConfig {
    pub fn new(cert_pem: Vec<u8>, key_pem: Vec<u8>, policy: Policy) -> Self {
        Self {
            credentials: HostCredentials::Pem { cert_pem, key_pem },
            policy,
        }
    }

    /// Generate a self-signed certificate for local development.
    pub fn self_signed(policy: Policy) -> Self {
        Self {
            credentials: HostCredentials::SelfSigned,
            policy,
        }
    }
}

pub struct Host {
    incoming: tokio::sync::mpsc::Receiver<(Sender, Receiver)>,
    local_addr: std::net::SocketAddr,
    _task: tokio::task::JoinHandle<()>,
}

impl Host {
    pub async fn next(&mut self) -> Option<(Sender, Receiver)> {
        self.incoming.recv().await
    }

    pub fn local_addr(&self) -> std::net::SocketAddr {
        self.local_addr
    }

    /// Stop accepting new connections. Already-accepted connections run on their
    /// own spawned tasks and are not affected.
    pub fn shutdown(&mut self) {
        self._task.abort();
    }
}

impl Drop for Host {
    fn drop(&mut self) {
        // The accept loop runs forever on its own task; dropping the Host
        // JoinHandle would only detach it. Abort it so dropping the Host
        // actually stops accepting new connections. Per-connection handler
        // tasks are spawned independently and keep running.
        self._task.abort();
    }
}

pub async fn host(
    ip: IpAddr,
    port: u16,
    cert_pem: Vec<u8>,
    key_pem: Vec<u8>,
    policy: Policy,
) -> Result<Host, CommunicationError> {
    host_with_config(ip, port, HostConfig::new(cert_pem, key_pem, policy)).await
}

/// Start a host using explicit TLS and transport configuration.
pub async fn host_with_config(
    ip: IpAddr,
    port: u16,
    config: HostConfig,
) -> Result<Host, CommunicationError> {
    mtp_crypto::ensure_crypto_provider();

    let (cert_pem, key_pem) = match config.credentials {
        HostCredentials::Pem { cert_pem, key_pem } => (cert_pem, key_pem),
        HostCredentials::SelfSigned => generate_self_signed_cert()?,
    };

    let server_config = configure_server(ip, port, cert_pem, key_pem, &config.policy).await?;
    let endpoint = Endpoint::server(server_config)
        .map_err(|e| CommunicationError::Other(format!("Endpoint creation failed: {}", e)))?;

    let local_addr = endpoint
        .local_addr()
        .map_err(|e| CommunicationError::Other(e.to_string()))?;

    let (incoming_tx, incoming_rx) = tokio::sync::mpsc::channel(16);

    let policy = Arc::new(config.policy);

    let task = tokio::spawn(async move {
        loop {
            let accept_started = Instant::now();
            let incoming_session = endpoint.accept().await;
            tracing::debug!(elapsed = ?accept_started.elapsed(), "host accept loop: received QUIC connection");

            let session_started = Instant::now();
            let request = match incoming_session.await {
                Ok(req) => req,
                Err(e) => {
                    debug!("incoming WebTransport session failed: {e}");
                    continue;
                }
            };
            tracing::debug!(elapsed = ?session_started.elapsed(), "host accept loop: complete WebTransport handshake");

            let request_accept_started = Instant::now();
            let connection = match request
                .accept_with_headers([("sec-webtransport-http3-draft02", "1")])
                .await
            {
                Ok(conn) => conn,
                Err(e) => {
                    debug!("WebTransport request accept failed: {e}");
                    continue;
                }
            };
            tracing::debug!(elapsed = ?request_accept_started.elapsed(), "host accept loop: accept WebTransport request");

            let incoming_tx = incoming_tx.clone();
            tokio::spawn(handle_connection(connection, incoming_tx, policy.clone()));
        }
    });

    Ok(Host {
        incoming: incoming_rx,
        local_addr,
        _task: task,
    })
}

async fn handle_connection(
    connection: WTConnection,
    tx: tokio::sync::mpsc::Sender<(Sender, Receiver)>,
    policy: Arc<Policy>,
) {
    let setup_started = Instant::now();
    let handle = Arc::new(ConnectionHandle::new());

    let sender = Sender::new(connection.clone(), handle.clone(), policy.clone());
    let receiver = Receiver::new_for_handshake(connection, handle, policy);
    if tx.send((sender, receiver)).await.is_ok() {
        tracing::debug!(elapsed = ?setup_started.elapsed(), "host accept loop: hand connection to authentication");
    }
}

async fn configure_server(
    bind_ip: IpAddr,
    port: u16,
    cert_pem: Vec<u8>,
    key_pem: Vec<u8>,
    policy: &Policy,
) -> Result<ServerConfig, CommunicationError> {
    let cert_chain = rustls::pki_types::CertificateDer::pem_slice_iter(&cert_pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| CommunicationError::CertificateLoadFailed)?;

    let key = PrivateKeyDer::from_pem_slice(&key_pem)
        .map_err(|_| CommunicationError::CertificateParseFailed)?;

    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)
        .map_err(|_| CommunicationError::CertificateLoadFailed)?;

    tls_config.alpn_protocols = vec![b"h3".to_vec()];

    let bind_addr = SocketAddr::new(bind_ip, port);

    let server_config = ServerConfig::builder()
        .with_bind_address(bind_addr)
        .with_custom_tls(tls_config)
        .keep_alive_interval(policy.keep_alive_interval)
        .max_idle_timeout(policy.max_idle_timeout)
        .map_err(|e| CommunicationError::Other(e.to_string()))?
        .build();

    Ok(server_config)
}
