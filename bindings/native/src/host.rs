use crate::{ConnectionHandle, Policy, Receiver, Sender};
use mtp_common::CommunicationError;
use rustls::pki_types::{PrivateKeyDer, pem::PemObject};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, watch};
use tokio::task::JoinSet;
use tokio::time::{Instant as TokioInstant, timeout_at};
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
    max_transport_handshakes: usize,
    max_pending_connections: usize,
    incoming_queue_capacity: usize,
}

impl HostConfig {
    pub fn new(cert_pem: Vec<u8>, key_pem: Vec<u8>, policy: Policy) -> Self {
        Self {
            credentials: HostCredentials::Pem { cert_pem, key_pem },
            policy,
            max_transport_handshakes: 64,
            max_pending_connections: 64,
            incoming_queue_capacity: 16,
        }
    }

    /// Generate a self-signed certificate for local development.
    pub fn self_signed(policy: Policy) -> Self {
        Self {
            credentials: HostCredentials::SelfSigned,
            policy,
            max_transport_handshakes: 64,
            max_pending_connections: 64,
            incoming_queue_capacity: 16,
        }
    }

    /// Limit concurrent transport handshakes. New sessions are dropped when
    /// this budget is exhausted.
    pub fn with_max_transport_handshakes(mut self, limit: usize) -> Self {
        self.max_transport_handshakes = limit;
        self
    }

    /// Limit accepted sessions waiting to be handed to the application.
    /// New sessions are dropped when this budget is exhausted.
    pub fn with_max_pending_connections(mut self, limit: usize) -> Self {
        self.max_pending_connections = limit;
        self
    }

    pub fn with_incoming_queue_capacity(mut self, capacity: usize) -> Self {
        self.incoming_queue_capacity = capacity;
        self
    }
}

pub struct Host {
    incoming: tokio::sync::mpsc::Receiver<PendingConnection>,
    local_addr: std::net::SocketAddr,
    stop_tx: watch::Sender<bool>,
    task: Option<tokio::task::JoinHandle<()>>,
}

struct PendingConnection {
    sender: Sender,
    receiver: Receiver,
    _permit: OwnedSemaphorePermit,
}

impl Host {
    pub async fn next(&mut self) -> Option<(Sender, Receiver)> {
        self.incoming
            .recv()
            .await
            .map(|connection| (connection.sender, connection.receiver))
    }

    pub fn local_addr(&self) -> std::net::SocketAddr {
        self.local_addr
    }

    /// Stop accepting new connections while retaining ownership of sessions
    /// already admitted to the transport handshake stage.
    pub fn stop_accepting(&self) {
        let _ = self.stop_tx.send(true);
    }

    /// Stop admission and reap every owned transport task by `deadline`.
    /// Tasks still running at the deadline are aborted and reaped before this
    /// method returns.
    pub async fn shutdown(&mut self, deadline: TokioInstant) {
        self.stop_accepting();
        self.incoming.close();
        let Some(mut task) = self.task.take() else {
            self.drain_pending_connections();
            return;
        };
        if timeout_at(deadline, &mut task).await.is_err() {
            task.abort();
            let _ = task.await;
        }
        self.drain_pending_connections();
    }

    fn drain_pending_connections(&mut self) {
        while self.incoming.try_recv().is_ok() {}
    }
}

impl Drop for Host {
    fn drop(&mut self) {
        self.stop_accepting();
        if let Some(task) = self.task.as_ref() {
            task.abort();
        }
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

    let (incoming_tx, incoming_rx) = mpsc::channel(config.incoming_queue_capacity.max(1));

    let policy = Arc::new(config.policy);
    let handshake_limit = Arc::new(Semaphore::new(config.max_transport_handshakes));
    let pending_connection_limit = Arc::new(Semaphore::new(config.max_pending_connections));
    let (stop_tx, mut stop_rx) = watch::channel(false);

    let task = tokio::spawn(async move {
        let mut handshakes = JoinSet::new();
        loop {
            while handshakes.try_join_next().is_some() {}
            if *stop_rx.borrow() {
                break;
            }
            let incoming_session = tokio::select! {
                _ = stop_rx.changed() => break,
                incoming = endpoint.accept() => incoming,
            };
            tracing::debug!("host accept loop: received QUIC connection");

            let Ok(handshake_permit) = handshake_limit.clone().try_acquire_owned() else {
                debug!("dropping incoming session: transport handshake budget exhausted");
                continue;
            };
            let incoming_tx = incoming_tx.clone();
            let policy = Arc::clone(&policy);
            let pending_connection_limit = Arc::clone(&pending_connection_limit);
            let mut task_stop_rx = stop_rx.clone();
            handshakes.spawn(async move {
                tokio::select! {
                    _ = task_stop_rx.changed() => {}
                    _ = async {
                        let session_started = Instant::now();
                        let request = match incoming_session.await {
                            Ok(req) => req,
                            Err(e) => {
                                debug!("incoming WebTransport session failed: {e}");
                                return;
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
                                return;
                            }
                        };
                        tracing::debug!(elapsed = ?request_accept_started.elapsed(), "host accept loop: accept WebTransport request");
                        drop(handshake_permit);
                        handle_connection(connection, incoming_tx, policy, pending_connection_limit).await;
                    } => {}
                }
            });
        }
        while handshakes.join_next().await.is_some() {}
    });

    Ok(Host {
        incoming: incoming_rx,
        local_addr,
        stop_tx,
        task: Some(task),
    })
}

async fn handle_connection(
    connection: WTConnection,
    tx: tokio::sync::mpsc::Sender<PendingConnection>,
    policy: Arc<Policy>,
    pending_connection_limit: Arc<Semaphore>,
) {
    let Ok(permit) = pending_connection_limit.try_acquire_owned() else {
        debug!("dropping accepted connection: pending connection budget exhausted");
        return;
    };
    let setup_started = Instant::now();
    let handle = Arc::new(ConnectionHandle::with_remote_addr(
        connection.quic_connection().remote_address(),
    ));

    let sender = Sender::new(connection.clone(), handle.clone(), policy.clone());
    let receiver = Receiver::new_for_handshake(connection, handle, policy);
    let Ok(reservation) = tx.try_reserve_owned() else {
        debug!("dropping accepted connection: application handoff queue is full");
        return;
    };
    reservation.send(PendingConnection {
        sender,
        receiver,
        _permit: permit,
    });
    {
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
