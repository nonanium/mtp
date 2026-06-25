use crate::{ConnectionHandle, Policy, Receiver, Sender};
use log;
use mtp_common::CommunicationError;
use rustls::pki_types::{PrivateKeyDer, pem::PemObject};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use wtransport::{Connection as WTConnection, Endpoint, ServerConfig};

pub struct Host {
    incoming: tokio::sync::mpsc::Receiver<(Sender, Receiver)>,
    local_addr: std::net::SocketAddr,
    _task: tokio::task::JoinHandle<()>,
}

impl Host {
    pub async fn next(&mut self) -> Option<(Sender, Receiver)> {
        log::warn!("[transport Host::next] waiting on recv...");
        let result = self.incoming.recv().await;
        match &result {
            Some(_) => log::warn!("[transport Host::next] received connection"),
            None => log::warn!("[transport Host::next] incoming channel closed - sender dropped"),
        }
        result
    }

    pub fn local_addr(&self) -> std::net::SocketAddr {
        self.local_addr
    }
}

pub async fn host(
    ip: IpAddr,
    port: u16,
    cert_pem: Vec<u8>,
    key_pem: Vec<u8>,
    policy: Policy,
) -> Result<Host, CommunicationError> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let server_config = configure_server(ip, port, cert_pem, key_pem, &policy).await?;
    let endpoint = Endpoint::server(server_config)
        .map_err(|e| CommunicationError::Other(format!("Endpoint creation failed: {}", e)))?;

    let local_addr = endpoint
        .local_addr()
        .map_err(|e| CommunicationError::Other(e.to_string()))?;

    let (incoming_tx, incoming_rx) = tokio::sync::mpsc::channel(16);

    let policy = Arc::new(policy);

    let task = tokio::spawn(async move {
        log::warn!("[transport bg task] started");
        loop {
            log::warn!("[transport bg task] waiting for connection...");
            let incoming_session = endpoint.accept().await;
            log::warn!("[transport bg task] got incoming session");

            let request = match incoming_session.await {
                Ok(req) => {
                    log::warn!("[transport bg task] got request");
                    req
                }
                Err(e) => {
                    log::warn!("[transport bg task] incoming session error: {e}");
                    continue;
                }
            };

            let connection = match request
                .accept_with_headers([("sec-webtransport-http3-draft02", "1")])
                .await
            {
                Ok(conn) => {
                    log::warn!("[transport bg task] connection accepted");
                    conn
                }
                Err(e) => {
                    log::warn!("[transport bg task] accept error: {e}");
                    continue;
                }
            };

            let incoming_tx = incoming_tx.clone();
            let policy = policy.clone();
            eprintln!("[transport bg task] spawning handle_connection");
            tokio::spawn(handle_connection(connection, incoming_tx, policy));
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
    let handle = Arc::new(ConnectionHandle::new());

    let sender = Sender::new(connection.clone(), handle.clone(), policy.clone());
    let receiver = Receiver::new(connection, handle, policy);
    let _ = tx.send((sender, receiver)).await;
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
