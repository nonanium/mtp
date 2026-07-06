use crate::{ConnectionHandle, Policy, Receiver, Sender};
use mtp_common::CommunicationError;
use rustls::pki_types::{PrivateKeyDer, pem::PemObject};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use wtransport::{Connection as WTConnection, Endpoint, ServerConfig};

fn generate_self_signed_cert() -> (Vec<u8>, Vec<u8>) {
    let key_pair = rcgen::KeyPair::generate().unwrap();
    let params =
        rcgen::CertificateParams::new(vec!["localhost".into(), "127.0.0.1".into()]).unwrap();
    let cert = params.self_signed(&key_pair).unwrap();
    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();
    (cert_pem.into_bytes(), key_pem.into_bytes())
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
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    // When MTP_INSECURE is set, generate a self-signed cert so the host can
    // run without externally-provided TLS credentials.
    let is_insecure = std::env::var("MTP_INSECURE").is_ok();
    let (use_cert_pem, use_key_pem) = if is_insecure {
        generate_self_signed_cert()
    } else {
        (cert_pem, key_pem)
    };

    let server_config = configure_server(ip, port, use_cert_pem, use_key_pem, &policy).await?;
    let endpoint = Endpoint::server(server_config)
        .map_err(|e| CommunicationError::Other(format!("Endpoint creation failed: {}", e)))?;

    let local_addr = endpoint
        .local_addr()
        .map_err(|e| CommunicationError::Other(e.to_string()))?;

    let (incoming_tx, incoming_rx) = tokio::sync::mpsc::channel(16);

    let policy = Arc::new(policy);

    let task = tokio::spawn(async move {
        loop {
            let incoming_session = endpoint.accept().await;

            let request = match incoming_session.await {
                Ok(req) => req,
                Err(e) => {
                    log::debug!("incoming WebTransport session failed: {e}");
                    continue;
                }
            };

            let connection = match request
                .accept_with_headers([("sec-webtransport-http3-draft02", "1")])
                .await
            {
                Ok(conn) => conn,
                Err(e) => {
                    log::debug!("WebTransport request accept failed: {e}");
                    continue;
                }
            };

            let incoming_tx = incoming_tx.clone();
            let policy = policy.clone();
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
