use std::sync::Arc;

use mtp_common::CommunicationError;
use rustls::{ClientConfig as RustlsClientConfig, RootCertStore, pki_types::pem::PemObject};
use wtransport::{ClientConfig, Endpoint};

use crate::{ConnectionHandle, Policy, Receiver, Sender};

pub async fn connect(
    url: &str,
    server_cert: Option<Vec<u8>>,
    policy: Policy,
) -> Result<(Sender, Receiver), CommunicationError> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let client_config = if let Some(cert_pem) = server_cert {
        configure_client_with_cert(cert_pem, &policy)?
    } else {
        configure_client_system_roots(&policy)?
    };

    let endpoint = Endpoint::client(client_config)
        .map_err(|e| CommunicationError::Other(format!("Endpoint creation failed: {}", e)))?;

    let connection = endpoint
        .connect(url)
        .await
        .map_err(|e| CommunicationError::ConnectingError(e.to_string()))?;

    let handle = Arc::new(ConnectionHandle::new());
    let policy = Arc::new(policy);

    let sender = Sender::new(connection.clone(), handle.clone(), policy.clone());
    let receiver = Receiver::new(connection, handle, policy);

    Ok((sender, receiver))
}

fn configure_client_with_cert(
    server_cert: Vec<u8>,
    policy: &Policy,
) -> Result<ClientConfig, CommunicationError> {
    let mut root_store = RootCertStore::empty();

    let certs = rustls::pki_types::CertificateDer::pem_slice_iter(&server_cert)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| CommunicationError::CertificateParseFailed)?;

    for cert in certs {
        root_store
            .add(cert)
            .map_err(|_| CommunicationError::CertificateParseFailed)?;
    }

    client_config_from_roots(root_store, policy)
}

fn configure_client_system_roots(policy: &Policy) -> Result<ClientConfig, CommunicationError> {
    let mut root_store = RootCertStore::empty();

    // Load native certs
    let certs = rustls_native_certs::load_native_certs().certs;

    for cert in certs {
        root_store.add(cert).ok();
    }

    client_config_from_roots(root_store, policy)
}

fn client_config_from_roots(
    root_store: RootCertStore,
    policy: &Policy,
) -> Result<ClientConfig, CommunicationError> {
    let mut tls_config = RustlsClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    tls_config.alpn_protocols = vec![b"h3".to_vec()];

    Ok(ClientConfig::builder()
        .with_bind_default()
        .with_custom_tls(tls_config)
        .keep_alive_interval(policy.keep_alive_interval)
        .max_idle_timeout(policy.max_idle_timeout)
        .map_err(|e| CommunicationError::Other(e.to_string()))?
        .build())
}
