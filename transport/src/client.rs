use std::sync::Arc;

use mtp_common::CommunicationError;
use rustls::{
    ClientConfig as RustlsClientConfig, RootCertStore,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{ServerName, UnixTime, pem::PemObject},
    DigitallySignedStruct, SignatureScheme,
};
use wtransport::{ClientConfig, Endpoint};

use crate::{ConnectionHandle, Policy, Receiver, Sender};

#[derive(Debug)]
struct NoopCertVerifier;

impl ServerCertVerifier for NoopCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA1,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
        ]
    }
}

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

fn client_config_insecure(policy: &Policy) -> Result<ClientConfig, CommunicationError> {
    let mut tls_config = RustlsClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoopCertVerifier))
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

fn configure_client_system_roots(policy: &Policy) -> Result<ClientConfig, CommunicationError> {
    // Check if insecure mode is enabled via env variable MTP_INSECURE
    let insecure = std::env::var("MTP_INSECURE").is_ok();
    if insecure {
        // Insecure mode: skip certificate verification entirely
        return client_config_insecure(policy);
    }
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
