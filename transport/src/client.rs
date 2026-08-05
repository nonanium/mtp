use std::sync::Arc;
use std::time::Instant;

use mtp_common::CommunicationError;
use rustls::{ClientConfig as RustlsClientConfig, RootCertStore, pki_types::pem::PemObject};
use wtransport::{ClientConfig as WTransportClientConfig, Endpoint};

use crate::{ConnectionHandle, Policy, Receiver, Sender};

#[cfg(feature = "insecure-tls")]
mod noop_verifier {
    use rustls::{
        DigitallySignedStruct, SignatureScheme,
        client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        pki_types::{CertificateDer, ServerName, UnixTime},
    };

    #[derive(Debug)]
    pub(super) struct NoopCertVerifier;

    impl ServerCertVerifier for NoopCertVerifier {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
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
}

/// TLS and transport settings for a native client connection.
///
/// Certificate verification uses system roots by default. Disabling verification
/// requires an explicit call to [`Self::with_insecure_certificate_verification`]
/// and the `insecure-tls` compile-time feature.
pub struct ClientConfig {
    server_cert: Option<Vec<u8>>,
    pinned_hash: Option<[u8; 32]>,
    insecure_certificate_verification: bool,
    policy: Policy,
}

impl ClientConfig {
    pub fn new(policy: Policy) -> Self {
        Self {
            server_cert: None,
            pinned_hash: None,
            insecure_certificate_verification: false,
            policy,
        }
    }

    pub fn with_server_certificate(mut self, cert_pem: Vec<u8>) -> Self {
        self.server_cert = Some(cert_pem);
        self.insecure_certificate_verification = false;
        self.pinned_hash = None;
        self
    }

    /// Pin the connection to a specific SPKI SHA-256 hash.
    ///
    /// The client will only accept server certificates whose DER-encoded Subject
    /// Public Key Info matches the given 32-byte hash. This is the recommended
    /// approach for trusting self-signed certificates without disabling
    /// verification entirely.
    pub fn with_pinned_certificate_hash(mut self, hash: [u8; 32]) -> Self {
        self.pinned_hash = Some(hash);
        self.server_cert = None;
        self.insecure_certificate_verification = false;
        self
    }

    /// Disable server certificate verification.
    ///
    /// Requires the `insecure-tls` feature at compile time and the environment
    /// variable `MTP_INSECURE_TLS=1` at runtime. Returns an error if either
    /// condition is not met.
    ///
    /// Intended only for local development with a self-signed host.
    #[cfg(feature = "insecure-tls")]
    pub fn with_insecure_certificate_verification(mut self) -> Self {
        self.server_cert = None;
        self.pinned_hash = None;
        self.insecure_certificate_verification = true;
        self
    }
}

pub async fn connect(
    url: &str,
    server_cert: Option<Vec<u8>>,
    policy: Policy,
) -> Result<(Sender, Receiver), CommunicationError> {
    let config = match server_cert {
        Some(cert_pem) => ClientConfig::new(policy).with_server_certificate(cert_pem),
        None => ClientConfig::new(policy),
    };
    connect_with_config(url, config).await
}

/// Connect using explicit TLS and transport configuration.
pub async fn connect_with_config(
    url: &str,
    config: ClientConfig,
) -> Result<(Sender, Receiver), CommunicationError> {
    let connect_started = Instant::now();
    mtp_crypto::ensure_crypto_provider();

    let config_started = Instant::now();
    let client_config = if config.insecure_certificate_verification {
        #[cfg(feature = "insecure-tls")]
        {
            let env_val = std::env::var("MTP_INSECURE_TLS")
                .map(|v| v == "1")
                .unwrap_or(false);
            if !env_val {
                return Err(CommunicationError::Other(
                    "insecure TLS requires MTP_INSECURE_TLS=1 in the environment".into(),
                ));
            }
            client_config_insecure(&config.policy)?
        }
        #[cfg(not(feature = "insecure-tls"))]
        {
            unreachable!(
                "insecure_certificate_verification is only set when \
                 the insecure-tls feature is enabled"
            )
        }
    } else if let Some(hash) = config.pinned_hash {
        crate::pinning::configure_client_pinned_hash(hash, &config.policy)?
    } else if let Some(cert_pem) = config.server_cert {
        configure_client_with_cert(cert_pem, &config.policy)?
    } else {
        configure_client_system_roots(&config.policy)?
    };
    tracing::debug!(elapsed = ?config_started.elapsed(), "client connect: configure TLS");

    let endpoint_started = Instant::now();
    let endpoint = Endpoint::client(client_config)
        .map_err(|e| CommunicationError::Other(format!("Endpoint creation failed: {}", e)))?;
    tracing::debug!(elapsed = ?endpoint_started.elapsed(), "client connect: create endpoint");

    let transport_connect_started = Instant::now();
    let connection = endpoint
        .connect(url)
        .await
        .map_err(|e| CommunicationError::ConnectingError(e.to_string()))?;
    tracing::debug!(elapsed = ?transport_connect_started.elapsed(), "client connect: establish WebTransport session");

    let handle = Arc::new(ConnectionHandle::with_remote_addr(
        connection.quic_connection().remote_address(),
    ));
    let policy = Arc::new(config.policy);

    let sender = Sender::new(connection.clone(), handle.clone(), policy.clone());
    let receiver = Receiver::new(connection, handle, policy);

    tracing::debug!(elapsed = ?connect_started.elapsed(), "client connect: complete");
    Ok((sender, receiver))
}

fn configure_client_with_cert(
    server_cert: Vec<u8>,
    policy: &Policy,
) -> Result<WTransportClientConfig, CommunicationError> {
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

#[cfg(feature = "insecure-tls")]
fn client_config_insecure(policy: &Policy) -> Result<WTransportClientConfig, CommunicationError> {
    use noop_verifier::NoopCertVerifier;

    let mut tls_config = RustlsClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoopCertVerifier))
        .with_no_client_auth();

    tls_config.alpn_protocols = vec![b"h3".to_vec()];

    Ok(WTransportClientConfig::builder()
        .with_bind_default()
        .with_custom_tls(tls_config)
        .keep_alive_interval(policy.keep_alive_interval)
        .max_idle_timeout(policy.max_idle_timeout)
        .map_err(|e| CommunicationError::Other(e.to_string()))?
        .build())
}

fn configure_client_system_roots(
    policy: &Policy,
) -> Result<WTransportClientConfig, CommunicationError> {
    let mut root_store = RootCertStore::empty();

    let certs = rustls_native_certs::load_native_certs().certs;

    for cert in certs {
        root_store.add(cert).ok();
    }

    client_config_from_roots(root_store, policy)
}

fn client_config_from_roots(
    root_store: RootCertStore,
    policy: &Policy,
) -> Result<WTransportClientConfig, CommunicationError> {
    let mut tls_config = RustlsClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    tls_config.alpn_protocols = vec![b"h3".to_vec()];

    Ok(WTransportClientConfig::builder()
        .with_bind_default()
        .with_custom_tls(tls_config)
        .keep_alive_interval(policy.keep_alive_interval)
        .max_idle_timeout(policy.max_idle_timeout)
        .map_err(|e| CommunicationError::Other(e.to_string()))?
        .build())
}
