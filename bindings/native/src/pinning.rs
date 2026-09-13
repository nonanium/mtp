use rustls::{
    ClientConfig as RustlsClientConfig, DigitallySignedStruct, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{
        CryptoProvider, WebPkiSupportedAlgorithms, verify_tls12_signature, verify_tls13_signature,
    },
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use sha2::{Digest, Sha256};
use wtransport::ClientConfig as WTransportClientConfig;

use crate::Policy;

use mtp_common::CommunicationError;
use std::sync::Arc;

/// A certificate verifier that pins a connection to a specific SPKI
/// (Subject Public Key Info) SHA-256 hash. The client will only accept
/// server certificates whose DER-encoded SPKI matches the provided hash.
#[derive(Debug)]
pub struct PinnedCertVerifier {
    expected_hash: [u8; 32],
    algorithms: WebPkiSupportedAlgorithms,
}

impl PinnedCertVerifier {
    pub fn new(expected_hash: [u8; 32]) -> Result<Self, rustls::Error> {
        let provider = CryptoProvider::get_default().ok_or_else(|| {
            rustls::Error::General("rustls crypto provider is not installed".into())
        })?;

        Ok(Self {
            expected_hash,
            algorithms: provider.signature_verification_algorithms,
        })
    }
}

impl ServerCertVerifier for PinnedCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let der = end_entity.as_ref();

        let spki = extract_spki_der(der)?;

        let computed = Sha256::digest(spki);

        if computed.as_slice() != self.expected_hash.as_slice() {
            return Err(rustls::Error::General(format!(
                "certificate SPKI hash mismatch: expected {:02x?}, got {:02x?}",
                self.expected_hash, computed
            )));
        }

        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

/// Extract the complete DER-encoded SubjectPublicKeyInfo sequence from an
/// X.509 certificate. The sequence tag and length are part of an SPKI pin.
fn extract_spki_der(der: &[u8]) -> Result<&[u8], rustls::Error> {
    let (remaining, cert) = x509_parser::parse_x509_certificate(der)
        .map_err(|_| rustls::Error::General("failed to parse X.509 certificate".into()))?;

    if !remaining.is_empty() {
        return Err(rustls::Error::General(
            "trailing data after X.509 certificate".into(),
        ));
    }

    Ok(cert.tbs_certificate.subject_pki.raw)
}

/// Build a [`WTransportClientConfig`] that verifies the server certificate
/// against a pinned SPKI SHA-256 hash.
pub fn configure_client_pinned_hash(
    expected_hash: [u8; 32],
    policy: &Policy,
) -> Result<WTransportClientConfig, CommunicationError> {
    mtp_crypto::ensure_crypto_provider();
    let verifier = PinnedCertVerifier::new(expected_hash).map_err(|e| {
        CommunicationError::Other(format!("failed to configure certificate pinning: {e}"))
    })?;

    let mut tls_config = RustlsClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
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
