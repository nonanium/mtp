use rustls::{
    ClientConfig as RustlsClientConfig, DigitallySignedStruct, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
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
}

impl PinnedCertVerifier {
    pub fn new(expected_hash: [u8; 32]) -> Self {
        Self { expected_hash }
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

        let spki = extract_spki(der).map_err(|_| {
            rustls::Error::General("failed to extract SPKI from certificate".into())
        })?;

        let computed = Sha256::digest(&spki);

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
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::ED25519,
        ]
    }
}

/// Extract the Subject Public Key Info (SPKI) field from a DER-encoded X.509
/// certificate. Returns the raw bytes of the SPKI sequence.
fn extract_spki(der: &[u8]) -> Result<Vec<u8>, ()> {
    let (_, outer) = parse_der_sequence(der).map_err(|_| ())?;

    let (_, tbs) = parse_der_sequence(outer).map_err(|_| ())?;

    // Skip version (context [0]), serial number, signature algorithm, issuer,
    // validity, subject to reach subjectPublicKeyInfo (index 6).
    let mut offset = 0;
    let mut element_index = 0;

    while offset < tbs.len() && element_index < 6 {
        let (len, _) = parse_der_element(&tbs[offset..]).map_err(|_| ())?;
        offset += len;
        element_index += 1;
    }

    if element_index != 6 {
        return Err(());
    }

    let (spki_len, spki) = parse_der_element(&tbs[offset..]).map_err(|_| ())?;
    if spki_len == 0 {
        return Err(());
    }

    Ok(spki.to_vec())
}

fn parse_der_element(data: &[u8]) -> Result<(usize, &[u8]), ()> {
    if data.len() < 2 {
        return Err(());
    }

    let mut offset = 1;

    let len_byte = data[offset];
    offset += 1;

    let content_len = if len_byte & 0x80 == 0 {
        len_byte as usize
    } else {
        let num_bytes = (len_byte & 0x7F) as usize;
        if offset + num_bytes > data.len() {
            return Err(());
        }
        let mut len = 0usize;
        for i in 0..num_bytes {
            len = (len << 8) | data[offset + i] as usize;
        }
        offset += num_bytes;
        len
    };

    if offset + content_len > data.len() {
        return Err(());
    }

    let total_len = offset + content_len;
    Ok((total_len, &data[offset..offset + content_len]))
}

fn parse_der_sequence(data: &[u8]) -> Result<(usize, &[u8]), ()> {
    if data.is_empty() || data[0] != 0x30 {
        return Err(());
    }
    parse_der_element(data)
}

/// Build a [`WTransportClientConfig`] that verifies the server certificate
/// against a pinned SPKI SHA-256 hash.
pub fn configure_client_pinned_hash(
    expected_hash: [u8; 32],
    policy: &Policy,
) -> Result<WTransportClientConfig, CommunicationError> {
    let verifier = PinnedCertVerifier::new(expected_hash);

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
