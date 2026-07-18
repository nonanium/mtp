use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, SanType};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use time::{Duration, OffsetDateTime};

use crate::CryptoError;

/// Generate a self-signed TLS certificate and private key for development.
///
/// Returns `(cert_pem, key_pem)` as byte vectors. The certificate is valid for
/// the given domain name plus `127.0.0.1` and `::1`, uses ECDSA P-256, and is
/// valid for 13 days from the time of generation.
///
/// Never panics; all errors are returned as [`CryptoError`].
pub fn generate_self_signed_cert(domain: &str) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .map_err(|e| CryptoError::Tls(format!("key generation failed: {e}")))?;

    let mut params = CertificateParams::new(vec![domain.to_string()])
        .map_err(|e| CryptoError::Tls(format!("certificate params failed: {e}")))?;

    params.not_before = OffsetDateTime::now_utc() - Duration::minutes(5);
    params.not_after = OffsetDateTime::now_utc() + Duration::days(13);

    params
        .subject_alt_names
        .push(SanType::IpAddress(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
    params
        .subject_alt_names
        .push(SanType::IpAddress(IpAddr::V6(Ipv6Addr::new(
            0, 0, 0, 0, 0, 0, 0, 1,
        ))));

    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.is_ca = IsCa::NoCa;

    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| CryptoError::Tls(format!("certificate signing failed: {e}")))?;

    let cert_pem = cert.pem().into_bytes();
    let key_pem = key_pair.serialize_pem().into_bytes();

    Ok((cert_pem, key_pem))
}
