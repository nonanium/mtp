use base64::Engine;
use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, SanType};
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use time::{Duration, OffsetDateTime};

pub fn load_or_generate_tls(
    cert_path: &str,
    key_path: &str,
) -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
    if let (Ok(c), Ok(k)) = (fs::read(cert_path), fs::read(key_path)) {
        println!("Using existing TLS cert from {cert_path}");
        return Ok((c, k));
    }

    println!("Generating self-signed TLS certificate ...");
    if let Some(parent) = Path::new(cert_path).parent() {
        fs::create_dir_all(parent)?;
    }
    if let Some(parent) = Path::new(key_path).parent() {
        fs::create_dir_all(parent)?;
    }

    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;

    let mut params = CertificateParams::new(vec!["localhost".into()])?;
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

    let cert = params.self_signed(&key_pair)?;

    let cert_str = cert.pem();
    let key_str = key_pair.serialize_pem();

    fs::write(cert_path, cert_str.as_bytes())?;
    fs::write(key_path, key_str.as_bytes())?;
    println!("Wrote {cert_path} and {key_path}");

    Ok((cert_str.into_bytes(), key_str.into_bytes()))
}

pub fn certificate_sha256_hex(cert: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
    let der = if cert.starts_with(b"-----BEGIN CERTIFICATE-----") {
        let pem = std::str::from_utf8(cert)?;
        let base64 = pem
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect::<String>();
        base64::engine::general_purpose::STANDARD.decode(base64)?
    } else {
        cert.to_vec()
    };

    Ok(hex::encode(mtp::crypto::sha256(&der)))
}

pub fn export_webtransport_cert_hash(hash: &str) -> Result<(), Box<dyn std::error::Error>> {
    let public_dir = if Path::new("web-client").exists() {
        Path::new("web-client/public")
    } else {
        Path::new("example/web-client/public")
    };
    fs::create_dir_all(public_dir)?;
    fs::write(public_dir.join("mtp_dev_cert_hash.txt"), hash)?;

    let dev_cert_dir = if Path::new("dev-cert").exists() {
        Path::new("dev-cert")
    } else {
        Path::new("example/dev-cert")
    };
    if dev_cert_dir.exists() {
        fs::write(dev_cert_dir.join("sha256.txt"), hash)?;
    }

    Ok(())
}
