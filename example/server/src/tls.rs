use std::fs;
use std::path::Path;

use base64::Engine;

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
    let key_pair = rcgen::KeyPair::generate()?;
    let params = rcgen::CertificateParams::new(vec!["localhost".into(), "127.0.0.1".into()])?;
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
