use base64::Engine;
use std::path::Path;
use tokio::fs;

pub async fn load_or_generate_tls(
    cert_path: &str,
    key_path: &str,
) -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
    if let (Ok(c), Ok(k)) = (fs::read(cert_path).await, fs::read(key_path).await) {
        println!("Using existing TLS cert from {cert_path}");
        return Ok((c, k));
    }

    println!("Generating self-signed TLS certificate ...");
    if let Some(parent) = Path::new(cert_path).parent() {
        fs::create_dir_all(parent).await?;
    }
    if let Some(parent) = Path::new(key_path).parent() {
        fs::create_dir_all(parent).await?;
    }

    let (cert_pem, key_pem) = mtp::crypto::tls::generate_self_signed_cert("localhost")?;

    fs::write(cert_path, &cert_pem).await?;
    fs::write(key_path, &key_pem).await?;
    println!("Wrote {cert_path} and {key_path}");

    Ok((cert_pem, key_pem))
}

pub async fn certificate_sha256_hex(cert: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
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

pub async fn export_webtransport_cert_hash(hash: &str) -> Result<(), Box<dyn std::error::Error>> {
    let public_dir = if Path::new("web-client").exists() {
        Path::new("web-client/public")
    } else {
        Path::new("example/web-client/public")
    };
    fs::create_dir_all(public_dir).await?;
    fs::write(public_dir.join("mtp_dev_cert_hash.txt"), hash).await?;

    let dev_cert_dir = if Path::new("dev-cert").exists() {
        Path::new("dev-cert")
    } else {
        Path::new("example/dev-cert")
    };
    if dev_cert_dir.exists() {
        fs::write(dev_cert_dir.join("sha256.txt"), hash).await?;
    }

    Ok(())
}
