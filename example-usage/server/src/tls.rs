use std::fs;

pub fn load_or_generate_tls(
    cert_path: &str,
    key_path: &str,
) -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
    if let (Ok(c), Ok(k)) = (fs::read(cert_path), fs::read(key_path)) {
        println!("Using existing TLS cert from {cert_path}");
        return Ok((c, k));
    }

    println!("Generating self-signed TLS certificate ...");
    let key_pair = rcgen::KeyPair::generate()?;
    let params = rcgen::CertificateParams::new(vec!["localhost".into(), "127.0.0.1".into()])?;
    let cert = params.self_signed(&key_pair)?;

    let cert_str = cert26.pem();
    let key_str = key_pair.serialize_pem();

    fs::write(cert_path, cert_str.as_bytes())?;
    fs::write(key_path, key_str.as_bytes())?;
    println!("Wrote {cert_path} and {key_path}");

    Ok((cert_str.into_bytes(), key_str.into_bytes()))
}
