mod auth;
mod messages;

use std::fs;
use std::path::Path;

use mtp::client::ClientConfig;
use mtp::crypto::{KemPublicKey, PublicKeyBundle, SignaturePqPublicKey, SignaturePublicKey};

fn dev_cert_path() -> String {
    std::env::var("MTP_DEV_CERT").unwrap_or_else(|_| {
        if Path::new("example-usage/dev-cert/cert.pem").exists() {
            "example-usage/dev-cert/cert.pem".to_string()
        } else {
            "dev-cert/cert.pem".to_string()
        }
    })
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cert_path = dev_cert_path();
    let cert_pem = fs::read(&cert_path).unwrap_or_else(|e| {
        panic!(
            "Missing TLS certificate at {cert_path}: enter the Nix shell first or run the server to generate it: {e}"
        )
    });
    let host_public_key = PublicKeyBundle::new(
        KemPublicKey::new(
            fs::read("host_enc_kem_pk.bin")
                .expect("Missing host_enc_kem_pk.bin: run server first"),
        ),
        SignaturePqPublicKey::new(
            fs::read("host_sig_pq_pk.bin")
                .expect("Missing host_sig_pq_pk.bin: run server first"),
        ),
        SignaturePublicKey::new(
            fs::read("host_sig_pk.bin").expect("Missing host_sig_pk.bin: run server first"),
        ),
    );

    println!("Connecting to 127.0.0.1:8080 ...");

    let config = ClientConfig {
        url: "https://127.0.0.1:8080".into(),
        server_cert: Some(cert_pem),
        client_id: 0,
    };

    let server_bundle = host_public_key.clone();
    let (conn, keyring) =
        auth::connect_or_register(config, host_public_key, "client_keys.json").await?;
    messages::send_and_receive(&conn, &keyring, &server_bundle).await?;

    println!("\nDone");
    Ok(())
}
