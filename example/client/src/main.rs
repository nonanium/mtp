mod auth;
mod messages;

use std::fs;
use std::path::Path;

use mtp::client::ClientConfig;
use mtp::files::load_public_key_bundle;

fn dev_cert_path() -> String {
    std::env::var("MTP_DEV_CERT").unwrap_or_else(|_| {
        if Path::new("example/dev-cert/cert.pem").exists() {
            "example/dev-cert/cert.pem".to_string()
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
    let host_public_key = load_public_key_bundle("host.mpkb")
        .expect("Missing host.mpkb: run the server first to export it");

    println!("Connecting to 127.0.0.1:8080 ...");

    let config = ClientConfig::new("https://127.0.0.1:8080")
        .with_pinned_pem(cert_pem)
        .with_description("MTP example client");

    let server_bundle = host_public_key.clone();
    let (conn, keyring) = auth::connect_or_register(config, host_public_key, "client").await?;
    messages::send_and_receive(&conn, &keyring, &server_bundle).await?;

    println!("\nDone");
    Ok(())
}
