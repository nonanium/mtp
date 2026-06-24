mod auth;
mod messages;

use std::fs;

use mtp::client::ClientConfig;
use mtp::crypto::{KemPublicKey, PublicKeyBundle, SignaturePqPublicKey, SignaturePublicKey};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cert_pem = fs::read("server.pem").expect("Missing server.pem: run server first");
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

    let (conn, keyring) =
        auth::connect_or_register(config, host_public_key, "client_keys.json").await?;
    messages::send_and_receive(&conn, &keyring).await?;

    println!("\nDone");
    Ok(())
}
