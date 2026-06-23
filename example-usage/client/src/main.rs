use std::fs;

use mtp::client::{ClientConfig, MTPClient, MTPConnection};
use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataValue};
use mtp::crypto::{
    Ed25519Signer, KemPublicKey, Keyring, MlDsaSigner, PublicKeyBundle, SignaturePqPublicKey,
    SignaturePublicKey,
};

/*
 * Either load a saved keyring from disk (login) or generate a fresh
 * keypair and register with the server.  Returns the established
 * connection and the local keyring.
 */
async fn connect_or_register(
    mut config: ClientConfig,
    host_public_key: PublicKeyBundle,
    client_key_path: &str,
) -> Result<(MTPConnection, Keyring), Box<dyn std::error::Error>> {
    if let Ok(data) = fs::read_to_string(client_key_path) {
        let json: serde_json::Value = serde_json::from_str(&data)?;
        let client_id = json["client_id"].as_u64().expect("Invalid client_id");
        let keyring = Keyring::from_bytes(&hex::decode(
            json["keyring"].as_str().expect("Missing keyring"),
        )?)?;

        println!("Loaded client keys (ID: {})", client_id);

        config.client_id = client_id;
        let conn = MTPClient::auth_connect(config, &keyring, &host_public_key).await?;
        println!("Authenticated (version {})", conn.version);
        Ok((conn, keyring))
    } else {
        println!("No existing keys found: registering new client");

        let (_ed_signer, sig_sk, sig_pk) = Ed25519Signer::generate();
        let (_pq_signer, sig_pq_sk, sig_pq_pk) = MlDsaSigner::generate();
        let keyring = Keyring::new(
            mtp::crypto::KemPublicKey::new(vec![]),
            mtp::crypto::KemPrivateKey::new(vec![]),
            sig_pq_pk,
            sig_pq_sk,
            sig_pk,
            sig_sk,
        );

        let keyring_bytes = keyring.to_bytes();
        let conn = MTPClient::auth_register(config, &keyring, &host_public_key).await?;
        println!("Registered with ID: {}", conn.client_id);

        let json = serde_json::json!({
            "client_id": conn.client_id,
            "keyring": hex::encode(&keyring_bytes),
        });
        fs::write(client_key_path, serde_json::to_string_pretty(&json)?)?;
        println!("Saved client keys -> {client_key_path}");

        let keyring = Keyring::from_bytes(&keyring_bytes)?;
        Ok((conn, keyring))
    }
}

/*
 * Send a Ping greeting with description, timestamp, and data fields,
 * then print the server's Pong response.
 */
async fn send_ping_and_receive(conn: &MTPConnection) -> Result<(), Box<dyn std::error::Error>> {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let greeting = CommunicationValue::new(CommunicationType::Ping)
        .add_typed_default(DataType::Description, DataValue::Str("Hello MTP!".into()))
        .add_typed_default(
            DataType::Timestamp,
            DataValue::UnsignedNumber(timestamp as u128),
        )
        .add_typed_default(DataType::Data, DataValue::UnsignedNumber(42))
        .with_sender(conn.client_id);

    println!("Sending: {greeting}");
    conn.sender.send(&greeting).await?;

    match conn.receiver.receive().await {
        Ok(msg) => println!("Received: {msg}"),
        Err(e) => eprintln!("Receive error: {e}"),
    }

    conn.sender.close();
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cert_pem = fs::read("server.pem").expect("Missing server.pem: run server first");
    let host_public_key = PublicKeyBundle::new(
        KemPublicKey::new(
            fs::read("host_enc_kem_pk.bin").expect("Missing host_enc_kem_pk.bin: run server first"),
        ),
        SignaturePqPublicKey::new(
            fs::read("host_sig_pq_pk.bin").expect("Missing host_sig_pq_pk.bin: run server first"),
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

    let (conn, _keyring) = connect_or_register(config, host_public_key, "client_keys.json").await?;
    send_ping_and_receive(&conn).await?;

    println!("\nDone");
    Ok(())
}
