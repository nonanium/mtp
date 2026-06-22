use std::fs;

use mtp_client::{ClientConfig, MTPClient, MTPConnection};
use mtp_codec::{CommunicationType, CommunicationValue, DataType, DataValue};
use mtp_crypto::{
    Ed25519Signer, EncryptionPrivateKey, EncryptionPublicKey, KeyGroup, Keyring,
    KemPrivateKey, KemPublicKey, SignaturePqPrivateKey, SignaturePqPublicKey,
    SignaturePrivateKey, SignaturePublicKey,
};

/*
 * Either load a saved keyring from disk (login) or generate a fresh
 * keypair and register with the server.  Returns the established
 * connection and the local keyring.
 */
async fn connect_or_register(
    config: ClientConfig,
    host_public_key: SignaturePublicKey,
    client_key_path: &str,
) -> Result<(MTPConnection, Keyring), Box<dyn std::error::Error>> {
    if let Ok(data) = fs::read_to_string(client_key_path) {
        let json: serde_json::Value = serde_json::from_str(&data)?;
        let client_id = json["client_id"].as_u64().expect("Invalid client_id");
        let keyring = Keyring::from_bytes(
            &hex::decode(json["keyring"].as_str().expect("Missing keyring"))?,
        )?;

        println!("Loaded client keys (ID: {})", client_id);

        let keygroup = KeyGroup::new(
            EncryptionPublicKey::new(vec![]),
            EncryptionPrivateKey::new(vec![]),
            keyring.sig_cl_public_key.clone(),
            SignaturePrivateKey::new(keyring.sig_cl_secret_key.as_bytes().to_vec()),
        );

        let conn = MTPClient::auth_connect(config, client_id, keygroup, host_public_key).await?;
        println!("Authenticated (version {})", conn.version);
        Ok((conn, keyring))
    } else {
        println!("No existing keys found - registering new client");

        let (_signer, sig_sk, sig_pk) = Ed25519Signer::generate();
        let keyring = Keyring::new(
            KemPublicKey::new(vec![]),
            KemPrivateKey::new(vec![]),
            SignaturePqPublicKey::new(vec![]),
            SignaturePqPrivateKey::new(vec![]),
            sig_pk,
            sig_sk,
        );

        // Serialise before the move so we can persist and return the keyring
        let keyring_bytes = keyring.to_bytes();
        let conn = MTPClient::auth_register(config, keyring, host_public_key).await?;
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
        .add_typed_default(DataType::Timestamp, DataValue::UnsignedNumber(timestamp as u128))
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
    let cert_pem = fs::read("server.pem").expect("Missing server.pem - run server first");
    let host_public_key = SignaturePublicKey::new(
        fs::read("host_sig_pk.bin").expect("Missing host_sig_pk.bin - run server first"),
    );

    println!("Connecting to 127.0.0.1:8080 ...");

    let config = ClientConfig {
        url: "https://127.0.0.1:8080".into(),
        server_cert: Some(cert_pem),
    };

    let (conn, _keyring) = connect_or_register(config, host_public_key, "client_keys.json").await?;
    send_ping_and_receive(&conn).await?;

    println!("\nDone");
    Ok(())
}
