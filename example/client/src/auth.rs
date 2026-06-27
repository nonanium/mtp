use std::fs;

use mtp::client::{ClientConfig, MTPClient, MTPConnection};
use mtp::crypto::{Ed25519Signer, Keyring, MlDsaSigner, PublicKeyBundle};

pub async fn connect_or_register(
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
