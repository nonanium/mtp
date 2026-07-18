use std::fs;

use mtp::client::{ClientConfig, MTPClient, MTPConnection};
use mtp::crypto::{
    Ed25519Signer, KemPrivateKey, KemPublicKey, Keyring, MlDsaSigner, PublicKeyBundle,
};
use mtp::files::{load_keyring_raw, save_keyring_raw};

pub async fn connect_or_register(
    mut config: ClientConfig,
    host_public_key: PublicKeyBundle,
    key_prefix: &str,
) -> Result<(MTPConnection, Keyring), Box<dyn std::error::Error>> {
    let keyring_path = format!("{key_prefix}.mk");
    let id_path = format!("{key_prefix}.id");

    if let (Ok(keyring), Ok(id)) = (
        load_keyring_raw(&keyring_path),
        fs::read_to_string(&id_path),
    ) {
        let client_id: u64 = id.trim().parse()?;
        println!("Loaded client keys (ID: {client_id})");

        config.client_id = client_id;
        let conn = MTPClient::auth_connect(config, &keyring, &host_public_key).await?;
        println!("Authenticated (version {})", conn.version);
        return Ok((conn, keyring));
    }

    println!("No existing keys found: registering new client");

    /* The client authenticates with signatures only, so the KEM slot is empty. */
    let (_ed_signer, sig_sk, sig_pk) = Ed25519Signer::generate();
    let (_pq_signer, sig_pq_sk, sig_pq_pk) = MlDsaSigner::generate();
    let keyring = Keyring::new(
        KemPublicKey::new(vec![]),
        KemPrivateKey::new(vec![]),
        sig_pq_pk,
        sig_pq_sk,
        sig_pk,
        sig_sk,
    );

    let conn = MTPClient::auth_register(config, &keyring, &host_public_key).await?;
    println!("Registered with ID: {}", conn.client_id);

    save_keyring_raw(&keyring, &keyring_path)?;
    fs::write(&id_path, conn.client_id.to_string())?;
    println!("Saved client keys -> {keyring_path}");

    Ok((conn, keyring))
}
