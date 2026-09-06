use std::time::{Duration, Instant};

use tokio::fs;

use mtp::client::{ClientConfig, MTPClient, MTPConnection};
use mtp::crypto::{Keyring, PublicKeyBundle};
use mtp::files::{load_keyring_raw, save_keyring_raw};

pub async fn connect_or_register(
    mut config: ClientConfig,
    host_public_key: PublicKeyBundle,
    key_prefix: &str,
) -> Result<(MTPConnection, Keyring, String, Duration), Box<dyn std::error::Error>> {
    let keyring_path = format!("{key_prefix}.mk");
    let id_path = format!("{key_prefix}.id");

    let file_load_started = Instant::now();
    if let (Ok(keyring), Ok(id)) = (
        load_keyring_raw(&keyring_path),
        fs::read_to_string(&id_path).await,
    ) {
        let client_id: u64 = id.trim().parse()?;
        println!(
            "Loaded client keys (ID: {client_id}) in {:?}",
            file_load_started.elapsed()
        );

        config.client_id = client_id;
        let auth_started = Instant::now();
        let conn = MTPClient::auth_connect(config, &keyring, &host_public_key).await?;
        let auth_duration = auth_started.elapsed();
        println!(
            "Authenticated (version {}) in {:?}",
            conn.version, auth_duration
        );
        return Ok((conn, keyring, "connect".into(), auth_duration));
    }

    println!("No existing keys found: registering new client");

    /* Registration publishes a complete MTP identity for later protection. */
    let keyring = Keyring::generate();

    let reg_started = Instant::now();
    let conn = MTPClient::auth_register(config, &keyring, &host_public_key).await?;
    let reg_duration = reg_started.elapsed();
    println!(
        "Registered with ID: {} in {:?}",
        conn.client_id, reg_duration
    );

    save_keyring_raw(&keyring, &keyring_path)?;
    fs::write(&id_path, conn.client_id.to_string()).await?;
    println!("Saved client keys -> {keyring_path}");

    Ok((conn, keyring, "register".into(), reg_duration))
}

/// Open a guest transport even when the caller already owns registered
/// credentials. The credentials stay with the caller for protected signing.
pub async fn connect_unauthenticated(
    config: ClientConfig,
) -> Result<MTPConnection, Box<dyn std::error::Error>> {
    let conn = MTPClient::connect(config).await?;
    if conn.auth_state != mtp::client::AuthState::Unauthenticated {
        return Err("guest connection did not report Unauthenticated state".into());
    }
    println!(
        "Opened unauthenticated transport with host-assigned guest ID {}",
        conn.client_id
    );
    Ok(conn)
}
