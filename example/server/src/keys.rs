use tokio::fs;

use mtp::crypto::Keyring;
use mtp::files::{load_keyring_raw, save_keyring_raw, save_public_key_bundle};

/* Host id is fixed for the example; only the keyring itself is persisted. */
const HOST_ID: u64 = 1;

pub fn load_or_generate_host_keys(
    keyring_path: &str,
) -> Result<(u64, Keyring), Box<dyn std::error::Error>> {
    if let Ok(keyring) = load_keyring_raw(keyring_path) {
        println!("Loaded host keyring from {keyring_path}");
        return Ok((HOST_ID, keyring));
    }

    let keyring = Keyring::generate();
    save_keyring_raw(&keyring, keyring_path)?;
    println!("Generated host keyring -> {keyring_path}");
    Ok((HOST_ID, keyring))
}

pub async fn export_host_public_keys(
    host_keyring: &Keyring,
) -> Result<(), Box<dyn std::error::Error>> {
    let bundle = host_keyring.public_key_bundle();
    save_public_key_bundle(&bundle, "host.mpkb")?;

    /* The web client fetches the bundle as hex over HTTP. */
    let bundle_hex = hex::encode(bundle.as_bytes());
    fs::write("host_public_key_bundle.hex", &bundle_hex).await?;
    fs::create_dir_all("web-client/public").await?;
    fs::write("web-client/public/host_public_key_bundle.hex", &bundle_hex).await?;
    Ok(())
}
