use std::fs;

use mtp::crypto::{Ed25519Signer, Keyring, MlDsaSigner};
use mtp::crypto::kem::HybridKem;

pub fn load_or_generate_host_keys(path: &str) -> Result<(u64, Keyring), Box<dyn std::error::Error>> {
    if let Ok(data) = fs::read_to_string(path) {
        let json: serde_json::Value = serde_json::from_str(&data)?;
        let hid = json["host_id"].as_u64().unwrap_or(1);
        let keyring = Keyring::from_bytes(&hex::decode(json["keyring"].as_str().unwrap())?)?;
        println!("Loaded host keys (ID: {})", hid);
        return Ok((hid, keyring));
    }

    let (_ed_signer, sig_sk, sig_pk) = Ed25519Signer::generate();
    let (_pq_signer, sig_pq_sk, sig_pq_pk) = MlDsaSigner::generate();
    let (kem_sk, kem_pk) = HybridKem::generate_keypair();
    let keyring = Keyring::new(kem_pk, kem_sk, sig_pq_pk, sig_pq_sk, sig_pk, sig_sk);

    let json = serde_json::json!({
        "host_id": 1,
        "keyring": hex::encode(keyring.to_bytes()),
    });
    fs::write(path, serde_json::to_string_pretty(&json)?)?;
    println!("Generated host keys -> {path}");
    Ok((1u64, keyring))
}

pub fn export_host_public_keys(host_keyring: &Keyring) -> Result<(), Box<dyn std::error::Error>> {
    let public_key_bundle_hex = hex::encode(host_keyring.public_key_bundle().as_bytes());

    fs::write(
        "host_public_key_bundle.hex",
        &public_key_bundle_hex,
    )?;
    fs::create_dir_all("web-client/public")?;
    fs::write(
        "web-client/public/host_public_key_bundle.hex",
        &public_key_bundle_hex,
    )?;
    fs::write(
        "host_enc_kem_pk.bin",
        host_keyring.kem_public_key.as_bytes(),
    )?;
    fs::write("host_sig_pk.bin", host_keyring.sig_cl_public_key.as_bytes())?;
    fs::write(
        "host_sig_pq_pk.bin",
        host_keyring.sig_pq_public_key.as_bytes(),
    )?;
    Ok(())
}
