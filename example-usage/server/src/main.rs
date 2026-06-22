use std::collections::HashMap;
use std::fs;
use std::sync::{Arc, Mutex};

use mtp_codec::{CommunicationType, CommunicationValue, DataType, DataTypeId, DataValue, TypeMap};
use mtp_host::{HostConfig, MTPHost};
use mtp_crypto::{
    Ed25519Signer, KemPrivateKey, KemPublicKey, Keyring, PublicKeyBundle,
    SignaturePqPrivateKey, SignaturePqPublicKey,
};

/*
 * Load an existing TLS certificate and key pair from disk.  If neither
 * file exists, generate a self-signed certificate so the server is
 * immediately usable without external tooling.
 */
fn load_or_generate_tls(cert_path: &str, key_path: &str) -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
    if let (Ok(c), Ok(k)) = (fs::read(cert_path), fs::read(key_path)) {
        println!("Using existing TLS cert from {cert_path}");
        return Ok((c, k));
    }

    println!("Generating self-signed TLS certificate ...");
    let key_pair = rcgen::KeyPair::generate()?;
    let params = rcgen::CertificateParams::new(vec!["localhost".into(), "127.0.0.1".into()])?;
    let cert = params.self_signed(&key_pair)?;

    let cert_str = cert.pem();
    let key_str = key_pair.serialize_pem();

    fs::write(cert_path, cert_str.as_bytes())?;
    fs::write(key_path, key_str.as_bytes())?;
    println!("Wrote {cert_path} and {key_path}");

    Ok((cert_str.into_bytes(), key_str.into_bytes()))
}

/*
 * Load the host's Ed25519 identity from a JSON file, or generate a
 * fresh one and persist it.  Clients need the corresponding public key
 * (exported separately as host_sig_pk.bin) to authenticate the host
 * during the handshake.
 */
fn load_or_generate_host_keys(path: &str) -> Result<(u64, Keyring), Box<dyn std::error::Error>> {
    if let Ok(data) = fs::read_to_string(path) {
        let json: serde_json::Value = serde_json::from_str(&data)?;
        let hid = json["host_id"].as_u64().unwrap_or(1);
        let keyring = Keyring::from_bytes(&hex::decode(json["keyring"].as_str().unwrap())?)?;
        println!("Loaded host keys (ID: {})", hid);
        return Ok((hid, keyring));
    }

    let (_signer, sig_sk, sig_pk) = Ed25519Signer::generate();
    let keyring = Keyring::new(
        KemPublicKey::new(vec![]),
        KemPrivateKey::new(vec![]),
        SignaturePqPublicKey::new(vec![]),
        SignaturePqPrivateKey::new(vec![]),
        sig_pk,
        sig_sk,
    );

    let json = serde_json::json!({
        "host_id": 1,
        "keyring": hex::encode(keyring.to_bytes()),
    });
    fs::write(path, serde_json::to_string_pretty(&json)?)?;
    println!("Generated host keys -> {path}");
    Ok((1u64, keyring))
}

/*
 * Load the client database from disk.  Each entry maps a numeric
 * client ID to its PublicKeyBundle.  next_id starts one past the
 * highest known ID (or 1000 if the DB is empty).
 */
fn load_client_db(
    path: &str,
) -> Result<
    (
        Arc<Mutex<HashMap<u64, PublicKeyBundle>>>,
        Arc<Mutex<u64>>,
    ),
    Box<dyn std::error::Error>,
> {
    let clients: Arc<Mutex<HashMap<u64, PublicKeyBundle>>> = Arc::new(Mutex::new(
        if let Ok(data) = fs::read_to_string(path) {
            serde_json::from_str(&data).unwrap_or_default()
        } else {
            HashMap::new()
        },
    ));
    let next_id = Arc::new(Mutex::new(
        clients.lock().unwrap().keys().max().unwrap_or(&999) + 1,
    ));
    Ok((clients, next_id))
}

/*
 * Build a Pong response carrying a description, a Unix timestamp, and
 * a custom payload according to the negotiated type map.
 */
fn build_pong_response(tm: &TypeMap) -> CommunicationValue {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    CommunicationValue::from_comm(CommunicationType::Pong, tm)
        .add_data(
            DataTypeId(tm.data_id_enum(DataType::Description).unwrap()),
            DataValue::Str("Hello from server!".into()),
        )
        .add_data(
            DataTypeId(tm.data_id_enum(DataType::Timestamp).unwrap()),
            DataValue::UnsignedNumber(timestamp as u128),
        )
        .add_data(
            DataTypeId(tm.data_id_enum(DataType::Data).unwrap()),
            DataValue::Str("custom payload".into()),
        )
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (cert_pem, key_pem) = load_or_generate_tls("server.pem", "server.key")?;
    let (host_id, host_keyring) = load_or_generate_host_keys("host_keys.json")?;

    // Export the host's Ed25519 public key so clients can verify it
    fs::write(
        "host_sig_pk.bin",
        host_keyring.sig_cl_public_key.as_bytes(),
    )?;

    let (clients, next_id) = load_client_db("clients.json")?;

    // Clone the Arc so each closure owns its own reference
    let clients_for_get = clients.clone();
    let get_existing_user = Box::new(move |id: u64| -> Option<PublicKeyBundle> {
        clients_for_get.lock().unwrap().get(&id).cloned()
    });

    let clients_for_register = clients.clone();
    let next_id_for_register = next_id.clone();
    let clients_path = "clients.json".to_string();
    let complete_register = Box::new(move |bundle: PublicKeyBundle| -> u64 {
        let mut db = clients_for_register.lock().unwrap();
        let mut nid = next_id_for_register.lock().unwrap();
        let id = *nid;
        *nid += 1;
        db.insert(id, bundle);
        fs::write(&clients_path, serde_json::to_string_pretty(&*db).unwrap()).ok();
        println!("Registered new client with ID: {}", id);
        id
    });

    println!("Starting MTP server on port 8080 ...");

    let config = HostConfig {
        port: 8080,
        tls_fullchain: cert_pem,
        tls_key: key_pem,
        require_authentication: true,
        host_id,
        host_keyring,
        get_existing_user,
        complete_register,
    };

    let mut host = MTPHost::new(config).await?;
    println!("Server listening on {}", host.local_addr());

    while let Some(conn) = host.accept().await {
        println!(
            "\n--- New authenticated connection (version {}) ---",
            conn.version
        );
        println!("Client ID: {}", conn.client_id);

        let tm: &TypeMap = conn.codec.registry().get(&conn.version).unwrap();

        match conn.receiver.receive().await {
            Ok(msg) => {
                println!("Received: {msg}");
                let response = build_pong_response(tm);
                println!("Sending: {response}");
                conn.sender.send(&response).await?;
            }
            Err(e) => {
                eprintln!("Receive error: {e}");
            }
        }

        conn.sender.close();
        println!("Connection closed\n");
    }

    Ok(())
}
