mod clients;
mod handlers;
mod keys;
mod tls;

use mtp::host::{HostConfig, MTPHost};
use mtp::type_map::TypeMap;
use std::future::Future;
use std::path::Path;
use std::pin::Pin;

fn dev_cert_paths() -> (String, String) {
    let cert = std::env::var("MTP_DEV_CERT").unwrap_or_else(|_| {
        if Path::new("example/dev-cert/cert.pem").exists() {
            "example/dev-cert/cert.pem".to_string()
        } else {
            "dev-cert/cert.pem".to_string()
        }
    });
    let key = std::env::var("MTP_DEV_KEY").unwrap_or_else(|_| {
        if Path::new("example/dev-cert/key.pem").exists() {
            "example/dev-cert/key.pem".to_string()
        } else {
            "dev-cert/key.pem".to_string()
        }
    });
    (cert, key)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (cert_path, key_path) = dev_cert_paths();
    let (cert_pem, key_pem) = tls::load_or_generate_tls(&cert_path, &key_path)?;
    let cert_hash = tls::certificate_sha256_hex(&cert_pem)?;
    tls::export_webtransport_cert_hash(&cert_hash)?;
    println!("WebTransport certificate sha256: {cert_hash}");

    let (_host_id, host_keyring) = keys::load_or_generate_host_keys("host_keys.json")?;
    keys::export_host_public_keys(&host_keyring)?;

    // The keyring is moved into the host config; keep a copy for decrypting the
    // demo payloads clients encrypt to our KEM public key.
    let decrypt_keyring = mtp::crypto::Keyring::from_bytes(&host_keyring.to_bytes())
        .expect("re-load host keyring for decryption");

    let (clients, next_id) = clients::load_client_db("clients.json")?;

    let clients_for_get = clients.clone();
    let get_existing_user = move |id: u64| {
        let clients = clients_for_get.clone();
        Box::pin(async move {
            let result = clients.lock().unwrap().get(&id).cloned();
            if result.is_some() {
                println!("Auth lookup: client ID {id} found");
            } else {
                eprintln!("Auth lookup: unknown client ID {id}");
            }
            result
        }) as Pin<Box<dyn Future<Output = Option<mtp::crypto::PublicKeyBundle>> + Send>>
    };

    let clients_for_register = clients.clone();
    let next_id_for_register = next_id.clone();
    let clients_path = "clients.json".to_string();
    let complete_register = move |bundle: mtp::crypto::PublicKeyBundle| {
        let db_arc = clients_for_register.clone();
        let nid_arc = next_id_for_register.clone();
        let path = clients_path.clone();
        Box::pin(async move {
            let mut db = db_arc.lock().unwrap();
            let mut nid = nid_arc.lock().unwrap();
            let id = *nid;
            *nid += 1;
            db.insert(id, bundle);
            match serde_json::to_string_pretty(&*db) {
                Ok(json) => match std::fs::write(&path, json) {
                    Ok(()) => {}
                    Err(e) => eprintln!("Failed to persist client database to {path}: {e}"),
                },
                Err(e) => eprintln!("Failed to serialize client database after registering {id}: {e}"),
            }
            println!("Registered new client with ID: {}", id);
            id
        }) as Pin<Box<dyn Future<Output = u64> + Send>>
    };

    println!("Starting MTP server on port 8080 ...");

    let config = HostConfig::new(
        std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
        8080,
        cert_pem,
        key_pem,
    )
    .with_authentication(host_keyring, get_existing_user, complete_register);

    let mut host = MTPHost::new(config).await?;
    println!("Server listening on {}", host.local_addr());

    while let Some(conn) = host.accept().await? {
        let desc = conn
            .description
            .as_deref()
            .unwrap_or("(no description)");
        println!(
            "\n--- New connection (version {}, description: {desc}) ---",
            conn.version
        );
        println!("Client ID: {}", conn.client_id);

        let tm: &TypeMap = conn.codec.registry().get(&conn.version).unwrap();

        match conn.receiver.receive().await {
            Ok(msg) => {
                println!("Received: {msg}");
                let response = handlers::process_and_respond(
                    &msg,
                    tm,
                    conn.client_public_key.as_ref(),
                    &decrypt_keyring,
                );
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
