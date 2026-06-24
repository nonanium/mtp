mod clients;
mod handlers;
mod keys;
mod tls;

use mtp::host::{HostConfig, MTPHost};
use mtp::type_map::TypeMap;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (cert_pem, key_pem) = tls::load_or_generate_tls("server.pem", "server.key")?;
    let (host_id, host_keyring) = keys::load_or_generate_host_keys("host_keys.json")?;
    keys::export_host_public_keys(&host_keyring)?;

    let (clients, next_id) = clients::load_client_db("clients.json")?;

    let clients_for_get = clients.clone();
    let get_existing_user = Box::new(move |id: u64| -> Option<mtp::crypto::PublicKeyBundle> {
        clients_for_get.lock().unwrap().get(&id).cloned()
    });

    let clients_for_register = clients.clone();
    let next_id_for_register = next_id.clone();
    let clients_path = "clients.json".to_string();
    let complete_register = Box::new(move |bundle: mtp::crypto::PublicKeyBundle| -> u64 {
        let mut db = clients_for_register.lock().unwrap();
        let mut nid = next_id_for_register.lock().unwrap();
        let id = *nid;
        *nid += 1;
        db.insert(id, bundle);
        std::fs::write(&clients_path, serde_json::to_string_pretty(&*db).unwrap()).ok();
        println!("Registered new client with ID: {}", id);
        id
    });

    println!("Starting MTP server on port 8080 ...");

    let config = HostConfig {
        ip: std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
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
                let response =
                    handlers::process_and_respond(&msg, tm, conn.client_public_key.as_ref());
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
