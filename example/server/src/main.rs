mod clients;
mod handlers;
mod keys;
mod tls;

use mtp::host::{AuthenticationPolicy, HostConfig, MTPHost};
use mtp::type_map::TypeMap;
use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;

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

async fn handle_pipe_loopback(
    conn: &mtp::host::MTPConnection,
    req: mtp::host::PipeRequest,
) -> Result<(), Box<dyn std::error::Error>> {
    let pipe_id = req.id();
    println!(
        "  [loopback] Pipe request: id={pipe_id} description={:?}",
        req.description()
    );

    println!("  [loopback] Calling accept() for pipe {pipe_id} ...");
    let mut reader = req.accept().await?;
    println!("  [loopback] Pipe {pipe_id} accepted, reading data ...");

    let handle = conn.create_pipe("loopback").await?;
    println!(
        "  [loopback] Return pipe created (id={}), waiting for client ...",
        handle.pipe_id()
    );

    match handle.wait().await? {
        Some(mut writer) => {
            println!("  [loopback] Client accepted return pipe, echoing incoming bytes ...");
            let mut total = 0usize;
            let mut buf = [0u8; 16 * 1024];
            loop {
                let n = tokio::io::AsyncReadExt::read(&mut reader, &mut buf).await?;
                if n == 0 {
                    break;
                }
                total += n;
                tokio::io::AsyncWriteExt::write_all(&mut writer, &buf[..n]).await?;
            }
            writer.finish().await?;
            println!(
                "  [loopback] Pipe {pipe_id} loopback complete ({} bytes)",
                total
            );
        }
        None => {
            eprintln!("  [loopback] Return pipe denied by client for pipe {pipe_id}");
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (cert_path, key_path) = dev_cert_paths();
    let (cert_pem, key_pem) = tls::load_or_generate_tls(&cert_path, &key_path)?;
    let cert_hash = tls::certificate_sha256_hex(&cert_pem)?;
    tls::export_webtransport_cert_hash(&cert_hash)?;
    println!("WebTransport certificate sha256: {cert_hash}");

    let (_host_id, host_keyring) = keys::load_or_generate_host_keys("host.mk")?;
    keys::export_host_public_keys(&host_keyring)?;

    let decrypt_keyring = Arc::new(match mtp::crypto::Keyring::from_bytes(&host_keyring.to_bytes())
    {
        Ok(keyring) => keyring,
        Err(e) => {
            return Err(format!("failed to re-load host keyring for decryption: {e}").into());
        }
    });

    let (clients, next_id) = clients::load_client_db("clients.json")?;

    let clients_for_get = clients.clone();
    let get_existing_user = move |id: u64, _description: Option<String>| {
        let clients = clients_for_get.clone();
        Box::pin(async move {
            let result = clients.lock()?.get(&id).cloned();
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
    let complete_register = move |bundle: mtp::crypto::PublicKeyBundle,
                                  _description: Option<String>| {
        let db_arc = clients_for_register.clone();
        let nid_arc = next_id_for_register.clone();
        let path = clients_path.clone();
        Box::pin(async move {
            let mut db = db_arc.lock()?;
            let mut nid = nid_arc.lock()?;
            let id = *nid;
            *nid += 1;
            db.insert(id, bundle);
            match serde_json::to_string_pretty(&*db) {
                Ok(json) => match std::fs::write(&path, json) {
                    Ok(()) => {}
                    Err(e) => eprintln!("Failed to persist client database to {path}: {e}"),
                },
                Err(e) => {
                    eprintln!("Failed to serialize client database after registering {id}: {e}")
                }
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
    .with_authentication(
        host_keyring,
        Box::new(get_existing_user),
        Box::new(complete_register),
    )
    .with_authentication_policy(AuthenticationPolicy::ForceAuthentication);

    let mut host = MTPHost::new(config).await?;
    println!("Server listening on {}", host.local_addr());

    while let Some(conn) = host.accept().await? {
        let decrypt_keyring = Arc::clone(&decrypt_keyring);
        tokio::spawn(async move {
            let desc = conn.description.as_deref().unwrap_or("(no description)");
            println!(
                "\n--- New connection (version {}, description: {desc}) ---",
                conn.version
            );
            println!("Client ID: {}", conn.client_id);

            let tm: &TypeMap = conn.codec.registry().get(&conn.version)?;

            println!("Waiting for messages / pipe requests ...");
            loop {
                tokio::select! {
                    biased;

                    pipe_req = conn.receive_pipe() => {
                        match pipe_req {
                            Ok(req) => {
                                println!("  Pipe request: id={} desc={:?}", req.id(), req.description());
                                if let Err(e) = handle_pipe_loopback(&conn, req).await {
                                    eprintln!("  Pipe loopback error: {e}");
                                }
                            }
                            Err(e) => {
                                println!("Pipe channel closed: {e}");
                                break;
                            }
                        }
                    }
                    msg = conn.receive() => {
                        match msg {
                            Ok(msg) => {
                                println!("Received: {msg}");
                                let response = match handlers::process_and_respond(
                                    &msg,
                                    tm,
                                    conn.client_public_key.as_ref(),
                                    &decrypt_keyring,
                                ) {
                                    Ok(response) => response,
                                    Err(e) => {
                                        eprintln!("Failed to build response: {e}");
                                        continue;
                                    }
                                };
                                println!("Sending: {response}");
                                if let Err(e) = conn.sender.send(&response).await {
                                    eprintln!("Send error: {e}");
                                    break;
                                }
                            }
                            Err(e) => {
                                println!("Connection ended: {e}");
                                break;
                            }
                        }
                    }
                }
            }

            conn.sender.close();
            println!("Connection closed\n");
        });
    }

    Ok(())
}
