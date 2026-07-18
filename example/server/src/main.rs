mod clients;
mod handlers;
mod keys;
mod tls;
#[path = "web-server.rs"]
mod web_server;

use mtp::host::HostConfig;
use mtp::type_map::TypeMap;
use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;

const CONNECTION_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);
const MAX_MESSAGES_PER_CONNECTION: u64 = 10_000;

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
    conn: &mtp::webserver::WebMTPConnection,
    request: mtp::host::PipeRequest<
        mtp::webserver::WebMtpSender,
        mtp::webserver::H3TransportReceiver,
    >,
) -> Result<(), Box<dyn std::error::Error>> {
    let pipe_id = request.id();
    println!("  [loopback] Accepting pipe {pipe_id} ...");
    let mut reader = request.accept().await?;

    let return_pipe = conn.create_pipe("loopback").await?;
    println!(
        "  [loopback] Requested return pipe {}; waiting for client acceptance ...",
        return_pipe.pipe_id()
    );
    let Some(mut writer) = return_pipe.wait().await? else {
        return Err("client denied the return pipe".into());
    };

    let copied = tokio::io::copy(&mut reader, &mut writer).await?;
    writer.finish_async().await?;
    println!("  [loopback] Pipe {pipe_id} complete ({copied} bytes)");
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    let (cert_path, key_path) = dev_cert_paths();
    let (cert_pem, key_pem) = tls::load_or_generate_tls(&cert_path, &key_path).await?;
    let cert_hash = tls::certificate_sha256_hex(&cert_pem).await?;
    tls::export_webtransport_cert_hash(&cert_hash).await?;
    println!("WebTransport certificate sha256: {cert_hash}");

    let (_host_id, host_keyring) = keys::load_or_generate_host_keys("host.mk")?;
    keys::export_host_public_keys(&host_keyring).await?;

    let (clients, next_id) = clients::load_client_db("clients.json").await?;
    let clients_for_get = clients.clone();
    let get_existing_client = move |id: u64, _description: Option<String>| {
        let clients = clients_for_get.clone();
        Box::pin(async move { clients.lock().ok()?.get(&id).cloned() })
            as Pin<Box<dyn Future<Output = Option<mtp::crypto::PublicKeyBundle>> + Send>>
    };
    let clients_for_register = clients.clone();
    let next_id_for_register = next_id.clone();
    let complete_register = move |bundle: mtp::crypto::PublicKeyBundle,
                                  _description: Option<String>| {
        let clients = clients_for_register.clone();
        let next_id = next_id_for_register.clone();

        Box::pin(async move {
            let id = {
                let mut next = next_id.lock().expect("client id mutex poisoned");
                let id = *next;
                *next += 1;
                id
            };

            let json = {
                let mut db = clients.lock().expect("client database mutex poisoned");
                db.insert(id, bundle);
                serde_json::to_string_pretty(&*db).ok()
            };

            if let Some(json) = json {
                if let Err(error) = tokio::fs::write("clients.json", json).await {
                    eprintln!("Failed to persist clients.json: {error}");
                }
            }

            println!("Registered new client with ID: {id}");
            id
        }) as Pin<Box<dyn Future<Output = u64> + Send>>
    };

    let decrypt_keyring = Arc::new(
        match mtp::crypto::Keyring::from_bytes(&host_keyring.to_bytes()) {
            Ok(keyring) => keyring,
            Err(e) => {
                return Err(format!("failed to re-load host keyring for decryption: {e}").into());
            }
        },
    );

    println!("Starting integrated MTP web server on port 8080 ...");

    let config = HostConfig::new(
        std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
        8080,
        cert_pem,
        key_pem,
    )
    .with_authentication(
        host_keyring,
        Box::new(get_existing_client),
        Box::new(complete_register),
    );

    let _https = web_server::spawn_https(
        std::net::SocketAddr::new(config.ip, config.port),
        &config.tls_fullchain,
        &config.tls_key,
    )
    .await?;
    let mut host = mtp::webserver::MTPWebServer::new(config, web_server::config()?).await?;
    println!(
        "Server listening on https://{} (TCP HTTPS + UDP WebTransport)",
        host.local_addr()
    );

    while let Some(conn) = host.accept().await? {
        let decrypt_keyring = Arc::clone(&decrypt_keyring);
        tokio::spawn(async move {
            let desc = conn.description.as_deref().unwrap_or("(no description)");
            println!(
                "\n--- New connection (version {}, description: {desc}) ---",
                conn.version
            );
            println!("Client ID: {}", conn.client_id);

            let tm: &TypeMap = conn.codec.registry().get(&conn.version).unwrap();

            println!("Waiting for messages / pipe requests ...");
            let mut pipe_open = true;
            let mut message_open = true;
            let mut messages_received = 0_u64;

            while pipe_open || message_open {
                let activity = tokio::time::timeout(CONNECTION_IDLE_TIMEOUT, async {
                    tokio::select! {
                        biased;
                        pipe_request = conn.receive_pipe(), if pipe_open => {
                            match pipe_request {
                                Ok(request) => {
                                    if let Err(error) = handle_pipe_loopback(&conn, request).await {
                                        eprintln!("  [loopback] Pipe error: {error}");
                                    }
                                }
                                Err(mtp::common::CommunicationError::StreamClosed)
                                | Err(mtp::common::CommunicationError::ClosedByPeer) => {
                                    println!("Pipe channel closed normally");
                                    pipe_open = false;
                                }
                                Err(error) => {
                                    println!("Pipe channel closed: {error}");
                                    pipe_open = false;
                                }
                            }
                        }
                        message = conn.receive(), if message_open => {
                            match message {
                                Ok(message) => {
                                    messages_received += 1;
                                    println!("Received: {message}");
                                    match handlers::process_and_respond(
                                        &message,
                                        tm,
                                        conn.client_public_key.as_ref(),
                                        &decrypt_keyring,
                                    ) {
                                        Ok(response) => {
                                            println!("Sending: {response}");
                                            if let Err(error) = conn.sender.send(&response).await {
                                                eprintln!("Send error: {error}");
                                                pipe_open = false;
                                                message_open = false;
                                            }
                                        }
                                        Err(error) => {
                                            eprintln!("Failed to build response: {error}");
                                        }
                                    }
                                }
                                Err(mtp::common::CommunicationError::StreamClosed)
                                | Err(mtp::common::CommunicationError::ClosedByPeer) => {
                                    println!("Message channel closed normally");
                                    message_open = false;
                                }
                                Err(error) => {
                                    println!("Message channel closed: {error}");
                                    message_open = false;
                                }
                            }
                        }
                    }
                })
                .await;

                if activity.is_err() {
                    println!("Connection idle timeout reached");
                    break;
                }
                if messages_received >= MAX_MESSAGES_PER_CONNECTION {
                    println!("Connection message limit reached");
                    break;
                }
            }

            println!("Connection closed\n");
        });
    }

    Ok(())
}
