mod auth;
mod metrics;
mod messages;
mod pipes;
mod protected;

use std::fs;
use std::path::Path;
use std::time::Duration;

use mtp::client::{AuthState, ClientConfig};
use mtp::files::load_public_key_bundle;

fn dev_cert_path() -> String {
    std::env::var("MTP_DEV_CERT").unwrap_or_else(|_| {
        if Path::new("example/dev-cert/cert.pem").exists() {
            "example/dev-cert/cert.pem".to_string()
        } else {
            "dev-cert/cert.pem".to_string()
        }
    })
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    let cert_path = dev_cert_path();
    let cert_pem = fs::read(&cert_path).unwrap_or_else(|e| {
        panic!(
            "Missing TLS certificate at {cert_path}: enter the Nix shell first or run the server to generate it: {e}"
        )
    });
    let host_public_key = match load_public_key_bundle("host.mpkb") {
        Ok(bundle) => bundle,
        Err(e) => {
            return Err(
                format!("Missing host.mpkb: run the server first to export it ({e})").into(),
            );
        }
    };

    let mut client_metrics = metrics::ClientMetrics::load("metrics/client_sessions.json");

    println!("Connecting to 127.0.0.1:8080 ...");

    let config = ClientConfig::new("https://127.0.0.1:8080")
        .with_pinned_pem(cert_pem.clone())
        .with_description("MTP example client");

    let server_bundle = host_public_key.clone();
    let (conn, keyring, auth_method, auth_duration) =
        match auth::connect_or_register(config, host_public_key, "client").await {
            Ok(result) => result,
            Err(e) => {
                let mut builder = metrics::SessionBuilder::new("failed", Duration::from_secs(0));
                builder.set_error(e.to_string());
                client_metrics.record_session(builder.build());
                client_metrics.save("metrics/client_sessions.json");
                client_metrics.build_overview("metrics/client_overview.json");
                return Err(e);
            }
        };

    let mut builder = metrics::SessionBuilder::new(&auth_method, auth_duration);

    if conn.auth_state != AuthState::Authenticated {
        return Err("authenticated example connection did not report Authenticated state".into());
    }
    println!(
        "Receive connection A: authenticated client {}",
        conn.client_id
    );

    let unauthenticated_config = ClientConfig::new("https://127.0.0.1:8080")
        .with_pinned_pem(cert_pem.clone())
        .with_description("MTP example unauthenticated sender");
    let unauthenticated_conn = auth::connect_unauthenticated(unauthenticated_config).await?;
    println!(
        "Send connection B: unauthenticated guest transport ID {}",
        unauthenticated_conn.client_id
    );

    let direct_roundtrip = protected::send_direct_protected(
        &unauthenticated_conn,
        conn.client_id,
        &keyring,
        &server_bundle,
    )
    .await?;
    println!(
        "Protected signer {} was accepted through unauthenticated connection B",
        conn.client_id
    );

    let relay_roundtrip = protected::send_sealed_relay(
        &unauthenticated_conn,
        conn.client_id,
        &keyring,
        &server_bundle,
    )
    .await?;
    println!(
        "Sealed relay round-trip completed in {:.3}ms",
        relay_roundtrip.as_secs_f64() * 1000.0
    );

    unauthenticated_conn.sender.close().await;

    let roundtrip = messages::send_and_receive(&conn, &keyring, &server_bundle).await?;
    builder.set_message_roundtrip(roundtrip);

    println!(
        "Direct protected round-trip: {:.3}ms",
        direct_roundtrip.as_secs_f64() * 1000.0
    );

    println!("\n--- Pipe demo ---");
    let pipe_results = pipes::run_pipe_demo(&conn, 1).await?;
    for result in &pipe_results {
        builder.add_pipe_result(result.clone());
    }

    let session_record = builder.build();
    println!(
        "\nSession {} complete: auth={}ms, msg_roundtrip={}ms, pipes={} results, pipe_bytes={}",
        session_record.session_id,
        session_record.auth_duration_ms,
        session_record.message_roundtrip_ms,
        session_record.pipe_results.len(),
        session_record.total_pipe_bytes,
    );

    client_metrics.record_session(session_record);
    client_metrics.save("metrics/client_sessions.json");
    client_metrics.build_overview("metrics/client_overview.json");

    conn.sender.close().await;
    println!("\nDone");
    Ok(())
}
