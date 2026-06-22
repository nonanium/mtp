use std::fs;

use mtp_client::{ClientConfig, MTPClient};
use mtp_codec::{CommunicationType, CommunicationValue, DataType, DataValue};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cert_pem = fs::read("server.pem")
        .expect("Missing server.pem server generates it");

    println!("Connecting to 127.0.0.1:8080 ...");

    let config = ClientConfig {
        url: "https://127.0.0.1:8080".into(),
        server_cert: Some(cert_pem),
    };

    let conn = MTPClient::connect(config, 1001).await?;
    println!("Connected (version {})", conn.version);

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let greeting = CommunicationValue::new(CommunicationType::Ping)
        .add_typed_default(DataType::Description, DataValue::Str("Hello MTP!".into()))
        .add_typed_default(DataType::Timestamp, DataValue::UnsignedNumber(timestamp as u128))
        .add_typed_default(DataType::Data, DataValue::UnsignedNumber(42))
        .with_sender(1001);

    println!("Sending: {greeting}");
    conn.sender.send(&greeting).await?;

    match conn.receiver.receive().await {
        Ok(msg) => {
            println!("Received: {msg}");
        }
        Err(e) => {
            eprintln!("Receive error: {e}");
        }
    }

    conn.sender.close();
    println!("\nDone");

    Ok(())
}
