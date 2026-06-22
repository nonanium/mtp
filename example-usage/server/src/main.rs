use std::fs;

use mtp_codec::{CommunicationType, CommunicationValue, DataType, DataValue, TypeMap};
use mtp_host::{HostConfig, MTPHost};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cert_path = "server.pem";
    let key_path = "server.key";

    let (cert_pem, key_pem) = if let (Ok(c), Ok(k)) = (fs::read(cert_path), fs::read(key_path)) {
        println!("Using existing TLS cert from {cert_path}");
        (c, k)
    } else {
        println!("Generating self-signed TLS certificate ...");

        let key_pair = rcgen::KeyPair::generate()?;
        let params = rcgen::CertificateParams::new(vec![
            "localhost".into(),
            "127.0.0.1".into(),
        ])?;
        let cert = params.self_signed(&key_pair)?;

        let cert_str = cert.pem();
        let key_str = key_pair.serialize_pem();

        fs::write(cert_path, cert_str.as_bytes())?;
        fs::write(key_path, key_str.as_bytes())?;
        println!("Wrote {cert_path} and {key_path}");

        (cert_str.into_bytes(), key_str.into_bytes())
    };

    println!("Starting MTP server on port 8080 ...");

    let config = HostConfig {
        ip: "::".into(),
        port: 8080,
        tls_fullchain: cert_pem,
        tls_key: key_pem,
    };

    let mut host = MTPHost::new(config).await?;
    println!("Server listening on {}", host.local_addr());

    while let Some(conn) = host.accept().await {
        println!("\n--- New connection accepted (version {}) ---", conn.version);

        let tm: &TypeMap = conn.codec.registry().get(&conn.version).unwrap();

        match conn.receiver.receive().await {
            Ok(msg) => {
                println!("Received: {msg}");

                let timestamp = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();

                let response = CommunicationValue::from_comm(
                    CommunicationType::Pong,
                    tm,
                )
                .add_data(
                    mtp_codec::DataTypeId(tm.data_id_enum(DataType::Description).unwrap()),
                    DataValue::Str("Hello from server!".into()),
                )
                .add_data(
                    mtp_codec::DataTypeId(tm.data_id_enum(DataType::Timestamp).unwrap()),
                    DataValue::UnsignedNumber(timestamp as u128),
                )
                .add_data(
                    mtp_codec::DataTypeId(tm.data_id_enum(DataType::Data).unwrap()),
                    DataValue::Str("custom payload".into()),
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
