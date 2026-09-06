use std::time::{Duration, Instant};

use mtp::client::MTPConnection;
use mtp::codec::ProtectionPurpose;
use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataValue};
use mtp::crypto::{Ed25519Signer, Keyring, PublicKeyBundle};
use mtp::type_map::TypeMap;

pub fn build_demo_message(
    client_id: u64,
    keyring: &Keyring,
    server_bundle: &PublicKeyBundle,
) -> Result<CommunicationValue, Box<dyn std::error::Error>> {
    // Encrypt to the server's KEM public key; the server decrypts with its keyring.
    let signer = Ed25519Signer::new(&keyring.sig_cl_secret_key)?;

    let tm = TypeMap::latest();
    let version_id = DataType::Version
        .try_to_id(&tm)
        .ok_or_else(|| std::io::Error::other("Version is absent from the type map"))?;
    let id_id = DataType::Id
        .try_to_id(&tm)
        .ok_or_else(|| std::io::Error::other("Id is absent from the type map"))?;

    let inner_enc = DataValue::Container(vec![
        (version_id, DataValue::Str("secret inner data".into())),
        (id_id, DataValue::UnsignedNumber(42)),
    ]);
    let dv_enc = inner_enc.encrypt_for(
        std::slice::from_ref(server_bundle),
        ProtectionPurpose::from(1),
    )?;

    let inner_sig = DataValue::Container(vec![
        (version_id, DataValue::Str("signed by client".into())),
        (id_id, DataValue::UnsignedNumber(99)),
    ]);
    let dv_sig = inner_sig.sign(client_id, ProtectionPurpose::from(2), &signer)?;

    let inner_sec = DataValue::Container(vec![
        (
            version_id,
            DataValue::Str("signed+encrypted payload".into()),
        ),
        (id_id, DataValue::UnsignedNumber(7)),
    ]);
    let dv_sec = inner_sec
        .sign(client_id, ProtectionPurpose::from(3), &signer)?
        .encrypt_for(
            std::slice::from_ref(server_bundle),
            ProtectionPurpose::from(4),
        )?;

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_millis();

    let msg = CommunicationValue::new(CommunicationType::Ping)
        .add_typed_default(
            DataType::Description,
            DataValue::Str("MTP Data Type Demo".into()),
        )
        .add_typed_default(DataType::Timestamp, DataValue::UnsignedNumber(timestamp))
        .add_typed_default(DataType::Data, DataValue::Str("Hello, MTP!".into()))
        .add_typed_default(DataType::Flags, DataValue::BoolTrue)
        .add_typed_default(DataType::Value, DataValue::Float(1_234_500.0))
        .add_typed_default(
            DataType::BinaryData,
            DataValue::Bytes(vec![0xDE, 0xAD, 0xBE, 0xEF, 0x42]),
        )
        .add_typed_default(
            DataType::Items,
            DataValue::Array(vec![
                DataValue::Str("alpha".into()),
                DataValue::Str("beta".into()),
                DataValue::Str("gamma".into()),
            ]),
        )
        .add_typed_default(DataType::EncryptedPayload, dv_enc)
        .add_typed_default(DataType::SignedPayload, dv_sig)
        .add_typed_default(DataType::SecurePayload, dv_sec)
        .with_sender(client_id);
    Ok(msg)
}

pub async fn send_and_receive(
    conn: &MTPConnection,
    keyring: &Keyring,
    server_bundle: &PublicKeyBundle,
) -> Result<Duration, Box<dyn std::error::Error>> {
    let msg = build_demo_message(conn.client_id, keyring, server_bundle)?;
    println!("Sending: {msg}");
    let start = Instant::now();
    conn.sender.send(&msg).await?;

    match conn.receive().await {
        Ok(resp) => {
            let roundtrip = start.elapsed();
            println!("Received: {resp}");
            println!(
                "Message round-trip: {:.3}ms",
                roundtrip.as_secs_f64() * 1000.0
            );
            Ok(roundtrip)
        }
        Err(e) => {
            eprintln!("Receive error: {e}");
            Err(e.into())
        }
    }
}
