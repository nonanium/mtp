use mtp::client::MTPConnection;
use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataTypeId, DataValue};
use mtp::crypto::{ChaCha20Poly1305, Ed25519Signer, Keyring, SigAlgorithm};

fn derive_demo_key() -> [u8; 32] {
    mtp::crypto::derive_encryption_key(
        b"MTP-demo-shared-secret",
        b"MTP-demo-salt",
        b"encrypted-container-demo",
    )
    .expect("key derivation must succeed")
}

pub fn build_demo_message(client_id: u64, keyring: &Keyring) -> CommunicationValue {
    let cipher = ChaCha20Poly1305::new(derive_demo_key());
    let signer = Ed25519Signer::new(&keyring.sig_cl_secret_key)
        .expect("Ed25519 signer from keyring");

    let inner_enc = DataValue::Container(vec![
        (DataTypeId(1), DataValue::Str("secret inner data".into())),
        (DataTypeId(2), DataValue::UnsignedNumber(42)),
    ]);
    let mut dv_enc = inner_enc;
    dv_enc.encrypt_container(&cipher, b"demo-aad");

    let inner_sig = DataValue::Container(vec![
        (DataTypeId(1), DataValue::Str("signed by client".into())),
        (DataTypeId(2), DataValue::UnsignedNumber(99)),
    ]);
    let mut dv_sig = inner_sig;
    dv_sig.sign_container(SigAlgorithm::ED25519, &signer);

    let inner_sec = DataValue::Container(vec![
        (DataTypeId(1), DataValue::Str("signed+encrypted payload".into())),
        (DataTypeId(2), DataValue::UnsignedNumber(7)),
    ]);
    let mut dv_sec = inner_sec;
    dv_sec.sign_and_encrypt_container(SigAlgorithm::ED25519, &signer, &cipher, b"demo-aad");

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    CommunicationValue::new(CommunicationType::Ping)
        .add_typed_default(DataType::Description, DataValue::Str("MTP Data Type Demo".into()))
        .add_typed_default(DataType::Timestamp, DataValue::UnsignedNumber(timestamp as u128))
        .add_typed_default(DataType::Data, DataValue::Str("Hello, MTP!".into()))
        .add_typed_default(DataType::Flags, DataValue::BoolTrue)
        .add_typed_default(DataType::Value, DataValue::Float(2, 12345))
        .add_typed_default(DataType::BinaryData, DataValue::Bytes(vec![0xDE, 0xAD, 0xBE, 0xEF, 0x42]))
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
        .with_sender(client_id)
}

pub async fn send_and_receive(
    conn: &MTPConnection,
    keyring: &Keyring,
) -> Result<(), Box<dyn std::error::Error>> {
    let msg = build_demo_message(conn.client_id, keyring);
    println!("Sending: {msg}");
    conn.sender.send(&msg).await?;

    match conn.receiver.receive().await {
        Ok(resp) => println!("Received: {resp}"),
        Err(e) => eprintln!("Receive error: {e}"),
    }

    conn.sender.close();
    Ok(())
}
