use mtp::client::MTPConnection;
use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataValue};
use mtp::crypto::{Ed25519Signer, EncryptionType, Keyring, PublicKeyBundle, SigAlgorithm};
use mtp::type_map::TypeMap;

pub fn build_demo_message(
    client_id: u64,
    keyring: &Keyring,
    server_bundle: &PublicKeyBundle,
) -> Result<CommunicationValue, Box<dyn std::error::Error>> {
    // Encrypt to the server's KEM public key; the server decrypts with its keyring.
    let enc_type = EncryptionType::MlKemChaCha20Poly1305;
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
    let mut dv_enc = inner_enc;
    dv_enc.encrypt_container(enc_type, server_bundle, b"demo-aad");

    let inner_sig = DataValue::Container(vec![
        (version_id, DataValue::Str("signed by client".into())),
        (id_id, DataValue::UnsignedNumber(99)),
    ]);
    let mut dv_sig = inner_sig;
    dv_sig.sign_container(SigAlgorithm::ED25519, &signer);

    let inner_sec = DataValue::Container(vec![
        (
            version_id,
            DataValue::Str("signed+encrypted payload".into()),
        ),
        (id_id, DataValue::UnsignedNumber(7)),
    ]);
    let mut dv_sec = inner_sec;
    dv_sec.sign_and_encrypt_container(
        SigAlgorithm::ED25519,
        &signer,
        enc_type,
        server_bundle,
        b"demo-aad",
    );

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();

    let msg = CommunicationValue::new(CommunicationType::Ping)
        .add_typed_default(
            DataType::Description,
            DataValue::Str("MTP Data Type Demo".into()),
        )
        .add_typed_default(
            DataType::Timestamp,
            DataValue::UnsignedNumber(timestamp as u128),
        )
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
) -> Result<(), Box<dyn std::error::Error>> {
    let msg = build_demo_message(conn.client_id, keyring, server_bundle)?;
    println!("Sending: {msg}");
    conn.sender.send(&msg).await?;

    match conn.receive().await {
        Ok(resp) => {
            println!("Received: {resp}");
        }
        Err(e) => eprintln!("Receive error: {e}"),
    }

    Ok(())
}
