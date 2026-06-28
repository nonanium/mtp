use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataTypeId, DataValue, TypeMap};
use mtp::crypto::{
    CryptoError, Keyring, SignaturePublicKey, SignatureScheme, verify_ed25519,
};

struct Ed25519Verifier(SignaturePublicKey);

impl SignatureScheme for Ed25519Verifier {
    fn sign(&self, _msg: &[u8]) -> Result<Vec<u8>, CryptoError> {
        Err(CryptoError::SigningFailed)
    }
    fn verify(&self, msg: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
        verify_ed25519(&self.0, msg, signature)
    }
}

pub fn process_and_respond(
    msg: &CommunicationValue,
    tm: &TypeMap,
    client_pk: Option<&mtp::crypto::PublicKeyBundle>,
    host_keyring: &Keyring,
) -> CommunicationValue {
    let desc_id = DataTypeId(tm.data_id_enum(DataType::Description).unwrap());
    let ts_id = DataTypeId(tm.data_id_enum(DataType::Timestamp).unwrap());
    let data_id = DataTypeId(tm.data_id_enum(DataType::Data).unwrap());
    let flags_id = DataTypeId(tm.data_id_enum(DataType::Flags).unwrap());
    let value_id = DataTypeId(tm.data_id_enum(DataType::Value).unwrap());
    let bin_id = DataTypeId(tm.data_id_enum(DataType::BinaryData).unwrap());
    let items_id = DataTypeId(tm.data_id_enum(DataType::Items).unwrap());
    let _enc_id = DataTypeId(tm.data_id_enum(DataType::EncryptedPayload).unwrap());
    let _sig_id = DataTypeId(tm.data_id_enum(DataType::SignedPayload).unwrap());
    let _secure_id = DataTypeId(tm.data_id_enum(DataType::SecurePayload).unwrap());

    let description = msg.get_data(DataType::Description);
    let timestamp = msg.get_data(DataType::Timestamp);
    let data = msg.get_data(DataType::Data);
    let flags = msg.get_data(DataType::Flags);
    let value = msg.get_data(DataType::Value);
    let binary = msg.get_data(DataType::BinaryData);
    let items = msg.get_data(DataType::Items);

    println!(
        "  Description: {}",
        description.as_str().unwrap_or("(missing)")
    );
    println!("  Timestamp: {:?}", timestamp.as_unsigned_number());
    println!("  Data: {}", data.as_str().unwrap_or("(missing)"));
    println!("  Flags: {:?}", flags.as_bool());
    println!("  Value: {:?}", value.as_float());
    println!("  Binary: {:?}", binary.as_bytes());
    println!("  Items: {:?}", items.as_array());

    let mut enc_status = String::from("EncryptedPayload: not present");
    let mut sig_status = String::from("SignedPayload: not present");
    let mut secure_status = String::from("SecurePayload: not present");

    let enc = msg.get_data(DataType::EncryptedPayload);
    if matches!(enc, DataValue::EncryptedContainer(_)) {
        let mut dv = enc.clone();
        if dv.decrypt_into_container(host_keyring, b"demo-aad").is_some() {
            if let Some(entries) = dv.as_container() {
                println!("  Decrypted EncryptedPayload: {:?}", entries);
                enc_status = format!("EncryptedPayload decrypted OK ({} entries)", entries.len());
            }
        } else {
            eprintln!("  EncryptedPayload decryption failed");
            enc_status = String::from("EncryptedPayload: decryption FAILED");
        }
    }

    let sig = msg.get_data(DataType::SignedPayload);
    if matches!(sig, DataValue::SignedContainer(_)) {
        if let Some(pk_bundle) = client_pk {
            let verifier = Ed25519Verifier(pk_bundle.sig_cl_public_key.clone());
            let mut dv = sig.clone();
            if dv.verify_into_container(&verifier).is_some() {
                if let Some(entries) = dv.as_container() {
                    println!("  Verified SignedPayload: {:?}", entries);
                    sig_status = format!("SignedPayload verified OK ({} entries)", entries.len());
                }
            } else {
                eprintln!("  SignedPayload verification failed");
                sig_status = String::from("SignedPayload: verification FAILED");
            }
        } else {
            eprintln!("  SignedPayload cannot be verified; no client public key available");
            sig_status = String::from("SignedPayload: no client public key available");
        }
    }

    let secure = msg.get_data(DataType::SecurePayload);
    if matches!(secure, DataValue::SignedEncryptedContainer(_)) {
        if let Some(pk_bundle) = client_pk {
            let verifier = Ed25519Verifier(pk_bundle.sig_cl_public_key.clone());
            let mut dv = secure.clone();
            if dv.decrypt_signed_encrypted_container(host_keyring, b"demo-aad").is_some()
                && dv.verify_into_container(&verifier).is_some()
            {
                if let Some(entries) = dv.as_container() {
                    println!("  Verified SecurePayload: {:?}", entries);
                    secure_status = format!(
                        "SecurePayload decrypted+verified OK ({} entries)",
                        entries.len()
                    );
                }
            } else {
                eprintln!("  SecurePayload decryption/verification failed");
                secure_status = String::from("SecurePayload: decryption/verification FAILED");
            }
        } else {
            eprintln!("  SecurePayload cannot be verified; no client public key available");
            secure_status = String::from("SecurePayload: no client public key available");
        }
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    CommunicationValue::from_comm(CommunicationType::Pong, tm)
        .add_data(desc_id, description.clone())
        .add_data(ts_id, DataValue::UnsignedNumber(now as u128))
        .add_data(
            data_id,
            DataValue::Str(format!(
                "{}. {}. {}.",
                enc_status, sig_status, secure_status
            )),
        )
        .add_data(flags_id, flags.clone())
        .add_data(value_id, value.clone())
        .add_data(bin_id, binary.clone())
        .add_data(items_id, items.clone())
}
