use std::collections::HashMap;

use mtp::codec::{
    CommunicationType, CommunicationValue, DataType, DataTypeId, DataValue, InMemoryReplayGuard,
    ProtectedOpenOptions, ProtectionPolicy, ProtectionPurpose, RelayOpenOptions, SignaturePolicy,
    TypeMap, forward_relay_frame, open_protected_with_checked,
    open_relay_content_with_limits_without_replay, open_relay_metadata_with_checked,
};
use mtp::crypto::{Keyring, PublicKeyBundle};

const DIRECT_DESTINATION_ID: u64 = 1;
const METADATA_RELAY_ID: u64 = 1;
const FINAL_RECIPIENT_ID: u64 = 7_002;
const DIRECT_SIGNATURE_PURPOSE: u8 = 0x40;
const DIRECT_ENCRYPTION_PURPOSE: u8 = 0x41;
const SIGNATURE_POLICY: ProtectionPolicy = ProtectionPolicy {
    signature: SignaturePolicy::Ed25519,
};

fn resolve_signer_key(
    signer_id: u64,
    registered_clients: &HashMap<u64, PublicKeyBundle>,
) -> Option<PublicKeyBundle> {
    registered_clients.get(&signer_id).cloned()
}

fn pong(tm: &TypeMap, data: impl Into<String>) -> Result<CommunicationValue, String> {
    let desc_id = DataTypeId(
        tm.data_id_enum(DataType::Description)
            .ok_or("missing Description type mapping")?,
    );
    let ts_id = DataTypeId(
        tm.data_id_enum(DataType::Timestamp)
            .ok_or("missing Timestamp type mapping")?,
    );
    let data_id = DataTypeId(
        tm.data_id_enum(DataType::Data)
            .ok_or("missing Data type mapping")?,
    );
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_millis();

    CommunicationValue::from_comm(CommunicationType::Pong, tm)
        .add_data(desc_id, DataValue::Str("MTP example response".into()))
        .map_err(|e| e.to_string())?
        .add_data(ts_id, DataValue::UnsignedNumber(now))
        .map_err(|e| e.to_string())?
        .add_data(data_id, DataValue::Str(data.into()))
        .map_err(|e| e.to_string())
}

fn process_direct_protected(
    msg: &CommunicationValue,
    tm: &TypeMap,
    client_pk: Option<&PublicKeyBundle>,
    registered_clients: &HashMap<u64, PublicKeyBundle>,
    host_keyring: &Keyring,
    accepted_messages: &mut InMemoryReplayGuard,
) -> Result<CommunicationValue, String> {
    if msg.receiver() != Some(DIRECT_DESTINATION_ID) {
        return Err(format!(
            "direct protected frame was addressed to {:?}, expected destination {DIRECT_DESTINATION_ID}",
            msg.receiver()
        ));
    }

    let opened = open_protected_with_checked(
        msg,
        std::slice::from_ref(&host_keyring),
        None,
        |signer_id| resolve_signer_key(signer_id, registered_clients).map(|key| vec![key]),
        ProtectedOpenOptions::new(
            Some(DIRECT_DESTINATION_ID),
            ProtectionPurpose::from(DIRECT_SIGNATURE_PURPOSE),
            ProtectionPurpose::from(DIRECT_ENCRYPTION_PURPOSE),
            SIGNATURE_POLICY,
        ),
        accepted_messages,
    )
    .map_err(|e| format!("direct protected message could not be authenticated: {e}"))?;
    let signer_id = opened.signer_id();
    let message_id = opened.message_id();
    let value = opened
        .content()
        .as_container()
        .ok_or("direct protected application value is not a container")?;

    let text_id = DataTypeId(
        tm.data_id_enum(DataType::ExampleText)
            .ok_or("missing ExampleText type mapping")?,
    );
    let number_id = DataTypeId(
        tm.data_id_enum(DataType::ExampleNumber)
            .ok_or("missing ExampleNumber type mapping")?,
    );
    let text = value
        .iter()
        .find(|(id, _)| *id == text_id)
        .and_then(|(_, value)| value.as_str())
        .ok_or("direct protected value is missing ExampleText")?;
    let number = value
        .iter()
        .find(|(id, _)| *id == number_id)
        .and_then(|(_, value)| value.as_unsigned_number())
        .ok_or("direct protected value is missing ExampleNumber")?;

    println!(
        "  Direct protected message: signer={signer_id}, message_id={message_id}, transport_key_available={}, ExampleText={text:?}, ExampleNumber={number}",
        client_pk.is_some()
    );
    if client_pk.is_none() {
        println!(
            "  Protected signer was verified from the registered key map; transport is unauthenticated"
        );
    }
    pong(
        tm,
        format!("direct protected value verified for signer {signer_id}"),
    )
}

fn process_sealed_relay(
    msg: &CommunicationValue,
    registered_clients: &HashMap<u64, PublicKeyBundle>,
    host_keyring: &Keyring,
    accepted_messages: &mut InMemoryReplayGuard,
) -> Result<CommunicationValue, String> {
    if msg.receiver() != Some(METADATA_RELAY_ID) {
        return Err(format!(
            "sealed relay next hop was {:?}, expected metadata relay {METADATA_RELAY_ID}",
            msg.receiver()
        ));
    }

    let metadata = open_relay_metadata_with_checked(
        msg,
        std::slice::from_ref(&host_keyring),
        None,
        |signer_id| resolve_signer_key(signer_id, registered_clients).map(|key| vec![key]),
        RelayOpenOptions::new(SIGNATURE_POLICY),
        accepted_messages,
    )
    .map_err(|e| format!("metadata relay could not authenticate metadata: {e}"))?;
    println!(
        "  Metadata relay opened message_id={} signer={} final_recipient={} metadata={:?}",
        metadata.message_id(),
        metadata.signer_id(),
        metadata.final_recipient_id(),
        metadata.metadata()
    );
    println!(
        "  Metadata relay retained opaque encrypted content ({} bytes)",
        metadata
            .encrypted_content()
            .to_bytes()
            .map_err(|e| format!("opaque content serialization failed: {e}"))?
            .len()
    );

    let content_result = open_relay_content_with_limits_without_replay(
        &metadata,
        &[host_keyring],
        &[resolve_signer_key(metadata.signer_id(), registered_clients)
            .ok_or("metadata signer key disappeared")?],
        Some(FINAL_RECIPIENT_ID),
        RelayOpenOptions::new(SIGNATURE_POLICY),
    );
    if content_result.is_ok() {
        return Err("metadata relay unexpectedly decrypted final-recipient content".into());
    }
    println!("  Metadata relay cannot decrypt final-recipient content (expected)");

    forward_relay_frame(msg, metadata.final_recipient_id())
        .map_err(|e| format!("metadata relay forwarding failed: {e}"))
}

pub fn process_and_respond(
    msg: &CommunicationValue,
    tm: &TypeMap,
    client_pk: Option<&mtp::crypto::PublicKeyBundle>,
    registered_clients: &HashMap<u64, PublicKeyBundle>,
    host_keyring: &Keyring,
    accepted_direct_messages: &mut InMemoryReplayGuard,
    accepted_relay_messages: &mut InMemoryReplayGuard,
) -> Result<CommunicationValue, String> {
    if msg.is_type(CommunicationType::ProtectedMessage) {
        return process_direct_protected(
            msg,
            tm,
            client_pk,
            registered_clients,
            host_keyring,
            accepted_direct_messages,
        );
    }
    if msg.is_type(CommunicationType::Relay) {
        return process_sealed_relay(
            msg,
            registered_clients,
            host_keyring,
            accepted_relay_messages,
        );
    }

    let desc_id = DataTypeId(
        tm.data_id_enum(DataType::Description)
            .ok_or("missing Description type mapping")?,
    );
    let ts_id = DataTypeId(
        tm.data_id_enum(DataType::Timestamp)
            .ok_or("missing Timestamp type mapping")?,
    );
    let data_id = DataTypeId(
        tm.data_id_enum(DataType::Data)
            .ok_or("missing Data type mapping")?,
    );
    let flags_id = DataTypeId(
        tm.data_id_enum(DataType::Flags)
            .ok_or("missing Flags type mapping")?,
    );
    let value_id = DataTypeId(
        tm.data_id_enum(DataType::Value)
            .ok_or("missing Value type mapping")?,
    );
    let bin_id = DataTypeId(
        tm.data_id_enum(DataType::BinaryData)
            .ok_or("missing BinaryData type mapping")?,
    );
    let items_id = DataTypeId(
        tm.data_id_enum(DataType::Items)
            .ok_or("missing Items type mapping")?,
    );
    let _enc_id = DataTypeId(
        tm.data_id_enum(DataType::EncryptedPayload)
            .ok_or("missing EncryptedPayload type mapping")?,
    );
    let _sig_id = DataTypeId(
        tm.data_id_enum(DataType::SignedPayload)
            .ok_or("missing SignedPayload type mapping")?,
    );
    let _secure_id = DataTypeId(
        tm.data_id_enum(DataType::SecurePayload)
            .ok_or("missing SecurePayload type mapping")?,
    );

    let description = msg
        .get_data(DataType::Description)
        .cloned()
        .unwrap_or(DataValue::Null);
    let timestamp = msg
        .get_data(DataType::Timestamp)
        .cloned()
        .unwrap_or(DataValue::Null);
    let data = msg
        .get_data(DataType::Data)
        .cloned()
        .unwrap_or(DataValue::Null);
    let flags = msg
        .get_data(DataType::Flags)
        .cloned()
        .unwrap_or(DataValue::Null);
    let value = msg
        .get_data(DataType::Value)
        .cloned()
        .unwrap_or(DataValue::Null);
    let binary = msg
        .get_data(DataType::BinaryData)
        .cloned()
        .unwrap_or(DataValue::Null);
    let items = msg
        .get_data(DataType::Items)
        .cloned()
        .unwrap_or(DataValue::Null);

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

    if let Some(enc @ DataValue::Encrypted(_)) = msg.get_data(DataType::EncryptedPayload) {
        if let Ok(dv) = enc.decrypt(host_keyring, mtp::codec::ProtectionPurpose::from(1)) {
            if let Some(entries) = dv.as_container() {
                println!("  Decrypted EncryptedPayload: {:?}", entries);
                enc_status = format!("EncryptedPayload decrypted OK ({} entries)", entries.len());
            }
        } else {
            eprintln!("  EncryptedPayload decryption failed");
            enc_status = String::from("EncryptedPayload: decryption FAILED");
        }
    }

    if let Some(sig @ DataValue::Signed(_)) = msg.get_data(DataType::SignedPayload) {
        if let Some(pk_bundle) = client_pk {
            let signer_id = sig.as_signed().map(|signed| signed.signer_id);
            if let Some(signer_id) = signer_id
                && sig
                    .verify_with_policy(
                        signer_id,
                        pk_bundle,
                        mtp::codec::ProtectionPurpose::from(2),
                        SIGNATURE_POLICY,
                    )
                    .is_ok()
            {
                let dv = sig
                    .clone()
                    .into_verified_with_policy(
                        signer_id,
                        pk_bundle,
                        mtp::codec::ProtectionPurpose::from(2),
                        SIGNATURE_POLICY,
                    )
                    .ok();
                if let Some(entries) = dv.and_then(|value| value.as_container()) {
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

    if let Some(secure @ DataValue::Encrypted(_)) = msg.get_data(DataType::SecurePayload) {
        if let Some(pk_bundle) = client_pk {
            if let Ok(opened) = secure.decrypt(host_keyring, mtp::codec::ProtectionPurpose::from(4))
                && let Some(signed) = opened.as_signed()
                && opened
                    .verify_with_policy(
                        signed.signer_id,
                        pk_bundle,
                        mtp::codec::ProtectionPurpose::from(3),
                        SIGNATURE_POLICY,
                    )
                    .is_ok()
            {
                let signer_id = signed.signer_id;
                let dv = opened
                    .into_verified_with_policy(
                        signer_id,
                        pk_bundle,
                        mtp::codec::ProtectionPurpose::from(3),
                        SIGNATURE_POLICY,
                    )
                    .ok();
                if let Some(entries) = dv.and_then(|value| value.as_container()) {
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
        .map_err(|e| e.to_string())?
        .as_millis();

    let response = CommunicationValue::from_comm(CommunicationType::Pong, tm)
        .add_data(desc_id, description)
        .map_err(|e| e.to_string())?
        .add_data(ts_id, DataValue::UnsignedNumber(now))
        .map_err(|e| e.to_string())?
        .add_data(
            data_id,
            DataValue::Str(format!(
                "{}. {}. {}.",
                enc_status, sig_status, secure_status
            )),
        )
        .map_err(|e| e.to_string())?
        .add_data(flags_id, flags)
        .map_err(|e| e.to_string())?
        .add_data(value_id, value)
        .map_err(|e| e.to_string())?
        .add_data(bin_id, binary)
        .map_err(|e| e.to_string())?
        .add_data(items_id, items)
        .map_err(|e| e.to_string())?;
    Ok(response)
}
