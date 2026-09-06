use std::time::{Duration, Instant};

use mtp::client::MTPConnection;
use mtp::codec::{
    CommunicationType, DataType, DataValue, ProtectedMessageBuilder, ProtectionPolicy,
    ProtectionPurpose, RelayOpenOptions, SealedRelayBuilder, SignaturePolicy, TypeMap,
    open_relay_content_with_limits_without_replay, open_relay_metadata_without_replay,
};
use mtp::common::unix_time_millis;
use mtp::crypto::{Ed25519Signer, Keyring, PublicKeyBundle};

/// The direct protected example sends to the host as the destination MTP ID.
pub const DIRECT_DESTINATION_ID: u64 = 1;

/// The example host acts as the metadata relay and uses this stable MTP ID.
pub const METADATA_RELAY_ID: u64 = 1;

/// This keyring represents a final recipient independently of the transport
/// identity used by the example client.
pub const FINAL_RECIPIENT_ID: u64 = 7_002;

const DIRECT_SIGNATURE_PURPOSE: u8 = 0x40;
const DIRECT_ENCRYPTION_PURPOSE: u8 = 0x41;
const RELAY_SIGNATURE_POLICY: ProtectionPolicy = ProtectionPolicy {
    signature: SignaturePolicy::Ed25519,
};

fn type_id(
    data_type: DataType,
    type_map: &TypeMap,
) -> Result<mtp::codec::DataTypeId, Box<dyn std::error::Error>> {
    data_type
        .try_to_id(type_map)
        .ok_or_else(|| format!("missing example data type mapping for {data_type}").into())
}

fn application_value(text: &str, number: u128) -> Result<DataValue, Box<dyn std::error::Error>> {
    let type_map = TypeMap::latest();
    Ok(DataValue::Container(vec![
        (
            type_id(DataType::ExampleText, &type_map)?,
            DataValue::Str(text.to_owned()),
        ),
        (
            type_id(DataType::ExampleNumber, &type_map)?,
            DataValue::UnsignedNumber(number),
        ),
    ]))
}

fn relay_metadata() -> Result<DataValue, Box<dyn std::error::Error>> {
    let type_map = TypeMap::latest();
    Ok(DataValue::Container(vec![
        (
            type_id(DataType::ExampleRole, &type_map)?,
            DataValue::Str("metadata relay".into()),
        ),
        (
            type_id(DataType::ExampleMetadata, &type_map)?,
            DataValue::Str("application metadata remains authenticated and opaque to MTP".into()),
        ),
    ]))
}

/// Send an application value directly to the host without constructing a
/// Relay frame. The outer sender is deliberately absent so the example also
/// demonstrates that the protected signer is independent of transport auth.
pub async fn send_direct_protected(
    conn: &MTPConnection,
    signer_id: u64,
    signer_keyring: &Keyring,
    recipient_public_key: &PublicKeyBundle,
) -> Result<Duration, Box<dyn std::error::Error>> {
    let signer = Ed25519Signer::new(&signer_keyring.sig_cl_secret_key)?;
    let created_at = unix_time_millis()?;
    let message_id = format!("example-direct-{created_at}-{}", rand::random::<u32>());
    let content = application_value("direct protected delivery", 40)?;
    let frame = ProtectedMessageBuilder::new(
        "ProtectedMessage",
        content,
        signer_id,
        DIRECT_DESTINATION_ID,
        &signer,
        ProtectionPurpose::from(DIRECT_SIGNATURE_PURPOSE),
        ProtectionPurpose::from(DIRECT_ENCRYPTION_PURPOSE),
    )
    .message_id(message_id)
    .created_at(created_at)
    .recipients(vec![recipient_public_key.clone()])
    .type_map(&TypeMap::latest())
    .build()?;

    println!(
        "Sending direct protected frame: type=ProtectedMessage receiver={} outer_sender=absent signer={signer_id}",
        DIRECT_DESTINATION_ID
    );
    let started = Instant::now();
    conn.sender.send(&frame).await?;
    let response = conn.receive().await?;
    if !response.is_type(CommunicationType::Pong) {
        return Err(format!("direct protected response was not Pong: {response}").into());
    }
    let elapsed = started.elapsed();
    println!(
        "Direct protected value verified and acknowledged in {:.3}ms",
        elapsed.as_secs_f64() * 1000.0
    );
    Ok(elapsed)
}

/// Send a sealed relay through the host, which can open metadata but cannot
/// decrypt the content. The final recipient is represented by a separate
/// keyring so the example does not conflate relay and content access.
pub async fn send_sealed_relay(
    conn: &MTPConnection,
    signer_id: u64,
    signer_keyring: &Keyring,
    metadata_relay_public_key: &PublicKeyBundle,
) -> Result<Duration, Box<dyn std::error::Error>> {
    let type_map = TypeMap::latest();
    let final_recipient_keyring = Keyring::generate();
    let final_recipient_public_key = final_recipient_keyring.public_key_bundle();
    let signer = Ed25519Signer::new(&signer_keyring.sig_cl_secret_key)?;
    let created_at = unix_time_millis()?;
    let message_id = format!("example-relay-{created_at}-{}", rand::random::<u32>());
    let frame = SealedRelayBuilder::new(
        "ProtectedMessage",
        application_value("sealed relay delivery", 41)?,
        signer_id,
        FINAL_RECIPIENT_ID,
        METADATA_RELAY_ID,
        &signer,
    )
    .message_id(message_id)
    .created_at(created_at)
    .metadata(relay_metadata()?)
    .metadata_recipients(vec![
        metadata_relay_public_key.clone(),
        final_recipient_public_key.clone(),
    ])
    .content_recipients(vec![final_recipient_public_key])
    .type_map(&type_map)
    .build()?;

    println!(
        "Sending sealed relay: next_hop={} final_recipient={} metadata_recipients=2 content_recipients=1",
        METADATA_RELAY_ID, FINAL_RECIPIENT_ID
    );
    let started = Instant::now();
    conn.sender.send(&frame).await?;
    let forwarded = conn.receive().await?;
    if !forwarded.is_type(CommunicationType::Relay) {
        return Err(format!("relay response was not Relay: {forwarded}").into());
    }
    if forwarded.sender().is_some() || forwarded.receiver() != Some(FINAL_RECIPIENT_ID) {
        return Err("relay forwarding changed the sealed-sender boundary".into());
    }

    let metadata = open_relay_metadata_without_replay(
        &forwarded,
        &final_recipient_keyring,
        signer_id,
        &signer_keyring.public_key_bundle(),
        RelayOpenOptions::new(RELAY_SIGNATURE_POLICY),
    )?;
    let application_metadata = metadata
        .metadata()
        .ok_or("forwarded relay metadata was missing")?;
    let content = open_relay_content_with_limits_without_replay(
        &metadata,
        &[&final_recipient_keyring],
        &[signer_keyring.public_key_bundle()],
        Some(FINAL_RECIPIENT_ID),
        RelayOpenOptions::new(RELAY_SIGNATURE_POLICY),
    )?;
    if content.message_type != "ProtectedMessage" {
        return Err(format!("unexpected relay message type: {}", content.message_type).into());
    }
    let expected_metadata = relay_metadata()?;
    if application_metadata != &expected_metadata {
        return Err("relay application metadata changed during forwarding".into());
    }
    let expected_content = application_value("sealed relay delivery", 41)?;
    if content.content != expected_content {
        return Err("relay application content changed during forwarding".into());
    }

    let elapsed = started.elapsed();
    println!(
        "Final recipient opened authenticated metadata and content in {:.3}ms (message_id={})",
        elapsed.as_secs_f64() * 1000.0,
        metadata.message_id()
    );
    Ok(elapsed)
}
