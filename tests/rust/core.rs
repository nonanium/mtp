use mtp_codec::{CommunicationType, CommunicationValue, DataValue};

#[test]
fn framing_preserves_a_generic_payload() {
    let payload = DataValue::Array(vec![
        DataValue::Str("payload".into()),
        DataValue::Bytes(vec![1, 2, 3]),
    ]);
    let frame = CommunicationValue::new(CommunicationType::Pong).with_payload(payload.clone());
    let bytes = mtp_core::encode_frame(&frame, 1024, 64).unwrap();

    let body_len = u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize;
    assert_eq!(body_len, bytes.len() - 4);
    let decoded = CommunicationValue::from_bytes(&bytes).unwrap();
    assert_eq!(decoded.into_payload(), payload);
}
