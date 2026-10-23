use super::*;
use mtp_type_map::DataTypeId;

#[test]
fn frame_merge_uses_codec_left_bias() {
    let destination = CommunicationValue::new(CommunicationType::Ping)
        .with_id(7)
        .with_payload(DataValue::Container(vec![(
            DataTypeId(1),
            DataValue::UnsignedNumber(1),
        )]));
    let source =
        CommunicationValue::new(CommunicationType::Ping).with_payload(DataValue::Container(vec![
            (DataTypeId(1), DataValue::UnsignedNumber(99)),
            (DataTypeId(2), DataValue::UnsignedNumber(2)),
        ]));

    let merged = merge_frame_payload_from(
        &destination.to_bytes().unwrap(),
        &source.to_bytes().unwrap(),
    )
    .unwrap();
    let merged = CommunicationValue::from_bytes(&merged).unwrap();
    assert_eq!(merged.id(), Some(7));
    assert_eq!(
        merged.data(),
        Some(
            &[
                (DataTypeId(1), DataValue::UnsignedNumber(1)),
                (DataTypeId(2), DataValue::UnsignedNumber(2)),
            ][..]
        )
    );
}
