use mtp_codec::{CommunicationValue, DecodeError, EncodeLimits};
use mtp_common::{CommunicationError, CommunicationErrorCode, TransportPhase};

pub(crate) struct RetryClassifier;

impl RetryClassifier {
    pub(crate) fn retry_persistent_stream(error: &CommunicationError) -> bool {
        classify_retry(error) == RetryDisposition::SafeToRetry
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DecodeRejectionClass {
    Malformed,
    ResourceLimit,
    DuplicateField,
}

pub fn classify_decode_error(error: &DecodeError) -> DecodeRejectionClass {
    match error {
        DecodeError::MalformedEncoding => DecodeRejectionClass::Malformed,
        DecodeError::DepthLimit
        | DecodeError::ValueCountLimit
        | DecodeError::BlobLimit
        | DecodeError::AllocationLimit
        | DecodeError::RecipientLimit => DecodeRejectionClass::ResourceLimit,
        DecodeError::DuplicateField => DecodeRejectionClass::DuplicateField,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryDisposition {
    SafeToRetry,
    DeliveryUnknown,
    Permanent,
}

pub fn classify_retry(error: &CommunicationError) -> RetryDisposition {
    match (error.code(), error.phase()) {
        (CommunicationErrorCode::DeliveryUnknown, _) => RetryDisposition::DeliveryUnknown,
        (
            CommunicationErrorCode::Timeout,
            Some(TransportPhase::Connect | TransportPhase::Handshake | TransportPhase::OpenStream),
        )
        | (
            CommunicationErrorCode::Transport,
            Some(TransportPhase::Connect | TransportPhase::Handshake | TransportPhase::OpenStream),
        ) => RetryDisposition::SafeToRetry,
        _ => RetryDisposition::Permanent,
    }
}

pub fn encode_frame(
    value: &CommunicationValue,
    max_message_size: u64,
    close_frame_len: u32,
) -> Result<Vec<u8>, CommunicationError> {
    let bytes = value
        .to_bytes_with_limits(EncodeLimits::for_transport_message_size(max_message_size))
        .map_err(|_| CommunicationError::Encode)?;
    if bytes.len() as u64 > max_message_size || bytes.len() as u64 >= close_frame_len as u64 {
        return Err(CommunicationError::MessageTooLarge);
    }
    Ok(bytes)
}

pub fn decode_frame_length(
    prefix: [u8; 4],
    max_message_size: u64,
    close_frame_len: u32,
) -> Result<usize, CommunicationError> {
    let body_len = u32::from_be_bytes(prefix);
    if body_len == close_frame_len {
        return Err(CommunicationError::ClosedByPeer);
    }
    let frame_len = body_len as u64 + 4;
    if frame_len > max_message_size {
        return Err(CommunicationError::MessageTooLarge);
    }
    Ok(frame_len as usize)
}
