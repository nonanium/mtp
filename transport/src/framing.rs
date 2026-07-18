use crate::{Policy, TransportSendStream};
use mtp_codec::CommunicationValue;
use mtp_common::CommunicationError;

/// Writes the canonical length-prefixed MTP frame used by every transport.
pub(crate) async fn write_frame<S: TransportSendStream>(
    stream: &mut S,
    value: &CommunicationValue,
    policy: &Policy,
) -> Result<(), CommunicationError> {
    let bytes = value.to_bytes().map_err(|_| CommunicationError::Encode)?;
    if bytes.len() as u64 > policy.max_message_size
        || bytes.len() as u64 >= policy.close_frame_len as u64
    {
        return Err(CommunicationError::MessageTooLarge);
    }
    stream
        .write_all(&(bytes.len() as u32).to_be_bytes())
        .await?;
    stream.write_all(&bytes).await
}
