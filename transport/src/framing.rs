use crate::{Policy, TransportSendStream};
use mtp_codec::{CommunicationValue, EncodeLimits};
use mtp_common::CommunicationError;

/// Classifies failures that may be recovered by replacing a persistent
/// application stream. Encoding and frame-size failures are deterministic and
/// must reach the caller without opening more streams.
pub(crate) struct RetryClassifier;

impl RetryClassifier {
    pub(crate) fn retry_persistent_stream(error: &CommunicationError) -> bool {
        matches!(
            error,
            CommunicationError::StreamError | CommunicationError::StreamClosed
        )
    }
}

/// Writes the canonical self-framed MTP value used by every transport.
///
/// `CommunicationValue` already begins with the four-byte body length. The
/// transport writes that representation directly so a frame does not carry a
/// redundant outer length prefix.
pub(crate) async fn write_frame<S: TransportSendStream>(
    stream: &mut S,
    value: &CommunicationValue,
    policy: &Policy,
) -> Result<(), CommunicationError> {
    let bytes = value
        .to_bytes_with_limits(EncodeLimits::for_transport_message_size(
            policy.max_message_size,
        ))
        .map_err(|_| CommunicationError::Encode)?;
    if bytes.len() as u64 > policy.max_message_size
        || bytes.len() as u64 >= policy.close_frame_len as u64
    {
        return Err(CommunicationError::MessageTooLarge);
    }
    stream.write_all(&bytes).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use mtp_codec::{CommunicationType, DataValue};
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::AsyncWrite;

    #[derive(Default)]
    struct BufferStream {
        bytes: Vec<u8>,
    }

    impl AsyncWrite for BufferStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            self.bytes.extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[async_trait]
    impl TransportSendStream for BufferStream {
        async fn write_all(&mut self, buf: &[u8]) -> Result<(), CommunicationError> {
            self.bytes.extend_from_slice(buf);
            Ok(())
        }

        async fn finish(&mut self) -> Result<(), CommunicationError> {
            Ok(())
        }

        fn reset(&mut self, _code: u32) -> Result<(), CommunicationError> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn framing_preserves_a_generic_payload() {
        let payload = DataValue::Array(vec![
            DataValue::Str("payload".into()),
            DataValue::Bytes(vec![1, 2, 3]),
        ]);
        let frame = CommunicationValue::new(CommunicationType::Pong).with_payload(payload.clone());
        let mut stream = BufferStream::default();

        write_frame(&mut stream, &frame, &Policy::default())
            .await
            .unwrap();

        let body_len = u32::from_be_bytes(stream.bytes[..4].try_into().unwrap()) as usize;
        assert_eq!(body_len, stream.bytes.len() - 4);
        let decoded = CommunicationValue::from_bytes(&stream.bytes).unwrap();
        assert_eq!(decoded.into_payload(), payload);
    }
}
