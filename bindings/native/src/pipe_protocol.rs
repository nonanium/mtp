//! Native adapters for the shared pipe negotiation engine.
use mtp_pipes::{PipeReceiver, PipeSender, TransportEvent};

impl PipeSender for crate::Sender {
    type Writer = crate::NativeSendStream;

    async fn send_pipe_message(
        &self,
        message: &mtp_codec::CommunicationValue,
    ) -> Result<(), mtp_common::CommunicationError> {
        self.send(message).await
    }

    async fn open_pipe_stream_id(
        &self,
        pipe_id: mtp_common::PipeId,
        description: &str,
    ) -> Result<mtp_core::PipeWriter<Self::Writer>, mtp_common::CommunicationError> {
        self.open_pipe_id(pipe_id, description).await
    }
}

impl PipeReceiver<crate::NativeRecvStream> for crate::Receiver {
    fn expect_pipe_id(
        &self,
        pipe_id: mtp_common::PipeId,
    ) -> Result<(), mtp_common::CommunicationError> {
        self.expect_pipe_id(pipe_id)
    }

    fn cancel_expected_pipe_id(&self, pipe_id: mtp_common::PipeId) {
        self.cancel_expected_pipe_id(pipe_id);
    }

    async fn receive_pipe_event(
        &self,
    ) -> Result<TransportEvent<crate::NativeRecvStream>, mtp_common::CommunicationError> {
        match self.receive_event().await? {
            crate::TransportEvent::Message(message) => Ok(TransportEvent::Message(message)),
            crate::TransportEvent::Pipe(reader) => Ok(TransportEvent::Pipe(reader)),
        }
    }
}
