//! Native connection adapters for the transport-neutral frame engine.

#[cfg(feature = "pipes")]
use crate::PipeId;
use crate::{ConnectionHandle, NativeConnection};
use mtp_codec::{CommunicationValue, TypeMap};
use mtp_common::{CommunicationError, PingId};
pub use mtp_core::{
    DecodeRejectionClass, DecodeRejectionCounters, DecodeRejectionCounts, Policy, SendMode,
    classify_decode_error,
};
use mtp_core::{GenericReceiver, GenericSender, TransportConnection};
use std::sync::Arc;
use tokio::sync::mpsc;
use wtransport::Connection;

#[cfg(feature = "pipes")]
pub enum TransportEvent {
    Message(CommunicationValue),
    Pipe(crate::pipe::PipeReader),
}

/// Native high-level sender backed by [`mtp_core::GenericSender`].
#[derive(Clone)]
pub struct Sender {
    inner: GenericSender<NativeConnection>,
    connection: NativeConnection,
    handle: Arc<ConnectionHandle>,
}

impl Sender {
    pub fn new(connection: Connection, handle: Arc<ConnectionHandle>, policy: Arc<Policy>) -> Self {
        let connection = NativeConnection::new(connection);
        Self {
            inner: GenericSender::new(connection.clone(), policy),
            connection,
            handle,
        }
    }

    pub async fn set_type_map(&self, type_map: &TypeMap) {
        self.inner.set_type_map(type_map).await;
    }

    pub async fn send(&self, value: &CommunicationValue) -> Result<(), CommunicationError> {
        let result = self.inner.send(value).await;
        if let Err(error) = &result
            && self.connection.close_reason().is_some()
        {
            self.handle.close(Some(error.clone()));
        }
        result
    }

    pub async fn finish_stream(&self) -> Result<(), CommunicationError> {
        self.inner.finish_stream().await
    }

    #[cfg(feature = "pipes")]
    pub async fn open_pipe_id(
        &self,
        pipe_id: PipeId,
        description: &str,
    ) -> Result<crate::pipe::PipeWriter, CommunicationError> {
        self.inner.open_pipe_id(pipe_id, description).await
    }

    pub fn close_immediate(&self) {
        self.close_transport();
    }
    pub async fn close(&self) {
        self.close_transport();
    }
    fn close_transport(&self) {
        self.inner.close();
        self.handle.close(Some(CommunicationError::ClosedLocally));
    }
    pub fn handle(&self) -> &Arc<ConnectionHandle> {
        &self.handle
    }
    pub fn is_open(&self) -> bool {
        self.handle.is_open() && self.inner.is_open()
    }
    pub fn is_closed(&self) -> bool {
        !self.is_open()
    }
    pub fn close_reason(&self) -> Option<CommunicationError> {
        self.handle
            .close_reason()
            .or_else(|| self.inner.close_reason())
    }
}

/// Native high-level receiver backed by [`mtp_core::GenericReceiver`].
#[derive(Clone)]
pub struct Receiver {
    inner: GenericReceiver<NativeConnection>,
    handle: Arc<ConnectionHandle>,
}

impl Receiver {
    pub fn new(connection: Connection, handle: Arc<ConnectionHandle>, policy: Arc<Policy>) -> Self {
        Self {
            inner: GenericReceiver::new(NativeConnection::new(connection), policy),
            handle,
        }
    }

    #[cfg(feature = "host")]
    pub(crate) fn new_for_handshake(
        connection: Connection,
        handle: Arc<ConnectionHandle>,
        policy: Arc<Policy>,
    ) -> Self {
        Self::new(connection, handle, policy)
    }

    pub async fn receive(&self) -> Result<CommunicationValue, CommunicationError> {
        self.inner.receive().await
    }
    pub async fn set_type_map(&self, type_map: &TypeMap) {
        self.inner.set_type_map(type_map).await;
    }
    pub fn set_max_message_size(&self, max_message_size: u64) {
        self.inner.set_max_message_size(max_message_size);
    }
    pub fn decode_rejection_counts(&self) -> DecodeRejectionCounts {
        self.inner.decode_rejection_counts()
    }
    pub fn respond_to_pings(&self, sender: Sender) {
        self.inner.respond_to_pings_now(sender.inner);
    }
    pub async fn observe_pongs_bounded(&self, observer: mpsc::Sender<CommunicationValue>) {
        self.inner.observe_pongs_bounded(observer).await;
    }
    pub async fn set_expected_pong_id_value(&self, expected: Option<PingId>) {
        self.inner.set_expected_pong_id_value(expected).await;
    }

    #[cfg(feature = "pipes")]
    pub async fn receive_event(&self) -> Result<TransportEvent, CommunicationError> {
        match self.inner.receive_event().await? {
            mtp_core::TransportEvent::Message(message) => Ok(TransportEvent::Message(message)),
            mtp_core::TransportEvent::Pipe(reader) => Ok(TransportEvent::Pipe(reader)),
        }
    }

    #[cfg(feature = "pipes")]
    pub async fn receive_pipe(&self) -> Result<crate::pipe::PipeReader, CommunicationError> {
        self.inner.receive_pipe().await
    }
    #[cfg(feature = "pipes")]
    pub fn try_receive_pipe(&self) -> Result<Option<crate::pipe::PipeReader>, CommunicationError> {
        self.inner.try_receive_pipe()
    }
    #[cfg(feature = "pipes")]
    pub fn expect_pipe_id(&self, pipe_id: PipeId) -> Result<(), CommunicationError> {
        self.inner.expect_pipe_id(pipe_id)
    }
    #[cfg(feature = "pipes")]
    pub fn cancel_expected_pipe_id(&self, pipe_id: PipeId) {
        self.inner.cancel_expected_pipe_id(pipe_id);
    }

    pub fn handle(&self) -> &Arc<ConnectionHandle> {
        &self.handle
    }
    pub fn close(&self) {
        self.handle.close(None);
    }
    pub fn is_open(&self) -> bool {
        self.handle.is_open() && self.inner.is_open()
    }
    pub fn is_closed(&self) -> bool {
        !self.is_open()
    }
    pub fn close_reason(&self) -> Option<CommunicationError> {
        self.handle
            .close_reason()
            .or_else(|| self.inner.close_reason())
    }
}
