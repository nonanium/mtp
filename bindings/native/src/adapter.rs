use mtp_common::{CommunicationError, TransportPhase};
use mtp_core::{TransportConnection, TransportRecvStream, TransportSendStream};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[derive(Clone)]
pub struct NativeConnection {
    connection: wtransport::Connection,
}

pub struct NativeSendStream {
    stream: wtransport::SendStream,
}

pub struct NativeRecvStream {
    stream: wtransport::RecvStream,
}

impl NativeConnection {
    pub fn new(connection: wtransport::Connection) -> Self {
        Self { connection }
    }

    pub fn inner(&self) -> &wtransport::Connection {
        &self.connection
    }
}

impl NativeSendStream {
    pub fn into_inner(self) -> wtransport::SendStream {
        self.stream
    }
}

impl NativeRecvStream {
    pub fn into_inner(self) -> wtransport::RecvStream {
        self.stream
    }
}

fn connection_error(error: wtransport::error::ConnectionError) -> CommunicationError {
    match error {
        wtransport::error::ConnectionError::ConnectionClosed(_)
        | wtransport::error::ConnectionError::ApplicationClosed(_) => {
            CommunicationError::ClosedByPeer
        }
        wtransport::error::ConnectionError::LocallyClosed
        | wtransport::error::ConnectionError::LocalH3Error(_) => CommunicationError::ClosedLocally,
        wtransport::error::ConnectionError::TimedOut
        | wtransport::error::ConnectionError::QuicProto(_)
        | wtransport::error::ConnectionError::CidsExhausted => CommunicationError::ConnectionLost,
    }
}

fn read_error(error: wtransport::error::StreamReadError) -> CommunicationError {
    match error {
        wtransport::error::StreamReadError::Reset(_) => CommunicationError::ClosedByPeer,
        wtransport::error::StreamReadError::NotConnected
        | wtransport::error::StreamReadError::QuicProto => CommunicationError::ConnectionLost,
    }
}

impl AsyncWrite for NativeSendStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

impl AsyncRead for NativeRecvStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

#[async_trait::async_trait]
impl TransportSendStream for NativeSendStream {
    async fn write_all(&mut self, buf: &[u8]) -> Result<(), CommunicationError> {
        self.stream
            .write_all(buf)
            .await
            // Once wtransport has accepted a write attempt it cannot tell us
            // whether any prefix reached the peer. Retrying could duplicate an
            // application message, so preserve that ambiguity for the core
            // framing policy.
            .map_err(|_| CommunicationError::DeliveryUnknownAt {
                phase: TransportPhase::WriteFrame,
            })
    }

    async fn finish(&mut self) -> Result<(), CommunicationError> {
        self.stream
            .finish()
            .await
            .map_err(|_| CommunicationError::DeliveryUnknownAt {
                phase: TransportPhase::FinishStream,
            })
    }

    fn reset(&mut self, code: u32) -> Result<(), CommunicationError> {
        self.stream
            .reset(wtransport::VarInt::from_u32(code))
            .map_err(|_| CommunicationError::ClosedLocally)
    }
}

#[async_trait::async_trait]
impl TransportRecvStream for NativeRecvStream {
    async fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), CommunicationError> {
        self.stream
            .read_exact(buf)
            .await
            .map_err(|error| match error {
                wtransport::error::StreamReadExactError::FinishedEarly(_) => {
                    CommunicationError::ClosedByPeer
                }
                wtransport::error::StreamReadExactError::Read(error) => read_error(error),
            })
    }

    async fn read_chunk(&mut self, max: usize) -> Result<Option<Vec<u8>>, CommunicationError> {
        let mut bytes = vec![0; max];
        let Some(read) = self.stream.read(&mut bytes).await.map_err(read_error)? else {
            return Ok(None);
        };
        bytes.truncate(read);
        Ok(Some(bytes))
    }

    fn stop(self, code: u32) -> Result<(), CommunicationError> {
        self.stream.stop(wtransport::VarInt::from_u32(code));
        Ok(())
    }
}

#[async_trait::async_trait]
impl TransportConnection for NativeConnection {
    type SendStream = NativeSendStream;
    type RecvStream = NativeRecvStream;

    async fn open_uni(&self) -> Result<Self::SendStream, CommunicationError> {
        let opening = self.connection.open_uni().await.map_err(|error| {
            CommunicationError::transport(TransportPhase::OpenStream, error.to_string())
        })?;
        opening
            .await
            .map(|stream| NativeSendStream { stream })
            .map_err(|error| {
                CommunicationError::transport(TransportPhase::OpenStream, error.to_string())
            })
    }

    async fn accept_uni(&self) -> Result<Self::RecvStream, CommunicationError> {
        self.connection
            .accept_uni()
            .await
            .map(|stream| NativeRecvStream { stream })
            .map_err(connection_error)
    }

    fn close_reason(&self) -> Option<CommunicationError> {
        self.connection
            .quic_connection()
            .close_reason()
            .map(|error| connection_error(error.into()))
    }

    fn close(&self, code: u32, reason: &[u8]) {
        self.connection
            .close(wtransport::VarInt::from_u32(code), reason);
    }
}
