use mtp_common::CommunicationError;
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
            .map_err(|error| match error {
                wtransport::error::StreamWriteError::Stopped(_) => {
                    CommunicationError::DeliveryUnknown
                }
                _ => CommunicationError::StreamError,
            })
    }

    async fn finish(&mut self) -> Result<(), CommunicationError> {
        self.stream.finish().await.map_err(|error| match error {
            wtransport::error::StreamWriteError::Stopped(_) => CommunicationError::DeliveryUnknown,
            _ => CommunicationError::StreamError,
        })
    }

    fn reset(&mut self, code: u32) -> Result<(), CommunicationError> {
        self.stream
            .reset(wtransport::VarInt::from_u32(code))
            .map_err(|_| CommunicationError::StreamClosed)
    }
}

#[async_trait::async_trait]
impl TransportRecvStream for NativeRecvStream {
    async fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), CommunicationError> {
        self.stream
            .read_exact(buf)
            .await
            .map_err(|_| CommunicationError::StreamClosed)
    }

    async fn read_chunk(&mut self, max: usize) -> Result<Option<Vec<u8>>, CommunicationError> {
        let mut bytes = vec![0; max];
        let Some(read) = self
            .stream
            .read(&mut bytes)
            .await
            .map_err(|_| CommunicationError::StreamError)?
        else {
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
        let opening = self
            .connection
            .open_uni()
            .await
            .map_err(|_| CommunicationError::ConnectionLost)?;
        opening
            .await
            .map(|stream| NativeSendStream { stream })
            .map_err(|_| CommunicationError::StreamError)
    }

    async fn accept_uni(&self) -> Result<Self::RecvStream, CommunicationError> {
        self.connection
            .accept_uni()
            .await
            .map(|stream| NativeRecvStream { stream })
            .map_err(|_| CommunicationError::ConnectionLost)
    }

    fn close_reason(&self) -> Option<CommunicationError> {
        self.connection
            .quic_connection()
            .close_reason()
            .map(|_| CommunicationError::StreamClosed)
    }

    fn close(&self, code: u32, reason: &[u8]) {
        self.connection
            .close(wtransport::VarInt::from_u32(code), reason);
    }
}
