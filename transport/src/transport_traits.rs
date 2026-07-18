//! Transport-neutral primitives used by alternative MTP hosts.
//!
//! The existing public `Sender` and `Receiver` remain backed by
//! `wtransport`.  These traits are deliberately introduced separately so new
//! QUIC/WebTransport backends can be added without changing that API in one
//! breaking step.

use async_trait::async_trait;
use mtp_common::CommunicationError;

/// A writable unidirectional stream suitable for MTP frames.
///
/// Implementors must also implement [`tokio::io::AsyncWrite`] so that the
/// stream can back a raw pipe via [`crate::PipeWriter`] when the `pipes`
/// feature is enabled.
#[async_trait]
pub trait TransportSendStream: tokio::io::AsyncWrite + Send + Sync {
    async fn write_all(&mut self, buf: &[u8]) -> Result<(), CommunicationError>;
    async fn finish(&mut self) -> Result<(), CommunicationError>;
}

/// A readable unidirectional stream suitable for MTP frames.
///
/// Implementors must also implement [`tokio::io::AsyncRead`] so that the
/// stream can back a raw pipe via [`crate::PipeReader`] when the `pipes`
/// feature is enabled.
#[async_trait]
pub trait TransportRecvStream: tokio::io::AsyncRead + Send + Sync {
    async fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), CommunicationError>;
    async fn read_chunk(&mut self, max: usize) -> Result<Option<Vec<u8>>, CommunicationError>;
}

/// A QUIC/WebTransport connection that provides MTP's unidirectional streams.
#[async_trait]
pub trait TransportConnection: Clone + Send + Sync + 'static {
    type SendStream: TransportSendStream + 'static;
    type RecvStream: TransportRecvStream + 'static;

    async fn open_uni(&self) -> Result<Self::SendStream, CommunicationError>;
    async fn accept_uni(&self) -> Result<Self::RecvStream, CommunicationError>;
    fn close_reason(&self) -> Option<CommunicationError>;
    fn close(&self, code: u32, reason: &[u8]);
}

#[async_trait]
impl TransportSendStream for wtransport::SendStream {
    async fn write_all(&mut self, buf: &[u8]) -> Result<(), CommunicationError> {
        wtransport::SendStream::write_all(self, buf)
            .await
            .map_err(|_| CommunicationError::StreamError)
    }

    async fn finish(&mut self) -> Result<(), CommunicationError> {
        wtransport::SendStream::finish(self)
            .await
            .map_err(|_| CommunicationError::StreamError)
    }
}

#[async_trait]
impl TransportRecvStream for wtransport::RecvStream {
    async fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), CommunicationError> {
        wtransport::RecvStream::read_exact(self, buf)
            .await
            .map_err(|_| CommunicationError::StreamError)
    }

    async fn read_chunk(&mut self, max: usize) -> Result<Option<Vec<u8>>, CommunicationError> {
        let mut buf = vec![0; max];
        match wtransport::RecvStream::read(self, &mut buf).await {
            Ok(Some(size)) => {
                buf.truncate(size);
                Ok(Some(buf))
            }
            Ok(None) => Ok(None),
            Err(_) => Err(CommunicationError::StreamError),
        }
    }
}

#[async_trait]
impl TransportConnection for wtransport::Connection {
    type SendStream = wtransport::SendStream;
    type RecvStream = wtransport::RecvStream;

    async fn open_uni(&self) -> Result<Self::SendStream, CommunicationError> {
        let opening = wtransport::Connection::open_uni(self)
            .await
            .map_err(CommunicationError::ConnectionError)?;
        opening.await.map_err(|_| CommunicationError::StreamError)
    }

    async fn accept_uni(&self) -> Result<Self::RecvStream, CommunicationError> {
        wtransport::Connection::accept_uni(self)
            .await
            .map_err(|_| CommunicationError::StreamError)
    }

    fn close_reason(&self) -> Option<CommunicationError> {
        self.quic_connection()
            .close_reason()
            .map(|_| CommunicationError::StreamClosed)
    }

    fn close(&self, code: u32, reason: &[u8]) {
        self.quic_connection().close(code.into(), reason);
    }
}
