use mtp_common::{PipeId, TransportPhase};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::warn;

#[derive(Debug)]
pub struct PipeWriter<S> {
    pub(crate) stream: S,
}

impl<S: tokio::io::AsyncWrite + Unpin> PipeWriter<S> {
    pub fn from_inner(stream: S) -> Self {
        Self { stream }
    }

    pub fn into_inner(self) -> S {
        self.stream
    }

    pub async fn finish_async(mut self) -> Result<(), mtp_common::CommunicationError> {
        tokio::io::AsyncWriteExt::shutdown(&mut self)
            .await
            .map_err(|e| {
                warn!("[PipeWriter] finish_async failed: {e}");
                mtp_common::CommunicationError::DeliveryUnknownAt {
                    phase: TransportPhase::FinishStream,
                }
            })
    }
}

impl<S: tokio::io::AsyncWrite + Unpin> AsyncWrite for PipeWriter<S> {
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

#[derive(Debug)]
pub struct PipeReader<R> {
    pub(crate) stream: R,
    pub(crate) description: String,
    pub(crate) pipe_id: PipeId,
}

impl<R> PipeReader<R> {
    pub fn from_parts_id(stream: R, description: String, pipe_id: PipeId) -> Self {
        Self {
            stream,
            description,
            pipe_id,
        }
    }

    pub fn into_parts(self) -> (R, String, PipeId) {
        (self.stream, self.description, self.pipe_id)
    }

    pub fn into_inner(self) -> R {
        self.stream
    }

    pub fn description(&self) -> &str {
        &self.description
    }

    pub fn pipe_id_value(&self) -> PipeId {
        self.pipe_id
    }
}

impl<S: crate::TransportSendStream + Unpin> PipeWriter<S> {
    pub async fn finish(mut self) -> Result<(), mtp_common::CommunicationError> {
        self.stream.finish().await
    }

    pub fn abort(&mut self) -> Result<(), mtp_common::CommunicationError> {
        self.stream.reset(0)
    }
}

impl<R: crate::TransportRecvStream> PipeReader<R> {
    pub fn stop(self, code: u32) -> Result<(), mtp_common::CommunicationError> {
        self.stream.stop(code)
    }
}

impl<R: tokio::io::AsyncRead + Unpin> AsyncRead for PipeReader<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}
