use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::warn;

#[derive(Debug)]
pub struct PipeWriter<S> {
    pub(crate) stream: S,
}

impl<S: tokio::io::AsyncWrite + Send + Unpin> PipeWriter<S> {
    pub fn into_inner(self) -> S {
        self.stream
    }

    pub async fn finish_async(mut self) -> Result<(), mtp_common::CommunicationError> {
        tokio::io::AsyncWriteExt::shutdown(&mut self)
            .await
            .map_err(|e| {
                warn!("[PipeWriter] finish_async failed: {e}");
                mtp_common::CommunicationError::StreamError
            })
    }
}

impl<S: tokio::io::AsyncWrite + Send + Unpin> AsyncWrite for PipeWriter<S> {
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
    pub(crate) pipe_id: u32,
}

impl<R> PipeReader<R> {
    pub fn into_inner(self) -> R {
        self.stream
    }

    pub fn description(&self) -> &str {
        &self.description
    }

    pub fn pipe_id(&self) -> u32 {
        self.pipe_id
    }
}

impl<R: tokio::io::AsyncRead + Send + Unpin> AsyncRead for PipeReader<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}
