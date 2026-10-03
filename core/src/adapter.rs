use async_trait::async_trait;
use mtp_common::CommunicationError;

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait TransportSendStream:
    tokio::io::AsyncWrite + crate::PlatformSend + crate::PlatformSync + Unpin
{
    async fn write_all(&mut self, buf: &[u8]) -> Result<(), CommunicationError>;
    async fn finish(&mut self) -> Result<(), CommunicationError>;
    fn reset(&mut self, code: u32) -> Result<(), CommunicationError>;
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait TransportRecvStream:
    tokio::io::AsyncRead + crate::PlatformSend + crate::PlatformSync + Unpin
{
    async fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), CommunicationError>;
    async fn read_chunk(&mut self, max: usize) -> Result<Option<Vec<u8>>, CommunicationError>;
    fn stop(self, code: u32) -> Result<(), CommunicationError>
    where
        Self: Sized;
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait TransportConnection: Clone + crate::PlatformSend + crate::PlatformSync + 'static {
    type SendStream: TransportSendStream + 'static;
    type RecvStream: TransportRecvStream + 'static;

    async fn open_uni(&self) -> Result<Self::SendStream, CommunicationError>;
    async fn accept_uni(&self) -> Result<Self::RecvStream, CommunicationError>;
    fn close_reason(&self) -> Option<CommunicationError>;
    fn close(&self, code: u32, reason: &[u8]);
}
