use crate::error::from_communication_error;
use crate::transport::{BrowserRecvStream, BrowserSendStream};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct PipeWriter {
    pub(crate) inner: mtp_core::PipeWriter<BrowserSendStream>,
    pub(crate) id: mtp_common::PipeId,
}
#[wasm_bindgen]
impl PipeWriter {
    pub async fn write(&mut self, data: &[u8]) -> Result<(), JsValue> {
        tokio::io::AsyncWriteExt::write_all(&mut self.inner, data)
            .await
            .map_err(|_| {
                from_communication_error(mtp_common::CommunicationError::DeliveryUnknownAt {
                    phase: mtp_common::TransportPhase::WriteFrame,
                })
            })
    }
    pub async fn close(self) -> Result<(), JsValue> {
        self.inner.finish().await.map_err(from_communication_error)
    }
    pub fn abort(&mut self) -> Result<(), JsValue> {
        self.inner.abort().map_err(from_communication_error)
    }
    pub fn pipe_id(&self) -> u32 {
        self.id.get()
    }
}

#[wasm_bindgen]
pub struct PipeReader {
    pub(crate) inner: mtp_core::PipeReader<BrowserRecvStream>,
}
#[wasm_bindgen]
impl PipeReader {
    pub async fn read(&mut self) -> Result<JsValue, JsValue> {
        let mut data = vec![0; 16 * 1024];
        let size = tokio::io::AsyncReadExt::read(&mut self.inner, &mut data)
            .await
            .map_err(|e| {
                from_communication_error(mtp_common::CommunicationError::transport(
                    mtp_common::TransportPhase::ReadFrame,
                    e.to_string(),
                ))
            })?;
        if size == 0 {
            Ok(JsValue::NULL)
        } else {
            Ok(js_sys::Uint8Array::from(&data[..size]).into())
        }
    }
    pub fn stop(self, code: u32) -> Result<(), JsValue> {
        self.inner.stop(code).map_err(from_communication_error)
    }
    pub fn pipe_id(&self) -> u32 {
        self.inner.pipe_id_value().get()
    }
    pub fn description(&self) -> String {
        self.inner.description().to_owned()
    }
}
