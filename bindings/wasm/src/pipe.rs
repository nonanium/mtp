use wasm_bindgen::prelude::*;

use crate::error::from_communication_error;
use crate::transport::{BrowserRecvStream, BrowserSendStream, log_stream_error_code};
use mtp_common::{CommunicationError, TransportPhase};

#[wasm_bindgen]
pub struct PipeWriter {
    stream: BrowserSendStream,
    pipe_id: u32,
}

impl PipeWriter {
    pub(crate) fn new(stream: BrowserSendStream, pipe_id: u32) -> Self {
        Self { stream, pipe_id }
    }
}

impl Drop for PipeWriter {
    fn drop(&mut self) {
        self.stream.release();
    }
}

#[wasm_bindgen]
impl PipeWriter {
    pub async fn write(&mut self, data: &[u8]) -> Result<(), JsValue> {
        self.stream.write_all(data).await.map_err(|_| {
            from_communication_error(CommunicationError::DeliveryUnknownAt {
                phase: TransportPhase::WriteFrame,
            })
        })
    }

    pub async fn close(mut self) -> Result<(), JsValue> {
        let result = self.stream.finish().await;
        if let Err(error) = &result {
            log_stream_error_code(error, "pipe writer close");
        }
        self.stream.release();
        result.map_err(|_| {
            from_communication_error(CommunicationError::DeliveryUnknownAt {
                phase: TransportPhase::FinishStream,
            })
        })
    }

    pub fn abort(&mut self) -> Result<(), JsValue> {
        let result = self.stream.reset(0);
        self.stream.release();
        result
    }

    pub fn pipe_id(&self) -> u32 {
        self.pipe_id
    }
}

#[wasm_bindgen]
pub struct PipeReader {
    stream: BrowserRecvStream,
    description: String,
    pipe_id: u32,
    pending: Vec<u8>,
    finished: bool,
}

impl PipeReader {
    pub(crate) fn new(
        stream: BrowserRecvStream,
        pipe_id: u32,
        description: String,
        pending: Vec<u8>,
    ) -> Self {
        Self {
            stream,
            pipe_id,
            description,
            pending,
            finished: false,
        }
    }
}

#[wasm_bindgen]
impl PipeReader {
    pub async fn read(&mut self) -> Result<JsValue, JsValue> {
        if !self.pending.is_empty() {
            let data = std::mem::take(&mut self.pending);
            return Ok(js_sys::Uint8Array::from(&data[..]).into());
        }

        if self.finished {
            return Ok(JsValue::NULL);
        }

        match self.stream.read_chunk().await.map_err(|_| {
            from_communication_error(CommunicationError::transport(
                TransportPhase::ReadFrame,
                "pipe read failed",
            ))
        })? {
            Some(value) => Ok(js_sys::Uint8Array::from(&value[..]).into()),
            None => {
                self.stream.release();
                self.finished = true;
                Ok(JsValue::NULL)
            }
        }
    }

    pub fn pipe_id(&self) -> u32 {
        self.pipe_id
    }

    pub fn description(&self) -> String {
        self.description.clone()
    }
}

impl Drop for PipeReader {
    fn drop(&mut self) {
        self.stream.release();
    }
}
