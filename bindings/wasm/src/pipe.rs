use wasm_bindgen::prelude::*;

use crate::transport::{BrowserRecvStream, BrowserSendStream, log_stream_error_code};

#[wasm_bindgen(typescript_custom_section)]
const PIPE_TS: &str = r#"
export interface PipeWriter {
  write(data: Uint8Array): Promise<void>;
  close(): Promise<void>;
  abort(): void;
  readonly pipeId: number;
}

export interface PipeReader {
  read(): Promise<Uint8Array | null>;
  readonly pipeId: number;
  readonly description: string;
}
"#;

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
        self.stream.write_all(data).await
    }

    pub async fn close(mut self) -> Result<(), JsValue> {
        let result = self.stream.finish().await;
        if let Err(error) = &result {
            log_stream_error_code(error, "pipe writer close");
        }
        self.stream.release();
        result
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

        match self.stream.read_chunk().await? {
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
