use wasm_bindgen::JsCast;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

use crate::error::js_error;
use crate::transport::release_writer_lock;

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
    writer: JsValue,
    pipe_id: u32,
}

impl PipeWriter {
    pub fn new(writer: JsValue, pipe_id: u32) -> Self {
        Self { writer, pipe_id }
    }
}

#[wasm_bindgen]
impl PipeWriter {
    pub async fn write(&mut self, data: &[u8]) -> Result<(), JsValue> {
        let chunk = js_sys::Uint8Array::from(data);
        let write_fn = js_sys::Reflect::get(&self.writer, &JsValue::from_str("write"))
            .map_err(|_| js_error("missing write"))?
            .dyn_into::<js_sys::Function>()
            .map_err(|_| js_error("write not a function"))?;
        let write_promise = write_fn
            .call1(&self.writer, &chunk)
            .map_err(|e| js_error(&format!("write failed: {:?}", e)))?;
        JsFuture::from(write_promise.unchecked_into::<js_sys::Promise>()).await?;
        Ok(())
    }

    pub async fn close(self) -> Result<(), JsValue> {
        let close_fn = js_sys::Reflect::get(&self.writer, &JsValue::from_str("close"))
            .map_err(|_| js_error("missing close"))?
            .dyn_into::<js_sys::Function>()
            .map_err(|_| js_error("close not a function"))?;
        let close_promise = close_fn
            .call0(&self.writer)
            .map_err(|e| js_error(&format!("close failed: {:?}", e)))?;
        if let Err(e) = JsFuture::from(close_promise.unchecked_into::<js_sys::Promise>()).await {
            crate::transport::log_stream_error_code(&e, "pipe writer close");
        }
        release_writer_lock(&self.writer);
        Ok(())
    }

    pub fn abort(&mut self) -> Result<(), JsValue> {
        let abort_fn = js_sys::Reflect::get(&self.writer, &JsValue::from_str("abort"))
            .map_err(|_| js_error("missing abort"))?
            .dyn_into::<js_sys::Function>()
            .map_err(|_| js_error("abort not a function"))?;
        let _ = abort_fn.call0(&self.writer);
        release_writer_lock(&self.writer);
        Ok(())
    }

    pub fn pipe_id(&self) -> u32 {
        self.pipe_id
    }
}

#[wasm_bindgen]
pub struct PipeReader {
    reader: JsValue,
    description: String,
    pipe_id: u32,
    pending: Vec<u8>,
}

impl PipeReader {
    pub fn new(reader: JsValue, pipe_id: u32, description: String, pending: Vec<u8>) -> Self {
        Self {
            reader,
            pipe_id,
            description,
            pending,
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

        let read_fn = js_sys::Reflect::get(&self.reader, &JsValue::from_str("read"))
            .map_err(|_| js_error("missing read"))?
            .dyn_into::<js_sys::Function>()
            .map_err(|_| js_error("read not a function"))?;
        let promise = read_fn
            .call0(&self.reader)
            .map_err(|_| js_error("read call failed"))?
            .unchecked_into::<js_sys::Promise>();
        let result = JsFuture::from(promise).await?;

        let done = js_sys::Reflect::get(&result, &JsValue::from_str("done"))
            .ok()
            .and_then(|v| v.as_bool())
            .unwrap_or(true);
        if done {
            return Ok(JsValue::NULL);
        }

        let value = js_sys::Reflect::get(&result, &JsValue::from_str("value"))
            .map_err(|_| js_error("missing value"))?;
        Ok(js_sys::Uint8Array::new(&value).into())
    }

    pub fn pipe_id(&self) -> u32 {
        self.pipe_id
    }

    pub fn description(&self) -> String {
        self.description.clone()
    }
}
