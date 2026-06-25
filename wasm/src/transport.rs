use wasm_bindgen::JsCast;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use web_sys::{WebTransport, WebTransportHash, WebTransportOptions};

use crate::error::js_error;

const CLOSE_FRAME_LEN: u32 = u32::MAX;

/// Given a `SendStream` (old API with `.writable` or new API where stream IS a WritableStream),
/// return the object to call `.getWriter()` on.
fn resolve_stream_writable(send_stream: &JsValue) -> Result<JsValue, JsValue> {
    let writable = js_sys::Reflect::get(send_stream, &JsValue::from_str("writable"));
    match writable {
        Ok(val) if !val.is_undefined() && !val.is_null() => Ok(val),
        _ => Ok(send_stream.clone()),
    }
}

/// Given a `ReceiveStream` (old API with `.readable` or new API where stream IS a ReadableStream),
/// return the object to call `.getReader()` on.
fn resolve_stream_readable(recv_stream: &JsValue) -> Result<JsValue, JsValue> {
    let readable = js_sys::Reflect::get(recv_stream, &JsValue::from_str("readable"));
    match readable {
        Ok(val) if !val.is_undefined() && !val.is_null() => Ok(val),
        _ => Ok(recv_stream.clone()),
    }
}

#[derive(Clone)]
pub struct WasmTransport {
    inner: WebTransport,
}

impl WasmTransport {
    pub async fn connect(url: &str, cert_hashes: Option<Vec<String>>) -> Result<Self, JsValue> {
        let transport = match cert_hashes {
            Some(hashes) => {
                let opts = WebTransportOptions::new();
                let mut wt_hashes = Vec::new();
                for h in hashes {
                    if let Some((algo, hex_val)) = h.split_once(':') {
                        if let Ok(bytes) = hex::decode(hex_val) {
                            let hash = WebTransportHash::new();
                            hash.set_algorithm(algo);
                            hash.set_value_u8_array(&js_sys::Uint8Array::from(&bytes[..]));
                            wt_hashes.push(hash);
                        }
                    }
                }
                if !wt_hashes.is_empty() {
                    opts.set_server_certificate_hashes(&wt_hashes);
                }
                WebTransport::new_with_options(url, &opts)?
            }
            None => WebTransport::new(url)?,
        };
        JsFuture::from(transport.ready())
            .await
            .map_err(|e| js_error(&format!("WebTransport ready failed: {:?}", e)))?;
        Ok(Self { inner: transport })
    }

    pub fn inner(&self) -> &WebTransport {
        &self.inner
    }

    pub fn from_inner(inner: WebTransport) -> Self {
        Self { inner }
    }

    pub async fn send_frame(&self, frame: &[u8]) -> Result<(), JsValue> {
        let stream_promise = self.inner.create_unidirectional_stream();
        let stream = JsFuture::from(stream_promise).await?;

        let writable_or_stream = resolve_stream_writable(&stream)?;

        let writer_val = js_sys::Reflect::get(&writable_or_stream, &JsValue::from_str("getWriter"))
            .map_err(|_| js_error("missing getWriter"))?
            .dyn_into::<js_sys::Function>()
            .map_err(|_| js_error("getWriter not a function"))?
            .call0(&writable_or_stream)
            .map_err(|_| js_error("getWriter call failed"))?;

        let len = frame.len() as u32;
        let mut wire = Vec::with_capacity(4 + frame.len());
        wire.extend_from_slice(&len.to_be_bytes());
        wire.extend_from_slice(frame);

        let chunk = js_sys::Uint8Array::from(&wire[..]);

        let write_fn = js_sys::Reflect::get(&writer_val, &JsValue::from_str("write"))
            .map_err(|_| js_error("missing write"))?
            .dyn_into::<js_sys::Function>()
            .map_err(|_| js_error("write not a function"))?;
        let write_promise = write_fn
            .call1(&writer_val, &chunk)
            .map_err(|e| js_error(&format!("write failed: {:?}", e)))?;
        JsFuture::from(write_promise.unchecked_into::<js_sys::Promise>()).await?;

        let close_fn = js_sys::Reflect::get(&writer_val, &JsValue::from_str("close"))
            .map_err(|_| js_error("missing close"))?
            .dyn_into::<js_sys::Function>()
            .map_err(|_| js_error("close not a function"))?;
        let close_promise = close_fn
            .call0(&writer_val)
            .map_err(|e| js_error(&format!("close failed: {:?}", e)))?;
        JsFuture::from(close_promise.unchecked_into::<js_sys::Promise>()).await?;

        Ok(())
    }

    /// Read exactly one frame from incoming uni streams, then release the reader
    /// so `receive_loop` can pick up from where we left off.
    pub async fn read_one_frame(&self) -> Result<Vec<u8>, JsValue> {
        let incoming = self.inner.incoming_unidirectional_streams();

        let reader_fn = js_sys::Reflect::get(&incoming, &JsValue::from_str("getReader"))
            .map_err(|_| js_error("missing getReader"))?
            .dyn_into::<js_sys::Function>()
            .map_err(|_| js_error("getReader not a function"))?;
        let reader_val = reader_fn
            .call0(&incoming)
            .map_err(|_| js_error("getReader call failed"))?;

        let read_fn = js_sys::Reflect::get(&reader_val, &JsValue::from_str("read"))
            .map_err(|_| js_error("missing read"))?
            .dyn_into::<js_sys::Function>()
            .map_err(|_| js_error("read not a function"))?;
        let result_promise = read_fn
            .call0(&reader_val)
            .map_err(|_| js_error("read call failed"))?;
        let result = JsFuture::from(result_promise.unchecked_into::<js_sys::Promise>())
            .await
            .map_err(|e| js_error(&format!("read failed: {:?}", e)))?;

        // Release the reader lock so receive_loop can create its own reader
        if let Some(release_fn) =
            js_sys::Reflect::get(&reader_val, &JsValue::from_str("releaseLock"))
                .ok()
                .and_then(|f| f.dyn_into::<js_sys::Function>().ok())
        {
            let _ = release_fn.call0(&reader_val);
        }

        let done = js_sys::Reflect::get(&result, &JsValue::from_str("done"))
            .ok()
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if done {
            return Err(js_error("stream ended before frame"));
        }

        let recv_stream = js_sys::Reflect::get(&result, &JsValue::from_str("value"))
            .map_err(|_| js_error("missing value"))?;

        let readable_or_stream = resolve_stream_readable(&recv_stream)?;
        let stream_reader_fn =
            js_sys::Reflect::get(&readable_or_stream, &JsValue::from_str("getReader"))
                .map_err(|_| js_error("missing stream getReader"))?
                .dyn_into::<js_sys::Function>()
                .map_err(|_| js_error("stream getReader not a function"))?;
        let stream_reader = stream_reader_fn
            .call0(&readable_or_stream)
            .map_err(|_| js_error("stream getReader call failed"))?;

        let mut buffer: Vec<u8> = Vec::new();
        loop {
            let stream_read_fn =
                match js_sys::Reflect::get(&stream_reader, &JsValue::from_str("read"))
                    .ok()
                    .and_then(|f| f.dyn_into::<js_sys::Function>().ok())
                {
                    Some(f) => f,
                    None => break,
                };
            let chunk_promise = match stream_read_fn.call0(&stream_reader) {
                Ok(p) => p,
                Err(_) => break,
            };
            let chunk_result =
                match JsFuture::from(chunk_promise.unchecked_into::<js_sys::Promise>()).await {
                    Ok(v) => v,
                    Err(_) => break,
                };

            let chunk_done = js_sys::Reflect::get(&chunk_result, &JsValue::from_str("done"))
                .ok()
                .and_then(|v| v.as_bool())
                .unwrap_or(true);
            if chunk_done {
                return Err(js_error("stream closed before complete frame"));
            }

            if let Ok(chunk_val) = js_sys::Reflect::get(&chunk_result, &JsValue::from_str("value"))
            {
                let arr = js_sys::Uint8Array::new(&chunk_val).to_vec();
                if !arr.is_empty() {
                    buffer.extend_from_slice(&arr);
                }
            }

            if buffer.len() >= 4 {
                let frame_len = u32::from_be_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]);
                if frame_len == CLOSE_FRAME_LEN {
                    return Err(js_error("connection closed before frame"));
                }

                let frame_len = frame_len as usize;
                let Some(frame_end) = 4usize.checked_add(frame_len) else {
                    return Err(js_error("invalid frame length"));
                };
                if frame_end <= buffer.len() {
                    return Ok(buffer[4..frame_end].to_vec());
                }
            }
        }

        Err(js_error("stream ended before frame complete"))
    }

    pub async fn receive_loop(&self, on_message: js_sys::Function, on_error: js_sys::Function) {
        let incoming = self.inner.incoming_unidirectional_streams();

        let reader_fn = match js_sys::Reflect::get(&incoming, &JsValue::from_str("getReader")) {
            Ok(f) => f.dyn_into::<js_sys::Function>().unwrap(),
            Err(_) => return,
        };
        let reader_val = match reader_fn.call0(&incoming) {
            Ok(v) => v,
            Err(_) => return,
        };

        loop {
            let read_fn = match js_sys::Reflect::get(&reader_val, &JsValue::from_str("read")) {
                Ok(f) => f.dyn_into::<js_sys::Function>().unwrap(),
                Err(_) => break,
            };
            let result = match read_fn.call0(&reader_val) {
                Ok(p) => match JsFuture::from(p.unchecked_into::<js_sys::Promise>()).await {
                    Ok(v) => v,
                    Err(_) => break,
                },
                Err(_) => break,
            };

            let done = js_sys::Reflect::get(&result, &JsValue::from_str("done"))
                .ok()
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            if done {
                break;
            }

            let recv_stream = match js_sys::Reflect::get(&result, &JsValue::from_str("value")) {
                Ok(v) => v,
                Err(_) => continue,
            };

            let this = self.clone();
            let on_msg = on_message.clone();
            let on_err = on_error.clone();
            wasm_bindgen_futures::spawn_local(async move {
                let _ = this.handle_stream(recv_stream, on_msg, on_err).await;
            });
        }
    }

    async fn handle_stream(
        &self,
        recv_stream: JsValue,
        on_message: js_sys::Function,
        _on_error: js_sys::Function,
    ) -> Result<(), JsValue> {
        let readable_or_stream = resolve_stream_readable(&recv_stream)?;
        let stream_reader_fn =
            js_sys::Reflect::get(&readable_or_stream, &JsValue::from_str("getReader"))?
                .dyn_into::<js_sys::Function>()?;
        let stream_reader = stream_reader_fn.call0(&readable_or_stream)?;

        let mut buffer: Vec<u8> = Vec::new();

        loop {
            let stream_read_fn = js_sys::Reflect::get(&stream_reader, &JsValue::from_str("read"))?
                .dyn_into::<js_sys::Function>()?;
            let chunk_promise = stream_read_fn.call0(&stream_reader)?;
            let chunk_result =
                JsFuture::from(chunk_promise.unchecked_into::<js_sys::Promise>()).await?;

            let chunk_done = js_sys::Reflect::get(&chunk_result, &JsValue::from_str("done"))
                .ok()
                .and_then(|v| v.as_bool())
                .unwrap_or(true);
            if chunk_done {
                break;
            }

            if let Ok(chunk_val) = js_sys::Reflect::get(&chunk_result, &JsValue::from_str("value"))
            {
                let arr = js_sys::Uint8Array::new(&chunk_val).to_vec();
                if !arr.is_empty() {
                    buffer.extend_from_slice(&arr);
                }
            }

            // Extract all complete frames from the buffer
            while buffer.len() >= 4 {
                let frame_len = u32::from_be_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]);
                if frame_len == CLOSE_FRAME_LEN {
                    return Ok(());
                }

                let frame_len = frame_len as usize;
                let Some(frame_end) = 4usize.checked_add(frame_len) else {
                    return Err(js_error("invalid frame length"));
                };
                if frame_end > buffer.len() {
                    break;
                }
                let frame = buffer[4..frame_end].to_vec();
                let arr = js_sys::Uint8Array::from(&frame[..]);
                let _ = on_message.call1(&JsValue::NULL, &arr);
                buffer.drain(..frame_end);
            }
        }

        // Process any remaining complete frames after stream closes
        while buffer.len() >= 4 {
            let frame_len = u32::from_be_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]);
            if frame_len == CLOSE_FRAME_LEN {
                return Ok(());
            }

            let frame_len = frame_len as usize;
            let Some(frame_end) = 4usize.checked_add(frame_len) else {
                return Err(js_error("invalid frame length"));
            };
            if frame_end > buffer.len() {
                break;
            }
            let frame = buffer[4..frame_end].to_vec();
            let arr = js_sys::Uint8Array::from(&frame[..]);
            let _ = on_message.call1(&JsValue::NULL, &arr);
            buffer.drain(..frame_end);
        }

        Ok(())
    }

    pub fn close(&self) {
        let info = web_sys::WebTransportCloseInfo::new();
        let _ = self.inner.close_with_close_info(&info);
    }
}
