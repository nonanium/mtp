use std::cell::RefCell;
use std::rc::Rc;

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

/// Outcome of reading the next framed message from the incoming stream(s).
enum FrameOutcome {
    /// A complete application frame.
    Frame(Vec<u8>),
    /// The peer sent an explicit close frame (length == `u32::MAX`).
    Closed,
    /// The incoming-streams readable ended (transport gone), no more frames.
    Ended,
}

/*
 * Debug-log the exact bytes about to be written to the WebTransport stream.
 *
 * Wire layout (note the DOUBLE length prefix):
 *   [0..4]   outer_len  u32 BE  - added by send_frame (= inner frame length)
 *   [4..8]   inner_len  u32 BE  - added by CommunicationValue::to_bytes
 *   [8..10]  comm_type  u16 BE  - e.g. Identification
 *   [10]     flags      u8
 *   [11..]   id/sender/receiver/signature/data, gated by `flags`
 */
fn log_frame_bytes(wire: &[u8]) {
    let hex: String = wire.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ");

    let outer_len = wire.get(0..4).map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]));
    let inner_len = wire.get(4..8).map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]));
    let comm_type = wire.get(8..10).map(|b| u16::from_be_bytes([b[0], b[1]]));
    let flags = wire.get(10).copied();

    web_sys::console::log_1(
        &format!(
            "mtp-wasm send_frame: {len} bytes | outer_len={outer_len:?} inner_len={inner_len:?} \
             comm_type={comm_type:?} flags={flags:?}\n{hex}",
            len = wire.len(),
        )
        .into(),
    );
}

/*
 * WebTransport client transport.
 *
 * The native host sends with a *persistent* uni-directional stream: the auth
 * `Challenge` and the final `IdentificationResponse`/`RegisterResponse` arrive
 * as two length-prefixed frames on the *same* QUIC stream, and later
 * application messages may arrive on subsequent streams. The reader state
 * (`streams_reader`, `stream_reader`, `buffer`) is therefore shared via `Rc`
 * between the handshake (`read_one_frame`) and the background `receive_loop`,
 * so frames are never lost across the boundary and multiple frames can be read
 * from one stream.
 */
#[derive(Clone)]
pub struct WasmTransport {
    inner: WebTransport,
    /// Reader over `incoming_unidirectional_streams()` (a singleton stream of streams).
    streams_reader: Rc<RefCell<Option<JsValue>>>,
    /// Reader over the host's current uni-directional stream, if one is open.
    stream_reader: Rc<RefCell<Option<JsValue>>>,
    /// Bytes already read from the current stream but not yet consumed as a frame.
    buffer: Rc<RefCell<Vec<u8>>>,
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
        Ok(Self {
            inner: transport,
            streams_reader: Rc::new(RefCell::new(None)),
            stream_reader: Rc::new(RefCell::new(None)),
            buffer: Rc::new(RefCell::new(Vec::new())),
        })
    }

    pub fn inner(&self) -> &WebTransport {
        &self.inner
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

        log_frame_bytes(&wire);

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

    /// Get (creating once) the reader over `incoming_unidirectional_streams()`.
    fn ensure_streams_reader(&self) -> Result<JsValue, JsValue> {
        if let Some(reader) = self.streams_reader.borrow().clone() {
            return Ok(reader);
        }
        let incoming = self.inner.incoming_unidirectional_streams();
        let reader = js_sys::Reflect::get(&incoming, &JsValue::from_str("getReader"))
            .map_err(|_| js_error("missing getReader"))?
            .dyn_into::<js_sys::Function>()
            .map_err(|_| js_error("getReader not a function"))?
            .call0(&incoming)
            .map_err(|_| js_error("getReader call failed"))?;
        *self.streams_reader.borrow_mut() = Some(reader.clone());
        Ok(reader)
    }

    /// Accept the next incoming uni-directional stream and make it current.
    /// Returns `false` if the incoming-streams readable has ended.
    async fn open_next_stream(&self) -> Result<bool, JsValue> {
        let streams_reader = self.ensure_streams_reader()?;

        let read_fn = js_sys::Reflect::get(&streams_reader, &JsValue::from_str("read"))
            .map_err(|_| js_error("missing read"))?
            .dyn_into::<js_sys::Function>()
            .map_err(|_| js_error("read not a function"))?;
        let result = JsFuture::from(
            read_fn
                .call0(&streams_reader)
                .map_err(|_| js_error("read call failed"))?
                .unchecked_into::<js_sys::Promise>(),
        )
        .await
        .map_err(|e| js_error(&format!("accept stream failed: {:?}", e)))?;

        let done = js_sys::Reflect::get(&result, &JsValue::from_str("done"))
            .ok()
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if done {
            return Ok(false);
        }

        let recv_stream = js_sys::Reflect::get(&result, &JsValue::from_str("value"))
            .map_err(|_| js_error("missing value"))?;
        let readable = resolve_stream_readable(&recv_stream)?;
        let reader = js_sys::Reflect::get(&readable, &JsValue::from_str("getReader"))
            .map_err(|_| js_error("missing stream getReader"))?
            .dyn_into::<js_sys::Function>()
            .map_err(|_| js_error("stream getReader not a function"))?
            .call0(&readable)
            .map_err(|_| js_error("stream getReader call failed"))?;

        *self.stream_reader.borrow_mut() = Some(reader);
        Ok(true)
    }

    /// Read one chunk from the current stream. `Ok(None)` means the stream ended.
    async fn read_chunk(&self) -> Result<Option<Vec<u8>>, JsValue> {
        let reader = match self.stream_reader.borrow().clone() {
            Some(r) => r,
            None => return Ok(None),
        };

        let read_fn = js_sys::Reflect::get(&reader, &JsValue::from_str("read"))
            .map_err(|_| js_error("missing read"))?
            .dyn_into::<js_sys::Function>()
            .map_err(|_| js_error("read not a function"))?;
        let result = JsFuture::from(
            read_fn
                .call0(&reader)
                .map_err(|_| js_error("read call failed"))?
                .unchecked_into::<js_sys::Promise>(),
        )
        .await
        .map_err(|e| js_error(&format!("read failed: {:?}", e)))?;

        let done = js_sys::Reflect::get(&result, &JsValue::from_str("done"))
            .ok()
            .and_then(|v| v.as_bool())
            .unwrap_or(true);
        if done {
            return Ok(None);
        }

        let value = js_sys::Reflect::get(&result, &JsValue::from_str("value"))
            .map_err(|_| js_error("missing value"))?;
        Ok(Some(js_sys::Uint8Array::new(&value).to_vec()))
    }

    /// Try to pull one complete frame out of the buffer without reading more.
    fn parse_buffer(&self) -> Result<Option<FrameOutcome>, JsValue> {
        let buf = self.buffer.borrow();
        if buf.len() < 4 {
            return Ok(None);
        }
        let frame_len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        if frame_len == CLOSE_FRAME_LEN {
            return Ok(Some(FrameOutcome::Closed));
        }
        let frame_len = frame_len as usize;
        let Some(frame_end) = 4usize.checked_add(frame_len) else {
            return Err(js_error("invalid frame length"));
        };
        if frame_end > buf.len() {
            return Ok(None);
        }
        let frame = buf[4..frame_end].to_vec();
        drop(buf);
        self.buffer.borrow_mut().drain(..frame_end);
        Ok(Some(FrameOutcome::Frame(frame)))
    }

    /*
     * Read the next framed message from the host. Frames are length-prefixed
     * (u32 big-endian) and may be packed several-per-stream (the host reuses a
     * persistent uni stream) or one-per-stream; both are handled by buffering
     * across reads and advancing to the next stream when the current one ends.
     */
    async fn next_frame(&self) -> Result<FrameOutcome, JsValue> {
        loop {
            if let Some(outcome) = self.parse_buffer()? {
                return Ok(outcome);
            }

            let have_stream = self.stream_reader.borrow().is_some();
            if !have_stream && !self.open_next_stream().await? {
                return Ok(FrameOutcome::Ended);
            }

            match self.read_chunk().await? {
                Some(chunk) => {
                    if !chunk.is_empty() {
                        self.buffer.borrow_mut().extend_from_slice(&chunk);
                    }
                }
                None => {
                    // Current stream finished; the next frame (if any) is on a
                    // subsequent stream. Any trailing partial bytes are dropped
                    // since the host never splits a frame across streams.
                    *self.stream_reader.borrow_mut() = None;
                    self.buffer.borrow_mut().clear();
                }
            }
        }
    }

    /// Read exactly one application frame (used during the auth handshake).
    pub async fn read_one_frame(&self) -> Result<Vec<u8>, JsValue> {
        match self.next_frame().await? {
            FrameOutcome::Frame(frame) => Ok(frame),
            FrameOutcome::Closed => Err(js_error("connection closed before frame")),
            FrameOutcome::Ended => Err(js_error("stream ended before frame")),
        }
    }

    /// Background loop: deliver every incoming frame to `on_message` until the
    /// connection closes. Shares reader state with `read_one_frame`, so frames
    /// buffered during the handshake are not lost.
    pub async fn receive_loop(&self, on_message: js_sys::Function, on_error: js_sys::Function) {
        loop {
            match self.next_frame().await {
                Ok(FrameOutcome::Frame(frame)) => {
                    let arr = js_sys::Uint8Array::from(&frame[..]);
                    let _ = on_message.call1(&JsValue::NULL, &arr);
                }
                Ok(FrameOutcome::Closed) | Ok(FrameOutcome::Ended) => break,
                Err(e) => {
                    let _ = on_error.call1(&JsValue::NULL, &e);
                    break;
                }
            }
        }
    }

    pub fn close(&self) {
        let info = web_sys::WebTransportCloseInfo::new();
        let _ = self.inner.close_with_close_info(&info);
    }
}
