use std::cell::{Cell, RefCell};
use std::rc::Rc;

use futures_util::lock::Mutex as AsyncMutex;
use wasm_bindgen::JsCast;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

use crate::error::js_error;
use crate::frame::parse_frame_value_with_limits;
use mtp_codec::{DecodeLimits, EncodeLimits, TypeMap};

const CLOSE_FRAME_LEN: u32 = u32::MAX;

/// Logs the `streamErrorCode` from a stream-level WebTransportError (STOP_SENDING / RESET_STREAM). Session errors are skipped.
pub(crate) fn log_stream_error_code(error: &JsValue, context: &str) {
    let source = js_sys::Reflect::get(error, &JsValue::from_str("source"))
        .ok()
        .and_then(|v| v.as_string());

    if source.as_deref() != Some("stream") {
        return;
    }

    let stream_error_code = js_sys::Reflect::get(error, &JsValue::from_str("streamErrorCode"))
        .ok()
        .and_then(|v| v.as_f64());
    if matches!(stream_error_code, Some(0.0)) {
        // WebTransport reports peer-driven stream shutdown as code 0 in this
        // environment. For one-frame handshake streams, that is expected and
        // should not be surfaced as a warning.
        return;
    }
    let message = error
        .as_string()
        .or_else(|| {
            js_sys::Reflect::get(error, &JsValue::from_str("message"))
                .ok()
                .and_then(|v| v.as_string())
        })
        .unwrap_or_else(|| format!("{:?}", error));

    let formatted = match stream_error_code {
        Some(code) => format!(
            "[WasmTransport] {context}: STOP_SENDING/RESET_STREAM streamErrorCode={code} \
             ({message})"
        ),
        None => format!("[WasmTransport] {context}: stream error ({message})"),
    };

    if let Ok(console) = js_sys::Reflect::get(&js_sys::global(), &JsValue::from_str("console"))
        && let Ok(warn) = js_sys::Reflect::get(&console, &JsValue::from_str("warn"))
            .and_then(|f| f.dyn_into::<js_sys::Function>())
    {
        let _ = warn.call1(&console, &JsValue::from_str(&formatted));
    }
}

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

/// Releases a writer's lock so an abandoned writer isn't treated as an abort (which sends STOP_SENDING).
pub(crate) fn release_writer_lock(writer: &JsValue) {
    if let Ok(release) = js_sys::Reflect::get(writer, &JsValue::from_str("releaseLock"))
        .and_then(|f| f.dyn_into::<js_sys::Function>())
    {
        let _ = release.call0(writer);
    }
}

/// Releases a reader's lock so an abandoned reader isn't treated as a cancel (which sends STOP_SENDING).
pub(crate) fn release_reader_lock(reader: &JsValue) {
    if let Ok(release) = js_sys::Reflect::get(reader, &JsValue::from_str("releaseLock"))
        .and_then(|f| f.dyn_into::<js_sys::Function>())
    {
        let _ = release.call0(reader);
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
    inner: JsValue,
    max_message_size: u32,
    /// Reader over `incoming_unidirectional_streams()` (a singleton stream of streams).
    streams_reader: Rc<RefCell<Option<JsValue>>>,
    /// Reader over the host's current uni-directional stream, if one is open.
    stream_reader: Rc<RefCell<Option<JsValue>>>,
    /// Bytes already read from the current stream but not yet consumed as a frame.
    buffer: Rc<RefCell<Vec<u8>>>,
    /// Set to `true` when `open_next_stream` succeeds; cleared after the first frame is parsed.
    new_stream_frame: Rc<Cell<bool>>,
    /// A single ordered browser send stream shared by all cloned transports.
    outgoing_writer: Rc<RefCell<Option<JsValue>>>,
    /// Serializes stream creation and writes across concurrent callers.
    send_lock: Rc<AsyncMutex<()>>,
    type_map: Rc<RefCell<TypeMap>>,
    decode_limits: Rc<RefCell<DecodeLimits>>,
}

impl WasmTransport {
    pub async fn connect(
        url: &str,
        cert_hashes: Option<Vec<String>>,
        max_message_size: u32,
    ) -> Result<Self, JsValue> {
        Self::connect_with_limits(url, cert_hashes, max_message_size, None).await
    }

    pub async fn connect_with_limits(
        url: &str,
        cert_hashes: Option<Vec<String>>,
        max_message_size: u32,
        configured_limits: Option<DecodeLimits>,
    ) -> Result<Self, JsValue> {
        let ctor = js_sys::Reflect::get(&js_sys::global(), &JsValue::from_str("WebTransport"))?
            .dyn_into::<js_sys::Function>()
            .map_err(|_| js_error("WebTransport not available"))?;
        let args = js_sys::Array::new();
        args.push(&JsValue::from_str(url));

        if let Some(hashes) = cert_hashes {
            let wt_hashes = js_sys::Array::new();
            for h in hashes {
                let (algo, hex_val) = match h.split_once(':') {
                    Some((algo, hex_val)) => (algo, hex_val),
                    None => ("sha-256", h.as_str()),
                };

                if let Ok(bytes) = hex::decode(hex_val) {
                    let hash = js_sys::Object::new();
                    js_sys::Reflect::set(
                        &hash,
                        &JsValue::from_str("algorithm"),
                        &JsValue::from_str(algo),
                    )?;
                    js_sys::Reflect::set(
                        &hash,
                        &JsValue::from_str("value"),
                        &js_sys::Uint8Array::from(&bytes[..]),
                    )?;
                    wt_hashes.push(&hash);
                }
            }
            if wt_hashes.length() > 0 {
                let opts = js_sys::Object::new();
                js_sys::Reflect::set(
                    &opts,
                    &JsValue::from_str("serverCertificateHashes"),
                    &wt_hashes,
                )?;
                args.push(&opts);
            }
        };

        let transport = js_sys::Reflect::construct(&ctor, &args)?;
        let ready = js_sys::Reflect::get(&transport, &JsValue::from_str("ready"))?
            .dyn_into::<js_sys::Promise>()
            .map_err(|_| js_error("WebTransport.ready is not a Promise"))?;
        JsFuture::from(ready)
            .await
            .map_err(|e| js_error(format!("WebTransport ready failed: {:?}", e)))?;
        let transport_limits = DecodeLimits::for_transport_message_size(max_message_size as u64);
        let decode_limits = configured_limits
            .map(|limits| restrict_decode_limits(limits, transport_limits))
            .unwrap_or(transport_limits);
        Ok(Self {
            inner: transport,
            max_message_size,
            streams_reader: Rc::new(RefCell::new(None)),
            stream_reader: Rc::new(RefCell::new(None)),
            buffer: Rc::new(RefCell::new(Vec::new())),
            new_stream_frame: Rc::new(Cell::new(false)),
            outgoing_writer: Rc::new(RefCell::new(None)),
            send_lock: Rc::new(AsyncMutex::new(())),
            type_map: Rc::new(RefCell::new(TypeMap::latest())),
            decode_limits: Rc::new(RefCell::new(decode_limits)),
        })
    }

    pub fn inner(&self) -> &JsValue {
        &self.inner
    }

    pub fn set_type_map(&self, type_map: &TypeMap) {
        *self.type_map.borrow_mut() = type_map.clone();
    }

    pub fn type_map(&self) -> TypeMap {
        self.type_map.borrow().clone()
    }

    pub fn decode_limits(&self) -> DecodeLimits {
        *self.decode_limits.borrow()
    }

    /// Encoder policy corresponding to the transport's admitted complete
    /// frame size. SDK builders use this before constructing a frame so an
    /// oversized value is rejected before its serialized buffer is created.
    pub fn encode_limits(&self) -> EncodeLimits {
        EncodeLimits::for_transport_message_size(self.max_message_size as u64)
    }

    pub async fn send_frame(&self, frame: &[u8]) -> Result<(), JsValue> {
        let _send_guard = self.send_lock.lock().await;
        if frame.len() as u64 > self.max_message_size as u64
            || frame.len() as u64 >= CLOSE_FRAME_LEN as u64
        {
            return Err(js_error("message too large"));
        }

        let writer_val = if let Some(writer) = self.outgoing_writer.borrow().clone() {
            writer
        } else {
            let create_stream = js_sys::Reflect::get(
                &self.inner,
                &JsValue::from_str("createUnidirectionalStream"),
            )?
            .dyn_into::<js_sys::Function>()
            .map_err(|_| js_error("createUnidirectionalStream not a function"))?;
            let stream_promise = create_stream
                .call0(&self.inner)?
                .dyn_into::<js_sys::Promise>()
                .map_err(|_| js_error("createUnidirectionalStream did not return a Promise"))?;
            let stream = JsFuture::from(stream_promise).await?;
            let writable_or_stream = resolve_stream_writable(&stream)?;
            let writer = js_sys::Reflect::get(&writable_or_stream, &JsValue::from_str("getWriter"))
                .map_err(|_| js_error("missing getWriter"))?
                .dyn_into::<js_sys::Function>()
                .map_err(|_| js_error("getWriter not a function"))?
                .call0(&writable_or_stream)
                .map_err(|_| js_error("getWriter call failed"))?;
            *self.outgoing_writer.borrow_mut() = Some(writer.clone());
            writer
        };

        let chunk = js_sys::Uint8Array::from(frame);

        let write_fn = js_sys::Reflect::get(&writer_val, &JsValue::from_str("write"))
            .map_err(|_| js_error("missing write"))?
            .dyn_into::<js_sys::Function>()
            .map_err(|_| js_error("write not a function"))?;
        let write_promise = write_fn
            .call1(&writer_val, &chunk)
            .map_err(|e| js_error(format!("write failed: {:?}", e)))?;
        if let Err(e) = JsFuture::from(write_promise.unchecked_into::<js_sys::Promise>()).await {
            log_stream_error_code(&e, "send_frame write");
            self.outgoing_writer.borrow_mut().take();
            release_writer_lock(&writer_val);
            return Err(e);
        }

        Ok(())
    }

    /// Get (creating once) the reader over `incoming_unidirectional_streams()`.
    fn ensure_streams_reader(&self) -> Result<JsValue, JsValue> {
        if let Some(reader) = self.streams_reader.borrow().clone() {
            return Ok(reader);
        }
        let incoming = js_sys::Reflect::get(
            &self.inner,
            &JsValue::from_str("incomingUnidirectionalStreams"),
        )?;
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
        let promise = read_fn
            .call0(&streams_reader)
            .map_err(|_| js_error("read call failed"))?
            .unchecked_into::<js_sys::Promise>();
        let result = match JsFuture::from(promise).await {
            Ok(r) => r,
            Err(e) => {
                log_stream_error_code(&e, "open_next_stream accept");
                return Err(js_error(format!("accept stream failed: {:?}", e)));
            }
        };

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
        self.new_stream_frame.set(true);
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
        let promise = read_fn
            .call0(&reader)
            .map_err(|_| js_error("read call failed"))?
            .unchecked_into::<js_sys::Promise>();
        let result = match JsFuture::from(promise).await {
            Ok(r) => r,
            Err(e) => {
                log_stream_error_code(&e, "read_chunk");
                return Err(js_error(format!("read failed: {:?}", e)));
            }
        };

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
    fn parse_buffer(&self, max_message_size: u32) -> Result<Option<FrameOutcome>, JsValue> {
        let buf = self.buffer.borrow();
        if buf.len() < 4 {
            return Ok(None);
        }
        let body_len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        if body_len == CLOSE_FRAME_LEN {
            return Ok(Some(FrameOutcome::Closed));
        }
        let frame_len = body_len
            .checked_add(4)
            .ok_or_else(|| js_error("invalid frame length"))?;
        if frame_len > max_message_size {
            return Err(js_error("message too large"));
        }
        let frame_end = frame_len as usize;
        if frame_end > buf.len() {
            return Ok(None);
        }
        let frame = buf[..frame_end].to_vec();
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
    async fn next_frame(&self, max_message_size: u32) -> Result<FrameOutcome, JsValue> {
        loop {
            if let Some(outcome) = self.parse_buffer(max_message_size)? {
                return Ok(outcome);
            }

            let have_stream = self.stream_reader.borrow().is_some();
            if !have_stream && !self.open_next_stream().await? {
                return Ok(FrameOutcome::Ended);
            }

            match self.read_chunk().await? {
                Some(chunk) => {
                    if !chunk.is_empty() {
                        let mut buffer = self.buffer.borrow_mut();
                        let maximum_buffer = max_message_size as usize + 4;
                        if buffer.len().saturating_add(chunk.len()) > maximum_buffer {
                            return Err(js_error("message too large"));
                        }
                        buffer
                            .try_reserve(chunk.len())
                            .map_err(|_| js_error("message allocation failed"))?;
                        buffer.extend_from_slice(&chunk);
                    }
                }
                None => {
                    // Stream finished; release the reader's lock to avoid a spurious cancel.
                    if let Some(reader) = self.stream_reader.borrow_mut().take() {
                        release_reader_lock(&reader);
                    }
                    // A frame is never allowed to span stream boundaries. The
                    // native persistent-stream sender packs frames on one
                    // stream, while the WASM sender uses one stream per frame;
                    // either mode must reject a truncated frame instead of
                    // silently dropping its prefix.
                    if !self.buffer.borrow().is_empty() {
                        return Err(js_error("stream ended in the middle of a frame"));
                    }
                }
            }
        }
    }

    /// Read exactly one application frame (used during the auth handshake).
    pub async fn read_one_frame(&self) -> Result<Vec<u8>, JsValue> {
        match self
            .next_frame(self.max_message_size.min(64 * 1024))
            .await?
        {
            FrameOutcome::Frame(frame) => Ok(frame),
            FrameOutcome::Closed => Err(js_error("connection closed before frame")),
            FrameOutcome::Ended => Err(js_error("stream ended before frame")),
        }
    }

    /// Background loop: deliver every incoming frame to `on_message` until the
    /// connection closes. Shares reader state with `read_one_frame`, so frames
    /// buffered during the handshake are not lost.
    pub async fn receive_loop<F>(&self, mut on_message: F, on_error: js_sys::Function)
    where
        F: FnMut(JsValue),
    {
        loop {
            match self.next_frame(self.max_message_size).await {
                Ok(FrameOutcome::Frame(frame)) => {
                    let type_map = self.type_map();
                    match parse_frame_value_with_limits(&frame, &type_map, self.decode_limits()) {
                        Ok(parsed) => {
                            on_message(parsed);
                        }
                        Err(e) => {
                            let message = e.as_string().unwrap_or_else(|| format!("{:?}", e));
                            let _ = on_error.call1(&JsValue::NULL, &JsValue::from_str(&message));
                        }
                    }
                }
                Ok(FrameOutcome::Closed) | Ok(FrameOutcome::Ended) => break,
                Err(e) => {
                    let _ = on_error.call1(&JsValue::NULL, &e);
                    break;
                }
            }
        }
    }

    /// Pipe-aware receive loop. Identical to `receive_loop` but detects
    /// `PipeRequest` as the first frame on a new incoming stream and routes
    /// the stream to `on_pipe` instead of `on_message`.
    pub async fn receive_loop_with_pipes<F, G, H>(
        &self,
        mut on_message: F,
        mut on_error: H,
        mut on_pipe: G,
    ) where
        F: FnMut(JsValue),
        G: FnMut(crate::pipe::PipeReader),
        H: FnMut(JsValue),
    {
        loop {
            match self.next_frame(self.max_message_size).await {
                Ok(FrameOutcome::Frame(frame)) => {
                    let type_map = self.type_map();
                    let decode_limits = self.decode_limits();
                    let pipe_request_type =
                        mtp_codec::CommunicationType::PipeRequest.try_to_id(&type_map);
                    let pipe_response_type =
                        mtp_codec::CommunicationType::PipeResponse.try_to_id(&type_map);
                    let is_first = self.new_stream_frame.get();
                    let comm =
                        mtp_codec::CommunicationValue::try_from_bytes_with_type_map_and_limits(
                            &frame,
                            &type_map,
                            decode_limits,
                        )
                        .ok();

                    if is_first {
                        self.new_stream_frame.set(false);
                        if let Some(comm) = comm.as_ref()
                            && Some(comm.get_type()) == pipe_request_type
                        {
                            let Some(pipe_id) = comm.id().filter(|id| *id != 0) else {
                                on_error(JsValue::from_str(
                                    "PipeRequest frame must contain a non-zero id",
                                ));
                                self.close();
                                break;
                            };
                            let description = comm
                                .get_str(mtp_codec::DataType::Description)
                                .unwrap_or("")
                                .to_string();

                            let pending = {
                                let mut buf = self.buffer.borrow_mut();
                                std::mem::take(&mut *buf)
                            };

                            if let Some(reader) = self.stream_reader.borrow_mut().take() {
                                let pipe_reader = crate::pipe::PipeReader::new(
                                    reader,
                                    pipe_id,
                                    description,
                                    pending,
                                );
                                on_pipe(pipe_reader);
                            }
                            continue;
                        }
                    }

                    if let Some(comm) = comm.as_ref()
                        && Some(comm.get_type()) == pipe_response_type
                        && !matches!(comm.id(), Some(id) if id != 0)
                    {
                        on_error(JsValue::from_str(
                            "PipeResponse frame must contain a non-zero id",
                        ));
                        self.close();
                        break;
                    }

                    if let Some(comm) = comm.as_ref()
                        && !matches!(comm.id(), Some(id) if id != 0)
                        && comm
                            .get_type_name()
                            .is_some_and(|name| name.ends_with("Response"))
                    {
                        on_error(JsValue::from_str(
                            "response frame must contain a non-zero id",
                        ));
                        self.close();
                        break;
                    }

                    match parse_frame_value_with_limits(&frame, &type_map, decode_limits) {
                        Ok(parsed) => {
                            on_message(parsed);
                        }
                        Err(e) => {
                            let message = e.as_string().unwrap_or_else(|| format!("{:?}", e));
                            on_error(JsValue::from_str(&message));
                        }
                    }
                }
                Ok(FrameOutcome::Closed) | Ok(FrameOutcome::Ended) => break,
                Err(e) => {
                    on_error(e);
                    break;
                }
            }
        }
    }

    /// Open a new outgoing unidirectional stream and write a `PipeRequest`
    /// frame as the first frame. Returns a `PipeWriter` whose underlying
    /// `WritableStream` remains open for subsequent raw-data writes.
    pub async fn open_pipe(
        &self,
        pipe_id: u32,
        description: &str,
    ) -> Result<crate::pipe::PipeWriter, JsValue> {
        let _send_guard = self.send_lock.lock().await;
        let create_stream = js_sys::Reflect::get(
            &self.inner,
            &JsValue::from_str("createUnidirectionalStream"),
        )?
        .dyn_into::<js_sys::Function>()
        .map_err(|_| js_error("createUnidirectionalStream not a function"))?;
        let stream_promise = create_stream
            .call0(&self.inner)?
            .dyn_into::<js_sys::Promise>()
            .map_err(|_| js_error("createUnidirectionalStream did not return a Promise"))?;
        let stream = JsFuture::from(stream_promise).await?;

        let writable_or_stream = resolve_stream_writable(&stream)?;
        let writer_val = js_sys::Reflect::get(&writable_or_stream, &JsValue::from_str("getWriter"))
            .map_err(|_| js_error("missing getWriter"))?
            .dyn_into::<js_sys::Function>()
            .map_err(|_| js_error("getWriter not a function"))?
            .call0(&writable_or_stream)
            .map_err(|_| js_error("getWriter call failed"))?;

        let type_map = self.type_map();
        let request = mtp_codec::CommunicationValue::new_with_type_map(
            mtp_codec::CommunicationType::PipeRequest,
            &type_map,
        )
        .with_id(pipe_id)
        .add_typed_default(
            mtp_codec::DataType::Description,
            mtp_codec::DataValue::Str(description.to_string()),
        );
        let frame_bytes = request
            .to_bytes()
            .map_err(|e| js_error(format!("encode failed: {}", e)))?;

        let chunk = js_sys::Uint8Array::from(&frame_bytes[..]);
        let write_fn = js_sys::Reflect::get(&writer_val, &JsValue::from_str("write"))
            .map_err(|_| js_error("missing write"))?
            .dyn_into::<js_sys::Function>()
            .map_err(|_| js_error("write not a function"))?;
        let write_promise = write_fn
            .call1(&writer_val, &chunk)
            .map_err(|e| js_error(format!("write failed: {:?}", e)))?;
        if let Err(e) = JsFuture::from(write_promise.unchecked_into::<js_sys::Promise>()).await {
            log_stream_error_code(&e, "open_pipe write");
            release_writer_lock(&writer_val);
            return Err(e);
        }

        Ok(crate::pipe::PipeWriter::new(writer_val, pipe_id))
    }

    pub fn close(&self) {
        if let Some(writer) = self.outgoing_writer.borrow_mut().take() {
            // The WebTransport session close below terminates the stream. The
            // lock must be released first so dropping it is not interpreted as
            // an application abort.
            release_writer_lock(&writer);
        }
        // Release reader locks before closing so they aren't treated as cancels.
        if let Some(reader) = self.stream_reader.borrow_mut().take() {
            release_reader_lock(&reader);
        }
        if let Some(reader) = self.streams_reader.borrow_mut().take() {
            release_reader_lock(&reader);
        }

        if let Ok(close) = js_sys::Reflect::get(&self.inner, &JsValue::from_str("close"))
            .and_then(|value| value.dyn_into::<js_sys::Function>())
        {
            let _ = close.call1(&self.inner, &js_sys::Object::new());
        }
    }
}

fn restrict_decode_limits(left: DecodeLimits, right: DecodeLimits) -> DecodeLimits {
    DecodeLimits {
        max_depth: left.max_depth.min(right.max_depth),
        max_values: left.max_values.min(right.max_values),
        max_blob_size: left.max_blob_size.min(right.max_blob_size),
        max_recipients: left.max_recipients.min(right.max_recipients),
        max_allocated_bytes: left.max_allocated_bytes.min(right.max_allocated_bytes),
    }
}
