//! Browser API adaptation. Framing, stream dispatch and pipe negotiation live in core.
use crate::error::{from_communication_error, js_error};
use futures_util::{FutureExt, future::LocalBoxFuture};
use mtp_codec::{CommunicationValue, DecodeLimits, EncodeLimits, TypeMap};
use mtp_common::{CommunicationError, TransportPhase};
use mtp_core::{
    GenericReceiver, GenericSender, Policy, SendMode, TransportConnection, TransportRecvStream,
    TransportSendStream,
};
use std::{
    cell::RefCell,
    pin::Pin,
    rc::Rc,
    sync::Arc,
    task::{Context, Poll},
};
use wasm_bindgen::{JsCast, prelude::*};
use wasm_bindgen_futures::JsFuture;

fn call(object: &JsValue, name: &str, argument: Option<&JsValue>) -> Result<JsValue, JsValue> {
    let function = js_sys::Reflect::get(object, &name.into())?.dyn_into::<js_sys::Function>()?;
    match argument {
        Some(value) => function.call1(object, value),
        None => function.call0(object),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::wasm_bindgen_test;

    #[wasm_bindgen_test]
    async fn browser_streams_use_shared_framing_and_resume_timed_out_accepts() {
        let previous = js_sys::Reflect::get(&js_sys::global(), &"WebTransport".into()).unwrap();
        js_sys::eval(
            r#"
            globalThis.WebTransport = class {
                constructor() {
                    this.ready = Promise.resolve();
                    this.incomingUnidirectionalStreams = new ReadableStream({
                        start(controller) { globalThis.mtpIncoming = controller; }
                    });
                }
                close() { globalThis.mtpIncoming.close(); }
            };
        "#,
        )
        .unwrap();
        let transport = WasmTransport::connect("https://localhost", None, 65536)
            .await
            .unwrap();
        promise(Ok(js_sys::eval(
            "new Promise(resolve => setTimeout(resolve, 550))",
        )
        .unwrap()))
        .await
        .unwrap();
        let message = CommunicationValue::new(mtp_codec::CommunicationType::Ping);
        let frame = message.to_bytes().unwrap();
        js_sys::Reflect::set(
            &js_sys::global(),
            &"mtpTestFrame".into(),
            &js_sys::Uint8Array::from(frame.as_slice()),
        )
        .unwrap();
        js_sys::eval(
            r#"
            globalThis.mtpIncoming.enqueue(new ReadableStream({ start(controller) {
                controller.error(Object.assign(new Error("STOP_SENDING"), {
                    source: "stream", streamErrorCode: 0
                }));
            }}));
            globalThis.mtpIncoming.enqueue(new ReadableStream({ start(controller) {
                const frame = globalThis.mtpTestFrame;
                controller.enqueue(frame.slice(0, 2));
                controller.enqueue(frame.slice(2));
                controller.enqueue(frame);
                controller.close();
            }}));
        "#,
        )
        .unwrap();
        assert_eq!(transport.read_one_frame().await.unwrap(), frame);
        assert_eq!(transport.read_one_frame().await.unwrap(), frame);
        transport.close();
        js_sys::Reflect::set(&js_sys::global(), &"WebTransport".into(), &previous).unwrap();
    }
}
async fn promise(value: Result<JsValue, JsValue>) -> Result<JsValue, JsValue> {
    JsFuture::from(value?.dyn_into::<js_sys::Promise>()?).await
}
pub(crate) fn log_stream_error_code(error: &JsValue, context: &str) {
    if js_sys::Reflect::get(error, &"source".into())
        .ok()
        .and_then(|v| v.as_string())
        .as_deref()
        == Some("stream")
    {
        tracing::debug!(context, error = ?error, "browser stream stopped or reset");
    }
}
fn transport_error(error: JsValue, phase: TransportPhase) -> CommunicationError {
    log_stream_error_code(&error, "transport");
    CommunicationError::transport(phase, format!("{error:?}"))
}
fn io_error(error: JsValue) -> std::io::Error {
    log_stream_error_code(&error, "stream I/O");
    let kind = if js_sys::Reflect::get(&error, &"source".into())
        .ok()
        .and_then(|value| value.as_string())
        .as_deref()
        == Some("stream")
    {
        std::io::ErrorKind::ConnectionReset
    } else {
        std::io::ErrorKind::Other
    };
    std::io::Error::new(kind, format!("{error:?}"))
}
fn stream_handle(stream: &JsValue, property: &str, method: &str) -> Result<JsValue, JsValue> {
    let value = js_sys::Reflect::get(stream, &property.into())?;
    call(
        if value.is_null() || value.is_undefined() {
            stream
        } else {
            &value
        },
        method,
        None,
    )
}

#[derive(Clone)]
pub(crate) struct BrowserConnection {
    inner: JsValue,
    incoming: Rc<RefCell<Option<JsValue>>>,
    closed: Rc<RefCell<Option<CommunicationError>>>,
    accept: Rc<tokio::sync::Mutex<Option<JsFuture>>>,
}
pub(crate) struct BrowserSendStream {
    pub(crate) writer: JsValue,
    operation: Option<LocalBoxFuture<'static, std::io::Result<()>>>,
}
pub(crate) struct BrowserRecvStream {
    reader: JsValue,
    operation: Option<LocalBoxFuture<'static, std::io::Result<Option<Vec<u8>>>>>,
    pending: Vec<u8>,
    offset: usize,
    finished: bool,
    custom: bool,
}
impl Drop for BrowserSendStream {
    fn drop(&mut self) {
        let _ = call(&self.writer, "releaseLock", None);
    }
}
impl Drop for BrowserRecvStream {
    fn drop(&mut self) {
        let _ = call(&self.reader, "releaseLock", None);
    }
}

impl tokio::io::AsyncWrite for BrowserSendStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if self.operation.is_none() {
            let result = call(
                &self.writer,
                "write",
                Some(&js_sys::Uint8Array::from(bytes).into()),
            );
            self.operation = Some(
                async move { promise(result).await.map(|_| ()).map_err(io_error) }.boxed_local(),
            );
        }
        let result = self.operation.as_mut().unwrap().as_mut().poll(cx);
        if result.is_ready() {
            self.operation = None;
        }
        result.map(|result| result.map(|_| bytes.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        if self.operation.is_none() {
            let result = call(&self.writer, "close", None);
            self.operation = Some(
                async move { promise(result).await.map(|_| ()).map_err(io_error) }.boxed_local(),
            );
        }
        let result = self.operation.as_mut().unwrap().as_mut().poll(cx);
        if result.is_ready() {
            self.operation = None;
        }
        result
    }
}
impl tokio::io::AsyncRead for BrowserRecvStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if buffer.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            if self.offset < self.pending.len() {
                let end = (self.offset + buffer.remaining()).min(self.pending.len());
                buffer.put_slice(&self.pending[self.offset..end]);
                self.offset = end;
                return Poll::Ready(Ok(()));
            }
            if self.finished {
                return Poll::Ready(Ok(()));
            }
            if self.operation.is_none() {
                let result = call(&self.reader, "read", None);
                let custom = self.custom;
                self.operation = Some(
                    async move {
                        let result = promise(result).await.map_err(io_error)?;
                        if custom {
                            if result.is_null() {
                                return Ok(None);
                            }
                            if !result.is_instance_of::<js_sys::Uint8Array>() {
                                return Err(std::io::Error::other(
                                    "pipe reader returned non-byte data",
                                ));
                            }
                            return Ok(Some(js_sys::Uint8Array::new(&result).to_vec()));
                        }
                        if js_sys::Reflect::get(&result, &"done".into())
                            .map_err(io_error)?
                            .as_bool()
                            == Some(true)
                        {
                            return Ok(None);
                        }
                        let value =
                            js_sys::Reflect::get(&result, &"value".into()).map_err(io_error)?;
                        Ok(Some(js_sys::Uint8Array::new(&value).to_vec()))
                    }
                    .boxed_local(),
                );
            }
            let result = std::task::ready!(self.operation.as_mut().unwrap().as_mut().poll(cx));
            self.operation = None;
            match result? {
                Some(bytes) => {
                    self.pending = bytes;
                    self.offset = 0;
                }
                None => self.finished = true,
            }
        }
    }
}
#[async_trait::async_trait(?Send)]
impl TransportSendStream for BrowserSendStream {
    async fn write_all(&mut self, bytes: &[u8]) -> Result<(), CommunicationError> {
        tokio::io::AsyncWriteExt::write_all(self, bytes)
            .await
            .map_err(|_| CommunicationError::DeliveryUnknownAt {
                phase: TransportPhase::WriteFrame,
            })
    }
    async fn finish(&mut self) -> Result<(), CommunicationError> {
        tokio::io::AsyncWriteExt::shutdown(self).await.map_err(|_| {
            CommunicationError::DeliveryUnknownAt {
                phase: TransportPhase::FinishStream,
            }
        })
    }
    fn reset(&mut self, code: u32) -> Result<(), CommunicationError> {
        let result = call(&self.writer, "abort", Some(&JsValue::from_f64(code as f64)));
        if let Ok(value) = &result
            && let Some(promise) = value.dyn_ref::<js_sys::Promise>()
        {
            let promise = promise.clone();
            wasm_bindgen_futures::spawn_local(async move {
                let _ = JsFuture::from(promise).await;
            });
        }
        result
            .map(|_| ())
            .map_err(|e| transport_error(e, TransportPhase::WriteFrame))
    }
}
#[async_trait::async_trait(?Send)]
impl TransportRecvStream for BrowserRecvStream {
    async fn read_exact(&mut self, bytes: &mut [u8]) -> Result<(), CommunicationError> {
        tokio::io::AsyncReadExt::read_exact(self, bytes)
            .await
            .map(|_| ())
            .map_err(|e| {
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::ConnectionReset
                ) {
                    CommunicationError::ClosedByPeer
                } else {
                    CommunicationError::transport(TransportPhase::ReadFrame, e.to_string())
                }
            })
    }
    async fn read_chunk(&mut self, max: usize) -> Result<Option<Vec<u8>>, CommunicationError> {
        let mut bytes = vec![0; max];
        let count = tokio::io::AsyncReadExt::read(self, &mut bytes)
            .await
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::ConnectionReset {
                    CommunicationError::ClosedByPeer
                } else {
                    CommunicationError::transport(TransportPhase::ReadFrame, e.to_string())
                }
            })?;
        bytes.truncate(count);
        Ok((count != 0).then_some(bytes))
    }
    fn stop(self, code: u32) -> Result<(), CommunicationError> {
        let result = call(
            &self.reader,
            "cancel",
            Some(&JsValue::from_f64(code as f64)),
        );
        if let Ok(value) = &result
            && let Some(promise) = value.dyn_ref::<js_sys::Promise>()
        {
            let promise = promise.clone();
            wasm_bindgen_futures::spawn_local(async move {
                let _ = JsFuture::from(promise).await;
            });
        }
        result
            .map(|_| ())
            .map_err(|e| transport_error(e, TransportPhase::ReadFrame))
    }
}
#[async_trait::async_trait(?Send)]
impl TransportConnection for BrowserConnection {
    type SendStream = BrowserSendStream;
    type RecvStream = BrowserRecvStream;
    async fn open_uni(&self) -> Result<BrowserSendStream, CommunicationError> {
        let stream = promise(call(&self.inner, "createUnidirectionalStream", None))
            .await
            .map_err(|e| transport_error(e, TransportPhase::OpenStream))?;
        let writer = stream_handle(&stream, "writable", "getWriter")
            .map_err(|e| transport_error(e, TransportPhase::OpenStream))?;
        Ok(BrowserSendStream {
            writer,
            operation: None,
        })
    }
    async fn accept_uni(&self) -> Result<BrowserRecvStream, CommunicationError> {
        let reader = if let Some(reader) = self.incoming.borrow().clone() {
            reader
        } else {
            let streams =
                js_sys::Reflect::get(&self.inner, &"incomingUnidirectionalStreams".into())
                    .map_err(|e| transport_error(e, TransportPhase::ReadFrame))?;
            let reader = call(&streams, "getReader", None)
                .map_err(|e| transport_error(e, TransportPhase::ReadFrame))?;
            *self.incoming.borrow_mut() = Some(reader.clone());
            reader
        };
        let mut accept = self.accept.lock().await;
        if accept.is_none() {
            let value = call(&reader, "read", None)
                .map_err(|e| transport_error(e, TransportPhase::ReadFrame))?;
            *accept = Some(JsFuture::from(
                value
                    .dyn_into::<js_sys::Promise>()
                    .map_err(|e| transport_error(e, TransportPhase::ReadFrame))?,
            ));
        }
        let result = accept.as_mut().unwrap().await;
        *accept = None;
        drop(accept);
        let result = result.map_err(|e| transport_error(e, TransportPhase::ReadFrame))?;
        if js_sys::Reflect::get(&result, &"done".into())
            .ok()
            .and_then(|v| v.as_bool())
            == Some(true)
        {
            return Err(CommunicationError::ClosedByPeer);
        }
        let stream = js_sys::Reflect::get(&result, &"value".into())
            .map_err(|e| transport_error(e, TransportPhase::ReadFrame))?;
        let reader = stream_handle(&stream, "readable", "getReader")
            .map_err(|e| transport_error(e, TransportPhase::ReadFrame))?;
        Ok(BrowserRecvStream {
            reader,
            operation: None,
            pending: Vec::new(),
            offset: 0,
            finished: false,
            custom: false,
        })
    }
    fn close_reason(&self) -> Option<CommunicationError> {
        self.closed.borrow().clone()
    }
    fn close(&self, _: u32, _: &[u8]) {
        *self.closed.borrow_mut() = Some(CommunicationError::ClosedLocally);
        if let Some(reader) = self.incoming.borrow_mut().take() {
            let _ = call(&reader, "releaseLock", None);
        }
        let _ = call(&self.inner, "close", Some(&js_sys::Object::new()));
    }
}

impl BrowserSendStream {
    pub(crate) fn from_pipe(writer: JsValue) -> Self {
        Self {
            writer,
            operation: None,
        }
    }
}
impl BrowserRecvStream {
    pub(crate) fn from_pipe(reader: JsValue, pending: Vec<u8>) -> Self {
        Self {
            reader,
            operation: None,
            pending,
            offset: 0,
            finished: false,
            custom: true,
        }
    }
}

#[derive(Clone)]
pub struct WasmTransport {
    connection: BrowserConnection,
    pub(crate) sender: GenericSender<BrowserConnection>,
    pub(crate) receiver: GenericReceiver<BrowserConnection>,
    type_map: Rc<RefCell<TypeMap>>,
    limits: DecodeLimits,
    max_message_size: u32,
}
impl WasmTransport {
    pub(crate) fn enable_application_frames(&self) {
        self.receiver
            .set_max_message_size(self.max_message_size as u64);
    }
    pub async fn connect(
        url: &str,
        hashes: Option<Vec<String>>,
        max: u32,
    ) -> Result<Self, JsValue> {
        Self::connect_with_limits(url, hashes, max, None).await
    }
    pub async fn connect_with_limits(
        url: &str,
        hashes: Option<Vec<String>>,
        max: u32,
        limits: Option<DecodeLimits>,
    ) -> Result<Self, JsValue> {
        let constructor = js_sys::Reflect::get(&js_sys::global(), &"WebTransport".into())?
            .dyn_into::<js_sys::Function>()?;
        let arguments = js_sys::Array::new();
        arguments.push(&url.into());
        if let Some(hashes) = hashes {
            let entries = js_sys::Array::new();
            for hash in hashes {
                let (algorithm, value) = hash.split_once(':').unwrap_or(("sha-256", &hash));
                let entry = js_sys::Object::new();
                let bytes = hex::decode(value).map_err(|_| js_error("invalid certificate hash"))?;
                js_sys::Reflect::set(&entry, &"algorithm".into(), &algorithm.into())?;
                js_sys::Reflect::set(
                    &entry,
                    &"value".into(),
                    &js_sys::Uint8Array::from(bytes.as_slice()),
                )?;
                entries.push(&entry);
            }
            let options = js_sys::Object::new();
            js_sys::Reflect::set(&options, &"serverCertificateHashes".into(), &entries)?;
            arguments.push(&options);
        }
        let inner = js_sys::Reflect::construct(&constructor, &arguments)?;
        promise(js_sys::Reflect::get(&inner, &"ready".into())).await?;
        let connection = BrowserConnection {
            inner,
            incoming: Rc::new(RefCell::new(None)),
            closed: Rc::new(RefCell::new(None)),
            accept: Rc::new(tokio::sync::Mutex::new(None)),
        };
        let policy = Arc::new(Policy {
            send_mode: SendMode::SingleStreamPerMessage,
            max_message_size: max as u64,
            ..Policy::default()
        });
        let sender = GenericSender::new(connection.clone(), policy.clone());
        let receiver = GenericReceiver::new(connection.clone(), policy);
        let transport_limits = DecodeLimits::for_transport_message_size(max as u64);
        let limits = limits
            .map(|l| l.intersection(transport_limits))
            .unwrap_or(transport_limits);
        receiver.set_decode_limits(limits);
        Ok(Self {
            connection,
            sender,
            receiver,
            type_map: Rc::new(RefCell::new(TypeMap::latest())),
            limits,
            max_message_size: max,
        })
    }
    pub fn inner(&self) -> &JsValue {
        &self.connection.inner
    }
    pub fn set_type_map(&self, map: &TypeMap) {
        *self.type_map.borrow_mut() = map.clone();
        self.sender.set_type_map_now(map);
        self.receiver.set_type_map_now(map);
    }
    pub fn type_map(&self) -> TypeMap {
        self.type_map.borrow().clone()
    }
    pub fn decode_limits(&self) -> DecodeLimits {
        self.limits
    }
    pub fn encode_limits(&self) -> EncodeLimits {
        EncodeLimits::for_transport_message_size(self.max_message_size as u64)
    }
    pub async fn send_frame(&self, frame: &[u8]) -> Result<(), JsValue> {
        let value = CommunicationValue::try_from_bytes_with_type_map_and_limits(
            frame,
            &self.type_map(),
            self.limits,
        )
        .map_err(|_| from_communication_error(CommunicationError::ParseCommunicationValue))?;
        self.sender
            .send(&value)
            .await
            .map_err(from_communication_error)
    }
    pub async fn read_one_frame(&self) -> Result<Vec<u8>, JsValue> {
        self.receiver
            .receive()
            .await
            .map_err(from_communication_error)?
            .to_bytes()
            .map_err(|e| js_error(e.to_string()))
    }
    pub async fn receive_loop<F: FnMut(JsValue)>(
        &self,
        mut on_message: F,
        on_error: js_sys::Function,
    ) {
        self.receiver
            .set_max_message_size(self.max_message_size as u64);
        loop {
            match self.receiver.receive().await {
                Ok(message) => match message
                    .to_bytes()
                    .map_err(|e| js_error(e.to_string()))
                    .and_then(|frame| {
                        crate::frame::parse_frame_value_with_limits(
                            &frame,
                            &self.type_map(),
                            self.limits,
                        )
                    }) {
                    Ok(value) => on_message(value),
                    Err(error) => {
                        let _ = on_error.call1(&JsValue::NULL, &error);
                    }
                },
                Err(error) => {
                    let _ = on_error.call1(&JsValue::NULL, &from_communication_error(error));
                    break;
                }
            }
        }
    }
    pub fn close(&self) {
        self.connection.close(0, b"mtp-close");
    }
}
