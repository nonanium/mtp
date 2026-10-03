use crate::{
    error::js_error,
    pipe::{PipeReader, PipeWriter},
    transport::{BrowserConnection, BrowserRecvStream, WasmTransport},
};
use futures_channel::oneshot;
use mtp_common::{PipeId, RequestId, RequestTracker};
use mtp_pipes::{PipeDispatcher, PipeHandle, PipeRequest};
use std::{cell::RefCell, collections::HashMap, rc::Rc, sync::Arc};
use wasm_bindgen::prelude::*;

pub(crate) struct PendingRequest {
    pub(crate) generation: u32,
    pub(crate) token: Rc<()>,
    pub(crate) response_type: Option<String>,
    pub(crate) sender: oneshot::Sender<Result<JsValue, JsValue>>,
}
pub(crate) fn remove_pending_request(
    pending: &Rc<RefCell<RequestTracker<PendingRequest>>>,
    id: RequestId,
    token: &Rc<()>,
) {
    pending
        .borrow_mut()
        .remove_if(id, |entry| Rc::ptr_eq(&entry.token, token));
}
pub(crate) fn expire_pending_request(
    pending: &Rc<RefCell<RequestTracker<PendingRequest>>>,
    id: RequestId,
    token: &Rc<()>,
) {
    pending.borrow_mut().expire_if(
        id,
        |entry| Rc::ptr_eq(&entry.token, token),
        js_sys::Date::now(),
    );
}
pub(crate) fn is_expired_request(
    pending: &Rc<RefCell<RequestTracker<PendingRequest>>>,
    id: RequestId,
) -> bool {
    pending.borrow_mut().is_expired(id, js_sys::Date::now())
}

type Sender = mtp_core::GenericSender<BrowserConnection>;
type Receiver = mtp_core::GenericReceiver<BrowserConnection>;
type Request = PipeRequest<Sender, Receiver, BrowserRecvStream>;
pub(crate) type PendingPipes = Rc<RefCell<HashMap<PipeId, Request>>>;
pub(crate) type PendingPipeCreations = Rc<RefCell<Option<Arc<PipeDispatcher<BrowserRecvStream>>>>>;

#[wasm_bindgen]
pub struct WasmPipeHandle {
    inner: RefCell<Option<PipeHandle<Sender, BrowserRecvStream>>>,
    pipe_id: PipeId,
    description: String,
}
#[wasm_bindgen]
impl WasmPipeHandle {
    pub async fn wait(&self) -> Result<JsValue, JsValue> {
        let handle = self
            .inner
            .borrow_mut()
            .take()
            .ok_or_else(|| js_error("handle already consumed"))?;
        match handle.wait().await.map_err(|e| js_error(e.to_string()))? {
            Some(inner) => Ok(PipeWriter {
                inner,
                id: self.pipe_id,
            }
            .into()),
            None => Ok(JsValue::NULL),
        }
    }
    pub async fn cancel(&self) -> Result<(), JsValue> {
        let handle = self
            .inner
            .borrow_mut()
            .take()
            .ok_or_else(|| js_error("handle already consumed"))?;
        handle.cancel().await.map_err(|e| js_error(e.to_string()))
    }
    #[wasm_bindgen(getter)]
    pub fn pipe_id(&self) -> u32 {
        self.pipe_id.get()
    }
    #[wasm_bindgen(getter)]
    pub fn description(&self) -> String {
        self.description.clone()
    }
}
pub(crate) fn reject_pending_pipe_creations(pending: &PendingPipeCreations, _: &str) {
    if let Some(dispatcher) = pending.borrow_mut().take() {
        mtp_pipes::fail_pending_creations(
            &dispatcher,
            &mtp_common::CommunicationError::ClosedLocally,
        );
    }
}
pub(crate) fn reject_pending_pipes(pending: &PendingPipes, _: &str) {
    pending.borrow_mut().clear();
}
pub(crate) async fn wasm_create_pipe(
    transport: &WasmTransport,
    description: &str,
    pending: &PendingPipeCreations,
) -> Result<WasmPipeHandle, JsValue> {
    let dispatcher = pending
        .borrow()
        .clone()
        .ok_or_else(|| js_error("not connected"))?;
    let inner = dispatcher
        .create(transport.sender.clone(), description)
        .await
        .map_err(|e| js_error(e.to_string()))?;
    Ok(WasmPipeHandle {
        pipe_id: inner.pipe_id_value(),
        description: inner.description().to_owned(),
        inner: RefCell::new(Some(inner)),
    })
}
pub(crate) async fn wasm_accept_pipe(
    pipe_id: u32,
    pending: &PendingPipes,
) -> Result<PipeReader, JsValue> {
    let id = PipeId::new(pipe_id).ok_or_else(|| js_error("pipe id must be non-zero"))?;
    let request = pending
        .borrow_mut()
        .remove(&id)
        .ok_or_else(|| js_error("unknown pipe request"))?;
    let inner = request
        .accept()
        .await
        .map_err(|e| js_error(e.to_string()))?;
    Ok(PipeReader { inner })
}
pub(crate) async fn wasm_deny_pipe(pipe_id: u32, pending: &PendingPipes) -> Result<(), JsValue> {
    let id = PipeId::new(pipe_id).ok_or_else(|| js_error("pipe id must be non-zero"))?;
    let request = pending
        .borrow_mut()
        .remove(&id)
        .ok_or_else(|| js_error("unknown pipe request"))?;
    request.deny().await.map_err(|e| js_error(e.to_string()))
}
