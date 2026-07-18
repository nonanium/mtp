use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use futures_channel::oneshot;
use tracing::debug;
use wasm_bindgen::prelude::*;

use mtp_codec::{CommunicationType, CommunicationValue, DataType, DataValue};

use crate::error::js_error;
use crate::pipe::PipeReader;
use crate::transport::WasmTransport;

pub(crate) struct PendingRequest {
    pub(crate) token: Rc<()>,
    pub(crate) response_type: Option<String>,
    pub(crate) sender: oneshot::Sender<Result<JsValue, JsValue>>,
}

pub(crate) fn remove_pending_request(
    pending_requests: &Rc<RefCell<HashMap<u32, PendingRequest>>>,
    request_id: u32,
    token: &Rc<()>,
) {
    let mut pending = pending_requests.borrow_mut();
    if pending
        .get(&request_id)
        .is_some_and(|entry| Rc::ptr_eq(&entry.token, token))
    {
        pending.remove(&request_id);
    }
}

#[wasm_bindgen(typescript_custom_section)]
const PIPE_HANDLE_TS: &str = r#"
export interface WasmPipeHandle {
  wait(): Promise<PipeWriter | null>;
  readonly pipeId: number;
  readonly description: string;
}
"#;

#[wasm_bindgen]
pub struct WasmPipeHandle {
    pipe_id: u32,
    description: String,
    transport: WasmTransport,
    response_rx: Rc<RefCell<Option<oneshot::Receiver<Result<bool, JsValue>>>>>,
}

#[wasm_bindgen]
impl WasmPipeHandle {
    pub async fn wait(&self) -> Result<JsValue, JsValue> {
        let rx = self
            .response_rx
            .borrow_mut()
            .take()
            .ok_or_else(|| js_error("handle already consumed"))?;

        let accepted = rx
            .await
            .map_err(|_| js_error("pipe handle channel closed"))?;

        match accepted {
            Ok(true) => {
                let writer = self
                    .transport
                    .open_pipe(self.pipe_id, &self.description)
                    .await?;
                Ok(JsValue::from(writer))
            }
            Ok(false) => Ok(JsValue::NULL),
            Err(e) => Err(e),
        }
    }

    #[wasm_bindgen(getter)]
    pub fn pipe_id(&self) -> u32 {
        self.pipe_id
    }

    #[wasm_bindgen(getter)]
    pub fn description(&self) -> String {
        self.description.clone()
    }
}

pub(crate) fn random_pipe_id() -> Result<u32, JsValue> {
    let mut bytes = [0u8; 4];
    getrandom_v04::fill(&mut bytes).map_err(|_| js_error("rng failed"))?;
    Ok(u32::from_be_bytes(bytes))
}

pub(crate) fn reject_pending_pipe_creations(
    pending: &Rc<RefCell<HashMap<u32, oneshot::Sender<Result<bool, JsValue>>>>>,
    message: &str,
) {
    let pending = std::mem::take(&mut *pending.borrow_mut());
    for (_, tx) in pending {
        let _ = tx.send(Err(js_error(message)));
    }
}

pub(crate) async fn wasm_create_pipe(
    transport: &WasmTransport,
    description: &str,
    pipe_id: u32,
    pending_pipe_creations: &Rc<RefCell<HashMap<u32, oneshot::Sender<Result<bool, JsValue>>>>>,
) -> Result<WasmPipeHandle, JsValue> {
    let (tx, rx) = oneshot::channel();
    pending_pipe_creations.borrow_mut().insert(pipe_id, tx);

    let request = CommunicationValue::new(CommunicationType::PipeRequest)
        .with_id(pipe_id)
        .add_typed_default(
            DataType::Description,
            DataValue::Str(description.to_string()),
        );
    let request_bytes = request
        .to_bytes()
        .map_err(|e| js_error(format!("encode failed: {}", e)))?;
    debug!(
        target = "mtp.wasm",
        pipe_id,
        description,
        frame_len = request_bytes.len(),
        "sending pipe request"
    );
    transport.send_frame(&request_bytes).await?;

    Ok(WasmPipeHandle {
        pipe_id,
        description: description.to_string(),
        transport: transport.clone(),
        response_rx: Rc::new(RefCell::new(Some(rx))),
    })
}

pub(crate) async fn wasm_accept_pipe(
    transport: &WasmTransport,
    pipe_id: u32,
    pending_pipes: &Rc<RefCell<HashMap<u32, oneshot::Sender<PipeReader>>>>,
) -> Result<PipeReader, JsValue> {
    let resp = CommunicationValue::new(CommunicationType::PipeResponse)
        .with_id(pipe_id)
        .add_typed_default(DataType::Accepted, DataValue::BoolTrue);
    let resp_bytes = resp
        .to_bytes()
        .map_err(|e| js_error(format!("encode failed: {}", e)))?;
    debug!(
        target = "mtp.wasm",
        pipe_id,
        accepted = true,
        frame_len = resp_bytes.len(),
        "sending pipe response"
    );
    transport.send_frame(&resp_bytes).await?;

    let (tx, rx) = oneshot::channel();
    pending_pipes.borrow_mut().insert(pipe_id, tx);

    rx.await
        .map_err(|_| js_error("pipe closed before stream arrived"))
}

pub(crate) async fn wasm_deny_pipe(transport: &WasmTransport, pipe_id: u32) -> Result<(), JsValue> {
    let resp = CommunicationValue::new(CommunicationType::PipeResponse)
        .with_id(pipe_id)
        .add_typed_default(DataType::Accepted, DataValue::BoolFalse);
    let resp_bytes = resp
        .to_bytes()
        .map_err(|e| js_error(format!("encode failed: {}", e)))?;
    transport.send_frame(&resp_bytes).await
}
