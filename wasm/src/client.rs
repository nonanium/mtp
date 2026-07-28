use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::collections::VecDeque;
use std::rc::Rc;

use futures_channel::oneshot;
use futures_util::{FutureExt, pin_mut, select};
use wasm_bindgen::prelude::*;

use mtp_codec::{CommunicationType, CommunicationValue, DataType, DataValue, PROTOCOL_VERSION};

use crate::auth;
use crate::client_pipe::{self, PendingRequest};
use crate::config::ConnectionConfig;
use crate::error::js_error;
use crate::pipe::PipeReader;
use crate::transport::WasmTransport;

struct PingTimer {
    id: i32,
    closure: Closure<dyn FnMut()>,
}

const DEFAULT_REQUEST_TIMEOUT_MS: u32 = 30_000;

fn frame_property(frame: &JsValue, key: &str) -> Option<JsValue> {
    js_sys::Reflect::get(frame, &JsValue::from_str(key))
        .ok()
        .filter(|value| !value.is_null() && !value.is_undefined())
}

fn frame_id(frame: &JsValue) -> Option<u32> {
    frame_property(frame, "id")
        .and_then(|value| value.as_f64())
        .map(|value| value as u32)
}

fn frame_type(frame: &JsValue) -> Option<String> {
    frame_property(frame, "type").and_then(|value| value.as_string())
}

fn route_incoming_frame(
    frame: &JsValue,
    on_message: &js_sys::Function,
    subscriptions: &Rc<RefCell<HashMap<u32, (String, js_sys::Function)>>>,
    pending_requests: &Rc<RefCell<HashMap<u32, PendingRequest>>>,
    pending_pings: &Rc<RefCell<HashMap<u32, f64>>>,
    ping_ms: &Rc<Cell<Option<f64>>>,
) {
    let message_type = frame_type(frame);

    if message_type.as_deref() == Some("Pong") {
        if let Some(sent_at) = frame_id(frame).and_then(|id| pending_pings.borrow_mut().remove(&id))
        {
            ping_ms.set(Some(js_sys::Date::now() - sent_at));
            return;
        }
    }

    if let Some(request_id) = frame_id(frame) {
        let pending = pending_requests.borrow_mut().remove(&request_id);
        if let Some(pending) = pending {
            let type_matches = pending
                .response_type
                .as_ref()
                .zip(message_type.as_ref())
                .map(|(expected, actual)| expected == actual)
                .unwrap_or(true);
            if type_matches {
                let _ = pending.sender.send(Ok(frame.clone()));
            } else {
                let actual = message_type.clone().unwrap_or_else(|| "unknown".into());
                let _ = pending.sender.send(Err(js_error(format!(
                    "unexpected response type: expected {}, got {}",
                    pending.response_type.unwrap_or_else(|| "unknown".into()),
                    actual
                ))));
            }
            return;
        }
    }

    let _ = on_message.call1(&JsValue::NULL, frame);

    let Some(message_type) = message_type else {
        return;
    };
    let callbacks: Vec<js_sys::Function> = subscriptions
        .borrow()
        .iter()
        .filter(|(_, (t, _))| t == &message_type)
        .map(|(_, (_, cb))| cb.clone())
        .collect();
    for callback in callbacks {
        let _ = callback.call1(&JsValue::NULL, frame);
    }
}

fn stop_ping_timer(ping_timer: &Rc<RefCell<Option<PingTimer>>>) {
    let Some(timer) = ping_timer.borrow_mut().take() else {
        return;
    };
    if let Ok(clear_interval) =
        js_sys::Reflect::get(&js_sys::global(), &JsValue::from_str("clearInterval"))
            .and_then(|value| value.dyn_into::<js_sys::Function>())
    {
        let _ = clear_interval.call1(&JsValue::NULL, &JsValue::from_f64(timer.id as f64));
    }
    drop(timer.closure);
}

fn reject_pending_requests(
    pending_requests: &Rc<RefCell<HashMap<u32, PendingRequest>>>,
    message: &str,
) {
    let pending = std::mem::take(&mut *pending_requests.borrow_mut());
    for (_, pending) in pending {
        let _ = pending.sender.send(Err(js_error(message)));
    }
}

async fn wait_for_timeout(timeout_ms: u32) -> Result<(), JsValue> {
    let promise = js_sys::Promise::new(&mut |resolve, reject| {
        let result = js_sys::Reflect::get(&js_sys::global(), &JsValue::from_str("setTimeout"))
            .and_then(|value| value.dyn_into::<js_sys::Function>())
            .and_then(|set_timeout| {
                set_timeout.call2(
                    &JsValue::NULL,
                    &resolve,
                    &JsValue::from_f64(timeout_ms as f64),
                )
            });
        if let Err(error) = result {
            let _ = reject.call1(&JsValue::NULL, &error);
        }
    });
    wasm_bindgen_futures::JsFuture::from(promise).await?;
    Ok(())
}

fn set_shared_state(
    state: &Rc<Cell<ConnectionState>>,
    pending_state_callbacks: &Rc<RefCell<VecDeque<ConnectionState>>>,
    state_callback: &JsValue,
    new_state: ConnectionState,
) {
    state.set(new_state);
    pending_state_callbacks.borrow_mut().push_back(new_state);

    let global = js_sys::global();
    let qmt = js_sys::Reflect::get(&global, &JsValue::from_str("queueMicrotask"))
        .and_then(|f| f.dyn_into::<js_sys::Function>());
    let scheduled = qmt
        .and_then(|qmt| qmt.call1(&global, state_callback))
        .is_ok();
    if !scheduled
        && js_sys::Reflect::get(&global, &JsValue::from_str("setTimeout"))
            .and_then(|f| f.dyn_into::<js_sys::Function>())
            .and_then(|set_timeout| {
                set_timeout.call2(&global, state_callback, &JsValue::from_f64(0.0))
            })
            .is_err()
    {
        pending_state_callbacks.borrow_mut().pop_back();
    }
}

#[wasm_bindgen]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    Disconnected = 0,
    Connecting = 1,
    Connected = 2,
    Failed = 3,
}

#[wasm_bindgen]
pub struct WasmClient {
    transport: Rc<RefCell<Option<WasmTransport>>>,
    connection_generation: Rc<Cell<u32>>,
    state: Rc<Cell<ConnectionState>>,
    pending_state_callbacks: Rc<RefCell<VecDeque<ConnectionState>>>,
    state_callback: Closure<dyn FnMut()>,
    pub(crate) on_message: js_sys::Function,
    pub(crate) on_error: js_sys::Function,
    subscriptions: Rc<RefCell<HashMap<u32, (String, js_sys::Function)>>>,
    next_subscription_id: Rc<Cell<u32>>,
    pending_requests: Rc<RefCell<HashMap<u32, PendingRequest>>>,
    ping_timer: Rc<RefCell<Option<PingTimer>>>,
    pending_pings: Rc<RefCell<HashMap<u32, f64>>>,
    ping_ms: Rc<Cell<Option<f64>>>,
    pending_pipe_creations: Rc<RefCell<HashMap<u32, oneshot::Sender<Result<bool, JsValue>>>>>,
    pending_pipes: Rc<RefCell<HashMap<u32, oneshot::Sender<PipeReader>>>>,
    on_pipe_request: Rc<RefCell<Option<js_sys::Function>>>,
}

#[wasm_bindgen]
impl WasmClient {
    #[wasm_bindgen(constructor)]
    pub fn new(
        on_state_change: Option<js_sys::Function>,
        on_message: Option<js_sys::Function>,
        on_error: Option<js_sys::Function>,
    ) -> Self {
        let noop = || js_sys::Function::new_no_args("");
        let on_state_change = on_state_change.unwrap_or_else(noop);
        let pending_state_callbacks = Rc::new(RefCell::new(VecDeque::new()));
        let callback_queue = pending_state_callbacks.clone();
        let callback = on_state_change.clone();
        let state_callback = Closure::wrap(Box::new(move || {
            let state = callback_queue.borrow_mut().pop_front();
            if let Some(state) = state {
                let _ = callback.call1(&JsValue::NULL, &JsValue::from(state as u8));
            }
        }) as Box<dyn FnMut()>);
        Self {
            transport: Rc::new(RefCell::new(None)),
            connection_generation: Rc::new(Cell::new(0)),
            state: Rc::new(Cell::new(ConnectionState::Disconnected)),
            pending_state_callbacks,
            state_callback,
            on_message: on_message.unwrap_or_else(noop),
            on_error: on_error.unwrap_or_else(noop),
            subscriptions: Rc::new(RefCell::new(HashMap::new())),
            next_subscription_id: Rc::new(Cell::new(1)),
            pending_requests: Rc::new(RefCell::new(HashMap::new())),
            ping_timer: Rc::new(RefCell::new(None)),
            pending_pings: Rc::new(RefCell::new(HashMap::new())),
            ping_ms: Rc::new(Cell::new(None)),
            pending_pipe_creations: Rc::new(RefCell::new(HashMap::new())),
            pending_pipes: Rc::new(RefCell::new(HashMap::new())),
            on_pipe_request: Rc::new(RefCell::new(None)),
        }
    }

    #[wasm_bindgen]
    pub fn is_supported() -> bool {
        js_sys::Reflect::has(&js_sys::global(), &JsValue::from_str("WebTransport")).unwrap_or(false)
    }

    #[wasm_bindgen(getter)]
    pub fn state(&self) -> u8 {
        self.state.get() as u8
    }

    #[wasm_bindgen(getter)]
    pub fn ping_ms(&self) -> Option<f64> {
        self.ping_ms.get()
    }

    #[wasm_bindgen]
    pub async fn connect(&self, config: &ConnectionConfig) -> Result<(), JsValue> {
        let generation = self.begin_connection();
        let transport = WasmTransport::connect(
            &config.url,
            config.server_certificate_hashes.clone(),
            config.max_message_size,
        )
        .await?;

        let version_str = format!("{}", PROTOCOL_VERSION);
        let mut ident = CommunicationValue::new(CommunicationType::Identification)
            .add_typed_default(DataType::Version, DataValue::Str(version_str))
            .add_typed_default(
                DataType::Id,
                DataValue::UnsignedNumber(config.client_id as u128),
            );
        if let Some(desc) = &config.description {
            ident = ident.add_typed_default(DataType::Description, DataValue::Str(desc.clone()));
        }
        let ident_bytes = ident
            .to_bytes()
            .map_err(|e| js_error(format!("encode failed: {}", e)))?;
        transport.send_frame(&ident_bytes).await?;

        let outcome_bytes = transport.read_one_frame().await?;
        let outcome = CommunicationValue::from_bytes(&outcome_bytes)
            .map_err(|e| js_error(format!("parse handshake outcome: {e}")))?;
        let tm = mtp_codec::TypeMap::latest();
        if Some(outcome.get_type()) == CommunicationType::ErrorBadVersion.try_to_id(&tm) {
            self.set_state_if_current(generation, ConnectionState::Disconnected);
            return Err(js_error(
                outcome
                    .get_str(DataType::ErrorMessage)
                    .unwrap_or("host does not support this protocol version"),
            ));
        }
        let expected = CommunicationType::IdentificationResponse
            .try_to_id(&tm)
            .ok_or_else(|| js_error("IdentificationResponse is absent from the type map"))?;
        if outcome.get_type() != expected
            || outcome.get_data(DataType::Connected) != &DataValue::BoolTrue
        {
            self.set_state_if_current(generation, ConnectionState::Disconnected);
            return Err(js_error(
                outcome
                    .get_str(DataType::ErrorMessage)
                    .unwrap_or("host rejected the connection"),
            ));
        }
        match outcome.get_data(DataType::Version) {
            DataValue::Str(version) if mtp_codec::Version::parse(version).is_some() => {}
            _ => {
                self.set_state_if_current(generation, ConnectionState::Disconnected);
                return Err(js_error("host omitted a valid negotiated protocol version"));
            }
        }

        if !self.start_receive_loop(transport, generation) {
            return Err(js_error("connection attempt superseded"));
        }
        Ok(())
    }

    #[wasm_bindgen]
    pub async fn auth_connect(
        &self,
        config: &ConnectionConfig,
        host_public_key_bytes: &[u8],
        keyring_bytes: &[u8],
        client_id: u64,
    ) -> Result<u64, JsValue> {
        let generation = self.begin_connection();

        let host_pk = mtp_crypto::PublicKeyBundle::from_bytes(host_public_key_bytes)
            .map_err(|e| js_error(format!("invalid host public key: {}", e)))?;
        let keyring = mtp_crypto::Keyring::from_bytes(keyring_bytes)
            .map_err(|e| js_error(format!("invalid keyring: {}", e)))?;

        let tm = mtp_codec::TypeMap::latest();
        let version_str = format!("{}", PROTOCOL_VERSION);

        let transport = WasmTransport::connect(
            &config.url,
            config.server_certificate_hashes.clone(),
            config.max_message_size,
        )
        .await?;

        let mut hello = CommunicationValue::new(CommunicationType::Identification)
            .add_typed_default(DataType::Version, DataValue::Str(version_str.clone()))
            .add_typed_default(DataType::Id, DataValue::UnsignedNumber(client_id as u128));
        if let Some(desc) = &config.description {
            hello = hello.add_typed_default(DataType::Description, DataValue::Str(desc.clone()));
        }
        let hello_bytes = hello
            .to_bytes()
            .map_err(|e| js_error(format!("encode failed: {}", e)))?;
        transport.send_frame(&hello_bytes).await?;

        let server_challenge = self
            .read_verified_challenge(
                &transport,
                &tm,
                &host_pk,
                client_id,
                "auth_connect challenge",
                config.require_pq,
                !keyring.sig_pq_secret_key.as_bytes().is_empty(),
                generation,
            )
            .await?;

        let client_nonce = auth::random_nonce()?;

        let proof_payload = mtp_crypto::auth::login_proof_payload(
            &version_str,
            client_id,
            server_challenge,
            client_nonce,
        );
        let proof = auth::signed_challenge_response_bytes(&keyring, &proof_payload, client_nonce)?;
        transport.send_frame(&proof).await?;

        let response = transport.read_one_frame().await?;
        let resp_comm = CommunicationValue::from_bytes(&response)
            .map_err(|e| js_error(format!("parse response: {}", e)))?;
        let resp_type = resp_comm.get_type();
        let expected_type = CommunicationType::IdentificationResponse
            .try_to_id(&tm)
            .ok_or_else(|| js_error("IdentificationResponse is absent from the type map"))?;
        if resp_type != expected_type {
            self.set_state_if_current(generation, ConnectionState::Disconnected);
            return Err(auth::unexpected_response_type_error(
                "auth_connect",
                expected_type,
                resp_type,
                &response,
                &resp_comm,
            ));
        }

        if resp_comm.get_data(DataType::Connected) != &DataValue::BoolTrue {
            self.set_state_if_current(generation, ConnectionState::Disconnected);
            return Err(js_error(
                resp_comm
                    .get_str(DataType::ErrorMessage)
                    .unwrap_or("host rejected authentication"),
            ));
        }

        if let Err(e) = auth::verify_host_final(
            &resp_comm,
            &tm,
            &host_pk,
            client_id,
            client_nonce,
            server_challenge,
            config.require_pq,
        ) {
            self.set_state_if_current(generation, ConnectionState::Disconnected);
            return Err(e);
        }

        let assigned_id = match resp_comm.get_data(DataType::Id) {
            DataValue::UnsignedNumber(n) => *n as u64,
            _ => {
                self.set_state_if_current(generation, ConnectionState::Disconnected);
                return Err(js_error("missing assigned ID"));
            }
        };

        if !self.start_receive_loop(transport, generation) {
            return Err(js_error("connection attempt superseded"));
        }

        Ok(assigned_id)
    }

    #[wasm_bindgen]
    pub async fn auth_register(
        &self,
        config: &ConnectionConfig,
        host_public_key_bytes: &[u8],
        keyring_bytes: &[u8],
    ) -> Result<u64, JsValue> {
        let generation = self.begin_connection();

        let host_pk = mtp_crypto::PublicKeyBundle::from_bytes(host_public_key_bytes)
            .map_err(|e| js_error(format!("invalid host public key: {}", e)))?;
        let keyring = mtp_crypto::Keyring::from_bytes(keyring_bytes)
            .map_err(|e| js_error(format!("invalid keyring: {}", e)))?;

        let tm = mtp_codec::TypeMap::latest();
        let version_str = format!("{}", PROTOCOL_VERSION);
        let pk_bytes = keyring.public_key_bundle().as_bytes();

        let transport = WasmTransport::connect(
            &config.url,
            config.server_certificate_hashes.clone(),
            config.max_message_size,
        )
        .await?;

        let mut hello = CommunicationValue::new(CommunicationType::Register)
            .add_typed_default(DataType::Version, DataValue::Str(version_str.clone()))
            .add_typed_default(DataType::PublicKeys, DataValue::Bytes(pk_bytes.clone()));
        if let Some(desc) = &config.description {
            hello = hello.add_typed_default(DataType::Description, DataValue::Str(desc.clone()));
        }
        let hello_bytes = hello
            .to_bytes()
            .map_err(|e| js_error(format!("encode failed: {}", e)))?;
        transport.send_frame(&hello_bytes).await?;

        let server_challenge = self
            .read_verified_challenge(
                &transport,
                &tm,
                &host_pk,
                0,
                "auth_register challenge",
                config.require_pq,
                !keyring.sig_pq_secret_key.as_bytes().is_empty(),
                generation,
            )
            .await?;

        let client_nonce = auth::random_nonce()?;

        let proof_payload = mtp_crypto::auth::register_proof_payload(
            &version_str,
            &pk_bytes,
            server_challenge,
            client_nonce,
        );
        let proof = auth::signed_challenge_response_bytes(&keyring, &proof_payload, client_nonce)?;
        transport.send_frame(&proof).await?;

        let response = transport.read_one_frame().await?;
        let resp_comm = CommunicationValue::from_bytes(&response)
            .map_err(|e| js_error(format!("parse response: {}", e)))?;
        let resp_type = resp_comm.get_type();
        let expected_type = CommunicationType::RegisterResponse
            .try_to_id(&tm)
            .ok_or_else(|| js_error("RegisterResponse is absent from the type map"))?;
        if resp_type != expected_type {
            self.set_state_if_current(generation, ConnectionState::Disconnected);
            return Err(auth::unexpected_response_type_error(
                "auth_register",
                expected_type,
                resp_type,
                &response,
                &resp_comm,
            ));
        }

        if resp_comm.get_data(DataType::Connected) != &DataValue::BoolTrue {
            self.set_state_if_current(generation, ConnectionState::Disconnected);
            return Err(js_error(
                resp_comm
                    .get_str(DataType::ErrorMessage)
                    .unwrap_or("host rejected registration"),
            ));
        }

        let assigned_id = match resp_comm.get_data(DataType::Id) {
            DataValue::UnsignedNumber(n) => *n as u64,
            _ => {
                self.set_state_if_current(generation, ConnectionState::Disconnected);
                return Err(js_error("missing assigned ID"));
            }
        };

        if let Err(e) = auth::verify_host_final(
            &resp_comm,
            &tm,
            &host_pk,
            assigned_id,
            client_nonce,
            server_challenge,
            config.require_pq,
        ) {
            self.set_state_if_current(generation, ConnectionState::Disconnected);
            return Err(e);
        }

        if !self.start_receive_loop(transport, generation) {
            return Err(js_error("connection attempt superseded"));
        }

        Ok(assigned_id)
    }

    #[wasm_bindgen]
    pub async fn send(&self, frame: Vec<u8>) -> Result<(), JsValue> {
        match self.transport.borrow().clone() {
            Some(t) => t.send_frame(&frame).await,
            None => Err(js_error("not connected")),
        }
    }

    #[wasm_bindgen]
    pub async fn request(
        &self,
        frame: Vec<u8>,
        response_type: Option<String>,
        timeout_ms: Option<u32>,
    ) -> Result<JsValue, JsValue> {
        let request = CommunicationValue::from_bytes(&frame)
            .map_err(|e| js_error(format!("parse request: {}", e)))?;
        let request_id = request.get_id();
        if request_id == 0 {
            return Err(js_error("request frame must have a non-zero id"));
        }

        let Some(transport) = self.transport.borrow().clone() else {
            return Err(js_error("not connected"));
        };

        let (sender, receiver) = oneshot::channel();
        let token = Rc::new(());
        {
            let mut pending = self.pending_requests.borrow_mut();
            if pending.contains_key(&request_id) {
                return Err(js_error(format!(
                    "request id {request_id} is already pending"
                )));
            }
            pending.insert(
                request_id,
                PendingRequest {
                    token: token.clone(),
                    response_type,
                    sender,
                },
            );
        }

        let timeout_ms = timeout_ms.unwrap_or(DEFAULT_REQUEST_TIMEOUT_MS);
        let response = async {
            transport.send_frame(&frame).await?;
            match receiver.await {
                Ok(result) => result,
                Err(_) => Err(js_error("request cancelled")),
            }
        }
        .fuse();
        let timeout = wait_for_timeout(timeout_ms).fuse();
        pin_mut!(response, timeout);
        select! {
            result = response => {
                if result.is_err() {
                    client_pipe::remove_pending_request(&self.pending_requests, request_id, &token);
                }
                result
            },
            result = timeout => {
                client_pipe::remove_pending_request(&self.pending_requests, request_id, &token);
                result?;
                Err(js_error(format!(
                    "request {request_id} timed out after {timeout_ms}ms"
                )))
            },
        }
    }

    #[wasm_bindgen]
    pub fn subscribe(&self, message_type: String, callback: js_sys::Function) -> u32 {
        let id = self.next_subscription_id.get();
        self.next_subscription_id.set(id.wrapping_add(1).max(1));
        self.subscriptions
            .borrow_mut()
            .insert(id, (message_type, callback));
        id
    }

    #[wasm_bindgen]
    pub fn unsubscribe(&self, id: u32) -> bool {
        self.subscriptions.borrow_mut().remove(&id).is_some()
    }

    #[wasm_bindgen]
    pub fn start_protocol_pings(&self, interval_ms: u32, client_id: u64) -> Result<(), JsValue> {
        self.stop_protocol_pings();
        let Some(transport) = self.transport.borrow().clone() else {
            return Err(js_error("not connected"));
        };
        let interval_ms = interval_ms.max(1_000) as i32;
        let on_error = self.on_error.clone();
        let pending_pings = self.pending_pings.clone();
        let closure = Closure::wrap(Box::new(move || {
            let transport = transport.clone();
            let on_error = on_error.clone();
            let pending_pings = pending_pings.clone();
            wasm_bindgen_futures::spawn_local(async move {
                let sent_at = js_sys::Date::now();
                pending_pings
                    .borrow_mut()
                    .retain(|_, pending_at| sent_at - *pending_at < interval_ms as f64 * 3.0);
                let timestamp = sent_at as u64;
                let frame = CommunicationValue::new(CommunicationType::Ping)
                    .add_typed_default(
                        DataType::Description,
                        DataValue::Str("protocol ping".into()),
                    )
                    .add_typed_default(
                        DataType::Timestamp,
                        DataValue::UnsignedNumber(timestamp as u128),
                    )
                    .with_sender(client_id);
                let ping_id = frame.get_id();
                let frame = frame
                    .to_bytes()
                    .map_err(|e| js_error(format!("encode ping failed: {}", e)));
                match frame {
                    Ok(frame) => {
                        pending_pings.borrow_mut().insert(ping_id, sent_at);
                        if let Err(error) = transport.send_frame(&frame).await {
                            pending_pings.borrow_mut().remove(&ping_id);
                            let _ = on_error.call1(&JsValue::NULL, &error);
                        }
                    }
                    Err(error) => {
                        let _ = on_error.call1(&JsValue::NULL, &error);
                    }
                }
            });
        }) as Box<dyn FnMut()>);

        let set_interval =
            js_sys::Reflect::get(&js_sys::global(), &JsValue::from_str("setInterval"))?
                .dyn_into::<js_sys::Function>()?;
        let id = set_interval
            .call2(
                &JsValue::NULL,
                closure.as_ref().unchecked_ref(),
                &JsValue::from_f64(interval_ms as f64),
            )?
            .as_f64()
            .ok_or_else(|| js_error("setInterval did not return an id"))? as i32;
        *self.ping_timer.borrow_mut() = Some(PingTimer { id, closure });
        Ok(())
    }

    #[wasm_bindgen]
    pub fn stop_protocol_pings(&self) {
        self.pending_pings.borrow_mut().clear();
        self.ping_ms.set(None);
        let Some(timer) = self.ping_timer.borrow_mut().take() else {
            return;
        };
        if let Ok(clear_interval) =
            js_sys::Reflect::get(&js_sys::global(), &JsValue::from_str("clearInterval"))
                .and_then(|value| value.dyn_into::<js_sys::Function>())
        {
            let _ = clear_interval.call1(&JsValue::NULL, &JsValue::from_f64(timer.id as f64));
        }
        drop(timer.closure);
    }

    #[wasm_bindgen]
    pub fn disconnect(&self) {
        self.connection_generation
            .set(self.connection_generation.get().wrapping_add(1));
        self.stop_protocol_pings();
        if let Some(t) = self.transport.borrow_mut().take() {
            t.close();
        }
        self.subscriptions.borrow_mut().clear();
        self.reject_pending_requests("disconnected");
        client_pipe::reject_pending_pipe_creations(&self.pending_pipe_creations, "disconnected");
        self.set_state(ConnectionState::Disconnected);
    }

    #[wasm_bindgen]
    pub fn set_on_pipe_request(&self, callback: Option<js_sys::Function>) {
        *self.on_pipe_request.borrow_mut() = callback;
    }

    #[wasm_bindgen]
    pub async fn create_pipe(
        &self,
        description: &str,
    ) -> Result<client_pipe::WasmPipeHandle, JsValue> {
        let transport = self
            .transport
            .borrow()
            .clone()
            .ok_or_else(|| js_error("not connected"))?;

        let pipe_id = client_pipe::random_pipe_id()?;
        client_pipe::wasm_create_pipe(
            &transport,
            description,
            pipe_id,
            &self.pending_pipe_creations,
        )
        .await
    }

    #[wasm_bindgen]
    pub async fn accept_pipe(&self, pipe_id: u32) -> Result<PipeReader, JsValue> {
        let transport = self
            .transport
            .borrow()
            .clone()
            .ok_or_else(|| js_error("not connected"))?;

        client_pipe::wasm_accept_pipe(&transport, pipe_id, &self.pending_pipes).await
    }

    #[wasm_bindgen]
    pub async fn deny_pipe(&self, pipe_id: u32) -> Result<(), JsValue> {
        let transport = self
            .transport
            .borrow()
            .clone()
            .ok_or_else(|| js_error("not connected"))?;

        client_pipe::wasm_deny_pipe(&transport, pipe_id).await
    }

    fn set_state(&self, new_state: ConnectionState) {
        set_shared_state(
            &self.state,
            &self.pending_state_callbacks,
            self.state_callback.as_ref(),
            new_state,
        );
    }

    fn set_state_if_current(&self, generation: u32, new_state: ConnectionState) {
        if self.connection_generation.get() == generation {
            self.set_state(new_state);
        }
    }

    fn begin_connection(&self) -> u32 {
        let generation = self.connection_generation.get().wrapping_add(1);
        self.connection_generation.set(generation);
        self.stop_protocol_pings();
        if let Some(transport) = self.transport.borrow_mut().take() {
            transport.close();
        }
        self.reject_pending_requests("connection replaced");
        client_pipe::reject_pending_pipe_creations(
            &self.pending_pipe_creations,
            "connection replaced",
        );
        self.set_state(ConnectionState::Connecting);
        generation
    }

    fn start_receive_loop(&self, transport: WasmTransport, generation: u32) -> bool {
        if self.connection_generation.get() != generation {
            transport.close();
            return false;
        }
        let loop_transport = transport.clone();
        *self.transport.borrow_mut() = Some(transport);
        self.set_state(ConnectionState::Connected);

        let connection_generation = self.connection_generation.clone();
        let error_generation = connection_generation.clone();
        let state = self.state.clone();
        let pending_state_callbacks = self.pending_state_callbacks.clone();
        let state_callback = self.state_callback.as_ref().clone();
        let on_msg = self.on_message.clone();
        let on_err = self.on_error.clone();
        let subscriptions = self.subscriptions.clone();
        let pending_requests = self.pending_requests.clone();
        let loop_pending_requests = pending_requests.clone();
        let ping_timer = self.ping_timer.clone();
        let pending_pings = self.pending_pings.clone();
        let loop_pending_pings = pending_pings.clone();
        let ping_ms = self.ping_ms.clone();
        let loop_ping_ms = ping_ms.clone();
        let pending_pipe_creations = self.pending_pipe_creations.clone();
        let pending_pipes = self.pending_pipes.clone();
        let on_pipe_request = self.on_pipe_request.clone();
        let loop_pipe_creations = pending_pipe_creations.clone();
        wasm_bindgen_futures::spawn_local(async move {
            loop_transport
                .receive_loop_with_pipes(
                    move |frame: JsValue| {
                        let message_type = frame_type(&frame);
                        if let Some(ref msg_type) = message_type {
                            if msg_type == "PipeRequest" {
                                let pipe_id = frame_id(&frame).unwrap_or(0);
                                let description = frame_property(&frame, "data")
                                    .and_then(|data| {
                                        let desc = js_sys::Reflect::get(
                                            &data,
                                            &JsValue::from_str("Description"),
                                        )
                                        .ok()?;
                                        desc.as_string()
                                    })
                                    .unwrap_or_default();

                                let cb = on_pipe_request.borrow();
                                if let Some(ref callback) = *cb {
                                    let obj = js_sys::Object::new();
                                    let _ = js_sys::Reflect::set(
                                        &obj,
                                        &"pipeId".into(),
                                        &JsValue::from_f64(pipe_id as f64),
                                    );
                                    let _ = js_sys::Reflect::set(
                                        &obj,
                                        &"description".into(),
                                        &JsValue::from_str(&description),
                                    );
                                    let _ = callback.call1(&JsValue::NULL, &obj.into());
                                }
                                return;
                            }

                            if msg_type == "PipeResponse" {
                                let pipe_id = frame_id(&frame).unwrap_or(0);
                                let accepted = frame_property(&frame, "data")
                                    .and_then(|data| {
                                        let acc = js_sys::Reflect::get(
                                            &data,
                                            &JsValue::from_str("Accepted"),
                                        )
                                        .ok()?;
                                        acc.as_bool()
                                    })
                                    .unwrap_or(false);

                                let mut pending = loop_pipe_creations.borrow_mut();
                                if let Some(tx) = pending.remove(&pipe_id) {
                                    let _ = tx.send(Ok(accepted));
                                }
                                return;
                            }
                        }

                        route_incoming_frame(
                            &frame,
                            &on_msg,
                            &subscriptions,
                            &loop_pending_requests,
                            &loop_pending_pings,
                            &loop_ping_ms,
                        );
                    },
                    move |error| {
                        if error_generation.get() == generation {
                            let _ = on_err.call1(&JsValue::NULL, &error);
                        }
                    },
                    move |pipe_reader: PipeReader| {
                        let pipe_id = pipe_reader.pipe_id();
                        let mut pending = pending_pipes.borrow_mut();
                        if let Some(tx) = pending.remove(&pipe_id) {
                            let _ = tx.send(pipe_reader);
                        }
                    },
                )
                .await;
            if connection_generation.get() != generation {
                return;
            }
            set_shared_state(
                &state,
                &pending_state_callbacks,
                &state_callback,
                ConnectionState::Disconnected,
            );
            stop_ping_timer(&ping_timer);
            pending_pings.borrow_mut().clear();
            ping_ms.set(None);
            reject_pending_requests(&pending_requests, "disconnected");
            client_pipe::reject_pending_pipe_creations(&pending_pipe_creations, "disconnected");
        });
        true
    }

    fn reject_pending_requests(&self, message: &str) {
        reject_pending_requests(&self.pending_requests, message);
    }

    async fn read_verified_challenge(
        &self,
        transport: &WasmTransport,
        tm: &mtp_codec::TypeMap,
        host_pk: &mtp_crypto::PublicKeyBundle,
        bound_id: u64,
        context: &str,
        require_pq: bool,
        client_has_pq_key: bool,
        generation: u32,
    ) -> Result<u128, JsValue> {
        let challenge_bytes = transport.read_one_frame().await?;
        let challenge = CommunicationValue::from_bytes(&challenge_bytes)
            .map_err(|e| js_error(format!("parse challenge: {}", e)))?;
        let expected = CommunicationType::Challenge
            .try_to_id(tm)
            .ok_or_else(|| js_error("Challenge is absent from the type map"))?;
        if challenge.get_type() != expected {
            self.set_state_if_current(generation, ConnectionState::Disconnected);
            return Err(auth::unexpected_response_type_error(
                context,
                expected,
                challenge.get_type(),
                &challenge_bytes,
                &challenge,
            ));
        }

        let server_challenge = match challenge.get_data(DataType::ServerNonce) {
            DataValue::UnsignedNumber(n) => *n,
            _ => {
                self.set_state_if_current(generation, ConnectionState::Disconnected);
                return Err(js_error("missing server challenge"));
            }
        };

        if challenge.get_data(DataType::RequirePq) == &DataValue::BoolTrue && !client_has_pq_key {
            self.set_state_if_current(generation, ConnectionState::Disconnected);
            return Err(js_error(
                "host requires post-quantum authentication but the client PQ key is absent",
            ));
        }

        if let Err(e) = auth::verify_host_challenge(
            &challenge,
            tm,
            host_pk,
            bound_id,
            server_challenge,
            require_pq,
        ) {
            self.set_state_if_current(generation, ConnectionState::Disconnected);
            return Err(e);
        }

        Ok(server_challenge)
    }
}
