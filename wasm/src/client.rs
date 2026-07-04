use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::rc::Rc;

use futures_channel::oneshot;
use wasm_bindgen::JsCast;
use wasm_bindgen::prelude::*;

use mtp_codec::{CommunicationType, CommunicationValue, DataType, DataValue, PROTOCOL_VERSION};
use mtp_type_map::CommunicationTypeId;

use mtp_crypto::SignatureScheme;

use crate::config::ConnectionConfig;
use crate::error::js_error;
use crate::transport::WasmTransport;

struct PendingRequest {
    response_type: Option<String>,
    sender: oneshot::Sender<Result<JsValue, JsValue>>,
}

struct PingTimer {
    id: i32,
    closure: Closure<dyn FnMut()>,
}

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
) {
    let message_type = frame_type(frame);

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
                let _ = pending.sender.send(Err(js_error(&format!(
                    "unexpected response type: expected {}, got {}",
                    pending.response_type.unwrap_or_else(|| "unknown".into()),
                    actual
                ))));
            }
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
            .and_then(|value| value.dyn_into::<js_sys::Function>().map_err(Into::into))
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

fn raw_frame_preview(bytes: &[u8]) -> String {
    let shown = bytes.len().min(256);
    let mut preview = hex::encode(&bytes[..shown]);
    if bytes.len() > shown {
        preview.push_str("...");
    }
    format!("{} bytes, hex={preview}", bytes.len())
}

fn unexpected_response_type_error(
    context: &str,
    expected_type: CommunicationTypeId,
    response_type: CommunicationTypeId,
    response: &[u8],
    parsed: &CommunicationValue,
) -> JsValue {
    js_error(&format!(
        "unexpected response type during {context}: expected {:?}, got {:?}; raw {}; parsed {}",
        expected_type,
        response_type,
        raw_frame_preview(response),
        parsed
    ))
}

/*
 * Verify the host's signature over the challenge it issued (step 2), mirroring
 * the native client (`client/src/lib.rs`). `id` is the client id for a login or
 * `0` for a registration. The Ed25519 signature is mandatory; the ML-DSA
 * signature is verified only when the host included one.
 */
fn verify_host_challenge(
    challenge: &CommunicationValue,
    _tm: &mtp_codec::TypeMap,
    host_pk: &mtp_crypto::PublicKeyBundle,
    id: u64,
    server_challenge: u128,
) -> Result<(), JsValue> {
    let sig = match challenge.get_data(DataType::Signature) {
        DataValue::Bytes(b) => b.clone(),
        _ => return Err(js_error("missing host challenge signature")),
    };
    let pq_sig = match challenge.get_data(DataType::PqSignature) {
        DataValue::Bytes(b) => b.clone(),
        _ => vec![],
    };

    let payload = mtp_crypto::auth::challenge_payload(id, server_challenge);
    mtp_crypto::verify_ed25519(&host_pk.sig_cl_public_key, &payload, &sig)
        .map_err(|_| js_error("host challenge signature invalid"))?;
    if !pq_sig.is_empty() {
        mtp_crypto::verify_ml_dsa(&host_pk.sig_pq_public_key, &payload, &pq_sig)
            .map_err(|_| js_error("host challenge PQ signature invalid"))?;
    }
    Ok(())
}

/*
 * Verify the host's final confirmation (step 4): the echoed `client_nonce` and
 * the host signature over the handshake transcript. `id` is the client id for a
 * login and the host-assigned id for a register.
 */
fn verify_host_final(
    resp: &CommunicationValue,
    _tm: &mtp_codec::TypeMap,
    host_pk: &mtp_crypto::PublicKeyBundle,
    id: u64,
    client_nonce: u128,
    server_challenge: u128,
) -> Result<(), JsValue> {
    if *resp.get_data(DataType::ClientNonce) != DataValue::UnsignedNumber(client_nonce) {
        return Err(js_error("nonce mismatch"));
    }
    let host_sig = match resp.get_data(DataType::Signature) {
        DataValue::Bytes(b) => b.clone(),
        _ => return Err(js_error("missing host signature")),
    };
    let host_pq_sig = match resp.get_data(DataType::PqSignature) {
        DataValue::Bytes(b) => b.clone(),
        _ => vec![],
    };

    let payload = mtp_crypto::auth::host_final_payload(id, client_nonce, server_challenge);
    mtp_crypto::verify_ed25519(&host_pk.sig_cl_public_key, &payload, &host_sig)
        .map_err(|_| js_error("host signature invalid"))?;
    if !host_pq_sig.is_empty() {
        mtp_crypto::verify_ml_dsa(&host_pk.sig_pq_public_key, &payload, &host_pq_sig)
            .map_err(|_| js_error("host PQ signature invalid"))?;
    }
    Ok(())
}

fn random_nonce() -> Result<u128, JsValue> {
    let mut nonce_bytes = [0u8; 16];
    getrandom::fill(&mut nonce_bytes).map_err(|_| js_error("rng failed"))?;
    Ok(u128::from_be_bytes(nonce_bytes))
}

fn signed_challenge_response_bytes(
    keyring: &mtp_crypto::Keyring,
    proof_payload: &[u8],
    client_nonce: u128,
) -> Result<Vec<u8>, JsValue> {
    let signer = mtp_crypto::Ed25519Signer::new(&keyring.sig_cl_secret_key)
        .map_err(|e| js_error(&format!("signer creation failed: {}", e)))?;
    let signature = signer
        .sign(proof_payload)
        .map_err(|e| js_error(&format!("signature failed: {}", e)))?;

    let mut proof = CommunicationValue::new(CommunicationType::ChallengeResponse)
        .add_typed_default(
            DataType::ClientNonce,
            DataValue::UnsignedNumber(client_nonce),
        )
        .add_typed_default(DataType::Signature, DataValue::Bytes(signature));

    if !keyring.sig_pq_secret_key.as_bytes().is_empty() {
        let pq_signer =
            mtp_crypto::MlDsaSigner::new(&keyring.sig_pq_secret_key, &keyring.sig_pq_public_key)
                .map_err(|e| js_error(&format!("PQ signer creation failed: {}", e)))?;
        let pq_signature = pq_signer
            .sign(proof_payload)
            .map_err(|e| js_error(&format!("PQ signature failed: {}", e)))?;
        proof = proof.add_typed_default(DataType::PqSignature, DataValue::Bytes(pq_signature));
    }

    proof
        .to_bytes()
        .map_err(|e| js_error(&format!("encode failed: {}", e)))
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
    transport: Option<WasmTransport>,
    state: Rc<Cell<ConnectionState>>,
    on_state_change: js_sys::Function,
    pub(crate) on_message: js_sys::Function,
    pub(crate) on_error: js_sys::Function,
    subscriptions: Rc<RefCell<HashMap<u32, (String, js_sys::Function)>>>,
    next_subscription_id: Rc<Cell<u32>>,
    pending_requests: Rc<RefCell<HashMap<u32, PendingRequest>>>,
    ping_timer: Rc<RefCell<Option<PingTimer>>>,
}

#[wasm_bindgen]
impl WasmClient {
    #[wasm_bindgen(constructor)]
    pub fn new(
        on_state_change: &js_sys::Function,
        on_message: &js_sys::Function,
        on_error: &js_sys::Function,
    ) -> Self {
        Self {
            transport: None,
            state: Rc::new(Cell::new(ConnectionState::Disconnected)),
            on_state_change: on_state_change.clone(),
            on_message: on_message.clone(),
            on_error: on_error.clone(),
            subscriptions: Rc::new(RefCell::new(HashMap::new())),
            next_subscription_id: Rc::new(Cell::new(1)),
            pending_requests: Rc::new(RefCell::new(HashMap::new())),
            ping_timer: Rc::new(RefCell::new(None)),
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

    /// Unauthenticated connect (sends basic Identification, enables receive loop).
    #[wasm_bindgen]
    pub async fn connect(&mut self, config: &ConnectionConfig) -> Result<(), JsValue> {
        self.set_state(ConnectionState::Connecting);
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
            .map_err(|e| js_error(&format!("encode failed: {}", e)))?;
        transport.send_frame(&ident_bytes).await?;

        self.start_receive_loop(transport);
        Ok(())
    }

    /// Authenticated login with an existing client ID.
    /// Exchanges Identification + signatures and verifies the host response.
    ///
    /// - `host_public_key_bytes`: serialized PublicKeyBundle from the server
    /// - `keyring_bytes`: serialized Keyring of this client (must match `client_id`)
    /// - `client_id`: previously assigned client ID
    ///
    /// Returns the confirmed (same) client ID on success.
    #[wasm_bindgen]
    pub async fn auth_connect(
        &mut self,
        config: &ConnectionConfig,
        host_public_key_bytes: &[u8],
        keyring_bytes: &[u8],
        client_id: u64,
    ) -> Result<u64, JsValue> {
        self.set_state(ConnectionState::Connecting);

        let host_pk = mtp_crypto::PublicKeyBundle::from_bytes(host_public_key_bytes)
            .map_err(|e| js_error(&format!("invalid host public key: {}", e)))?;
        let keyring = mtp_crypto::Keyring::from_bytes(keyring_bytes)
            .map_err(|e| js_error(&format!("invalid keyring: {}", e)))?;

        let tm = mtp_codec::TypeMap::latest();
        let version_str = format!("{}", PROTOCOL_VERSION);

        let transport = WasmTransport::connect(
            &config.url,
            config.server_certificate_hashes.clone(),
            config.max_message_size,
        )
        .await?;

        // 1. Send the unsigned Identification hello.
        let mut hello = CommunicationValue::new(CommunicationType::Identification)
            .add_typed_default(DataType::Version, DataValue::Str(version_str.clone()))
            .add_typed_default(DataType::Id, DataValue::UnsignedNumber(client_id as u128));
        if let Some(desc) = &config.description {
            hello = hello.add_typed_default(DataType::Description, DataValue::Str(desc.clone()));
        }
        let hello_bytes = hello
            .to_bytes()
            .map_err(|e| js_error(&format!("encode failed: {}", e)))?;
        transport.send_frame(&hello_bytes).await?;

        // 2. Receive and verify the host's challenge.
        let server_challenge = self
            .read_verified_challenge(
                &transport,
                &tm,
                &host_pk,
                client_id,
                "auth_connect challenge",
            )
            .await?;

        // 3. Sign the host's challenge and send the proof.
        let client_nonce = random_nonce()?;

        let proof_payload = mtp_crypto::auth::login_proof_payload(
            &version_str,
            client_id,
            server_challenge,
            client_nonce,
        );
        let proof = signed_challenge_response_bytes(&keyring, &proof_payload, client_nonce)?;
        transport.send_frame(&proof).await?;

        // 4. Receive and verify the host's final confirmation.
        let response = transport.read_one_frame().await?;
        let resp_comm = CommunicationValue::from_bytes(&response)
            .map_err(|e| js_error(&format!("parse response: {}", e)))?;
        let resp_type = resp_comm.get_type();
        let expected_type = CommunicationType::IdentificationResponse.to_id(&tm);
        if resp_type != expected_type {
            self.set_state(ConnectionState::Disconnected);
            return Err(unexpected_response_type_error(
                "auth_connect",
                expected_type,
                resp_type,
                &response,
                &resp_comm,
            ));
        }

        if resp_comm.get_data(DataType::Connected) != &DataValue::BoolTrue {
            self.set_state(ConnectionState::Disconnected);
            return Err(js_error("host rejected authentication"));
        }

        // Verify echoed nonce + host signature (login: id is client_id).
        if let Err(e) = verify_host_final(
            &resp_comm,
            &tm,
            &host_pk,
            client_id,
            client_nonce,
            server_challenge,
        ) {
            self.set_state(ConnectionState::Disconnected);
            return Err(e);
        }

        // Extract assigned ID
        let assigned_id = match resp_comm.get_data(DataType::Id) {
            DataValue::UnsignedNumber(n) => *n as u64,
            _ => {
                self.set_state(ConnectionState::Disconnected);
                return Err(js_error("missing assigned ID"));
            }
        };

        self.start_receive_loop(transport);

        Ok(assigned_id)
    }

    /// Authenticated registration with a fresh keyring.
    /// The server assigns a new client ID.
    ///
    /// - `host_public_key_bytes`: serialized PublicKeyBundle from the server
    /// - `keyring_bytes`: serialized Keyring (must include ed25519 secret key)
    ///
    /// Returns the newly assigned client ID.
    #[wasm_bindgen]
    pub async fn auth_register(
        &mut self,
        config: &ConnectionConfig,
        host_public_key_bytes: &[u8],
        keyring_bytes: &[u8],
    ) -> Result<u64, JsValue> {
        self.set_state(ConnectionState::Connecting);

        let host_pk = mtp_crypto::PublicKeyBundle::from_bytes(host_public_key_bytes)
            .map_err(|e| js_error(&format!("invalid host public key: {}", e)))?;
        let keyring = mtp_crypto::Keyring::from_bytes(keyring_bytes)
            .map_err(|e| js_error(&format!("invalid keyring: {}", e)))?;

        let tm = mtp_codec::TypeMap::latest();
        let version_str = format!("{}", PROTOCOL_VERSION);
        let pk_bytes = keyring.public_key_bundle().as_bytes();

        let transport = WasmTransport::connect(
            &config.url,
            config.server_certificate_hashes.clone(),
            config.max_message_size,
        )
        .await?;

        // 1. Send the unsigned Register hello (version + public-key bundle).
        let mut hello = CommunicationValue::new(CommunicationType::Register)
            .add_typed_default(DataType::Version, DataValue::Str(version_str.clone()))
            .add_typed_default(DataType::PublicKeys, DataValue::Bytes(pk_bytes.clone()));
        if let Some(desc) = &config.description {
            hello = hello.add_typed_default(DataType::Description, DataValue::Str(desc.clone()));
        }
        let hello_bytes = hello
            .to_bytes()
            .map_err(|e| js_error(&format!("encode failed: {}", e)))?;
        transport.send_frame(&hello_bytes).await?;

        // 2. Receive and verify the host's challenge (register binds id = 0).
        let server_challenge = self
            .read_verified_challenge(&transport, &tm, &host_pk, 0, "auth_register challenge")
            .await?;

        // 3. Sign the host's challenge over the bundle and send the proof.
        let client_nonce = random_nonce()?;

        let proof_payload = mtp_crypto::auth::register_proof_payload(
            &version_str,
            &pk_bytes,
            server_challenge,
            client_nonce,
        );
        let proof = signed_challenge_response_bytes(&keyring, &proof_payload, client_nonce)?;
        transport.send_frame(&proof).await?;

        // 4. Receive the host's final confirmation; extract + verify assigned id.
        let response = transport.read_one_frame().await?;
        let resp_comm = CommunicationValue::from_bytes(&response)
            .map_err(|e| js_error(&format!("parse response: {}", e)))?;
        let resp_type = resp_comm.get_type();
        let expected_type = CommunicationType::RegisterResponse.to_id(&tm);
        if resp_type != expected_type {
            self.set_state(ConnectionState::Disconnected);
            return Err(unexpected_response_type_error(
                "auth_register",
                expected_type,
                resp_type,
                &response,
                &resp_comm,
            ));
        }

        if resp_comm.get_data(DataType::Connected) != &DataValue::BoolTrue {
            self.set_state(ConnectionState::Disconnected);
            return Err(js_error("host rejected registration"));
        }

        let assigned_id = match resp_comm.get_data(DataType::Id) {
            DataValue::UnsignedNumber(n) => *n as u64,
            _ => {
                self.set_state(ConnectionState::Disconnected);
                return Err(js_error("missing assigned ID"));
            }
        };

        // Verify echoed nonce + host signature (register: id is host-assigned).
        if let Err(e) = verify_host_final(
            &resp_comm,
            &tm,
            &host_pk,
            assigned_id,
            client_nonce,
            server_challenge,
        ) {
            self.set_state(ConnectionState::Disconnected);
            return Err(e);
        }

        self.start_receive_loop(transport);

        Ok(assigned_id)
    }

    #[wasm_bindgen]
    pub async fn send(&self, frame: Vec<u8>) -> Result<(), JsValue> {
        match &self.transport {
            Some(t) => t.send_frame(&frame).await,
            None => Err(js_error("not connected")),
        }
    }

    #[wasm_bindgen]
    pub async fn request(
        &self,
        frame: Vec<u8>,
        response_type: Option<String>,
    ) -> Result<JsValue, JsValue> {
        let request = CommunicationValue::from_bytes(&frame)
            .map_err(|e| js_error(&format!("parse request: {}", e)))?;
        let request_id = request.get_id();
        if request_id == 0 {
            return Err(js_error("request frame must have a non-zero id"));
        }

        let Some(transport) = self.transport.clone() else {
            return Err(js_error("not connected"));
        };

        let (sender, receiver) = oneshot::channel();
        self.pending_requests.borrow_mut().insert(
            request_id,
            PendingRequest {
                response_type,
                sender,
            },
        );

        if let Err(error) = transport.send_frame(&frame).await {
            self.pending_requests.borrow_mut().remove(&request_id);
            return Err(error);
        }

        match receiver.await {
            Ok(result) => result,
            Err(_) => Err(js_error("request cancelled")),
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
        let Some(transport) = self.transport.clone() else {
            return Err(js_error("not connected"));
        };
        let interval_ms = interval_ms.max(1_000) as i32;
        let on_error = self.on_error.clone();
        let closure = Closure::wrap(Box::new(move || {
            let transport = transport.clone();
            let on_error = on_error.clone();
            wasm_bindgen_futures::spawn_local(async move {
                let timestamp = js_sys::Date::now() as u64;
                let frame = CommunicationValue::new(CommunicationType::Ping)
                    .add_typed_default(
                        DataType::Description,
                        DataValue::Str("protocol ping".into()),
                    )
                    .add_typed_default(
                        DataType::Timestamp,
                        DataValue::UnsignedNumber(timestamp as u128),
                    )
                    .with_sender(client_id)
                    .to_bytes()
                    .map_err(|e| js_error(&format!("encode ping failed: {}", e)));
                match frame {
                    Ok(frame) => {
                        if let Err(error) = transport.send_frame(&frame).await {
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
        let Some(timer) = self.ping_timer.borrow_mut().take() else {
            return;
        };
        if let Ok(clear_interval) =
            js_sys::Reflect::get(&js_sys::global(), &JsValue::from_str("clearInterval"))
                .and_then(|value| value.dyn_into::<js_sys::Function>().map_err(Into::into))
        {
            let _ = clear_interval.call1(&JsValue::NULL, &JsValue::from_f64(timer.id as f64));
        }
        drop(timer.closure);
    }

    #[wasm_bindgen]
    pub fn disconnect(&mut self) {
        self.stop_protocol_pings();
        if let Some(t) = &self.transport {
            t.close();
        }
        self.transport = None;
        self.subscriptions.borrow_mut().clear();
        self.reject_pending_requests("disconnected");
        self.set_state(ConnectionState::Disconnected);
    }

    fn set_state(&self, new_state: ConnectionState) {
        self.state.set(new_state);

        // Defer the callback to a microtask so re-entrant &mut self calls don't alias.
        let cb = self.on_state_change.clone();
        let val = JsValue::from(new_state as u8);
        let closure = Closure::wrap(Box::new(move || {
            let _ = cb.call1(&JsValue::NULL, &val);
        }) as Box<dyn FnMut()>);

        let global = js_sys::global();
        let mut closure_opt = Some(closure);

        let qmt = js_sys::Reflect::get(&global, &JsValue::from_str("queueMicrotask"))
            .and_then(|f| f.dyn_into::<js_sys::Function>().map_err(Into::into));
        let scheduled = match qmt {
            Ok(qmt) => {
                if let Some(c) = closure_opt.take() {
                    let _ = qmt.call1(&global, c.as_ref());
                    c.forget();
                }
                true
            }
            Err(_) => false,
        };
        if !scheduled {
            if let Ok(set_timeout) = js_sys::Reflect::get(&global, &JsValue::from_str("setTimeout"))
                .and_then(|f| f.dyn_into::<js_sys::Function>().map_err(Into::into))
            {
                if let Some(c) = closure_opt.take() {
                    let _ = set_timeout.call2(&global, c.as_ref(), &JsValue::from_f64(0.0));
                    c.forget();
                }
            }
        }
    }

    fn start_receive_loop(&mut self, transport: WasmTransport) {
        let loop_transport = transport.clone();
        self.transport = Some(transport);
        self.set_state(ConnectionState::Connected);

        let state = self.state.clone();
        let on_msg = self.on_message.clone();
        let on_err = self.on_error.clone();
        let subscriptions = self.subscriptions.clone();
        let pending_requests = self.pending_requests.clone();
        let loop_pending_requests = pending_requests.clone();
        let ping_timer = self.ping_timer.clone();
        wasm_bindgen_futures::spawn_local(async move {
            loop_transport
                .receive_loop(
                    move |frame: JsValue| {
                        route_incoming_frame(
                            &frame,
                            &on_msg,
                            &subscriptions,
                            &loop_pending_requests,
                        );
                    },
                    on_err.clone(),
                )
                .await;
            state.set(ConnectionState::Disconnected);
            stop_ping_timer(&ping_timer);
            reject_pending_requests(&pending_requests, "disconnected");
        });
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
    ) -> Result<u128, JsValue> {
        let challenge_bytes = transport.read_one_frame().await?;
        let challenge = CommunicationValue::from_bytes(&challenge_bytes)
            .map_err(|e| js_error(&format!("parse challenge: {}", e)))?;
        let expected = CommunicationType::Challenge.to_id(tm);
        if challenge.get_type() != expected {
            self.set_state(ConnectionState::Disconnected);
            return Err(unexpected_response_type_error(
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
                self.set_state(ConnectionState::Disconnected);
                return Err(js_error("missing server challenge"));
            }
        };

        if let Err(e) = verify_host_challenge(&challenge, tm, host_pk, bound_id, server_challenge) {
            self.set_state(ConnectionState::Disconnected);
            return Err(e);
        }

        Ok(server_challenge)
    }
}
