use std::cell::Cell;
use std::rc::Rc;

use wasm_bindgen::prelude::*;

use mtp_codec::{
    CommunicationType, CommunicationValue, DataType, DataValue, PROTOCOL_VERSION,
};
use mtp_type_map::{CommunicationTypeId, DataTypeId};

use mtp_crypto::SignatureScheme;

use crate::error::js_error;
use crate::transport::WasmTransport;

#[wasm_bindgen]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    Disconnected = 0,
    Connecting = 1,
    Connected = 2,
    Failed = 3,
}

#[wasm_bindgen]
pub struct ConnectionConfig {
    url: String,
    server_certificate_hashes: Option<Vec<String>>,
    client_id: u64,
}

#[wasm_bindgen]
impl ConnectionConfig {
    #[wasm_bindgen(constructor)]
    pub fn new(url: String) -> Self {
        Self { url, server_certificate_hashes: None, client_id: 0 }
    }

    #[wasm_bindgen(getter)]
    pub fn url(&self) -> String { self.url.clone() }

    #[wasm_bindgen(setter)]
    pub fn set_client_id(&mut self, id: u64) { self.client_id = id; }

    #[wasm_bindgen(getter)]
    pub fn client_id(&self) -> u64 { self.client_id }

    #[wasm_bindgen(setter)]
    pub fn set_server_certificate_hashes(&mut self, hashes: Vec<String>) {
        self.server_certificate_hashes = Some(hashes);
    }
}

#[wasm_bindgen]
pub struct WasmClient {
    transport: Option<WasmTransport>,
    state: Rc<Cell<ConnectionState>>,
    on_state_change: js_sys::Function,
    pub(crate) on_message: js_sys::Function,
    pub(crate) on_error: js_sys::Function,
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
        }
    }

    #[wasm_bindgen]
    pub fn is_supported() -> bool {
        js_sys::Reflect::has(&js_sys::global(), &JsValue::from_str("WebTransport"))
            .unwrap_or(false)
    }

    #[wasm_bindgen(getter)]
    pub fn state(&self) -> u8 { self.state.get() as u8 }

    /// Unauthenticated connect (sends basic Identification, enables receive loop).
    #[wasm_bindgen]
    pub async fn connect(&mut self, config: &ConnectionConfig) -> Result<(), JsValue> {
        self.set_state(ConnectionState::Connecting);
        let transport = WasmTransport::connect(&config.url, config.server_certificate_hashes.clone()).await?;
        let inner = transport.inner().clone();

        let version_str = format!("{}", PROTOCOL_VERSION);
        let ident = CommunicationValue::new(CommunicationType::Identification)
            .add_typed_default(DataType::Version, DataValue::Str(version_str))
            .add_typed_default(DataType::Id, DataValue::UnsignedNumber(config.client_id as u128));
        transport.send_frame(&ident.to_bytes()).await?;

        self.transport = Some(transport);
        self.set_state(ConnectionState::Connected);

        let state = self.state.clone();
        let on_msg = self.on_message.clone();
        let on_err = self.on_error.clone();
        wasm_bindgen_futures::spawn_local(async move {
            WasmTransport::from_inner(inner).receive_loop(on_msg, on_err).await;
            state.set(ConnectionState::Disconnected);
        });
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

        let _host_pk = mtp_crypto::PublicKeyBundle::from_bytes(host_public_key_bytes)
            .map_err(|e| js_error(&format!("invalid host public key: {}", e)))?;
        let keyring = mtp_crypto::Keyring::from_bytes(keyring_bytes)
            .map_err(|e| js_error(&format!("invalid keyring: {}", e)))?;

        let version_str = format!("{}", PROTOCOL_VERSION);
        let mut nonce_bytes = [0u8; 16];
        getrandom::fill(&mut nonce_bytes)
            .map_err(|_| js_error("rng failed"))?;
        let client_nonce = u128::from_be_bytes(nonce_bytes);

        // Build signature payload: version || client_id || client_nonce
        let mut sig_payload = Vec::new();
        sig_payload.extend_from_slice(version_str.as_bytes());
        sig_payload.extend_from_slice(&client_id.to_be_bytes());
        sig_payload.extend_from_slice(&client_nonce.to_be_bytes());

        let signer = mtp_crypto::Ed25519Signer::new(&keyring.sig_cl_secret_key)
            .map_err(|e| js_error(&format!("signer creation failed: {}", e)))?;
        let signature = signer.sign(&sig_payload)
            .map_err(|e| js_error(&format!("signature failed: {}", e)))?;

        let frame = CommunicationValue::new(CommunicationType::Identification)
            .add_typed_default(DataType::Version, DataValue::Str(version_str))
            .add_typed_default(DataType::Id, DataValue::UnsignedNumber(client_id as u128))
            .add_typed_default(DataType::ClientNonce, DataValue::UnsignedNumber(client_nonce))
            .add_typed_default(DataType::Signature, DataValue::Bytes(signature))
            .to_bytes();

        let transport = WasmTransport::connect(&config.url, config.server_certificate_hashes.clone()).await?;
        let inner = transport.inner().clone();
        transport.send_frame(&frame).await?;

        // Read and verify the host's IdentificationResponse
        let response = transport.read_one_frame().await?;
        let resp_comm = CommunicationValue::from_bytes(&response)
            .map_err(|e| js_error(&format!("parse response: {}", e)))?;

        let resp_type = resp_comm.get_type();
        let expected_type = CommunicationTypeId(16); // IdentificationResponse
        if resp_type != expected_type {
            return Err(js_error("unexpected response type"));
        }

        if resp_comm.get_data(DataTypeId(11)) != &DataValue::BoolTrue {
            return Err(js_error("host rejected authentication"));
        }

        // Verify echoed nonce
        let echo_nonce = resp_comm.get_data(DataTypeId(7));
        if *echo_nonce != DataValue::UnsignedNumber(client_nonce) {
            return Err(js_error("nonce mismatch"));
        }

        // Extract assigned ID
        let assigned_id = match resp_comm.get_data(DataTypeId(6)) {
            DataValue::UnsignedNumber(n) => *n as u64,
            _ => return Err(js_error("missing assigned ID")),
        };

        self.transport = Some(transport);
        self.set_state(ConnectionState::Connected);

        let state = self.state.clone();
        let on_msg = self.on_message.clone();
        let on_err = self.on_error.clone();
        wasm_bindgen_futures::spawn_local(async move {
            WasmTransport::from_inner(inner).receive_loop(on_msg, on_err).await;
            state.set(ConnectionState::Disconnected);
        });

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

        let _host_pk = mtp_crypto::PublicKeyBundle::from_bytes(host_public_key_bytes)
            .map_err(|e| js_error(&format!("invalid host public key: {}", e)))?;
        let keyring = mtp_crypto::Keyring::from_bytes(keyring_bytes)
            .map_err(|e| js_error(&format!("invalid keyring: {}", e)))?;

        let version_str = format!("{}", PROTOCOL_VERSION);
        let mut nonce_bytes = [0u8; 16];
        getrandom::fill(&mut nonce_bytes)
            .map_err(|_| js_error("rng failed"))?;
        let client_nonce = u128::from_be_bytes(nonce_bytes);

        let pk_bytes = keyring.public_key_bundle().as_bytes();

        // Build signature payload: version || client_nonce || pk_bytes
        let mut sig_payload = Vec::new();
        sig_payload.extend_from_slice(version_str.as_bytes());
        sig_payload.extend_from_slice(&client_nonce.to_be_bytes());
        sig_payload.extend_from_slice(&pk_bytes);

        let signer = mtp_crypto::Ed25519Signer::new(&keyring.sig_cl_secret_key)
            .map_err(|e| js_error(&format!("signer creation failed: {}", e)))?;
        let signature = signer.sign(&sig_payload)
            .map_err(|e| js_error(&format!("signature failed: {}", e)))?;

        let frame = CommunicationValue::new(CommunicationType::Register)
            .add_typed_default(DataType::Version, DataValue::Str(version_str))
            .add_typed_default(DataType::ClientNonce, DataValue::UnsignedNumber(client_nonce))
            .add_typed_default(DataType::PublicKeys, DataValue::Bytes(pk_bytes))
            .add_typed_default(DataType::Signature, DataValue::Bytes(signature))
            .to_bytes();

        let transport = WasmTransport::connect(&config.url, config.server_certificate_hashes.clone()).await?;
        let inner = transport.inner().clone();
        transport.send_frame(&frame).await?;

        let response = transport.read_one_frame().await?;
        let resp_comm = CommunicationValue::from_bytes(&response)
            .map_err(|e| js_error(&format!("parse response: {}", e)))?;

        let resp_type = resp_comm.get_type();
        let expected_type = CommunicationTypeId(18); // RegisterResponse
        if resp_type != expected_type {
            return Err(js_error("unexpected response type"));
        }

        if resp_comm.get_data(DataTypeId(11)) != &DataValue::BoolTrue {
            return Err(js_error("host rejected registration"));
        }

        let echo = resp_comm.get_data(DataTypeId(7));
        if *echo != DataValue::UnsignedNumber(client_nonce) {
            return Err(js_error("nonce mismatch"));
        }

        let assigned_id = match resp_comm.get_data(DataTypeId(6)) {
            DataValue::UnsignedNumber(n) => *n as u64,
            _ => return Err(js_error("missing assigned ID")),
        };

        self.transport = Some(transport);
        self.set_state(ConnectionState::Connected);

        let state = self.state.clone();
        let on_msg = self.on_message.clone();
        let on_err = self.on_error.clone();
        wasm_bindgen_futures::spawn_local(async move {
            WasmTransport::from_inner(inner).receive_loop(on_msg, on_err).await;
            state.set(ConnectionState::Disconnected);
        });

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
    pub fn disconnect(&mut self) {
        if let Some(t) = &self.transport { t.close(); }
        self.transport = None;
        self.set_state(ConnectionState::Disconnected);
    }

    fn set_state(&self, new_state: ConnectionState) {
        self.state.set(new_state);
        let _ = self.on_state_change.call1(
            &JsValue::NULL,
            &JsValue::from(new_state as u8),
        );
    }
}
