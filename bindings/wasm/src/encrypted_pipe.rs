//! JS byte-stream adaptation for the shared encrypted pipe protocol.
use crate::encrypted_pipe_duplex::Duplex;
use crate::{error::js_error, transport::BrowserRecvStream};
use mtp_crypto::Keyring;
use mtp_pipes::*;
use wasm_bindgen::prelude::*;

fn context(
    session: &[u8],
    purpose: u8,
    direction: u8,
    transcript: Option<Vec<u8>>,
) -> Result<PipeProtectionContext, JsValue> {
    let context = PipeProtectionContext::new(session, purpose, direction)
        .map_err(|e| js_error(e.to_string()))?;
    match transcript {
        Some(bytes) => Ok(context.with_transcript_hash(
            bytes
                .try_into()
                .map_err(|_| js_error("transcript hash must be 32 bytes"))?,
        )),
        None => Ok(context),
    }
}
fn parameters(value: &JsValue) -> Result<PipeSessionParameters, JsValue> {
    let property = |name: &str| js_sys::Reflect::get(value, &name.into());
    let number = |name: &str| -> Result<u64, JsValue> {
        let value = property(name)?;
        if let Some(number) = value.as_f64()
            && number.is_finite()
            && number.fract() == 0.0
            && (0.0..=9_007_199_254_740_991.0).contains(&number)
        {
            return Ok(number as u64);
        }
        if value.js_typeof().as_string().as_deref() == Some("bigint") {
            return value
                .unchecked_into::<js_sys::BigInt>()
                .to_string(10)?
                .as_string()
                .unwrap_or_default()
                .parse()
                .map_err(|_| js_error("invalid integer"));
        }
        Err(js_error(format!("invalid {name}")))
    };
    let id = u32::try_from(number("pipeId")?)
        .ok()
        .and_then(mtp_common::PipeId::new)
        .ok_or_else(|| js_error("invalid pipe ID"))?;
    PipeSessionParameters::new_id(
        js_sys::Uint8Array::new(&property("sessionId")?).to_vec(),
        id,
        number("senderId")?,
        number("recipientId")?,
        u8::try_from(number("purpose")?).map_err(|_| js_error("invalid purpose"))?,
        u8::try_from(number("direction")?).map_err(|_| js_error("invalid direction"))?,
    )
    .map_err(|e| js_error(e.to_string()))
}
fn error(error: impl std::fmt::Display) -> JsValue {
    js_error(error.to_string())
}

#[wasm_bindgen]
pub struct WasmEncryptedPipeWriter {
    inner: Option<EncryptedPipeWriter<Duplex>>,
    sequence: u64,
}
#[wasm_bindgen]
impl WasmEncryptedPipeWriter {
    #[wasm_bindgen(constructor)]
    pub fn new(
        writer: JsValue,
        key: &[u8],
        session: &[u8],
        purpose: u8,
        direction: u8,
        transcript: Option<Vec<u8>>,
    ) -> Result<Self, JsValue> {
        Ok(Self {
            inner: Some(EncryptedPipeWriter::new(
                Duplex::new(writer),
                key.try_into()
                    .map_err(|_| js_error("key must be 32 bytes"))?,
                context(session, purpose, direction, transcript)?,
            )),
            sequence: 0,
        })
    }
    pub fn sequence(&self) -> u64 {
        self.sequence
    }
    pub async fn write_record(&mut self, data: &[u8]) -> Result<(), JsValue> {
        let inner = self
            .inner
            .as_mut()
            .ok_or_else(|| js_error("encrypted pipe is no longer usable"))?;
        inner.write_record(data).await.map_err(error)?;
        self.sequence = inner.sequence();
        Ok(())
    }
    pub async fn close(&mut self) -> Result<(), JsValue> {
        self.inner
            .take()
            .ok_or_else(|| js_error("encrypted pipe is no longer usable"))?
            .finish()
            .await
            .map_err(error)
    }
    pub fn abort(&mut self) -> Result<(), JsValue> {
        if let Some(inner) = self.inner.take() {
            let mut stream = inner.abort();
            mtp_core::TransportSendStream::reset(&mut stream.write, 0).map_err(error)?;
        }
        Ok(())
    }
}
#[wasm_bindgen]
pub struct WasmEncryptedPipeReader {
    inner: EncryptedPipeReader<Duplex>,
}
#[wasm_bindgen]
impl WasmEncryptedPipeReader {
    #[wasm_bindgen(constructor)]
    pub fn new(
        reader: JsValue,
        key: &[u8],
        session: &[u8],
        purpose: u8,
        direction: u8,
        transcript: Option<Vec<u8>>,
        pending: &[u8],
    ) -> Result<Self, JsValue> {
        let mut stream = Duplex::new(reader.clone());
        stream.read = BrowserRecvStream::from_pipe(reader, pending.to_vec());
        Ok(Self {
            inner: EncryptedPipeReader::new(
                stream,
                key.try_into()
                    .map_err(|_| js_error("key must be 32 bytes"))?,
                context(session, purpose, direction, transcript)?,
            ),
        })
    }
    pub fn sequence(&self) -> u64 {
        self.inner.sequence()
    }
    pub async fn read_record(&mut self) -> Result<JsValue, JsValue> {
        Ok(match self.inner.read_record().await.map_err(error)? {
            Some(data) => js_sys::Uint8Array::from(data.as_slice()).into(),
            None => JsValue::NULL,
        })
    }
}
#[wasm_bindgen]
pub async fn mtp_initiate_pipe_session(
    writer: JsValue,
    params: JsValue,
    keys: &[u8],
    recipients: JsValue,
    dual: bool,
) -> Result<WasmEncryptedPipeWriter, JsValue> {
    let params = parameters(&params)?;
    let keys = Keyring::from_bytes(keys).map_err(error)?;
    let recipients = crate::crypto::public_key_bundles_from_js(&recipients)?;
    let inner = initiate_group_pipe_session_with_suite(
        Duplex::new(writer),
        params,
        &keys,
        &recipients,
        dual,
    )
    .await
    .map_err(error)?;
    Ok(WasmEncryptedPipeWriter {
        inner: Some(inner),
        sequence: 0,
    })
}
#[wasm_bindgen]
pub async fn mtp_accept_pipe_session(
    reader: JsValue,
    params: JsValue,
    keys: &[u8],
    senders: JsValue,
    suite: u8,
    auto: bool,
) -> Result<WasmEncryptedPipeReader, JsValue> {
    let keys = Keyring::from_bytes(keys).map_err(error)?;
    let senders = crate::crypto::public_key_bundles_from_js(&senders)?;
    let policy = crate::crypto::protection_policy_from_suite(suite)?;
    let params = parameters(&params)?;
    let stream = Duplex::new(reader);
    let inner = if auto {
        accept_pipe_session_auto(
            stream,
            params.pipe_id_value(),
            params.sender_id(),
            params.recipient_id(),
            params.purpose(),
            params.direction(),
            &keys,
            &senders,
            policy,
        )
        .await
    } else {
        accept_pipe_session_with_key_history(stream, &params, &keys, &senders, policy).await
    }
    .map_err(error)?;
    Ok(WasmEncryptedPipeReader { inner })
}

#[wasm_bindgen]
pub async fn mtp_initiate_forward_secure_pipe_session(
    stream: JsValue,
    params: JsValue,
    keys: &[u8],
    recipient: &[u8],
    suite: u8,
    dual: bool,
) -> Result<WasmEncryptedPipeWriter, JsValue> {
    let params = parameters(&params)?;
    let keys = pipe_session_signing_keys(Keyring::from_bytes(keys).map_err(error)?, dual)
        .map_err(error)?;
    let recipient = mtp_crypto::PublicKeyBundle::from_bytes(recipient).map_err(error)?;
    let policy = crate::crypto::protection_policy_from_suite(suite)?;
    let inner = initiate_forward_secure_pipe_session(
        Duplex::new(stream),
        params,
        &keys,
        &recipient,
        policy,
    )
    .await
    .map_err(error)?;
    Ok(WasmEncryptedPipeWriter {
        inner: Some(inner),
        sequence: 0,
    })
}
#[wasm_bindgen]
pub async fn mtp_accept_forward_secure_pipe_session(
    stream: JsValue,
    params: JsValue,
    keys: &[u8],
    senders: JsValue,
    suite: u8,
    dual: bool,
) -> Result<WasmEncryptedPipeReader, JsValue> {
    let params = parameters(&params)?;
    let keys = pipe_session_signing_keys(Keyring::from_bytes(keys).map_err(error)?, dual)
        .map_err(error)?;
    let senders = crate::crypto::public_key_bundles_from_js(&senders)?;
    let policy = crate::crypto::protection_policy_from_suite(suite)?;
    let inner = accept_forward_secure_pipe_session_auto(
        Duplex::new(stream),
        params.pipe_id_value(),
        params.sender_id(),
        params.recipient_id(),
        params.purpose(),
        params.direction(),
        &keys,
        &senders,
        policy,
    )
    .await
    .map_err(error)?;
    Ok(WasmEncryptedPipeReader { inner })
}

#[wasm_bindgen]
pub fn mtp_pipe_context_hash(
    session: &[u8],
    purpose: u8,
    direction: u8,
) -> Result<Vec<u8>, JsValue> {
    Ok(PipeProtectionContext::new(session, purpose, direction)
        .map_err(error)?
        .transcript_hash()
        .to_vec())
}
