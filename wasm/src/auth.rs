use mtp_codec::{CommunicationType, CommunicationValue, DataType, DataValue};
use mtp_type_map::CommunicationTypeId;
use wasm_bindgen::prelude::*;

use crate::error::js_error;

pub(crate) fn raw_frame_preview(bytes: &[u8]) -> String {
    let shown = bytes.len().min(256);
    let mut preview = hex::encode(&bytes[..shown]);
    if bytes.len() > shown {
        preview.push_str("...");
    }
    format!("{} bytes, hex={preview}", bytes.len())
}

pub(crate) fn unexpected_response_type_error(
    context: &str,
    expected_type: CommunicationTypeId,
    response_type: CommunicationTypeId,
    response: &[u8],
    parsed: &CommunicationValue,
) -> JsValue {
    js_error(format!(
        "unexpected response type during {context}: expected {:?}, got {:?}; raw {}; parsed {}",
        expected_type,
        response_type,
        raw_frame_preview(response),
        parsed
    ))
}

pub(crate) fn verify_host_challenge(
    challenge: &CommunicationValue,
    _tm: &mtp_codec::TypeMap,
    host_pk: &mtp_crypto::PublicKeyBundle,
    id: u64,
    server_challenge: u128,
    require_pq: bool,
) -> Result<(), JsValue> {
    let sig = match challenge.get_data(DataType::Signature) {
        DataValue::Bytes(b) => b.clone(),
        _ => return Err(js_error("missing host challenge signature")),
    };
    let pq_sig = match challenge.get_data(DataType::PqSignature) {
        DataValue::Bytes(b) => b.clone(),
        _ => vec![],
    };

    let host_requires_pq = challenge.get_data(DataType::RequirePq) == &DataValue::BoolTrue;
    if host_requires_pq && host_pk.sig_pq_public_key.as_bytes().is_empty() {
        return Err(js_error(
            "host requires post-quantum authentication but its PQ public key is absent",
        ));
    }
    if require_pq && pq_sig.is_empty() {
        return Err(js_error(
            "host challenge is missing the required PQ signature",
        ));
    }

    let payload = mtp_crypto::auth::challenge_payload(id, server_challenge);
    mtp_crypto::verify_ed25519(&host_pk.sig_cl_public_key, &payload, &sig)
        .map_err(|_| js_error("host challenge signature invalid"))?;
    if !pq_sig.is_empty() {
        mtp_crypto::verify_ml_dsa(&host_pk.sig_pq_public_key, &payload, &pq_sig)
            .map_err(|_| js_error("host challenge PQ signature invalid"))?;
    }
    Ok(())
}

pub(crate) fn verify_host_final(
    resp: &CommunicationValue,
    _tm: &mtp_codec::TypeMap,
    host_pk: &mtp_crypto::PublicKeyBundle,
    id: u64,
    client_nonce: u128,
    server_challenge: u128,
    require_pq: bool,
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
    if require_pq && host_pq_sig.is_empty() {
        return Err(js_error(
            "host confirmation is missing the required PQ signature",
        ));
    }

    let payload = mtp_crypto::auth::host_final_payload(id, client_nonce, server_challenge);
    mtp_crypto::verify_ed25519(&host_pk.sig_cl_public_key, &payload, &host_sig)
        .map_err(|_| js_error("host signature invalid"))?;
    if !host_pq_sig.is_empty() {
        mtp_crypto::verify_ml_dsa(&host_pk.sig_pq_public_key, &payload, &host_pq_sig)
            .map_err(|_| js_error("host PQ signature invalid"))?;
    }
    Ok(())
}

pub(crate) fn random_nonce() -> Result<u128, JsValue> {
    let mut nonce_bytes = [0u8; 16];
    getrandom_v04::fill(&mut nonce_bytes).map_err(|_| js_error("rng failed"))?;
    Ok(u128::from_be_bytes(nonce_bytes))
}

pub(crate) fn signed_challenge_response_bytes(
    keyring: &mtp_crypto::Keyring,
    proof_payload: &[u8],
    client_nonce: u128,
) -> Result<Vec<u8>, JsValue> {
    use mtp_crypto::SignatureScheme;

    let signer = mtp_crypto::Ed25519Signer::new(&keyring.sig_cl_secret_key)
        .map_err(|e| js_error(format!("signer creation failed: {}", e)))?;
    let signature = signer
        .sign(proof_payload)
        .map_err(|e| js_error(format!("signature failed: {}", e)))?;

    let mut proof = CommunicationValue::new(CommunicationType::ChallengeResponse)
        .add_typed_default(
            DataType::ClientNonce,
            DataValue::UnsignedNumber(client_nonce),
        )
        .add_typed_default(DataType::Signature, DataValue::Bytes(signature));

    if !keyring.sig_pq_secret_key.as_bytes().is_empty() {
        let pq_signer =
            mtp_crypto::MlDsaSigner::new(&keyring.sig_pq_secret_key, &keyring.sig_pq_public_key)
                .map_err(|e| js_error(format!("PQ signer creation failed: {}", e)))?;
        let pq_signature = pq_signer
            .sign(proof_payload)
            .map_err(|e| js_error(format!("PQ signature failed: {}", e)))?;
        proof = proof.add_typed_default(DataType::PqSignature, DataValue::Bytes(pq_signature));
    }

    proof
        .to_bytes()
        .map_err(|e| js_error(format!("encode failed: {}", e)))
}
