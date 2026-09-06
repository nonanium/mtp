use mtp_codec::{CommunicationType, CommunicationValue, DataType, DataValue, TypeMap, Version};
use mtp_common::CommunicationError;

pub(crate) fn unexpected_response_type_error(
    context: &str,
    expected_type: mtp_codec::CommunicationTypeId,
    response: &CommunicationValue,
) -> CommunicationError {
    CommunicationError::AuthenticationFailed(format!(
        "unexpected response type during {context}: expected {:?}, got {:?}; parsed {}",
        expected_type,
        response.get_type(),
        response
    ))
}

pub(crate) async fn verify_host_challenge(
    challenge: &CommunicationValue,
    host_pk: &mtp_crypto::PublicKeyBundle,
    id: u64,
    server_challenge: u128,
    require_pq: bool,
) -> Result<(), CommunicationError> {
    use mtp_crypto::{auth, verify_ed25519};

    let sig = match challenge.get_data(DataType::Signature) {
        Some(DataValue::Bytes(b)) => b.clone(),
        _ => {
            return Err(CommunicationError::AuthenticationFailed(
                "Missing host challenge signature".into(),
            ));
        }
    };
    let pq_sig = match challenge.get_data(DataType::PqSignature) {
        Some(DataValue::Bytes(b)) => b.clone(),
        _ => vec![],
    };

    let host_requires_pq = challenge.get_data(DataType::RequirePq) == Some(&DataValue::BoolTrue);
    if host_requires_pq && host_pk.sig_pq_public_key.as_bytes().is_empty() {
        return Err(CommunicationError::AuthenticationFailed(
            "Host requires post-quantum authentication but its PQ public key is absent".into(),
        ));
    }
    if require_pq && pq_sig.is_empty() {
        return Err(CommunicationError::AuthenticationFailed(
            "Host challenge is missing the required PQ signature".into(),
        ));
    }

    let payload = auth::challenge_payload(id, server_challenge);
    if pq_sig.is_empty() {
        verify_ed25519(&host_pk.sig_cl_public_key, &payload, &sig).map_err(|_| {
            CommunicationError::AuthenticationFailed("Host challenge signature invalid".into())
        })?;
    } else {
        mtp_crypto::sign_parallel::verify_dual_parallel(
            host_pk.sig_cl_public_key.clone(),
            host_pk.sig_pq_public_key.clone(),
            payload,
            sig,
            pq_sig,
        )
        .await
        .map_err(|_| {
            CommunicationError::AuthenticationFailed("Host challenge signature invalid".into())
        })?;
    }
    Ok(())
}

pub(crate) async fn verify_host_final(
    response: &CommunicationValue,
    host_pk: &mtp_crypto::PublicKeyBundle,
    id: u64,
    client_nonce: u128,
    server_challenge: u128,
    require_pq: bool,
) -> Result<(), CommunicationError> {
    use mtp_crypto::{auth, verify_ed25519};

    match response.get_data(DataType::ClientNonce) {
        Some(DataValue::UnsignedNumber(n)) if *n == client_nonce => {}
        _ => {
            return Err(CommunicationError::AuthenticationFailed(
                "Nonce mismatch".into(),
            ));
        }
    }

    let sig = match response.get_data(DataType::Signature) {
        Some(DataValue::Bytes(b)) => b.clone(),
        _ => {
            return Err(CommunicationError::AuthenticationFailed(
                "Missing signature".into(),
            ));
        }
    };
    let pq_sig = match response.get_data(DataType::PqSignature) {
        Some(DataValue::Bytes(b)) => b.clone(),
        _ => vec![],
    };
    if require_pq && pq_sig.is_empty() {
        return Err(CommunicationError::AuthenticationFailed(
            "Host confirmation is missing the required PQ signature".into(),
        ));
    }

    let payload = auth::host_final_payload(id, client_nonce, server_challenge);
    if pq_sig.is_empty() {
        verify_ed25519(&host_pk.sig_cl_public_key, &payload, &sig).map_err(|_| {
            CommunicationError::AuthenticationFailed("Host signature invalid".into())
        })?;
    } else {
        mtp_crypto::sign_parallel::verify_dual_parallel(
            host_pk.sig_cl_public_key.clone(),
            host_pk.sig_pq_public_key.clone(),
            payload,
            sig,
            pq_sig,
        )
        .await
        .map_err(|_| CommunicationError::AuthenticationFailed("Host signature invalid".into()))?;
    }
    Ok(())
}

pub(crate) fn check_connected(
    response: &CommunicationValue,
    reject_msg: &str,
) -> Result<(), CommunicationError> {
    match response.get_data(DataType::Connected) {
        Some(DataValue::BoolTrue) => Ok(()),
        Some(DataValue::BoolFalse) => Err(CommunicationError::AuthenticationFailed(
            response
                .get_str(DataType::ErrorMessage)
                .unwrap_or(reject_msg)
                .into(),
        )),
        _ => Err(CommunicationError::AuthenticationFailed(
            "Invalid response".into(),
        )),
    }
}

pub(crate) fn negotiated_version(
    response: &CommunicationValue,
) -> Result<Version, CommunicationError> {
    match response.get_data(DataType::Version) {
        Some(DataValue::Str(version)) => Version::parse(version).ok_or_else(|| {
            CommunicationError::AuthenticationFailed(
                "Host returned an invalid negotiated protocol version".into(),
            )
        }),
        _ => Err(CommunicationError::AuthenticationFailed(
            "Host omitted the negotiated protocol version".into(),
        )),
    }
}

pub(crate) async fn signed_challenge_response(
    keys: &mtp_crypto::Keyring,
    proof_payload: Vec<u8>,
    client_nonce: u128,
    type_map: &TypeMap,
) -> Result<CommunicationValue, CommunicationError> {
    use mtp_crypto::{Ed25519Signer, MlDsaSigner, SignatureScheme};

    let signer = Ed25519Signer::new(&keys.sig_cl_secret_key)
        .map_err(|e| CommunicationError::Other(e.to_string()))?;
    let mut proof =
        CommunicationValue::new_with_type_map(CommunicationType::ChallengeResponse, type_map)
            .add_typed_default(
                DataType::ClientNonce,
                DataValue::UnsignedNumber(client_nonce),
            );

    if keys.sig_pq_secret_key.as_bytes().is_empty() {
        let signature = signer
            .sign(&proof_payload)
            .map_err(|e| CommunicationError::Other(e.to_string()))?;
        proof = proof.add_typed_default(DataType::Signature, DataValue::Bytes(signature));
    } else {
        let pq_signer = MlDsaSigner::new(&keys.sig_pq_secret_key, &keys.sig_pq_public_key)
            .map_err(|e| CommunicationError::Other(e.to_string()))?;
        let (signature, pq_signature) =
            mtp_crypto::sign_parallel::sign_dual_parallel(signer, pq_signer, proof_payload)
                .await
                .map_err(|e| CommunicationError::Other(e.to_string()))?;
        proof = proof
            .add_typed_default(DataType::Signature, DataValue::Bytes(signature))
            .add_typed_default(DataType::PqSignature, DataValue::Bytes(pq_signature));
    }

    Ok(proof)
}

pub(crate) async fn receive_verified_challenge(
    receiver: &mtp_native::Receiver,
    tm: &mtp_codec::TypeMap,
    host_public_key_bundle: &mtp_crypto::PublicKeyBundle,
    bound_id: u64,
    context: &str,
    require_pq: bool,
    client_has_pq_key: bool,
) -> Result<u128, CommunicationError> {
    let challenge = receiver.receive().await?;
    let expected = CommunicationType::Challenge
        .try_to_id(tm)
        .ok_or_else(|| CommunicationError::Other("Challenge is absent from the type map".into()))?;
    if challenge.get_type() != expected {
        return Err(unexpected_response_type_error(
            context, expected, &challenge,
        ));
    }

    let server_challenge = match challenge.get_data(DataType::ServerNonce) {
        Some(DataValue::UnsignedNumber(n)) => *n,
        _ => {
            return Err(CommunicationError::AuthenticationFailed(
                "Missing server challenge".into(),
            ));
        }
    };
    if challenge.get_data(DataType::RequirePq) == Some(&DataValue::BoolTrue) && !client_has_pq_key {
        return Err(CommunicationError::AuthenticationFailed(
            "Host requires post-quantum authentication but the client PQ key is absent".into(),
        ));
    }

    verify_host_challenge(
        &challenge,
        host_public_key_bundle,
        bound_id,
        server_challenge,
        require_pq,
    )
    .await?;

    Ok(server_challenge)
}
