use mtp_codec::{CommunicationValue, DataType, DataValue, PROTOCOL_VERSION, Version};
use mtp_common::CommunicationError;
use mtp_transport::{Policy, Receiver, Sender};

#[cfg(feature = "crypto")]
fn unexpected_response_type_error(
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

pub struct ClientConfig {
    pub url: String,
    pub server_cert: Option<Vec<u8>>,
    pub client_id: u64,
}

/* Established MTP connection with a single negotiated version. */
pub struct MTPConnection {
    pub version: Version,
    pub sender: Sender,
    pub receiver: Receiver,
    #[cfg(feature = "crypto")]
    pub auth_state: AuthState,
    #[cfg(feature = "crypto")]
    pub client_id: u64,
}

#[cfg(feature = "crypto")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthState {
    Pending,
    Authenticated,
    Failed,
}

pub struct MTPClient;

impl MTPClient {
    /*
     * Connect to an MTP host.
     *
     * The first message includes the client's protocol version
     * (a reserved `Version` data entry) so the host can negotiate.
     */
    pub async fn connect(config: ClientConfig) -> Result<MTPConnection, CommunicationError> {
        let (sender, receiver) =
            mtp_transport::connect(&config.url, config.server_cert, Policy::default()).await?;

        // Build the initial identification message with the protocol version.
        let version_str = format!("{}", PROTOCOL_VERSION);
        let ident = CommunicationValue::new(mtp_codec::CommunicationType::Identification)
            .add_typed_default(DataType::Version, DataValue::Str(version_str))
            .add_typed_default(
                DataType::Id,
                DataValue::UnsignedNumber(config.client_id.into()),
            );

        sender.send(&ident).await?;

        Ok(MTPConnection {
            version: PROTOCOL_VERSION,
            sender,
            receiver,
            #[cfg(feature = "crypto")]
            auth_state: AuthState::Authenticated,
            #[cfg(feature = "crypto")]
            client_id: config.client_id,
        })
    }
}

/* ===== Authentication ===== */

/*
 * Verify the host's signature over the challenge it issued (step 2).
 *
 * `id` is the client id for a login, or `0` for a registration (the host binds
 * `0` since no id has been assigned yet). The Ed25519 signature is mandatory;
 * the ML-DSA signature is checked only when the host included one.
 */
#[cfg(feature = "crypto")]
fn verify_host_challenge(
    challenge: &CommunicationValue,
    tm: &mtp_codec::TypeMap,
    host_pk: &mtp_crypto::PublicKeyBundle,
    id: u64,
    server_challenge: u128,
) -> Result<(), CommunicationError> {
    use mtp_crypto::{auth, verify_ed25519, verify_ml_dsa};

    let sig = match challenge.get_data(DataType::Signature.to_id(tm)) {
        DataValue::Bytes(b) => b.clone(),
        _ => {
            return Err(CommunicationError::AuthenticationFailed(
                "Missing host challenge signature".into(),
            ));
        }
    };
    let pq_sig = match challenge.get_data(DataType::PqSignature.to_id(tm)) {
        DataValue::Bytes(b) => b.clone(),
        _ => vec![],
    };

    let payload = auth::challenge_payload(id, server_challenge);
    verify_ed25519(&host_pk.sig_cl_public_key, &payload, &sig).map_err(|_| {
        CommunicationError::AuthenticationFailed("Host challenge signature invalid".into())
    })?;
    if !pq_sig.is_empty() && verify_ml_dsa(&host_pk.sig_pq_public_key, &payload, &pq_sig).is_err() {
        return Err(CommunicationError::AuthenticationFailed(
            "Host challenge PQ signature invalid".into(),
        ));
    }
    Ok(())
}

/*
 * Verify the host's final confirmation (step 4): the echoed `client_nonce` and
 * the host signature over the handshake transcript.
 */
#[cfg(feature = "crypto")]
fn verify_host_final(
    response: &CommunicationValue,
    tm: &mtp_codec::TypeMap,
    host_pk: &mtp_crypto::PublicKeyBundle,
    id: u64,
    client_nonce: u128,
    server_challenge: u128,
) -> Result<(), CommunicationError> {
    use mtp_crypto::{auth, verify_ed25519, verify_ml_dsa};

    match response.get_data(DataType::ClientNonce.to_id(tm)) {
        DataValue::UnsignedNumber(n) if *n == client_nonce => {}
        _ => {
            return Err(CommunicationError::AuthenticationFailed(
                "Nonce mismatch".into(),
            ));
        }
    }

    let sig = match response.get_data(DataType::Signature.to_id(tm)) {
        DataValue::Bytes(b) => b.clone(),
        _ => {
            return Err(CommunicationError::AuthenticationFailed(
                "Missing signature".into(),
            ));
        }
    };
    let pq_sig = match response.get_data(DataType::PqSignature.to_id(tm)) {
        DataValue::Bytes(b) => b.clone(),
        _ => vec![],
    };

    let payload = auth::host_final_payload(id, client_nonce, server_challenge);
    verify_ed25519(&host_pk.sig_cl_public_key, &payload, &sig)
        .map_err(|_| CommunicationError::AuthenticationFailed("Host signature invalid".into()))?;
    if !pq_sig.is_empty() && verify_ml_dsa(&host_pk.sig_pq_public_key, &payload, &pq_sig).is_err() {
        return Err(CommunicationError::AuthenticationFailed(
            "Host PQ signature invalid".into(),
        ));
    }
    Ok(())
}

/* Interpret the host's `Connected` flag. */
#[cfg(feature = "crypto")]
fn check_connected(
    response: &CommunicationValue,
    tm: &mtp_codec::TypeMap,
    reject_msg: &str,
) -> Result<(), CommunicationError> {
    match response.get_data(DataType::Connected.to_id(tm)) {
        DataValue::BoolTrue => Ok(()),
        DataValue::BoolFalse => Err(CommunicationError::AuthenticationFailed(reject_msg.into())),
        _ => Err(CommunicationError::AuthenticationFailed(
            "Invalid response".into(),
        )),
    }
}

#[cfg(feature = "crypto")]
fn signed_challenge_response(
    keys: &mtp_crypto::Keyring,
    proof_payload: &[u8],
    client_nonce: u128,
) -> Result<CommunicationValue, CommunicationError> {
    use mtp_crypto::{Ed25519Signer, MlDsaSigner, SignatureScheme};

    let signer = Ed25519Signer::new(&keys.sig_cl_secret_key)
        .map_err(|e| CommunicationError::Other(e.to_string()))?;
    let signature = signer
        .sign(proof_payload)
        .map_err(|e| CommunicationError::Other(e.to_string()))?;

    let mut proof = CommunicationValue::new(mtp_codec::CommunicationType::ChallengeResponse)
        .add_typed_default(
            DataType::ClientNonce,
            DataValue::UnsignedNumber(client_nonce),
        )
        .add_typed_default(DataType::Signature, DataValue::Bytes(signature));

    if !keys.sig_pq_secret_key.as_bytes().is_empty() {
        let pq_signer = MlDsaSigner::new(&keys.sig_pq_secret_key, &keys.sig_pq_public_key)
            .map_err(|e| CommunicationError::Other(e.to_string()))?;
        let pq_signature = pq_signer
            .sign(proof_payload)
            .map_err(|e| CommunicationError::Other(e.to_string()))?;
        proof = proof.add_typed_default(DataType::PqSignature, DataValue::Bytes(pq_signature));
    }

    Ok(proof)
}

#[cfg(feature = "crypto")]
async fn receive_verified_challenge(
    receiver: &Receiver,
    tm: &mtp_codec::TypeMap,
    host_public_key_bundle: &mtp_crypto::PublicKeyBundle,
    bound_id: u64,
    context: &str,
) -> Result<u128, CommunicationError> {
    let challenge = receiver.receive().await?;
    let expected = mtp_codec::CommunicationType::Challenge.to_id(tm);
    if challenge.get_type() != expected {
        return Err(unexpected_response_type_error(
            context, expected, &challenge,
        ));
    }

    let server_challenge = match challenge.get_data(DataType::ServerNonce.to_id(tm)) {
        DataValue::UnsignedNumber(n) => *n,
        _ => {
            return Err(CommunicationError::AuthenticationFailed(
                "Missing server challenge".into(),
            ));
        }
    };

    verify_host_challenge(
        &challenge,
        tm,
        host_public_key_bundle,
        bound_id,
        server_challenge,
    )?;

    Ok(server_challenge)
}

#[cfg(feature = "crypto")]
impl MTPClient {
    pub async fn auth_connect(
        config: ClientConfig,
        keys: &mtp_crypto::Keyring,
        host_public_key_bundle: &mtp_crypto::PublicKeyBundle,
    ) -> Result<MTPConnection, CommunicationError> {
        use mtp_crypto::auth;

        let (sender, receiver) =
            mtp_transport::connect(&config.url, config.server_cert, Policy::default()).await?;

        let tm = mtp_codec::TypeMap::latest();
        let version_str = format!("{}", PROTOCOL_VERSION);

        // 1. Send the unsigned Identification hello (version + claimed id).
        let ident = CommunicationValue::new(mtp_codec::CommunicationType::Identification)
            .add_typed_default(DataType::Version, DataValue::Str(version_str.clone()))
            .add_typed_default(
                DataType::Id,
                DataValue::UnsignedNumber(config.client_id as u128),
            );
        sender.send(&ident).await?;

        // 2. Receive and verify the host's challenge.
        let server_challenge = receive_verified_challenge(
            &receiver,
            &tm,
            host_public_key_bundle,
            config.client_id,
            "auth_connect challenge",
        )
        .await?;

        // 3. Sign the host's challenge and send the proof.
        let client_nonce: u128 = rand::random();
        let proof_payload = auth::login_proof_payload(
            &version_str,
            config.client_id,
            server_challenge,
            client_nonce,
        );

        let proof = signed_challenge_response(keys, &proof_payload, client_nonce)?;
        sender.send(&proof).await?;

        // 4. Receive and verify the host's final confirmation.
        let response = receiver.receive().await?;
        let expected_type = mtp_codec::CommunicationType::IdentificationResponse.to_id(&tm);
        if response.get_type() != expected_type {
            return Err(unexpected_response_type_error(
                "auth_connect",
                expected_type,
                &response,
            ));
        }
        check_connected(&response, &tm, "Server rejected authentication")?;
        verify_host_final(
            &response,
            &tm,
            host_public_key_bundle,
            config.client_id,
            client_nonce,
            server_challenge,
        )?;

        Ok(MTPConnection {
            version: PROTOCOL_VERSION,
            sender,
            receiver,
            auth_state: AuthState::Authenticated,
            client_id: config.client_id,
        })
    }

    pub async fn auth_register(
        config: ClientConfig,
        keys: &mtp_crypto::Keyring,
        host_public_key_bundle: &mtp_crypto::PublicKeyBundle,
    ) -> Result<MTPConnection, CommunicationError> {
        use mtp_crypto::auth;

        let (sender, receiver) =
            mtp_transport::connect(&config.url, config.server_cert, Policy::default()).await?;

        let tm = mtp_codec::TypeMap::latest();
        let version_str = format!("{}", PROTOCOL_VERSION);
        let pk_bundle = keys.public_key_bundle();
        let pk_bytes = pk_bundle.as_bytes();

        // 1. Send the unsigned Register hello (version + public-key bundle).
        let register = CommunicationValue::new(mtp_codec::CommunicationType::Register)
            .add_typed_default(DataType::Version, DataValue::Str(version_str.clone()))
            .add_typed_default(DataType::PublicKeys, DataValue::Bytes(pk_bytes.clone()));
        sender.send(&register).await?;

        // 2. Receive and verify the host's challenge (register binds id = 0).
        let server_challenge = receive_verified_challenge(
            &receiver,
            &tm,
            host_public_key_bundle,
            0,
            "auth_register challenge",
        )
        .await?;

        // 3. Sign the host's challenge over the bundle and send the proof.
        let client_nonce: u128 = rand::random();
        let proof_payload =
            auth::register_proof_payload(&version_str, &pk_bytes, server_challenge, client_nonce);

        let proof = signed_challenge_response(keys, &proof_payload, client_nonce)?;
        sender.send(&proof).await?;

        // 4. Receive the host's final confirmation; extract the assigned id and
        //    verify the host signature binds to it.
        let response = receiver.receive().await?;
        let expected_type = mtp_codec::CommunicationType::RegisterResponse.to_id(&tm);
        if response.get_type() != expected_type {
            return Err(unexpected_response_type_error(
                "auth_register",
                expected_type,
                &response,
            ));
        }
        check_connected(&response, &tm, "Server rejected registration")?;
        let assigned_id = match response.get_data(DataType::Id.to_id(&tm)) {
            DataValue::UnsignedNumber(n) => *n as u64,
            _ => {
                return Err(CommunicationError::AuthenticationFailed(
                    "Missing assigned ID".into(),
                ));
            }
        };
        verify_host_final(
            &response,
            &tm,
            host_public_key_bundle,
            assigned_id,
            client_nonce,
            server_challenge,
        )?;

        Ok(MTPConnection {
            version: PROTOCOL_VERSION,
            sender,
            receiver,
            auth_state: AuthState::Authenticated,
            client_id: assigned_id,
        })
    }
}

/* ================================ TESTS ================================ */
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_config_url() {
        let config = ClientConfig {
            url: "https://example.com:4433".into(),
            server_cert: None,
            client_id: 0,
        };
        assert_eq!(config.url, "https://example.com:4433");
        assert!(config.server_cert.is_none());
    }

    #[test]
    fn test_client_config_with_cert() {
        let config = ClientConfig {
            url: "https://localhost:4433".into(),
            server_cert: Some(vec![0x01, 0x02, 0x03]),
            client_id: 42,
        };
        assert_eq!(config.server_cert, Some(vec![0x01, 0x02, 0x03]));
        assert_eq!(config.client_id, 42);
    }

    #[cfg(feature = "crypto")]
    #[test]
    fn test_auth_state_derive() {
        assert_eq!(AuthState::Pending, AuthState::Pending);
        assert_ne!(AuthState::Authenticated, AuthState::Failed);
    }
}
