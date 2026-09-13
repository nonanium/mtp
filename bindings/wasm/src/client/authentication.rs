use wasm_bindgen::prelude::*;

use mtp_codec::{CommunicationType, CommunicationValue, DataType, DataValue, PROTOCOL_VERSION};

use crate::auth;
use crate::client::{ConnectionState, WasmClient};
use crate::config::ConnectionConfig;
use crate::error::js_error;
use crate::transport::WasmTransport;

fn server_rejection_message(outcome: &CommunicationValue) -> Option<&str> {
    (outcome.get_data(DataType::Connected) == Some(&DataValue::BoolFalse)).then(|| {
        outcome
            .get_str(DataType::ErrorMessage)
            .unwrap_or("host rejected the connection")
    })
}

#[wasm_bindgen]
#[allow(deprecated)]
impl WasmClient {
    pub async fn connect(&self, config: &ConnectionConfig) -> Result<(), JsValue> {
        self.connect_owned(config.clone()).await
    }

    #[wasm_bindgen(js_name = connectOwned)]
    pub async fn connect_owned(&self, config: ConnectionConfig) -> Result<(), JsValue> {
        let generation = self.begin_connection();
        let transport = match WasmTransport::connect_with_limits(
            &config.url,
            config.server_certificate_hashes.clone(),
            config.max_message_size,
            self.receive_decode_limits(),
        )
        .await
        {
            Ok(transport) => transport,
            Err(error) => {
                self.set_state_if_current(generation, ConnectionState::Disconnected);
                return Err(error);
            }
        };
        if !self.install_attempt_transport(&transport, generation) {
            return Err(js_error("connection attempt superseded"));
        }

        let result = async {
            let version_str = format!("{}", PROTOCOL_VERSION);
            let opening_codec = mtp_codec::registry::VersionedCodec::for_version(
                mtp_codec::registry::Registry::builtin(),
                PROTOCOL_VERSION,
            )
            .ok_or_else(|| js_error("client protocol version is not registered"))?;
            transport.set_type_map(opening_codec.type_map());
            let mut ident = CommunicationValue::new_with_type_map(
                CommunicationType::Identification,
                opening_codec.type_map(),
            )
            .add_typed_default(DataType::Version, DataValue::Str(version_str))
            .add_typed_default(
                DataType::Id,
                DataValue::UnsignedNumber(config.client_id as u128),
            );
            if let Some(desc) = &config.description {
                ident =
                    ident.add_typed_default(DataType::Description, DataValue::Str(desc.clone()));
            }
            let ident_bytes = ident
                .to_bytes()
                .map_err(|e| js_error(format!("encode failed: {}", e)))?;
            transport.send_frame(&ident_bytes).await?;

            let outcome_bytes = transport.read_one_frame().await?;
            let outcome = CommunicationValue::try_from_bytes_with_type_map_and_limits(
                &outcome_bytes,
                opening_codec.type_map(),
                transport.decode_limits(),
            )
            .map_err(|e| js_error(format!("parse handshake outcome: {e}")))?;
            if Some(outcome.get_type())
                == CommunicationType::ErrorBadVersion.try_to_id(opening_codec.type_map())
            {
                self.set_state_if_current(generation, ConnectionState::Disconnected);
                return Err(js_error(
                    outcome
                        .get_str(DataType::ErrorMessage)
                        .unwrap_or("host does not support this protocol version"),
                ));
            }

            // Generic host rejections are IdentificationResponse frames with
            // Connected=false. They intentionally do not carry a negotiated
            // Version because negotiation never completed. Check this before
            // reading Version, otherwise a useful server error such as an
            // authentication timeout is reported as the misleading
            // "host omitted a valid negotiated protocol version".
            if let Some(message) = server_rejection_message(&outcome) {
                self.set_state_if_current(generation, ConnectionState::Disconnected);
                return Err(js_error(message));
            }

            let missing_version = || {
                js_error(format!(
                    "host omitted a valid negotiated protocol version (response_type={:?}, connected={:?}, frame_len={})",
                    outcome.get_type(),
                    outcome.get_data(DataType::Connected),
                    outcome_bytes.len(),
                ))
            };

            let negotiated_version = match outcome.get_data(DataType::Version) {
                Some(DataValue::Str(version)) => mtp_codec::Version::parse(version)
                    .ok_or_else(missing_version)?,
                _ => return Err(missing_version()),
            };
            if negotiated_version != PROTOCOL_VERSION {
                return Err(js_error(
                    "host selected a protocol version the client did not offer",
                ));
            }
            let codec = mtp_codec::registry::VersionedCodec::for_version(
                mtp_codec::registry::Registry::builtin(),
                negotiated_version,
            )
            .ok_or_else(|| js_error("host returned an unsupported negotiated protocol version"))?;
            transport.set_type_map(codec.type_map());
            let outcome = CommunicationValue::try_from_bytes_with_type_map_and_limits(
                &outcome_bytes,
                codec.type_map(),
                transport.decode_limits(),
            )
            .map_err(|e| js_error(format!("parse negotiated handshake outcome: {e}")))?;
            let tm = codec.type_map();
            let expected = CommunicationType::IdentificationResponse
                .try_to_id(tm)
                .ok_or_else(|| js_error("IdentificationResponse is absent from the type map"))?;
            if outcome.get_type() != expected
                || outcome.get_data(DataType::Connected) != Some(&DataValue::BoolTrue)
            {
                self.set_state_if_current(generation, ConnectionState::Disconnected);
                return Err(js_error(
                    outcome
                        .get_str(DataType::ErrorMessage)
                        .unwrap_or("host rejected the connection"),
                ));
            }
            let assigned_id = match outcome.get_data(DataType::Id) {
                Some(DataValue::UnsignedNumber(id)) => {
                    u64::try_from(*id).map_err(|_| js_error("assigned ID is out of range"))?
                }
                _ => {
                    self.set_state_if_current(generation, ConnectionState::Disconnected);
                    return Err(js_error("host omitted the assigned client ID"));
                }
            };

            if !self.start_receive_loop(transport.clone(), generation, assigned_id) {
                return Err(js_error("connection attempt superseded"));
            }
            Ok(())
        }
        .await;
        if let Err(error) = &result {
            self.abort_attempt(&transport, generation);
            let _ = error;
        }
        result
    }

    #[wasm_bindgen]
    #[deprecated(
        note = "use the SDK authentication methods; this raw method remains for compatibility"
    )]
    pub async fn auth_connect(
        &self,
        config: &ConnectionConfig,
        host_public_key_bytes: &[u8],
        keyring_bytes: &[u8],
        client_id: u64,
    ) -> Result<u64, JsValue> {
        self.auth_connect_owned(
            config.clone(),
            host_public_key_bytes.to_vec(),
            keyring_bytes.to_vec(),
            client_id,
        )
        .await
    }

    #[wasm_bindgen(js_name = authConnectOwned)]
    pub async fn auth_connect_owned(
        &self,
        config: ConnectionConfig,
        host_public_key_bytes: Vec<u8>,
        keyring_bytes: Vec<u8>,
        client_id: u64,
    ) -> Result<u64, JsValue> {
        let generation = self.begin_connection();

        let host_pk = match mtp_crypto::PublicKeyBundle::from_bytes(&host_public_key_bytes) {
            Ok(value) => value,
            Err(error) => {
                let error = js_error(format!("invalid host public key: {}", error));
                self.set_state_if_current(generation, ConnectionState::Disconnected);
                return Err(error);
            }
        };
        let keyring = match mtp_crypto::Keyring::from_bytes(&keyring_bytes) {
            Ok(value) => value,
            Err(error) => {
                let error = js_error(format!("invalid keyring: {}", error));
                self.set_state_if_current(generation, ConnectionState::Disconnected);
                return Err(error);
            }
        };

        let handshake_codec = mtp_codec::registry::VersionedCodec::for_version(
            mtp_codec::registry::Registry::builtin(),
            PROTOCOL_VERSION,
        )
        .ok_or_else(|| js_error("client protocol version is not registered"))?;
        let tm = handshake_codec.type_map().clone();
        let version_str = format!("{}", PROTOCOL_VERSION);
        let public_key_bytes = keyring
            .public_key_bundle()
            .try_as_bytes()
            .map_err(|error| js_error(format!("public key serialization failed: {error}")))?;

        let transport = match WasmTransport::connect_with_limits(
            &config.url,
            config.server_certificate_hashes.clone(),
            config.max_message_size,
            self.receive_decode_limits(),
        )
        .await
        {
            Ok(transport) => transport,
            Err(error) => {
                self.set_state_if_current(generation, ConnectionState::Disconnected);
                return Err(error);
            }
        };
        transport.set_type_map(&tm);
        if !self.install_attempt_transport(&transport, generation) {
            return Err(js_error("connection attempt superseded"));
        }

        let result = async {
            let mut hello =
                CommunicationValue::new_with_type_map(CommunicationType::Identification, &tm)
                    .add_typed_default(DataType::Version, DataValue::Str(version_str.clone()))
                    .add_typed_default(DataType::Id, DataValue::UnsignedNumber(client_id as u128))
                    // Mark this as an authentication-capable opening so a
                    // non-crypto host can reject it explicitly.
                    .add_typed_default(
                        DataType::PublicKeys,
                        DataValue::Bytes(public_key_bytes.clone()),
                    );
            if let Some(desc) = &config.description {
                hello =
                    hello.add_typed_default(DataType::Description, DataValue::Str(desc.clone()));
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
                config.description.as_deref(),
                client_id,
                server_challenge,
                client_nonce,
            );
            let proof =
                auth::signed_challenge_response_bytes(&keyring, &proof_payload, client_nonce, &tm)?;
            transport.send_frame(&proof).await?;

            let response = transport.read_one_frame().await?;
            let resp_comm = CommunicationValue::try_from_bytes_with_type_map_and_limits(
                &response,
                &tm,
                transport.decode_limits(),
            )
            .map_err(|e| js_error(format!("parse response: {}", e)))?;
            let negotiated_version = match resp_comm.get_data(DataType::Version) {
                Some(DataValue::Str(version)) => mtp_codec::Version::parse(version)
                    .ok_or_else(|| js_error("host returned an invalid negotiated version"))?,
                _ => return Err(js_error("host omitted the negotiated version")),
            };
            if negotiated_version != PROTOCOL_VERSION {
                return Err(js_error(
                    "host selected a protocol version the client did not offer",
                ));
            }
            let codec = mtp_codec::registry::VersionedCodec::for_version(
                mtp_codec::registry::Registry::builtin(),
                negotiated_version,
            )
            .ok_or_else(|| js_error("host returned an unsupported negotiated version"))?;
            transport.set_type_map(codec.type_map());
            let resp_comm = CommunicationValue::try_from_bytes_with_type_map_and_limits(
                &response,
                codec.type_map(),
                transport.decode_limits(),
            )
            .map_err(|e| js_error(format!("parse negotiated response: {}", e)))?;
            let tm = codec.type_map();
            let resp_type = resp_comm.get_type();
            let expected_type = CommunicationType::IdentificationResponse
                .try_to_id(tm)
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

            if resp_comm.get_data(DataType::Connected) != Some(&DataValue::BoolTrue) {
                self.set_state_if_current(generation, ConnectionState::Disconnected);
                return Err(js_error(
                    resp_comm
                        .get_str(DataType::ErrorMessage)
                        .unwrap_or("host rejected authentication"),
                ));
            }

            if let Err(e) = auth::verify_host_final(
                &resp_comm,
                &host_pk,
                config.description.as_deref(),
                client_id,
                client_nonce,
                server_challenge,
                config.require_pq,
            ) {
                self.set_state_if_current(generation, ConnectionState::Disconnected);
                return Err(e);
            }

            let assigned_id = match resp_comm.get_data(DataType::Id) {
                Some(DataValue::UnsignedNumber(n)) => match u64::try_from(*n) {
                    Ok(id) => id,
                    Err(_) => {
                        self.set_state_if_current(generation, ConnectionState::Disconnected);
                        return Err(js_error("assigned ID is out of range"));
                    }
                },
                _ => {
                    self.set_state_if_current(generation, ConnectionState::Disconnected);
                    return Err(js_error("missing assigned ID"));
                }
            };

            if !self.start_receive_loop(transport.clone(), generation, assigned_id) {
                return Err(js_error("connection attempt superseded"));
            }

            Ok(assigned_id)
        }
        .await;
        if let Err(error) = &result {
            self.abort_attempt(&transport, generation);
            let _ = error;
        }
        result
    }

    #[wasm_bindgen]
    #[deprecated(
        note = "use the SDK registration methods; this raw method remains for compatibility"
    )]
    pub async fn auth_register(
        &self,
        config: &ConnectionConfig,
        host_public_key_bytes: &[u8],
        keyring_bytes: &[u8],
    ) -> Result<u64, JsValue> {
        self.auth_register_owned(
            config.clone(),
            host_public_key_bytes.to_vec(),
            keyring_bytes.to_vec(),
        )
        .await
    }

    #[wasm_bindgen(js_name = authRegisterOwned)]
    pub async fn auth_register_owned(
        &self,
        config: ConnectionConfig,
        host_public_key_bytes: Vec<u8>,
        keyring_bytes: Vec<u8>,
    ) -> Result<u64, JsValue> {
        let generation = self.begin_connection();

        let host_pk = match mtp_crypto::PublicKeyBundle::from_bytes(&host_public_key_bytes) {
            Ok(value) => value,
            Err(error) => {
                let error = js_error(format!("invalid host public key: {}", error));
                self.set_state_if_current(generation, ConnectionState::Disconnected);
                return Err(error);
            }
        };
        let keyring = match mtp_crypto::Keyring::from_bytes(&keyring_bytes) {
            Ok(value) => value,
            Err(error) => {
                let error = js_error(format!("invalid keyring: {}", error));
                self.set_state_if_current(generation, ConnectionState::Disconnected);
                return Err(error);
            }
        };

        let handshake_codec = mtp_codec::registry::VersionedCodec::for_version(
            mtp_codec::registry::Registry::builtin(),
            PROTOCOL_VERSION,
        )
        .ok_or_else(|| js_error("client protocol version is not registered"))?;
        let tm = handshake_codec.type_map().clone();
        let version_str = format!("{}", PROTOCOL_VERSION);
        let pk_bytes = keyring
            .public_key_bundle()
            .try_as_bytes()
            .map_err(|error| js_error(format!("public key serialization failed: {error}")))?;

        let transport = match WasmTransport::connect_with_limits(
            &config.url,
            config.server_certificate_hashes.clone(),
            config.max_message_size,
            self.receive_decode_limits(),
        )
        .await
        {
            Ok(transport) => transport,
            Err(error) => {
                self.set_state_if_current(generation, ConnectionState::Disconnected);
                return Err(error);
            }
        };
        transport.set_type_map(&tm);
        if !self.install_attempt_transport(&transport, generation) {
            return Err(js_error("connection attempt superseded"));
        }

        let result = async {
            let mut hello = CommunicationValue::new_with_type_map(CommunicationType::Register, &tm)
                .add_typed_default(DataType::Version, DataValue::Str(version_str.clone()))
                .add_typed_default(DataType::PublicKeys, DataValue::Bytes(pk_bytes.clone()));
            if let Some(desc) = &config.description {
                hello =
                    hello.add_typed_default(DataType::Description, DataValue::Str(desc.clone()));
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
                config.description.as_deref(),
                &pk_bytes,
                server_challenge,
                client_nonce,
            );
            let proof =
                auth::signed_challenge_response_bytes(&keyring, &proof_payload, client_nonce, &tm)?;
            transport.send_frame(&proof).await?;

            let response = transport.read_one_frame().await?;
            let resp_comm = CommunicationValue::try_from_bytes_with_type_map_and_limits(
                &response,
                &tm,
                transport.decode_limits(),
            )
            .map_err(|e| js_error(format!("parse response: {}", e)))?;
            let negotiated_version = match resp_comm.get_data(DataType::Version) {
                Some(DataValue::Str(version)) => mtp_codec::Version::parse(version)
                    .ok_or_else(|| js_error("host returned an invalid negotiated version"))?,
                _ => return Err(js_error("host omitted the negotiated version")),
            };
            if negotiated_version != PROTOCOL_VERSION {
                return Err(js_error(
                    "host selected a protocol version the client did not offer",
                ));
            }
            let codec = mtp_codec::registry::VersionedCodec::for_version(
                mtp_codec::registry::Registry::builtin(),
                negotiated_version,
            )
            .ok_or_else(|| js_error("host returned an unsupported negotiated version"))?;
            transport.set_type_map(codec.type_map());
            let resp_comm = CommunicationValue::try_from_bytes_with_type_map_and_limits(
                &response,
                codec.type_map(),
                transport.decode_limits(),
            )
            .map_err(|e| js_error(format!("parse negotiated response: {}", e)))?;
            let tm = codec.type_map();
            let resp_type = resp_comm.get_type();
            let expected_type = CommunicationType::RegisterResponse
                .try_to_id(tm)
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

            if resp_comm.get_data(DataType::Connected) != Some(&DataValue::BoolTrue) {
                self.set_state_if_current(generation, ConnectionState::Disconnected);
                return Err(js_error(
                    resp_comm
                        .get_str(DataType::ErrorMessage)
                        .unwrap_or("host rejected registration"),
                ));
            }

            let assigned_id = match resp_comm.get_data(DataType::Id) {
                Some(DataValue::UnsignedNumber(n)) => match u64::try_from(*n) {
                    Ok(id) => id,
                    Err(_) => {
                        self.set_state_if_current(generation, ConnectionState::Disconnected);
                        return Err(js_error("assigned ID is out of range"));
                    }
                },
                _ => {
                    self.set_state_if_current(generation, ConnectionState::Disconnected);
                    return Err(js_error("missing assigned ID"));
                }
            };

            if let Err(e) = auth::verify_host_final(
                &resp_comm,
                &host_pk,
                config.description.as_deref(),
                assigned_id,
                client_nonce,
                server_challenge,
                config.require_pq,
            ) {
                self.set_state_if_current(generation, ConnectionState::Disconnected);
                return Err(e);
            }

            if !self.start_receive_loop(transport.clone(), generation, assigned_id) {
                return Err(js_error("connection attempt superseded"));
            }

            Ok(assigned_id)
        }
        .await;
        if let Err(error) = &result {
            self.abort_attempt(&transport, generation);
            let _ = error;
        }
        result
    }

    #[allow(clippy::too_many_arguments)]
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
        let challenge = CommunicationValue::try_from_bytes_with_type_map_and_limits(
            &challenge_bytes,
            tm,
            transport.decode_limits(),
        )
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
            Some(DataValue::UnsignedNumber(n)) => *n,
            _ => {
                self.set_state_if_current(generation, ConnectionState::Disconnected);
                return Err(js_error("missing server challenge"));
            }
        };

        if challenge.get_data(DataType::RequirePq) == Some(&DataValue::BoolTrue)
            && !client_has_pq_key
        {
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

#[cfg(test)]
mod tests {
    use super::server_rejection_message;
    use mtp_codec::{CommunicationType, CommunicationValue, DataType, DataValue};

    #[test]
    fn reports_rejection_reason_without_a_negotiated_version() {
        let response = CommunicationValue::new(CommunicationType::IdentificationResponse)
            .add_typed_default(DataType::Connected, DataValue::BoolFalse)
            .add_typed_default(
                DataType::ErrorMessage,
                DataValue::Str("authentication handshake timed out".into()),
            );

        assert_eq!(
            server_rejection_message(&response),
            Some("authentication handshake timed out")
        );
    }
}
