use super::*;

impl HandshakeEngine {
    #[cfg(feature = "crypto")]
    pub(super) async fn unauthenticated_handshake<S: HandshakeSender>(
        &self,
        sender: &S,
        first_msg: CommunicationValue,
        negotiated: Version,
        codec: VersionedCodec,
        description: Option<String>,
    ) -> Result<HandshakeResult, AcceptError> {
        let tm = codec.type_map();

        // Reject explicit authentication attempts on unauthenticated hosts.
        // Authenticated clients include PublicKeys in Identification as an
        // intent marker; this avoids acknowledging the opening as a guest
        // connection and leaving the client waiting for a Challenge.
        if Some(first_msg.get_type()) == CommunicationType::Register.try_to_id(tm)
            || first_msg.get_data(DataType::PublicKeys).is_some()
        {
            send_rejection_generic(
                sender,
                RejectionReason::AuthenticationFailed {
                    detail: "authentication not allowed on this host".into(),
                },
                Some(tm),
            )
            .await;
            sender.close();
            return Err(AcceptError::AuthenticationFailed(
                "authentication not allowed on this host".into(),
            ));
        }

        let guest_id_lease = match self.assign_guest_id().await {
            Ok(lease) => lease,
            Err(error) => {
                reject_error_generic(sender, &error, tm).await;
                return Err(error);
            }
        };
        let guest_id = guest_id_lease.id;
        send_accepted_generic(sender, &negotiated, tm, Some(guest_id))
            .await
            .map_err(AcceptError::Send)?;

        Ok(HandshakeResult {
            negotiated_version: negotiated,
            codec,
            description,
            auth_state: crate::error::AuthState::Unauthenticated,
            client_id: guest_id,
            client_public_key: None,
            guest_id_lease: Some(guest_id_lease),
        })
    }

    #[cfg(feature = "crypto")]
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn allow_auth_handshake<S: HandshakeSender, R: HandshakeReceiver>(
        &self,
        sender: &S,
        receiver: &R,
        first_msg: CommunicationValue,
        negotiated: Version,
        codec: VersionedCodec,
        description: Option<String>,
        version_str: &str,
        client_version: Version,
    ) -> Result<HandshakeResult, AcceptError> {
        let tm = codec.type_map();

        // Register frames always go through full authentication
        if Some(first_msg.get_type()) == CommunicationType::Register.try_to_id(tm) {
            let bundle = match extract_register_bundle(&first_msg) {
                Ok(bundle) => bundle,
                Err(error) => {
                    reject_error_generic(sender, &error, tm).await;
                    return Err(error);
                }
            };
            let pk_bytes = match bundle.try_as_bytes() {
                Ok(bytes) => bytes,
                Err(error) => {
                    let error = AcceptError::AuthenticationFailed(error.to_string());
                    reject_error_generic(sender, &error, tm).await;
                    return Err(error);
                }
            };
            return self
                .complete_auth_handshake(
                    sender,
                    receiver,
                    Flow::Register { bundle, pk_bytes },
                    CommunicationType::RegisterResponse,
                    &negotiated,
                    &codec,
                    description,
                    version_str,
                    client_version,
                )
                .await;
        }

        // Identification: try lookup, fall back to guest
        if Some(first_msg.get_type()) == CommunicationType::Identification.try_to_id(tm) {
            let cid = match first_msg.get_data(DataType::Id) {
                Some(DataValue::UnsignedNumber(n)) => u64::try_from(*n).unwrap_or(0),
                _ => 0,
            };

            if cid > 0
                && let Some(bundle) =
                    (self.config.get_existing_client)(cid, description.clone()).await
            {
                return self
                    .complete_auth_handshake(
                        sender,
                        receiver,
                        Flow::Login { id: cid, bundle },
                        CommunicationType::IdentificationResponse,
                        &negotiated,
                        &codec,
                        description,
                        version_str,
                        client_version,
                    )
                    .await;
            }

            // Unknown or zero ID: an Identification carrying PublicKeys is an
            // explicit authentication attempt, not a guest connection.
            if first_msg.get_data(DataType::PublicKeys).is_some() {
                if self.config.conceal_authentication_identities && cid > 0 {
                    /* Keep an unknown authenticated ID on the same
                    challenge/proof path as a known ID. The fixed host
                    identity makes the eventual proof fail without
                    disclosing whether the lookup succeeded. */
                    return self
                        .complete_auth_handshake(
                            sender,
                            receiver,
                            Flow::Login {
                                id: cid,
                                bundle: self.config.host_keyring.public_key_bundle(),
                            },
                            CommunicationType::IdentificationResponse,
                            &negotiated,
                            &codec,
                            description,
                            version_str,
                            client_version,
                        )
                        .await;
                }
                let error = AcceptError::AuthenticationFailed(
                    "unknown authenticated client identity".into(),
                );
                reject_error_generic(sender, &error, tm).await;
                return Err(error);
            }

            // Unknown or zero ID: fall back to guest
            tracing::info!("allocating MTP guest identity");
            let guest_id_lease = match self.assign_guest_id().await {
                Ok(lease) => lease,
                Err(error) => {
                    reject_error_generic(sender, &error, tm).await;
                    return Err(error);
                }
            };
            let guest_id = guest_id_lease.id;
            tracing::info!(guest_id, "allocated MTP guest identity");
            send_accepted_generic(sender, &negotiated, tm, Some(guest_id))
                .await
                .map_err(AcceptError::Send)?;
            return Ok(HandshakeResult {
                negotiated_version: negotiated,
                codec,
                description,
                auth_state: crate::error::AuthState::Unauthenticated,
                client_id: guest_id,
                client_public_key: None,
                guest_id_lease: Some(guest_id_lease),
            });
        }

        let error = AcceptError::AuthenticationFailed("unexpected message type".into());
        reject_error_generic(sender, &error, tm).await;
        Err(error)
    }

    #[cfg(feature = "crypto")]
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn force_auth_handshake<S: HandshakeSender, R: HandshakeReceiver>(
        &self,
        sender: &S,
        receiver: &R,
        first_msg: CommunicationValue,
        negotiated: Version,
        codec: VersionedCodec,
        description: Option<String>,
        version_str: &str,
        client_version: Version,
    ) -> Result<HandshakeResult, AcceptError> {
        let tm = codec.type_map();

        let (flow, response_type) = if Some(first_msg.get_type())
            == CommunicationType::Identification.try_to_id(tm)
        {
            let cid = match first_msg.get_data(DataType::Id) {
                Some(DataValue::UnsignedNumber(n)) => match u64::try_from(*n) {
                    Ok(id) => id,
                    Err(_) => {
                        let error =
                            AcceptError::AuthenticationFailed("client id is out of range".into());
                        reject_error_generic(sender, &error, tm).await;
                        return Err(error);
                    }
                },
                _ => {
                    let error = AcceptError::AuthenticationFailed("missing client id".into());
                    reject_error_generic(sender, &error, tm).await;
                    return Err(error);
                }
            };
            let bundle = match (self.config.get_existing_client)(cid, description.clone()).await {
                Some(b) => b,
                None => {
                    if self.config.conceal_authentication_identities {
                        // Use a valid fixed-cost dummy identity so an unknown
                        // client follows the same challenge/proof sequence as
                        // a registered client. The host public bundle is
                        // already public and the peer cannot produce its
                        // private-key proof.
                        self.config.host_keyring.public_key_bundle()
                    } else {
                        let rejection = CommunicationValue::new_with_type_map(
                            CommunicationType::IdentificationResponse,
                            tm,
                        )
                        .add_typed_default(DataType::Connected, DataValue::BoolFalse)
                        .add_typed_default(
                            DataType::ErrorMessage,
                            DataValue::Str("unknown client id".into()),
                        );
                        let _ = sender.send(&rejection).await;
                        sender.close();
                        return Err(AcceptError::AuthenticationFailed(
                            "unknown client id".into(),
                        ));
                    }
                }
            };
            (
                Flow::Login { id: cid, bundle },
                CommunicationType::IdentificationResponse,
            )
        } else if Some(first_msg.get_type()) == CommunicationType::Register.try_to_id(tm) {
            let bundle = match extract_register_bundle(&first_msg) {
                Ok(bundle) => bundle,
                Err(error) => {
                    reject_error_generic(sender, &error, tm).await;
                    return Err(error);
                }
            };
            let pk_bytes = match bundle.try_as_bytes() {
                Ok(bytes) => bytes,
                Err(error) => {
                    let error = AcceptError::AuthenticationFailed(error.to_string());
                    reject_error_generic(sender, &error, tm).await;
                    return Err(error);
                }
            };
            (
                Flow::Register { bundle, pk_bytes },
                CommunicationType::RegisterResponse,
            )
        } else {
            let error =
                AcceptError::AuthenticationFailed("unexpected authentication message".into());
            reject_error_generic(sender, &error, tm).await;
            return Err(error);
        };

        self.complete_auth_handshake(
            sender,
            receiver,
            flow,
            response_type,
            &negotiated,
            &codec,
            description,
            version_str,
            client_version,
        )
        .await
    }

    #[cfg(feature = "crypto")]
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn complete_auth_handshake<S: HandshakeSender, R: HandshakeReceiver>(
        &self,
        sender: &S,
        receiver: &R,
        flow: Flow,
        response_type: CommunicationType,
        negotiated: &Version,
        codec: &VersionedCodec,
        description: Option<String>,
        version_str: &str,
        _client_version: Version,
    ) -> Result<HandshakeResult, AcceptError> {
        use mtp_crypto::{Ed25519Signer, MlDsaSigner, SignatureScheme, auth, verify_ed25519};

        let tm = codec.type_map();

        // PQ preflight: host requiring PQ must have a PQ key
        let bind_dictionary = |payload| {
            mtp_codec::dictionary::bind_authentication(tm, payload)
                .map_err(|error| AcceptError::AuthenticationFailed(error.to_string()))
        };
        let pq_enabled = !self
            .config
            .host_keyring
            .sig_pq_secret_key
            .as_bytes()
            .is_empty();
        if self.config.require_pq
            && (!pq_enabled
                || self
                    .config
                    .host_keyring
                    .sig_pq_public_key
                    .as_bytes()
                    .is_empty())
        {
            send_rejection_generic(
                sender,
                RejectionReason::AuthenticationFailed {
                    detail: "host requires PQ authentication but has no PQ signing key".into(),
                },
                Some(tm),
            )
            .await;
            sender.close();
            return Err(AcceptError::AuthenticationFailed(
                "PQ authentication is required but the host PQ key is absent".into(),
            ));
        }

        // Initialize host signers
        let host_pq_signer = if pq_enabled {
            Some(Arc::new(
                match MlDsaSigner::new(
                    &self.config.host_keyring.sig_pq_secret_key,
                    &self.config.host_keyring.sig_pq_public_key,
                ) {
                    Ok(signer) => signer,
                    Err(error) => {
                        let error = AcceptError::AuthenticationFailed(error.to_string());
                        reject_error_generic(sender, &error, tm).await;
                        return Err(error);
                    }
                },
            ))
        } else {
            None
        };

        let host_sign = |payload: Vec<u8>| async {
            let signer = Ed25519Signer::new(&self.config.host_keyring.sig_cl_secret_key)
                .map_err(|e| AcceptError::AuthenticationFailed(e.to_string()))?;
            if let Some(pq_signer) = host_pq_signer.as_ref() {
                mtp_crypto::sign_parallel::sign_dual_parallel_shared_pq(
                    signer,
                    Arc::clone(pq_signer),
                    payload,
                )
                .await
                .map_err(|e| AcceptError::AuthenticationFailed(e.to_string()))
            } else {
                let sig = signer
                    .sign(&payload)
                    .map_err(|e| AcceptError::AuthenticationFailed(e.to_string()))?;
                Ok((sig, Vec::new()))
            }
        };

        // Sign and send challenge
        let challenge_id = match &flow {
            Flow::Login { id, .. } => *id,
            Flow::Register { .. } => 0,
        };

        let server_challenge: u128 = rand::random();
        let (chal_sig, chal_pq_sig) = match host_sign(bind_dictionary(auth::challenge_payload(
            challenge_id,
            server_challenge,
        ))?)
        .await
        {
            Ok(signatures) => signatures,
            Err(error) => {
                reject_error_generic(sender, &error, tm).await;
                return Err(error);
            }
        };

        let mut challenge_msg =
            CommunicationValue::new_with_type_map(CommunicationType::Challenge, tm)
                .add_typed_default(
                    DataType::ServerNonce,
                    DataValue::UnsignedNumber(server_challenge),
                )
                .add_typed_default(DataType::Signature, DataValue::Bytes(chal_sig));
        challenge_msg = challenge_msg.add_typed_default(
            DataType::DictionaryFingerprint,
            mtp_codec::dictionary::value(tm).map_err(AcceptError::Send)?,
        );
        challenge_msg = challenge_msg.add_typed_default(
            DataType::RequirePq,
            if self.config.require_pq {
                DataValue::BoolTrue
            } else {
                DataValue::BoolFalse
            },
        );
        if pq_enabled {
            challenge_msg = challenge_msg
                .add_typed_default(DataType::PqSignature, DataValue::Bytes(chal_pq_sig));
        }
        if let Err(e) = sender.send(&challenge_msg).await {
            sender.close();
            return Err(AcceptError::Send(e));
        }

        // Receive and verify client proof
        let proof = receiver.receive().await.map_err(|e| {
            sender.close();
            AcceptError::Receive(e)
        })?;
        if Some(proof.get_type()) != CommunicationType::ChallengeResponse.try_to_id(tm) {
            let error = AcceptError::AuthenticationFailed("missing challenge response".into());
            reject_error_generic(sender, &error, tm).await;
            return Err(error);
        }
        if let Err(error) = mtp_codec::dictionary::verify_selection(&proof, tm) {
            let error = AcceptError::AuthenticationFailed(error.to_string());
            reject_error_generic(sender, &error, tm).await;
            return Err(error);
        }
        let client_nonce = match proof.get_data(DataType::ClientNonce) {
            Some(DataValue::UnsignedNumber(n)) => *n,
            _ => {
                let error = AcceptError::AuthenticationFailed("missing client nonce".into());
                reject_error_generic(sender, &error, tm).await;
                return Err(error);
            }
        };
        let sig_bytes = match proof.get_data(DataType::Signature) {
            Some(DataValue::Bytes(b)) => b.clone(),
            _ => {
                let error = AcceptError::AuthenticationFailed("missing challenge signature".into());
                reject_error_generic(sender, &error, tm).await;
                return Err(error);
            }
        };
        let pq_sig_bytes: Vec<u8> = match proof.get_data(DataType::PqSignature) {
            Some(DataValue::Bytes(b)) => b.clone(),
            _ => vec![],
        };

        let (proof_payload, bundle) = match &flow {
            Flow::Login { id, bundle } => (
                auth::login_proof_payload(
                    version_str,
                    description.as_deref(),
                    *id,
                    server_challenge,
                    client_nonce,
                ),
                bundle,
            ),
            Flow::Register {
                bundle, pk_bytes, ..
            } => (
                auth::register_proof_payload(
                    version_str,
                    description.as_deref(),
                    pk_bytes,
                    server_challenge,
                    client_nonce,
                ),
                bundle,
            ),
        };

        let has_client_pq_key = !bundle.sig_pq_public_key.as_bytes().is_empty();
        let proof_payload = bind_dictionary(proof_payload)?;
        let proof_ok = if pq_sig_bytes.is_empty() {
            !self.config.require_pq
                && verify_ed25519(&bundle.sig_cl_public_key, &proof_payload, &sig_bytes).is_ok()
        } else if has_client_pq_key {
            mtp_crypto::sign_parallel::verify_dual_parallel(
                bundle.sig_cl_public_key.clone(),
                bundle.sig_pq_public_key.clone(),
                proof_payload,
                sig_bytes,
                pq_sig_bytes,
            )
            .await
            .is_ok()
        } else {
            false
        };

        if !proof_ok {
            send_rejection_generic(
                sender,
                RejectionReason::AuthenticationFailed {
                    detail: "client proof signature invalid".into(),
                },
                Some(tm),
            )
            .await;
            sender.close();
            return Err(AcceptError::AuthenticationFailed(
                "client proof signature invalid".into(),
            ));
        }

        // Register or login
        let (assigned_id, client_bundle) = match flow {
            Flow::Login { id, bundle } => (id, bundle),
            Flow::Register { bundle, .. } => {
                let _registration_guard = self.config.registration_lock.lock().await;
                let new_id = if let Some(lookup) = &self.config.find_registered_client {
                    match lookup(bundle.clone(), description.clone()).await {
                        Some(id) => id,
                        None => {
                            (self.config.complete_register)(bundle.clone(), description.clone())
                                .await
                        }
                    }
                } else {
                    (self.config.complete_register)(bundle.clone(), description.clone()).await
                };
                if new_id == 0 {
                    let error = AcceptError::AuthenticationFailed(
                        "registration callback returned reserved client id 0".into(),
                    );
                    reject_error_generic(sender, &error, tm).await;
                    return Err(error);
                }
                (new_id, bundle)
            }
        };
        if assigned_id == 0 {
            let error = AcceptError::AuthenticationFailed(
                "client id 0 is reserved for no authenticated identity".into(),
            );
            reject_error_generic(sender, &error, tm).await;
            return Err(error);
        }

        // Sign and send final response
        let (host_sig, host_pq_sig) = match host_sign(bind_dictionary(auth::host_final_payload(
            description.as_deref(),
            assigned_id,
            client_nonce,
            server_challenge,
        ))?)
        .await
        {
            Ok(signatures) => signatures,
            Err(error) => {
                reject_error_generic(sender, &error, tm).await;
                return Err(error);
            }
        };

        let mut response = CommunicationValue::new_with_type_map(response_type, tm)
            .add_typed_default(
                DataType::DictionaryFingerprint,
                mtp_codec::dictionary::value(tm).map_err(AcceptError::Send)?,
            )
            .add_typed_default(DataType::Connected, DataValue::BoolTrue)
            .add_typed_default(DataType::Id, DataValue::UnsignedNumber(assigned_id as u128))
            .add_typed_default(
                DataType::ClientNonce,
                DataValue::UnsignedNumber(client_nonce),
            )
            .add_typed_default(DataType::Signature, DataValue::Bytes(host_sig));
        response =
            response.add_typed_default(DataType::Version, DataValue::Str(negotiated.to_string()));
        if pq_enabled {
            response =
                response.add_typed_default(DataType::PqSignature, DataValue::Bytes(host_pq_sig));
        }

        if let Err(e) = sender.send(&response).await {
            sender.close();
            return Err(AcceptError::Send(e));
        }
        if let Err(e) = sender.finish_stream().await {
            sender.close();
            return Err(AcceptError::Send(e));
        }

        Ok(HandshakeResult {
            negotiated_version: negotiated.clone(),
            codec: codec.clone(),
            description,
            auth_state: crate::error::AuthState::Authenticated,
            client_id: assigned_id,
            client_public_key: Some(client_bundle),
            guest_id_lease: None,
        })
    }
}
