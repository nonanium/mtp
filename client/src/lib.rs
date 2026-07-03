use mtp_codec::{CommunicationValue, DataType, DataValue, PROTOCOL_VERSION, Version};
use mtp_common::CommunicationError;
#[cfg(feature = "crypto")]
use tokio::time::Duration;

pub use MTPClient as Client;
pub use MTPConnection as Connection;
pub use mtp_transport::Policy;
pub use mtp_transport::Receiver;
pub use mtp_transport::SendMode;
pub use mtp_transport::Sender;

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
    pub tls: ClientTlsConfig,
    pub client_id: u64,
    pub description: Option<String>,
    pub policy: Policy,
    #[cfg(feature = "crypto")]
    pub auth_timeout: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientTlsConfig {
    SystemRoots,
    PinnedPem(Vec<u8>),
}

impl ClientConfig {
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            tls: ClientTlsConfig::SystemRoots,
            client_id: 0,
            description: None,
            policy: Policy::default(),
            #[cfg(feature = "crypto")]
            auth_timeout: Duration::from_secs(30),
        }
    }

    pub fn with_tls(mut self, tls: ClientTlsConfig) -> Self {
        self.tls = tls;
        self
    }

    pub fn with_pinned_pem(self, cert_pem: Vec<u8>) -> Self {
        self.with_tls(ClientTlsConfig::PinnedPem(cert_pem))
    }

    pub fn with_client_id(mut self, client_id: u64) -> Self {
        self.client_id = client_id;
        self
    }

    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    pub fn with_policy(mut self, policy: Policy) -> Self {
        self.policy = policy;
        self
    }

    #[cfg(feature = "crypto")]
    pub fn with_auth_timeout(mut self, timeout: Duration) -> Self {
        self.auth_timeout = timeout;
        self
    }

    fn server_cert(&self) -> Option<Vec<u8>> {
        match &self.tls {
            ClientTlsConfig::SystemRoots => None,
            ClientTlsConfig::PinnedPem(cert) => Some(cert.clone()),
        }
    }
}

/* Established MTP connection with a single negotiated version. */
pub struct MTPConnection {
    pub version: Version,
    pub sender: Sender,
    pub receiver: Receiver,
    pub description: Option<String>,
    #[cfg(feature = "crypto")]
    pub auth_state: AuthState,
    #[cfg(feature = "crypto")]
    pub client_id: u64,
}

impl MTPConnection {
    /*
     * Send a request frame and wait for the response with the same frame id.
     * Any expected response type is validated after the id match. Frames with
     * other ids are consumed by this call, so applications that need broad
     * routing should put request correlation in a dedicated receive task.
     */
    pub async fn request(
        &self,
        request: &CommunicationValue,
        expected_response: Option<mtp_codec::CommunicationType>,
    ) -> Result<CommunicationValue, CommunicationError> {
        let request_id = request.get_id();
        if request_id == 0 {
            return Err(CommunicationError::Other(
                "request frame must have a non-zero id".into(),
            ));
        }

        self.sender.send(request).await?;

        let tm = mtp_codec::TypeMap::latest();
        loop {
            let response = self.receiver.receive().await?;
            if response.get_id() != request_id {
                continue;
            }

            if let Some(expected) = expected_response {
                let expected_type = expected.to_id(&tm);
                if response.get_type() != expected_type {
                    return Err(CommunicationError::Other(format!(
                        "unexpected response type: expected {:?}, got {:?}; parsed {}",
                        expected_type,
                        response.get_type(),
                        response
                    )));
                }
            }

            return Ok(response);
        }
    }
}

#[cfg(feature = "crypto")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthState {
    Unauthenticated,
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
            mtp_transport::connect(&config.url, config.server_cert(), Policy::default()).await?;

        let version_str = format!("{}", PROTOCOL_VERSION);
        let mut ident = CommunicationValue::new(mtp_codec::CommunicationType::Identification)
            .add_typed_default(DataType::Version, DataValue::Str(version_str))
            .add_typed_default(
                DataType::Id,
                DataValue::UnsignedNumber(config.client_id.into()),
            );
        if let Some(desc) = &config.description {
            ident = ident.add_typed_default(DataType::Description, DataValue::Str(desc.clone()));
        }

        sender.send(&ident).await?;

        Ok(MTPConnection {
            version: PROTOCOL_VERSION,
            sender,
            receiver,
            description: config.description,
            #[cfg(feature = "crypto")]
            auth_state: AuthState::Unauthenticated,
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
    host_pk: &mtp_crypto::PublicKeyBundle,
    id: u64,
    server_challenge: u128,
) -> Result<(), CommunicationError> {
    use mtp_crypto::{auth, verify_ed25519, verify_ml_dsa};

    let sig = match challenge.get_data(DataType::Signature) {
        DataValue::Bytes(b) => b.clone(),
        _ => {
            return Err(CommunicationError::AuthenticationFailed(
                "Missing host challenge signature".into(),
            ));
        }
    };
    let pq_sig = match challenge.get_data(DataType::PqSignature) {
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
    host_pk: &mtp_crypto::PublicKeyBundle,
    id: u64,
    client_nonce: u128,
    server_challenge: u128,
) -> Result<(), CommunicationError> {
    use mtp_crypto::{auth, verify_ed25519, verify_ml_dsa};

    match response.get_data(DataType::ClientNonce) {
        DataValue::UnsignedNumber(n) if *n == client_nonce => {}
        _ => {
            return Err(CommunicationError::AuthenticationFailed(
                "Nonce mismatch".into(),
            ));
        }
    }

    let sig = match response.get_data(DataType::Signature) {
        DataValue::Bytes(b) => b.clone(),
        _ => {
            return Err(CommunicationError::AuthenticationFailed(
                "Missing signature".into(),
            ));
        }
    };
    let pq_sig = match response.get_data(DataType::PqSignature) {
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
    reject_msg: &str,
) -> Result<(), CommunicationError> {
    match response.get_data(DataType::Connected) {
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

    let server_challenge = match challenge.get_data(DataType::ServerNonce) {
        DataValue::UnsignedNumber(n) => *n,
        _ => {
            return Err(CommunicationError::AuthenticationFailed(
                "Missing server challenge".into(),
            ));
        }
    };

    verify_host_challenge(
        &challenge,
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
        let timeout = config.auth_timeout;
        match tokio::time::timeout(
            timeout,
            Self::auth_connect_inner(config, keys, host_public_key_bundle),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => Err(CommunicationError::AuthenticationFailed(
                "authentication timed out".into(),
            )),
        }
    }

    async fn auth_connect_inner(
        config: ClientConfig,
        keys: &mtp_crypto::Keyring,
        host_public_key_bundle: &mtp_crypto::PublicKeyBundle,
    ) -> Result<MTPConnection, CommunicationError> {
        use mtp_crypto::auth;

        let (sender, receiver) =
            mtp_transport::connect(&config.url, config.server_cert(), config.policy).await?;

        let tm = mtp_codec::TypeMap::latest();
        let version_str = format!("{}", PROTOCOL_VERSION);

        // 1. Send the unsigned Identification hello (version + claimed id).
        let mut ident = CommunicationValue::new(mtp_codec::CommunicationType::Identification)
            .add_typed_default(DataType::Version, DataValue::Str(version_str.clone()))
            .add_typed_default(
                DataType::Id,
                DataValue::UnsignedNumber(config.client_id as u128),
            );
        if let Some(desc) = &config.description {
            ident = ident.add_typed_default(DataType::Description, DataValue::Str(desc.clone()));
        }
        if let Err(e) = sender.send(&ident).await {
            sender.close();
            return Err(e);
        }

        // 2. Receive and verify the host's challenge.
        let server_challenge = match receive_verified_challenge(
            &receiver,
            &tm,
            host_public_key_bundle,
            config.client_id,
            "auth_connect challenge",
        )
        .await
        {
            Ok(c) => c,
            Err(e) => {
                sender.close();
                return Err(e);
            }
        };

        // 3. Sign the host's challenge and send the proof.
        let client_nonce: u128 = rand::random();
        let proof_payload = auth::login_proof_payload(
            &version_str,
            config.client_id,
            server_challenge,
            client_nonce,
        );

        let proof = match signed_challenge_response(keys, &proof_payload, client_nonce) {
            Ok(p) => p,
            Err(e) => {
                sender.close();
                return Err(e);
            }
        };
        if let Err(e) = sender.send(&proof).await {
            sender.close();
            return Err(e);
        }

        // 4. Receive and verify the host's final confirmation.
        let response = match receiver.receive().await {
            Ok(r) => r,
            Err(e) => {
                sender.close();
                return Err(e);
            }
        };
        let expected_type = mtp_codec::CommunicationType::IdentificationResponse.to_id(&tm);
        if response.get_type() != expected_type {
            sender.close();
            return Err(unexpected_response_type_error(
                "auth_connect",
                expected_type,
                &response,
            ));
        }
        if let Err(e) = check_connected(&response, "Server rejected authentication") {
            sender.close();
            return Err(e);
        }
        if let Err(e) = verify_host_final(
            &response,
            host_public_key_bundle,
            config.client_id,
            client_nonce,
            server_challenge,
        ) {
            sender.close();
            return Err(e);
        }

        Ok(MTPConnection {
            version: PROTOCOL_VERSION,
            sender,
            receiver,
            description: config.description,
            auth_state: AuthState::Authenticated,
            client_id: config.client_id,
        })
    }

    pub async fn auth_register(
        config: ClientConfig,
        keys: &mtp_crypto::Keyring,
        host_public_key_bundle: &mtp_crypto::PublicKeyBundle,
    ) -> Result<MTPConnection, CommunicationError> {
        let timeout = config.auth_timeout;
        match tokio::time::timeout(
            timeout,
            Self::auth_register_inner(config, keys, host_public_key_bundle),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => Err(CommunicationError::AuthenticationFailed(
                "authentication timed out".into(),
            )),
        }
    }

    pub async fn auth_connect_or_register(
        mut config: ClientConfig,
        existing_client_id: Option<u64>,
        keys: &mtp_crypto::Keyring,
        host_public_key_bundle: &mtp_crypto::PublicKeyBundle,
    ) -> Result<MTPConnection, CommunicationError> {
        match existing_client_id {
            Some(client_id) => {
                config.client_id = client_id;
                Self::auth_connect(config, keys, host_public_key_bundle).await
            }
            None => Self::auth_register(config, keys, host_public_key_bundle).await,
        }
    }

    async fn auth_register_inner(
        config: ClientConfig,
        keys: &mtp_crypto::Keyring,
        host_public_key_bundle: &mtp_crypto::PublicKeyBundle,
    ) -> Result<MTPConnection, CommunicationError> {
        use mtp_crypto::auth;

        let (sender, receiver) =
            mtp_transport::connect(&config.url, config.server_cert(), config.policy).await?;

        let tm = mtp_codec::TypeMap::latest();
        let version_str = format!("{}", PROTOCOL_VERSION);
        let pk_bundle = keys.public_key_bundle();
        let pk_bytes = pk_bundle.as_bytes();

        // 1. Send the unsigned Register hello (version + public-key bundle).
        let mut register = CommunicationValue::new(mtp_codec::CommunicationType::Register)
            .add_typed_default(DataType::Version, DataValue::Str(version_str.clone()))
            .add_typed_default(DataType::PublicKeys, DataValue::Bytes(pk_bytes.clone()));
        if let Some(desc) = &config.description {
            register =
                register.add_typed_default(DataType::Description, DataValue::Str(desc.clone()));
        }
        if let Err(e) = sender.send(&register).await {
            sender.close();
            return Err(e);
        }

        // 2. Receive and verify the host's challenge (register binds id = 0).
        let server_challenge = match receive_verified_challenge(
            &receiver,
            &tm,
            host_public_key_bundle,
            0,
            "auth_register challenge",
        )
        .await
        {
            Ok(c) => c,
            Err(e) => {
                sender.close();
                return Err(e);
            }
        };

        // 3. Sign the host's challenge over the bundle and send the proof.
        let client_nonce: u128 = rand::random();
        let proof_payload =
            auth::register_proof_payload(&version_str, &pk_bytes, server_challenge, client_nonce);

        let proof = match signed_challenge_response(keys, &proof_payload, client_nonce) {
            Ok(p) => p,
            Err(e) => {
                sender.close();
                return Err(e);
            }
        };
        if let Err(e) = sender.send(&proof).await {
            sender.close();
            return Err(e);
        }

        // 4. Receive the host's final confirmation; extract the assigned id and
        //    verify the host signature binds to it.
        let response = match receiver.receive().await {
            Ok(r) => r,
            Err(e) => {
                sender.close();
                return Err(e);
            }
        };
        let expected_type = mtp_codec::CommunicationType::RegisterResponse.to_id(&tm);
        if response.get_type() != expected_type {
            sender.close();
            return Err(unexpected_response_type_error(
                "auth_register",
                expected_type,
                &response,
            ));
        }
        if let Err(e) = check_connected(&response, "Server rejected registration") {
            sender.close();
            return Err(e);
        }
        let assigned_id = match response.get_data(DataType::Id) {
            DataValue::UnsignedNumber(n) => *n as u64,
            _ => {
                sender.close();
                return Err(CommunicationError::AuthenticationFailed(
                    "Missing assigned ID".into(),
                ));
            }
        };
        if let Err(e) = verify_host_final(
            &response,
            host_public_key_bundle,
            assigned_id,
            client_nonce,
            server_challenge,
        ) {
            sender.close();
            return Err(e);
        }

        Ok(MTPConnection {
            version: PROTOCOL_VERSION,
            sender,
            receiver,
            description: config.description,
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
        let config = ClientConfig::new("https://example.com:4433");
        assert_eq!(config.url, "https://example.com:4433");
        assert_eq!(config.tls, ClientTlsConfig::SystemRoots);
    }

    #[test]
    fn test_client_config_with_cert() {
        let config = ClientConfig::new("https://localhost:4433")
            .with_pinned_pem(vec![0x01, 0x02, 0x03])
            .with_client_id(42);
        assert_eq!(
            config.tls,
            ClientTlsConfig::PinnedPem(vec![0x01, 0x02, 0x03])
        );
        assert_eq!(config.client_id, 42);
    }

    #[cfg(feature = "crypto")]
    #[test]
    fn test_auth_state_unauthenticated_is_not_authenticated() {
        assert_ne!(AuthState::Unauthenticated, AuthState::Authenticated);
        assert_ne!(AuthState::Pending, AuthState::Authenticated);
    }

    #[cfg(feature = "crypto")]
    #[test]
    fn test_auth_timeout_default() {
        let config = ClientConfig::new("https://localhost:4433");
        assert_eq!(config.auth_timeout, Duration::from_secs(30));
    }

    #[cfg(feature = "crypto")]
    #[test]
    fn test_auth_timeout_custom() {
        let config =
            ClientConfig::new("https://localhost:4433").with_auth_timeout(Duration::from_secs(10));
        assert_eq!(config.auth_timeout, Duration::from_secs(10));
    }
}
