use mtp_codec::{
    CommunicationValue, DataType, DataValue, Version,
    registry::{Registry, VersionedCodec},
};
use mtp_common::CommunicationError;
use std::net::IpAddr;
#[cfg(feature = "crypto")]
use std::pin::Pin;
use std::{error::Error, fmt};
#[cfg(feature = "crypto")]
use tokio::time::Duration;

pub use MTPConnection as Connection;
pub use MTPHost as Host;
pub use mtp_transport::Policy;
pub use mtp_transport::Receiver;
pub use mtp_transport::SendMode;
pub use mtp_transport::Sender;

/* ---- async callback type aliases ---- */
#[cfg(feature = "crypto")]
pub type GetExistingClient = Box<
    dyn Fn(
            u64,
            Option<String>,
        )
            -> Pin<Box<dyn std::future::Future<Output = Option<mtp_crypto::PublicKeyBundle>> + Send>>
        + Send
        + Sync,
>;

#[cfg(feature = "crypto")]
pub type CompleteRegister = Box<
    dyn Fn(
            mtp_crypto::PublicKeyBundle,
            Option<String>,
        ) -> Pin<Box<dyn std::future::Future<Output = u64> + Send>>
        + Send
        + Sync,
>;

#[cfg(feature = "crypto")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthenticationPolicy {
    ForceAuthentication,
    AllowAuthentication,
    Unauthenticated,
}

/* Host configuration. */
pub struct HostConfig {
    pub ip: IpAddr,
    pub port: u16,
    pub tls_fullchain: Vec<u8>,
    pub tls_key: Vec<u8>,

    pub policy: Policy,

    #[cfg(feature = "crypto")]
    pub authentication_policy: AuthenticationPolicy,
    #[cfg(feature = "crypto")]
    pub auth_timeout: Duration,
    #[cfg(feature = "crypto")]
    pub host_keyring: mtp_crypto::Keyring,
    #[cfg(feature = "crypto")]
    pub get_existing_client: GetExistingClient,
    #[cfg(feature = "crypto")]
    pub complete_register: CompleteRegister,
}

impl HostConfig {
    pub fn new(ip: IpAddr, port: u16, tls_fullchain: Vec<u8>, tls_key: Vec<u8>) -> Self {
        Self {
            ip,
            port,
            tls_fullchain,
            tls_key,
            policy: Policy::default(),
            #[cfg(feature = "crypto")]
            authentication_policy: AuthenticationPolicy::Unauthenticated,
            #[cfg(feature = "crypto")]
            auth_timeout: Duration::from_secs(30),
            #[cfg(feature = "crypto")]
            host_keyring: mtp_crypto::Keyring::new(
                mtp_crypto::KemPublicKey::new(Vec::new()),
                mtp_crypto::KemPrivateKey::new(Vec::new()),
                mtp_crypto::SignaturePqPublicKey::new(Vec::new()),
                mtp_crypto::SignaturePqPrivateKey::new(Vec::new()),
                mtp_crypto::SignaturePublicKey::new(Vec::new()),
                mtp_crypto::SignaturePrivateKey::new(Vec::new()),
            ),
            #[cfg(feature = "crypto")]
            get_existing_client: Box::new(|_, _| Box::pin(async { None })),
            #[cfg(feature = "crypto")]
            complete_register: Box::new(|_, _| Box::pin(async { 0 })),
        }
    }

    pub fn with_policy(mut self, policy: Policy) -> Self {
        self.policy = policy;
        self
    }

    #[cfg(feature = "crypto")]
    pub fn with_authentication(
        mut self,
        host_keyring: mtp_crypto::Keyring,
        get_existing_client: GetExistingClient,
        complete_register: CompleteRegister,
    ) -> Self {
        self.authentication_policy = AuthenticationPolicy::ForceAuthentication;
        self.host_keyring = host_keyring;
        self.get_existing_client = Box::new(get_existing_client);
        self.complete_register = Box::new(complete_register);
        self
    }

    #[cfg(feature = "crypto")]
    pub fn with_authentication_policy(mut self, policy: AuthenticationPolicy) -> Self {
        self.authentication_policy = policy;
        self
    }

    #[cfg(feature = "crypto")]
    pub fn with_auth_timeout(mut self, timeout: Duration) -> Self {
        self.auth_timeout = timeout;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcceptError {
    Receive(CommunicationError),
    MissingVersion,
    UnsupportedVersion(Version),
    AuthenticationFailed(String),
    AuthenticationTimedOut,
    Send(CommunicationError),
}

impl fmt::Display for AcceptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Receive(error) => write!(f, "failed to receive opening message: {error}"),
            Self::MissingVersion => write!(
                f,
                "opening message did not include a valid protocol version"
            ),
            Self::UnsupportedVersion(version) => {
                write!(f, "unsupported protocol version: {version}")
            }
            Self::AuthenticationFailed(reason) => write!(f, "authentication failed: {reason}"),
            Self::AuthenticationTimedOut => write!(f, "authentication handshake timed out"),
            Self::Send(error) => write!(f, "failed to send handshake message: {error}"),
        }
    }
}

impl Error for AcceptError {}

#[cfg(feature = "crypto")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthState {
    Unauthenticated,
    Pending,
    Authenticated,
    Failed,
}

/* A connection that has completed version negotiation. */
pub struct MTPConnection {
    pub version: Version,
    pub codec: VersionedCodec,
    pub sender: Sender,
    pub receiver: Receiver,
    pub description: Option<String>,
    #[cfg(feature = "crypto")]
    pub auth_state: AuthState,
    #[cfg(feature = "crypto")]
    pub client_id: u64,
    #[cfg(feature = "crypto")]
    pub client_public_key: Option<mtp_crypto::PublicKeyBundle>,
}

/* High-level MTP host with built-in version negotiation. */
pub struct MTPHost {
    transport: mtp_transport::Host,
    registry: Registry,
    #[cfg(feature = "crypto")]
    config: HostConfig,
}

impl MTPHost {
    pub async fn new(config: HostConfig) -> Result<Self, CommunicationError> {
        let registry = Registry::builtin();

        let transport = mtp_transport::host(
            config.ip,
            config.port,
            config.tls_fullchain.clone(),
            config.tls_key.clone(),
            config.policy,
        )
        .await?;

        Ok(Self {
            transport,
            registry,
            #[cfg(feature = "crypto")]
            config,
        })
    }

    /*
     * Accept an incoming connection, negotiate the protocol version,
     * and return a ready-to-use `MTPConnection`.
     *
     * Returns `Ok(None)` if the listener is closed. Handshake and version
     * negotiation failures are returned explicitly.
     */
    pub async fn accept(&mut self) -> Result<Option<MTPConnection>, AcceptError> {
        let (sender, receiver) = match self.transport.next().await {
            Some(pair) => pair,
            None => return Ok(None),
        };

        #[cfg(feature = "crypto")]
        match self.config.authentication_policy {
            AuthenticationPolicy::ForceAuthentication => {
                let timeout = self.config.auth_timeout;
                return match tokio::time::timeout(
                    timeout,
                    self.accept_authenticated(sender, receiver),
                )
                .await
                {
                    Ok(result) => result,
                    Err(_) => Err(AcceptError::AuthenticationTimedOut),
                };
            }
            AuthenticationPolicy::AllowAuthentication => {
                return self.accept_allow_auth(sender, receiver).await;
            }
            AuthenticationPolicy::Unauthenticated => {
                let first_msg = match receiver.receive().await {
                    Ok(m) => m,
                    Err(e) => return Err(AcceptError::Receive(e)),
                };
                if first_msg.get_type()
                    == mtp_codec::CommunicationType::Register.to_id(&mtp_codec::TypeMap::latest())
                {
                    sender.close();
                    return Err(AcceptError::AuthenticationFailed(
                        "authentication not allowed on this host".into(),
                    ));
                }
                let client_version = match extract_version(&first_msg) {
                    Some(v) => v,
                    None => return Err(AcceptError::MissingVersion),
                };
                let negotiated = match self
                    .registry
                    .negotiate(std::slice::from_ref(&client_version))
                {
                    Some(v) => v,
                    None => return Err(AcceptError::UnsupportedVersion(client_version)),
                };
                let codec = VersionedCodec::new(self.registry.clone());
                let description = match first_msg.get_data(DataType::Description) {
                    DataValue::Str(s) => Some(s.clone()),
                    _ => None,
                };
                Ok(Some(MTPConnection {
                    version: negotiated,
                    codec,
                    sender,
                    receiver,
                    description,
                    #[cfg(feature = "crypto")]
                    auth_state: AuthState::Unauthenticated,
                    #[cfg(feature = "crypto")]
                    client_id: rand::random(),
                    #[cfg(feature = "crypto")]
                    client_public_key: None,
                }))
            }
        }

        // Non-crypto fallback: no authentication feature, just read and respond.
        #[cfg(not(feature = "crypto"))]
        {
            let first_msg = match receiver.receive().await {
                Ok(m) => m,
                Err(e) => return Err(AcceptError::Receive(e)),
            };
            let client_version = match extract_version(&first_msg) {
                Some(v) => v,
                None => return Err(AcceptError::MissingVersion),
            };
            let negotiated = match self
                .registry
                .negotiate(std::slice::from_ref(&client_version))
            {
                Some(v) => v,
                None => return Err(AcceptError::UnsupportedVersion(client_version)),
            };
            let codec = VersionedCodec::new(self.registry.clone());
            let description = match first_msg.get_data(DataType::Description) {
                DataValue::Str(s) => Some(s.clone()),
                _ => None,
            };
            return Ok(Some(MTPConnection {
                version: negotiated,
                codec,
                sender,
                receiver,
                description,
            }));
        }
    }

    pub fn local_addr(&self) -> std::net::SocketAddr {
        self.transport.local_addr()
    }

    pub fn registry(&self) -> &Registry {
        &self.registry
    }
}

#[cfg(feature = "crypto")]
enum Flow {
    Login {
        id: u64,
        bundle: mtp_crypto::PublicKeyBundle,
    },
    Register {
        bundle: mtp_crypto::PublicKeyBundle,
        pk_bytes: Vec<u8>,
    },
}

#[cfg(feature = "crypto")]
impl MTPHost {
    /*
     * Mutually-authenticated handshake with a server-issued challenge.
     *
     *   1. C -> H : Identification { version, id }   (or Register { version, public_keys })
     *   2. H -> C : Challenge { server_challenge, host_sig }
     *   3. C -> H : ChallengeResponse { client_nonce, sig }
     *   4. H -> C : IdentificationResponse / RegisterResponse { connected, id, sig }
     *
     * The client's authenticating signature (step 3) covers `server_challenge`,
     * a fresh value generated here in step 2 and kept on this task's stack for
     * the lifetime of the connection. It is therefore one-time per connection
     * with no shared replay state, and a captured proof cannot be replayed on
     * any other connection.
     */
    async fn accept_authenticated(
        &mut self,
        sender: Sender,
        receiver: Receiver,
    ) -> Result<Option<MTPConnection>, AcceptError> {
        use mtp_crypto::PublicKeyBundle;

        let tm = mtp_codec::TypeMap::latest();

        // ===== Step 1: receive the client's unsigned hello =====
        let hello = match receiver.receive().await {
            Ok(m) => m,
            Err(e) => {
                sender.close();
                return Err(AcceptError::Receive(e));
            }
        };
        let version_str = match hello.get_data(DataType::Version) {
            DataValue::Str(s) => s.clone(),
            _ => {
                sender.close();
                return Err(AcceptError::MissingVersion);
            }
        };
        let client_version = match Version::parse(&version_str) {
            Some(v) => v,
            None => {
                sender.close();
                return Err(AcceptError::MissingVersion);
            }
        };

        let description = match hello.get_data(DataType::Description) {
            DataValue::Str(s) => Some(s.clone()),
            _ => None,
        };

        let (flow, response_type) = if hello.get_type()
            == mtp_codec::CommunicationType::Identification.to_id(&tm)
        {
            let cid = match hello.get_data(DataType::Id) {
                DataValue::UnsignedNumber(n) => *n as u64,
                _ => {
                    sender.close();
                    return Err(AcceptError::AuthenticationFailed(
                        "missing client id".into(),
                    ));
                }
            };
            let bundle = match (self.config.get_existing_client)(cid, description.clone()).await {
                Some(b) => b,
                None => {
                    let rejection = CommunicationValue::new(
                        mtp_codec::CommunicationType::IdentificationResponse,
                    )
                    .add_typed_default(DataType::Connected, DataValue::BoolFalse);
                    let _ = sender.send(&rejection).await;
                    sender.close();
                    return Err(AcceptError::AuthenticationFailed(
                        "unknown client id".into(),
                    ));
                }
            };
            (
                Flow::Login { id: cid, bundle },
                mtp_codec::CommunicationType::IdentificationResponse,
            )
        } else if hello.get_type() == mtp_codec::CommunicationType::Register.to_id(&tm) {
            let bundle = match hello.get_data(DataType::PublicKeys) {
                DataValue::Bytes(b) => PublicKeyBundle::from_bytes(b).map_err(|_| {
                    AcceptError::AuthenticationFailed("invalid public key bundle".into())
                })?,
                _ => {
                    sender.close();
                    return Err(AcceptError::AuthenticationFailed(
                        "missing public keys".into(),
                    ));
                }
            };
            let pk_bytes = bundle.as_bytes();
            (
                Flow::Register { bundle, pk_bytes },
                mtp_codec::CommunicationType::RegisterResponse,
            )
        } else {
            sender.close();
            return Err(AcceptError::AuthenticationFailed(
                "unexpected authentication message".into(),
            ));
        };

        self.complete_auth_handshake(
            sender,
            receiver,
            flow,
            response_type,
            &version_str,
            client_version,
            description,
        )
        .await
    }

    /*
     * Steps 2-4 of the authenticated handshake, shared by both ForceAuthentication
     * and AllowAuthentication. Takes the already-parsed hello (step 1) via `flow`,
     * `version_str`, and `client_version`.
     */
    #[allow(clippy::too_many_arguments)]
    async fn complete_auth_handshake(
        &self,
        sender: Sender,
        receiver: Receiver,
        flow: Flow,
        response_type: mtp_codec::CommunicationType,
        version_str: &str,
        client_version: Version,
        description: Option<String>,
    ) -> Result<Option<MTPConnection>, AcceptError> {
        use mtp_crypto::{
            Ed25519Signer, MlDsaSigner, SignatureScheme, auth, verify_ed25519, verify_ml_dsa,
        };

        let tm = mtp_codec::TypeMap::latest();
        let pq_enabled = !self
            .config
            .host_keyring
            .sig_pq_secret_key
            .as_bytes()
            .is_empty();

        let host_sign = |payload: &[u8]| -> Result<(Vec<u8>, Vec<u8>), AcceptError> {
            let signer = Ed25519Signer::new(&self.config.host_keyring.sig_cl_secret_key)
                .map_err(|e| AcceptError::AuthenticationFailed(e.to_string()))?;
            let sig = signer
                .sign(payload)
                .map_err(|e| AcceptError::AuthenticationFailed(e.to_string()))?;
            let pq_sig = if pq_enabled {
                let pq = MlDsaSigner::new(
                    &self.config.host_keyring.sig_pq_secret_key,
                    &self.config.host_keyring.sig_pq_public_key,
                )
                .map_err(|e| AcceptError::AuthenticationFailed(e.to_string()))?;
                pq.sign(payload)
                    .map_err(|e| AcceptError::AuthenticationFailed(e.to_string()))?
            } else {
                Vec::new()
            };
            Ok((sig, pq_sig))
        };

        let challenge_id = match &flow {
            Flow::Login { id, .. } => *id,
            Flow::Register { .. } => 0,
        };

        // ===== Step 2: issue a fresh, host-signed challenge =====
        let server_challenge: u128 = rand::random();
        let (chal_sig, chal_pq_sig) =
            host_sign(&auth::challenge_payload(challenge_id, server_challenge))?;

        let mut challenge_msg = CommunicationValue::new(mtp_codec::CommunicationType::Challenge)
            .add_typed_default(
                DataType::ServerNonce,
                DataValue::UnsignedNumber(server_challenge),
            )
            .add_typed_default(DataType::Signature, DataValue::Bytes(chal_sig));
        if pq_enabled {
            challenge_msg = challenge_msg
                .add_typed_default(DataType::PqSignature, DataValue::Bytes(chal_pq_sig));
        }
        if let Err(e) = sender.send(&challenge_msg).await {
            sender.close();
            return Err(AcceptError::Send(e));
        }

        // ===== Step 3: receive and verify the client's proof =====
        let proof = match receiver.receive().await {
            Ok(m) => m,
            Err(e) => {
                sender.close();
                return Err(AcceptError::Receive(e));
            }
        };
        if proof.get_type() != mtp_codec::CommunicationType::ChallengeResponse.to_id(&tm) {
            sender.close();
            return Err(AcceptError::AuthenticationFailed(
                "missing challenge response".into(),
            ));
        }
        let client_nonce = match proof.get_data(DataType::ClientNonce) {
            DataValue::UnsignedNumber(n) => *n,
            _ => {
                sender.close();
                return Err(AcceptError::AuthenticationFailed(
                    "missing client nonce".into(),
                ));
            }
        };
        let sig_bytes = match proof.get_data(DataType::Signature) {
            DataValue::Bytes(b) => b.clone(),
            _ => {
                sender.close();
                return Err(AcceptError::AuthenticationFailed(
                    "missing challenge signature".into(),
                ));
            }
        };
        let pq_sig_bytes: Vec<u8> = match proof.get_data(DataType::PqSignature) {
            DataValue::Bytes(b) => b.clone(),
            _ => vec![],
        };

        let (proof_payload, bundle) = match &flow {
            Flow::Login { id, bundle } => (
                auth::login_proof_payload(version_str, *id, server_challenge, client_nonce),
                bundle,
            ),
            Flow::Register {
                bundle, pk_bytes, ..
            } => (
                auth::register_proof_payload(version_str, pk_bytes, server_challenge, client_nonce),
                bundle,
            ),
        };

        let proof_ok = verify_ed25519(&bundle.sig_cl_public_key, &proof_payload, &sig_bytes)
            .is_ok()
            && (pq_sig_bytes.is_empty()
                || verify_ml_dsa(&bundle.sig_pq_public_key, &proof_payload, &pq_sig_bytes).is_ok());

        if !proof_ok {
            let rejection = CommunicationValue::new(response_type)
                .add_typed_default(DataType::Connected, DataValue::BoolFalse);
            let _ = sender.send(&rejection).await;
            sender.close();
            return Err(AcceptError::AuthenticationFailed(
                "client proof signature invalid".into(),
            ));
        }

        // Proof verified: resolve the assigned id and retain the client's bundle.
        let (assigned_id, client_bundle) = match flow {
            Flow::Login { id, bundle } => (id, bundle),
            Flow::Register { bundle, .. } => {
                let new_id =
                    (self.config.complete_register)(bundle.clone(), description.clone()).await;
                (new_id, bundle)
            }
        };

        // ===== Step 4: send the host's final confirmation =====
        let (host_sig, host_pq_sig) = host_sign(&auth::host_final_payload(
            assigned_id,
            client_nonce,
            server_challenge,
        ))?;

        let mut response = CommunicationValue::new(response_type)
            .add_typed_default(DataType::Connected, DataValue::BoolTrue)
            .add_typed_default(DataType::Id, DataValue::UnsignedNumber(assigned_id as u128))
            .add_typed_default(
                DataType::ClientNonce,
                DataValue::UnsignedNumber(client_nonce),
            )
            .add_typed_default(DataType::Signature, DataValue::Bytes(host_sig));
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

        // ===== Version negotiation =====
        let negotiated = match self
            .registry
            .negotiate(std::slice::from_ref(&client_version))
        {
            Some(v) => v,
            None => {
                sender.close();
                return Err(AcceptError::UnsupportedVersion(client_version));
            }
        };
        let codec = VersionedCodec::new(self.registry.clone());

        Ok(Some(MTPConnection {
            version: negotiated,
            codec,
            sender,
            receiver,
            description,
            auth_state: AuthState::Authenticated,
            client_id: assigned_id,
            client_public_key: Some(client_bundle),
        }))
    }

    /*
     * Allow-authentication accept: clients may connect with or without
     * authentication.  Register messages always trigger the auth handshake.
     * Identification with a known client-id triggers login; otherwise the
     * client is treated as unauthenticated with a random id.
     */
    async fn accept_allow_auth(
        &mut self,
        sender: Sender,
        receiver: Receiver,
    ) -> Result<Option<MTPConnection>, AcceptError> {
        use mtp_crypto::PublicKeyBundle;

        let tm = mtp_codec::TypeMap::latest();

        let hello = match receiver.receive().await {
            Ok(m) => m,
            Err(e) => return Err(AcceptError::Receive(e)),
        };

        let version_str = match hello.get_data(DataType::Version) {
            DataValue::Str(s) => s.clone(),
            _ => {
                sender.close();
                return Err(AcceptError::MissingVersion);
            }
        };
        let client_version = match Version::parse(&version_str) {
            Some(v) => v,
            None => {
                sender.close();
                return Err(AcceptError::MissingVersion);
            }
        };

        let description = match hello.get_data(DataType::Description) {
            DataValue::Str(s) => Some(s.clone()),
            _ => None,
        };

        // Register → authenticated registration.
        if hello.get_type() == mtp_codec::CommunicationType::Register.to_id(&tm) {
            let bundle = match hello.get_data(DataType::PublicKeys) {
                DataValue::Bytes(b) => PublicKeyBundle::from_bytes(b).map_err(|_| {
                    sender.close();
                    AcceptError::AuthenticationFailed("invalid public key bundle".into())
                })?,
                _ => {
                    sender.close();
                    return Err(AcceptError::AuthenticationFailed(
                        "missing public keys".into(),
                    ));
                }
            };
            let pk_bytes = bundle.as_bytes();
            return self
                .complete_auth_handshake(
                    sender,
                    receiver,
                    Flow::Register { bundle, pk_bytes },
                    mtp_codec::CommunicationType::RegisterResponse,
                    &version_str,
                    client_version,
                    description,
                )
                .await;
        }

        // Identification with a known client-id → login.
        if hello.get_type() == mtp_codec::CommunicationType::Identification.to_id(&tm) {
            let cid = match hello.get_data(DataType::Id) {
                DataValue::UnsignedNumber(n) => *n as u64,
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
                        mtp_codec::CommunicationType::IdentificationResponse,
                        &version_str,
                        client_version,
                        description,
                    )
                    .await;
            }

            // Unknown (or zero) client id → unauthenticated connection.
            let negotiated = match self
                .registry
                .negotiate(std::slice::from_ref(&client_version))
            {
                Some(v) => v,
                None => return Err(AcceptError::UnsupportedVersion(client_version)),
            };
            let codec = VersionedCodec::new(self.registry.clone());
            return Ok(Some(MTPConnection {
                version: negotiated,
                codec,
                sender,
                receiver,
                description,
                auth_state: AuthState::Unauthenticated,
                client_id: rand::random(),
                client_public_key: None,
            }));
        }

        sender.close();
        Err(AcceptError::AuthenticationFailed(
            "unexpected message type".into(),
        ))
    }
}

/*
 * Extract the protocol version from an initial `CommunicationValue`.
 *
 * The client's first message must contain a `Version` data entry
 * (reserved ID 3) mapping to `DataValue::Str("major.minor")`.
 */
fn extract_version(msg: &CommunicationValue) -> Option<Version> {
    let value = msg.get_data(DataType::Version);
    match value {
        DataValue::Str(s) => Version::parse(s.as_str()),
        _ => None,
    }
}

/* ================================ TESTS ================================ */
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_extraction() {
        let tm = mtp_codec::TypeMap::latest();
        let msg = mtp_codec::CommunicationValue::from_comm(
            mtp_codec::CommunicationType::Identification,
            &tm,
        )
        .add_data(
            DataType::Version.to_id(&tm),
            DataValue::Str("2.0".to_string()),
        );
        let version = extract_version(&msg);
        assert_eq!(version, Some(Version(2, 0)));
    }

    #[test]
    fn version_extraction_returns_none_for_missing() {
        let tm = mtp_codec::TypeMap::latest();
        let msg = mtp_codec::CommunicationValue::from_comm(
            mtp_codec::CommunicationType::Identification,
            &tm,
        );
        assert!(extract_version(&msg).is_none());
    }

    #[test]
    fn version_extraction_bad_format() {
        let tm = mtp_codec::TypeMap::latest();
        let msg = mtp_codec::CommunicationValue::from_comm(
            mtp_codec::CommunicationType::Identification,
            &tm,
        )
        .add_data(DataType::Version.to_id(&tm), DataValue::UnsignedNumber(42));
        assert!(extract_version(&msg).is_none());
    }

    #[cfg(feature = "crypto")]
    #[test]
    fn auth_state_unauthenticated_is_not_authenticated() {
        assert_ne!(AuthState::Unauthenticated, AuthState::Authenticated);
        assert_ne!(AuthState::Pending, AuthState::Authenticated);
    }
}
