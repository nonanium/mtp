use mtp_codec::{
    CommunicationValue, DataType, DataValue, TypeMap, Version,
    registry::{Registry, VersionedCodec},
};
use mtp_common::CommunicationError;
use mtp_transport::{Policy, Receiver, Sender};
use std::net::IpAddr;

/* Host configuration. */
pub struct HostConfig {
    pub ip: IpAddr,
    pub port: u16,
    pub tls_fullchain: Vec<u8>,
    pub tls_key: Vec<u8>,

    #[cfg(feature = "crypto")]
    pub require_authentication: bool,
    #[cfg(feature = "crypto")]
    pub host_id: u64,
    #[cfg(feature = "crypto")]
    pub host_keyring: mtp_crypto::Keyring,
    #[cfg(feature = "crypto")]
    pub get_existing_user: Box<dyn Fn(u64) -> Option<mtp_crypto::PublicKeyBundle> + Send>,
    #[cfg(feature = "crypto")]
    pub complete_register: Box<dyn Fn(mtp_crypto::PublicKeyBundle) -> u64 + Send>,
}

#[cfg(feature = "crypto")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthState {
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
            Policy::default(),
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
     * Returns `None` if the connection is closed or the version is
     * incompatible.
     */
    pub async fn accept(&mut self) -> Option<MTPConnection> {
        let (sender, receiver) = self.transport.next().await?;

        #[cfg(feature = "crypto")]
        if self.config.require_authentication {
            return self.accept_authenticated(sender, receiver).await;
        }

        // Read the first message (always encoded with reserved types).
        let first_msg = receiver.receive().await.ok()?;

        /*
         * Extract the client's version from the first message.
         * The client is expected to send DataType::Version (reserved ID 3)
         * as a DataValue::Str("X.Y").
         *
         * Then negotiate the version for single-version clients
         */
        let client_version = extract_version(&first_msg)?;

        let negotiated = self.registry.negotiate(&[client_version])?;

        let codec = VersionedCodec::new(self.registry.clone());

        Some(MTPConnection {
            version: negotiated,
            codec,
            sender,
            receiver,
            #[cfg(feature = "crypto")]
            auth_state: AuthState::Authenticated,
            #[cfg(feature = "crypto")]
            client_id: 0,
            #[cfg(feature = "crypto")]
            client_public_key: None,
        })
    }

    pub fn local_addr(&self) -> std::net::SocketAddr {
        self.transport.local_addr()
    }

    pub fn registry(&self) -> &Registry {
        &self.registry
    }
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
    ) -> Option<MTPConnection> {
        use mtp_crypto::{
            Ed25519Signer, MlDsaSigner, PublicKeyBundle, SignatureScheme, auth, verify_ed25519,
            verify_ml_dsa,
        };

        // Flow-specific state resolved from the client's opening hello.
        enum Flow {
            Login {
                id: u64,
                bundle: PublicKeyBundle,
            },
            Register {
                bundle: PublicKeyBundle,
                pk_bytes: Vec<u8>,
            },
        }

        let tm = TypeMap::latest();
        let pq_enabled = !self
            .config
            .host_keyring
            .sig_pq_secret_key
            .as_bytes()
            .is_empty();

        // Sign `payload` with the host keys (Ed25519 always, ML-DSA when configured).
        let host_sign = |payload: &[u8]| -> Option<(Vec<u8>, Vec<u8>)> {
            let signer = Ed25519Signer::new(&self.config.host_keyring.sig_cl_secret_key).ok()?;
            let sig = signer.sign(payload).ok()?;
            let pq_sig = if pq_enabled {
                let pq = MlDsaSigner::new(
                    &self.config.host_keyring.sig_pq_secret_key,
                    &self.config.host_keyring.sig_pq_public_key,
                )
                .ok()?;
                pq.sign(payload).ok()?
            } else {
                Vec::new()
            };
            Some((sig, pq_sig))
        };

        // ===== Step 1: receive the client's unsigned hello =====
        let hello = receiver.receive().await.ok()?;
        let version_str = match hello.get_data(DataType::Version.to_id(&tm)) {
            DataValue::Str(s) => s.clone(),
            _ => {
                sender.close();
                return None;
            }
        };
        let client_version = Version::parse(&version_str)?;

        let (flow, response_type) =
            if hello.get_type() == mtp_codec::CommunicationType::Identification.to_id(&tm) {
                // LOGIN: look up the claimed user before issuing a challenge.
                let cid = match hello.get_data(DataType::Id.to_id(&tm)) {
                    DataValue::UnsignedNumber(n) => *n as u64,
                    _ => {
                        sender.close();
                        return None;
                    }
                };
                let bundle = match (self.config.get_existing_user)(cid) {
                    Some(b) => b,
                    None => {
                        let rejection = CommunicationValue::new(
                            mtp_codec::CommunicationType::IdentificationResponse,
                        )
                        .add_typed_default(DataType::Connected, DataValue::BoolFalse);
                        let _ = sender.send(&rejection).await;
                        sender.close();
                        return None;
                    }
                };
                (
                    Flow::Login { id: cid, bundle },
                    mtp_codec::CommunicationType::IdentificationResponse,
                )
            } else if hello.get_type() == mtp_codec::CommunicationType::Register.to_id(&tm) {
                // REGISTER: the client presents the bundle it wants to register.
                let bundle = match hello.get_data(DataType::PublicKeys.to_id(&tm)) {
                    DataValue::Bytes(b) => PublicKeyBundle::from_bytes(b).ok()?,
                    _ => {
                        sender.close();
                        return None;
                    }
                };
                let pk_bytes = bundle.as_bytes();
                (
                    Flow::Register { bundle, pk_bytes },
                    mtp_codec::CommunicationType::RegisterResponse,
                )
            } else {
                sender.close();
                return None;
            };

        // The id bound into the challenge (0 for register: none assigned yet).
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
        sender.send(&challenge_msg).await.ok()?;

        // ===== Step 3: receive and verify the client's proof =====
        let proof = receiver.receive().await.ok()?;
        if proof.get_type() != mtp_codec::CommunicationType::ChallengeResponse.to_id(&tm) {
            sender.close();
            return None;
        }
        let client_nonce = match proof.get_data(DataType::ClientNonce.to_id(&tm)) {
            DataValue::UnsignedNumber(n) => *n,
            _ => {
                sender.close();
                return None;
            }
        };
        let sig_bytes = match proof.get_data(DataType::Signature.to_id(&tm)) {
            DataValue::Bytes(b) => b.clone(),
            _ => {
                sender.close();
                return None;
            }
        };
        let pq_sig_bytes: Vec<u8> = match proof.get_data(DataType::PqSignature.to_id(&tm)) {
            DataValue::Bytes(b) => b.clone(),
            _ => vec![],
        };

        let (proof_payload, bundle) = match &flow {
            Flow::Login { id, bundle } => (
                auth::login_proof_payload(&version_str, *id, server_challenge, client_nonce),
                bundle,
            ),
            Flow::Register {
                bundle, pk_bytes, ..
            } => (
                auth::register_proof_payload(
                    &version_str,
                    pk_bytes,
                    server_challenge,
                    client_nonce,
                ),
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
            return None;
        }

        // Proof verified: resolve the assigned id and retain the client's bundle.
        let (assigned_id, client_bundle) = match flow {
            Flow::Login { id, bundle } => (id, bundle),
            Flow::Register { bundle, .. } => {
                let new_id = (self.config.complete_register)(bundle.clone());
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

        sender.send(&response).await.ok()?;
        sender.finish_stream().await.ok()?;

        // ===== Version negotiation =====
        let negotiated = self.registry.negotiate(&[client_version])?;
        let codec = VersionedCodec::new(self.registry.clone());

        Some(MTPConnection {
            version: negotiated,
            codec,
            sender,
            receiver,
            auth_state: AuthState::Authenticated,
            client_id: assigned_id,
            client_public_key: Some(client_bundle),
        })
    }
}

/*
 * Extract the protocol version from an initial `CommunicationValue`.
 *
 * The client's first message must contain a `Version` data entry
 * (reserved ID 3) mapping to `DataValue::Str("major.minor")`.
 */
fn extract_version(msg: &CommunicationValue) -> Option<Version> {
    let tm = TypeMap::latest();
    let value = msg.get_data(DataType::Version.to_id(&tm));
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
}
