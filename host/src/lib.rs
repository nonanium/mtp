#[cfg(feature = "crypto")]
use mtp_codec::DataType;
use mtp_codec::{
    CommunicationValue, DataTypeId, DataValue, Version,
    registry::{Registry, VersionedCodec},
};
use mtp_common::CommunicationError;
use mtp_transport::{Policy, Receiver, Sender};
use std::net::IpAddr;

// Host configuration.
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

// A connection that has completed version negotiation.
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

// High-level MTP host with built-in version negotiation.
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
    async fn accept_authenticated(
        &mut self,
        sender: Sender,
        receiver: Receiver,
    ) -> Option<MTPConnection> {
        use mtp_crypto::{
            Ed25519Signer, PublicKeyBundle, SignatureScheme, verify_ed25519, verify_ml_dsa,
        };

        // 1. Receive client message first (no host greeting)
        let msg = receiver.receive().await.ok()?;
        let version_str = match msg.get_data(DataTypeId(3)) {
            DataValue::Str(s) => s.clone(),
            _ => {
                sender.close();
                return None;
            }
        };

        let client_version = Version::parse(&version_str)?;

        let client_nonce = match msg.get_data(DataTypeId(7)) {
            DataValue::UnsignedNumber(n) => *n,
            _ => {
                sender.close();
                return None;
            }
        };

        let sig_bytes = match msg.get_data(DataTypeId(10)) {
            DataValue::Bytes(b) => b.clone(),
            _ => {
                sender.close();
                return None;
            }
        };

        let pq_sig_bytes: Vec<u8> = match msg.get_data(DataTypeId(12)) {
            DataValue::Bytes(b) => b.clone(),
            _ => vec![],
        };

        let (assigned_id, client_bundle, response_type) = if msg.get_type()
            == mtp_codec::CommunicationTypeId(15)
        {
            // LOGIN
            let cid = match msg.get_data(DataTypeId(6)) {
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
                    .add_typed_default(DataType::Connected, DataValue::BoolFalse)
                    .add_typed_default(
                        DataType::ClientNonce,
                        DataValue::UnsignedNumber(client_nonce),
                    );
                    let _ = sender.send(&rejection).await;
                    sender.close();
                    return None;
                }
            };

            let mut sig_payload = Vec::new();
            sig_payload.extend_from_slice(version_str.as_bytes());
            sig_payload.extend_from_slice(&cid.to_be_bytes());
            sig_payload.extend_from_slice(&client_nonce.to_be_bytes());

            /* ===== Signature ===== */
            if verify_ed25519(&bundle.sig_cl_public_key, &sig_payload, &sig_bytes).is_err() {
                let rejection =
                    CommunicationValue::new(mtp_codec::CommunicationType::IdentificationResponse)
                        .add_typed_default(DataType::Connected, DataValue::BoolFalse)
                        .add_typed_default(
                            DataType::ClientNonce,
                            DataValue::UnsignedNumber(client_nonce),
                        );
                let _ = sender.send(&rejection).await;
                sender.close();
                return None;
            }
            if !pq_sig_bytes.is_empty()
                && verify_ml_dsa(&bundle.sig_pq_public_key, &sig_payload, &pq_sig_bytes).is_err()
            {
                let rejection =
                    CommunicationValue::new(mtp_codec::CommunicationType::IdentificationResponse)
                        .add_typed_default(DataType::Connected, DataValue::BoolFalse)
                        .add_typed_default(
                            DataType::ClientNonce,
                            DataValue::UnsignedNumber(client_nonce),
                        );
                let _ = sender.send(&rejection).await;
                sender.close();
                return None;
            }
            /* ===== End Signature ===== */

            (
                cid,
                bundle,
                mtp_codec::CommunicationType::IdentificationResponse,
            )
        } else if msg.get_type() == mtp_codec::CommunicationTypeId(17) {
            // REGISTER
            let bundle = match msg.get_data(DataTypeId(9)) {
                DataValue::Bytes(b) => PublicKeyBundle::from_bytes(b).ok()?,
                _ => {
                    sender.close();
                    return None;
                }
            };
            let pk_bytes = bundle.as_bytes();

            let mut sig_payload = Vec::new();
            sig_payload.extend_from_slice(version_str.as_bytes());
            sig_payload.extend_from_slice(&client_nonce.to_be_bytes());
            sig_payload.extend_from_slice(&pk_bytes);

            /* ===== Signature ===== */
            if verify_ed25519(&bundle.sig_cl_public_key, &sig_payload, &sig_bytes).is_err() {
                let rejection =
                    CommunicationValue::new(mtp_codec::CommunicationType::RegisterResponse)
                        .add_typed_default(DataType::Connected, DataValue::BoolFalse)
                        .add_typed_default(
                            DataType::ClientNonce,
                            DataValue::UnsignedNumber(client_nonce),
                        );
                let _ = sender.send(&rejection).await;
                sender.close();
                return None;
            }
            if !pq_sig_bytes.is_empty()
                && verify_ml_dsa(&bundle.sig_pq_public_key, &sig_payload, &pq_sig_bytes).is_err()
            {
                let rejection =
                    CommunicationValue::new(mtp_codec::CommunicationType::RegisterResponse)
                        .add_typed_default(DataType::Connected, DataValue::BoolFalse)
                        .add_typed_default(
                            DataType::ClientNonce,
                            DataValue::UnsignedNumber(client_nonce),
                        );
                let _ = sender.send(&rejection).await;
                sender.close();
                return None;
            }
            /* ===== End Signature ===== */

            let new_id = (self.config.complete_register)(bundle.clone());
            (
                new_id,
                bundle,
                mtp_codec::CommunicationType::RegisterResponse,
            )
        } else {
            sender.close();
            return None;
        };

        // 2. Send success response (single host message)
        let new_nonce: u128 = rand::random();

        let mut host_sig_payload = Vec::new();
        host_sig_payload.push(0x01);
        host_sig_payload.extend_from_slice(&assigned_id.to_be_bytes());
        host_sig_payload.extend_from_slice(&client_nonce.to_be_bytes());
        host_sig_payload.extend_from_slice(&new_nonce.to_be_bytes());

        let host_signer = Ed25519Signer::new(&self.config.host_keyring.sig_cl_secret_key).ok()?;

        /* ===== Signature ===== */
        let host_sig = host_signer.sign(&host_sig_payload).ok()?;

        let mut response = CommunicationValue::new(response_type)
            .add_typed_default(DataType::Connected, DataValue::BoolTrue)
            .add_typed_default(
                DataType::ClientNonce,
                DataValue::UnsignedNumber(client_nonce),
            )
            .add_typed_default(DataType::Timestamp, DataValue::UnsignedNumber(new_nonce))
            .add_typed_default(DataType::Signature, DataValue::Bytes(host_sig))
            .add_typed_default(DataType::Id, DataValue::UnsignedNumber(assigned_id as u128));

        if !self
            .config
            .host_keyring
            .sig_pq_secret_key
            .as_bytes()
            .is_empty()
        {
            use mtp_crypto::MlDsaSigner;
            let host_pq_signer = MlDsaSigner::new(
                &self.config.host_keyring.sig_pq_secret_key,
                &self.config.host_keyring.sig_pq_public_key,
            )
            .ok()?;
            let host_pq_sig = host_pq_signer.sign(&host_sig_payload).ok()?;
            response =
                response.add_typed_default(DataType::PqSignature, DataValue::Bytes(host_pq_sig));
        }
        /* ===== End Signature ===== */

        sender.send(&response).await.ok()?;
        sender.finish_stream().await.ok()?;

        // 3. Version negotiation
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
    let value = msg.get_data(DataTypeId(3));
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
        .add_data(DataTypeId(3), DataValue::Str("2.0".to_string()));
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
        .add_data(DataTypeId(3), DataValue::UnsignedNumber(42));
        assert!(extract_version(&msg).is_none());
    }
}
