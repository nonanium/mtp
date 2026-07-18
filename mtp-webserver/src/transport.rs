use bytes::Bytes;
use mtp_codec::{
    DataType, DataValue, Version,
    registry::{Registry, VersionedCodec},
};
use mtp_common::CommunicationError;
use mtp_host::AcceptError;
use mtp_host::HostConfig;
use mtp_transport::{
    GenericReceiver, GenericSender, Policy, TransportConnection, TransportRecvStream,
    TransportSendStream,
};
use std::sync::Arc;
#[cfg(feature = "crypto")]
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::error;

type Session = h3_webtransport::server::WebTransportSession<h3_quinn::Connection, Bytes>;
type H3SendStream = h3_webtransport::stream::SendStream<h3_quinn::SendStream<Bytes>, Bytes>;
type H3RecvStream = h3_webtransport::stream::RecvStream<h3_quinn::RecvStream, Bytes>;

/// h3-webtransport implementation of MTP's transport connection boundary.
///
/// This is intentionally separate from [`WebMTPConnection`]: it is the
/// adapter used by the in-progress migration of `mtp_transport::Sender` and
/// `Receiver` away from concrete wtransport stream types.
#[derive(Clone)]
pub struct H3TransportConnection {
    session: Arc<Session>,
    quinn: quinn::Connection,
}

pub struct H3TransportSender {
    stream: H3SendStream,
}

pub struct H3TransportReceiver {
    stream: H3RecvStream,
}

impl H3TransportConnection {
    pub(crate) fn new(session: Arc<Session>, quinn: quinn::Connection) -> Self {
        Self { session, quinn }
    }
}

#[async_trait::async_trait]
impl TransportSendStream for H3TransportSender {
    async fn write_all(&mut self, buf: &[u8]) -> Result<(), CommunicationError> {
        self.stream
            .write_all(buf)
            .await
            .map_err(|_| CommunicationError::StreamError)?;
        // Control/authentication frames use a persistent stream. h3 keeps
        // those writes buffered until flushed; without this the peer can wait
        // for the challenge while the server waits for its proof.
        self.stream
            .flush()
            .await
            .map_err(|_| CommunicationError::StreamError)
    }

    async fn finish(&mut self) -> Result<(), CommunicationError> {
        self.stream
            .shutdown()
            .await
            .map_err(|_| CommunicationError::StreamError)
    }
}

#[async_trait::async_trait]
impl TransportRecvStream for H3TransportReceiver {
    async fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), CommunicationError> {
        self.stream
            .read_exact(buf)
            .await
            .map(|_| ())
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::UnexpectedEof {
                    // Browser control frames are sent on one-frame uni streams.
                    // Reaching FIN while looking for another frame is normal.
                    return CommunicationError::StreamClosed;
                }
                error!("[mtp-webserver] receive stream read_exact failed ({} bytes): {error}", buf.len());
                tracing::warn!(len = buf.len(), %error, "WebTransport receive stream read_exact failed");
                CommunicationError::StreamError
            })
    }

    async fn read_chunk(&mut self, max: usize) -> Result<Option<Vec<u8>>, CommunicationError> {
        let mut buf = vec![0; max];
        match self.stream.read(&mut buf).await {
            Ok(0) => Ok(None),
            Ok(size) => {
                buf.truncate(size);
                Ok(Some(buf))
            }
            Err(error) => {
                error!(
                    "[mtp-webserver] receive stream read failed (max {} bytes): {error}",
                    max
                );
                tracing::warn!(max, %error, "WebTransport receive stream read failed");
                Err(CommunicationError::StreamError)
            }
        }
    }
}

impl tokio::io::AsyncWrite for H3TransportSender {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

impl tokio::io::AsyncRead for H3TransportReceiver {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

#[async_trait::async_trait]
impl TransportConnection for H3TransportConnection {
    type SendStream = H3TransportSender;
    type RecvStream = H3TransportReceiver;

    async fn open_uni(&self) -> Result<Self::SendStream, CommunicationError> {
        self.session
            .open_uni(self.session.session_id())
            .await
            .map(|stream| H3TransportSender { stream })
            .map_err(|_| CommunicationError::StreamError)
    }

    async fn accept_uni(&self) -> Result<Self::RecvStream, CommunicationError> {
        const MAX_CONSECUTIVE_ERRORS: u32 = 10;
        const INITIAL_RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(20);

        let mut consecutive_errors = 0_u32;
        loop {
            match self.session.accept_uni().await {
                Ok(Some((id, stream))) if id == self.session.session_id() => {
                    return Ok(H3TransportReceiver { stream });
                }
                Ok(Some(_)) => {
                    consecutive_errors = 0;
                    continue;
                }
                Ok(None) => return Err(CommunicationError::StreamClosed),
                Err(error) => {
                    // A browser can reset an individual pipe stream while it
                    // is stopping MediaRecorder. h3-webtransport reports that
                    // through accept_uni even though the QUIC connection is
                    // still healthy. Do not turn that stream-local failure
                    // into a connection-wide MTP failure.
                    if self.quinn.close_reason().is_some() {
                        return Err(CommunicationError::StreamClosed);
                    }

                    consecutive_errors += 1;
                    if consecutive_errors > MAX_CONSECUTIVE_ERRORS {
                        tracing::warn!(
                            %error,
                            consecutive_errors,
                            "WebTransport receive-stream accept repeatedly failed"
                        );
                        return Err(CommunicationError::StreamError);
                    }

                    let multiplier = 1_u32 << consecutive_errors.saturating_sub(1).min(5);
                    let retry_delay = INITIAL_RETRY_DELAY * multiplier;
                    tracing::debug!(
                        %error,
                        consecutive_errors,
                        ?retry_delay,
                        "retrying transient WebTransport receive-stream error"
                    );
                    tokio::time::sleep(retry_delay).await;
                }
            }
        }
    }

    fn close_reason(&self) -> Option<CommunicationError> {
        self.quinn
            .close_reason()
            .map(|_| CommunicationError::StreamClosed)
    }

    fn close(&self, code: u32, reason: &[u8]) {
        self.quinn.close(quinn::VarInt::from_u32(code), reason);
    }
}

/// Shared host MTP connection instantiated with HTTP/3 stream adapters.
pub type WebMtpSender = GenericSender<H3TransportConnection>;
pub type WebMtpReceiver = GenericReceiver<H3TransportConnection>;
pub type WebMTPConnection =
    mtp_host::MTPConnection<WebMtpSender, WebMtpReceiver, H3TransportReceiver>;

pub(crate) async fn accept_web_connection(
    session: Arc<Session>,
    path: String,
    quinn: quinn::Connection,
    send_pongs: bool,
    policy: Policy,
    host_config: Arc<HostConfig>,
) -> Result<WebMTPConnection, AcceptError> {
    #[cfg(feature = "crypto")]
    {
        tokio::time::timeout(
            host_config.auth_timeout,
            accept_web_connection_inner(session, path, quinn, send_pongs, policy, host_config),
        )
        .await
        .unwrap_or(Err(AcceptError::AuthenticationTimedOut))
    }

    #[cfg(not(feature = "crypto"))]
    accept_web_connection_inner(session, path, quinn, send_pongs, policy, host_config).await
}

async fn accept_web_connection_inner(
    session: Arc<Session>,
    path: String,
    quinn: quinn::Connection,
    send_pongs: bool,
    policy: Policy,
    _host_config: Arc<HostConfig>,
) -> Result<WebMTPConnection, AcceptError> {
    #[cfg(feature = "crypto")]
    let auth_handshake_started = Instant::now();
    let max_message_size = policy.max_message_size;
    let transport = H3TransportConnection::new(session, quinn);
    let policy = Arc::new(policy);
    let receiver = WebMtpReceiver::new(transport.clone(), policy.clone());

    let first = receiver.receive().await.map_err(AcceptError::Receive)?;
    let version = match first.get_data(DataType::Version) {
        DataValue::Str(value) => Version::parse(value).ok_or(AcceptError::MissingVersion)?,
        _ => return Err(AcceptError::MissingVersion),
    };
    let registry = Registry::builtin();
    let negotiated = registry
        .negotiate(std::slice::from_ref(&version))
        .ok_or_else(|| AcceptError::UnsupportedVersion(version.clone()))?;
    let codec = VersionedCodec::for_version(registry, negotiated.clone())
        .ok_or_else(|| AcceptError::UnsupportedVersion(negotiated.clone()))?;
    let description = match first.get_data(DataType::Description) {
        DataValue::Str(value) => Some(value.clone()),
        _ => None,
    };
    let sender = WebMtpSender::new(transport, policy);
    if send_pongs {
        receiver.respond_to_pings(sender.clone()).await;
    }
    let connection = mtp_host::MTPConnection::from_transport_parts(
        negotiated,
        codec,
        sender,
        receiver,
        path,
        description.clone(),
    );
    #[cfg(feature = "crypto")]
    let mut connection = connection;
    #[cfg(feature = "crypto")]
    if !matches!(
        _host_config.authentication_policy,
        mtp_host::AuthenticationPolicy::Unauthenticated
    ) {
        use mtp_crypto::{
            Ed25519Signer, MlDsaSigner, PublicKeyBundle, SignatureScheme, auth, verify_ed25519,
            verify_ml_dsa,
        };
        let tm = mtp_codec::TypeMap::latest();
        let client_lookup_started = Instant::now();
        let (client_id, client_bundle, response_type) = if Some(first.get_type())
            == mtp_codec::CommunicationType::Identification.try_to_id(&tm)
        {
            let id = match first.get_data(DataType::Id) {
                DataValue::UnsignedNumber(value) => *value as u64,
                _ => {
                    return Err(AcceptError::AuthenticationFailed(
                        "missing client id".into(),
                    ));
                }
            };
            let bundle = (_host_config.get_existing_client)(id, description.clone())
                .await
                .ok_or_else(|| AcceptError::AuthenticationFailed("unknown client id".into()))?;
            (
                id,
                bundle,
                mtp_codec::CommunicationType::IdentificationResponse,
            )
        } else if Some(first.get_type()) == mtp_codec::CommunicationType::Register.try_to_id(&tm) {
            let bundle = match first.get_data(DataType::PublicKeys) {
                DataValue::Bytes(bytes) => PublicKeyBundle::from_bytes(bytes).map_err(|_| {
                    AcceptError::AuthenticationFailed("invalid public key bundle".into())
                })?,
                _ => {
                    return Err(AcceptError::AuthenticationFailed(
                        "missing public keys".into(),
                    ));
                }
            };
            (0, bundle, mtp_codec::CommunicationType::RegisterResponse)
        } else {
            return Err(AcceptError::AuthenticationFailed(
                "unexpected authentication message".into(),
            ));
        };
        tracing::debug!(elapsed = ?client_lookup_started.elapsed(), "web authentication handshake: identify client");

        let signer_init_started = Instant::now();
        let host_pq_signer = if !_host_config
            .host_keyring
            .sig_pq_secret_key
            .as_bytes()
            .is_empty()
        {
            Some(
                MlDsaSigner::new(
                    &_host_config.host_keyring.sig_pq_secret_key,
                    &_host_config.host_keyring.sig_pq_public_key,
                )
                .map_err(|e| AcceptError::AuthenticationFailed(e.to_string()))?,
            )
        } else {
            None
        };
        tracing::debug!(elapsed = ?signer_init_started.elapsed(), "web authentication handshake: signer initialization");

        let server_challenge: u128 = rand::random();
        let host_sign = |payload: &[u8]| -> Result<(Vec<u8>, Vec<u8>), AcceptError> {
            let signer = Ed25519Signer::new(&_host_config.host_keyring.sig_cl_secret_key)
                .map_err(|e| AcceptError::AuthenticationFailed(e.to_string()))?;
            let sig = signer
                .sign(payload)
                .map_err(|e| AcceptError::AuthenticationFailed(e.to_string()))?;
            let pq = if let Some(pq_signer) = host_pq_signer.as_ref() {
                pq_signer
                    .sign(payload)
                    .map_err(|e| AcceptError::AuthenticationFailed(e.to_string()))?
            } else {
                Vec::new()
            };
            Ok((sig, pq))
        };
        let sign_challenge_started = Instant::now();
        let (sig, pq_sig) = host_sign(&auth::challenge_payload(client_id, server_challenge))?;
        tracing::debug!(elapsed = ?sign_challenge_started.elapsed(), "web authentication handshake: sign challenge");
        let mut challenge =
            mtp_codec::CommunicationValue::new(mtp_codec::CommunicationType::Challenge)
                .add_typed_default(
                    DataType::ServerNonce,
                    DataValue::UnsignedNumber(server_challenge),
                )
                .add_typed_default(DataType::Signature, DataValue::Bytes(sig))
                .add_typed_default(
                    DataType::RequirePq,
                    if _host_config.require_pq {
                        DataValue::BoolTrue
                    } else {
                        DataValue::BoolFalse
                    },
                );
        if !pq_sig.is_empty() {
            challenge =
                challenge.add_typed_default(DataType::PqSignature, DataValue::Bytes(pq_sig));
        }
        let send_challenge_started = Instant::now();
        connection
            .sender
            .send(&challenge)
            .await
            .map_err(AcceptError::Send)?;
        tracing::debug!(elapsed = ?send_challenge_started.elapsed(), "web authentication handshake: send challenge");
        let receive_proof_started = Instant::now();
        let proof = connection.receive().await.map_err(AcceptError::Receive)?;
        tracing::debug!(elapsed = ?receive_proof_started.elapsed(), "web authentication handshake: receive client proof");
        if Some(proof.get_type()) != mtp_codec::CommunicationType::ChallengeResponse.try_to_id(&tm)
        {
            return Err(AcceptError::AuthenticationFailed(
                "missing challenge response".into(),
            ));
        }
        let nonce = match proof.get_data(DataType::ClientNonce) {
            DataValue::UnsignedNumber(n) => *n,
            _ => {
                return Err(AcceptError::AuthenticationFailed(
                    "missing client nonce".into(),
                ));
            }
        };
        let signature = match proof.get_data(DataType::Signature) {
            DataValue::Bytes(bytes) => bytes,
            _ => {
                return Err(AcceptError::AuthenticationFailed(
                    "missing challenge signature".into(),
                ));
            }
        };
        let pq_signature = match proof.get_data(DataType::PqSignature) {
            DataValue::Bytes(bytes) => bytes.as_slice(),
            _ => &[],
        };
        let payload = if first.get_type()
            == mtp_codec::CommunicationType::Register
                .try_to_id(&tm)
                .unwrap()
        {
            auth::register_proof_payload(
                &version.to_string(),
                &client_bundle.as_bytes(),
                server_challenge,
                nonce,
            )
        } else {
            auth::login_proof_payload(&version.to_string(), client_id, server_challenge, nonce)
        };
        let verify_proof_started = Instant::now();
        if verify_ed25519(&client_bundle.sig_cl_public_key, &payload, signature).is_err() {
            return Err(AcceptError::AuthenticationFailed(
                "client proof signature invalid".into(),
            ));
        }
        let client_has_pq = !client_bundle.sig_pq_public_key.as_bytes().is_empty();
        if _host_config.require_pq
            && (!client_has_pq
                || pq_signature.is_empty()
                || verify_ml_dsa(&client_bundle.sig_pq_public_key, &payload, pq_signature).is_err())
        {
            return Err(AcceptError::AuthenticationFailed(
                "client PQ proof signature invalid".into(),
            ));
        }
        tracing::debug!(elapsed = ?verify_proof_started.elapsed(), "web authentication handshake: verify client proof");
        let register_started = Instant::now();
        let assigned_id = if response_type == mtp_codec::CommunicationType::RegisterResponse {
            (_host_config.complete_register)(client_bundle.clone(), description.clone()).await
        } else {
            client_id
        };
        tracing::debug!(elapsed = ?register_started.elapsed(), "web authentication handshake: registration callback");
        let sign_final_started = Instant::now();
        let (final_sig, final_pq) = host_sign(&auth::host_final_payload(
            assigned_id,
            nonce,
            server_challenge,
        ))?;
        tracing::debug!(elapsed = ?sign_final_started.elapsed(), "web authentication handshake: sign final response");
        let mut response = mtp_codec::CommunicationValue::new(response_type)
            .add_typed_default(DataType::Connected, DataValue::BoolTrue)
            .add_typed_default(DataType::Id, DataValue::UnsignedNumber(assigned_id as u128))
            .add_typed_default(DataType::ClientNonce, DataValue::UnsignedNumber(nonce))
            .add_typed_default(DataType::Signature, DataValue::Bytes(final_sig))
            .add_typed_default(DataType::Version, DataValue::Str(version.to_string()));
        if !final_pq.is_empty() {
            response =
                response.add_typed_default(DataType::PqSignature, DataValue::Bytes(final_pq));
        }
        let send_final_started = Instant::now();
        connection
            .sender
            .send(&response)
            .await
            .map_err(AcceptError::Send)?;
        connection
            .sender
            .finish_stream()
            .await
            .map_err(AcceptError::Send)?;
        tracing::debug!(elapsed = ?send_final_started.elapsed(), "web authentication handshake: send final response");
        tracing::debug!(elapsed = ?auth_handshake_started.elapsed(), "web authentication handshake: complete");
        connection.receiver.set_max_message_size(max_message_size);
        connection.auth_state = mtp_host::AuthState::Authenticated;
        connection.client_id = assigned_id;
        connection.client_public_key = Some(client_bundle);
        return Ok(connection);
    }

    // Complete the opening handshake for unauthenticated connections. Native clients
    // wait for this response before sending application messages.
    let response =
        mtp_codec::CommunicationValue::new(mtp_codec::CommunicationType::IdentificationResponse)
            .add_typed_default(
                mtp_codec::DataType::Connected,
                mtp_codec::DataValue::BoolTrue,
            )
            .add_typed_default(
                mtp_codec::DataType::Version,
                mtp_codec::DataValue::Str(connection.version.to_string()),
            )
            .add_typed_default(
                mtp_codec::DataType::Id,
                // WebTransport connections currently do not expose the host's guest
                // ID through MTPConnection; unauthenticated clients do not need it.
                mtp_codec::DataValue::UnsignedNumber(0),
            );
    connection
        .sender
        .send(&response)
        .await
        .map_err(AcceptError::Send)?;
    connection
        .sender
        .finish_stream()
        .await
        .map_err(AcceptError::Send)?;
    connection.receiver.set_max_message_size(max_message_size);
    Ok(connection)
}
