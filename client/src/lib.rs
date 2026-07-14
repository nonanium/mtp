use mtp_codec::{CommunicationValue, DataType, DataValue, PROTOCOL_VERSION, Version};
use mtp_common::CommunicationError;
#[cfg(feature = "pipes")]
pub use mtp_common::PipeError;
use std::collections::HashMap;
use std::sync::Arc;
use rand::Rng;
use tokio::sync::{Mutex, mpsc};
use tokio::time::{Duration, Instant};

#[cfg(feature = "pipes")]
use mtp_transport::PipeReader;

pub use MTPClient as Client;
pub use MTPConnection as Connection;
pub use mtp_transport::Policy;
pub use mtp_transport::Receiver;
pub use mtp_transport::SendMode;
pub use mtp_transport::Sender;

#[cfg(feature = "pipes")]
pub use mtp_transport::PipeWriter;

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

#[cfg(feature = "pipes")]
pub struct PipeHandle {
    pipe_id: u32,
    description: String,
    sender: Sender,
    response_rx: tokio::sync::oneshot::Receiver<Result<bool, PipeError>>,
}

#[cfg(feature = "pipes")]
impl PipeHandle {
    pub fn pipe_id(&self) -> u32 {
        self.pipe_id
    }

    pub fn description(&self) -> &str {
        &self.description
    }

    pub async fn wait(self) -> Result<Option<PipeWriter>, PipeError> {
        match self.response_rx.await {
            Ok(Ok(true)) => {
                let writer = self
                    .sender
                    .open_pipe(self.pipe_id, &self.description)
                    .await
                    .map_err(PipeError::from)?;
                Ok(Some(writer))
            }
            Ok(Ok(false)) => Ok(None),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(PipeError::StreamClosed),
        }
    }
}

#[cfg(feature = "pipes")]
pub struct PipeRequest {
    pipe_id: u32,
    description: String,
    sender: Sender,
    dispatcher: Arc<PipeDispatcher>,
}

#[cfg(feature = "pipes")]
impl PipeRequest {
    pub fn id(&self) -> u32 {
        self.pipe_id
    }

    pub fn description(&self) -> &str {
        &self.description
    }

    pub async fn accept(self) -> Result<PipeReader, PipeError> {
        let (pipe_tx, pipe_rx) = tokio::sync::oneshot::channel();
        {
            let mut pending = self.dispatcher.pending_pipes.lock().await;
            pending.insert(self.pipe_id, pipe_tx);
        }

        let resp = CommunicationValue::new(mtp_codec::CommunicationType::PipeResponse)
            .with_id(self.pipe_id)
            .add_typed_default(DataType::Accepted, DataValue::BoolTrue);
        self.sender.send(&resp).await.map_err(PipeError::from)?;

        let timeout = self.dispatcher.policy.read_timeout;
        tokio::time::timeout(timeout, pipe_rx)
            .await
            .map_err(|_| PipeError::HandshakeTimeout)?
            .map_err(|_| PipeError::StreamClosed)
    }

    pub async fn deny(self) -> Result<(), PipeError> {
        let resp = CommunicationValue::new(mtp_codec::CommunicationType::PipeResponse)
            .with_id(self.pipe_id)
            .add_typed_default(DataType::Accepted, DataValue::BoolFalse);
        self.sender.send(&resp).await.map_err(PipeError::from)?;
        Ok(())
    }
}

#[cfg(feature = "pipes")]
struct PipeDispatcher {
    pending_creations: Mutex<HashMap<u32, tokio::sync::oneshot::Sender<Result<bool, PipeError>>>>,
    pending_pipes: Mutex<HashMap<u32, tokio::sync::oneshot::Sender<PipeReader>>>,
    policy: Arc<Policy>,
}

#[cfg(not(feature = "pipes"))]
struct PipeDispatcher;

#[cfg(not(feature = "pipes"))]
pub(crate) struct PipeRequest;

#[cfg(feature = "pipes")]
async fn run_dispatcher(
    receiver: Receiver,
    sender: Sender,
    app_tx: mpsc::Sender<Result<CommunicationValue, CommunicationError>>,
    pipe_req_tx: mpsc::Sender<PipeRequest>,
    dispatcher: Arc<PipeDispatcher>,
) {
    let pipe_req_type =
        mtp_codec::CommunicationType::PipeRequest.to_id(&mtp_codec::TypeMap::latest());
    let pipe_resp_type =
        mtp_codec::CommunicationType::PipeResponse.to_id(&mtp_codec::TypeMap::latest());

    loop {
        match receiver.receive_event().await {
            Ok(mtp_transport::TransportEvent::Message(msg)) => {
                if msg.get_type() == pipe_req_type {
                    let pipe_id = msg.get_id();
                    let description = msg
                        .get_str(DataType::Description)
                        .unwrap_or("")
                        .to_string();
                    let req = PipeRequest {
                        pipe_id,
                        description,
                        sender: sender.clone(),
                        dispatcher: dispatcher.clone(),
                    };
                    let _ = pipe_req_tx.send(req).await;
                    continue;
                }

                if msg.get_type() == pipe_resp_type {
                    let pipe_id = msg.get_id();
                    let accepted = msg.get_bool(DataType::Accepted).unwrap_or(false);
                    let mut pending = dispatcher.pending_creations.lock().await;
                    if let Some(tx) = pending.remove(&pipe_id) {
                        let _ = tx.send(Ok(accepted));
                    }
                    continue;
                }

                if app_tx.send(Ok(msg)).await.is_err() {
                    break;
                }
            }
            Ok(mtp_transport::TransportEvent::Pipe(reader)) => {
                let pipe_id = reader.pipe_id();
                let mut pending = dispatcher.pending_pipes.lock().await;
                if let Some(tx) = pending.remove(&pipe_id) {
                    let _ = tx.send(reader);
                }
            }
            Err(e) => {
                if app_tx.send(Err(e)).await.is_err() {
                    break;
                }
            }
        }
    }
}

pub struct ClientConfig {
    pub url: String,
    pub tls: ClientTlsConfig,
    pub client_id: u64,
    pub description: Option<String>,
    pub policy: Policy,
    pub ping_interval: Duration,
    pub ping_jitter: Option<Duration>,
    pub max_missed_pings: usize,
    pub ping_timestamp: bool,
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
            ping_interval: Duration::ZERO,
            ping_jitter: None,
            max_missed_pings: 3,
            ping_timestamp: true,
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

    pub fn with_ping_interval(mut self, interval: Duration) -> Self {
        self.ping_interval = interval;
        self
    }

    pub fn with_ping_jitter(mut self, jitter: Option<Duration>) -> Self {
        self.ping_jitter = jitter;
        self
    }

    pub fn with_max_missed_pings(mut self, max_missed_pings: usize) -> Self {
        self.max_missed_pings = max_missed_pings;
        self
    }

    pub fn with_ping_timestamp(mut self, ping_timestamp: bool) -> Self {
        self.ping_timestamp = ping_timestamp;
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
    ping: Option<PingSession>,
    app_rx: Mutex<mpsc::Receiver<Result<CommunicationValue, CommunicationError>>>,
    pipe_req_rx: Mutex<mpsc::Receiver<PipeRequest>>,
    pipe_dispatcher: Arc<PipeDispatcher>,
    _dispatcher_task: tokio::task::JoinHandle<()>,
    #[cfg(feature = "crypto")]
    pub auth_state: AuthState,
    #[cfg(feature = "crypto")]
    pub client_id: u64,
}

struct PingSession {
    last_ping: Arc<Mutex<Option<Duration>>>,
    task: tokio::task::JoinHandle<()>,
}

impl PingSession {
    fn get_ping(&self) -> Option<Duration> {
        self.last_ping.try_lock().ok().and_then(|ping| *ping)
    }
}

impl Drop for PingSession {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl MTPConnection {
    /* Returns the round-trip time for the latest Ping/Pong exchange. */
    pub fn get_ping(&self) -> Option<Duration> {
        self.ping.as_ref().and_then(PingSession::get_ping)
    }

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
            let response = self.receive().await?;
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

    pub async fn receive(&self) -> Result<CommunicationValue, CommunicationError> {
        #[cfg(feature = "pipes")]
        {
            let mut rx = self.app_rx.lock().await;
            match rx.recv().await {
                Some(result) => result,
                None => Err(CommunicationError::StreamClosed),
            }
        }
        #[cfg(not(feature = "pipes"))]
        {
            self.receiver.receive().await
        }
    }
}

#[cfg(feature = "pipes")]
impl MTPConnection {
    pub async fn create_pipe(&self, description: &str) -> Result<PipeHandle, PipeError> {
        let pipe_id = rand::random::<u32>();
        let (tx, rx) = tokio::sync::oneshot::channel();

        {
            let mut pending = self.pipe_dispatcher.pending_creations.lock().await;
            pending.insert(pipe_id, tx);
        }

        let request = CommunicationValue::new(mtp_codec::CommunicationType::PipeRequest)
            .with_id(pipe_id)
            .add_typed_default(DataType::Description, DataValue::Str(description.into()));

        self.sender.send(&request).await.map_err(PipeError::from)?;

        Ok(PipeHandle {
            pipe_id,
            description: description.to_string(),
            sender: self.sender.clone(),
            response_rx: rx,
        })
    }

    pub async fn receive_pipe(&self) -> Result<PipeRequest, CommunicationError> {
        let mut rx = self.pipe_req_rx.lock().await;
        match rx.recv().await {
            Some(req) => Ok(req),
            None => Err(CommunicationError::StreamClosed),
        }
    }
}

fn start_ping_session(
    config: &ClientConfig,
    sender: Sender,
    receiver: &Receiver,
) -> Option<PingSession> {
    if config.ping_interval.is_zero() {
        return None;
    }

    let (pong_tx, mut pong_rx) = mpsc::unbounded_channel();
    receiver.observe_pongs(pong_tx);
    let last_ping = Arc::new(Mutex::new(None));
    let ping_state = last_ping.clone();
    let interval = config.ping_interval;
    let ping_jitter = config.ping_jitter;
    let max_missed_pings = config.max_missed_pings;
    let ping_timestamp = config.ping_timestamp;
    let mut close_rx = receiver.handle().subscribe_close();

    let task = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.tick().await;
        let mut pending = HashMap::new();

        loop {
            tokio::select! {
                _ = close_rx.changed() => {
                    if close_rx.borrow().is_some() {
                        break;
                    }
                }
                _ = ticker.tick() => {
                    if max_missed_pings > 0 && !pending.is_empty() && pending.len() >= max_missed_pings {
                        sender.close();
                        break;
                    }

                    if let Some(jitter) = ping_jitter && !jitter.is_zero() {
                        let max_ms = jitter.as_millis() as u64;
                        let extra = rand::thread_rng().gen_range(0..=max_ms);
                        tokio::time::sleep(Duration::from_millis(extra)).await;
                    }

                    let mut ping = CommunicationValue::new(mtp_codec::CommunicationType::Ping);
                    if ping_timestamp {
                        let sent_at = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_millis();
                        ping = ping.add_typed_default(
                            DataType::Timestamp,
                            DataValue::UnsignedNumber(sent_at),
                        );
                    }
                    let id = ping.get_id();
                    if sender.send(&ping).await.is_err() {
                        sender.close();
                        break;
                    }
                    pending.insert(id, Instant::now());
                }
                pong = pong_rx.recv() => match pong {
                    Some(pong) => {
                        if let Some(sent_at) = pending.remove(&pong.get_id()) {
                            let mut last_ping = ping_state.lock().await;
                            *last_ping = Some(sent_at.elapsed());
                        }
                    }
                    None => break,
                },
            }
        }
    });

    Some(PingSession { last_ping, task })
}

fn connection_from_parts(
    config: ClientConfig,
    sender: Sender,
    receiver: Receiver,
    #[cfg(feature = "crypto")] auth_state: AuthState,
    #[cfg(feature = "crypto")] client_id: u64,
) -> MTPConnection {
    let ping = start_ping_session(&config, sender.clone(), &receiver);

    #[cfg(feature = "pipes")]
    {
        let (app_tx, app_rx) = mpsc::channel::<Result<CommunicationValue, CommunicationError>>(
            config.policy.receiver_queue_capacity,
        );
        let (pipe_req_tx, pipe_req_rx) = mpsc::channel::<PipeRequest>(
            config.policy.receiver_queue_capacity,
        );

        let dispatcher = Arc::new(PipeDispatcher {
            pending_creations: Mutex::new(HashMap::new()),
            pending_pipes: Mutex::new(HashMap::new()),
            policy: Arc::new(config.policy),
        });

        let dispatcher_clone = dispatcher.clone();
        let sender_clone = sender.clone();
        let dispatcher_task = tokio::spawn(run_dispatcher(
            receiver.clone(),
            sender_clone,
            app_tx,
            pipe_req_tx,
            dispatcher_clone,
        ));

        MTPConnection {
            version: PROTOCOL_VERSION,
            sender,
            receiver,
            app_rx: Mutex::new(app_rx),
            pipe_req_rx: Mutex::new(pipe_req_rx),
            pipe_dispatcher: dispatcher,
            description: config.description,
            ping,
            _dispatcher_task: dispatcher_task,
            #[cfg(feature = "crypto")]
            auth_state,
            #[cfg(feature = "crypto")]
            client_id,
        }
    }

    #[cfg(not(feature = "pipes"))]
    {
        let (_, app_rx) = mpsc::channel::<Result<CommunicationValue, CommunicationError>>(1);
        let (_, pipe_req_rx) = mpsc::channel::<PipeRequest>(1);
        let dispatcher = Arc::new(PipeDispatcher);
        let task = tokio::spawn(async {});

        MTPConnection {
            version: PROTOCOL_VERSION,
            sender,
            receiver,
            app_rx: Mutex::new(app_rx),
            pipe_req_rx: Mutex::new(pipe_req_rx),
            pipe_dispatcher: dispatcher,
            description: config.description,
            ping,
            _dispatcher_task: task,
            #[cfg(feature = "crypto")]
            auth_state,
            #[cfg(feature = "crypto")]
            client_id,
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
            mtp_transport::connect(&config.url, config.server_cert(), config.policy).await?;

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

        #[cfg(feature = "crypto")]
        let client_id = config.client_id;
        #[cfg(feature = "crypto")]
        return Ok(connection_from_parts(
            config,
            sender,
            receiver,
            AuthState::Unauthenticated,
            client_id,
        ));
        #[cfg(not(feature = "crypto"))]
        Ok(connection_from_parts(config, sender, receiver))
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

        let client_id = config.client_id;
        Ok(connection_from_parts(
            config,
            sender,
            receiver,
            AuthState::Authenticated,
            client_id,
        ))
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

        Ok(connection_from_parts(
            config,
            sender,
            receiver,
            AuthState::Authenticated,
            assigned_id,
        ))
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

    #[test]
    fn test_ping_config() {
        let config = ClientConfig::new("https://localhost:4433")
            .with_ping_interval(Duration::from_secs(5))
            .with_max_missed_pings(2)
            .with_ping_timestamp(false);
        assert_eq!(config.ping_interval, Duration::from_secs(5));
        assert_eq!(config.ping_jitter, None);
        assert_eq!(config.max_missed_pings, 2);
        assert!(!config.ping_timestamp);
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
