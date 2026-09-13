use mtp_codec::registry::Registry;
use mtp_core::{GenericReceiver, GenericSender, Policy};
use mtp_h3::{H3TransportConnection, H3TransportReceiver, Session};
use mtp_host::{AcceptError, HostConfig};
use std::sync::Arc;

pub type WebMtpSender = GenericSender<H3TransportConnection>;
pub type WebMtpReceiver = GenericReceiver<H3TransportConnection>;
pub type WebMTPConnection =
    mtp_host::MTPConnection<WebMtpSender, WebMtpReceiver, H3TransportReceiver>;

struct SessionTask(Option<tokio::task::JoinHandle<()>>);

impl SessionTask {
    fn take(&mut self) -> tokio::task::JoinHandle<()> {
        self.0.take().expect("session task is available")
    }
}

impl Drop for SessionTask {
    fn drop(&mut self) {
        if let Some(task) = self.0.take() {
            task.abort();
        }
    }
}

#[allow(clippy::needless_return, clippy::too_many_arguments)]
pub(crate) async fn accept_web_connection(
    session: Arc<Session>,
    path: String,
    quinn: quinn::Connection,
    send_pongs: bool,
    policy: Policy,
    host_config: Arc<HostConfig>,
    #[allow(unused_variables)] auth_semaphore: Arc<tokio::sync::Semaphore>,
    connection_guard: Option<tokio::sync::OwnedSemaphorePermit>,
    session_task: tokio::task::JoinHandle<()>,
) -> Result<WebMTPConnection, AcceptError> {
    let mut session_task = SessionTask(Some(session_task));
    #[cfg(feature = "crypto")]
    {
        let deadline = tokio::time::Instant::now() + host_config.auth_timeout;
        let permit = tokio::time::timeout_at(deadline, auth_semaphore.clone().acquire_owned())
            .await
            .map_err(|_| AcceptError::AuthenticationTimedOut)?
            .map_err(|_| {
                AcceptError::AuthenticationFailed("authentication service stopped".into())
            })?;
        let result = accept_web_connection_inner(
            session,
            path,
            quinn,
            send_pongs,
            policy,
            host_config,
            Some(deadline),
            connection_guard,
            &mut session_task,
        )
        .await;
        drop(permit);
        result
    }

    #[cfg(not(feature = "crypto"))]
    {
        accept_web_connection_inner(
            session,
            path,
            quinn,
            send_pongs,
            policy,
            host_config,
            None,
            connection_guard,
            &mut session_task,
        )
        .await
    }
}

#[allow(clippy::too_many_arguments)]
async fn accept_web_connection_inner(
    session: Arc<Session>,
    path: String,
    quinn: quinn::Connection,
    send_pongs: bool,
    policy: Policy,
    host_config: Arc<HostConfig>,
    #[allow(unused_variables)] deadline: Option<tokio::time::Instant>,
    connection_guard: Option<tokio::sync::OwnedSemaphorePermit>,
    session_task: &mut SessionTask,
) -> Result<WebMTPConnection, AcceptError> {
    let max_message_size = policy.max_message_size;
    let transport = H3TransportConnection::new(session, quinn);
    let remote_addr = transport.remote_addr();
    #[cfg(feature = "crypto")]
    let connection_id = transport.connection_id();
    let policy = Arc::new(policy);
    let sender = WebMtpSender::new(transport.clone(), policy.clone());
    let receiver = WebMtpReceiver::new(transport, policy.clone());

    let engine = mtp_host::HandshakeEngine::new(Registry::builtin(), host_config);
    #[cfg(feature = "crypto")]
    let result = engine
        .accept_until_with_context(
            &sender,
            &receiver,
            deadline.expect("crypto WebTransport handshakes have a deadline"),
            mtp_host::AuthenticationContext {
                peer_network_identity: Some(remote_addr.ip()),
                connection_id,
            },
        )
        .await;
    #[cfg(feature = "crypto")]
    if let Err(error) = &result {
        tracing::warn!(
            remote = %remote_addr,
            connection_id,
            %error,
            "WebTransport MTP handshake failed"
        );
    }
    #[cfg(feature = "crypto")]
    let result = result?;
    #[cfg(not(feature = "crypto"))]
    let result = engine.accept(&sender, &receiver).await?;

    let version = result.negotiated_version.clone();
    let codec = result.codec.clone();
    let description = result.description.clone();
    #[cfg(feature = "pipes")]
    let connection: WebMTPConnection = mtp_host::MTPConnection::from_transport_parts_with_policy(
        version,
        codec,
        sender,
        receiver,
        path,
        description,
        Some(remote_addr),
        policy,
    );
    #[cfg(not(feature = "pipes"))]
    let connection: WebMTPConnection =
        mtp_host::MTPConnection::from_transport_parts_with_remote_addr(
            version,
            codec,
            sender,
            receiver,
            path,
            description,
            Some(remote_addr),
        );

    let mut connection = connection;
    #[cfg(feature = "crypto")]
    {
        connection.auth_state = result.auth_state;
        connection.client_id = result.client_id;
        connection.client_public_key = result.client_public_key;
        connection.set_guest_id_lease(result.guest_id_lease);
    }
    if let Some(connection_guard) = connection_guard {
        connection.set_connection_guard(connection_guard);
    }
    connection.set_session_task(session_task.take());
    if send_pongs {
        connection
            .receiver
            .respond_to_pings(connection.sender.clone())
            .await;
    }
    connection.receiver.set_max_message_size(max_message_size);
    Ok(connection)
}
