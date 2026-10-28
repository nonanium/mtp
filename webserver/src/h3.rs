use crate::{
    HttpRequest, HttpResponse, Router, WebMTPConnection, WebServerError, WebServerMetrics,
    transport::accept_web_connection,
};
use bytes::{Buf, Bytes};
use http::{Request, Response, StatusCode};
use mtp_host::HostConfig;
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::sync::{Semaphore, watch};

pub(crate) struct DriverConfig {
    pub(crate) router: Router,
    pub(crate) mtp_path: String,
    pub(crate) max_request_body: usize,
    pub(crate) request_timeout: Duration,
    pub(crate) drain_timeout: Duration,
    pub(crate) send_pongs: bool,
    pub(crate) policy: mtp_native::Policy,
    pub(crate) host_config: Arc<HostConfig>,
    pub(crate) metrics: Option<Arc<dyn WebServerMetrics>>,
    pub(crate) auth_semaphore: Arc<Semaphore>,
    pub(crate) max_concurrent_requests_per_connection: usize,
    pub(crate) max_concurrent_webtransport_requests_per_session: usize,
    pub(crate) max_webtransport_sessions: usize,
    pub(crate) request_semaphore: Option<Arc<Semaphore>>,
}

pub(crate) async fn run_driver(
    endpoint: quinn::Endpoint,
    config: DriverConfig,
    mtp_tx: tokio::sync::mpsc::Sender<Result<WebMTPConnection, mtp_host::AcceptError>>,
    connection_semaphore: Arc<Semaphore>,
    mut shutdown_rx: watch::Receiver<()>,
) {
    let DriverConfig {
        router,
        mtp_path,
        max_request_body,
        request_timeout,
        drain_timeout,
        send_pongs,
        policy,
        host_config,
        metrics,
        auth_semaphore,
        max_concurrent_requests_per_connection,
        max_concurrent_webtransport_requests_per_session,
        max_webtransport_sessions,
        request_semaphore,
    } = config;
    let mut connection_tasks = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            biased;
            _ = shutdown_rx.changed() => {
                break;
            }
            result = connection_tasks.join_next(), if !connection_tasks.is_empty() => {
                if let Some(Err(error)) = result {
                    tracing::warn!(%error, "HTTP/3 connection task panicked");
                }
            }
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else {
                    break;
                };
                // Do not await capacity here: doing so would prevent this loop
                // from observing shutdown while all connection slots are in use.
                let permit = match connection_semaphore.clone().try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        tracing::debug!("rejecting QUIC connection at configured connection limit");
                        continue;
                    }
                };
                let router = router.clone();
                let mtp_path = mtp_path.clone();
                let mtp_tx = mtp_tx.clone();
                let metrics = metrics.clone();
                let host_config = host_config.clone();
                let auth_semaphore = auth_semaphore.clone();
                let request_semaphore = request_semaphore.clone();
                connection_tasks.spawn(async move {
                    // The permit normally lives for this HTTP/3 connection.
                    // For an MTP session it is moved into the resulting
                    // connection so the limit covers the session lifetime.
                    let mut connection_permit = Some(permit);
                    let connect_start = std::time::Instant::now();
                    let connection = match incoming.await {
                        Ok(connection) => connection,
                        Err(error) => {
                            tracing::debug!(%error, "QUIC connection failed during handshake");
                            return;
                        }
                    };
                    let mut builder = h3::server::builder();
                    builder.enable_extended_connect(true);
                    builder.enable_webtransport(true);
                    builder.enable_datagram(true);
                    builder.max_webtransport_sessions(max_webtransport_sessions as u64);
                    let mut h3 = match builder
                        .build(h3_quinn::Connection::new(connection.clone()))
                        .await
                    {
                        Ok(connection) => connection,
                        Err(error) => {
                            tracing::debug!(%error, "HTTP/3 connection setup failed");
                            return;
                        }
                    };

                    if let Some(ref m) = metrics {
                        m.connection_accepted();
                    }
                    let remote_addr = connection.remote_address();

                    let mut tasks = tokio::task::JoinSet::new();
                    let request_permits = Arc::new(Semaphore::new(max_concurrent_requests_per_connection));
                    loop {
                        while let Some(result) = tasks.try_join_next() {
                            if let Err(error) = result {
                                tracing::warn!(%error, "HTTP/3 request task panicked");
                            }
                        }
                        let resolver = match h3.accept().await {
                            Ok(Some(resolver)) => resolver,
                            Ok(None) => break,
                            Err(error) => {
                                tracing::debug!(%error, "HTTP/3 request accept failed");
                                break;
                            }
                        };
                        let (request, mut stream) = match resolver.resolve_request().await {
                            Ok(request) => request,
                            Err(error) => {
                                tracing::debug!(%error, "HTTP/3 request parse failed");
                                continue;
                            }
                        };
                        if request.method() == http::Method::CONNECT && request.uri().path() == mtp_path {
                            if request.extensions().get::<h3::ext::Protocol>()
                                != Some(&h3::ext::Protocol::WEB_TRANSPORT)
                            {
                                let _ = stream
                                    .send_response(
                                        Response::builder()
                                            .status(StatusCode::METHOD_NOT_ALLOWED)
                                            .body(())
                                            .unwrap(),
                                    )
                                    .await;
                                let _ = stream.finish().await;
                                continue;
                            }
                            let session = match h3_webtransport::server::WebTransportSession::accept(
                                request, stream, h3,
                            )
                            .await
                            {
                                Ok(session) => Arc::new(session),
                                Err(error) => {
                                    tracing::debug!(%error, "WebTransport session accept failed");
                                    return;
                                }
                            };
                            tracing::debug!(
                                remote = %remote_addr,
                                session_id = ?session.session_id(),
                                "accepted WebTransport MTP session"
                            );
                            let session_task = tokio::spawn(run_session_requests(
                                session.clone(),
                                router.clone(),
                                max_request_body,
                                request_timeout,
                                metrics.clone(),
                                remote_addr,
                                Arc::new(Semaphore::new(max_concurrent_webtransport_requests_per_session)),
                                request_semaphore.clone(),
                            ));
                            let mtp_tx = mtp_tx.clone();
                            let mtp_queue_permit = match mtp_tx.clone().try_reserve_owned() {
                                Ok(permit) => permit,
                                Err(_) => {
                                    tracing::debug!(
                                        "rejecting MTP session because the application queue is full"
                                    );
                                    connection.close(
                                        quinn::VarInt::from_u32(0),
                                        b"mtp application queue is full",
                                    );
                                    session_task.abort();
                                    return;
                                }
                            };
                            let auth_semaphore = auth_semaphore.clone();
                            let host_config = host_config.clone();
                            let connection_guard = connection_permit.take();
                            let connection = connection.clone();
                            let close_connection = connection.clone();
                            let result = accept_web_connection(
                                    session,
                                    mtp_path,
                                    connection,
                                    send_pongs,
                                    policy,
                                    host_config,
                                    auth_semaphore,
                                    connection_guard,
                                    session_task,
                                )
                                .await;
                            if result.is_err() {
                                close_connection.close(quinn::VarInt::from_u32(0), b"mtp handshake failed");
                            }
                            mtp_queue_permit.send(result);
                            return;
                        }
                        let request_permit = match request_permits.clone().try_acquire_owned() {
                            Ok(permit) => permit,
                            Err(_) => {
                                let _ = write_response(&mut stream, HttpResponse::new(StatusCode::TOO_MANY_REQUESTS)).await;
                                continue;
                            }
                        };
                        let global_request_permit = match request_semaphore.as_ref().map(|semaphore| semaphore.clone().try_acquire_owned()).transpose() {
                            Ok(permit) => permit,
                            Err(_) => {
                                let _ = write_response(&mut stream, HttpResponse::new(StatusCode::TOO_MANY_REQUESTS)).await;
                                continue;
                            }
                        };
                        let router = router.clone();
                        let metrics = metrics.clone();
                        tasks.spawn(async move {
                            let _request_permit = request_permit;
                            let _global_request_permit = global_request_permit;
                            let path = request.uri().path().to_string();
                            let response = crate::http::run_request(
                                &path,
                                request_timeout,
                                metrics.as_ref(),
                                handle_http_request(request, &mut stream, &router, max_request_body, remote_addr),
                            ).await;
                            if let Err(error) = write_response(&mut stream, response).await
                                && let Some(metrics) = &metrics
                            {
                                metrics.error_occurred(&WebServerError::Http(format!("HTTP/3 response write failed: {error}")));
                            }
                        });
                    }
                    tasks.join_all().await;
                    if let Some(ref m) = metrics {
                        m.connection_closed(connect_start.elapsed(), "normal");
                    }
                });
            }
        }
    }

    // --- Drain phase: wait for in-flight connections ---

    endpoint.close(quinn::VarInt::from_u32(0), b"mtp-webserver shutdown");

    let drain_start = std::time::Instant::now();
    while !connection_tasks.is_empty() {
        tokio::select! {
            Some(result) = connection_tasks.join_next() => {
                if let Err(e) = result {
                    tracing::warn!("Connection task panicked: {}", e);
                }
            }
            _ = tokio::time::sleep(drain_timeout.saturating_sub(drain_start.elapsed())) => {
                tracing::warn!(
                    "Drain timeout expired with {} connections still in flight",
                    connection_tasks.len()
                );
                break;
            }
        }
    }

    connection_tasks.shutdown().await;
}

async fn handle_http_request<S>(
    request: Request<()>,
    stream: &mut h3::server::RequestStream<S, Bytes>,
    router: &Router,
    max_request_body: usize,
    remote_addr: SocketAddr,
) -> Result<HttpResponse, WebServerError>
where
    S: h3::quic::BidiStream<Bytes>,
{
    let (request, too_large) = read_request(request, stream, max_request_body, remote_addr)
        .await
        .map_err(|e| WebServerError::BadRequest(format!("request body read failed: {e}")))?;
    if too_large {
        return Err(WebServerError::PayloadTooLarge);
    }
    Ok(crate::http::dispatch_request(request, router).await)
}

#[allow(clippy::too_many_arguments)]
async fn run_session_requests(
    session: Arc<h3_webtransport::server::WebTransportSession<h3_quinn::Connection, Bytes>>,
    router: Router,
    max_request_body: usize,
    request_timeout: Duration,
    metrics: Option<Arc<dyn WebServerMetrics>>,
    remote_addr: SocketAddr,
    request_permits: Arc<Semaphore>,
    global_request_permits: Option<Arc<Semaphore>>,
) {
    let mut tasks = tokio::task::JoinSet::new();
    loop {
        while let Some(result) = tasks.try_join_next() {
            if let Err(error) = result {
                tracing::warn!(%error, "WebTransport request task panicked");
            }
        }
        match session.accept_bi().await {
            Ok(Some(h3_webtransport::server::AcceptedBi::Request(request, mut stream))) => {
                let request_permit = match request_permits.clone().try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        let _ = write_response(
                            &mut stream,
                            HttpResponse::new(StatusCode::TOO_MANY_REQUESTS),
                        )
                        .await;
                        continue;
                    }
                };
                let global_request_permit = match global_request_permits
                    .as_ref()
                    .map(|semaphore| semaphore.clone().try_acquire_owned())
                    .transpose()
                {
                    Ok(permit) => permit,
                    Err(_) => {
                        let _ = write_response(
                            &mut stream,
                            HttpResponse::new(StatusCode::TOO_MANY_REQUESTS),
                        )
                        .await;
                        continue;
                    }
                };
                let router = router.clone();
                let metrics = metrics.clone();
                tasks.spawn(async move {
                    let _request_permit = request_permit;
                    let _global_request_permit = global_request_permit;
                    let path = request.uri().path().to_string();
                    let response = crate::http::run_request(
                        &path,
                        request_timeout,
                        metrics.as_ref(),
                        handle_http_request(
                            request,
                            &mut stream,
                            &router,
                            max_request_body,
                            remote_addr,
                        ),
                    )
                    .await;
                    if let Err(error) = write_response(&mut stream, response).await
                        && let Some(metrics) = &metrics
                    {
                        metrics.error_occurred(&WebServerError::Http(format!(
                            "HTTP/3 response write failed: {error}"
                        )));
                    }
                });
            }
            Ok(Some(h3_webtransport::server::AcceptedBi::BidiStream(_, _))) => {}
            Ok(None) | Err(_) => break,
        }
    }
    tasks.shutdown().await;
}

async fn read_request<S>(
    request: Request<()>,
    stream: &mut h3::server::RequestStream<S, Bytes>,
    max_body: usize,
    remote_addr: SocketAddr,
) -> Result<(HttpRequest, bool), h3::error::StreamError>
where
    S: h3::quic::BidiStream<Bytes>,
{
    let (parts, _) = request.into_parts();
    let mut body = Vec::new();
    let mut too_large = false;
    while let Some(chunk) = stream.recv_data().await? {
        if body.len().saturating_add(chunk.remaining()) > max_body {
            too_large = true;
            break;
        }
        body.extend_from_slice(chunk.chunk());
    }
    Ok((
        HttpRequest {
            method: parts.method,
            uri: parts.uri,
            headers: parts.headers,
            body: (!body.is_empty()).then(|| Bytes::from(body)),
            remote_addr,
        },
        too_large,
    ))
}

async fn write_response<S>(
    stream: &mut h3::server::RequestStream<S, Bytes>,
    response: HttpResponse,
) -> Result<(), h3::error::StreamError>
where
    S: h3::quic::BidiStream<Bytes>,
{
    let mut builder = Response::builder().status(response.status);
    for (name, value) in &response.headers {
        builder = builder.header(name, value);
    }
    stream
        .send_response(builder.body(()).expect("valid HTTP response"))
        .await?;
    for chunk in response.body {
        stream.send_data(chunk).await?;
    }
    if let Some(mut chunks) = response.stream {
        while let Some(chunk) = chunks.recv().await {
            stream.send_data(chunk).await?;
        }
    }
    stream.finish().await
}
