use crate::{HttpRequest, HttpResponse, Router, WebServerError, WebServerMetrics};
use bytes::Bytes;
use http::{Request, Response, header::CONTENT_LENGTH};
use http_body_util::{BodyExt, Full, StreamBody, combinators::BoxBody};
use hyper::{
    body::{Frame, Incoming},
    service::service_fn,
};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder,
};
use std::{convert::Infallible, sync::Arc, time::Duration};
use tokio::{
    net::TcpListener,
    sync::{Semaphore, watch},
    task::JoinSet,
};
use tokio_rustls::TlsAcceptor;
use tokio_stream::{StreamExt, wrappers::ReceiverStream};

pub(crate) struct TcpDriverConfig {
    pub router: Router,
    pub max_request_body: usize,
    pub request_timeout: Duration,
    pub tls_handshake_timeout: Duration,
    pub drain_timeout: Duration,
    pub max_connections: usize,
    pub metrics: Option<Arc<dyn WebServerMetrics>>,
    pub request_semaphore: Option<Arc<Semaphore>>,
}

pub(crate) async fn run_driver(
    listener: TcpListener,
    tls: Arc<rustls::ServerConfig>,
    config: TcpDriverConfig,
    mut shutdown_rx: watch::Receiver<()>,
) {
    let permits = Arc::new(Semaphore::new(config.max_connections));
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            biased;
            _ = shutdown_rx.changed() => break,
            accepted = listener.accept() => {
                let Ok((stream, remote_addr)) = accepted else { break };
                let Ok(permit) = permits.clone().try_acquire_owned() else {
                    tracing::debug!(%remote_addr, "rejecting TCP connection at configured connection limit");
                    continue;
                };
                let acceptor = TlsAcceptor::from(tls.clone());
                let router = config.router.clone();
                let metrics = config.metrics.clone();
                let timeout = config.request_timeout;
                let body_limit = config.max_request_body;
                let handshake_timeout = config.tls_handshake_timeout;
                let request_semaphore = config.request_semaphore.clone();
                let connection_shutdown = shutdown_rx.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                    let started = std::time::Instant::now();
                    let tls_stream = match tokio::time::timeout(handshake_timeout, acceptor.accept(stream)).await {
                        Ok(Ok(stream)) => stream,
                        Ok(Err(error)) => {
                            report_error(metrics.as_ref(), WebServerError::Tls(error.to_string()));
                            return;
                        }
                        Err(_) => {
                            report_error(metrics.as_ref(), WebServerError::Tls("TLS handshake timed out".into()));
                            return;
                        }
                    };
                    if let Some(metrics) = &metrics { metrics.connection_accepted(); }
                    let service_metrics = metrics.clone();
                    let service = service_fn(move |request| {
                        serve_request(
                            request,
                            remote_addr,
                            router.clone(),
                            body_limit,
                            timeout,
                            service_metrics.clone(),
                            request_semaphore.clone(),
                        )
                    });
                    let builder = Builder::new(TokioExecutor::new());
                    let connection = builder.serve_connection_with_upgrades(TokioIo::new(tls_stream), service);
                    tokio::pin!(connection);
                    tokio::select! {
                        result = &mut connection => {
                            if let Err(error) = result {
                                report_error(metrics.as_ref(), WebServerError::Http(format!("TCP HTTP connection failed: {error}")));
                            }
                        }
                        _ = wait_for_shutdown(connection_shutdown) => {
                            connection.as_mut().graceful_shutdown();
                            if let Err(error) = connection.await {
                                tracing::debug!(%error, "TCP HTTP connection ended during shutdown");
                            }
                        }
                    }
                    if let Some(metrics) = &metrics { metrics.connection_closed(started.elapsed(), "normal"); }
                });
            }
        }
    }

    let drain = async { while tasks.join_next().await.is_some() {} };
    if tokio::time::timeout(config.drain_timeout, drain)
        .await
        .is_err()
    {
        tasks.shutdown().await;
    }
}

async fn wait_for_shutdown(mut shutdown_rx: watch::Receiver<()>) {
    let _ = shutdown_rx.changed().await;
}

async fn serve_request(
    request: Request<Incoming>,
    remote_addr: std::net::SocketAddr,
    router: Router,
    max_body: usize,
    timeout: Duration,
    metrics: Option<Arc<dyn WebServerMetrics>>,
    request_semaphore: Option<Arc<Semaphore>>,
) -> Result<Response<BoxBody<Bytes, Infallible>>, Infallible> {
    let request_permit = match request_semaphore
        .as_ref()
        .map(|semaphore| semaphore.clone().try_acquire_owned())
        .transpose()
    {
        Ok(permit) => permit,
        Err(_) => {
            return Ok(into_hyper_response(HttpResponse::new(
                http::StatusCode::TOO_MANY_REQUESTS,
            )));
        }
    };
    let path = request.uri().path().to_string();
    let response = crate::http::run_request(&path, timeout, metrics.as_ref(), async move {
        let _request_permit = request_permit;
        let request = read_request(request, remote_addr, max_body).await?;
        Ok(crate::http::dispatch_request(request, &router).await)
    })
    .await;
    Ok(into_hyper_response(response))
}

async fn read_request(
    request: Request<Incoming>,
    remote_addr: std::net::SocketAddr,
    max_body: usize,
) -> Result<HttpRequest, WebServerError> {
    let (parts, mut body) = request.into_parts();
    if parts
        .headers
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok())
        .is_some_and(|length| length > max_body)
    {
        return Err(WebServerError::PayloadTooLarge);
    }
    let mut chunks = Vec::new();
    let mut size = 0usize;
    while let Some(frame) = body.frame().await {
        let frame = frame
            .map_err(|error| WebServerError::Http(format!("request body read failed: {error}")))?;
        if let Ok(data) = frame.into_data() {
            size = size.saturating_add(data.len());
            if size > max_body {
                return Err(WebServerError::PayloadTooLarge);
            }
            chunks.push(data);
        }
    }
    let body = if chunks.is_empty() {
        None
    } else {
        let mut combined = bytes::BytesMut::with_capacity(size);
        for chunk in chunks {
            combined.extend_from_slice(&chunk);
        }
        Some(combined.freeze())
    };
    Ok(HttpRequest {
        method: parts.method,
        uri: parts.uri,
        headers: parts.headers,
        body,
        remote_addr,
    })
}

fn into_hyper_response(mut response: HttpResponse) -> Response<BoxBody<Bytes, Infallible>> {
    let mut builder = Response::builder().status(response.status);
    if let Some(headers) = builder.headers_mut() {
        *headers = response.headers;
    }
    let body = if let Some(stream) = response.stream.take() {
        let stream = ReceiverStream::new(stream).map(|chunk| Ok(Frame::data(chunk)));
        BodyExt::boxed(StreamBody::new(stream))
    } else {
        let length: usize = response.body.iter().map(Bytes::len).sum();
        if let Some(headers) = builder.headers_mut()
            && !headers.contains_key(CONTENT_LENGTH)
        {
            headers.insert(CONTENT_LENGTH, length.into());
        }
        let mut body = bytes::BytesMut::with_capacity(length);
        for chunk in response.body {
            body.extend_from_slice(&chunk);
        }
        Full::new(body.freeze()).boxed()
    };
    builder.body(body).expect("valid HTTP response")
}

fn report_error(metrics: Option<&Arc<dyn WebServerMetrics>>, error: WebServerError) {
    if let Some(metrics) = metrics {
        metrics.error_occurred(&error);
    }
}
