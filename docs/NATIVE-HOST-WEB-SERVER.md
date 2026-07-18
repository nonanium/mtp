# MTP Web Server

`MTPWebServer` serves ordinary HTTP/3 routes and WebTransport MTP sessions through one QUIC endpoint. HTTP/3 requests are handled inside the server;
WebTransport sessions are returned by `accept()` for application messages.
`MTPWebServer` and `MTPHost` cannot bind the same IP and port.

## WebServerConfig

| Builder | Default | Purpose |
| --- | --- | --- |
| `route(path, handler)` | None | Register an exact-path HTTP/3 handler. |
| `route_method(method, path, handler)` | None | Register a method-specific handler. |
| `fallback(handler)` | None | Handle requests that match no route. |
| `mtp_path(path)` | `/` | Path for WebTransport extended CONNECT. |
| `max_request_body(bytes)` | 4 MiB | Maximum buffered HTTP/3 request body. |
| `max_connections(count)` | 256 | Maximum concurrent HTTP/3 connections. |
| `request_timeout(duration)` | 30 seconds | HTTP/3 request handling timeout. |
| `drain_timeout(duration)` | 10 seconds | Shutdown drain period. |
| `with_metrics(metrics)` | None | Receive connection, request, and error callbacks. |

The route and fallback builders return `Result` because duplicate routes and duplicate fallback handlers are rejected.

## HTTP/3 Requests and Responses

`Http3Request` contains `method`, `uri`, `headers`, and an optional buffered `body` represented by `bytes::Bytes`. `Http3Response::status`, `header`, and `body` build a buffered response. `try_header` returns an error for invalid header names or values. `stream` takes a `tokio::sync::mpsc::Receiver<Bytes>` for incremental response chunks.

```rust
use bytes::Bytes;
use http::{Method, StatusCode};
use tokio::sync::mpsc;
use mtp::webserver::{Http3Request, Http3Response, WebServerConfig};

async fn health(_request: Http3Request, response: Http3Response) -> Http3Response {
    response.status(StatusCode::OK).body("ok")
}

async fn stream_numbers(_request: Http3Request, response: Http3Response) -> Http3Response {
    let (tx, rx) = mpsc::channel::<Bytes>(10);
    tokio::spawn(async move {
        for number in 0..10 {
            if tx.send(Bytes::from(format!("{number}\n"))).await.is_err() {
                break;
            }
        }
    });
    response
        .status(StatusCode::OK)
        .header("content-type", "text/plain")
        .stream(rx)
}

let web = WebServerConfig::new()
    .route("/health", health)?
    .route_method(Method::GET, "/numbers", stream_numbers)?
    .fallback(|_request, response| async move {
        response.status(StatusCode::NOT_FOUND).body("not found")
    })?
    .mtp_path("/mtp");
```

## Starting and Accepting MTP Sessions

```rust
use mtp::{host::HostConfig, webserver::MTPWebServer};

let host = HostConfig::new(
    "0.0.0.0".parse()?,
    4433,
    std::fs::read("cert.pem")?,
    std::fs::read("key.pem")?,
);
let mut server = MTPWebServer::new(host, web).await?;

while let Some(connection) = server.accept().await? {
    // connection: WebMTPConnection
    while let Ok(message) = connection.receiver.receive().await {
        println!("received MTP message {}", message.get_id());
    }
}
```

`server.accept()` returns `Option<WebMTPConnection>` for each WebTransport session. HTTP/3 routes do not surface through `accept()` because the server dispatches them internally. `WebMTPConnection` retains the negotiated version, codec, request path, description, sender, and receiver used by native MTP connections.

WebTransport sessions are unauthenticated. With the `crypto` feature enabled, construction rejects any `AuthenticationPolicy` other than `Unauthenticated`. The connection has `AuthState::Unauthenticated` and a random 48-bit client ID when crypto fields are compiled in; `guest_id_generator` is not used by this adapter.

## Errors

`MTPWebServer::new` returns `CommunicationError` for certificate parsing, certificate loading, bind failures, and rejected authentication policy.
`accept()` returns `AcceptError` for a missing or unsupported version, a receive failure, or a send failure during the WebTransport opening handshake. HTTP route failures are reported through `WebServerMetrics::error_occurred` when metrics are configured. See [Errors](ERRORS.md) for shared error variants.

`WebServerMetrics` has these callbacks:

```rust
fn request_started(&self, path: &str)
fn request_completed(&self, path: &str, status: u16, duration: Duration)
fn error_occurred(&self, error: &WebServerError)
```

Errors include route misses, invalid requests, body-limit failures, handler timeouts, response construction failures, and transport failures. Supply the metrics object with `WebServerConfig::with_metrics`.
