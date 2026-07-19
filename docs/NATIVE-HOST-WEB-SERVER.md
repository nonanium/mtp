# MTP Web Server

`MTPWebServer` serves ordinary HTTP/3 routes and WebTransport MTP sessions through one QUIC endpoint. HTTP/3 requests are handled inside the server;
WebTransport sessions are returned by `accept()` for application messages.
`MTPWebServer` and `MTPHost` cannot bind the same IP and port.

The repository's combined server example registers `/` on `MTPWebServer` and
returns `OK` while the process is running. The route is served over HTTP/3 at
`https://localhost:8080/` on the same QUIC endpoint as WebTransport MTP sessions.

## WebServerConfig

| Builder | Default | Purpose |
| --- | --- | --- |
| `route(path, handler)` | None | Register an exact-path HTTP/3 handler. |
| `route_method(method, path, handler)` | None | Register a method-specific handler. |
| `route_pattern(pattern, handler)` | None | Register a route with `{name}` single-segment parameters. |
| `route_pattern_method(method, pattern, handler)` | None | Register a method-specific parameterized route. |
| `fallback(handler)` | None | Handle requests that match no route. |
| `mtp_path(path)` | `/` | Path for WebTransport extended CONNECT. |
| `max_request_body(bytes)` | 4 MiB | Maximum buffered HTTP/3 request body. |
| `max_connections(count)` | 256 | Maximum concurrent HTTP/3 connections. |
| `request_timeout(duration)` | 30 seconds | HTTP/3 request handling timeout. |
| `drain_timeout(duration)` | 10 seconds | Shutdown drain period. |
| `with_metrics(metrics)` | None | Receive connection, request, and error callbacks. |

The route and fallback builders return `Result` because duplicate routes and duplicate fallback handlers are rejected.

Parameterized routes use braces around a name and pass extracted values to the
handler as `RouteParams`. Each parameter matches exactly one path segment. Exact
routes take precedence over parameterized routes; among parameterized routes,
method-specific and more-specific routes take precedence.

```rust
use http::{Method, StatusCode};
use mtp::webserver::{Http3Request, Http3Response, RouteParams, WebServerConfig};

async fn profile(
    _request: Http3Request,
    response: Http3Response,
    params: RouteParams,
) -> Http3Response {
    let Some(userid) = params.get("userid") else {
        return response.status(StatusCode::BAD_REQUEST);
    };

    response
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(format!(r#"{{"userid":"{}"}}"#, userid))
}

let web = WebServerConfig::new()
    .route_pattern_method(
        Method::GET,
        "/api/get/{userid}/profile.json",
        profile,
    )?;
```

`GET /api/get/user-123/profile.json` invokes `profile` with
`params["userid"] == "user-123"`. Percent-encoded parameter values are
UTF-8 decoded before being passed to the handler. Malformed encoded values do
not match the route. Query strings remain available through
`request.uri.query()` and are not part of route matching.

## HTTP/3 Requests and Responses

`Http3Request` contains `method`, `uri`, `headers`, the connecting `remote_addr`, and an optional buffered `body` represented by `bytes::Bytes`. `Http3Response::status`, `header`, and `body` build a buffered response. `try_header` returns an error for invalid header names or values. `stream` takes a `tokio::sync::mpsc::Receiver<Bytes>` for incremental response chunks.

```rust
use bytes::Bytes;
use http::{Method, StatusCode};
use tokio::sync::mpsc;
use mtp::webserver::{Http3Request, Http3Response, WebServerConfig};

async fn health(_request: Http3Request, response: Http3Response) -> Http3Response {
    response.status(StatusCode::OK).body("ok")
}

async fn whoami(request: Http3Request, response: Http3Response) -> Http3Response {
    response.body(format!("client: {}", request.remote_addr))
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
    .route("/whoami", whoami)?
    .route_method(Method::GET, "/numbers", stream_numbers)?
    .fallback(|_request, response| async move {
        response.status(StatusCode::NOT_FOUND).body("not found")
    })?
    .mtp_path("/mtp");
```

## Starting and Accepting MTP Sessions

```rust
use mtp::{host::HostConfig, webserver::MTPWebServer};

let host_config = HostConfig::new(
    "0.0.0.0".parse()?,
    4433,
    std::fs::read("cert.pem")?,
    std::fs::read("key.pem")?,
);
let mut server = MTPWebServer::new(host_config, web).await?;

while let Some(connection) = server.accept().await? {
    // connection: WebMTPConnection
    while let Ok(message) = connection.receive().await {
        println!("received MTP message {}", message.get_id());
    }
}
```
> `MTPWebServer::new` consumes a `HostConfig` (not an `MTPHost` instance). It creates its own QUIC endpoint and does not share a port with a running `MTPHost`.

`server.accept()` returns `Option<WebMTPConnection>` for each WebTransport session. HTTP/3 routes do not surface through `accept()` because the server dispatches them internally. `WebMTPConnection` retains the negotiated version, codec, request path, remote address, description, sender, and receiver used by native MTP connections.

### Authentication

`MTPWebServer` does not impose its own authentication policy. It respects the `AuthenticationPolicy` set on the supplied `HostConfig`:

| Policy | Behavior |
|--------|----------|
| `Unauthenticated` (default) | No authentication handshake is performed. The connection has `AuthState::Unauthenticated` and a random 48-bit client ID. `guest_id_generator` is not used by this adapter. |
| `AllowAuthentication` | The server accepts the first message. If it is an `Identification` or `Register` message, a full challenge-response handshake is performed. If it is an ordinary opening message, the connection remains unauthenticated. |
| `ForceAuthentication` | The server requires a valid `Identification` or `Register` message as the first frame and performs the challenge-response handshake. Any other opening message is rejected. |

When authentication is required or allowed and the client presents credentials, the server performs the same Ed25519/ML-DSA challenge-response handshake used by native MTP host connections:

1. The client sends `Identification` (with a client ID) or `Register` (with a public-key bundle).
2. The server looks up or accepts the client's public keys, generates a random 128-bit server nonce, and signs a challenge payload with its host keyring.
3. The client responds with a proof signed by its own keys.
4. The server verifies the proof, assigns the client ID, and sends a final signed response.

On success, the connection has `AuthState::Authenticated`, the assigned `client_id`, and `client_public_key` populated. On failure, `accept()` returns `AcceptError::AuthenticationFailed` (or `AcceptError::AuthenticationTimedOut` if the handshake exceeds `host_config.auth_timeout`).

`MTPWebServer::new` returns `CommunicationError` for certificate parsing, certificate loading, and bind failures. It does **not** reject `HostConfig` based on `AuthenticationPolicy`; any policy is accepted at construction time.


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
