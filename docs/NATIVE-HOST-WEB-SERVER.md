# MTP Web Server

`MTPWebServer` is a complete browser-facing HTTPS server. TCP TLS serves HTTP/1.1 and HTTP/2, while UDP QUIC serves HTTP/3 and WebTransport. Both listeners use the same certificate, router, IP address, and numeric port. Ordinary HTTP requests are handled inside the server; WebTransport MTP sessions are returned by `accept()` for application messages.

`MTPWebServer` and the native `MTPHost` cannot bind the same IP and port. The TCP integration does not add the native MTP QUIC ALPN protocol to `MTPWebServer`.

The repository's server example serves the compiled web client at `/`, exposes status at `/health`, and accepts WebTransport sessions at the same origin. No second TCP server is required.

## WebServerConfig

| Builder | Default | Purpose |
| --- | --- | --- |
| `route(path, handler)` | None | Register an exact-path HTTP handler. |
| `route_method(method, path, handler)` | None | Register a method-specific handler. |
| `route_pattern(pattern, handler)` | None | Register a route with `{name}` single-segment parameters. |
| `route_pattern_method(method, pattern, handler)` | None | Register a method-specific parameterized route. |
| `fallback(handler)` | None | Handle requests that match no route. |
| `mtp_path(path)` | `/` | Path for WebTransport extended CONNECT. |
| `serve_tcp_https(enabled)` | `true` | Enable the TCP TLS listener for HTTP/1.1 and HTTP/2. |
| `max_tcp_connections(count)` | 256 | Maximum concurrent TCP TLS connections. |
| `tls_handshake_timeout(duration)` | 10 seconds | Maximum TCP TLS handshake duration. |
| `max_request_body(bytes)` | 4 MiB | Maximum request body across all HTTP versions. |
| `max_connections(count)` | 256 | Maximum concurrent QUIC/HTTP/3 connections. |
| `request_timeout(duration)` | 30 seconds | Handler timeout across all HTTP versions. |
| `drain_timeout(duration)` | 5 seconds | Graceful shutdown period across both transports. |
| `with_metrics(metrics)` | None | Receive connection, request, and error callbacks. |

The route and fallback builders return `Result` because duplicate routes and duplicate fallback handlers are rejected.

Parameterized routes use braces around a name and pass extracted values to the
handler as `RouteParams`. Each parameter matches exactly one path segment. Exact
routes take precedence over parameterized routes; among parameterized routes,
method-specific and more-specific routes take precedence.

```rust
use http::{Method, StatusCode};
use mtp::webserver::{HttpRequest, HttpResponse, RouteParams, WebServerConfig};

async fn profile(
    _request: HttpRequest,
    response: HttpResponse,
    params: RouteParams,
) -> HttpResponse {
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

## HTTP Requests and Responses

`HttpRequest` contains `method`, `uri`, `headers`, the connecting `remote_addr`, and an optional buffered `body` represented by `bytes::Bytes`. `HttpResponse::status`, `header`, and `body` build a buffered response. `try_header` returns an error for invalid header names or values. `stream` takes a `tokio::sync::mpsc::Receiver<Bytes>` for incremental response chunks. The deprecated `Http3Request` and `Http3Response` aliases remain available for source compatibility.

```rust
use bytes::Bytes;
use http::{Method, StatusCode};
use tokio::sync::mpsc;
use mtp::webserver::{HttpRequest, HttpResponse, WebServerConfig};

async fn health(_request: HttpRequest, response: HttpResponse) -> HttpResponse {
    response.status(StatusCode::OK).body("ok")
}

async fn whoami(request: HttpRequest, response: HttpResponse) -> HttpResponse {
    response.body(format!("client: {}", request.remote_addr))
}

async fn stream_numbers(_request: HttpRequest, response: HttpResponse) -> HttpResponse {
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
        println!("received MTP message {:?}", message.id());
    }
}
```
> `MTPWebServer::new` consumes a `HostConfig` (not an `MTPHost` instance). It creates its own QUIC endpoint and does not share a port with a running `MTPHost`.

`server.accept()` returns `Option<WebMTPConnection>` for each WebTransport session. Ordinary HTTP routes do not surface through `accept()` because the server dispatches them internally. `WebMTPConnection` retains the negotiated version, codec, request path, remote address, description, sender, and receiver used by native MTP connections.

## Deployment

For direct browser access, leave `serve_tcp_https(true)` enabled. The server advertises `h2` and `http/1.1` on TCP TLS and `h3` on UDP QUIC; WebTransport extended CONNECT is available only over HTTP/3. Both transports must present the certificate supplied by the same `HostConfig` and use the same origin port.

When a reverse proxy or another process owns TCP, use `WebServerConfig::new().serve_tcp_https(false)`. This retains the UDP HTTP/3/WebTransport endpoint and its shared router without claiming the TCP port.

With port `0` and TCP enabled, construction binds TCP first and binds UDP to the selected TCP port, so `local_addr()` reports the common address. With TCP disabled, Quinn selects the UDP port as before. `shutdown()` stops both accept loops, gracefully finishes active HTTP requests until `drain_timeout`, closes Quinn, and then aborts remaining work. `close()` and dropping the server stop both listeners immediately.

### Authentication

`MTPWebServer` does not impose its own authentication policy. It respects the `AuthenticationPolicy` set on the supplied `HostConfig`:

| Policy | Behavior |
|--------|----------|
| `Unauthenticated` (default) | No authentication handshake is performed. The connection has `AuthState::Unauthenticated` and a random full-width `u64` client ID. `guest_id_generator` is not used by this adapter. |
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

Errors include invalid requests, body-limit failures, handler timeouts, response write failures, TLS failures, and transport failures. Completion callbacks include the final HTTP status for every supported HTTP version. Supply the metrics object with `WebServerConfig::with_metrics`.
