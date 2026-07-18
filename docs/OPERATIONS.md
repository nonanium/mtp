# Operations

## Monitoring

Expose counters and gauges around the host and transport callbacks:

| Metric | Interpretation |
| --- | --- |
| Accepted and rejected connections | Compare admission failures with traffic volume. A rise in rejected connections points to certificate, version, policy, or authentication problems. |
| Active connections and active pipe streams | Capacity currently consumed by sessions and raw streams. |
| Authentication failures and timeouts | Credential, policy, or reachability failures during the handshake. |
| Unsupported protocol versions | Clients that require a version still absent from the registry. |
| Message-too-large and decode errors | Peer or schema mismatch, malformed input, or an overly small policy limit. |
| Request latency and request timeout count | Application handler time and transport deadline pressure. |
| Ping round-trip time and missed pings | Peer reachability and path latency. |
| Pipe accept, reject, EOF, and reset counts | Application admission and stream completion behavior. |

Implement `WebServerMetrics` for HTTP/3 request and error callbacks. Record the request path, status, duration, and `WebServerError` category without logging credentials, private keys, or message contents. Export host callback results through the application's metrics system for native deployments.

## Tuning

`Policy::default()` uses a 16 MiB message limit, a 64 KiB handshake limit, a 30 second read timeout, a 30 second idle timeout, a receiver queue capacity of 1000, and 128 concurrent stream tasks.

For low-latency request traffic, use `SendMode::SingleStreamPerMessage`, keep message sizes bounded, use shorter read and idle timeouts, and keep queue and concurrency limits near the amount of work the application can process.

For high-throughput bulk traffic, use persistent streams, raise `max_message_size` only when messages require it, and size `receiver_queue_capacity` and `max_concurrent_stream_tasks` for available memory and downstream processing capacity. Use pipes for large sequential byte streams instead of increasing message limits.

Every queued frame consumes memory until the application reads it. Test policy changes with realistic peer counts and payload sizes before deployment.

## Deployment

### Certificate Rotation

Publish the replacement certificate or pin before changing the server. Update clients to trust the replacement while the current certificate remains valid, switch the server, then remove the old trust value after clients migrate. Use system roots when certificate rotation is managed by the issuing authority.

### Key Backup

Back up host keyrings and client keyrings as protected secrets. Test restoring a backup before relying on it. Keep private key files owner-only on Unix, protect backup access, and store public key bundles separately from private material.

### Graceful Shutdown

Stop accepting new connections, reject new work at the application layer, and allow active requests and pipe writers to finish. Send a normal connection close, wait for the configured drain period, then force-close remaining QUIC sessions. For `MTPWebServer`, call `shutdown()` after the accept loop stops; Headits `drain_timeout` controls the drain period.
