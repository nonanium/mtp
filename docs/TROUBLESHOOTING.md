# Troubleshooting

Use the failure stage to narrow the cause. MTP connections pass through TLS, the opening version frame, optional authentication, and application framing in that order.

Each entry identifies the symptom, diagnosis, fix, and prevention. Security labels identify workarounds that change certificate verification or keepalive.

## Diagnosis Flow

```text
Connection fails?
  -> TLS or WebTransport error? Check certificate, origin, and endpoint.
  -> UnsupportedVersion? Check compiled client version and host registry.
  -> AuthenticationFailed? Check policy, key lookup, and key bundles.
  -> CodecError? Check generated type maps and negotiated version.
  -> MessageTooLarge? Compare peer payload with Policy limits.
  -> Ping or pipe failure? Check the protocol reference or Pipes guide.
```

## TLS Connection Failures

**Security impact:** Safe when the certificate or pin is corrected. Insecure TLS is restricted to Development Mode.

Check the certificate before investigating MTP frames.

- With native clients, confirm the certificate chains to the system roots or pass the expected PEM certificate with `ClientConfig::with_pinned_pem`.
- With browser clients, confirm WebTransport is supported and that `serverCertificateHashes` contains the expected certificate hash when using a pinned certificate.
- For local self-signed certificates, pin the generated PEM certificate. The lower-level insecure mode requires both the `insecure-tls` feature and `MTP_INSECURE_TLS=1`.
- Confirm the hostname or IP address is present in the certificate's subject alternative names. A valid certificate with the wrong name still fails TLS.

Use [Security](SECURITY.md) for certificate trust and rotation rules.

## Version Negotiation Failures

An `AcceptError::UnsupportedVersion` means the client's compiled `PROTOCOL_VERSION` is absent from the host registry. Check that both peers were built from compatible `type-maps.yaml` files and that the host includes the required generated version.

An `AcceptError::MissingVersion` means the opening frame did not contain a valid `DataType::Version` string in `major.minor` form. Do not send an application frame before the opening version frame completes.

Use [Connector](CONNECTOR.md) for registry and migration rules.

## Authentication Failures

Check the selected `AuthenticationPolicy` first.

- `Unauthenticated` rejects login and registration by configuration.
- `AllowAuthentication` accepts both authenticated and guest connections.
- `ForceAuthentication` requires a registered login or a successful registration callback.

For login, verify the client ID lookup returns the expected public key bundle, the client keyring matches that bundle, and the client has the host public key used to verify the host signature. For registration, verify that `complete_register` persists the submitted public bundle and returns a valid client ID.

When `require_pq` is true, both Ed25519 and ML-DSA-65 keys and signatures must be available. Set `with_require_pq(false)` only for an explicit Ed25519-only compatibility deployment. Authentication sequence: [Protocol Reference](PROTOCOL-REFERENCE.md#authentication-flow).

## CodecError Failures

**Symptom:** `UnknownCommunicationType` or `UnknownDataType`.

**Diagnosis:** The peers use different generated type maps or the selected version does not define the value.

**Fix:** Build both peers from the same type-map configuration and send only types defined by the negotiated version.

**Prevention:** Treat generated type maps as versioned build artifacts.

`CodecError::UnknownVersion` means the codec was created for a version absent from its registry. `UnknownCommunicationType` and `UnknownDataType` mean the selected `TypeMap` has no mapping for the value being encoded. `MissingTypeMap` means a versioned value lost its retained negotiated map; `TypeMapMismatch` means it was combined with a value or codec for another version. Select the negotiated type map and do not send an unmapped variant.

`ReservedCommunicationType` means application code attempted to use a reserved wire ID. Use generated communication types instead of assigning protocol IDs manually. `MissingField` means a required typed field was not present.

`InvalidEncoding` indicates truncated, malformed, duplicate-field, reserved-kind, or structurally invalid bytes. `TooManyEntries` indicates that an array, container, or frame exceeds the codec's representable count or length. Protection operations return typed errors for malformed envelopes, authentication failures, invalid signatures, and missing recipients. The complete variant table is in [Errors](ERRORS.md).

## Frames and Message Limits

`MessageTooLarge` means the serialized frame exceeds the configured policy. Native transport defaults are a 16 MiB application message limit and a 64 KiB handshake limit. The browser SDK defaults `maxMessageSize` to 16 MiB.

`ParseCommunicationValue`, `ParseError`, or `CodecError::InvalidEncoding` means the received bytes do not match the length-prefixed frame and value format. Check that the sender writes the four-byte big-endian frame length exactly once and that the receiver reads exactly that many bytes. Frame layout: [Type Map](TYPE-MAP.md).

## Requests and Subscriptions

If `request()` times out, confirm that the peer sends a response with the same non-zero frame ID. If `responseType` is set, confirm that the response uses the expected communication type after the ID matches.

If a subscription callback does not run, confirm that the generated type map contains the message type and that the client is connected before the sender emits the frame. Enable the SDK logger to inspect state changes and errors.

## Protocol Pings

If `get_ping()` remains `None` or the connection closes after missed pings, check the keepalive configuration and responder mode in [Protocol Reference](PROTOCOL-REFERENCE.md#protocol-keepalive).

## Pipes

If a pipe handle resolves to `null` or `PipeError::Rejected`, the peer denied the request. If `receive_pipe()` never produces a request, use the connection facade instead of reading the underlying receiver directly. If a reader sees an error instead of EOF, the writer likely aborted the stream or the connection closed. Pipe lifecycle: [Pipes](PIPES.md).

## Browser Diagnostics

Use `MTPClient.isSupported()` before creating a browser client. Inspect browser console errors, WebTransport session state, certificate pins, and the SDK logger callback. Raw WASM bindings expose lower-level callbacks, but the SDK adds timeout and lifecycle handling.

| Browser or WebTransport signal | Meaning and next check |
| --- | --- |
| `WebTransportError.source = "stream"`, `streamErrorCode = 0` | The peer closed a one-frame stream normally in the supported browser behavior. Check session state before treating it as a failure. |
| `WebTransportError.source = "stream"`, non-zero `streamErrorCode` | A stream-level failure. Check whether the peer sent `STOP_SENDING` or reset the stream, then inspect the active pipe or frame. |
| `WebTransportError.source = "session"` | The WebTransport session failed. Check TLS, the endpoint, the `webtransport` CONNECT path, and server logs. |
| `WebTransportError` without `streamErrorCode` | The error is session-level or browser-specific. Inspect `error.message`, `error.source`, and the browser network panel. |
| Close code `0`, reason `mtp-webserver shutdown` | `MTPWebServer` performed an intentional shutdown. Reconnect after the process restarts. |

MTP logs stream-level `STOP_SENDING` and `RESET_STREAM` events with their `streamErrorCode`. QUIC transport error numbers are implementation-specific; use the browser's source, stream code, message, and server logs together.

## Development Mode

Use `mtp_crypto::tls::generate_self_signed_cert` for local certificates. Native insecure verification requires the `insecure-tls` feature and `MTP_INSECURE_TLS=1`; it disables certificate verification and is not a production fix.

## Getting More Help

Capture the negotiated version, connection state, error variant, endpoint, and relevant server log entries. Enable the SDK logger or Rust tracing, then remove credentials, private keys, and message contents before sharing a report.
