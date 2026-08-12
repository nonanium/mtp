# MTP Architecture

MTP separates wire encoding, QUIC transport, connection policy, protocol negotiation, and application-facing clients.

```text
                         application
             ┌────────────────┴────────────────┐
             │                                 │
       Native client                       Browser SDK
       mtp-client                           mtp + WASM
             │                                 │
             └──────────────┬──────────────────┘
                            │ MTP frames
                  ┌─────────▼─────────┐
                  │ codec + type-map  │
                  │ versions, values  │
                  └─────────┬─────────┘
                            │
                  ┌─────────▼─────────┐
                  │ QUIC transport    │
                  │ framing, policy   │
                  └─────────┬─────────┘
                            │
          ┌─────────────────┴─────────────────┐
          │                                   │
      MTPHost                            MTPWebServer
      native QUIC                    HTTPS + HTTP/3 + WebTransport
          │                                   │
          └──────────────┬────────────────────┘
                         │
                 optional mtp-crypto
                 authentication and E2EE
```

`mtp-codec` owns `CommunicationValue` and `DataValue` serialization. A version-specific `TypeMap` translates generated type names to wire IDs.
`mtp-transport` writes each frame as a four-byte big-endian length followed by the frame bytes and applies message, timeout, queue, and stream limits.

The top row represents application entry points. Native Rust code calls the client or host crates directly. Browser code calls the TypeScript SDK, which uses generated WASM bindings for the same codec and WebTransport session.
Both clients exchange the same MTP frames with a host.

The middle row is shared protocol machinery. The type map determines numeric IDs, the codec serializes self-delimiting `DataValue` payloads, and transport framing places each serialized frame on a QUIC stream. `CommunicationValue` contains only routing metadata and one generic payload. Protection is a composable value property (`Signed<Value>` or `Encrypted<Value>`), not a transport or communication-frame mode, so the frame and transport layers never infer encryption or signature state from header flags. This is why a type-map or codec change must be compiled into both peers before the new message can be exchanged.

The bottom row shows the two server entry points. `MTPHost` is a native QUIC endpoint for native MTP clients. `MTPWebServer` owns TCP HTTPS and UDP HTTP/3/WebTransport listeners on the same numeric port, reuses one `HostConfig` and router, and provides the same `accept()`-based MTP session API. Its QUIC listener still uses only the `h3` ALPN, so it cannot share its UDP address with the native MTP ALPN endpoint. Choose `MTPHost` for native clients and `MTPWebServer` for browser-facing HTTP and WebTransport.

`mtp-crypto` is an optional cross-cutting layer used by authenticated native connections, WebTransport connections, and browser E2EE; TLS remains the transport security layer in both paths.

MTP exposes protection as independent capabilities rather than prescribing an
application topology:

- A stateless protected `DataValue` composes `Signed<Value>` and
  `Encrypted<Value>` in the order selected by the application.
- A direct protected frame carries a protected value under its application
  communication type and routes it straight to the frame receiver.
- A sealed relay uses the reserved `Relay` communication type, an absent outer
  sender, and separately protected metadata and content. Applications choose
  the next hop, final recipient, and both recipient sets.
- A stateful encrypted session advances symmetric send and receive chains for
  an active exchange.
- An encrypted pipe protects an ordered byte stream with transcript-bound
  records and an authenticated final record; forward-secure duplex setup is an
  explicit option.

These constructions are peers. Relay is optional and is not the default path
for encrypted application messages. Use direct protected frames when no
intermediate component needs relay metadata; use sealed relay when routing or
store-and-forward topology requires a distinct metadata-access boundary.

`mtp-host` performs version negotiation and native authentication before returning an `MTPConnection`. `mtp-webserver` routes HTTP/1.1, HTTP/2, and HTTP/3 requests through one route table and surfaces WebTransport sessions through `accept()`. WebTransport MTP sessions support the same optional cryptographic authentication as native hosts when the `crypto` feature is enabled.

The [native client](NATIVE-CLIENT.md), [WASM client](WASM-CLIENT.md), [native host](NATIVE-HOST.md), and [web server](NATIVE-HOST-WEB-SERVER.md) guides cover the public APIs for each boundary. The web server guide should be read as the host API for browser-facing deployments; it accepts the same `HostConfig` and authentication callbacks as the native host.
