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
      native QUIC                         HTTP/3 + WebTransport
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

The middle row is shared protocol machinery. The type map determines numeric IDs, the codec serializes values, and transport framing places each serialized frame on a QUIC stream. This is why a type-map change must be compiled into both peers before the new message can be exchanged.

The bottom row shows the two server entry points. `MTPHost` is a native QUIC endpoint for native MTP clients. `MTPWebServer` is an HTTP/3 server that reuses `HostConfig` and provides the same `accept()`-based MTP session API, adding web routing and WebTransport support for browser clients. Because they rely on different QUIC ALPN protocols (native MTP vs. `h3`), they must bind to different IP/port pairs and should not be enabled as Cargo features in the same binary. Choose `MTPHost` when you only serve native clients; choose `MTPWebServer` when you need HTTP/3 routes or browser-based MTP clients.

`mtp-crypto` is an optional cross-cutting layer used by authenticated native connections, WebTransport connections, and browser E2EE; TLS remains the transport security layer in both paths.

`mtp-host` performs version negotiation and native authentication before returning an `MTPConnection`. `mtp-webserver` routes HTTP/3 requests and WebTransport sessions through its endpoint. WebTransport MTP sessions support the same optional cryptographic authentication as native hosts when the `crypto` feature is enabled.

The [native client](NATIVE-CLIENT.md), [WASM client](WASM-CLIENT.md), [native host](NATIVE-HOST.md), and [web server](NATIVE-HOST-WEB-SERVER.md) guides cover the public APIs for each boundary. The web server guide should be read as the host API for browser-facing deployments; it accepts the same `HostConfig` and authentication callbacks as the native host.
