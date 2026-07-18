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

The bottom row shows the two server entry points. `MTPHost` owns a native QUIC endpoint. `MTPWebServer` owns an HTTP/3 endpoint that also accepts WebTransport MTP sessions. They cannot bind the same IP and port. `mtp-crypto` is an optional cross-cutting layer used by authenticated native connections and browser E2EE;
TLS remains the transport security layer in both paths.

`mtp-host` performs version negotiation and native authentication before returning an `MTPConnection`. `mtp-webserver` routes HTTP/3 requests and WebTransport sessions through its endpoint. It currently accepts only unauthenticated WebTransport MTP sessions.

The [native client](NATIVE-CLIENT.md), [WASM client](WASM-CLIENT.md), [native host](NATIVE-HOST.md), and [web server](NATIVE-HOST-WEB-SERVER.md) guides cover the public APIs for each boundary.
