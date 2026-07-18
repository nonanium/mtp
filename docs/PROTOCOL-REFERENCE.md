# Protocol Reference

This document owns the connection lifecycle, protocol keepalive, and application authentication flow. API guides link here for configuration.

## Connection Lifecycle

```text
bind -> accept QUIC -> negotiate version -> authenticate if enabled
     -> dispatch application frames -> close or drain
```

The opening version frame is processed before application messages. The host selects a registered type map. Authentication then completes according to the host policy. A connection is returned to the application only after these stages complete.

## Protocol Keepalive

The client sends an MTP `Ping` communication value with a frame ID. The host returns a `Pong` with the same ID when automatic responses are enabled. The client records the matched round-trip duration and closes after its configured missed-Ping limit. These frames are handled by the keepalive dispatcher and do not reach ordinary message handlers.

If automatic responses are disabled, the application must read Ping frames and send compatible Pong frames. Keepalive configuration is documented in the [native client](NATIVE-CLIENT.md) and [native host](NATIVE-HOST.md) guides.

## Authentication Flow

```text
Client                                      Host
  |                                           |
  | Identification or Register, unsigned     |
  |------------------------------------------>|
  |                                           | generate challenge
  | Challenge plus host signature             |
  |<------------------------------------------|
  | ChallengeResponse plus client signature   |
  |------------------------------------------>|
  |                                           | verify proof and assign identity
  | IdentificationResponse plus host signature|
  |<------------------------------------------|
```

Login proof binds the protocol version, client ID, host challenge, and client nonce. Registration proof binds the protocol version, public key bundle, host challenge, and client nonce. The host challenge is generated per connection.

`ForceAuthentication` requires login or registration. `AllowAuthentication` accepts authenticated and unauthenticated clients. `Unauthenticated` rejects authentication attempts. The connection states are `Pending`, `Authenticated`, `Unauthenticated`, and `Failed`.

## Version Negotiation

The client sends one compiled-in protocol version. The host compares it with the versions in its registry and returns the selected version in the opening response. Subsequent frames use that version's type map. An unsupported version closes the connection with `AcceptError::UnsupportedVersion`.
