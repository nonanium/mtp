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

## Relay metadata version

Protected relay metadata declares the reserved `RelayVersion` field as an unsigned integer. Builders currently emit version `1` automatically. Receivers select the metadata schema from this field before interpreting any version-specific fields. Missing versions are unsupported legacy relays, and unknown versions are rejected.

Relay format versions are independent of application type-map versions. A type-map version selects application-defined communication and data types. It does not select the protected relay metadata schema.

## Relay `CreatedAt`

The reserved `CreatedAt` field in relay metadata is an unsigned integer containing milliseconds elapsed since `1970-01-01T00:00:00Z`. It is not an ISO timestamp and it is not measured in seconds.

For example:

```text
2026-08-11T12:00:00.000Z
    ↓
Unix epoch milliseconds
    ↓
CreatedAt = 1786449600000
```

Native relay builders and browser relay senders use this unit. Verified browser metadata exposes `createdAt` as a `bigint`; native verified metadata exposes `u64`.

## Direct protected envelope

The high-level direct protected API signs an MTP-owned envelope before it is
encrypted for the recipient. Its reserved fields are `ProtectedVersion`,
`MessageType`, `FinalRecipientId`, `MessageId`, `CreatedAt`, and `Content`.
Receivers verify the envelope before dispatching application content and require
the signed message type and final recipient to match the outer communication
type and receiver. If the outer sender is present, it must match the signed
signer ID. `MessageId` and `CreatedAt` are authenticated; callers can pass a
replay guard to reject a previously accepted `(signerId, MessageId)` pair.
Native and browser replay guards both receive `CreatedAt` as authenticated
metadata, but the timestamp is not part of the replay key.
Verified SDK results expose the authenticated `protectedVersion` and
`finalRecipientId` alongside the application content.

Native applications use the same schema through `ProtectedMessageBuilder` and
the replay-explicit `open_protected_checked` or `open_protected_without_replay`
APIs; language bindings delegate envelope construction and opening to this
codec boundary.

Message processing uses the replay-required native APIs
`open_protected_checked` and `open_relay_metadata_checked` (or the equivalent
browser client path). Stored-message or forensic tooling must opt into the
explicit `*_without_replay` APIs. Native in-memory guards are bounded and
configurable; durable guards must perform an atomic insert-if-absent on
`(signer ID, MessageId)`.

Protected identifiers have semantic limits separate from the generic codec
blob limit. The default maximum `MessageId` is 256 UTF-8 bytes and relay
metadata is limited to 1 MiB of encoded metadata. Deployments can provide
stricter limits through the receive policy. Limits are checked after
authentication and before retained values enter replay or application state.

Transport-derived resource policies use a conservative decoder allocation
factor of `4 * max_message_size`, in addition to the frame-size output limit.
This factor accounts for owned wrapper, recipient, ciphertext, and decoded
value copies; it is an implementation admission policy rather than a wire
field.

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

Authentication attempts pass through a deployment-configurable limiter before
client lookup, key validation, challenge signing, or registration callbacks.
The default host configuration uses a bounded in-memory window. Hosts may key
limits by connection, peer identity, claimed client ID, or registration flow.
When identity concealment is enabled, an unknown client ID follows a dummy
challenge/proof path and receives the same generic authentication failure as a
known client with an invalid proof; disabling concealment restores the legacy
identity-specific response for deployments where IDs are public.

`ForceAuthentication` requires login or registration. `AllowAuthentication` accepts authenticated and unauthenticated clients. `Unauthenticated` rejects authentication attempts. The connection states are `Pending`, `Authenticated`, `Unauthenticated`, and `Failed`.

## Version Negotiation

The client sends one compiled-in protocol version. The host compares it with the versions in its registry and returns the selected version in the opening response. Subsequent frames use that version's type map. An unsupported version closes the connection with `AcceptError::UnsupportedVersion`.

The self-delimiting `DataValue` codec and the three-bit communication header begin at protocol version `3.0`. A peer offering an older codec version is rejected during version negotiation; the new decoder does not attempt legacy flag, ID, or crypto-container fallbacks.
