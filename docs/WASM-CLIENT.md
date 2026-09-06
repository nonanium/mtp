# MTP WASM Client

The browser client is exposed through the `mtp` npm package. Most applications should use the SDK-first `MTPClient` API; direct generated WASM bindings remain available from `mtp/raw` for advanced integrations.

## Browser Compatibility

The SDK requires the browser to expose `WebTransport`. `MTPClient.isSupported()` is the runtime check. A browser without WebTransport cannot connect through this client.

| Requirement | Check |
| --- | --- |
| WebTransport API | `MTPClient.isSupported()` |
| Certificate trust | Browser validation or `serverCertificateHashes` |
| Secure context | Serve the application from HTTPS where required by the browser |
| Generated bindings | Run the Vite integration during development and build |

## Package Entry Points

```typescript
import { MTPClient } from "mtp";
import init, { WasmClient } from "mtp/raw";
import { mtp } from "mtp/vite";
```

- `mtp` exports the SDK-first `MTPClient` wrapper.
- `mtp/raw` exports the generated `wasm-bindgen` module and raw classes/functions.
- `mtp/vite` exports the Vite plugin that builds app-specific WASM bindings from your `type-maps.yaml`.
- `mtp/type-map` exports generated TypeScript unions for communication and data type names.

## Vite Type-Map Workflow

Browser apps provide their own type map. The Vite plugin runs `wasm-pack` during dev and build with `MTP_TYPE_MAPS` set, writes generated output under `node_modules/.vite/mtp/` by default, and aliases `mtp/raw` plus `mtp/type-map` to that generated output. Configuration: [Type Map](TYPE-MAP.md).

The browser build uses the map named by `protocol_version` and includes the
reserved MTP names. It does not advertise application names from other map
versions, because the generated WASM client is compiled for that one protocol
version. The selected version must exist in `type_maps`.

You do not need to publish, fork, or copy an app-specific generated WASM package.

The [web client example](../tests/fixtures/example/web-client/src/main.ts) shows the entry point. Its [Vite configuration](../tests/fixtures/example/web-client/vite.config.ts) shows the generated binding integration.

## SDK Quick Start

```typescript
import { MTPClient } from "mtp";

const client = await MTPClient.create({
  url: "https://host.example.com:4433",
  hostPublicKey,
  credentials,
  storage,
  serverCertificateHashes: ["sha-256:abcd1234..."],
  maxMessageSize: 1_000_000,
  authTimeoutMs: 30_000,
  pings: true,
  logger: (event) => console.log(event),
});

const unsubscribe = client.subscribe("SomeType", (message) => {
  console.log(message.type, message.data);
});

if (client.credentials?.clientId == null) {
  await client.register();
} else {
  await client.connect();
}
await client.send("SomeType", { value: "hello" });

const response = await client.request(
  "SomeRequestType",
  { id: "abc" },
  { responseType: "SomeResponseType" },
);

client.raw.client;   // underlying WasmClient instance
client.raw.bindings; // generated raw WASM module exports

unsubscribe();
client.disconnect();
```

`MTPClient.isSupported()` checks whether the current browser exposes WebTransport:

```typescript
if (!MTPClient.isSupported()) {
  throw new Error("WebTransport is not available in this browser");
}
```

## MTPClient Options

| Option | Default | Purpose |
| --- | --- | --- |
| `url` | Required | WebTransport endpoint. |
| `descriptor` | None | Client label sent during connection setup. |
| `hostPublicKey` | None | Host public key bundle for authenticated login or registration. |
| `credentials` | None | Existing client ID and serialized keyring. |
| `credentialsStorageKey` | `mtp:credentials` | Key used by configured credential storage. |
| `storage` | None | Sync or async credential storage adapter. |
| `serverCertificateHashes` | Omitted | WebTransport certificate pins. |
| `maxMessageSize` | 16 MiB | Inbound and outbound frame limit. Values below frame overhead are rejected by the transport. |
| `authTimeoutMs` | No SDK timeout | Login and registration timeout. `undefined` leaves the promise pending until transport or peer failure. |
| `requestTimeoutMs` | 30 seconds | Default `request()` timeout. |
| `pings` | `false` | Protocol pings, or an object with `intervalMs`. |
| `logger` | No-op | Receives SDK state and error events. |
| `schemas` | None | Client-wide request and response schema registry. |
| `throwProtocolErrors` | `false` | Reject requests whose correlated response is an `Error*` frame. |
| `onValidationError` | No-op | Receives subscription validation failures. |
| `sessionStorage` | In-memory | E2EE session state storage. |
| `encryptedSecretProvider` | In-memory | Independent caller-managed encrypted secret storage. |
| `defaultSignatureVerificationPolicy` | `"ed25519"` | Receiver policy for protected signatures. |

`wasm` selects a custom generated WASM module. `MTPClient.create` validates positive safe-integer values for the numeric limits and timeout options.

## Differences from Native Client

The browser SDK uses WebTransport and JavaScript promises. The native client uses Rust futures, direct QUIC configuration, and `MTPConnection` handles. Browser pipes expose promise-based readers and writers; native pipes implement Tokio I/O traits.

### Native and Browser Credential Persistence

The `storage` option supplies the credential adapter. The adapter stores the client ID and serialized keyring after registration and returns them for later connections. The SDK does not select `localStorage` or IndexedDB for an application. Treat the serialized keyring as private key material.

`sessionStorage` and `encryptedSecretProvider` are separate caller-managed
stores. The latter exchanges `MTPEncryptedSecretRecord` values through
`set`, `get`, and `delete`; the `MTPClient` convenience methods are named
`setEncryptedSecret`, `getEncryptedSecret`, and `deleteEncryptedSecret`.
`MTPSessionManager` does not automatically route session state through the
provider. If session material must be encrypted at rest, the caller must make
that coordination explicit in its `MTPSessionStorage` implementation. Secret
IDs are opaque to MTP, so a caller can map its own state to the ID while
choosing the backing store and protecting its wrapping key.

### Direct Protected Messages

Use `sendProtected` when the destination is the frame receiver and no
intermediate relay needs a separately encrypted metadata layer. It keeps the
application communication type on the outer frame and encrypts an MTP-owned
signed envelope for the exact recipient bundles supplied by the caller. The
envelope authenticates `ProtectedVersion`, `MessageType`, `FinalRecipientId`,
`MessageId`, `CreatedAt`, and `Content`. The opening operation checks the
authenticated type and final recipient against the outer frame.

```typescript
await client.sendProtected("ProtectedMessage", { Content: "hello" }, {
  receiverId: recipientId,
  recipients: [recipientPublicKey],
  signaturePurpose: 0x40,
  encryptionPurpose: 0x41,
  exposeSender: false,
});
```

The protection purposes are application-defined domain-separation values.
`exposeSender` controls only the outer frame sender; the protected value remains
signed in either case. If `identity` is omitted, the SDK uses stored registered
credentials and rejects the operation when no usable protection identity is
available.

An unauthenticated connection can still send a protected value when the caller
provides an explicit `identity` with the signer ID and keyring. The connection's
authentication state and the protected signer's identity are independent.

When `signatureSuite` is omitted, protected send helpers use Ed25519 even when
the signing keyring also contains post-quantum keys. This matches the default
receiver policy. Use `signatureSuite: "dual"` together with
`signaturePolicy: "dual"` when both sides explicitly require hybrid
signatures.

Open a direct protected frame with the recipient keyring and a resolver that
receives the claimed, unverified signer ID only as a trusted-key lookup key:

```typescript
const message = await client.openProtected(frame, {
  recipient: {
    id: recipientId,
    keyring: recipientKeyring,
    keyringHistory: previousRecipientKeyrings,
  },
  expectedReceiverId: recipientId,
  expectedSignerId: signerId,
  resolveSignerPublicKeys: (id) => signerDirectory.get(id) ?? [],
  signaturePolicy: "dual",
  signaturePurpose: 0x40,
  encryptionPurpose: 0x41,
  replayGuard,
});

console.log(message.type, message.signerId, message.messageId, message.data);
```

`protectedVersion`, `finalRecipientId`, `signerId`, `messageId`, and `createdAt`
are taken from the verified protected envelope. `outerSender`, when present,
must equal the authenticated signer. `messageId` is an unsigned 128-bit
`bigint`.
Protected application data may be any supported MTP `DataValue`, including
scalar, byte, array, and container values. Direct opening uses a bounded
process-local duplicate-suppression guard by default. The bounded cache can
evict old entries, so supply a durable `replayGuard` keyed by authenticated
signer and message ID when replay protection must survive eviction, reloads, or
multiple receiver processes. The guard also receives authenticated
`createdAt` metadata, which is not part of the replay key.
`subscribeProtected` uses the same opening and verification path:

```typescript
const unsubscribe = client.subscribeProtected(
  "ProtectedMessage",
  (message, frame) => handleMessage(message.data, frame),
  {
    recipient: { id: recipientId, keyring: recipientKeyring },
    resolveSignerPublicKeys: (id) => signerDirectory.get(id) ?? [],
    signaturePolicy: "dual",
    signaturePurpose: 0x40,
    encryptionPurpose: 0x41,
  },
);
```

Each `subscribeProtected` registration owns its own bounded default replay
guard, so multiple handlers receive the same raw frame through the WASM
fan-out dispatcher. Pass the same caller-owned `replayGuard` deliberately when
several subscriptions should share replay state.

### Sealed Relay Messages

`sendSealedRelay` uses the reserved opaque `Relay` communication type. Its
inner message type must be an application communication type, not an MTP
control type. The outer frame contains no sender and exposes only the next-hop
receiver. The
signed relay metadata contains the generic `signerId`, `finalRecipientId`,
`messageId`, `createdAt`, application `metadata`, and an opaque encrypted
content value. `createdAt` is generated as Unix epoch milliseconds. For
example, `2026-08-11T12:00:00.000Z` is `1786449600000`.

```typescript
const data = { Content: "hello" };

await client.sendSealedRelay("ProtectedMessage", data, {
  finalRecipientId,
  nextHop: { kind: "iota", id: nextHopId },
  metadataRecipients: [
    relayPublicKey,
    recipientPublicKey,
  ],
  contentRecipients: [
    recipientPublicKey,
  ],
  metadata: {
    ExampleMetadata: "routing context",
  },
});

client.subscribeSealedRelay(
  "ProtectedMessage",
  (message, frame) => handleMessage(message.data, frame),
  {
    recipient: {
      id: finalRecipientId,
      keyring: recipientKeyring,
    },
    expectedSignerId: signerId,
    resolveSignerPublicKeys: () => [senderPublicKey],
  },
);
```

The caller supplies the exact metadata and content recipient sets; the SDK
does not infer application topology. Set `signaturePolicy: "dual"` to require
hybrid signatures explicitly, and install a durable `replayGuard` so a valid
`(signerId, messageId)` is dispatched only once.

Each sealed-relay or metadata subscription likewise gets an independent
bounded default guard. This preserves fan-out when multiple handlers inspect
the same outer `Relay` frame; an explicitly supplied guard is shared by the
subscriptions that receive it.

Applications choose between direct protected delivery and sealed relay based
on topology and metadata-access requirements. Prefer `sendProtected` for a
direct destination. Use `sendSealedRelay` when a next hop must route or store a
message and the application needs metadata recipients to differ from content
recipients. Neither construction requires connection authentication, although
the host can associate an authenticated connection with its registered MTP
identity.

For metadata-only access, call `openRelayMetadata` or subscribe with
`subscribeRelayMetadata`. These operations authenticate the metadata and
expose `encryptedContent` for forwarding without attempting content
decryption. A final recipient calls `openRelayContent` after metadata
verification; the returned `MTPVerifiedRelayContent` includes the application
type and data plus `signerId`, `finalRecipientId`, `messageId`, `createdAt`,
and generic metadata fields. These are authenticated protected identities, not
the clear outer sender and next-hop receiver.
Relay content inherits the authenticated metadata's `signaturePolicy` when no
content override is supplied. A different content policy is rejected so the
two relay layers cannot be verified under conflicting rules.
Metadata passed to a `subscribeRelayMetadata` handler is callback-scoped and is
disposed after the handler resolves. Do not retain it for a later
`openRelayContent` call; use `openRelayMetadata` directly when a longer-lived
verified capability is needed, and call `dispose()` when finished.
When signer key history is used, `signerPublicKeys` exposes the trusted
candidates, `matchedSignerKeyIndex` identifies the key that verified the
metadata, and `matchedSignerPublicKey` returns that exact bundle.

Protected receive operations accept an optional `recipient` decryption
identity. Its `keyring` controls decryption and its optional `id` is used only
for final-recipient validation. The identity is independent from connection
authentication. Metadata opening does not require the identity ID to match the
clear next-hop receiver, so a forwarded frame can be opened by a metadata
recipient or final recipient with the appropriate keyring. When `recipient` is
omitted, stored registered credentials remain the convenience fallback.

To open values encrypted for a rotated recipient, provide `keyringHistory` on
the decryption identity. The current `keyring` is tried first, followed by
history entries from newest to oldest. Exact duplicate byte sequences are
removed without changing the caller's input arrays. An empty current keyring
or an empty history entry is rejected.

Generic MTP `DataValue` inputs accept `bigint` for exact integer values. An
integral JavaScript `number` outside the safe-integer range is rejected, so it
cannot silently become an imprecise float. Use `bigint` for large signed or
unsigned integers.

For streams, prefer `createEncryptedPipe` and `acceptEncryptedPipe`; they bind
the actual pipe ID and local identity automatically. The lower-level
`initiateMTPPipeSession` API also accepts multiple recipient bundles for a
group bootstrap. Group membership changes require a fresh session ID and
recipient set. Live calls that need forward secrecy can use the exported
duplex `initiateMTPForwardSecurePipeSession` and
`acceptMTPForwardSecurePipeSession` helpers.

The convenience pipe methods intentionally require registered client
credentials because they use the connection's registered identity as the
endpoint identity. Use the lower-level session functions when transport
authentication and cryptographic endpoint identity must remain independent.

Receive-side signature policy is independent from the recipient keyring. Use
`signaturePolicy` on protected receive and encrypted-pipe accept operations,
or configure `defaultSignatureVerificationPolicy` on the client. The sender's
`signatureSuite` selects how local values are signed and is a separate choice.
Both sender and receiver default to Ed25519; `dual` is always an explicit
choice on each side.

### Native and Browser Certificate Checks

WebTransport certificate pins must match the server certificate hash. A pin mismatch is a TLS failure, not an MTP authentication failure. Check the browser network panel, endpoint origin, and WebTransport CONNECT path before inspecting frames.

## Credentials And Storage

Authenticated connections need stable key material. Pass `credentials` when you already have a client ID and serialized keyring, or pass a small `storage` object and let the SDK persist credentials after registration.

```typescript
const storage = {
  getItem: (key: string) => localStorage.getItem(key),
  setItem: (key: string, value: string) => localStorage.setItem(key, value),
  removeItem: (key: string) => localStorage.removeItem(key),
};

const client = await MTPClient.create({
  url: "https://host.example.com:4433",
  hostPublicKey,
  storage,
});

const clientId = client.credentials?.clientId == null
  ? await client.register()
  : (await client.connect(), client.credentials.clientId);
```

The storage contract is intentionally small and may be sync or async:

```typescript
interface MTPCredentialStorage {
  getItem(key: string): string | null | Promise<string | null>;
  setItem(key: string, value: string): void | Promise<void>;
  removeItem(key: string): void | Promise<void>;
}
```

`credentials` can also be supplied directly:

```typescript
const client = await MTPClient.create({
  url: "https://host.example.com:4433",
  hostPublicKey,
  credentials: {
    clientId: 42n,
    keyring: savedKeyringBytes,
  },
});

await client.connect();
```

`client.credentials` returns the current public credential object. Call `clearCredentials()` to remove in-memory credentials and delete the configured storage key.

## Connection Methods

- `connect()` opens a connection. If credentials include a `clientId` and `hostPublicKey` is available, it uses authenticated login; otherwise it uses unauthenticated connect.
- `register()` performs authenticated registration and persists the assigned client ID when storage is configured.
- `disconnect()` stops protocol pings and closes the underlying WebTransport session.

For certificate pinning, pass WebTransport certificate hashes:

```typescript
await MTPClient.create({
  url: "https://host.example.com:4433",
  serverCertificateHashes: ["sha-256:abcd1234..."],
});
```

If hashes are omitted, the browser uses its normal TLS root store.

`maxMessageSize` caps inbound and outbound MTP frames before buffering/sending.
`authTimeoutMs` bounds connect/login/register promises at the SDK layer.
`requestTimeoutMs` sets the default timeout for `request()` calls; a request can override it with `timeoutMs` in its options.

## Streams

The browser client uses one WebTransport session per `MTPClient` instance.
`send()`, `request()`, and `subscribe()` all operate over that session; the SDK does not expose browser stream objects directly.

Use the normal message APIs to send and receive over that session:

```typescript
const client = await MTPClient.create({ url, hostPublicKey });
await client.connect();

const unsubscribe = client.subscribe("SomeType", (message) => {
  console.log(message.data);
});

await client.send("SomeType", { value: "hello" });
unsubscribe();
```

Internally, each outbound MTP frame is written to a new WebTransport unidirectional stream as a four-byte big-endian length followed by the frame, then that stream is closed. Incoming frames are read from the session's incoming unidirectional streams. The reader accepts both one-frame streams and native peers that place several frames on a persistent stream, so browser and native clients interoperate without stream configuration.

The SDK owns stream lifetime and framing. Do not create browser streams for MTP frames yourself through the SDK. For direct generated bindings, use `client.raw.client` or import `WasmClient` from `mtp/raw`; a `WasmClient` still owns one active WebTransport session, so create another instance for an independent connection.

## Sending, Requests, Subscriptions, And Pings

`send` accepts either a typed message or a prebuilt raw frame:

```typescript
await client.send("SomeType", { value: "hello" });
await client.send(rawFrameBytes);
```

Typed sends are encoded by the generated WASM binding using the app type map. Optional frame metadata can be passed as the third argument:

```typescript
await client.send("SomeType", { value: "hello" }, {
  id: 7,
  sender: client.credentials?.clientId ?? 0n,
});
```

`request` sends one frame and resolves with the parsed response carrying the same frame id. If the matching response has a different `responseType`, the promise rejects with a response-type error. A timeout rejects the promise and removes the pending request:

```typescript
const response = await client.request(
  "SomeRequestType",
  { id: "abc" },
  { responseType: "SomeResponseType" },
);
```

`subscribe` registers a message-type handler and returns an unsubscribe function:

```typescript
const unsubscribe = client.subscribe("SomeType", (message) => {
  console.log(message.id, message.sender, message.data);
});

unsubscribe();
```

### Zod request and response schemas

Applications can provide their request and response schemas once when creating
the client. MTP uses `parseAsync`, so synchronous schemas, async refinements,
defaults, coercions, and transforms all work. MTP has no runtime dependency on
Zod; the application supplies its preferred Zod version.

```typescript
import { z } from "zod";
import { MTPClient, MTPValidationError } from "mtp";

const schemas = {
  GetUser: {
    request: z.object({ UserId: z.number().int().positive() }),
    response: z.object({
      UserId: z.number().int().positive(),
      Display: z.string(),
    }),
  },
};

const client = await MTPClient.create({
  url,
  schemas,
  throwProtocolErrors: true,
  onValidationError(error) {
    console.error(error.messageType, error.cause);
  },
});

const response = await client.request("GetUser", { UserId: 42 });
console.log(response.data.Display);
```

Request schemas run before frame encoding and transmission. Their transformed
output is sent. Response schemas run after request correlation, and their
transformed output replaces `frame.data`; `frame.raw`, when present, remains the
original wire frame. Invalid requests and responses reject with
`MTPValidationError`. Invalid subscription messages do not reach the handler
and are reported through `onValidationError`.

`throwProtocolErrors: true` converts correlated `Error*` frames into
`MTPProtocolError`. It defaults to `false` for compatibility.

`MTPProxyConnection` applies the same schema registry to another TypeScript
request/subscription transport, such as a Tauri command and event proxy:

```typescript
const connection = new MTPProxyConnection(adapter, {
  schemas,
  throwProtocolErrors: true,
});
```

Protocol ping behavior is defined in [Protocol Reference](PROTOCOL-REFERENCE.md#protocol-keepalive). The SDK configuration is:

```typescript
await MTPClient.create({
  url: "https://host.example.com:4433",
  pings: { intervalMs: 30_000 },
});
```

Use `pings: true` for the default interval.

## Pipes

Pipes are byte-oriented streams over WebTransport. The `PipeRequest` type and
description are clear transport metadata; raw stream bytes are not protected
by MTP. For sensitive calls, files, or application streams, wrap the accepted
pipe with `MTPEncryptedPipeWriter` or `MTPEncryptedPipeReader`.

### Outgoing Pipes

`createPipe` sends a `PipeRequest` frame and returns a handle. Call `wait()` to block until the remote peer accepts or denies:

```typescript
const handle = await client.createPipe("file-transfer");

const writer = await handle.wait();
if (writer == null) {
  console.log("host denied the pipe");
  return;
}

await writer.write(new Uint8Array([0x01, 0x02, 0x03]));
await writer.write(chunk);
await writer.close();
```

`writer.close()` sends a QUIC stream FIN. `writer.abort()` resets the stream abruptly. Each `write` resolves when the chunk has been handed to the transport; it does not wait for the peer to consume it.

Call `handle.cancel()` to withdraw a request before it is accepted and opened. This sends a `PipeAbort` control frame; use `writer.abort()` after a writer exists.

### Encrypted Pipe Records

`initiateMTPPipeSession` and `acceptMTPPipeSession` perform the signed/KEM
protected pipe-session offer and return the encrypted record wrapper. The
offer binds the session ID, pipe ID, endpoint IDs, direction, and purpose. Do
not derive the initial chain key from the clear description or pipe ID alone.

```typescript
import {
  initiateMTPPipeSession,
} from "mtp";

const encryptedWriter = await initiateMTPPipeSession(
  writer,
  {
    sessionId: new TextEncoder().encode(`file-transfer/${writer.pipeId}`),
    pipeId: writer.pipeId,
    senderId: ownClientId,
    recipientId: hostClientId,
    purpose: 0x40,
    direction: 0,
  },
  ownKeyring,
  hostPublicKeyBundle,
);
await encryptedWriter.writeRecord(chunk);
await encryptedWriter.close();
```

`writeRecord` and `readRecord` use XChaCha20-Poly1305 with ordered sequence
numbers bound to the session context. Each record advances an HKDF chain and
uses a one-use message key. Record insertion, removal, reordering, or
modification fails authentication. The wrapper is intentionally separate from
the raw `PipeWriter`/`PipeReader` transport primitives.

The handle and writer expose `pipeId` and `description`:

```typescript
console.log(handle.pipeId, handle.description);
console.log(writer.pipeId);
```

### Incoming Pipes

Set a handler to receive pipe requests from the remote peer:

```typescript
client.setOnPipeRequest((request) => {
  console.log("incoming pipe", request.pipeId, request.description);
  // accept or deny asynchronously
});
```

Accept a request to receive a `PipeReader`:

```typescript
client.setOnPipeRequest(async (request) => {
  if (request.description === "file-transfer") {
    const reader = await client.acceptPipe(request.pipeId);

    while (true) {
      const chunk = await reader.read();
      if (chunk == null) break; // stream closed by peer
      processChunk(chunk);
    }
  } else {
    await client.denyPipe(request.pipeId);
  }
});
```

`reader.read()` resolves with a `Uint8Array` or `null` when the peer closes the stream. The reader exposes `pipeId` and `description`:

```typescript
console.log(reader.pipeId, reader.description);
```

### Pipe Handshake

1. The initiator calls `createPipe(description)`; the SDK sends a `PipeRequest` frame with a random `pipeId` and the description.
2. The receiver's `setOnPipeRequest` callback fires with `{ pipeId, description }`.
3. The receiver calls `acceptPipe(pipeId)`; the SDK sends a `PipeResponse` with `Accepted = true` and opens a new unidirectional stream for byte transport.
4. The initiator's `handle.wait()` resolves with a `PipeWriter` bound to that stream. Sensitive applications then perform their signed/encrypted session-key setup and construct an encrypted record wrapper.
5. If the receiver calls `denyPipe(pipeId)`, `handle.wait()` resolves with `null`.

Pipes share the same WebTransport session as message frames; they do not need a separate connection.

## Logger Events

The SDK logger receives parsed events:

```typescript
type MTPLogEvent =
  | {
      hint: "info" | "warning";
      type: string;
      data: unknown;
      direction?: "send" | "recv";
    }
  | {
      hint: "error";
      type: string | "error";
      error: string;
      data?: unknown;
      direction?: "send" | "recv";
    };
```

Incoming non-error frames and sent frames are logged as `info`. Error frames and transport errors are logged as `error`.

## Advanced Raw Bindings

Use `mtp/raw` when you need direct access to the generated `wasm-bindgen` API:

```typescript
import init, {
  ConnectionConfig,
  WasmClient,
  ed25519_generate,
  keyring_from_ed25519,
} from "mtp/raw";

await init();

const rawClient = new WasmClient(
  (state) => console.log("state", state),
  (frame) => console.log("message", frame),
  (error) => console.error(error),
);

const config = new ConnectionConfig("https://host.example.com:4433");
config.client_id = 42n;

await rawClient.connect(config);
config.free();
```

Raw callbacks receive parsed frames, not application-specific SDK objects:

```typescript
interface ParsedEncryptedValue {
  kind: "encrypted";
  encryptionType: number;
  purpose: number;
  recipientCount: number;
  encoded: Uint8Array;
}

interface ParsedSignedValue {
  kind: "signed";
  signatureType: number;
  purpose: number;
  signerId: bigint;
  value: ParsedDataValue;
}

type ParsedDataValue =
  | boolean
  | number
  | bigint
  | string
  | Uint8Array
  | ParsedDataValue[]
  | { [key: string]: ParsedDataValue }
  | ParsedEncryptedValue
  | ParsedSignedValue
  | null;

interface ParsedFrame {
  id?: number;
  type: string;
  sender?: bigint;
  receiver?: bigint;
  data: ParsedDataValue;
  raw: Uint8Array;
}
```

### Frames

Raw message helpers that remain available include:

- `build_frame(messageType, data, options?)`
- `build_ping_frame(clientId, description, timestamp, data)`
- `parse_frame(frame)`
- `format_frame(frame)`
- `parse_auth_response(frame)`

The SDK export also exposes the same frame codec through `codec`:

```typescript
import { codec } from "mtp";

const frame = codec.encode("SomeType", { value: "hello" });
const parsed = codec.decode(frame);
const display = codec.format(frame);
```

### Crypto

Raw crypto and key helpers include:

- `ed25519_generate()`
- `ed25519_verify(publicKey, message, signature)`
- `keyring_generate()`
- `keyring_from_ed25519(secretKey, publicKey)`
- `WasmKeyring.from_bytes(bytes)` and `keyring.to_bytes()`
- `keyring.validate_encryption()` for envelope decryption roles
- `keyring.validate_full()` for complete hybrid identities
- `WasmPublicKeyBundle.from_bytes(bytes)` and `bundle.to_bytes()`
- `WasmEd25519Signer`
- `WasmChaCha20Poly1305`
- `sign_data_value_with_keyring` and `verify_data_value_with_policy` (both require an explicit signature suite), plus `encrypt_data_value`, `encrypt_data_value_for_recipients`, and `decrypt_data_value`
- `parse_data_value` and `encode_data_value`
- `wasm_sha256`, `wasm_sha256_double`, `wasm_hkdf_expand`, and `wasm_derive_encryption_key`

Raw authenticated login and registration map directly to the Rust WASM layer:

```typescript
const generated = ed25519_generate();
const keyringBytes = keyring_from_ed25519(generated.secretKey, generated.publicKey);

const registeredId = await rawClient.auth_register(
  config,
  hostPublicKeyBytes,
  keyringBytes,
);

const confirmedId = await rawClient.auth_connect(
  config,
  hostPublicKeyBytes,
  keyringBytes,
  registeredId,
);
```

### Pipes

The raw `WasmClient` exposes the same pipe operations as the SDK wrapper. The shared lifecycle is in [Pipes](PIPES.md); raw bindings use snake_case names.

```typescript
rawClient.set_on_pipe_request((event) => {
  void rawClient.accept_pipe(event.pipeId);
});

const handle = await rawClient.create_pipe("file-transfer");
const writer = await handle.wait();
if (writer) {
  await writer.write(chunk);
  await writer.close();
}
```

A `WasmClient` manages one active WebTransport session. Create a new instance for independent connections, and call `free()` or `[Symbol.dispose]()` on raw WASM objects when you want to release memory eagerly.

### State Management

A `WasmClient` owns one active WebTransport session. Create a separate client for each independent connection. Call `free()` or `[Symbol.dispose]()` on raw WASM objects when the application no longer needs them. SDK session and encrypted secret persistence are documented in [Security](SECURITY.md#browser-end-to-end-encryption).
