# MTP WASM Client

The browser client is exposed through the `mtp` npm package. Most applications should use the SDK-first `MTPClient` API; direct generated WASM bindings remain available from `mtp/raw` for advanced integrations.

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

Browser apps provide their own type map. The Vite plugin runs `wasm-pack` during dev/build with `MTP_TYPE_MAPS` set, writes generated output under `node_modules/.vite/mtp/` by default, and aliases `mtp/raw` plus `mtp/type-map` to that generated output.

```typescript
// vite.config.ts
import { defineConfig } from "vite";
import { mtp } from "mtp/vite";

export default defineConfig({
  plugins: [mtp({ typeMaps: "./type-maps.yaml" })],
});
```

You do not need to publish, fork, or copy an app-specific generated WASM package.

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

## Streams

The browser client uses one WebTransport session per `MTPClient` instance.
`send()`, `request()`, and `subscribe()` all operate over that session; the SDK
does not expose browser stream objects directly.

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

Internally, each outbound MTP frame is written to a new WebTransport
unidirectional stream as a four-byte big-endian length followed by the frame,
then that stream is closed. Incoming frames are read from the session's
incoming unidirectional streams. The reader accepts both one-frame streams and
native peers that place several frames on a persistent stream, so browser and
native clients interoperate without stream configuration.

The SDK deliberately owns stream lifetime and framing. Do not create browser
streams for MTP frames yourself through the SDK. For direct generated bindings,
use `client.raw.client` or import `WasmClient` from `mtp/raw`; a `WasmClient`
still owns one active WebTransport session, so create another instance for an
independent connection.

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

`request` sends one frame and resolves with the parsed response carrying the same frame id. `responseType` is validated after the id match:

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

Protocol pings are real MTP `Ping` frames sent by the WASM client, not just transport keepalives:

```typescript
await MTPClient.create({
  url: "https://host.example.com:4433",
  pings: { intervalMs: 30_000 },
});
```

Use `pings: true` for the default interval.

## Pipes

Pipes are raw binary streams over QUIC. A pipe starts with a lightweight `PipeRequest` handshake frame, then the stream carries raw bytes with zero per-frame overhead. Pipes are unidirectional; the peer that initiates the pipe writes, and the peer that accepts it reads.

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
3. The receiver calls `acceptPipe(pipeId)`; the SDK sends a `PipeResponse` with `Accepted = true` and opens a new unidirectional stream for raw data.
4. The initiator's `handle.wait()` resolves with a `PipeWriter` bound to that stream.
5. If the receiver calls `denyPipe(pipeId)`, `handle.wait()` resolves with `null`.

Pipes share the same WebTransport session as message frames; they do not need a separate connection.

## Logger Events

The SDK logger receives parsed events:

```typescript
type MTPLogEvent =
  | { hint: "info" | "warning"; type: string; data: unknown }
  | { hint: "error"; type: string | "error"; error: string };
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
interface ParsedFrame {
  id?: number;
  type: string;
  sender?: bigint;
  receiver?: bigint;
  data: Record<string, unknown>;
  raw: Uint8Array;
}
```

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

Raw crypto and key helpers include:

- `ed25519_generate()`
- `ed25519_verify(publicKey, message, signature)`
- `keyring_generate()`
- `keyring_from_ed25519(secretKey, publicKey)`
- `WasmKeyring.from_bytes(bytes)` and `keyring.to_bytes()`
- `WasmPublicKeyBundle.from_bytes(bytes)` and `bundle.to_bytes()`
- `WasmEd25519Signer`
- `WasmChaCha20Poly1305`
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

### Raw Pipes

The raw `WasmClient` exposes the same pipe operations as the SDK wrapper:

```typescript
// Incoming pipe requests
rawClient.set_on_pipe_request((event) => {
  const { pipeId, description } = event;
  // accept or deny
});

// Outgoing pipe
const handle = await rawClient.create_pipe("file-transfer");
const writer = await handle.wait();
if (writer) {
  await writer.write(new Uint8Array([0x01, 0x02]));
  await writer.close();
}

// Accept incoming pipe
const reader = await rawClient.accept_pipe(pipeId);
const chunk = await reader.read();

// Deny incoming pipe
await rawClient.deny_pipe(pipeId);
```

Raw `PipeWriter` and `PipeReader` have the same interface as the SDK types:

```typescript
interface PipeWriter {
  write(data: Uint8Array): Promise<void>;
  close(): Promise<void>;
  abort(): void;
  readonly pipeId: number;
}

interface PipeReader {
  read(): Promise<Uint8Array | null>;
  readonly pipeId: number;
  readonly description: string;
}
```

A `WasmClient` manages one active WebTransport session. Create a new instance for independent connections, and call `free()` or `[Symbol.dispose]()` on raw WASM objects when you want to release memory eagerly.
