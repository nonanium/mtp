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
  pings: true,
  logger: (event) => console.log(event),
});

const unsubscribe = client.subscribe("SomeType", (message) => {
  console.log(message.type, message.data);
});

await client.connectOrRegister();
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

const clientId = await client.connectOrRegister();
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
- `connectOrRegister()` registers when no client ID is present, otherwise performs authenticated login.
- `disconnect()` stops protocol pings and closes the underlying WebTransport session.

For certificate pinning, pass WebTransport certificate hashes:

```typescript
await MTPClient.create({
  url: "https://host.example.com:4433",
  serverCertificateHashes: ["sha-256:abcd1234..."],
});
```

If hashes are omitted, the browser uses its normal TLS root store.

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

`request` sends one frame and resolves with the matching parsed response from the WASM layer:

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

Raw crypto and key helpers include:

- `ed25519_generate()`
- `ed25519_verify(publicKey, message, signature)`
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

A `WasmClient` manages one active WebTransport session. Create a new instance for independent connections, and call `free()` or `[Symbol.dispose]()` on raw WASM objects when you want to release memory eagerly.
