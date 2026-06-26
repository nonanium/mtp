# MTP WASM Client

The WASM client is a browser-compatible MTP implementation that uses the **WebTransport** API to communicate with an MTP host over QUIC (HTTP/3). It compiles from Rust to WebAssembly via `wasm-bindgen` and exposes a JavaScript/TypeScript API through the `mtp-wasm` npm package.

## Package

The compiled package lives in `wasm/pkg/` and contains:

- `mtp_wasm.js` -- generated JS glue
- `mtp_wasm_bg.wasm` -- the WebAssembly binary
- `mtp_wasm.d.ts` -- TypeScript type declarations
- `package.json` -- npm package definition

Install or copy these files into your web project. Then initialise the module:

```typescript
import init, { WasmClient } from 'mtp-wasm';

await init();
```

## Browser Support

WebTransport is required. Check availability at runtime:

```typescript
if (!WasmClient.is_supported()) {
  // fall back or show an error
}
```

## Connecting to a Host

### ConnectionConfig

```typescript
const config = new ConnectionConfig("https://host.example.com:4433");
config.client_id = 12345n;                    // optional, for re-authentication
config.server_certificate_hashes = [           // optional, for certificate pinning
  "sha-256:abc123...",
];
```

`client_id` is only needed for authenticated login (`auth_connect`). For registration (`auth_register`) it is ignored.

### TLS Certificate Handling

By default, when `server_certificate_hashes` is not set, the browser uses its
**built-in root certificate store** to verify the server's TLS certificate,
just like any other HTTPS/WebSocket connection. This works with publicly-trusted
certificate authorities automatically.

For development or self-signed certificates, pin the server certificate by
providing its hash:

```typescript
config.server_certificate_hashes = [
  "sha-256:abcd1234...",  // hex-encoded hash value
];
```

The hash format is `"<algorithm>:<hex-encoded-hash>"`, where the only algorithm
the browser's WebTransport API currently accepts is `sha-256`. When hashes are
provided, the browser **only** trusts certificates matching one of the given
hashes and ignores its root store for this connection.

### Callbacks

The client uses three callbacks for state, messages, and errors:

```typescript
const client = new WasmClient(
  (state: number) => console.log("state", state),   // ConnectionState enum
  (data: Uint8Array) => console.log("msg", data),    // raw frame bytes
  (err: any) => console.error("err", err),           // error description
);
```

### Connection States

| Value | Name         |
|-------|--------------|
| 0     | Disconnected |
| 1     | Connecting   |
| 2     | Connected    |
| 3     | Failed       |

Poll `client.state` at any time.

## Connection Methods

### Unauthenticated Connect

```typescript
await client.connect(config);
```

Sends an `Identification` frame with the protocol version and client ID. The host may accept or reject. No cryptographic handshake occurs.

### Authenticated Login

```typescript
const confirmedId = await client.auth_connect(
  config,
  hostPublicKeyBytes,   // Uint8Array: serialized PublicKeyBundle from the host
  keyringBytes,         // Uint8Array: serialized Keyring matching the client ID
  clientId,             // bigint: previously assigned client ID
);
```

Exchange (challenge-response): the client sends an unsigned `Identification`
hello, the host replies with a signed `Challenge` carrying a fresh
`server_challenge`, the client signs that challenge in a `ChallengeResponse`, and
the host verifies it and replies with a signed `IdentificationResponse`. Signing
over the host-issued challenge is what prevents a captured proof from being
replayed on another connection. Returns the confirmed client ID.

### Registration

```typescript
const newId = await client.auth_register(
  config,
  hostPublicKeyBytes,   // Uint8Array: serialized PublicKeyBundle from the host
  keyringBytes,         // Uint8Array: serialized Keyring for the new identity
);
```

Exchange (challenge-response): the client sends an unsigned `Register` hello with
its public keys, the host replies with a signed `Challenge`, the client signs it
(binding the public-key bundle) in a `ChallengeResponse`, and the host verifies
it, assigns a new ID, and responds with a signed `RegisterResponse`. Returns the
newly assigned client ID.

## Sending and Receiving Messages

### Send

```typescript
const frame = build_ping_frame(clientId, "hello", timestamp, data);
await client.send(frame);
```

`send()` takes raw frame bytes (a serialized `CommunicationValue`). Build frames
with the provided helper functions or construct them manually.

### Receive

Incoming frames arrive on the `on_message` callback registered in the constructor.
The callback receives a `Uint8Array` of raw frame bytes. Parse with
`CommunicationValue.from_bytes()` on the Rust side or handle the bytes in JS.

### Disconnect

```typescript
client.disconnect();
```

Gracefully closes the WebTransport session.

## Building Frames

### `build_ping_frame`

```typescript
function build_ping_frame(
  clientId: bigint,
  description: string,
  timestamp: bigint,
  data: Uint8Array,
): Uint8Array;
```

Constructs a basic `Ping` message with description, timestamp, and optional
binary payload. Useful for health checks and simple messaging.

### `build_demo_message`

```typescript
function build_demo_message(
  clientId: bigint,
  keyringBytes: Uint8Array,
  hostBundleBytes: Uint8Array,
): Uint8Array;
```

Constructs a `Ping` frame that demonstrates encrypted, signed, and
signed+encrypted containers. The containers are ML-KEM-encrypted to the host's
`PublicKeyBundle` (`hostBundleBytes`, the same bytes passed to `auth_connect` /
`auth_register`), so the host decrypts them with its own keyring; signatures use
the client keyring's Ed25519 key. The client keyring only needs its Ed25519
signing key for this demo.

### `parse_auth_response`

```typescript
function parse_auth_response(response: Uint8Array): any;
```

Parses an `IdentificationResponse` or `RegisterResponse` frame into a JS object:

```typescript
{
  connected: boolean,
  clientNonce?: Uint8Array,
  assignedId?: number,
  timestamp?: number,
  signature?: Uint8Array,
}
```

## Crypto Primitives

### Key Generation

```typescript
const result = ed25519_generate();
// result.signer      -> WasmEd25519Signer
// result.secretKey   -> Uint8Array (32 bytes)
// result.publicKey   -> Uint8Array (32 bytes)
```

### Keyring

A `Keyring` bundles all key material for an identity. For Ed25519-only setups:

```typescript
const keyringBytes = keyring_from_ed25519(secretKey, publicKey);
// keyringBytes is ready for WasmClient.auth_register or WasmClient.auth_connect
```

Full keyring with KEM + ML-DSA requires constructing on the Rust side. The
serialized bytes are portable:

```typescript
const keyring = WasmKeyring.from_bytes(keyringBytes);
const bundle = keyring.public_key_bundle();
// bundle.kem_public_key   -> Uint8Array
// bundle.sig_cl_public_key -> Uint8Array
// bundle.sig_pq_public_key -> Uint8Array
```

### Signing and Verification

```typescript
const signer = new WasmEd25519Signer(secretKey);
const sig = signer.sign(message);            // Uint8Array
signer.verify(message, sig);                 // throws on mismatch

// Standalone verification (no signer object needed):
ed25519_verify(publicKey, message, signature);
```

### Symmetric Encryption

```typescript
const cipher = new WasmChaCha20Poly1305(key); // 32-byte key
const encrypted = cipher.encrypt(plaintext, aad); // nonce || ciphertext
const decrypted = cipher.decrypt(encrypted, aad);
```

### Hashing and KDF

```typescript
const hash = wasm_sha256(data);                        // 32 bytes
const double = wasm_sha256_double(data);               // SHA-256(SHA-256(data))

const derived = wasm_hkdf_expand(ikm, salt, info, len);
const encKey = wasm_derive_encryption_key(ikm, salt, context); // 32 bytes
```

## Lifecycle and Best Practices

1. **Key persistence** -- serialise keyring bytes after registration and store
   them (e.g. in `localStorage`). On next visit, load the saved keyring and
   call `auth_connect` instead of registering again.

2. **Ownership** -- call `config.free()` after connecting if the config object
   is no longer needed. WASM objects (`WasmClient`, `WasmKeyring`, etc.) are
   garbage-collected, but explicit `free()` or `dispose()` reclaims memory
   sooner.

3. **Receive loop** -- once `connect`, `auth_connect`, or `auth_register`
   resolves, the receive loop is running in the background. Incoming frames
   arrive on the `on_message` callback. There is no need to poll.

4. **Single active client** -- a `WasmClient` manages one WebTransport session.
   Create a new instance for each connection.

5. **State transitions** -- after `disconnect()` the client transitions to
   `Disconnected`. The instance is reusable; call a connect method again to
   open a new session.
