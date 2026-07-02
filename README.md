# Methanium Transport Protocol

MTP is a modular transport protocol built on QUIC. It provides version-negotiable type maps, a binary codec, cryptographic primitives (classical and post-quantum), and host/client connection management with mutual authentication.

See the area-specific docs for [Native Client](./docs/NATIVE-CLIENT.md), [WASM Client](./docs/WASM-CLIENT.md), [Host](./docs/NATIVE-HOST.md), and [Type Maps](./docs/TYPE-MAP.md).

## Browser SDK

The JavaScript package is `mtp`:

```typescript
import { MTPClient } from "mtp";
import { mtp } from "mtp/vite";
```

Use `mtp` for the SDK-first API, `mtp/raw` for generated WASM bindings, and `mtp/vite` for the Vite integration.

```typescript
// vite.config.ts
import { defineConfig } from "vite";
import { mtp } from "mtp/vite";

export default defineConfig({
  plugins: [mtp({ typeMaps: "./type-maps.yaml" })],
});
```

```typescript
import { MTPClient, type MTPCredentials } from "mtp";

const credentialsStorageKey = "mtpCredentialsForMyApp";

function loadCredentials(): MTPCredentials {
  const saved = localStorage.getItem(credentialsStorageKey);
  if (saved) {
    return JSON.parse(saved) as MTPCredentials;
  }

  return {
    clientId: null,
    keyring: MTPClient.crypto.generateKeyring(),
  };
}

await MTPClient.init();

// Example-looking host public key bundle bytes. Replace this with the public
// key bundle published by your MTP host before connecting to a real service.
const hostPublicKey = Uint8Array.from({ length: 128 }, (_, index) => (
  [0xb6, 0x4f, 0x7d, 0x9a, 0x3c, 0x21, 0xe8, 0x05][index % 8] ^ index
));

const client = await MTPClient.create({
  url: "https://localhost:4433",
  hostPublicKey,
  credentials: loadCredentials(),
  storage: window.localStorage, // Same API as localStorage for convenience
  credentialsStorageKey,
  pings: true,
  logger: (event) => console.log("[MTP]: " + event),
});

client.subscribe("SomeType", (message) => console.log(message));

const clientId = await client.auth();

await client.send("SomeType", { value: "hello" });
console.log("Connected MTP client", clientId, client.state);
```

`client.raw` exposes the lower-level WASM client and generated binding module for advanced integrations. Prefer the SDK methods unless you specifically need an API the wrapper does not expose; raw calls bypass SDK validation, credential persistence, logging, timeout handling, frame helpers, and lifecycle safeguards.

Use `MTPClient.crypto` for SDK-level crypto helpers such as `generateKeyring()`, `generateEd25519()`, `keyringFromEd25519()`, `verifyEd25519()`, `sha256()`, `sha256Double()`, `hkdfExpand()`, and `deriveEncryptionKey()`.

## Getting Started

Add the `mtp` crate with your desired features:

```toml
[dependencies]
mtp = { path = "..", features = ["client", "crypto"] }
```

The `mtp` umbrella crate re-exports all sub-crates behind feature flags:

| Feature  | Pulls in                    | Enables                                   |
| -------- | --------------------------- | ----------------------------------------- |
| `crypto` | `mtp::crypto`               | AEAD, signatures, KEM, KDF, hashing       |
| `host`   | `mtp::host`, `mtp::codec::registry` | QUIC server, version negotiation  |
| `client` | `mtp::client`               | QUIC client connections                   |

Core crates (`codec`, `transport`, `common`, `type_map`) are always available.

```rust
use mtp::codec::{CommunicationValue, DataValue};
use mtp::type_map::{CommunicationType, DataType, TypeMap};
use mtp::transport::{Sender, Receiver};

#[cfg(feature = "crypto")]
use mtp::crypto::ChaCha20Poly1305;
```

## Sub-crates

All sub-crates are re-exported through the `mtp` facade and can be referenced as `mtp::codec`, `mtp::transport`, `mtp::common`, `mtp::type_map`, `mtp::crypto`, `mtp::host`, `mtp::client`.

### Codec

The codec crate handles binary encoding and decoding of MTP packets using Communication Types and Data Types resolved through the type-map registry.

**Data Value types:**
- Container (key-value map of typed entries)
- Encrypted Container (requires `crypto`)
- Signed Container (requires `crypto`)
- SignedEncrypted Container (requires `crypto`)
- Signed Integer (i128)
- Unsigned Integer (u128)
- Boolean
- Float (exponent + mantissa)
- String
- Array
- Bytes
- Null

Encoding and decoding use a `TypeMap` to resolve type names to wire IDs. The `CommunicationValue` struct provides the frame format (type, flags, optional id/sender/receiver, data payload, optional signature).

### Transport

The transport crate wraps QUIC using `wtransport`. It provides `Sender`/`Receiver` for bidirectional message passing over uni-directional QUIC streams. Supports two send modes: persistent stream and single-stream-per-message.

### Host

The host crate provides `MTPHost` with built-in version negotiation and optional authenticated login/registration (requires `crypto`). Accepts connections, negotiates protocol version, and returns `MTPConnection` handles.

### Client

The client crate provides `MTPClient` that connects to an MTP host. Supports `connect` (unauthenticated), `auth_connect` (login), and `auth_register` (registration) when built with `crypto`.

### Common

Common defines shared error types (`CodecError`, `CommunicationError`) used across all crates.

### Type Map

The type-map build script reads a YAML configuration to generate `CommunicationType` and `DataType` enums at compile time. The runtime crate provides `TypeMap`, `Version`, `CommunicationTypeId`, `DataTypeId`, and the multi-version `Registry` (requires `registry` feature).

### Crypto Stack

| Crate            | Audited? | Notes                                            |
| ---------------- | -------- | ------------------------------------------------ |
| ml-dsa           | No       | NIST vectors pass; regression bug fixed Jan 2026 |
| ed25519-dalek    | Yes      | Used by Signal, Diem                             |
| chacha20poly1305 | Yes      | NCC Group audit, Dec 2019                        |
| aes-gcm          | Yes      | NCC Group audit, Dec 2019                        |
| hkdf             | No       | Simple construction; well-reviewed               |
| sha2             | No       | Standard construction; widely reviewed           |
| zeroize          | No       | Simple; widely used                              |
| mlkem-tls        | No       | mlkem-rs backend unaudited                       |
