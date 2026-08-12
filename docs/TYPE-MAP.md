# Type Map

This file documents the Type Map & Registry configuration used by the MTP protocol. It will assume you are working with the [example-type-maps.yaml](./../example-type-maps.yaml).

## Binary Frame Format

Every transport frame is a four-byte big-endian length followed by one `CommunicationValue`. The length counts all bytes after the length field.

This is the only transport frame length prefix. Transports write the
`CommunicationValue` bytes directly and do not add another length before this
field. The close-frame sentinel occupies the same four-byte position.

```text
[4 bytes total length]
[2 bytes communication type]
[1 byte flags]
    bit 0 = has ID
    bit 1 = has sender ID
    bit 2 = has receiver ID
    bits 3-7 must be zero
[4 bytes ID]          if bit 0
[8 bytes sender ID]   if bit 1
[8 bytes receiver ID] if bit 2
[DataValue payload]
```

The only defined flag values are `0x01` for ID, `0x02` for sender, and `0x04` for receiver. Unknown flag bits are rejected. IDs are full-width unsigned big-endian values: the correlation ID is `u32`, while sender and receiver IDs are `u64`. Encryption and signing are properties of the `DataValue` payload, never of the frame header.

`Relay` is the reserved opaque application communication type. Relay frames
omit the outer sender, expose only the next-hop receiver and transport
correlation data, and carry the actual operation and application metadata in
their protected payload.

## DataValue Wire Format

Every `DataValue` begins with a one-byte kind marker. MTP assigns `0x01` and `0x02` to boolean true and false, `0x03` to signed `i128`, `0x04` to unsigned `u128`, `0x05` to `f64`, `0x06` to UTF-8 strings, `0x07` to bytes, `0x08` to arrays, `0x09` to containers, `0x0A` to `Encrypted<Value>`, `0x0B` to `Signed<Value>`, and `0xFF` to null. Kind `0x0C` is reserved and rejected. All multibyte numeric values, counts, and lengths are big-endian.

Strings and bytes have a four-byte byte length. Arrays have a two-byte element count followed by that many self-delimiting values. The protection wrappers have the following canonical layouts.

```text
Container

09
[2 bytes element count]

repeat for each element:
    [2 bytes DataTypeId]
    [DataValue]
```

Container field IDs must be unique. Each nested value is self-delimiting, so container elements have no generic per-element payload length.

```text
Signed

0B
[4 bytes wrapper length]

[1 byte signature algorithm]
[1 byte purpose]
[8 bytes signer ID]
[signature]
[DataValue]
```

The wrapper length counts the bytes after the length field. Signature length is determined by the signature algorithm. The signature covers `MTP-DATA-SIGN-1 || algorithm || purpose || signer ID || serialized inner value`.

```text
Encrypted

0A
[4 bytes envelope length]

[1 byte encryption suite]
[1 byte purpose]
[2 bytes recipient count]

[recipient entry]
...

[encrypted DataValue bytes]
```

The envelope length counts the bytes after the length field. A recipient entry is an unlabeled fixed-size KEM ciphertext and wrapped content-encryption key; both lengths are determined by the selected suite. The encrypted bytes are the AEAD output for the complete serialized inner `DataValue`.

Protection nesting directly represents both signer-visibility choices: `Encrypted(Signed(Container))` keeps signer metadata private, while `Signed(Encrypted(Container))` exposes it. A frame with no outer sender and an `Encrypted(Signed(Container))` payload uses sealed sender. Sealed sender adds no flag or distinct wire type.

## TypeMap & Compile-Time Type Safety

A `TypeMap` maps Communication-Types and Data-Types to their wire IDs. Each protocol version has its own `TypeMap` because the same type name may use different wire IDs in different versions.

Type names are defined in a YAML config and turned into Rust enums at **compile time** by a `build.rs` in the `type-map` crate. This means invalid type names are caught by the compiler instead of failing at runtime.

### Defining Type Maps

Place your own `type-maps.yaml` in your project root. Browser apps should use the Vite plugin so the app-specific WASM package is generated into Vite's cache during dev/build:

```typescript
import { defineConfig } from "vite";
import { mtp } from "mtp/vite";

export default defineConfig({
  plugins: [mtp({ typeMaps: "./type-maps.yaml" })],
});
```

Rust and manual WASM builds can set `MTP_TYPE_MAPS` directly (see [Customizing Type Maps in Downstream Projects](#customizing-type-maps-in-downstream-projects)).

For browser builds, `protocol_version` selects the one application map compiled
into that WASM client. The Vite-generated `mtp/type-map` module contains the
reserved MTP names and the application names from that selected version only;
the selected version must be present in `type_maps`. This keeps its TypeScript
unions aligned with the client runtime.

### Using Generated Enums

After editing the config and rebuilding, `CommunicationType` and `DataType` enums are generated automatically. Use them in code:

```rust
use mtp::type_map::{CommunicationType, DataType, TypeMap};

let tm = TypeMap::v3_0();
let id = tm.data_id_enum(DataType::SomeType).unwrap();
```

For native builds with the `registry` feature, the enums are a **union across
all versions**; every type name from every version is a variant. The
version-specific `TypeMap` maps each variant to the correct wire ID for that
version. For a type absent from a selected version, the lookup returns `None`.
Browser-generated TypeScript unions intentionally differ: they contain only
the selected `protocol_version` plus reserved names, matching the WASM client
compiled by the Vite plugin.

Encoding/decoding uses a `TypeMap` to resolve type names to wire IDs:

```rust
use mtp::codec::{encode, decode, DataValue};
use mtp::type_map::TypeMap;

let tm = TypeMap::v2_0();
let value = DataValue::Str("hello".into());

let bytes = encode(&value, &tm).unwrap();
let decoded = decode(&bytes, &tm).unwrap();
```

```rust
let tm_v3 = TypeMap::v3_0();
assert!(tm_v3.data_id_enum(DataType::SomeType).is_some());
```

When communicating with a peer on another version, encode only variants that map in the negotiated version. If an incoming frame names a type absent from the selected map, reject it as a protocol or type-map compatibility error; do not reinterpret its wire ID using another version's map. The self-delimiting codec begins at protocol version `3.0`; older versions are not codec fallbacks.

### Forward/Backward Compatibility Between Versions

Because enums are a union of all types across versions, a variant might exist that has no wire mapping in the *negotiated* version:

```
v3.0 client sends DataType::SomeType    → host encodes with v3.0 TypeMap → wire ID 32
v3.0 host receives an unsupported pre-v3.0 peer                    → version negotiation error
```

Encoding a frame with an unmapped communication or data type returns `CodecError::UnknownCommunicationType` or `CodecError::UnknownDataType`. Select a mapped variant from the compiled-in version before sending it.

## Registry

The `registry` feature of the Codec crate adds `VersionedCodec` for version-aware encoding:

Requires the `host` feature (which enables `mtp-codec`'s `registry` feature):

```toml
[dependencies]
mtp = { path = "..", features = ["host"] }
```

```rust
use mtp::codec::registry::{Registry, VersionedCodec};

let registry = Registry::builtin();
let codec = VersionedCodec::new(registry);

// Encode with a specific version
let bytes = codec.encode(&value, Version(3, 0)).unwrap();

// Decode with a specific version
let decoded = codec.decode(&bytes, Version(3, 0)).unwrap();
```

## Customizing Type Maps in Downstream Projects

External projects must provide their own type map configuration. Browser projects use the Vite plugin from [Defining Type Maps](#defining-type-maps) and do not need to publish, fork, or copy a generated WASM package.

For Rust builds, or when invoking `wasm-pack` manually, set the `MTP_TYPE_MAPS` environment variable. If the variable points to an invalid file, the build fails. If `MTP_TYPE_MAPS` is not set, the build script emits a warning and generates reserved protocol types only; application-specific communication and data types will not be available.

1. Create a `type-maps.yaml` in your project root (or anywhere else, adapt the path accordingly)
2. Set the `MTP_TYPE_MAPS` environment variable in `.cargo/config.toml`:

```toml
# .cargo/config.toml
[env]
MTP_TYPE_MAPS = { value = "type-maps.yaml", relative = true }
```
