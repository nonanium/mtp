# Type Map

This file documents the type-map and registry configuration used by MTP. The
repository workspace uses [`tests/fixtures/example/type-maps.yaml`](../tests/fixtures/example/type-maps.yaml)
through [`.cargo/config.toml`](../.cargo/config.toml); that map currently
selects protocol version 3.0. The root [`tests/fixtures/e2e-type-maps.yaml`](../tests/fixtures/e2e-type-maps.yaml)
is a separate illustrative multi-version configuration used by the manual WASM
build script. Downstream applications should provide their own map.

The protocol version selects the generated codec/type-map build, while the
type-map entries define the available application types and their IDs.

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

### Container ordering and signatures

Container entries are ordered sequences in the current format. Insertion order
is therefore semantic: two containers with the same field/value pairs in a
different order have different serialized bytes and different signatures. The
decoder rejects duplicate field IDs. Applications that need map semantics must
canonicalize their own input before signing; a future canonical map encoding
requires a protocol-format version and cannot be inferred by a receiver.

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
let id = tm.data_id_enum(DataType::ExampleText).unwrap();
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
use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataValue};
use mtp::type_map::TypeMap;

let tm = TypeMap::v3_0();
let value = CommunicationValue::new_with_type_map(CommunicationType::Ping, &tm)
    .add_typed(DataType::Description, &tm, DataValue::Str("hello".into()));

let bytes = value.to_bytes().unwrap();
let decoded = CommunicationValue::from_bytes_with(&bytes, &tm).unwrap();
```

```rust
let tm_v3 = TypeMap::v3_0();
assert!(tm_v3.data_id_enum(DataType::ExampleText).is_some());
```

When communicating with a peer on another version, encode only variants that map in the negotiated version. If an incoming frame names a type absent from the selected map, reject it as a protocol or type-map compatibility error; do not reinterpret its wire ID using another version's map. The current repository map uses the self-delimiting codec format for protocol version `3.0`; a custom registry may register other version numbers, but those maps are not legacy wire-format fallbacks.

### Forward/Backward Compatibility Between Versions

Because enums are a union of all types across versions, a variant might exist that has no wire mapping in the *negotiated* version:

```
v3.0 client sends DataType::ExampleText → host encodes with v3.0 TypeMap → wire ID 43
v3.0 host receives a version absent from the registry                 → version negotiation error
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
use mtp::codec::{CommunicationType, CommunicationValue, DataValue};
use mtp_type_map::Version;

let registry = Registry::builtin();
let codec = VersionedCodec::for_version(registry, Version(3, 0)).unwrap();
let value = CommunicationValue::new_with_type_map(
    CommunicationType::Ping,
    codec.type_map(),
).with_payload(DataValue::Null);

// The value must retain the negotiated map used to construct it.
let bytes = codec.encode(&value).unwrap();

let decoded = codec.decode(&bytes).unwrap();

// A clear value can be migrated explicitly when the application has chosen
// that behavior. Protected values are not silently remapped.
let migrated = codec.encode_migrating(&value).unwrap();
```

`VersionedCodec::encode` compares the retained map identity (its protocol
version) and returns `CodecError::MissingTypeMap` or
`CodecError::TypeMapMismatch` on failure. `reply_to` retains the request's
map, while `try_merge_payload_from` rejects frames from different maps before
copying any fields. Payload merging is shallow and left-biased: a field already
present in the destination keeps its value and position, and a field present
only in the source is appended in source order. The frames must also have the
same communication type; contradictory sender or receiver metadata is
rejected. Frame IDs and routing metadata are never copied from the source.

Use `try_merge_payload_from` for the detailed `MergeError` and `MergeReport`.
The deprecated `try_merge` and `merge` compatibility methods retain their
`CodecError` behavior, but now use the same left-biased semantics. Code that
previously used `try_merge` for right-biased overrides must switch to
`try_merge_payload_from_with` and `MergeConflictPolicy::KeepRight`.

## Payload merging

Compose clear application content before building a protected message. The
default merge is shallow and destination-biased:

```rust
let report = destination.try_merge_payload_from(&source)?;
// destination fields win; source-only fields are appended in source order.
```

The destination frame ID and routing metadata remain unchanged. A sender or
receiver present on both frames must agree; routing values are never copied
from the source. Both payloads must be structurally valid containers, so
signed, encrypted, scalar, and malformed nested values are rejected.

`MergeOptions` provides explicit `KeepRight`, `RequireEqual`, and `Reject`
conflict policies, plus opt-in recursive container merging. When
`recursiveContainers` is enabled and both overlapping values are containers,
their children are merged before the leaf conflict policy is applied. Arrays
remain ordinary field values and are never concatenated.

Detailed reports contain complete numeric field paths. For a source that adds
`City` below an existing `Metadata` container, the report is:

```ts
{
  inserted: [[metadataId, cityId]],
  preserved: [],
  replaced: [],
  matched: [],
  recursed: [[metadataId]],
}
```

The TypeScript SDK offers `mergePayloadFrom`, `mergePayloadFromDetailed`,
`mergeDataValues`, and `mergeDataValuesDetailed`; the data-value helpers are
useful for combining content before `ProtectedMessageBuilder`, signing, or
encryption. `EncodeLimits` passed to frame merging bound the complete encoded
frame, while limits passed to standalone data-value merging bound the complete
serialized `DataValue`.

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
