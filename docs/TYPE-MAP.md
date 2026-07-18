# Type Map

This file documents the Type Map & Registry configuration used by the MTP protocol. It will assume you are working with the [example-type-maps.yaml](./../example-type-maps.yaml).

## Binary Frame Format

Every transport frame is a four-byte big-endian length followed by one `CommunicationValue`. The length counts all bytes after the length field.

```text
u32 length
u16 communication_type
u8  flags
u32 id              if flag 0x04 is set
u48 sender          if flag 0x01 is set
u48 receiver        if flag 0x02 is set
u8  signature_type  if flag 0x10 is set
... signature       if flag 0x10 is set, length depends on signature_type
... data container or encrypted payload
```

The flag values are `0x01` for sender, `0x02` for receiver, `0x04` for frame ID, `0x08` for encrypted data, `0x10` for a frame signature, and `0x20` for a signed encrypted container. Sender and receiver IDs are six-byte unsigned big-endian values. The `communication_type` and every container field use IDs from the negotiated `TypeMap`.

Data values begin with a one-byte kind marker. MTP assigns `0x01` and `0x02` to boolean true and false, `0x03` to signed integers, `0x04` to unsigned integers, `0x05` to floats, `0x06` to UTF-8 strings, `0x07` to bytes, `0x08` to arrays, `0x09` to containers, `0x0A` through `0x0C` to crypto containers, and `0xFF` to null. Length-prefixed values use a four-byte big-endian payload length; container and array counts use two-byte big-endian counts.

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

### Using Generated Enums

After editing the config and rebuilding, `CommunicationType` and `DataType` enums are generated automatically. Use them in code:

```rust
use mtp::type_map::{CommunicationType, DataType, TypeMap};

let tm = TypeMap::v2_0();
let id = tm.data_id_enum(DataType::SomeType).unwrap();
```

The enums are a **union across all versions**; every type name from every version is a variant. The version-specific `TypeMap` maps each variant to the correct wire ID for that version. For a type absent from a selected version, the lookup returns `None`.

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
let tm_v2 = TypeMap::v2_0();
assert!(tm_v2.data_id_enum(DataType::SomeType).is_some());    // defined in v2.0
assert!(tm_v2.data_id_enum(DataType::ExampleType).is_none()); // NOT in v2.0

let tm_v1 = TypeMap::v1_0();
assert!(tm_v1.data_id_enum(DataType::ExampleType).is_some());  // defined in v1.0
```

When communicating with a peer on another version, encode only variants that map in the negotiated version. If an incoming frame names a type absent from the selected map, reject it as a protocol or type-map compatibility error; do not reinterpret its wire ID using another version's map. Keep old IDs stable, register both versions during migration, and remove a version only after its clients have moved.

### Forward/Backward Compatibility Between Versions

Because enums are a union of all types across versions, a variant might exist that has no wire mapping in the *negotiated* version:

```
v2.0 client sends DataType::SomeType    → host encodes with v2.0 TypeMap → wire ID 32
v2.0 host receives DataType::ExampleType (from v1.0 client) → not in v2.0 TypeMap → None → Error
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
let bytes = codec.encode(&value, Version(2, 0)).unwrap();

// Decode with a specific version
let decoded = codec.decode(&bytes, Version(2, 0)).unwrap();
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
