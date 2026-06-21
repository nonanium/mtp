# Type Map

This file documents the Type Map & Registry configuration used by the MTP protocol.

## TypeMap & Compile-Time Type Safety

A `TypeMap` maps Communication-Types and Data-Types to their wire IDs. Each protocol version has its own `TypeMap` because the same type name may use different wire IDs in different versions.

Type names are defined in a YAML config and turned into Rust enums at **compile time** by a `build.rs` in the `type-map` crate. This means invalid type names are caught by the compiler instead of failing at runtime.

### Defining Type Maps

An example `type-maps.yaml` is provided in the [`example-type-maps.yaml`](./example-type-maps.yaml) file. Place your own `type-maps.yaml` in your project root and set the `MTP_TYPE_MAPS` environment variable (see [Customizing Type Maps in Downstream Projects](#customizing-type-maps-in-downstream-projects)).

### Using Generated Enums

After editing the config and rebuilding, `CommunicationType` and `DataType` enums are generated automatically. Use them in code:

```rust
use mtp_type_map::{CommunicationType, DataType, TypeMap};

let tm = TypeMap::v2_0();
let id = tm.data_id_enum(DataType::SomeType).unwrap();
```

The enums are a **union across all versions**; every type name from every version is a variant. The version-specific `TypeMap` maps each variant to the correct wire ID for that version. Types not defined in a version return `None`:

Encoding/decoding uses a `TypeMap` to resolve type names to wire IDs:

```rust
use mtp_codec::{encode, decode, DataValue};
use mtp_type_map::TypeMap;

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

### Forward/Backward Compatibility Between Versions

Because enums are a union of all types across versions, a variant might exist that has no wire mapping in the *negotiated* version:

```
v2.0 client sends DataType::SomeType    → host encodes with v2.0 TypeMap → wire ID 32
v2.0 host receives DataType::ExampleType (from v1.0 client) → not in v2.0 TypeMap → None → Error
```

This is by design: the host maps unknown types to `Error`, and the client should only send types that exist in its compiled-in version.

## Registry

The `registry` feature of the Codec crate adds `VersionedCodec` for version-aware encoding:

```rust
use mtp_codec::registry::{Registry, VersionedCodec};

let registry = Registry::builtin();
let codec = VersionedCodec::new(registry);

// Encode with a specific version
let bytes = codec.encode(&value, Version(2, 0)).unwrap();

// Decode with a specific version
let decoded = codec.decode(&bytes, Version(2, 0)).unwrap();
```

## Customizing Type Maps in Downstream Projects

External projects must provide their own type map configuration via the `MTP_TYPE_MAPS` environment variable. There is no bundled default; the build script will error if the variable is not set or points to an invalid file.

1. Create a `type-maps.yaml` in your project root
2. Set the `MTP_TYPE_MAPS` environment variable in `.cargo/config.toml`:

```toml
# .cargo/config.toml
[env]
MTP_TYPE_MAPS = { value = "type-maps.yaml", relative = true }
```
