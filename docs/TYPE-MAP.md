# Type Map

This file documents the Type Map & Registry configuration used by the MTP protocol.

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

The enums are a **union across all versions**; every type name from every version is a variant. The version-specific `TypeMap` maps each variant to the correct wire ID for that version. Types not defined in a version return `None`:

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

### Forward/Backward Compatibility Between Versions

Because enums are a union of all types across versions, a variant might exist that has no wire mapping in the *negotiated* version:

```
v2.0 client sends DataType::SomeType    → host encodes with v2.0 TypeMap → wire ID 32
v2.0 host receives DataType::ExampleType (from v1.0 client) → not in v2.0 TypeMap → None → Error
```

This is by design: the host maps unknown types to `Error`, and the client should only send types that exist in its compiled-in version.

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

External projects must provide their own type map configuration. Browser projects should install `mtp` and configure `mtp/vite`; they do not need to publish, fork, or copy a generated WASM package.

```typescript
import { defineConfig } from "vite";
import { mtp } from "mtp/vite";

export default defineConfig({
  plugins: [mtp({ typeMaps: "./type-maps.yaml" })],
});
```

For Rust builds, or when invoking `wasm-pack` manually, set the `MTP_TYPE_MAPS` environment variable. If the variable points to an invalid file, the build fails. If `MTP_TYPE_MAPS` is not set, the build script emits a warning and generates reserved protocol types only; application-specific communication and data types will not be available.

1. Create a `type-maps.yaml` in your project root
2. Set the `MTP_TYPE_MAPS` environment variable in `.cargo/config.toml`:

```toml
# .cargo/config.toml
[env]
MTP_TYPE_MAPS = { value = "type-maps.yaml", relative = true }
```
