# Rust test organization

Integration and adapter-contract tests live here. Unit suites remain beside their crates when
they exercise private invariants or cryptographic internals that should not become public API.
The `test-helpers` feature is reserved for safe deterministic parsers and state transitions.

Inline suites currently retained:

- `crypto`: secret-key state, ratchets, replay caches, and sealed-sender internals.
- `codec`: decoder allocation and parser invariants.
- `client`, `host`, and `bindings/wasm`: executor and browser state that would require test-only
  production plumbing to construct externally.
- `bindings/native`: private stream lifecycle and ping-control state.
- `type-map`, `files`, and `webserver`: small module-local parsing and routing invariants.
