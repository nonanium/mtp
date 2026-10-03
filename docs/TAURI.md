# Tauri integration

`tauri-plugin-mtp` owns native connections, identities, protected frames, relay capabilities and pipes for Android Tauri applications. The SDK selects its native adapter when `__TAURI_INTERNALS__` exists and the user agent is Android. Browser and Electron use the existing transport. WASM remains the bounded public codec; transport secrets and encrypted pipe keys stay native. The SDK does not call credential export, and its credentials getter does not expose native credentials.

## Host initialization and Android registration

Add `tauri-plugin-mtp` with features `tauri` and `mobile` to the host Rust dependency. Register `tauri_plugin_mtp::init(manager.clone())`. In the host native library initializer, call `tauri_plugin_mtp::mobile::install(manager.clone())` before any webview or Android service can start. Both paths must use the same `Arc<Manager>`.

The initializer must also run when `System.loadLibrary` loads the library in a boot-started service process. Installing only inside Tauri setup cannot support cold service startup. Keep the initializer linked into the host cdylib. The process-wide Tokio runtime, manager registry and identity store exist before JavaScript and are shared by background and frontend sessions.

The plugin registers Java package `org.methanium.mtp`, class `MtpPlugin`. Set `plugins.mtp.nativeLibrary` in `tauri.conf.json` to the host cdylib name without `lib` or `.so`:

```json
{
  "plugins": {
    "mtp": { "nativeLibrary": "app_lib" }
  }
}
```

Implement `HostCallbacks::resolve` for endpoint discovery and pinned host keys. `HostCallbacks::message` receives live background frames and an `Arc<Session>` for correlated requests. Keep account sync, notifications and application-specific decryption in those callbacks.

## Persistence and background lifecycle

Successful frontend connect automatically sends durable configuration and credentials directly to Android's `configure` command. Connect and credential clear serialize persistence coordination. Android Keystore persistence runs before the optional `HostCallbacks::persist` storage hook. Configurations contain serialized native keys and must not be forwarded to JavaScript. Temporary, zero-ID and unpinned identities are excluded. Never persist an enrollment identity as a permanent authenticated connection.

An optional host persistence hook can store the same configuration:

```rust
fn persist<'a>(
    &'a self,
    connections: Vec<tauri_plugin_mtp::lifecycle::BackgroundConnection>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + 'a>> {
    Box::pin(async move {
        let configuration = serde_json::to_string(&connections).map_err(|e| e.to_string())?;
        self.secure_store.write(&configuration).await
    })
}
```

Android encrypts configuration with AES-256-GCM using an Android Keystore key and authenticated format context. Backups of encrypted preferences cannot decrypt on another device. The service decrypts and restores saved `BackgroundConnection` values through `Lifecycle::start` before JavaScript, including at boot. For host-managed restoration, call the lifecycle returned by `mobile::install(manager)` with persisted connections on the native runtime before JS starts.

JS uses the same connection name and public options without importing or exporting keys. Equivalent default options reuse the restored identity; changed pins or limits fail. Endpoint and certificate options are restored from encrypted configuration. Keep discovery updates in the host's persisted options. The supervisor reconnects authenticated sessions with capped exponential backoff and randomized delay. Client protocol pings default to a 30-second interval with 5-second jitter.

The Android service is sticky and has an ongoing notification with a Stop action. Boot restoration runs only while enabled. Stop disables restoration and closes supervised sessions. Activity reopening re-enables saved configuration. Task removal requests service restart, then kills the process to permit Tauri webview recreation, with a persisted 15-second cooldown. Android force-stop prevents boot/service restart until the user opens the application.

`client.setBackgroundEnabled(false)` disables the service while preserving encrypted credentials; `true` enables it. Both require `mtp:background-service`. Frontend detach and named connection stop do not erase credentials. Credential clear cancels the named supervisor, disconnects the identity, invalidates associated capabilities and rewrites remaining credentials. If none remain, Android `clear` removes the ciphertext and Keystore key.

## Permissions and credential export

Grant `mtp:default` for ordinary connection, frame, protection, relay and raw pipe commands. Grant `mtp:encrypted-pipes` for encrypted negotiation and record commands, and `mtp:background-service` for service control. Named connection stop requires the separate `mtp:allow-mtp-stop` permission.

Credential export defaults to denied. Both `manager.set_credential_export(true)` in Rust and the explicit `mtp:export-credentials` capability are required. No frontend option enables host export policy. Export is not part of the default permission set.

## Frontend integration and migration

Keep using `MTPClient.create` and SDK request, protection, relay and pipe APIs.

| Previous integration | Plugin integration |
| --- | --- |
| Application `mtp_request` | SDK `request`, native `plugin:mtp\|mtp_request` |
| Application `mtp_status` | Native `plugin:mtp\|mtp_status` |
| Application credential storage | Native initialization and host persistence callback |
| Application sealed relay command | SDK relay construction/opening and native frame request |
| UI visibility and activity hooks | Plugin attach/detach and Android lifecycle |
| Application background receive loop | `HostCallbacks::message` |
| Application service/JNI/boot receiver | Packaged Android plugin and `mobile::install` |

Use `requestProtected(type, data, protectionOptions, requestOptions)` for correlated ciphertext responses, then `openProtected(response, openingOptions)`. Use `subscribeRaw` for ciphertext subscriptions when the application schema describes plaintext, or `subscribeProtected` to verify before callbacks. Raw paths do not validate ciphertext as plaintext. Decode protected content only after native verification.

Enrollment requests use signature/encryption purposes `0x72`/`0x73`; responses use `0x74`/`0x75`. Require dual signatures, pinned Iota keys, expected signer and expected receiver. Contact provisioning uses `0x76`/`0x77`, a permanent signing identity and an explicit temporary recipient.

Temporary native clients reject `auth` and `register`. Call `connectUnauthenticated` and use their native public identity. Their assigned guest ID and fresh keys remain available for protection but never enter durable configuration.

## Native command contract

Commands use `plugin:mtp|mtp_<command>`. Connection-scoped commands take `name`; service control takes only `enabled`. Argument keys and returned fields are camelCase. Byte buffers are arrays of u8. Identity IDs and protected/relay u64/u128 envelope fields use decimal strings, never JSON numbers. Numeric timeout and limit options use SDK-validated numbers. Content and metadata are encoded MTP DataValue bytes, preserving integers and byte values. Errors retain structured SDK `code`, `message`, `phase` and protected version fields rather than becoming strings.

### Connections and identities

- `initialize { name, options } -> { clientId: string | null, publicKeys: u8[] }`. Options include url, descriptor, pinned hostPublicKey bytes, optional imported credentials, fresh, serverCertificateHashes, maxMessageSize, authTimeoutMs, requirePq, pings and receiveLimits. Import only explicitly supplied credentials; otherwise create/load a native-held keyring. Persist pins and reject incompatible name reuse rather than ignoring options. The SDK credential name defaults to `mtp:credentials`. Repeated initialization reuses the persistent identity and authenticated connection. SDK `nativeFresh: true` or explicit `credentials: null` creates a UUID-named ephemeral identity with its own pinned host keys, independent of the default connection.
- `connect { name, mode } -> { clientId: string, state: number }`. Modes are connect, unauthenticated, auth and register. Connect authenticates a registered identity if pinned, otherwise connects unauthenticated. Auth registers an unregistered identity. Auth/register require pinned host keys. Native enforces authTimeoutMs and cancels expired handshakes, owns protocol pings and persistence, and uses WASM ConnectionState values.
- `status { name } -> boolean` reports whether the named connection is connected. `stop { name }` stops the named connection without erasing credentials.
- `clear_credentials { name }` destroys stored credentials, disconnects the identity and invalidates associated capabilities.
- `export_credentials { name } -> { clientId: string | null, keyring: u8[], hostPublicKey: u8[] | null }` requires both export gates described above.
- `attach` and `detach` take `{ name, attachmentId }`, with a stable UUID per SDK instance. Attach is idempotent. Detach leaves the named background session alive and does not stop other attachments.
- `send { name, bytes }` sends an encoded frame.
- `set_background_enabled { enabled }` is Android-only and preserves credentials when disabled.
- `request { name, bytes, responseType: string | null, deadlineMs } -> u8[]` matches response type, enforces native expiry and retains late-response tombstones. There is no arbitrary 300000ms cap. SDK deadlines must be positive safe integers. Send/request frames also have a 16 MiB bridge bound and configured receive limits.

`mtp://event` carries `[name, frameBytes]` or pipe offers `[name, { pipeId, description }]` only to attached windows. Events contain live frames and offers, never private keys or decrypted content. Detached UI history is not replayed. Multiple SDK views/listeners can attach independently.

### Protected frames

- `build_protected { name, type, content, options } -> frameBytes`. Options include receiverId, recipient public bundles, signaturePurpose, encryptionPurpose, signatureSuite ed25519/dual, optional identity, id, exposeSender, messageId u128, createdAt u64 and limits. The default identity is native-owned; an explicit keyring is imported only for the operation. Honor envelope fields and suite exactly.
- `protected_claimed_signer { name, bytes, options } -> string` decrypts enough to obtain an unverified lookup ID using the native recipient or explicit recipient/keyringHistory. Enforce encryption purpose and limits. This is not authentication.
- `open_protected { name, bytes, options } -> { type, protectedVersion, signerId, finalRecipientId, messageId, createdAt, content }`. Options additionally include signerId, signerPublicKeys, expectedSignerId, expectedReceiverId and signaturePolicy. Verify trusted bundles supplied by the SDK resolver with newest-first history. Enforce purposes, destination, signer, suite policy, version and receive limits. Return encoded content only after verification. Native does not consume a replay guard; the SDK atomically applies the caller guard after verification. Claimed IDs are not verified IDs.

Signature policies use SDK string values and the same policy registry and dual-signature verification as the WASM codec. Not every operation requires dual signatures. Explicit identities and recipients must not be replaced by the transport identity.

### Sealed relays

- `build_relay { name, type, content, metadata: u8[] | null, options } -> frameBytes`. Options include identity, finalRecipientId, nextHopId encoded route target, metadataRecipients, contentRecipients, signatureSuite, messageId, createdAt and limits. Use the native codec's reserved relay purposes and version.
- `relay_claimed_signer { name, bytes, options } -> string` provides the same bounded, unverified recipient/history lookup as protected frames, for relay metadata.
- `open_relay_metadata { name, bytes, options } -> { handle, relayVersion, signerId, finalRecipientId, messageId, createdAt, metadata: u8[] | null, encryptedContent: u8[], matchedSignerKeyIndex }`. Options include recipient, limits, signerId, signerPublicKeys, expectedSignerId and signaturePolicy. It does not consume replay state. The opaque native capability is bound to the connection and authenticated metadata, exact matched signer key and encrypted content.
- `open_relay_content { name, handle, options } -> { type, content, signerId, finalRecipientId }` enforces metadata/content binding, exact metadata suite policy, matched signer key continuity, expectedFinalRecipientId, expectedSignerId, recipient/history and limits. Released, foreign or forged handles fail.
- `release_relay { name, handle }` is idempotent. SDK calls it on disposal, finalization and opening failures.

SDK subscriptions share bounded asynchronous dispatch and per-subscription replay guards. Relay metadata callbacks dispose capabilities on completion. Opaque relay forwarding uses the public codec followed by native send.

### Raw and encrypted pipes

Shared negotiation, deadlines, cancellation and encrypted record logic live in `mtp-pipes`, with encryption behind its `encrypted` feature. The plugin owns connection-bound handles; native and WASM adapters use the shared crate rather than separate copies of record logic. See [Pipes](PIPES.md) for protocol details.

- `create_pipe { name, description } -> { handle, pipeId, description }` returns a pending outgoing handle.
- `pipe_wait { name, handle } -> { handle, pipeId, description } | null` consumes pending negotiation and returns a writer on acceptance. Null means denied.
- `pipe_cancel { name, handle }` cancels a pending offer.
- `accept_pipe { name, pipeId } -> { handle, pipeId, description }` returns a reader.
- `deny_pipe { name, pipeId }` denies an offer. Offers without an attached UI are denied.
- `create_encrypted_pipe { name, options } -> { handle, pipeId, description, context } | null` negotiates the SDK pipe-session protocol with native identity and session keys. Options include recipientId, recipientPublicKey or recipientPublicKeys, description, purpose, direction and signatureSuite. Defaults are purpose `0x40` and direction `0`. Validate recipient arrays/public bundles and bind pipe ID, sender/recipient IDs, session ID, purpose and direction in the signed transcript.
- `accept_encrypted_pipe { name, request, options } -> { handle, pipeId, description, context }` performs legacy/group/forward-secure acceptance as the SDK does. Options include senderId, senderPublicKey or senderPublicKeys, purpose, direction and signaturePolicy. Verify signer/recipient constraints and transcript before returning a handle.
- `pipe_write { name, handle, bytes }` and `pipe_read { name, handle } -> u8[] | null` are raw I/O only.
- `pipe_write_record { name, handle, bytes }` and `pipe_read_record { name, handle } -> u8[] | null` operate on plaintext records with native encryption/decryption. Serialize concurrent calls in arrival order. Maintain sequence, chain-key erasure, authenticated final records, bounded buffering and poisoned state after failure. Null means authenticated finalization, never unauthenticated EOF.
- `pipe_close { name, handle }` emits the encrypted final record for encrypted writers and closes transport. `pipe_abort { name, handle }` destroys keys and aborts transport. Reject foreign/released handles and raw I/O on encrypted capabilities.

Encrypted results include public context fields `sessionId`, `purpose`, `direction` and `transcriptHash`. SDK builds `MTPPipeProtectionContext` from these; session keys remain native. The current SDK implements these command paths, beyond the original six-command bridge.

## Packaging and release

`node plugins/tauri/stage-release.mjs <destination>` stages the Rust workspace, Android source, permissions and this guide into `<destination>/mtp-native`. It does not publish or build an APK. The plugin Cargo readme points to `../../docs/TAURI.md`; release staging preserves that layout. Cargo packaging includes the external readme as `TAURI.md` at the package root.

Host Android builds include the plugin Gradle library through Tauri registration. Keep the host native initializer linked into its cdylib. The local upstream Tauri Android build support is described in [Android source notes](../plugins/tauri/android/Info.md).

## Verification and platform limitations

Use the repository Nix development shell. Linux Tauri checks need GLib, GTK3, WebKitGTK 4.1 and libsoup 3, supplied by the default shell:

```sh
nix develop
cargo test -p tauri-plugin-mtp -p mtp-native -p mtp-client -p mtp-pipes --features tauri-plugin-mtp/mobile,mtp-pipes/encrypted
cargo check -p tauri-plugin-mtp --features tauri,mobile
pnpm --dir sdk run build:ts
pnpm --dir sdk run test:types
```

Local loopback tests exercise concurrent request IDs, reverse-order responses, shared connection reuse, conflicts, native fanout, detach without replay, absent-UI pipe denial and cancellation while waiting. Export tests check host policy and the separate permission manifest. SDK attachment independence and disposal during connection also need verification when changing adapter lifecycle; there is currently no `sdk/src/sdk/native.test.ts` or runnable `sdk/dist/sdk/native.test.js` suite in this checkout.

Earlier integration verification recorded Kotlin compilation with a temporary host Gradle fixture using AGP 8.7.3, Kotlin 2.0.21 and Cargo's Tauri 2.12.1 Android project. A Nix Android SDK supplied platforms 35/36, build-tools 34/35 and accepted licenses. All-feature Rust checks used aarch64-linux-android through rust-overlay, native Nix clang/LLVM ar and NDK r29 sysroot headers targeting API 24. These were compilation checks, without APK linking.

Android compilation requires a JVM, Android SDK and NDK. Linux compilation does not verify Android-only registration or Kotlin source. Device lifecycle verification requires an Android device, including cold boot restoration, Stop, activity reopening, task removal and force-stop behavior. Automatic SDK native selection and background service integration are Android-specific; this plugin does not supply an iOS background service.
