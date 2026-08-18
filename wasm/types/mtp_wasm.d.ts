/* tslint:disable */
/* eslint-disable */

export interface ParsedEncryptedValue {
    kind: "encrypted";
    encryptionType: number;
    purpose: number;
    recipientCount: number;
    encoded: Uint8Array;
}

export interface ParsedSignedValue {
    kind: "signed";
    signatureType: number;
    purpose: number;
    signerId: bigint;
    value: ParsedDataValue;
}

export type ParsedDataValue =
| boolean
| number
| bigint
| string
| Uint8Array
| ParsedDataValue[]
| { [key: string]: ParsedDataValue }
| ParsedEncryptedValue
| ParsedSignedValue
| null;

export interface ParsedFrame {
    id?: number;
    type: string;
    sender?: bigint;
    receiver?: bigint;
    data: ParsedDataValue;
    raw: Uint8Array;
}



export interface PipeWriter {
    write(data: Uint8Array): Promise<void>;
    close(): Promise<void>;
    abort(): void;
    readonly pipeId: number;
}

export interface PipeReader {
    read(): Promise<Uint8Array | null>;
    readonly pipeId: number;
    readonly description: string;
}



export interface WasmPipeHandle {
    wait(): Promise<PipeWriter | null>;
    readonly pipeId: number;
    readonly description: string;
}



export class ConnectionConfig {
    free(): void;
    [Symbol.dispose](): void;
    constructor(url: string);
    client_id: bigint;
    get description(): string | undefined;
    set description(value: string);
    max_message_size: number;
    require_pq: boolean;
    set server_certificate_hashes(value: string[]);
    readonly url: string;
}

export enum ConnectionState {
    Disconnected = 0,
    Connecting = 1,
    Connected = 2,
    Failed = 3,
}

export class PipeReader {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    description(): string;
    pipe_id(): number;
    read(): Promise<any>;
}

export class PipeWriter {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    abort(): void;
    close(): Promise<void>;
    pipe_id(): number;
    write(data: Uint8Array): Promise<void>;
}

export class WasmChaCha20Poly1305 {
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Decrypt `nonce || ciphertext` with `aad`.
     */
    decrypt(ciphertext: Uint8Array, aad: Uint8Array): Uint8Array;
    /**
     * Encrypt `plaintext` with `aad`.
     * Returns `nonce || ciphertext`.
     */
    encrypt(plaintext: Uint8Array, aad: Uint8Array): Uint8Array;
    /**
     * Create a new cipher with a 32-byte key.
     */
    constructor(key: Uint8Array);
}

export class WasmClient {
    free(): void;
    [Symbol.dispose](): void;
    accept_pipe(pipe_id: number): Promise<PipeReader>;
    authConnectOwned(config: ConnectionConfig, host_public_key_bytes: Uint8Array, keyring_bytes: Uint8Array, client_id: bigint): Promise<bigint>;
    authRegisterOwned(config: ConnectionConfig, host_public_key_bytes: Uint8Array, keyring_bytes: Uint8Array): Promise<bigint>;
    auth_connect(config: ConnectionConfig, host_public_key_bytes: Uint8Array, keyring_bytes: Uint8Array, client_id: bigint): Promise<bigint>;
    auth_register(config: ConnectionConfig, host_public_key_bytes: Uint8Array, keyring_bytes: Uint8Array): Promise<bigint>;
    connect(config: ConnectionConfig): Promise<void>;
    connectOwned(config: ConnectionConfig): Promise<void>;
    create_pipe(description: string): Promise<WasmPipeHandle>;
    deny_pipe(pipe_id: number): Promise<void>;
    disconnect(): void;
    static is_supported(): boolean;
    constructor(on_state_change?: Function | null, on_message?: Function | null, on_error?: Function | null);
    request(frame: Uint8Array, response_type?: string | null, timeout_ms?: number | null): Promise<any>;
    send(frame: Uint8Array): Promise<void>;
    set_on_pipe_request(callback?: Function | null): void;
    /**
     * Apply one decoder policy to frames received by this raw WASM client.
     * The high-level SDK calls this before authentication so handshake,
     * transport, and protected opening share the same policy input.
     */
    set_receive_limits(limits: any): void;
    start_protocol_pings(interval_ms: number, client_id: bigint): void;
    stop_protocol_pings(): void;
    subscribe(message_type: string, callback: Function): number;
    unsubscribe(id: number): boolean;
    readonly client_id: bigint;
    readonly ping_ms: number | undefined;
    readonly state: number;
}

export class WasmEd25519Signer {
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Load a signer from its 32-byte secret key.
     */
    constructor(secret_key: Uint8Array);
    /**
     * Sign `message` and return the signature bytes.
     */
    sign(message: Uint8Array): Uint8Array;
    /**
     * Verify `signature` against `message`.
     */
    verify(message: Uint8Array, signature: Uint8Array): void;
}

/**
 * KEM encapsulation result returned to JavaScript.
 *
 * `shared_secret` is the symmetric key both parties will derive; `ciphertext`
 * is the KEM ciphertext that must be sent to the recipient so they can
 * decapsulate and recover the same shared secret.
 */
export class WasmEncapsulated {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    /**
     * KEM ciphertext to transmit to the recipient.
     */
    readonly ciphertext: Uint8Array;
    /**
     * Symmetric secret derived during encapsulation.
     */
    readonly shared_secret: Uint8Array;
}

/**
 * A short-lived ephemeral hybrid-KEM keypair for the forward-secure pipe
 * handshake. The secret is zeroized when the object is freed.
 */
export class WasmKemKeypair {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    readonly public_key: Uint8Array;
    readonly secret_key: Uint8Array;
}

export class WasmKeyring {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Deserialise a keyring from bytes.
     */
    static from_bytes(bytes: Uint8Array): WasmKeyring;
    /**
     * Return the public half of this keyring as a bundle.
     */
    public_key_bundle(): WasmPublicKeyBundle;
    /**
     * Serialise the keyring to bytes and report malformed caller-owned
     * material as a JavaScript exception.
     */
    to_bytes(): Uint8Array;
    try_to_bytes(): Uint8Array;
    /**
     * Validate the KEM public/private pair without requiring PQ signing
     * material. This is the invariant needed by envelope recipients and
     * sealed-relay clients that explicitly choose Ed25519 signatures.
     */
    validate_encryption(): void;
    /**
     * Validate that all full-suite public/private components correspond.
     * Role-specific browser keyrings may intentionally fail this check.
     */
    validate_full(): void;
}

/**
 * Log severity used by the public SDK when translating raw WASM events.
 */
export enum WasmLogHint {
    Info = 0,
    Warning = 1,
    Error = 2,
}

export class WasmPipeHandle {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    wait(): Promise<any>;
    readonly description: string;
    readonly pipe_id: number;
}

export class WasmPublicKeyBundle {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    static from_bytes(bytes: Uint8Array): WasmPublicKeyBundle;
    /**
     * Deserialise an explicitly partial bundle for development-only key
     * material. Protocol encryption and signature verification use the
     * strict `from_bytes` parser above.
     */
    static from_bytes_unvalidated(bytes: Uint8Array): WasmPublicKeyBundle;
    to_bytes(): Uint8Array;
    try_to_bytes(): Uint8Array;
    readonly kem_public_key: Uint8Array;
    readonly sig_cl_public_key: Uint8Array;
    readonly sig_pq_public_key: Uint8Array;
}

/**
 * Minimal message router used by higher-level SDK subscription code.
 */
export class WasmSubscriptionRouter {
    free(): void;
    [Symbol.dispose](): void;
    dispatch(message_type: string, message: any): boolean;
    constructor();
    subscribe(message_type: string, callback: Function): void;
    unsubscribe(message_type: string): boolean;
}

export class WasmVerifiedProtectedMessage {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    content(): Uint8Array;
    created_at(): bigint;
    final_recipient_id(): bigint;
    matched_signer_key_index(): number;
    message_id(): string;
    message_type(): string;
    protected_version(): bigint;
    signer_id(): bigint;
}

export class WasmVerifiedRelayContent {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    content(): Uint8Array;
    final_recipient_id(): bigint;
    message_type(): string;
    signer_id(): bigint;
}

export class WasmVerifiedRelayMetadata {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    created_at(): bigint;
    encrypted_content(): Uint8Array;
    final_recipient_id(): bigint;
    matched_signer_key_index(): number;
    message_id(): string;
    metadata(): any;
    relay_version(): bigint;
    signer_id(): bigint;
}

/**
 * Build a relay frame using an explicit Ed25519 or dual-signature policy.
 * `created_at` is Unix epoch milliseconds.
 */
export function build_encrypted_relay_frame_with_keyring(message_type: string, data: any, signer_id: bigint, final_recipient_id: bigint, next_hop_id: bigint, message_id: string, created_at: bigint, encoded_metadata: Uint8Array | null | undefined, keyring_bytes: Uint8Array, signature_suite: number, metadata_recipient_public_key_bundles: any, content_recipient_public_key_bundles: any): Uint8Array;

/**
 * Build a sealed relay frame with explicit encoder and semantic field
 * limits. The same limits are applied by the native relay builder.
 */
export function build_encrypted_relay_frame_with_keyring_with_limits(message_type: string, data: any, signer_id: bigint, final_recipient_id: bigint, next_hop_id: bigint, message_id: string, created_at: bigint, encoded_metadata: Uint8Array | null | undefined, keyring_bytes: Uint8Array, signature_suite: number, metadata_recipient_public_key_bundles: any, content_recipient_public_key_bundles: any, limits: any): Uint8Array;

/**
 * Build a typed MTP frame using generated communication/data type names.
 */
export function build_frame(message_type: string, data: any, options: any): Uint8Array;

/**
 * Build a typed frame with explicit recursion and complete-frame output
 * limits. High-level SDK sends use this entry point with the transport's
 * admitted message size.
 */
export function build_frame_with_limits(message_type: string, data: any, options: any, limits: any): Uint8Array;

/**
 * Build a typed MTP frame around a complete serialized `DataValue` payload.
 *
 * Unlike [`build_frame`], this does not interpret the payload as a clear data
 * container. It can therefore carry any value supported by the codec,
 * including signed and encrypted protection wrappers.
 */
export function build_frame_with_payload(message_type: string, serialized_payload: Uint8Array, options: any): Uint8Array;

/**
 * Build a typed frame around a serialized payload with explicit output
 * limits. The payload is also parsed with a policy derived from that limit so
 * an oversized/deep input cannot bypass the bounded builder.
 */
export function build_frame_with_payload_with_limits(message_type: string, serialized_payload: Uint8Array, options: any, limits: any): Uint8Array;

/**
 * Build a protocol-level Ping frame with description, timestamp, and optional data.
 */
export function build_ping_frame(client_id: bigint, description: string, timestamp: bigint, data: Uint8Array): Uint8Array;

/**
 * Build a complete encrypted direct protected frame in the native codec.
 * The native builder owns both the protected envelope and the clear outer
 * routing fields, including the optional sender exposure and frame ID.
 */
export function build_protected_frame_with_keyring(message_type: string, encoded_content: Uint8Array, signer_id: bigint, final_recipient_id: bigint, message_id: string, created_at: bigint, signature_purpose: number, encryption_purpose: number, keyring_bytes: Uint8Array, signature_suite: number, frame_id: number | null | undefined, expose_sender: boolean, recipient_public_key_bundles: any): Uint8Array;

/**
 * Build a complete encrypted protected frame with explicit encoder and
 * semantic protected-field limits.
 */
export function build_protected_frame_with_keyring_with_limits(message_type: string, encoded_content: Uint8Array, signer_id: bigint, final_recipient_id: bigint, message_id: string, created_at: bigint, signature_purpose: number, encryption_purpose: number, keyring_bytes: Uint8Array, signature_suite: number, frame_id: number | null | undefined, expose_sender: boolean, recipient_public_key_bundles: any, limits: any): Uint8Array;

/**
 * Decrypt a serialized `Encrypted<Value>` wrapper with a serialized keyring.
 * The expected purpose is supplied by the protocol caller, not taken from
 * the untrusted encrypted wrapper.
 */
export function decrypt_data_value(value: Uint8Array, keyring: Uint8Array, expected_purpose: number): Uint8Array;

/**
 * Decrypt using a caller-supplied local key history. Recipient key
 * identifiers remain absent from the serialized envelope.
 */
export function decrypt_data_value_with_keyrings(value: Uint8Array, keyrings: any, expected_purpose: number): Uint8Array;

/**
 * Generate a fresh Ed25519 keypair.
 *
 * Returns `{ signer: WasmEd25519Signer, secretKey: Uint8Array, publicKey: Uint8Array }`.
 */
export function ed25519_generate(): any;

/**
 * Standalone Ed25519 signature verification.
 */
export function ed25519_verify(public_key: Uint8Array, message: Uint8Array, signature: Uint8Array): void;

/**
 * Encode one standalone `DataValue` using the negotiated/current type map.
 */
export function encode_data_value(value: any): Uint8Array;

/**
 * Encode one standalone `DataValue` using explicit recursion and output
 * limits. The compatibility entry point above keeps the historical default.
 */
export function encode_data_value_with_limits(value: any, limits: any): Uint8Array;

/**
 * Encrypt a serialized `DataValue` for one recipient using the canonical
 * multi-recipient envelope.
 */
export function encrypt_data_value(value: Uint8Array, recipient_public_key_bundle: Uint8Array, purpose: number): Uint8Array;

/**
 * Encrypt a serialized `DataValue` for one or more recipients.
 *
 * `recipient_public_key_bundles` may be a single `Uint8Array` for the common
 * case or an array of serialized public-key bundles. The array form uses the
 * same canonical envelope as native multi-recipient encryption.
 */
export function encrypt_data_value_for_recipients(value: Uint8Array, recipient_public_key_bundles: any, purpose: number): Uint8Array;

/**
 * Parse any MTP frame into the human-readable CommunicationValue display form.
 */
export function format_frame(frame: Uint8Array): string;

/**
 * Forward a sealed relay frame to another clear next hop without opening or
 * re-encoding its authenticated encrypted payload.
 */
export function forward_encrypted_relay_frame(frame: Uint8Array, next_hop_receiver_id: bigint): Uint8Array;

/**
 * Build a [`Keyring`] containing only an Ed25519 keypair (no KEM, no ML-DSA).
 *
 * Takes the Ed25519 secret key and public key, each 32 bytes.
 * Returns the serialised keyring bytes, suitable for passing to `WasmClient.auth_register`.
 */
export function keyring_from_ed25519(secret_key: Uint8Array, public_key: Uint8Array): Uint8Array;

/**
 * Generate a full keyring with KEM, ML-DSA, and Ed25519 keys.
 */
export function keyring_generate(): Uint8Array;

/**
 * Generate a full keyring and report serialization failures to JavaScript.
 */
export function keyring_generate_checked(): Uint8Array;

export function main(): void;

/**
 * Return the canonical MTP pipe-session encryption purpose.
 */
export function mtp_pipe_session_encryption_purpose(): number;

/**
 * Return the canonical MTP pipe-session signature purpose.
 */
export function mtp_pipe_session_signature_purpose(): number;

/**
 * Explicit compatibility policy value accepting any signature suite
 * supported by this WASM build. New callers should prefer a fixed suite.
 */
export function mtp_protection_signature_suite_any_supported(): number;

export function mtp_protection_signature_suite_dual(): number;

export function mtp_protection_signature_suite_ed25519(): number;

/**
 * Return the canonical MTP relay content-encryption purpose.
 */
export function mtp_relay_content_encryption_purpose(): number;

/**
 * Return the canonical MTP relay content-signature purpose.
 */
export function mtp_relay_content_signature_purpose(): number;

/**
 * Return the canonical MTP relay metadata-encryption purpose.
 */
export function mtp_relay_metadata_encryption_purpose(): number;

/**
 * Return the canonical MTP relay metadata-signature purpose.
 */
export function mtp_relay_metadata_signature_purpose(): number;

/**
 * Length, in bytes, of symmetric keys produced by the MTP key-derivation
 * bindings. SDKs should query this instead of duplicating the crypto
 * primitive's output size.
 */
export function mtp_symmetric_key_length(): number;

/**
 * Open a bounded protected value without replay protection. The raw WASM
 * boundary cannot accept a native replay-guard trait, so message-processing
 * callers must use the SDK guard or a native checked API.
 */
export function open_protected_with_keyrings_with_limits_without_replay(frame: Uint8Array, keyrings: any, expected_signer_id: any, signer_public_key_bundles: any, expected_receiver_id: any, signature_purpose: number, encryption_purpose: number, signature_suite: number, limits: any): WasmVerifiedProtectedMessage;

/**
 * Open a protected value without replay protection. This raw entry point is
 * intended for stored/forensic messages; message-processing callers should
 * apply their replay guard in the SDK or use a checked native API.
 */
export function open_protected_with_keyrings_without_replay(frame: Uint8Array, keyrings: any, expected_signer_id: any, signer_public_key_bundles: any, expected_receiver_id: any, signature_purpose: number, encryption_purpose: number, signature_suite: number): WasmVerifiedProtectedMessage;

/**
 * Open bounded relay content without replay protection. Replay is consumed
 * when metadata is accepted by the live SDK/native processing boundary.
 */
export function open_relay_content_with_keyrings_with_limits_without_replay(metadata: WasmVerifiedRelayMetadata, keyrings: any, signer_public_key_bundles: any, expected_final_recipient_id: any, signature_suite: number, limits: any): WasmVerifiedRelayContent;

/**
 * Open relay content without making a second replay decision. Replay is
 * consumed when live message processing accepts the authenticated metadata.
 */
export function open_relay_content_with_keyrings_without_replay(metadata: WasmVerifiedRelayMetadata, keyrings: any, signer_public_key_bundles: any, expected_final_recipient_id: any, signature_suite: number): WasmVerifiedRelayContent;

/**
 * Open bounded relay metadata without replay protection. Use the SDK's
 * message-processing guard or a native checked API for live traffic.
 */
export function open_relay_metadata_with_keyrings_with_limits_without_replay(frame: Uint8Array, keyrings: any, expected_signer_id: any, signer_public_key_bundles: any, signature_suite: number, limits: any): WasmVerifiedRelayMetadata;

/**
 * Open relay metadata without replay protection. This raw entry point is for
 * stored/forwarded messages; message-processing paths should add a guard in
 * the SDK or use the checked native API.
 */
export function open_relay_metadata_with_keyrings_without_replay(frame: Uint8Array, keyrings: any, expected_signer_id: any, signer_public_key_bundles: any, signature_suite: number): WasmVerifiedRelayMetadata;

/**
 * Parse an auth response frame into a JS object.
 */
export function parse_auth_response(response: Uint8Array): AuthResponse;

/**
 * Parse a standalone serialized `DataValue` into the same structured form
 * used for frame payloads. Protected values remain opaque until the caller
 * explicitly opens and verifies them.
 */
export function parse_data_value(value: Uint8Array): ParsedDataValue;

/**
 * Parse a standalone serialized `DataValue` with the caller's bounded
 * receive policy. The compatibility `parse_data_value` entry point retains
 * the default policy for existing callers.
 */
export function parse_data_value_with_limits(value: Uint8Array, limits: any): ParsedDataValue;

/**
 * Parse any MTP frame into structured JavaScript data.
 */
export function parse_frame(frame: Uint8Array): ParsedFrame;

/**
 * Parse a frame with the caller's bounded receive policy. The compatibility
 * `parse_frame` entry point retains the default policy for existing callers.
 */
export function parse_frame_with_limits(frame: Uint8Array, limits: any): ParsedFrame;

/**
 * Read the claimed, unverified signer ID after decrypting the protected
 * payload. The result may only select trusted keys for the same signer ID.
 */
export function protected_claimed_signer_id(frame: Uint8Array, keyrings: any, encryption_purpose: number): bigint;

export function protected_claimed_signer_id_with_limits(frame: Uint8Array, keyrings: any, encryption_purpose: number, limits: any): bigint;

/**
 * Read the claimed, unverified signer ID from a relay without duplicating the
 * versioned relay metadata parser in the JavaScript SDK. The caller must bind
 * this value as the expected signer during the subsequent verification call.
 */
export function relay_metadata_claimed_signer_id(frame: Uint8Array, keyrings: any): bigint;

export function relay_metadata_claimed_signer_id_with_limits(frame: Uint8Array, keyrings: any, limits: any): bigint;

/**
 * Sign a serialized `DataValue` using the selected suite from a serialized
 * keyring.
 */
export function sign_data_value_with_keyring(value: Uint8Array, signer_id: bigint, purpose: number, keyring: Uint8Array, signature_suite: number): Uint8Array;

/**
 * Verify a serialized `Signed<Value>` wrapper while enforcing the receiver's
 * required signature suite. `0` retains the legacy any-supported behavior;
 * new protocol callers should pass one of the exported suite constants.
 */
export function verify_data_value_with_policy(value: Uint8Array, public_key_bundle: Uint8Array, expected_signer_id: bigint, expected_purpose: number, signature_suite: number): void;

/**
 * Derive a 32-byte key from a passphrase using explicit Argon2id parameters.
 * The salt and parameters are part of the caller's protected-data format.
 */
export function wasm_argon2id(passphrase: Uint8Array, salt: Uint8Array, memory_kib: number, iterations: number, lanes: number): Uint8Array;

/**
 * Derive a 32-byte encryption key from `ikm` with `salt` and `context`.
 */
export function wasm_derive_encryption_key(ikm: Uint8Array, salt: Uint8Array, context: Uint8Array): Uint8Array;

/**
 * HKDF-expand: derive `len` bytes from `ikm` with `salt` and `info`.
 */
export function wasm_hkdf_expand(ikm: Uint8Array, salt: Uint8Array, info: Uint8Array, len: number): Uint8Array;

/**
 * Decapsulate a KEM `ciphertext` with the recipient's `private_key`.
 *
 * Returns the same shared secret the initiator obtained from
 * [`wasm_kem_encapsulate`].
 */
export function wasm_kem_decapsulate(recipient_private_key: Uint8Array, ciphertext: Uint8Array): Uint8Array;

/**
 * Encapsulate a fresh shared secret for `recipient_public_key`.
 *
 * Returns a [`WasmEncapsulated`] containing the shared secret and the KEM
 * ciphertext that the recipient needs to recover it via
 * [`wasm_kem_decapsulate`].
 */
export function wasm_kem_encapsulate(recipient_public_key: Uint8Array): WasmEncapsulated;

export function wasm_kem_generate_keypair(): WasmKemKeypair;

/**
 * SHA-256 digest.
 */
export function wasm_sha256(data: Uint8Array): Uint8Array;

/**
 * Double SHA-256 (SHA-256 applied twice).
 */
export function wasm_sha256_double(data: Uint8Array): Uint8Array;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly __wbg_wasmchacha20poly1305_free: (a: number, b: number) => void;
    readonly __wbg_wasmed25519signer_free: (a: number, b: number) => void;
    readonly __wbg_wasmencapsulated_free: (a: number, b: number) => void;
    readonly __wbg_wasmkemkeypair_free: (a: number, b: number) => void;
    readonly __wbg_wasmkeyring_free: (a: number, b: number) => void;
    readonly __wbg_wasmpublickeybundle_free: (a: number, b: number) => void;
    readonly build_encrypted_relay_frame_with_keyring: (a: number, b: number, c: any, d: bigint, e: bigint, f: bigint, g: number, h: number, i: bigint, j: number, k: number, l: number, m: number, n: number, o: any, p: any) => [number, number, number, number];
    readonly build_encrypted_relay_frame_with_keyring_with_limits: (a: number, b: number, c: any, d: bigint, e: bigint, f: bigint, g: number, h: number, i: bigint, j: number, k: number, l: number, m: number, n: number, o: any, p: any, q: any) => [number, number, number, number];
    readonly decrypt_data_value: (a: number, b: number, c: number, d: number, e: number) => [number, number, number, number];
    readonly decrypt_data_value_with_keyrings: (a: number, b: number, c: any, d: number) => [number, number, number, number];
    readonly ed25519_generate: () => [number, number, number];
    readonly ed25519_verify: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number];
    readonly encrypt_data_value: (a: number, b: number, c: number, d: number, e: number) => [number, number, number, number];
    readonly encrypt_data_value_for_recipients: (a: number, b: number, c: any, d: number) => [number, number, number, number];
    readonly forward_encrypted_relay_frame: (a: number, b: number, c: bigint) => [number, number, number, number];
    readonly keyring_from_ed25519: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly keyring_generate: () => [number, number, number, number];
    readonly keyring_generate_checked: () => [number, number, number, number];
    readonly mtp_pipe_session_encryption_purpose: () => number;
    readonly mtp_pipe_session_signature_purpose: () => number;
    readonly mtp_protection_signature_suite_any_supported: () => number;
    readonly mtp_protection_signature_suite_dual: () => number;
    readonly mtp_protection_signature_suite_ed25519: () => number;
    readonly mtp_relay_content_encryption_purpose: () => number;
    readonly mtp_relay_content_signature_purpose: () => number;
    readonly mtp_relay_metadata_encryption_purpose: () => number;
    readonly mtp_relay_metadata_signature_purpose: () => number;
    readonly mtp_symmetric_key_length: () => number;
    readonly sign_data_value_with_keyring: (a: number, b: number, c: bigint, d: number, e: number, f: number, g: number) => [number, number, number, number];
    readonly verify_data_value_with_policy: (a: number, b: number, c: number, d: number, e: bigint, f: number, g: number) => [number, number];
    readonly wasm_argon2id: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => [number, number, number, number];
    readonly wasm_derive_encryption_key: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly wasm_hkdf_expand: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => [number, number, number, number];
    readonly wasm_kem_decapsulate: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly wasm_kem_encapsulate: (a: number, b: number) => [number, number, number];
    readonly wasm_kem_generate_keypair: () => number;
    readonly wasm_sha256: (a: number, b: number) => [number, number];
    readonly wasm_sha256_double: (a: number, b: number) => [number, number];
    readonly wasmchacha20poly1305_decrypt: (a: number, b: number, c: number, d: number, e: number) => [number, number, number, number];
    readonly wasmchacha20poly1305_encrypt: (a: number, b: number, c: number, d: number, e: number) => [number, number, number, number];
    readonly wasmchacha20poly1305_new: (a: number, b: number) => [number, number, number];
    readonly wasmed25519signer_new: (a: number, b: number) => [number, number, number];
    readonly wasmed25519signer_sign: (a: number, b: number, c: number) => [number, number, number, number];
    readonly wasmed25519signer_verify: (a: number, b: number, c: number, d: number, e: number) => [number, number];
    readonly wasmencapsulated_ciphertext: (a: number) => [number, number];
    readonly wasmencapsulated_shared_secret: (a: number) => [number, number];
    readonly wasmkemkeypair_public_key: (a: number) => [number, number];
    readonly wasmkemkeypair_secret_key: (a: number) => [number, number];
    readonly wasmkeyring_from_bytes: (a: number, b: number) => [number, number, number];
    readonly wasmkeyring_public_key_bundle: (a: number) => number;
    readonly wasmkeyring_to_bytes: (a: number) => [number, number, number, number];
    readonly wasmkeyring_try_to_bytes: (a: number) => [number, number, number, number];
    readonly wasmkeyring_validate_encryption: (a: number) => [number, number];
    readonly wasmkeyring_validate_full: (a: number) => [number, number];
    readonly wasmpublickeybundle_from_bytes: (a: number, b: number) => [number, number, number];
    readonly wasmpublickeybundle_from_bytes_unvalidated: (a: number, b: number) => [number, number, number];
    readonly wasmpublickeybundle_kem_public_key: (a: number) => [number, number];
    readonly wasmpublickeybundle_sig_cl_public_key: (a: number) => [number, number];
    readonly wasmpublickeybundle_sig_pq_public_key: (a: number) => [number, number];
    readonly wasmpublickeybundle_to_bytes: (a: number) => [number, number, number, number];
    readonly wasmpublickeybundle_try_to_bytes: (a: number) => [number, number, number, number];
    readonly build_frame: (a: number, b: number, c: any, d: any) => [number, number, number, number];
    readonly build_frame_with_limits: (a: number, b: number, c: any, d: any, e: any) => [number, number, number, number];
    readonly build_frame_with_payload: (a: number, b: number, c: number, d: number, e: any) => [number, number, number, number];
    readonly build_frame_with_payload_with_limits: (a: number, b: number, c: number, d: number, e: any, f: any) => [number, number, number, number];
    readonly build_ping_frame: (a: bigint, b: number, c: number, d: bigint, e: number, f: number) => [number, number, number, number];
    readonly encode_data_value: (a: any) => [number, number, number, number];
    readonly encode_data_value_with_limits: (a: any, b: any) => [number, number, number, number];
    readonly format_frame: (a: number, b: number) => [number, number, number, number];
    readonly parse_auth_response: (a: number, b: number) => [number, number, number];
    readonly parse_data_value: (a: number, b: number) => [number, number, number];
    readonly parse_data_value_with_limits: (a: number, b: number, c: any) => [number, number, number];
    readonly parse_frame: (a: number, b: number) => [number, number, number];
    readonly parse_frame_with_limits: (a: number, b: number, c: any) => [number, number, number];
    readonly __wbg_wasmclient_free: (a: number, b: number) => void;
    readonly wasmclient_client_id: (a: number) => bigint;
    readonly wasmclient_is_supported: () => number;
    readonly wasmclient_new: (a: number, b: number, c: number) => number;
    readonly wasmclient_ping_ms: (a: number) => [number, number];
    readonly wasmclient_request: (a: number, b: number, c: number, d: number, e: number, f: number) => any;
    readonly wasmclient_send: (a: number, b: number, c: number) => any;
    readonly wasmclient_set_receive_limits: (a: number, b: any) => [number, number];
    readonly wasmclient_state: (a: number) => number;
    readonly wasmclient_subscribe: (a: number, b: number, c: number, d: any) => number;
    readonly wasmclient_unsubscribe: (a: number, b: number) => number;
    readonly __wbg_wasmverifiedrelaycontent_free: (a: number, b: number) => void;
    readonly __wbg_wasmverifiedrelaymetadata_free: (a: number, b: number) => void;
    readonly open_relay_content_with_keyrings_with_limits_without_replay: (a: number, b: any, c: any, d: any, e: number, f: any) => [number, number, number];
    readonly open_relay_content_with_keyrings_without_replay: (a: number, b: any, c: any, d: any, e: number) => [number, number, number];
    readonly open_relay_metadata_with_keyrings_with_limits_without_replay: (a: number, b: number, c: any, d: any, e: any, f: number, g: any) => [number, number, number];
    readonly open_relay_metadata_with_keyrings_without_replay: (a: number, b: number, c: any, d: any, e: any, f: number) => [number, number, number];
    readonly relay_metadata_claimed_signer_id: (a: number, b: number, c: any) => [bigint, number, number];
    readonly relay_metadata_claimed_signer_id_with_limits: (a: number, b: number, c: any, d: any) => [bigint, number, number];
    readonly wasmverifiedrelaycontent_content: (a: number) => [number, number, number, number];
    readonly wasmverifiedrelaycontent_final_recipient_id: (a: number) => bigint;
    readonly wasmverifiedrelaycontent_message_type: (a: number) => [number, number];
    readonly wasmverifiedrelaycontent_signer_id: (a: number) => bigint;
    readonly wasmverifiedrelaymetadata_created_at: (a: number) => bigint;
    readonly wasmverifiedrelaymetadata_encrypted_content: (a: number) => [number, number, number, number];
    readonly wasmverifiedrelaymetadata_final_recipient_id: (a: number) => bigint;
    readonly wasmverifiedrelaymetadata_matched_signer_key_index: (a: number) => number;
    readonly wasmverifiedrelaymetadata_message_id: (a: number) => [number, number];
    readonly wasmverifiedrelaymetadata_metadata: (a: number) => [number, number, number];
    readonly wasmverifiedrelaymetadata_relay_version: (a: number) => bigint;
    readonly wasmverifiedrelaymetadata_signer_id: (a: number) => bigint;
    readonly __wbg_wasmverifiedprotectedmessage_free: (a: number, b: number) => void;
    readonly build_protected_frame_with_keyring: (a: number, b: number, c: number, d: number, e: bigint, f: bigint, g: number, h: number, i: bigint, j: number, k: number, l: number, m: number, n: number, o: number, p: number, q: any) => [number, number, number, number];
    readonly build_protected_frame_with_keyring_with_limits: (a: number, b: number, c: number, d: number, e: bigint, f: bigint, g: number, h: number, i: bigint, j: number, k: number, l: number, m: number, n: number, o: number, p: number, q: any, r: any) => [number, number, number, number];
    readonly open_protected_with_keyrings_with_limits_without_replay: (a: number, b: number, c: any, d: any, e: any, f: any, g: number, h: number, i: number, j: any) => [number, number, number];
    readonly open_protected_with_keyrings_without_replay: (a: number, b: number, c: any, d: any, e: any, f: any, g: number, h: number, i: number) => [number, number, number];
    readonly protected_claimed_signer_id: (a: number, b: number, c: any, d: number) => [bigint, number, number];
    readonly protected_claimed_signer_id_with_limits: (a: number, b: number, c: any, d: number, e: any) => [bigint, number, number];
    readonly wasmverifiedprotectedmessage_content: (a: number) => [number, number, number, number];
    readonly wasmverifiedprotectedmessage_created_at: (a: number) => bigint;
    readonly wasmverifiedprotectedmessage_final_recipient_id: (a: number) => bigint;
    readonly wasmverifiedprotectedmessage_matched_signer_key_index: (a: number) => number;
    readonly wasmverifiedprotectedmessage_message_id: (a: number) => [number, number];
    readonly wasmverifiedprotectedmessage_message_type: (a: number) => [number, number];
    readonly wasmverifiedprotectedmessage_protected_version: (a: number) => bigint;
    readonly wasmverifiedprotectedmessage_signer_id: (a: number) => bigint;
    readonly __wbg_wasmpipehandle_free: (a: number, b: number) => void;
    readonly wasmpipehandle_description: (a: number) => [number, number];
    readonly wasmpipehandle_pipe_id: (a: number) => number;
    readonly wasmpipehandle_wait: (a: number) => any;
    readonly __wbg_wasmsubscriptionrouter_free: (a: number, b: number) => void;
    readonly wasmsubscriptionrouter_dispatch: (a: number, b: number, c: number, d: any) => number;
    readonly wasmsubscriptionrouter_new: () => number;
    readonly wasmsubscriptionrouter_subscribe: (a: number, b: number, c: number, d: any) => void;
    readonly wasmsubscriptionrouter_unsubscribe: (a: number, b: number, c: number) => number;
    readonly main: () => void;
    readonly wasmclient_authConnectOwned: (a: number, b: number, c: number, d: number, e: number, f: number, g: bigint) => any;
    readonly wasmclient_authRegisterOwned: (a: number, b: number, c: number, d: number, e: number, f: number) => any;
    readonly wasmclient_auth_connect: (a: number, b: number, c: number, d: number, e: number, f: number, g: bigint) => any;
    readonly wasmclient_auth_register: (a: number, b: number, c: number, d: number, e: number, f: number) => any;
    readonly wasmclient_connect: (a: number, b: number) => any;
    readonly wasmclient_connectOwned: (a: number, b: number) => any;
    readonly __wbg_connectionconfig_free: (a: number, b: number) => void;
    readonly __wbg_pipereader_free: (a: number, b: number) => void;
    readonly __wbg_pipewriter_free: (a: number, b: number) => void;
    readonly connectionconfig_client_id: (a: number) => bigint;
    readonly connectionconfig_description: (a: number) => [number, number];
    readonly connectionconfig_max_message_size: (a: number) => number;
    readonly connectionconfig_new: (a: number, b: number) => number;
    readonly connectionconfig_require_pq: (a: number) => number;
    readonly connectionconfig_set_client_id: (a: number, b: bigint) => void;
    readonly connectionconfig_set_description: (a: number, b: number, c: number) => void;
    readonly connectionconfig_set_max_message_size: (a: number, b: number) => void;
    readonly connectionconfig_set_require_pq: (a: number, b: number) => void;
    readonly connectionconfig_set_server_certificate_hashes: (a: number, b: number, c: number) => void;
    readonly connectionconfig_url: (a: number) => [number, number];
    readonly pipereader_description: (a: number) => [number, number];
    readonly pipereader_pipe_id: (a: number) => number;
    readonly pipereader_read: (a: number) => any;
    readonly pipewriter_abort: (a: number) => [number, number];
    readonly pipewriter_close: (a: number) => any;
    readonly pipewriter_pipe_id: (a: number) => number;
    readonly pipewriter_write: (a: number, b: number, c: number) => any;
    readonly wasmclient_accept_pipe: (a: number, b: number) => any;
    readonly wasmclient_create_pipe: (a: number, b: number, c: number) => any;
    readonly wasmclient_deny_pipe: (a: number, b: number) => any;
    readonly wasmclient_disconnect: (a: number) => void;
    readonly wasmclient_set_on_pipe_request: (a: number, b: number) => void;
    readonly wasmclient_start_protocol_pings: (a: number, b: number, c: bigint) => [number, number];
    readonly wasmclient_stop_protocol_pings: (a: number) => void;
    readonly wasm_bindgen__convert__closures_____invoke__hbfde51476b904d71: (a: number, b: number, c: any) => [number, number];
    readonly wasm_bindgen__convert__closures_____invoke__h7cf76fd16cb52006: (a: number, b: number, c: any, d: any) => void;
    readonly wasm_bindgen__convert__closures_____invoke__heaefed2e0f18042f: (a: number, b: number) => void;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __wbindgen_exn_store: (a: number) => void;
    readonly __externref_table_alloc: () => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_destroy_closure: (a: number, b: number) => void;
    readonly __externref_table_dealloc: (a: number) => void;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
