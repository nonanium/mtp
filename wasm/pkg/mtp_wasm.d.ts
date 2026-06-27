/* tslint:disable */
/* eslint-disable */

export class ConnectionConfig {
    free(): void;
    [Symbol.dispose](): void;
    constructor(url: string);
    client_id: bigint;
    set server_certificate_hashes(value: string[]);
    readonly url: string;
}

export enum ConnectionState {
    Disconnected = 0,
    Connecting = 1,
    Connected = 2,
    Failed = 3,
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
    /**
     * Authenticated login with an existing client ID.
     * Exchanges Identification + signatures and verifies the host response.
     *
     * - `host_public_key_bytes`: serialized PublicKeyBundle from the server
     * - `keyring_bytes`: serialized Keyring of this client (must match `client_id`)
     * - `client_id`: previously assigned client ID
     *
     * Returns the confirmed (same) client ID on success.
     */
    auth_connect(config: ConnectionConfig, host_public_key_bytes: Uint8Array, keyring_bytes: Uint8Array, client_id: bigint): Promise<bigint>;
    /**
     * Authenticated registration with a fresh keyring.
     * The server assigns a new client ID.
     *
     * - `host_public_key_bytes`: serialized PublicKeyBundle from the server
     * - `keyring_bytes`: serialized Keyring (must include ed25519 secret key)
     *
     * Returns the newly assigned client ID.
     */
    auth_register(config: ConnectionConfig, host_public_key_bytes: Uint8Array, keyring_bytes: Uint8Array): Promise<bigint>;
    /**
     * Unauthenticated connect (sends basic Identification, enables receive loop).
     */
    connect(config: ConnectionConfig): Promise<void>;
    disconnect(): void;
    static is_supported(): boolean;
    constructor(on_state_change: Function, on_message: Function, on_error: Function);
    send(frame: Uint8Array): Promise<void>;
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
     * Serialise the keyring to bytes.
     */
    to_bytes(): Uint8Array;
}

export class WasmPublicKeyBundle {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    static from_bytes(bytes: Uint8Array): WasmPublicKeyBundle;
    to_bytes(): Uint8Array;
    readonly kem_public_key: Uint8Array;
    readonly sig_cl_public_key: Uint8Array;
    readonly sig_pq_public_key: Uint8Array;
}

/**
 * Build a demo Ping frame with encrypted and signed containers
 * (mirrors the Rust client example but uses only reserved data types).
 */
export function build_demo_message(client_id: bigint, keyring_bytes: Uint8Array, host_bundle_bytes: Uint8Array): Uint8Array;

/**
 * Build a simple Ping frame with description, timestamp, and optional data.
 */
export function build_ping_frame(client_id: bigint, description: string, timestamp: bigint, data: Uint8Array): Uint8Array;

/**
 * Build a request frame with the given communication type name, request ID, and JSON data.
 *
 * - `comm_type`: communication type name (e.g. "get_model", "rank_models") or PascalCase
 * - `id`: request ID for response correlation
 * - `json_data`: JSON-stringified request payload
 */
export function build_request_frame(comm_type: string, id: number, json_data: string): Uint8Array;

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
 * Parse any MTP frame into the human-readable CommunicationValue display form.
 */
export function format_frame(frame: Uint8Array): string;

/**
 * Build a [`Keyring`] containing only an Ed25519 keypair (no KEM, no ML-DSA).
 *
 * Takes the Ed25519 secret key and public key, each 32 bytes.
 * Returns the serialised keyring bytes, suitable for passing to `WasmClient.auth_register`.
 */
export function keyring_from_ed25519(secret_key: Uint8Array, public_key: Uint8Array): Uint8Array;

export function main(): void;

/**
 * Parse an auth response frame into a JS object.
 */
export function parse_auth_response(response: Uint8Array): any;

/**
 * Parse a response frame into a JSON string containing `_id`, `_type`, and data fields.
 */
export function parse_response_frame(frame: Uint8Array): string;

/**
 * Derive a 32-byte encryption key from `ikm` with `salt` and `context`.
 */
export function wasm_derive_encryption_key(ikm: Uint8Array, salt: Uint8Array, context: Uint8Array): Uint8Array;

/**
 * HKDF-expand: derive `len` bytes from `ikm` with `salt` and `info`.
 */
export function wasm_hkdf_expand(ikm: Uint8Array, salt: Uint8Array, info: Uint8Array, len: number): Uint8Array;

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
    readonly __wbg_wasmkeyring_free: (a: number, b: number) => void;
    readonly __wbg_wasmpublickeybundle_free: (a: number, b: number) => void;
    readonly ed25519_generate: () => [number, number, number];
    readonly ed25519_verify: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number];
    readonly keyring_from_ed25519: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly wasm_derive_encryption_key: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly wasm_hkdf_expand: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => [number, number, number, number];
    readonly wasm_sha256: (a: number, b: number) => [number, number];
    readonly wasm_sha256_double: (a: number, b: number) => [number, number];
    readonly wasmchacha20poly1305_decrypt: (a: number, b: number, c: number, d: number, e: number) => [number, number, number, number];
    readonly wasmchacha20poly1305_encrypt: (a: number, b: number, c: number, d: number, e: number) => [number, number, number, number];
    readonly wasmchacha20poly1305_new: (a: number, b: number) => [number, number, number];
    readonly wasmed25519signer_new: (a: number, b: number) => [number, number, number];
    readonly wasmed25519signer_sign: (a: number, b: number, c: number) => [number, number, number, number];
    readonly wasmed25519signer_verify: (a: number, b: number, c: number, d: number, e: number) => [number, number];
    readonly wasmkeyring_from_bytes: (a: number, b: number) => [number, number, number];
    readonly wasmkeyring_public_key_bundle: (a: number) => number;
    readonly wasmkeyring_to_bytes: (a: number) => [number, number];
    readonly wasmpublickeybundle_from_bytes: (a: number, b: number) => [number, number, number];
    readonly wasmpublickeybundle_kem_public_key: (a: number) => [number, number];
    readonly wasmpublickeybundle_sig_cl_public_key: (a: number) => [number, number];
    readonly wasmpublickeybundle_sig_pq_public_key: (a: number) => [number, number];
    readonly wasmpublickeybundle_to_bytes: (a: number) => [number, number];
    readonly build_demo_message: (a: bigint, b: number, c: number, d: number, e: number) => [number, number, number, number];
    readonly build_ping_frame: (a: bigint, b: number, c: number, d: bigint, e: number, f: number) => [number, number, number, number];
    readonly build_request_frame: (a: number, b: number, c: number, d: number, e: number) => [number, number, number, number];
    readonly format_frame: (a: number, b: number) => [number, number, number, number];
    readonly parse_auth_response: (a: number, b: number) => [number, number, number];
    readonly parse_response_frame: (a: number, b: number) => [number, number, number, number];
    readonly main: () => void;
    readonly __wbg_connectionconfig_free: (a: number, b: number) => void;
    readonly __wbg_wasmclient_free: (a: number, b: number) => void;
    readonly connectionconfig_client_id: (a: number) => bigint;
    readonly connectionconfig_new: (a: number, b: number) => number;
    readonly connectionconfig_set_client_id: (a: number, b: bigint) => void;
    readonly connectionconfig_set_server_certificate_hashes: (a: number, b: number, c: number) => void;
    readonly connectionconfig_url: (a: number) => [number, number];
    readonly wasmclient_auth_connect: (a: number, b: number, c: number, d: number, e: number, f: number, g: bigint) => any;
    readonly wasmclient_auth_register: (a: number, b: number, c: number, d: number, e: number, f: number) => any;
    readonly wasmclient_connect: (a: number, b: number) => any;
    readonly wasmclient_disconnect: (a: number) => void;
    readonly wasmclient_is_supported: () => number;
    readonly wasmclient_new: (a: any, b: any, c: any) => number;
    readonly wasmclient_send: (a: number, b: number, c: number) => any;
    readonly wasmclient_state: (a: number) => number;
    readonly wasm_bindgen__convert__closures_____invoke__h6588d25cdde23584: (a: number, b: number, c: any) => [number, number];
    readonly wasm_bindgen__convert__closures_____invoke__h5c81efa430e34369: (a: number, b: number, c: any) => [number, number];
    readonly wasm_bindgen__convert__closures_____invoke__h5c81efa430e34369_2: (a: number, b: number, c: any) => [number, number];
    readonly wasm_bindgen__convert__closures_____invoke__h4bf2427f775cf424: (a: number, b: number, c: any, d: any) => void;
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
