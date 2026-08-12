export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;
export type SyncInitInput = BufferSource | WebAssembly.Module;

export interface InitOutput {
  readonly memory: WebAssembly.Memory;
}

export interface DisposableWasmObject {
  free(): void;
  [Symbol.dispose](): void;
}

export type StateChangeCallback = (state: ConnectionState) => void;
export type MessageCallback = (frame: ParsedFrame) => void;
export type ErrorCallback = (error: string) => void;

export interface Ed25519GenerateResult {
  signer: WasmEd25519Signer;
  secretKey: Uint8Array;
  publicKey: Uint8Array;
}

export interface AuthResponse {
  connected: boolean;
  clientNonce?: Uint8Array;
  assignedId?: bigint;
  timestamp?: bigint;
  signature?: Uint8Array;
}

export interface ParsedResponse {
  _id?: number;
  _type: string;
  [field: string]: unknown;
}

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

export class ConnectionConfig implements DisposableWasmObject {
  constructor(url: string);
  free(): void;
  [Symbol.dispose](): void;
  client_id: bigint;
  description: string | undefined;
  max_message_size: number;
  require_pq: boolean;
  server_certificate_hashes: string[];
  readonly url: string;
}

export enum ConnectionState {
  Disconnected = 0,
  Connecting = 1,
  Connected = 2,
  Failed = 3,
}

export enum WasmLogHint {
  Info = 0,
  Warning = 1,
  Error = 2,
}

export class WasmChaCha20Poly1305 implements DisposableWasmObject {
  constructor(key: Uint8Array);
  free(): void;
  [Symbol.dispose](): void;
  decrypt(ciphertext: Uint8Array, aad: Uint8Array): Uint8Array;
  encrypt(plaintext: Uint8Array, aad: Uint8Array): Uint8Array;
}

export interface KemEncapsulateResult {
  shared_secret: Uint8Array;
  ciphertext: Uint8Array;
}

export class WasmEncapsulated implements DisposableWasmObject {
  private constructor();
  free(): void;
  [Symbol.dispose](): void;
  readonly shared_secret: Uint8Array;
  readonly ciphertext: Uint8Array;
}

export class WasmKemKeypair implements DisposableWasmObject {
  readonly public_key: Uint8Array;
  readonly secret_key: Uint8Array;
  free(): void;
  [Symbol.dispose](): void;
}

export class WasmClient implements DisposableWasmObject {
  constructor(
    on_state_change: StateChangeCallback,
    on_message: MessageCallback,
    on_error: ErrorCallback,
  );
  free(): void;
  [Symbol.dispose](): void;
  auth_connect(
    config: ConnectionConfig,
    host_public_key_bytes: Uint8Array,
    keyring_bytes: Uint8Array,
    client_id: bigint,
  ): Promise<bigint>;
  auth_register(
    config: ConnectionConfig,
    host_public_key_bytes: Uint8Array,
    keyring_bytes: Uint8Array,
  ): Promise<bigint>;
  connect(config: ConnectionConfig): Promise<void>;
  disconnect(): void;
  request(
    frame: Uint8Array,
    response_type?: string | null,
    timeout_ms?: number | null,
  ): Promise<ParsedFrame>;
  send(frame: Uint8Array): Promise<void>;
  start_protocol_pings(interval_ms: number, client_id: bigint): void;
  stop_protocol_pings(): void;
  subscribe(message_type: string, callback: MessageCallback): number;
  unsubscribe(id: number): boolean;
  static is_supported(): boolean;
  readonly ping_ms: number | undefined;
  readonly client_id: bigint;
  readonly state: ConnectionState;
}

export class WasmEd25519Signer implements DisposableWasmObject {
  constructor(secret_key: Uint8Array);
  free(): void;
  [Symbol.dispose](): void;
  sign(message: Uint8Array): Uint8Array;
  verify(message: Uint8Array, signature: Uint8Array): void;
}

export class WasmKeyring implements DisposableWasmObject {
  private constructor();
  free(): void;
  [Symbol.dispose](): void;
  static from_bytes(bytes: Uint8Array): WasmKeyring;
  public_key_bundle(): WasmPublicKeyBundle;
  to_bytes(): Uint8Array;
  validate_full(): void;
}

export class WasmPublicKeyBundle implements DisposableWasmObject {
  private constructor();
  free(): void;
  [Symbol.dispose](): void;
  static from_bytes(bytes: Uint8Array): WasmPublicKeyBundle;
  static from_bytes_unvalidated(bytes: Uint8Array): WasmPublicKeyBundle;
  to_bytes(): Uint8Array;
  readonly kem_public_key: Uint8Array;
  readonly sig_cl_public_key: Uint8Array;
  readonly sig_pq_public_key: Uint8Array;
}

export class WasmSubscriptionRouter implements DisposableWasmObject {
  constructor();
  free(): void;
  [Symbol.dispose](): void;
  dispatch(message_type: string, message: unknown): boolean;
  subscribe(message_type: string, callback: (message: unknown) => void): void;
  unsubscribe(message_type: string): boolean;
}

export class WasmVerifiedProtectedMessage implements DisposableWasmObject {
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

export class WasmVerifiedRelayContent implements DisposableWasmObject {
  private constructor();
  free(): void;
  [Symbol.dispose](): void;
  content(): Uint8Array;
  final_recipient_id(): bigint;
  message_type(): string;
  signer_id(): bigint;
}

export class WasmVerifiedRelayMetadata implements DisposableWasmObject {
  private constructor();
  free(): void;
  [Symbol.dispose](): void;
  created_at(): bigint;
  encrypted_content(): Uint8Array;
  final_recipient_id(): bigint;
  message_id(): string;
  metadata(): Uint8Array | null;
  matched_signer_key_index(): number;
  relay_version(): bigint;
  signer_id(): bigint;
}

export function build_ping_frame(
  client_id: bigint,
  description: string,
  timestamp: bigint,
  data: Uint8Array,
): Uint8Array;

export function build_frame(message_type: string, data: Record<string, unknown>, options?: {
  id?: number;
  sender?: bigint | number;
  receiver?: bigint | number;
}): Uint8Array;
export function build_frame_with_payload(message_type: string, serialized_payload: Uint8Array, options?: {
  id?: number;
  sender?: bigint | number;
  receiver?: bigint | number;
}): Uint8Array;

export function verify_data_value_with_policy(value: Uint8Array, public_key_bundle: Uint8Array, expected_signer_id: bigint, expected_purpose: number, signature_suite: number): void;
export function encrypt_data_value(value: Uint8Array, recipient_public_key_bundle: Uint8Array, purpose: number): Uint8Array;
export function encrypt_data_value_for_recipients(value: Uint8Array, recipient_public_key_bundles: Uint8Array | Uint8Array[], purpose: number): Uint8Array;
export function decrypt_data_value(value: Uint8Array, keyring: Uint8Array, expected_purpose: number): Uint8Array;
export function decrypt_data_value_with_keyrings(value: Uint8Array, keyrings: Uint8Array | Uint8Array[], expected_purpose: number): Uint8Array;
export function mtp_relay_metadata_encryption_purpose(): number;
export function mtp_relay_content_signature_purpose(): number;
export function mtp_relay_content_encryption_purpose(): number;
export function mtp_relay_metadata_signature_purpose(): number;
export function mtp_pipe_session_signature_purpose(): number;
export function mtp_pipe_session_encryption_purpose(): number;
export function mtp_protection_signature_suite_ed25519(): number;
export function mtp_protection_signature_suite_dual(): number;
export function open_relay_content_with_keyrings(
  metadata: WasmVerifiedRelayMetadata,
  keyrings: Uint8Array | Uint8Array[],
  signer_public_key_bundles: Uint8Array | Uint8Array[],
  expected_final_recipient_id: bigint | number | null,
  signature_suite: number,
): WasmVerifiedRelayContent;
export function open_relay_metadata_with_keyrings(
  frame: Uint8Array,
  keyrings: Uint8Array | Uint8Array[],
  expected_signer_id: bigint | number,
  signer_public_key_bundles: Uint8Array | Uint8Array[],
  signature_suite: number,
): WasmVerifiedRelayMetadata;
export function relay_metadata_claimed_signer_id(
  frame: Uint8Array,
  keyrings: Uint8Array | Uint8Array[],
): bigint;
export function forward_encrypted_relay_frame(frame: Uint8Array, next_hop_receiver_id: bigint): Uint8Array;
export function sign_data_value_with_keyring(value: Uint8Array, signer_id: bigint, purpose: number, keyring: Uint8Array, signature_suite: number): Uint8Array;
export function build_encrypted_relay_frame_with_keyring(
  message_type: string,
  data: unknown,
  signer_id: bigint,
  final_recipient_id: bigint,
  next_hop_id: bigint,
  message_id: string,
  created_at: bigint,
  encoded_metadata: Uint8Array | null | undefined,
  keyring_bytes: Uint8Array,
  signature_suite: number,
  metadata_recipient_public_key_bundles: Uint8Array | Uint8Array[],
  content_recipient_public_key_bundles: Uint8Array | Uint8Array[],
): Uint8Array;

export function build_protected_frame_with_keyring(
  message_type: string,
  encoded_content: Uint8Array,
  signer_id: bigint,
  final_recipient_id: bigint,
  message_id: string,
  created_at: bigint,
  signature_purpose: number,
  encryption_purpose: number,
  keyring_bytes: Uint8Array,
  signature_suite: number,
  frame_id: number | null | undefined,
  expose_sender: boolean,
  recipient_public_key_bundles: Uint8Array | Uint8Array[],
): Uint8Array;

export function open_protected_with_keyrings(
  frame: Uint8Array,
  keyrings: Uint8Array | Uint8Array[],
  expected_signer_id: bigint | number,
  signer_public_key_bundles: Uint8Array | Uint8Array[],
  expected_receiver_id: bigint | number | null,
  signature_purpose: number,
  encryption_purpose: number,
  signature_suite: number,
): WasmVerifiedProtectedMessage;

export function protected_claimed_signer_id(
  frame: Uint8Array,
  keyrings: Uint8Array | Uint8Array[],
  encryption_purpose: number,
): bigint;

export function ed25519_generate(): Ed25519GenerateResult;
export function ed25519_verify(public_key: Uint8Array, message: Uint8Array, signature: Uint8Array): void;
export function format_frame(frame: Uint8Array): string;
export function parse_data_value(value: Uint8Array): ParsedDataValue;
export function encode_data_value(value: unknown): Uint8Array;
export function keyring_from_ed25519(secret_key: Uint8Array, public_key: Uint8Array): Uint8Array;
export function keyring_generate(): Uint8Array;
export function main(): void;
export function parse_auth_response(response: Uint8Array): AuthResponse;
export function parse_frame(frame: Uint8Array): ParsedFrame;
export function wasm_derive_encryption_key(ikm: Uint8Array, salt: Uint8Array, context: Uint8Array): Uint8Array;
export function wasm_hkdf_expand(ikm: Uint8Array, salt: Uint8Array, info: Uint8Array, len: number): Uint8Array;
export function wasm_kem_decapsulate(recipient_private_key: Uint8Array, ciphertext: Uint8Array): Uint8Array;
export function wasm_kem_encapsulate(recipient_public_key: Uint8Array): WasmEncapsulated;
export function wasm_kem_generate_keypair(): WasmKemKeypair;
export function wasm_sha256(data: Uint8Array): Uint8Array;
export function wasm_sha256_double(data: Uint8Array): Uint8Array;

export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

export default function init(
  module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>,
): Promise<InitOutput>;
