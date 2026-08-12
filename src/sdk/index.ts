import initWasm, {
  ConnectionConfig,
  ConnectionState,
  WasmClient,
  WasmPipeHandle,
  keyring_generate,
} from "mtp/raw";
import * as bindings from "mtp/raw";
import { unixTimeMillis, utf8Encode } from "./utils.js";
import type * as RawBindings from "../raw/index";
import type { MTPCommunicationType } from "../type-map/index";
import { RESERVED_COMMUNICATION_TYPE_IDS } from "../type-map/reserved.js";
import type { MTPSessionStorage, MTPSessionState } from "./session";
import { MTPSessionManager } from "./session.js";
import type {
  MTPEncryptedSecretRecord,
  MTPEncryptedSecretProvider,
} from "./encrypted-secret";
import { InMemoryEncryptedSecretProvider } from "./encrypted-secret.js";
import { InMemorySessionStorage } from "./session.js";
import {
  acceptMTPPipeSession,
  acceptMTPPipeSessionAuto,
  acceptMTPForwardSecurePipeSession,
  initiateMTPForwardSecurePipeSession,
  initiateMTPPipeSession,
  MTPEncryptedPipeReader,
  MTPEncryptedPipeWriter,
  validateApplicationProtectionPurpose,
} from "./encrypted-pipe.js";
import {
  DEFAULT_SIGNATURE_VERIFICATION_POLICY,
  MTPSignatureVerificationError,
  resolveSignatureVerificationPolicy,
  signatureVerificationPolicyValue,
  signerKeysUnavailable,
} from "./signature-policy.js";
import type { MTPSignatureVerificationPolicy } from "./signature-policy.js";
export type {
  MTPSignatureVerificationErrorCode,
  MTPSignatureVerificationPolicy,
} from "./signature-policy.js";
export {
  DEFAULT_SIGNATURE_VERIFICATION_POLICY,
  MTPSignatureVerificationError,
  resolveSignatureVerificationPolicy,
} from "./signature-policy.js";

export type StorageValue = string | null;

export interface MTPCredentialStorage {
  getItem(key: string): StorageValue | Promise<StorageValue>;
  setItem(key: string, value: string): void | Promise<void>;
  removeItem(key: string): void | Promise<void>;
}

export type MTPStorage = MTPCredentialStorage;

export type MTPLogEvent =
  | {
      hint: "info" | "warning";
      type: string;
      data: unknown;
      direction?: "send" | "recv";
    }
  | {
      hint: "error";
      type: string | "error";
      error: string;
      data?: unknown;
      direction?: "send" | "recv";
    };

export type ParsedFrame = RawBindings.ParsedFrame;

export type Ed25519GenerateResult = ReturnType<
  typeof bindings.ed25519_generate
>;

export type WasmEncapsulated = RawBindings.WasmEncapsulated;

export interface MTPCrypto {
  generateKeyring(): Uint8Array;
  generateEd25519(): Ed25519GenerateResult;
  keyringFromEd25519(secretKey: Uint8Array, publicKey: Uint8Array): Uint8Array;
  verifyEd25519(
    publicKey: Uint8Array,
    message: Uint8Array,
    signature: Uint8Array,
  ): void;
  deriveEncryptionKey(
    ikm: Uint8Array,
    salt: Uint8Array,
    context: Uint8Array,
  ): Uint8Array;
  hkdfExpand(
    ikm: Uint8Array,
    salt: Uint8Array,
    info: Uint8Array,
    len: number,
  ): Uint8Array;
  sha256(data: Uint8Array): Uint8Array;
  sha256Double(data: Uint8Array): Uint8Array;
  keyringToKeys(keyring: string | MTPBytesInput): MTPKeyringKeys;
  publicKeyBundleToKeys(
    publicKeyBundle: string | MTPBytesInput,
  ): MTPPublicKeyBundleKeys;
  encrypt(key: Uint8Array, input: Uint8Array): Promise<Uint8Array>;
  decrypt(key: Uint8Array, input: Uint8Array): Promise<Uint8Array>;
  encryptText(key: Uint8Array, plaintext: string): Promise<string>;
  decryptText(key: Uint8Array, ciphertext: string): Promise<string>;
  encapsulate(otherPublicKey: Uint8Array): WasmEncapsulated;
  decapsulate(ownPrivateKey: Uint8Array, ciphertext: Uint8Array): Uint8Array;
}

export const crypto: MTPCrypto = {
  generateKeyring: () => bindings.keyring_generate(),
  generateEd25519: () => bindings.ed25519_generate(),
  keyringFromEd25519: (secretKey, publicKey) =>
    bindings.keyring_from_ed25519(secretKey, publicKey),
  verifyEd25519: (publicKey, message, signature) =>
    bindings.ed25519_verify(publicKey, message, signature),
  deriveEncryptionKey: (ikm, salt, context) =>
    bindings.wasm_derive_encryption_key(ikm, salt, context),
  hkdfExpand: (ikm, salt, info, len) =>
    bindings.wasm_hkdf_expand(ikm, salt, info, len),
  sha256: (data) => bindings.wasm_sha256(data),
  sha256Double: (data) => bindings.wasm_sha256_double(data),
  keyringToKeys: (keyring) => keyringToKeys(keyring),
  publicKeyBundleToKeys: (publicKeyBundle) =>
    publicKeyBundleToKeys(publicKeyBundle),

  encrypt: async (key, input) => {
    const cipher = new bindings.WasmChaCha20Poly1305(key);
    try {
      return cipher.encrypt(input, new Uint8Array(0));
    } finally {
      cipher.free();
    }
  },

  decrypt: async (key, input) => {
    const cipher = new bindings.WasmChaCha20Poly1305(key);
    try {
      return cipher.decrypt(input, new Uint8Array(0));
    } finally {
      cipher.free();
    }
  },

  encryptText: async (key, plaintext) => {
    const cipher = new bindings.WasmChaCha20Poly1305(key);
    try {
      const ciphertext = cipher.encrypt(
        utf8Encode(plaintext),
        new Uint8Array(0),
      );
      return bytesToBase64(ciphertext);
    } finally {
      cipher.free();
    }
  },

  decryptText: async (key, ciphertext) => {
    const cipher = new bindings.WasmChaCha20Poly1305(key);
    try {
      const decoded = base64ToBytes(ciphertext);
      const plaintext = cipher.decrypt(decoded, new Uint8Array(0));
      return utf8Decode(plaintext);
    } finally {
      cipher.free();
    }
  },

  encapsulate: (otherPublicKey) =>
    bindings.wasm_kem_encapsulate(otherPublicKey),

  decapsulate: (ownPrivateKey, ciphertext) =>
    bindings.wasm_kem_decapsulate(ownPrivateKey, ciphertext),
};

export type MTPRawBindings = typeof bindings;

export interface MTPRaw {
  /**
   * Underlying generated WASM client instance.
   *
   * Prefer the `MTPClient` methods for application code. Calling the raw client
   * bypasses SDK-level validation, credential persistence, logging, timeout
   * handling, frame parsing helpers, and ping lifecycle management. Use this
   * escape hatch only when integrating a feature that the SDK wrapper does not
   * expose yet.
   */
  client: RawBindings.WasmClient;

  /**
   * Generated WASM binding module exported by `mtp/raw`.
   *
   * These bindings mirror the lower-level WASM API and can change shape as the
   * generated interface evolves. Prefer the SDK wrapper where possible so your
   * code keeps the safer, typed MTPClient flow instead of depending directly on
   * transport internals.
   */
  bindings: MTPRawBindings;
}

export type MTPBytesInput = Uint8Array | number[];

export interface MTPCodecOptions {
  id?: number;
  sender?: bigint | number;
  receiver?: bigint | number;
}

export interface MTPCodec {
  encode(
    type: MTPCommunicationType,
    data: Record<string, unknown>,
    options?: MTPCodecOptions,
  ): Uint8Array;
  decode(frame: MTPBytesInput): ParsedFrame;
  format(frame: MTPBytesInput): string;
}

export function encode(
  type: MTPCommunicationType,
  data: Record<string, unknown>,
  options?: MTPCodecOptions,
): Uint8Array {
  return bindings.build_frame(type, data, options ?? {});
}

export function decode(frame: MTPBytesInput): ParsedFrame {
  return bindings.parse_frame(bytesFrom(frame, "frame"));
}

export function format(frame: MTPBytesInput): string {
  return bindings.format_frame(bytesFrom(frame, "frame"));
}

export const codec: MTPCodec = {
  encode,
  decode,
  format,
};

export interface MTPCredentials {
  clientId: bigint | string | number | null;
  keyring: MTPBytesInput;
  hostPublicKey?: MTPBytesInput | string;
}

export interface MTPClientCredentials {
  clientId: bigint | null;
  keyring: Uint8Array;
  hostPublicKey?: Uint8Array;
}

export interface MTPKeyringKeys {
  kemPublicKey: Uint8Array;
  kemSecretKey: Uint8Array;
  sigPqPublicKey: Uint8Array;
  sigPqSecretKey: Uint8Array;
  sigClPublicKey: Uint8Array;
  sigClSecretKey: Uint8Array;
}

export interface MTPPublicKeyBundleKeys {
  kemPublicKey: Uint8Array;
  sigPqPublicKey: Uint8Array;
  sigClPublicKey: Uint8Array;
}

export interface MTPClientOptions {
  url: string;
  descriptor?: string;
  hostPublicKey?: MTPBytesInput | string;
  credentials?: MTPCredentials | string | null;
  credentialsStorageKey?: string;
  storage?: MTPCredentialStorage;
  serverCertificateHashes?: string[];
  maxMessageSize?: number;
  authTimeoutMs?: number;
  requestTimeoutMs?: number;
  pings?: boolean | { intervalMs?: number };
  wasm?:
    | RawBindings.InitInput
    | Promise<RawBindings.InitInput>
    | {
        module_or_path: RawBindings.InitInput | Promise<RawBindings.InitInput>;
      };
  logger?: (event: MTPLogEvent) => void;
  sessionStorage?: MTPSessionStorage;
  /**
   * Independent caller-managed encrypted-secret storage. Session state is not
   * routed through this provider automatically.
   */
  encryptedSecretProvider?: MTPEncryptedSecretProvider;
  /** Default receiver policy for protected signatures. */
  defaultSignatureVerificationPolicy?: MTPSignatureVerificationPolicy;
}

export type Unsubscribe = () => void;

export interface MTPFrameIdOptions {
  id?: number;
}

export interface MTPAddressedFrameOptions extends MTPFrameIdOptions {
  sender?: bigint | number;
  receiver?: bigint | number;
}

export interface MTPSendOptions extends MTPAddressedFrameOptions {}

export interface MTPProtectionIdentity {
  signerId: bigint | number | string;
  keyring: string | MTPBytesInput;
}

/**
 * Key material used to open protected MTP values.
 *
 * This identity is independent from transport authentication. Its optional
 * ID is used only for structural destination checks when a receive operation
 * supports one.
 */
export interface MTPDecryptionIdentity {
  id?: bigint | number | string;
  keyring: string | MTPBytesInput;
  /**
   * Previously used recipient keyrings, ordered newest to oldest. The
   * current keyring is always attempted first.
   */
  keyringHistory?: Array<string | MTPBytesInput>;
}

/** Decoded value returned by the MTP DataValue codec. */
export type MTPDataValue = RawBindings.ParsedDataValue;

/** JavaScript values accepted by the MTP DataValue encoder. */
export type MTPDataValueInput =
  | null
  | boolean
  | number
  | bigint
  | string
  | Uint8Array
  | MTPDataValueInput[]
  | { [key: string]: MTPDataValueInput };

/** Public-key material trusted for one protected signer identity. */
export type MTPResolvedSignerKeys = Array<string | MTPBytesInput>;

/**
 * Resolve trusted public-key bundles for a claimed, unverified signer ID.
 * The ID is used only as a trusted-key lookup key and becomes authenticated
 * after the native protected codec verifies the signature.
 */
export type MTPSignerKeyResolver = (
  signerId: bigint,
) => MTPResolvedSignerKeys | Promise<MTPResolvedSignerKeys>;

export interface MTPRelayPlan {
  nextHopId: bigint | number | string;
  finalRecipientId: bigint | number | string;
  metadataRecipients: Array<string | MTPBytesInput>;
  contentRecipients: Array<string | MTPBytesInput>;
  metadata?: MTPDataValueInput;
}

export interface MTPSendProtectedOptions extends MTPFrameIdOptions {
  receiverId: bigint | number | string;
  identity?: MTPProtectionIdentity;
  recipients: Array<string | MTPBytesInput>;
  signaturePurpose: number;
  encryptionPurpose: number;
  signatureSuite?: MTPProtectionSignatureSuite;
  exposeSender?: boolean;
}

export interface MTPSendSealedRelayOptions extends MTPRelayPlan {
  identity?: MTPProtectionIdentity;
  signatureSuite?: MTPProtectionSignatureSuite;
}

export interface MTPRelayVerificationOptions {
  /** Key material used for protected opening, independent from transport auth. */
  recipient?: MTPDecryptionIdentity;
  /** Require the protected signer to be this MTP identity. */
  expectedSignerId?: bigint | number | string;
  /** Resolve trusted keys for a claimed, unverified signer lookup ID. */
  resolveSignerPublicKeys?: MTPSignerKeyResolver;
  /** Receiver policy applied to relay metadata and content signatures. */
  signaturePolicy?: MTPSignatureVerificationPolicy;
}

export interface MTPOpenRelayMetadataOptions extends MTPRelayVerificationOptions {
  /** Consume one authenticated relay ID from a caller-owned store. */
  replayGuard?: MTPReplayGuard;
}

export interface MTPOpenRelayContentOptions extends MTPRelayVerificationOptions {
  /** Validate the authenticated final recipient when supplied. */
  expectedFinalRecipientId?: bigint | number | string;
}

export interface MTPOpenProtectedOptions {
  recipient?: MTPDecryptionIdentity;

  expectedSignerId?: bigint | number | string;
  expectedReceiverId?: bigint | number | string;

  resolveSignerPublicKeys: MTPSignerKeyResolver;

  signaturePolicy?: MTPSignatureVerificationPolicy;

  signaturePurpose: number;
  encryptionPurpose: number;

  /** Override the default process-local replay guard for durable storage. */
  replayGuard?: MTPReplayGuard;
}

export interface MTPVerifiedProtectedMessage<T = MTPDataValue> {
  type: string;

  /** Authenticated direct-message envelope schema version. */
  protectedVersion: number;

  signerId: bigint;

  /** Authenticated destination from the protected envelope. */
  finalRecipientId: bigint;

  /** Authenticated application message identifier. */
  messageId: string;

  /** Authenticated Unix epoch timestamp in milliseconds. */
  createdAt: bigint;

  receiver?: bigint;
  outerSender?: bigint;

  data: T;
}

export type MTPProtectedFrameInput = ParsedFrame | MTPBytesInput;

/** Options shared by the sealed-relay subscription APIs. */
export interface MTPEncryptedSubscriptionOptions
  extends MTPOpenRelayContentOptions {
  /** Consume authenticated relay IDs while dispatching the subscription. */
  replayGuard?: MTPReplayGuard;
}

export type MTPProtectionSignatureSuite = "ed25519" | "dual";

export interface MTPReplayGuard {
  /**
   * Return true and atomically record the pair when it has not been seen.
   * `createdAt` is authenticated metadata for retention/observability; the
   * replay identity is only `(signerId, messageId)`.
   */
  accept(
    signerId: bigint,
    messageId: string,
    createdAt: bigint,
  ): boolean | Promise<boolean>;
}

/**
 * Bounded process-local duplicate-suppression guard used by high-level direct
 * protected and relay receives when the caller does not provide durable
 * storage. Once the fixed cache is full, the oldest entry is evicted and may
 * be accepted again; use a durable `MTPReplayGuard` for security-sensitive
 * replay protection that must survive cache eviction, reloads, or multiple
 * receiver processes.
 */
export class InMemoryReplayGuard implements MTPReplayGuard {
  #accepted = new Set<string>();
  readonly #capacity = 10_000;

  accept(signerId: bigint, messageId: string, _createdAt: bigint): boolean {
    const key = `${signerId}:${messageId}`;
    if (this.#accepted.has(key)) return false;
    this.#accepted.add(key);
    if (this.#accepted.size > this.#capacity) {
      const oldest = this.#accepted.values().next().value;
      if (oldest !== undefined) this.#accepted.delete(oldest);
    }
    return true;
  }
}

export class MTPReplayError extends Error {
  readonly signerId: bigint;
  readonly messageId: string;

  constructor(signerId: bigint, messageId: string) {
    super(`message ${messageId} from signer ${signerId} was already accepted`);
    this.name = "MTPReplayError";
    this.signerId = signerId;
    this.messageId = messageId;
  }
}

export class MTPMissingRelayVersionError extends Error {
  constructor() {
    super("relay frame does not declare a relay version");
    this.name = "MTPMissingRelayVersionError";
  }
}

export class MTPUnsupportedRelayVersionError extends Error {
  readonly relayVersion: bigint;

  constructor(relayVersion: bigint) {
    super(`unsupported relay version ${relayVersion}`);
    this.name = "MTPUnsupportedRelayVersionError";
    this.relayVersion = relayVersion;
  }
}

export class MTPMissingProtectedVersionError extends Error {
  constructor() {
    super("protected message does not declare a protected version");
    this.name = "MTPMissingProtectedVersionError";
  }
}

export class MTPUnsupportedProtectedVersionError extends Error {
  readonly protectedVersion: bigint;

  constructor(protectedVersion: bigint) {
    super(`unsupported protected message version ${protectedVersion}`);
    this.name = "MTPUnsupportedProtectedVersionError";
    this.protectedVersion = protectedVersion;
  }
}

function relayOpeningError(error: unknown, signerId?: bigint): Error {
  if (error !== null && typeof error === "object") {
    const structured = error as {
      code?: unknown;
      relayVersion?: unknown;
    };
    if (typeof structured.code === "string") {
      switch (structured.code) {
        case "missing-relay-version":
          return new MTPMissingRelayVersionError();
        case "unsupported-relay-version":
          if (
            typeof structured.relayVersion === "bigint" ||
            typeof structured.relayVersion === "number" ||
            typeof structured.relayVersion === "string"
          ) {
            return new MTPUnsupportedRelayVersionError(
              inputU64(structured.relayVersion, "relayVersion"),
            );
          }
          break;
        case "no-matching-recipient":
          return new Error(
            "Unable to decrypt protected value with supplied recipient keyrings",
          );
        case "not-final-recipient":
          return new Error(
            "relay content is addressed to a different final recipient",
          );
        case "reserved-application-type":
          return new Error(
            "relay application message type is reserved for MTP control",
          );
        case "signature-policy-mismatch":
          return new MTPSignatureVerificationError(
            "policy-rejected",
            signerId,
          );
        case "unsupported-signature-suite":
          return new MTPSignatureVerificationError(
            "unsupported-suite",
            signerId,
          );
        case "invalid-signature":
          return new MTPSignatureVerificationError(
            "invalid-signature",
            signerId,
          );
        case "signer-id-mismatch":
          return new Error("relay signer ID mismatch");
        case "purpose-mismatch":
          return new Error("relay protection purpose mismatch");
        case "signer-key-not-found":
          return signerKeysUnavailable(signerId);
        case "replay":
          return new Error("relay message was already accepted");
      }
    }
  }
  return error instanceof Error ? error : new Error(String(error));
}

function protectedOpeningError(error: unknown, signerId?: bigint): Error {
  if (error !== null && typeof error === "object") {
    const structured = error as {
      code?: unknown;
      protectedVersion?: unknown;
    };
    if (typeof structured.code === "string") {
      switch (structured.code) {
        case "missing-protected-version":
          return new MTPMissingProtectedVersionError();
        case "unsupported-protected-version":
          if (
            typeof structured.protectedVersion === "bigint" ||
            typeof structured.protectedVersion === "number" ||
            typeof structured.protectedVersion === "string"
          ) {
            return new MTPUnsupportedProtectedVersionError(
              inputU64(structured.protectedVersion, "protectedVersion"),
            );
          }
          break;
        case "no-matching-recipient":
          return new Error(
            "Unable to decrypt protected value with supplied recipient keyrings",
          );
        case "reserved-application-type":
          return new Error(
            "MTP control communication types cannot be used as application content",
          );
        case "signature-policy-mismatch":
          return new MTPSignatureVerificationError(
            "policy-rejected",
            signerId,
          );
        case "unsupported-signature-suite":
          return new MTPSignatureVerificationError(
            "unsupported-suite",
            signerId,
          );
        case "invalid-signature":
          return new MTPSignatureVerificationError(
            "invalid-signature",
            signerId,
          );
        case "signer-id-mismatch":
          return new Error("protected signer ID mismatch");
        case "receiver-id-mismatch":
          return new Error("protected frame receiver ID mismatch");
        case "message-type-mismatch":
          return new Error(
            "protected message type does not match outer routing",
          );
        case "final-recipient-mismatch":
          return new Error(
            "protected final recipient does not match outer routing receiver",
          );
        case "sender-id-mismatch":
          return new Error(
            "protected frame sender does not match authenticated signer",
          );
        case "signer-key-not-found":
          return signerKeysUnavailable(signerId);
        case "replay":
          return new Error("protected message was already accepted");
      }
    }
  }
  return error instanceof Error ? error : new Error(String(error));
}

interface MTPRelayMetadataState {
  frame: ParsedFrame;
  native: RawBindings.WasmVerifiedRelayMetadata;
  relayVersion: number;
  signerId: bigint;
  finalRecipientId: bigint;
  messageId: string;
  createdAt: bigint;
  hasMetadata: boolean;
  metadata?: MTPDataValue;
  encryptedContent: Uint8Array;
  signerPublicKeys: Uint8Array[];
  matchedSignerKeyIndex: number;
  signaturePolicy: MTPSignatureVerificationPolicy;
  disposed: boolean;
  finalizerToken: object;
}

const relayMetadataState = new WeakMap<
  MTPVerifiedRelayMetadata,
  MTPRelayMetadataState
>();
const relayMetadataFinalizer = new FinalizationRegistry<
  RawBindings.WasmVerifiedRelayMetadata
>((native) => {
  try {
    native.free();
  } catch {
    // The WASM instance may already have been torn down during page unload.
  }
});
const RELAY_METADATA_TOKEN = Symbol("mtp-authenticated-relay-metadata");

/**
 * Authenticated relay metadata produced only by `openRelayMetadata()`.
 *
 * The internal state is intentionally kept out of the public structural type
 * so `openRelayContent()` cannot be fed a caller-fabricated "verified"
 * object. Getters return immutable primitives or defensive byte copies.
 */
export class MTPVerifiedRelayMetadata {
  constructor(
    token: typeof RELAY_METADATA_TOKEN,
    state: MTPRelayMetadataState,
  ) {
    if (token !== RELAY_METADATA_TOKEN) {
      throw new Error(
        "relay metadata must be created by authenticated opening",
      );
    }
    relayMetadataState.set(this, state);
  }

  private get state(): MTPRelayMetadataState {
    const state = relayMetadataState.get(this);
    if (!state)
      throw new Error("relay metadata authentication state is missing");
    if (state.disposed) throw new Error("relay metadata has been disposed");
    return state;
  }

  /** Release the native verified metadata handle immediately. */
  dispose(): void {
    const state = relayMetadataState.get(this);
    if (!state || state.disposed) return;
    state.disposed = true;
    relayMetadataFinalizer.unregister(state.finalizerToken);
    try {
      state.native.free();
    } catch {
      // The WASM instance may already have been torn down during page unload.
    }
  }

  /** Alias for callers that use the WASM resource naming convention. */
  free(): void {
    this.dispose();
  }

  [Symbol.dispose](): void {
    this.dispose();
  }

  get frame(): ParsedFrame {
    return cloneParsedFrame(this.state.frame);
  }

  get signerId(): bigint {
    return this.state.signerId;
  }

  /** Authenticated MTP relay metadata schema version. */
  get relayVersion(): number {
    return this.state.relayVersion;
  }

  get finalRecipientId(): bigint {
    return this.state.finalRecipientId;
  }

  get messageId(): string {
    return this.state.messageId;
  }

  /** Unix epoch milliseconds from the authenticated relay metadata. */
  get createdAt(): bigint {
    return this.state.createdAt;
  }

  get metadata(): MTPDataValue | undefined {
    return this.state.hasMetadata
      ? (cloneParsedValue(this.state.metadata) as MTPDataValue)
      : undefined;
  }

  get encryptedContent(): Uint8Array {
    return this.state.encryptedContent.slice();
  }

  /** Trusted public-key history used for this verification. */
  get signerPublicKeys(): Uint8Array[] {
    return this.state.signerPublicKeys.map((bundle) => bundle.slice());
  }

  /** Index of the trusted key that authenticated this metadata. */
  get matchedSignerKeyIndex(): number {
    return this.state.matchedSignerKeyIndex;
  }

  /** The exact trusted public-key bundle that authenticated this metadata. */
  get matchedSignerPublicKey(): Uint8Array {
    const key = this.state.signerPublicKeys[this.state.matchedSignerKeyIndex];
    if (!key) {
      throw new Error("relay verification matched an unavailable signer key");
    }
    return key.slice();
  }

  get signaturePolicy(): MTPSignatureVerificationPolicy {
    return this.state.signaturePolicy;
  }
}

export interface MTPVerifiedRelayContent {
  type: string;
  data: MTPDataValue;
  signerId: bigint;
  finalRecipientId: bigint;
  messageId: string;
  /** Unix epoch milliseconds from the authenticated relay metadata. */
  createdAt: bigint;
  metadata?: MTPDataValue;
}

export interface MTPRequestOptions extends MTPSendOptions {
  responseType?: MTPCommunicationType;
  timeoutMs?: number;
}

export interface MTPPipeWriter {
  write(data: Uint8Array): Promise<void>;
  close(): Promise<void>;
  abort(): void;
  readonly pipeId: number;
}

export interface MTPPipeReader {
  read(): Promise<Uint8Array | null>;
  readonly pipeId: number;
  readonly description: string;
}

export interface MTPPipeRequest {
  pipeId: number;
  description: string;
}

export interface MTPOutgoingPipeHandle {
  readonly pipeId: number;
  readonly description: string;
  wait(): Promise<MTPPipeWriter | null>;
}

export interface MTPCreateEncryptedPipeOptions {
  recipientId: bigint | number | string;
  recipientPublicKey?: string | MTPBytesInput;
  recipientPublicKeys?: Array<string | MTPBytesInput>;
  description?: string;
  purpose?: number;
  direction?: number;
  signatureSuite?: MTPProtectionSignatureSuite;
}

export interface MTPAcceptEncryptedPipeOptions {
  senderId: bigint | number | string;
  senderPublicKey?: string | MTPBytesInput;
  senderPublicKeys?: Array<string | MTPBytesInput>;
  purpose?: number;
  direction?: number;
  signaturePolicy?: MTPSignatureVerificationPolicy;
}

type InternalCredentials = {
  clientId: bigint | null;
  keyring: Uint8Array;
  hostPublicKey?: Uint8Array;
};

type NormalizedMTPClientOptions = Omit<MTPClientOptions, "hostPublicKey"> & {
  hostPublicKey?: Uint8Array;
};

const DEFAULT_CREDENTIALS_KEY = "mtp:credentials";
let wasmInitPromise: Promise<Awaited<ReturnType<typeof initWasm>>> | undefined;

function createMessageId(): string {
  const bytes = new Uint8Array(16);
  globalThis.crypto.getRandomValues(bytes);
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join(
    "",
  );
}

function protectionSignatureSuiteValue(
  suite: MTPProtectionSignatureSuite,
): number {
  return suite === "dual"
    ? bindings.mtp_protection_signature_suite_dual()
    : bindings.mtp_protection_signature_suite_ed25519();
}

function effectiveProtectionSignatureSuite(
  keyring: Uint8Array,
  requested?: MTPProtectionSignatureSuite,
): MTPProtectionSignatureSuite {
  const keys = keyringToKeys(keyring);
  const hasPqPublicKey = keys.sigPqPublicKey.length > 0;
  const hasPqSecretKey = keys.sigPqSecretKey.length > 0;
  const suite = requested ?? "ed25519";
  if (suite !== "ed25519" && suite !== "dual") {
    throw new Error("signatureSuite must be 'ed25519' or 'dual'");
  }
  if (suite === "dual" && !(hasPqPublicKey && hasPqSecretKey)) {
    throw new Error(
      "dual protected signatures require a complete ML-DSA key pair; choose 'ed25519' for a partial keyring",
    );
  }
  return suite;
}

interface ResolvedProtectionIdentity {
  signerId: bigint;
  keyring: Uint8Array;
}

interface ResolvedDecryptionIdentity {
  id?: bigint;
  keyrings: Uint8Array[];
}

interface SignerResolutionOptions {
  expectedSignerId?: bigint | number | string;
  resolveSignerPublicKeys?: MTPSignerKeyResolver;
}

function sameBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  for (let index = 0; index < left.length; index += 1) {
    if (left[index] !== right[index]) return false;
  }
  return true;
}

/**
 * Normalize one recipient identity into current-first, duplicate-free keyring
 * bytes. The returned arrays are owned by the SDK and never alias caller
 * input.
 */
function normalizeDecryptionKeyrings(
  identity: MTPDecryptionIdentity,
): Uint8Array[] {
  const current = normalizeBytes(identity.keyring, "recipient.keyring");
  if (current.length === 0) {
    throw new Error("recipient.keyring must not be empty");
  }

  if (
    identity.keyringHistory !== undefined &&
    !Array.isArray(identity.keyringHistory)
  ) {
    throw new TypeError("recipient.keyringHistory must be an array");
  }

  const keyrings: Uint8Array[] = [];
  const add = (value: string | MTPBytesInput, name: string): void => {
    const bytes = normalizeBytes(value, name);
    if (bytes.length === 0) {
      throw new Error(`${name} must not be empty`);
    }
    if (!keyrings.some((existing) => sameBytes(existing, bytes))) {
      keyrings.push(bytes.slice());
    }
  };

  add(current, "recipient.keyring");
  for (const [index, history] of (
    identity.keyringHistory ?? []
  ).entries()) {
    add(history, `recipient.keyringHistory[${index}]`);
  }

  if (keyrings.length === 0) {
    throw new Error("recipient must contain at least one keyring");
  }
  return keyrings;
}

function normalizeRecipientBundles(
  recipients: Array<string | MTPBytesInput>,
  name: string,
): Uint8Array[] {
  if (!Array.isArray(recipients) || recipients.length === 0) {
    throw new TypeError(`${name} must contain at least one public key bundle`);
  }

  return recipients.map((value, index) => {
    const bundle = normalizeBytes(value, `${name}[${index}]`);
    publicKeyBundleToKeys(bundle);
    return bundle.slice();
  });
}

function resolveProtectionIdentity(
  explicit: MTPProtectionIdentity | undefined,
  stored: InternalCredentials | null,
): ResolvedProtectionIdentity {
  if (explicit) {
    return {
      signerId: inputU64(explicit.signerId, "identity.signerId"),
      keyring: normalizeBytes(explicit.keyring, "identity.keyring").slice(),
    };
  }

  if (stored?.clientId != null && stored.keyring.length > 0) {
    return {
      signerId: stored.clientId,
      keyring: stored.keyring.slice(),
    };
  }

  throw new Error(
    "protected send requires an explicit protection identity or stored registered credentials",
  );
}

function resolveDecryptionIdentity(
  explicit: MTPDecryptionIdentity | undefined,
  stored: InternalCredentials | null,
): ResolvedDecryptionIdentity {
  if (explicit) {
    return {
      id:
        explicit.id == null
          ? undefined
          : inputU64(explicit.id, "recipient.id"),
      keyrings: normalizeDecryptionKeyrings(explicit),
    };
  }

  if (stored?.clientId != null && stored.keyring.length > 0) {
    return {
      id: stored.clientId,
      keyrings: normalizeDecryptionKeyrings({
        id: stored.clientId,
        keyring: stored.keyring,
      }),
    };
  }

  throw new Error(
    "protected receive requires an explicit decryption identity or stored registered credentials",
  );
}

const KEM_PUBLIC_KEY_LEN = 1216;
const SIG_PQ_PUBLIC_KEY_LEN = 1952;
const SIG_CL_PUBLIC_KEY_LEN = 32;

function emit(
  logger: MTPClientOptions["logger"] | undefined,
  event: MTPLogEvent,
): void {
  if (typeof logger === "function") {
    logger(event);
  }
}

function isErrorType(type: string): boolean {
  return (
    type === "Error" ||
    type.startsWith("Error") ||
    [
      "BadRequest",
      "Unauthorized",
      "Forbidden",
      "NotFound",
      "TooManyRequests",
      "InternalServerError",
      "BadGateway",
      "ServiceUnavailable",
      "GatewayTimeout",
    ].includes(type)
  );
}

function parsedDataObject(
  data: ParsedFrame["data"] | null | undefined,
): Record<string, unknown> {
  if (
    data === null ||
    typeof data !== "object" ||
    Array.isArray(data) ||
    data instanceof Uint8Array
  ) {
    return {};
  }

  const object = data as Record<string, unknown>;
  if (object.kind === "encrypted" || object.kind === "signed") {
    return {};
  }
  return object;
}

function parseProtectedFrame(frame: MTPProtectedFrameInput): ParsedFrame {
  if (isBytes(frame)) {
    return bindings.parse_frame(bytesFrom(frame, "frame"));
  }
  if (
    frame === null ||
    typeof frame !== "object" ||
    typeof frame.type !== "string"
  ) {
    throw new TypeError("frame must be a parsed MTP frame or serialized bytes");
  }
  if (frame.raw instanceof Uint8Array) {
    return bindings.parse_frame(frame.raw);
  }
  return frame;
}

function assertKnownCommunicationType(frame: ParsedFrame): void {
  if (!frame.type || /^[0-9]+$/.test(frame.type)) {
    throw new Error(`Unknown communication type: ${frame.type || "unknown"}`);
  }
  try {
    bindings.build_frame(frame.type, null, {});
  } catch (error) {
    throw new Error(`Unknown communication type: ${frame.type}`, {
      cause: error,
    });
  }
}

function protectedFrameBytes(frame: ParsedFrame): Uint8Array {
  if (frame.raw instanceof Uint8Array) return frame.raw.slice();
  const data =
    frame.data !== null &&
    typeof frame.data === "object" &&
    !Array.isArray(frame.data) &&
    !(frame.data instanceof Uint8Array)
      ? (frame.data as Record<string, unknown>)
      : null;
  const encoded = data?.encoded;
  if (data?.kind !== "encrypted" || !(encoded instanceof Uint8Array)) {
    throw new Error("protected frame payload is not encrypted");
  }
  return bindings.build_frame_with_payload(frame.type, encoded, {
    id: frame.id,
    ...(frame.sender == null ? {} : { sender: frame.sender }),
    ...(frame.receiver == null ? {} : { receiver: frame.receiver }),
  });
}

function assertApplicationCommunicationType(type: string): string {
  if (typeof type !== "string" || !type.trim() || /^[0-9]+$/.test(type)) {
    throw new Error(`Unknown communication type: ${type || "unknown"}`);
  }
  if (Object.prototype.hasOwnProperty.call(RESERVED_COMMUNICATION_TYPE_IDS, type)) {
    throw new Error(
      `MTP control communication type ${type} cannot be used as application content`,
    );
  }
  try {
    bindings.build_frame(type, null, {});
  } catch (error) {
    throw new Error(`Unknown communication type: ${type}`, { cause: error });
  }
  return type;
}

function cloneParsedValue(value: unknown): unknown {
  if (value instanceof Uint8Array) return value.slice();
  if (Array.isArray(value)) return value.map(cloneParsedValue);
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([key, entry]) => [
        key,
        cloneParsedValue(entry),
      ]),
    );
  }
  return value;
}

function cloneParsedFrame(frame: ParsedFrame): ParsedFrame {
  return cloneParsedValue(frame) as ParsedFrame;
}

function encodeMTPDataValue(value: unknown): Uint8Array {
  const ancestors = new WeakSet<object>();
  const validate = (candidate: unknown): void => {
    if (
      candidate === null ||
      typeof candidate === "boolean" ||
      typeof candidate === "string" ||
      typeof candidate === "bigint" ||
      candidate instanceof Uint8Array
    ) {
      return;
    }
    if (typeof candidate === "number") {
      if (Number.isInteger(candidate) && !Number.isSafeInteger(candidate)) {
        throw new TypeError(
          "unsafe integral MTP DataValue inputs must use bigint",
        );
      }
      return;
    }
    if (typeof candidate !== "object") {
      throw new TypeError(`unsupported MTP DataValue input: ${typeof candidate}`);
    }
    const object = candidate as object;
    if (ancestors.has(object)) {
      throw new TypeError("MTP DataValue input must not be cyclic");
    }
    if (
      !Array.isArray(candidate) &&
      Object.getPrototypeOf(candidate) !== Object.prototype &&
      Object.getPrototypeOf(candidate) !== null
    ) {
      throw new TypeError("MTP DataValue containers must be plain objects");
    }
    ancestors.add(object);
    const entries = Array.isArray(candidate)
      ? candidate
      : Object.values(candidate as Record<string, unknown>);
    for (const entry of entries) validate(entry);
    ancestors.delete(object);
  };

  validate(value);
  return bindings.encode_data_value(value);
}

function valueAsBigInt(value: unknown, name: string): bigint {
  try {
    if (typeof value === "bigint") return value;
    if (typeof value === "number" && Number.isSafeInteger(value)) {
      return BigInt(value);
    }
    if (typeof value === "string" && value.length > 0) {
      return BigInt(value);
    }
  } catch {
    // Normalize all malformed protected metadata to one caller-facing error.
  }
  throw new Error(`protected metadata field ${name} is not an integer`);
}

function valueAsUnsignedBigInt(value: unknown, name: string): bigint {
  const result = valueAsBigInt(value, name);
  if (result < 0n) {
    throw new Error(`protected metadata field ${name} must be unsigned`);
  }
  return result;
}

function valueAsU64BigInt(value: unknown, name: string): bigint {
  const result = valueAsUnsignedBigInt(value, name);
  if (result > 0xffff_ffff_ffff_ffffn) {
    throw new Error(`protected metadata field ${name} is outside u64 range`);
  }
  return result;
}

function inputU64(value: bigint | number | string, name: string): bigint {
  if (typeof value === "number" && !Number.isSafeInteger(value)) {
    throw new RangeError(
      `${name} must be a safe integer number, bigint, or integer string`,
    );
  }
  let result: bigint;
  try {
    result = BigInt(value);
  } catch (error) {
    throw new RangeError(`${name} must be an integer`, { cause: error });
  }
  if (result < 0n || result > 0xffff_ffff_ffff_ffffn) {
    throw new RangeError(`${name} must be a u64`);
  }
  return result;
}

function valueAsString(value: unknown, name: string): string {
  if (typeof value === "string" && value.length > 0) return value;
  throw new Error(`protected metadata field ${name} is not a non-empty string`);
}

function errorMessage(
  frame: Pick<ParsedFrame, "type" | "data"> | null | undefined,
): string {
  const data = parsedDataObject(frame?.data);
  return String(
    data.ErrorMessage ??
      data.Error ??
      data.Description ??
      `Received ${frame?.type ?? "error"} frame`,
  );
}

async function storageGet(
  storage: MTPCredentialStorage | undefined,
  key: string,
): Promise<StorageValue> {
  return storage ? await storage.getItem(key) : null;
}

async function storageSet(
  storage: MTPCredentialStorage | undefined,
  key: string,
  value: string,
): Promise<void> {
  if (storage) {
    await storage.setItem(key, value);
  }
}

async function storageRemove(
  storage: MTPCredentialStorage | undefined,
  key: string,
): Promise<void> {
  if (storage) {
    await storage.removeItem(key);
  }
}

function isBytes(value: unknown): value is MTPBytesInput {
  return value instanceof Uint8Array || Array.isArray(value);
}

function bytesFrom(value: MTPBytesInput, name: string): Uint8Array {
  if (value instanceof Uint8Array) {
    return value;
  }
  if (Array.isArray(value)) {
    return new Uint8Array(value);
  }
  throw new TypeError(`${name} must be a Uint8Array or number[]`);
}

function bytesFromString(value: string, name: string): Uint8Array {
  const trimmed = value.trim();
  if (!trimmed) {
    throw new TypeError(`${name} must not be empty`);
  }

  const hex = trimmed.replace(/^(0x)/i, "").replace(/[\s:_-]/g, "");
  if (/^[0-9a-fA-F]+$/.test(hex)) {
    if (hex.length % 2 !== 0) {
      throw new TypeError(`${name} hex string has an odd length`);
    }
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i += 1) {
      bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    }
    return bytes;
  }

  if (typeof atob === "function") {
    const binary = atob(trimmed);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  if (typeof Buffer !== "undefined") {
    return new Uint8Array(Buffer.from(trimmed, "base64"));
  }

  throw new TypeError(`${name} must be bytes, hex, or base64`);
}

const HEX_DIGITS = "0123456789abcdef";

function bytesToHex(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i += 1) {
    out += HEX_DIGITS[(bytes[i] >> 4) & 0xf] + HEX_DIGITS[bytes[i] & 0xf];
  }
  return out;
}

export function bytesToBase64(bytes: Uint8Array): string {
  if (typeof btoa === "function") {
    let binary = "";
    for (let i = 0; i < bytes.length; i += 1) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }
  if (typeof Buffer !== "undefined") {
    return Buffer.from(bytes).toString("base64");
  }
  throw new TypeError("base64 encoding is not available in this environment");
}

export function base64ToBytes(input: string): Uint8Array {
  if (typeof atob === "function") {
    const binary = atob(input);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }
  if (typeof Buffer !== "undefined") {
    return new Uint8Array(Buffer.from(input, "base64"));
  }
  throw new TypeError("base64 decoding is not available in this environment");
}

function utf8Decode(bytes: Uint8Array): string {
  if (typeof TextDecoder !== "undefined") {
    return new TextDecoder().decode(bytes);
  }
  if (typeof Buffer !== "undefined") {
    return Buffer.from(bytes).toString("utf-8");
  }
  let out = "";
  let i = 0;
  while (i < bytes.length) {
    const b = bytes[i];
    if (b < 0x80) {
      out += String.fromCharCode(b);
      i += 1;
    } else if (b < 0xc0) {
      i += 1;
    } else if (b < 0xe0) {
      out += String.fromCharCode(((b & 0x1f) << 6) | (bytes[i + 1] & 0x3f));
      i += 2;
    } else if (b < 0xf0) {
      out += String.fromCharCode(
        ((b & 0x0f) << 12) |
          ((bytes[i + 1] & 0x3f) << 6) |
          (bytes[i + 2] & 0x3f),
      );
      i += 3;
    } else {
      const cp =
        ((b & 0x07) << 18) |
        ((bytes[i + 1] & 0x3f) << 12) |
        ((bytes[i + 2] & 0x3f) << 6) |
        (bytes[i + 3] & 0x3f);
      out += String.fromCodePoint(cp);
      i += 4;
    }
  }
  return out;
}

const SYMMETRIC_KEY_SALT = utf8Encode("mtp-symmetric-key");

export function secretKeyFromString(secret: string): Uint8Array {
  if (typeof secret !== "string" || !secret.trim()) {
    throw new TypeError("secret must be a non-empty string");
  }

  const trimmed = secret.trim();
  const hex = trimmed.replace(/^(0x)/i, "").replace(/[\s:_-]/g, "");
  if (/^[0-9a-fA-F]+$/.test(hex) && hex.length === 64) {
    const bytes = new Uint8Array(32);
    for (let i = 0; i < 32; i += 1) {
      bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    }
    return bytes;
  }

  if (typeof atob === "function" || typeof Buffer !== "undefined") {
    try {
      const decoded = bytesFromString(trimmed, "secret");
      if (decoded.length === 32) {
        return decoded;
      }
    } catch {
      // fall through to HKDF derivation
    }
  }

  const ikm = utf8Encode(trimmed);
  return bindings.wasm_derive_encryption_key(
    ikm,
    SYMMETRIC_KEY_SALT,
    SYMMETRIC_KEY_SALT,
  );
}

function normalizeBytes(
  value: string | MTPBytesInput,
  name: string,
): Uint8Array {
  if (typeof value === "string") {
    return bytesFromString(value, name);
  }
  return bytesFrom(value, name);
}

function normalizeCredentials(
  value: MTPCredentials | string | null,
): MTPCredentials | null {
  if (!value) {
    return null;
  }

  if (typeof value === "string") {
    return JSON.parse(value);
  }

  return value;
}

function toBigInt(
  value: bigint | string | number | null | undefined,
): bigint | null {
  if (value == null || value === "") {
    return null;
  }
  return inputU64(value, "clientId");
}

function generateKeyringBytes() {
  return keyring_generate();
}

export function keyringToKeys(keyring: string | MTPBytesInput): MTPKeyringKeys {
  const bytes =
    typeof keyring === "string"
      ? bytesFromString(keyring, "keyring")
      : bytesFrom(keyring, "keyring");

  if (bytes.length < 12) {
    throw new TypeError("keyring data is too short to contain 6 keys");
  }

  let offset = 0;
  const readKey = () => {
    if (offset + 2 > bytes.length) {
      throw new TypeError("keyring is truncated");
    }
    const len = (bytes[offset] << 8) | bytes[offset + 1];
    offset += 2;
    if (offset + len > bytes.length) {
      throw new TypeError("keyring is truncated");
    }
    const key = bytes.slice(offset, offset + len);
    offset += len;
    return key;
  };

  const result = {
    kemPublicKey: readKey(),
    kemSecretKey: readKey(),
    sigPqPublicKey: readKey(),
    sigPqSecretKey: readKey(),
    sigClPublicKey: readKey(),
    sigClSecretKey: readKey(),
  };
  if (offset !== bytes.length) {
    throw new TypeError("keyring has trailing data");
  }
  return result;
}

export function publicKeyBundleToKeys(
  publicKeyBundle: string | MTPBytesInput,
): MTPPublicKeyBundleKeys {
  const bytes =
    typeof publicKeyBundle === "string"
      ? bytesFromString(publicKeyBundle, "publicKeyBundle")
      : bytesFrom(publicKeyBundle, "publicKeyBundle");

  if (bytes.length < 6) {
    throw new TypeError(
      "public key bundle data is too short to contain 3 keys",
    );
  }

  let offset = 0;
  const readKey = () => {
    if (offset + 2 > bytes.length) {
      throw new TypeError("public key bundle is truncated");
    }
    const len = (bytes[offset] << 8) | bytes[offset + 1];
    offset += 2;
    if (offset + len > bytes.length) {
      throw new TypeError("public key bundle is truncated");
    }
    const key = bytes.slice(offset, offset + len);
    offset += len;
    return key;
  };

  const result = {
    kemPublicKey: readKey(),
    sigPqPublicKey: readKey(),
    sigClPublicKey: readKey(),
  };

  if (offset !== bytes.length) {
    throw new TypeError("public key bundle has trailing data");
  }

  if (
    result.kemPublicKey.length !== KEM_PUBLIC_KEY_LEN ||
    result.sigPqPublicKey.length !== SIG_PQ_PUBLIC_KEY_LEN ||
    result.sigClPublicKey.length !== SIG_CL_PUBLIC_KEY_LEN
  ) {
    throw new TypeError("public key bundle contains invalid suite key lengths");
  }

  return result;
}

function serializeCredentials(credentials) {
  return JSON.stringify({
    clientId: credentials.clientId?.toString() ?? null,
    keyring: Array.from(credentials.keyring ?? []),
    hostPublicKey: credentials.hostPublicKey
      ? Array.from(credentials.hostPublicKey)
      : undefined,
  });
}

function deserializeCredentials(credentials) {
  const normalized = normalizeCredentials(credentials);
  if (!normalized) {
    return null;
  }

  const keyring = normalized.keyring;
  if (!isBytes(keyring)) {
    throw new TypeError("credentials.keyring must be a Uint8Array or number[]");
  }

  return {
    clientId: toBigInt(normalized.clientId),
    keyring: bytesFrom(keyring, "credentials.keyring"),
    hostPublicKey:
      normalized.hostPublicKey == null
        ? undefined
        : normalizeBytes(normalized.hostPublicKey, "credentials.hostPublicKey"),
  };
}

function publicCredentials(credentials) {
  if (!credentials) {
    return null;
  }
  return {
    clientId: credentials.clientId,
    keyring: credentials.keyring,
    hostPublicKey: credentials.hostPublicKey,
  };
}

function validateOptions(options) {
  if (!options || typeof options !== "object") {
    throw new TypeError("MTPClient.create requires an options object");
  }
  if (typeof options.url !== "string" || !options.url.trim()) {
    throw new TypeError("MTPClient.create requires a non-empty url");
  }
  if (options.descriptor != null && typeof options.descriptor !== "string") {
    throw new TypeError("descriptor must be a string");
  }
  resolveSignatureVerificationPolicy(
    undefined,
    options.defaultSignatureVerificationPolicy,
  );
  if (options.storage) {
    for (const method of ["getItem", "setItem", "removeItem"]) {
      if (typeof options.storage[method] !== "function") {
        throw new TypeError(`storage.${method} must be a function`);
      }
    }
  }
  if (
    options.maxMessageSize != null &&
    (!Number.isSafeInteger(options.maxMessageSize) ||
      options.maxMessageSize <= 0)
  ) {
    throw new TypeError("maxMessageSize must be a positive safe integer");
  }
  if (
    options.authTimeoutMs != null &&
    (!Number.isSafeInteger(options.authTimeoutMs) || options.authTimeoutMs <= 0)
  ) {
    throw new TypeError("authTimeoutMs must be a positive safe integer");
  }
  if (
    options.requestTimeoutMs != null &&
    (!Number.isSafeInteger(options.requestTimeoutMs) ||
      options.requestTimeoutMs <= 0)
  ) {
    throw new TypeError("requestTimeoutMs must be a positive safe integer");
  }
}

async function withTimeout(promise, timeoutMs, message, cancel?: () => void) {
  if (!timeoutMs) {
    return await promise;
  }

  let timeoutId;
  let timedOut = false;
  try {
    return await Promise.race([
      promise,
      new Promise((_resolve, reject) => {
        timeoutId = setTimeout(() => {
          timedOut = true;
          cancel?.();
          reject(new Error(message));
        }, timeoutMs);
      }),
    ]);
  } finally {
    clearTimeout(timeoutId);
    // A JS Promise.race cannot cancel the losing WASM future. Wait for the
    // raw attempt to observe disconnect() before its borrowed wasm arguments
    // are released by the caller's finally block.
    if (timedOut) {
      await promise.catch(() => undefined);
    }
  }
}

export class MTPClient {
  static readonly crypto = crypto;
  static readonly codec = codec;

  #credentials: InternalCredentials | null;
  #options: NormalizedMTPClientOptions;
  readonly #protectedReplayGuard = new InMemoryReplayGuard();
  readonly raw: MTPRaw;

  readonly crypto = MTPClient.crypto;
  readonly codec = MTPClient.codec;

  readonly sessionManager: MTPSessionManager;
  /** Independent encrypted-secret storage selected by the caller. */
  readonly encryptedSecretProvider: MTPEncryptedSecretProvider;

  private constructor(
    options: NormalizedMTPClientOptions,
    client: RawBindings.WasmClient,
  ) {
    this.#options = options;
    this.#credentials = deserializeCredentials(options.credentials);
    this.raw = { client, bindings };
    this.encryptedSecretProvider =
      options.encryptedSecretProvider ?? new InMemoryEncryptedSecretProvider();
    this.sessionManager = new MTPSessionManager(
      options.sessionStorage ?? new InMemorySessionStorage(),
    );
  }

  static async create(options: MTPClientOptions): Promise<MTPClient> {
    validateOptions(options);
    await MTPClient.init(options.wasm);

    const normalizedOptions = {
      ...options,
      hostPublicKey:
        options.hostPublicKey == null
          ? undefined
          : normalizeBytes(options.hostPublicKey, "hostPublicKey"),
    };

    let sdk: MTPClient | undefined;
    const client = new WasmClient(
      (state) =>
        emit(normalizedOptions.logger, {
          hint: "info",
          type: "state",
          data: ConnectionState[state] ?? state,
        }),
      (frame) => {
        if (sdk) {
          sdk.#handleFrame(frame);
        }
      },
      (error) =>
        emit(normalizedOptions.logger, {
          hint: "error",
          type: "Error",
          error: String(error),
        }),
    );

    sdk = new MTPClient(normalizedOptions, client);
    await sdk.#loadStoredCredentials();
    if (!sdk.#credentials) {
      sdk.#credentials = {
        clientId: null,
        keyring: generateKeyringBytes(),
        hostPublicKey: normalizedOptions.hostPublicKey,
      };
    } else if (
      !sdk.#credentials.hostPublicKey &&
      normalizedOptions.hostPublicKey
    ) {
      sdk.#credentials = {
        ...sdk.#credentials,
        hostPublicKey: normalizedOptions.hostPublicKey,
      };
    } else if (
      !normalizedOptions.hostPublicKey &&
      sdk.#credentials.hostPublicKey
    ) {
      sdk.#options = {
        ...sdk.#options,
        hostPublicKey: sdk.#credentials.hostPublicKey,
      };
    }
    return sdk;
  }

  static isSupported(): boolean {
    return WasmClient.is_supported();
  }

  static async init(
    wasm?: MTPClientOptions["wasm"],
  ): Promise<Awaited<ReturnType<typeof initWasm>>> {
    wasmInitPromise ??= initWasm(wasm);
    return await wasmInitPromise;
  }

  get credentials(): MTPClientCredentials | null {
    return publicCredentials(this.#credentials);
  }

  get defaultSignatureVerificationPolicy(): MTPSignatureVerificationPolicy {
    return resolveSignatureVerificationPolicy(
      undefined,
      this.#options.defaultSignatureVerificationPolicy,
    );
  }

  get state(): RawBindings.ConnectionState {
    return this.raw.client.state;
  }

  get pingMs(): number | null {
    return this.raw.client.ping_ms ?? null;
  }

  async #loadStoredCredentials() {
    if (this.#credentials || !this.#options.storage) {
      return;
    }

    const stored = await storageGet(
      this.#options.storage,
      this.#options.credentialsStorageKey ?? DEFAULT_CREDENTIALS_KEY,
    );
    this.#credentials = deserializeCredentials(stored);
  }

  #connectionConfig() {
    const config = new ConnectionConfig(this.#options.url);
    if (this.#options.serverCertificateHashes) {
      config.server_certificate_hashes = this.#options.serverCertificateHashes;
    }
    if (this.#options.maxMessageSize != null) {
      config.max_message_size = this.#options.maxMessageSize;
    }
    if (this.#options.descriptor != null) {
      config.description = this.#options.descriptor;
    }
    return config;
  }

  async connect(): Promise<void> {
    if (this.#credentials?.clientId != null && this.#options.hostPublicKey) {
      await this.auth();
      return;
    }

    await this.connectUnauthenticated();
  }

  async connectUnauthenticated(): Promise<void> {
    const config = this.#connectionConfig();
    try {
      await withTimeout(
        this.raw.client.connect(config),
        this.#options.authTimeoutMs,
        "connection timed out",
        () => this.raw.client.disconnect(),
      );
      const clientId = (
        this.raw.client as RawBindings.WasmClient & { readonly client_id: bigint }
      ).client_id;
      this.#startPings(clientId);
    } finally {
      config.free();
    }
  }

  async auth(): Promise<bigint> {
    if (!this.#options.hostPublicKey) {
      throw new Error("MTPClient.auth requires hostPublicKey");
    }
    return this.#credentials?.clientId == null
      ? await this.register()
      : await this.#connectAuthenticated();
  }

  async #connectAuthenticated() {
    if (!this.#options.hostPublicKey) {
      throw new Error(
        "MTPClient.connect requires hostPublicKey for authenticated connections",
      );
    }
    if (
      !this.#credentials?.keyring?.length ||
      this.#credentials.clientId == null
    ) {
      throw new Error(
        "MTPClient.connect requires credentials with clientId and keyring",
      );
    }

    const config = this.#connectionConfig();
    try {
      const clientId = await withTimeout(
        this.raw.client.auth_connect(
          config,
          this.#options.hostPublicKey,
          this.#credentials.keyring,
          this.#credentials.clientId,
        ),
        this.#options.authTimeoutMs,
        "authentication timed out",
        () => this.raw.client.disconnect(),
      );
      this.#credentials = { ...this.#credentials, clientId };
      await this.#persistCredentials();
      this.#startPings(clientId);
      return clientId;
    } finally {
      config.free();
    }
  }

  async register(): Promise<bigint> {
    if (!this.#options.hostPublicKey) {
      throw new Error("MTPClient.register requires hostPublicKey");
    }
    if (!this.#credentials?.keyring?.length) {
      this.#credentials = {
        clientId: null,
        keyring: generateKeyringBytes(),
        hostPublicKey: this.#options.hostPublicKey,
      };
    }

    const config = this.#connectionConfig();
    try {
      const clientId = await withTimeout(
        this.raw.client.auth_register(
          config,
          this.#options.hostPublicKey,
          this.#credentials.keyring,
        ),
        this.#options.authTimeoutMs,
        "authentication timed out",
        () => this.raw.client.disconnect(),
      );
      this.#credentials = { ...this.#credentials, clientId };
      await this.#persistCredentials();
      this.#startPings(clientId);
      return clientId;
    } finally {
      config.free();
    }
  }

  async #persistCredentials() {
    await storageSet(
      this.#options.storage,
      this.#options.credentialsStorageKey ?? DEFAULT_CREDENTIALS_KEY,
      serializeCredentials(this.#credentials),
    );
  }

  async clearCredentials(): Promise<void> {
    this.#credentials = null;
    await storageRemove(
      this.#options.storage,
      this.#options.credentialsStorageKey ?? DEFAULT_CREDENTIALS_KEY,
    );
  }

  #startPings(clientId) {
    const pings = this.#options.pings;
    if (!pings) {
      this.raw.client.stop_protocol_pings();
      return;
    }
    const intervalMs =
      typeof pings === "object" ? (pings.intervalMs ?? 30_000) : 30_000;
    this.raw.client.start_protocol_pings(intervalMs, clientId);
  }

  #buildFrame(typeOrFrame, data, options) {
    if (typeOrFrame instanceof Uint8Array) {
      return typeOrFrame;
    }
    if (typeof typeOrFrame !== "string" || !typeOrFrame) {
      throw new TypeError(
        "message type must be a non-empty string or Uint8Array frame",
      );
    }
    if (data == null || typeof data !== "object" || Array.isArray(data)) {
      throw new TypeError("message data must be an object");
    }
    return this.raw.bindings.build_frame(typeOrFrame, data, options ?? {});
  }

  async send(message: Uint8Array): Promise<void>;
  async send(
    type: MTPCommunicationType,
    data: Record<string, unknown>,
    options?: MTPSendOptions,
  ): Promise<void>;
  async send(
    typeOrFrame: Uint8Array | MTPCommunicationType,
    data?: Record<string, unknown>,
    options?: MTPSendOptions,
  ): Promise<void> {
    const message = this.#buildFrame(typeOrFrame, data, options);

    try {
      const frame = this.raw.bindings.parse_frame(message);
      emit(
        this.#options.logger,
        isErrorType(frame.type)
          ? {
              hint: "error",
              type: frame.type,
              error: errorMessage(frame),
              data: frame.data,
              direction: "send",
            }
          : {
              hint: "info",
              type: frame.type,
              data: frame.data,
              direction: "send",
            },
      );
    } catch (error) {
      emit(this.#options.logger, {
        hint: "error",
        type: "Error",
        error: String(error),
        direction: "send",
      });
    }

    await this.raw.client.send(message);
  }

  /** Re-route an opaque sealed relay payload without opening it. */
  forwardRelayFrame(
    frame: Uint8Array | ParsedFrame,
    nextHopId: bigint | number | string,
  ): Uint8Array {
    const raw = frame instanceof Uint8Array ? frame : frame.raw;
    const nextHop = inputU64(nextHopId, "nextHopId");
    return bindings.forward_encrypted_relay_frame(raw, nextHop);
  }

  /** Forward an opaque sealed relay frame through this client connection. */
  async forwardRelay(
    frame: Uint8Array | ParsedFrame,
    nextHopId: bigint | number | string,
  ): Promise<void> {
    await this.send(this.forwardRelayFrame(frame, nextHopId));
  }

  async request(
    message: Uint8Array,
    data?: never,
    options?: MTPRequestOptions,
  ): Promise<ParsedFrame>;
  async request(
    type: MTPCommunicationType,
    data: Record<string, unknown>,
    options?: MTPRequestOptions,
  ): Promise<ParsedFrame>;
  async request(
    typeOrFrame: Uint8Array | MTPCommunicationType,
    data?: Record<string, unknown>,
    options: MTPRequestOptions = {},
  ): Promise<ParsedFrame> {
    const timeoutMs =
      options.timeoutMs ?? this.#options.requestTimeoutMs ?? 30_000;
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0) {
      throw new TypeError("request timeoutMs must be a positive safe integer");
    }
    const frame = this.#buildFrame(typeOrFrame, data, options);
    try {
      const parsed = this.raw.bindings.parse_frame(frame);
      emit(
        this.#options.logger,
        isErrorType(parsed.type)
          ? {
              hint: "error",
              type: parsed.type,
              error: errorMessage(parsed),
              data: parsed.data,
              direction: "send",
            }
          : {
              hint: "info",
              type: parsed.type,
              data: parsed.data,
              direction: "send",
            },
      );
    } catch (error) {
      emit(this.#options.logger, {
        hint: "error",
        type: "Error",
        error: String(error),
        direction: "send",
      });
    }
    // The WASM client owns request expiry and its late-response tombstones.
    // Keeping a second Promise timer here can reject the SDK call while the
    // protocol request is still allowed to complete successfully.
    return await this.raw.client.request(
      frame,
      options.responseType ?? null,
      timeoutMs,
    );
  }

  subscribe(
    type: MTPCommunicationType,
    handler: (message: ParsedFrame) => void,
  ): Unsubscribe {
    if (typeof type !== "string" || !type) {
      throw new TypeError("subscription type must be a non-empty string");
    }
    if (typeof handler !== "function") {
      throw new TypeError("subscription handler must be a function");
    }
    const id = this.raw.client.subscribe(type, handler);
    return () => this.raw.client.unsubscribe(id);
  }

  #handleFrame(frame) {
    if (isErrorType(frame.type)) {
      emit(this.#options.logger, {
        hint: "error",
        type: frame.type,
        error: errorMessage(frame),
        data: frame.data,
        direction: "recv",
      });
    } else {
      emit(this.#options.logger, {
        hint: "info",
        type: frame.type,
        data: frame.data,
        direction: "recv",
      });
    }
  }

  #getKemPublicKey(): Uint8Array {
    if (!this.#credentials?.keyring?.length) {
      throw new Error("No keyring available");
    }
    const keys = keyringToKeys(this.#credentials.keyring);
    return keys.kemPublicKey;
  }

  #getKemSecretKey(): Uint8Array {
    if (!this.#credentials?.keyring?.length) {
      throw new Error("No keyring available");
    }
    const keys = keyringToKeys(this.#credentials.keyring);
    return keys.kemSecretKey;
  }

  #getPublicKeyBundleBytes(): Uint8Array {
    if (!this.#credentials?.keyring?.length) {
      throw new Error("No keyring available");
    }
    const keyring = bindings.WasmKeyring.from_bytes(
      this.#credentials.keyring,
    );
    try {
      const bundle = keyring.public_key_bundle();
      try {
        return bundle.to_bytes();
      } finally {
        bundle.free();
      }
    } finally {
      keyring.free();
    }
  }

  #resolveDecryptionIdentity(
    explicit?: MTPDecryptionIdentity,
  ): ResolvedDecryptionIdentity {
    return resolveDecryptionIdentity(explicit, this.#credentials);
  }

  #assertExpectedSignerId(
    signerId: bigint,
    expectedSignerId: bigint | number | string | undefined,
  ): void {
    if (
      expectedSignerId != null &&
      inputU64(expectedSignerId, "expectedSignerId") !== signerId
    ) {
      throw new Error("protected signer ID mismatch");
    }
  }

  async #resolveSignerPublicKeys(
    signerId: bigint,
    options: SignerResolutionOptions,
  ): Promise<Uint8Array[] | null> {
    if (options.resolveSignerPublicKeys) {
      let resolved: MTPResolvedSignerKeys;
      try {
        resolved = await options.resolveSignerPublicKeys(signerId);
      } catch {
        throw signerKeysUnavailable(signerId);
      }
      if (!Array.isArray(resolved) || resolved.length === 0) {
        throw signerKeysUnavailable(signerId);
      }
      return resolved.map((value, index) => {
        try {
          const bytes = normalizeBytes(value, `senderPublicKeys[${index}]`);
          publicKeyBundleToKeys(bytes);
          return bytes;
        } catch {
          throw signerKeysUnavailable(signerId);
        }
      });
    }
    if (this.#credentials?.clientId === signerId) {
      try {
        const bytes = this.#getPublicKeyBundleBytes();
        publicKeyBundleToKeys(bytes);
        return [bytes];
      } catch {
        throw signerKeysUnavailable(signerId);
      }
    }
    return null;
  }

  /**
   * Decrypt and verify only relay metadata. The content remains opaque so a
   * metadata-only relay participant can index or forward it without possessing
   * a content-recipient key.
   */
  async openRelayMetadata(
    frame: ParsedFrame,
    options: MTPOpenRelayMetadataOptions = {},
  ): Promise<MTPVerifiedRelayMetadata> {
    // The resolver is asynchronous. Keep an immutable byte snapshot so the
    // signer claim and the later native verification refer to one frame.
    const frameBytes = frame.raw.slice();
    const frameSnapshot = bindings.parse_frame(frameBytes);
    const signaturePolicy = resolveSignatureVerificationPolicy(
      options.signaturePolicy,
      this.#options.defaultSignatureVerificationPolicy,
    );
    const recipient = this.#resolveDecryptionIdentity(options.recipient);
    let signerId: bigint;
    try {
      signerId = BigInt(
        bindings.relay_metadata_claimed_signer_id(
          frameBytes,
          recipient.keyrings,
        ),
      );
    } catch (error) {
      throw relayOpeningError(error);
    }
    this.#assertExpectedSignerId(signerId, options.expectedSignerId);
    const signerBundles = await this.#resolveSignerPublicKeys(
      signerId,
      options,
    );
    if (!signerBundles) {
      throw signerKeysUnavailable(signerId);
    }

    let native: RawBindings.WasmVerifiedRelayMetadata | undefined;
    let ownershipTransferred = false;
    try {
      native = bindings.open_relay_metadata_with_keyrings(
        frameBytes,
        recipient.keyrings,
        signerId,
        signerBundles,
        signatureVerificationPolicyValue(signaturePolicy),
      );
    } catch (error) {
      throw relayOpeningError(error, signerId);
    }

    try {
      if (!native) throw new Error("relay metadata opening returned no handle");
      const metadataBytes = native.metadata();
      const hasApplicationMetadata = metadataBytes != null;
      const applicationMetadata = hasApplicationMetadata
        ? (cloneParsedValue(
            bindings.parse_data_value(metadataBytes),
          ) as MTPDataValue)
        : undefined;
      const nativeSignerId = BigInt(native.signer_id());
      const messageId = native.message_id();
      const createdAt = BigInt(native.created_at());
      if (options.replayGuard) {
        const accepted = await options.replayGuard.accept(
          nativeSignerId,
          messageId,
          createdAt,
        );
        if (!accepted) throw new MTPReplayError(nativeSignerId, messageId);
      }

      const matchedSignerKeyIndex = Number(native.matched_signer_key_index());
      if (
        !Number.isSafeInteger(matchedSignerKeyIndex) ||
        matchedSignerKeyIndex < 0 ||
        matchedSignerKeyIndex >= signerBundles.length
      ) {
        throw new Error("relay verification returned an invalid key index");
      }

      const verified = new MTPVerifiedRelayMetadata(RELAY_METADATA_TOKEN, {
        frame: frameSnapshot,
        native,
        relayVersion: Number(native.relay_version()),
        signerId: nativeSignerId,
        finalRecipientId: BigInt(native.final_recipient_id()),
        messageId,
        createdAt,
        hasMetadata: hasApplicationMetadata,
        metadata: applicationMetadata,
        encryptedContent: native.encrypted_content().slice(),
        signerPublicKeys: signerBundles.map((bundle) => bundle.slice()),
        matchedSignerKeyIndex,
        signaturePolicy,
        disposed: false,
        finalizerToken: {},
      });
      // Register only after the JS wrapper owns the native handle. The
      // finally block below handles every failure before this transfer.
      const state = relayMetadataState.get(verified);
      if (!state) throw new Error("relay metadata state was not initialized");
      relayMetadataFinalizer.register(verified, native, state.finalizerToken);
      ownershipTransferred = true;
      return verified;
    } finally {
      if (!ownershipTransferred) {
        try {
          native?.free();
        } catch {
          // Preserve the original opening or conversion failure.
        }
      }
    }
  }

  /** Open and verify content after relay metadata has been authenticated. */
  async openRelayContent(
    metadata: MTPVerifiedRelayMetadata,
    options: MTPOpenRelayContentOptions = {},
  ): Promise<MTPVerifiedRelayContent> {
    const recipient = this.#resolveDecryptionIdentity(options.recipient);
    const state = relayMetadataState.get(metadata);
    if (!state) {
      throw new Error(
        "relay metadata was not produced by authenticated opening",
      );
    }
    if (state.disposed) {
      throw new Error("relay metadata has been disposed");
    }
    const expectedFinalRecipientId =
      options.expectedFinalRecipientId == null
        ? recipient.id
        : inputU64(
            options.expectedFinalRecipientId,
            "expectedFinalRecipientId",
          );
    // Content belongs to the authenticated metadata operation. Inherit its
    // policy when no content override is supplied so a client default cannot
    // split the two relay verification layers.
    const signaturePolicy = resolveSignatureVerificationPolicy(
      options.signaturePolicy,
      state.signaturePolicy,
    );
    if (signaturePolicy !== state.signaturePolicy) {
      throw new MTPSignatureVerificationError(
        "policy-rejected",
        state.signerId,
      );
    }

    let signerBundles: Uint8Array[] = state.signerPublicKeys.map((bundle) =>
      bundle.slice(),
    );
    this.#assertExpectedSignerId(state.signerId, options.expectedSignerId);
    if (options.resolveSignerPublicKeys != null) {
      const resolved = await this.#resolveSignerPublicKeys(
        state.signerId,
        options,
      );
      if (state.disposed) {
        throw new Error("relay metadata has been disposed");
      }
      if (!resolved) {
        throw signerKeysUnavailable(state.signerId);
      }
      signerBundles = resolved;
    }

    // A caller may dispose the capability while asynchronous signer-key
    // resolution is in flight. Never hand a freed native handle back to
    // wasm-bindgen after that await, even if the resolver returned no keys.
    if (state.disposed) {
      throw new Error("relay metadata has been disposed");
    }

    let nativeContent: RawBindings.WasmVerifiedRelayContent;
    try {
      nativeContent = bindings.open_relay_content_with_keyrings(
        state.native,
        recipient.keyrings,
        signerBundles,
        expectedFinalRecipientId == null
          ? null
          : BigInt(expectedFinalRecipientId),
        signatureVerificationPolicyValue(signaturePolicy),
      );
    } catch (error) {
      throw relayOpeningError(error, state.signerId);
    }
    try {
      return this.#formatRelayContent(nativeContent, state);
    } finally {
      nativeContent.free();
    }
  }

  #formatRelayContent(
    nativeContent: RawBindings.WasmVerifiedRelayContent,
    state: MTPRelayMetadataState,
  ): MTPVerifiedRelayContent {
    const data = bindings.parse_data_value(nativeContent.content()) as MTPDataValue;

    return {
      type: nativeContent.message_type(),
      data: cloneParsedValue(data) as MTPDataValue,
      signerId: BigInt(nativeContent.signer_id()),
      finalRecipientId: BigInt(nativeContent.final_recipient_id()),
      messageId: state.messageId,
      createdAt: state.createdAt,
      metadata:
        state.hasMetadata
          ? (cloneParsedValue(state.metadata) as MTPDataValue)
          : undefined,
    };
  }

  async #openProtectedFrame(
    frameInput: MTPProtectedFrameInput,
    options: MTPOpenProtectedOptions,
  ): Promise<{
    frame: ParsedFrame;
    message: MTPVerifiedProtectedMessage;
  }> {
    if (!options || typeof options !== "object") {
      throw new TypeError("openProtected requires an options object");
    }
    if (typeof options.resolveSignerPublicKeys !== "function") {
      throw new TypeError("openProtected requires resolveSignerPublicKeys");
    }

    // Detach parsed-object inputs before awaiting signer-key resolution. This
    // keeps the authenticated payload and routing fields bound to one
    // snapshot even when a caller reuses or mutates its frame object.
    const frame = cloneParsedFrame(parseProtectedFrame(frameInput));
    assertKnownCommunicationType(frame);
    const frameBytes = protectedFrameBytes(frame);
    validateApplicationProtectionPurpose(options.signaturePurpose);
    validateApplicationProtectionPurpose(options.encryptionPurpose);

    const recipient = this.#resolveDecryptionIdentity(options.recipient);
    const signaturePolicy = resolveSignatureVerificationPolicy(
      options.signaturePolicy,
      this.#options.defaultSignatureVerificationPolicy,
    );
    const expectedReceiverId =
      options.expectedReceiverId == null
        ? recipient.id
        : inputU64(options.expectedReceiverId, "expectedReceiverId");
    let signerId: bigint;
    try {
      signerId = BigInt(
        bindings.protected_claimed_signer_id(
          frameBytes,
          recipient.keyrings,
          options.encryptionPurpose,
        ),
      );
    } catch (error) {
      throw protectedOpeningError(error);
    }
    this.#assertExpectedSignerId(signerId, options.expectedSignerId);
    const signerBundles = await this.#resolveSignerPublicKeys(signerId, options);
    if (!signerBundles) {
      throw signerKeysUnavailable(signerId);
    }

    let native: RawBindings.WasmVerifiedProtectedMessage;
    try {
      native = bindings.open_protected_with_keyrings(
        frameBytes,
        recipient.keyrings,
        signerId,
        signerBundles,
        expectedReceiverId == null ? null : expectedReceiverId,
        options.signaturePurpose,
        options.encryptionPurpose,
        signatureVerificationPolicyValue(signaturePolicy),
      );
    } catch (error) {
      throw protectedOpeningError(error, signerId);
    }

    const replayGuard = options.replayGuard ?? this.#protectedReplayGuard;
    const nativeSignerId = BigInt(native.signer_id());
    const messageId = native.message_id();
    const createdAt = BigInt(native.created_at());
    try {
      const accepted = await replayGuard.accept(
        nativeSignerId,
        messageId,
        createdAt,
      );
      if (!accepted) throw new MTPReplayError(nativeSignerId, messageId);

      const data = bindings.parse_data_value(native.content()) as MTPDataValue;
      const receiver = frame.receiver;
      const outerSender = frame.sender;
      return {
        frame,
        message: {
          type: native.message_type(),
          protectedVersion: Number(native.protected_version()),
          signerId: nativeSignerId,
          finalRecipientId: BigInt(native.final_recipient_id()),
          messageId,
          createdAt,
          ...(receiver == null ? {} : { receiver }),
          ...(outerSender == null ? {} : { outerSender }),
          data: cloneParsedValue(data) as MTPDataValue,
        },
      };
    } finally {
      native.free();
    }
  }

  async openProtected<T = MTPDataValue>(
    frame: MTPProtectedFrameInput,
    options: MTPOpenProtectedOptions,
  ): Promise<MTPVerifiedProtectedMessage<T>> {
    const opened = await this.#openProtectedFrame(frame, options);
    return opened.message as MTPVerifiedProtectedMessage<T>;
  }

  subscribeProtected<T = MTPDataValue>(
    type: MTPCommunicationType,
    handler: (
      message: MTPVerifiedProtectedMessage<T>,
      frame: ParsedFrame,
    ) => void | Promise<void>,
    options: MTPOpenProtectedOptions,
  ): Unsubscribe {
    if (typeof type !== "string" || !type) {
      throw new TypeError(
        "protected subscription type must be a non-empty string",
      );
    }
    const applicationType = assertApplicationCommunicationType(type);
    if (typeof handler !== "function") {
      throw new TypeError("protected handler must be a function");
    }
    const replayGuard = options.replayGuard ?? new InMemoryReplayGuard();
    const subscriptionOptions = { ...options, replayGuard };

    const sub = this.raw.client.subscribe(
      applicationType,
      async (frame: ParsedFrame) => {
        try {
          const opened = await this.#openProtectedFrame(
            frame,
            subscriptionOptions,
          );
          if (opened.message.type !== applicationType) return;
          await handler(
            opened.message as MTPVerifiedProtectedMessage<T>,
            opened.frame,
          );
        } catch (error) {
          emit(this.#options.logger, {
            hint: "error",
            type: "E2EE",
            error: String(error),
            direction: "recv",
          });
        }
      },
    );

    return () => this.raw.client.unsubscribe(sub);
  }

  async sendProtected(
    type: MTPCommunicationType,
    data: MTPDataValueInput,
    options: MTPSendProtectedOptions,
  ): Promise<void> {
    const messageType = assertApplicationCommunicationType(type);
    const identity = resolveProtectionIdentity(
      options.identity,
      this.#credentials,
    );
    const receiverId = inputU64(options.receiverId, "receiverId");
    const recipients = normalizeRecipientBundles(options.recipients, "recipients");
    const messageId = createMessageId();
    const createdAt = unixTimeMillis();
    validateApplicationProtectionPurpose(options.signaturePurpose);
    validateApplicationProtectionPurpose(options.encryptionPurpose);
    const signatureSuite = effectiveProtectionSignatureSuite(
      identity.keyring,
      options.signatureSuite,
    );
    const encodedContent = encodeMTPDataValue(data);
    let frame: Uint8Array;
    try {
      frame = bindings.build_protected_frame_with_keyring(
        messageType,
        encodedContent,
        identity.signerId,
        receiverId,
        messageId,
        createdAt,
        options.signaturePurpose,
        options.encryptionPurpose,
        identity.keyring,
        protectionSignatureSuiteValue(signatureSuite),
        options.id ?? null,
        options.exposeSender ?? false,
        recipients,
      );
    } catch (error) {
      throw protectedOpeningError(error, identity.signerId);
    }
    await this.send(frame);
  }

  async sendSealedRelay(
    type: MTPCommunicationType,
    data: MTPDataValueInput,
    options: MTPSendSealedRelayOptions,
  ): Promise<void> {
    const messageType = assertApplicationCommunicationType(type);
    const identity = resolveProtectionIdentity(
      options.identity,
      this.#credentials,
    );
    const finalRecipientId = inputU64(
      options.finalRecipientId,
      "finalRecipientId",
    );
    const nextHopId = inputU64(options.nextHopId, "nextHopId");
    const metadataRecipients = normalizeRecipientBundles(
      options.metadataRecipients,
      "metadataRecipients",
    );
    const contentRecipients = normalizeRecipientBundles(
      options.contentRecipients,
      "contentRecipients",
    );
    const signatureSuite = effectiveProtectionSignatureSuite(
      identity.keyring,
      options.signatureSuite,
    );
    const frame = bindings.build_encrypted_relay_frame_with_keyring(
      messageType,
      data,
      identity.signerId,
      finalRecipientId,
      nextHopId,
      createMessageId(),
      unixTimeMillis(),
      options.metadata === undefined
        ? undefined
        : encodeMTPDataValue(options.metadata),
      identity.keyring,
      protectionSignatureSuiteValue(signatureSuite),
      metadataRecipients,
      contentRecipients,
    );
    await this.send(frame);
  }

  subscribeSealedRelay(
    type: MTPCommunicationType,
    handler: (
      content: MTPVerifiedRelayContent,
      frame: ParsedFrame,
    ) => void | Promise<void>,
    options?: MTPEncryptedSubscriptionOptions,
  ): Unsubscribe;
  subscribeSealedRelay(
    handler: (
      content: MTPVerifiedRelayContent,
      frame: ParsedFrame,
    ) => void | Promise<void>,
    options?: MTPEncryptedSubscriptionOptions,
  ): Unsubscribe;
  subscribeSealedRelay(
    typeOrHandler:
      | MTPCommunicationType
      | ((
          content: MTPVerifiedRelayContent,
          frame: ParsedFrame,
        ) => void | Promise<void>),
    maybeHandlerOrOptions?:
      | ((
          content: MTPVerifiedRelayContent,
          frame: ParsedFrame,
        ) => void | Promise<void>)
      | MTPEncryptedSubscriptionOptions,
    maybeOptions?: MTPEncryptedSubscriptionOptions,
  ): Unsubscribe {
    const expectedInnerType =
      typeof typeOrHandler === "function" ? null : typeOrHandler;
    if (expectedInnerType != null) {
      assertApplicationCommunicationType(expectedInnerType);
    }
    const handler =
      typeof typeOrHandler === "function"
        ? typeOrHandler
        : typeof maybeHandlerOrOptions === "function"
          ? maybeHandlerOrOptions
          : null;
    if (!handler) {
      throw new TypeError("sealed relay handler must be a function");
    }
    const options: MTPEncryptedSubscriptionOptions =
      typeof typeOrHandler === "function"
        ? typeof maybeHandlerOrOptions === "function" ||
          maybeHandlerOrOptions == null
          ? {}
          : maybeHandlerOrOptions
        : (maybeOptions ?? {});
    const replayGuard = options.replayGuard ?? new InMemoryReplayGuard();
    const subscriptionOptions = { ...options, replayGuard };
    const sub = this.raw.client.subscribe(
      "Relay",
      async (frame: ParsedFrame) => {
        let metadata: MTPVerifiedRelayMetadata | undefined;
        try {
          metadata = await this.openRelayMetadata(frame, subscriptionOptions);
          const opened = await this.openRelayContent(
            metadata,
            subscriptionOptions,
          );
          if (
            !opened ||
            (expectedInnerType && opened.type !== expectedInnerType)
          ) {
            return;
          }
          const parsedFrame: ParsedFrame = {
            ...frame,
            type: opened.type,
            data: opened.data as ParsedFrame["data"],
          };
          await handler(opened, parsedFrame);
        } catch (e) {
          emit(this.#options.logger, {
            hint: "error",
            type: "E2EE",
            error: String(e),
            direction: "recv",
          });
        } finally {
          metadata?.dispose();
        }
      },
    );

    return () => this.raw.client.unsubscribe(sub);
  }

  /**
   * Subscribe to verified relay metadata without attempting content
   * decryption. The metadata capability is callback-scoped: it is disposed
   * after the handler resolves, so do not retain it for later content opening.
   * Call `openRelayMetadata()` directly when a longer-lived capability is
   * required and dispose it when finished.
   */
  subscribeRelayMetadata(
    handler: (
      metadata: MTPVerifiedRelayMetadata,
      frame: ParsedFrame,
    ) => void | Promise<void>,
    options: MTPOpenRelayMetadataOptions = {},
  ): Unsubscribe {
    if (typeof handler !== "function") {
      throw new TypeError("relay metadata handler must be a function");
    }
    const replayGuard = options.replayGuard ?? new InMemoryReplayGuard();
    const subscriptionOptions = { ...options, replayGuard };
    const sub = this.raw.client.subscribe(
      "Relay",
      async (frame: ParsedFrame) => {
        let metadata: MTPVerifiedRelayMetadata | undefined;
        try {
          metadata = await this.openRelayMetadata(frame, subscriptionOptions);
          await handler(metadata, frame);
        } catch (e) {
          emit(this.#options.logger, {
            hint: "error",
            type: "E2EE",
            error: String(e),
            direction: "recv",
          });
        } finally {
          metadata?.dispose();
        }
      },
    );
    return () => this.raw.client.unsubscribe(sub);
  }

  /** Explicit alias for callers that want to emphasize encrypted metadata. */
  subscribeEncryptedMetadata(
    handler: (
      metadata: MTPVerifiedRelayMetadata,
      frame: ParsedFrame,
    ) => void | Promise<void>,
    options: MTPOpenRelayMetadataOptions = {},
  ): Unsubscribe {
    return this.subscribeRelayMetadata(handler, options);
  }

  async setEncryptedSecret(record: MTPEncryptedSecretRecord): Promise<void> {
    await this.encryptedSecretProvider.set(record);
  }

  async getEncryptedSecret(id: string): Promise<MTPEncryptedSecretRecord | null> {
    return this.encryptedSecretProvider.get(id);
  }

  async deleteEncryptedSecret(id: string): Promise<void> {
    await this.encryptedSecretProvider.delete(id);
  }

  setOnPipeRequest(handler: ((request: MTPPipeRequest) => void) | null): void {
    if (handler == null) {
      this.raw.client.set_on_pipe_request(null);
      return;
    }
    this.raw.client.set_on_pipe_request(
      (event: { pipeId: number; description: string }) => {
        emit(this.#options.logger, {
          hint: "info",
          type: "PipeRequest",
          data: event,
          direction: "recv",
        });
        handler({ pipeId: event.pipeId, description: event.description });
      },
    );
  }

  async createPipe(description: string): Promise<MTPOutgoingPipeHandle> {
    if (typeof description !== "string") {
      throw new TypeError("description must be a string");
    }
    const handle: WasmPipeHandle =
      await this.raw.client.create_pipe(description);
    const sdk = this;
    return {
      pipeId: handle.pipeId,
      description: handle.description,
      async wait(): Promise<MTPPipeWriter | null> {
        const result = await handle.wait();
        if (result == null) {
          return null;
        }
        emit(sdk.#options.logger, {
          hint: "info",
          type: "PipeCreated",
          data: { pipeId: result.pipeId },
          direction: "send",
        });
        return result as unknown as MTPPipeWriter;
      },
    };
  }

  /**
   * Create and negotiate an encrypted pipe with the actual MTP pipe ID and
   * local identity bound automatically. A recipient array creates a group
   * bootstrap; membership changes should create a fresh session with the new
   * array.
   */
  async createEncryptedPipe(
    options: MTPCreateEncryptedPipeOptions,
  ): Promise<MTPEncryptedPipeWriter | null> {
    const credentials = this.#credentials;
    if (!credentials || credentials.clientId == null) {
      throw new Error("Client not registered");
    }
    const recipientId = inputU64(options.recipientId, "recipientId");
    if (
      options.recipientPublicKey != null &&
      options.recipientPublicKeys != null
    ) {
      throw new Error(
        "provide recipientPublicKey or recipientPublicKeys, not both",
      );
    }
    const rawRecipients =
      options.recipientPublicKeys ??
      (options.recipientPublicKey != null ? [options.recipientPublicKey] : []);
    if (rawRecipients.length === 0) {
      throw new Error("at least one recipient public key is required");
    }
    const recipients = rawRecipients.map((value, index) =>
      normalizeBytes(value, `recipientPublicKeys[${index}]`),
    );
    recipients.forEach((value) => publicKeyBundleToKeys(value));
    const purpose = options.purpose ?? 0x40;
    const direction = options.direction ?? 0;
    validateApplicationProtectionPurpose(purpose);
    if (!Number.isInteger(direction) || direction < 0 || direction > 0xff) {
      throw new RangeError("direction must be a u8");
    }

    const handle = await this.createPipe(
      options.description ?? "encrypted pipe",
    );
    const writer = await handle.wait();
    if (!writer) return null;
    if (writer.pipeId !== handle.pipeId) {
      throw new Error("created pipe ID does not match the accepted writer");
    }
    const sessionId = new Uint8Array(32);
    globalThis.crypto.getRandomValues(sessionId);
    return initiateMTPPipeSession(
      writer,
      {
        sessionId,
        pipeId: writer.pipeId,
        senderId: credentials.clientId,
        recipientId,
        purpose,
        direction,
      },
      credentials.keyring,
      recipients,
      options.signatureSuite,
    );
  }

  async acceptPipe(pipeId: number): Promise<MTPPipeReader> {
    if (typeof pipeId !== "number" || !Number.isFinite(pipeId)) {
      throw new TypeError("pipeId must be a finite number");
    }
    const reader = await this.raw.client.accept_pipe(pipeId);
    emit(this.#options.logger, {
      hint: "info",
      type: "PipeAccepted",
      data: { pipeId: reader.pipeId, description: reader.description },
      direction: "send",
    });
    return reader as unknown as MTPPipeReader;
  }

  /** Accept a pipe and learn its authenticated session ID from the offer. */
  async acceptEncryptedPipe(
    request: MTPPipeRequest,
    options: MTPAcceptEncryptedPipeOptions,
  ): Promise<MTPEncryptedPipeReader> {
    const credentials = this.#credentials;
    if (!credentials || credentials.clientId == null) {
      throw new Error("Client not registered");
    }
    if (!Number.isSafeInteger(request.pipeId) || request.pipeId <= 0) {
      throw new TypeError("request.pipeId must be a non-zero safe integer");
    }
    const senderId = inputU64(options.senderId, "senderId");
    const purpose = options.purpose ?? 0x40;
    const direction = options.direction ?? 0;
    validateApplicationProtectionPurpose(purpose);
    if (!Number.isInteger(direction) || direction < 0 || direction > 0xff) {
      throw new RangeError("direction must be a u8");
    }
    if (
      options.senderPublicKeys != null &&
      options.senderPublicKeys.length === 0
    ) {
      throw new Error("senderPublicKeys must contain at least one key");
    }
    const singleSenderPublicKey = options.senderPublicKey;
    if (options.senderPublicKeys == null && singleSenderPublicKey == null) {
      throw new Error("senderPublicKey or senderPublicKeys is required");
    }
    const senderPublicKey =
      options.senderPublicKeys != null
        ? options.senderPublicKeys.map((value, index) =>
            normalizeBytes(value, `senderPublicKeys[${index}]`),
          )
        : normalizeBytes(singleSenderPublicKey!, "senderPublicKey");
    const reader = await this.acceptPipe(request.pipeId);
    if (reader.pipeId !== request.pipeId) {
      throw new Error("accepted pipe ID does not match the requested pipe");
    }
    const signaturePolicy = resolveSignatureVerificationPolicy(
      options.signaturePolicy,
      this.#options.defaultSignatureVerificationPolicy,
    );
    return acceptMTPPipeSessionAuto(
      reader,
      {
        pipeId: reader.pipeId,
        senderId,
        recipientId: credentials.clientId,
        purpose,
        direction,
      },
      credentials.keyring,
      senderPublicKey,
      signaturePolicy,
    );
  }

  async denyPipe(pipeId: number): Promise<void> {
    if (typeof pipeId !== "number" || !Number.isFinite(pipeId)) {
      throw new TypeError("pipeId must be a finite number");
    }
    await this.raw.client.deny_pipe(pipeId);
    emit(this.#options.logger, {
      hint: "info",
      type: "PipeDenied",
      data: { pipeId },
      direction: "send",
    });
  }

  disconnect(): void {
    this.raw.client.stop_protocol_pings();
    this.raw.client.disconnect();
  }
}

export { ConnectionState, bindings as raw };

// E2EE exports
export type {
  MTPSessionState,
  MTPSessionStorage,
  MTPSessionTranscriptContext,
  SkippedMessageKey,
} from "./session";
export {
  MTPSessionManager,
  InMemorySessionStorage,
  derivePeerSessionId,
  deriveSessionKeys,
  buildSessionTranscript,
} from "./session.js";
export { MTPRatchet } from "./ratchet.js";
export type { RatchetStep } from "./ratchet.js";
export {
  MTPEncryptedPipeError,
  MTPEncryptedPipeReader,
  MTPEncryptedPipeWriter,
  MTPPipeProtectionContext,
  MAX_ENCRYPTED_PIPE_RECORD,
  pipeSessionSignaturePurpose,
  pipeSessionEncryptionPurpose,
  validateApplicationProtectionPurpose,
  MAX_PIPE_SESSION_OFFER,
  initiateMTPPipeSession,
  acceptMTPPipeSession,
  acceptMTPPipeSessionAuto,
  initiateMTPForwardSecurePipeSession,
  acceptMTPForwardSecurePipeSession,
} from "./encrypted-pipe.js";
export type {
  MTPReadablePipe,
  MTPWritablePipe,
  MTPPipeSessionParameters,
  MTPPipeSessionExpectation,
  MTPDuplexPipe,
  MTPEncryptedPipeReaderSource,
  MTPEncryptedPipeWriterSource,
} from "./encrypted-pipe.js";
export {
  serializeEncryptedMessage,
  parseEncryptedMessage,
  encryptPayload,
  decryptPayload,
  MTP_E2EE_VERSION,
  FLAG_INIT,
  MAX_RATCHET_SKIP,
} from "./encrypted-message.js";
export type {
  EncryptedMessageHeader,
  SerializedEncryptedMessage,
} from "./encrypted-message";
export type {
  MTPEncryptedSecretRecord,
  MTPEncryptedSecretProvider,
} from "./encrypted-secret";
export { InMemoryEncryptedSecretProvider } from "./encrypted-secret.js";
