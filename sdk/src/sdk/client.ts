// Private SDK client implementation. The public facade remains in index.ts.
import {
  ConnectionConfig,
  ConnectionState,
  WasmClient,
} from "mtp/raw";
import * as bindings from "mtp/raw";
import { unixTimeMillis } from "./utils.js";
import type * as RawBindings from "../raw/index";
import type { MTPCommunicationType } from "../type-map/index";
import { MTPProtocol } from "./schema.js";
import type {
  MTPMessageType,
  MTPFrame,
  MTPNoSchemas,
  MTPRequestData,
  MTPResponseFrame,
  MTPSchemaRegistry,
} from "./schema.js";
import type { MTPSessionStorage, MTPSessionState } from "./session";
import { MTPSessionManager } from "./session.js";
import {
  assertApplicationCommunicationType,
  assertKnownCommunicationType,
  base64ToBytes,
  bytesFrom,
  bytesToBase64,
  cloneParsedFrame,
  cloneParsedValue,
  codec,
  crypto,
  decode,
  decodeDataValueWithLimits,
  decodeWithLimits,
  encode,
  encodeMTPDataValue,
  errorMessage,
  format,
  inputU64,
  isBytes,
  keyringToKeys,
  normalizeBytes,
  parseProtectedFrame,
  protectedFrameBytes,
  publicKeyBundleToKeys,
  secretKeyFromString,
  legacySecretKeyFromStringV1,
  deriveKeyFromPassphraseSync,
  validateMTPDataValue,
} from "./codec.js";
import type {
  MTPEncryptedSecretRecord,
  MTPEncryptedSecretProvider,
} from "./encrypted-secret";
import { InMemoryEncryptedSecretProvider } from "./encrypted-secret.js";
import { InMemorySessionStorage } from "./session.js";
import {
  publicCredentials,
  zeroCredentials,
} from "./credentials.js";
import type { InternalCredentials } from "./credentials.js";
import { withTimeout } from "./timeout.js";
import { androidTauri, NativeTransport, nativeOptions } from "./native.js";
import { communicationError } from "./communication-error.js";

async function normalizeCommunicationError<T>(operation: Promise<T>): Promise<T> {
  try {
    return await operation;
  } catch (error) {
    throw communicationError(error);
  }
}
export {
  MTPCommunicationError,
  communicationError,
} from "./communication-error.js";
export type {
  MTPCommunicationErrorCode,
  MTPTransportPhase,
} from "./communication-error.js";
import { initWasmOnce } from "./wasm-init.js";
import {
  SubscriptionDispatcher,
  type MTPSubscriptionOptions,
} from "./subscription.js";
export type {
  MTPSubscriptionOptions,
  MTPSubscriptionHandler,
} from "./subscription.js";
import {
  acceptMTPPipeSession,
  acceptMTPPipeSessionAuto,
  acceptMTPForwardSecurePipeSession,
  initiateMTPForwardSecurePipeSession,
  initiateMTPPipeSession,
  MTPEncryptedPipeReader,
  MTPEncryptedPipeWriter,
  MTPPipeProtectionContext,
  validateApplicationProtectionPurpose,
} from "./encrypted-pipe.js";
import {
  acceptEncryptedPipe as acceptEncryptedPipeWithContext,
  acceptPipe as acceptPipeWithContext,
  createEncryptedPipe as createEncryptedPipeWithContext,
  createPipe as createPipeWithContext,
  denyPipe as denyPipeWithContext,
  setOnPipeRequest as setOnPipeRequestWithContext,
} from "./pipe-client.js";
import {
  InMemoryReplayGuard,
  MTPReplayError,
  effectiveProtectionSignatureSuite,
  normalizeRecipientBundles,
  protectedOpeningError,
  protectionSignatureSuiteValue,
  resolveDecryptionIdentity,
  resolveProtectionIdentity,
} from "./protection.js";
import type {
  ResolvedDecryptionIdentity,
  SignerResolutionOptions,
} from "./protection.js";
import {
  MTPVerifiedRelayMetadata,
  RELAY_METADATA_TOKEN,
  relayMetadataState,
  relayOpeningError,
  registerRelayMetadata,
} from "./relay.js";
import type { MTPRelayMetadataState } from "./relay.js";
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
      relay?: MTPRelayLogDetails;
    }
  | {
      hint: "error";
      type: string | "error";
      error: string;
      data?: unknown;
      direction?: "send" | "recv";
    };

export interface MTPRelayLogDetails {
  signerId: bigint;
  finalRecipientId: bigint;
  messageId: bigint;
  createdAt: bigint;
}

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
  keyringToKeys(keyring: MTPKeyMaterialInput): MTPKeyringKeys;
  publicKeyBundleToKeys(
    publicKeyBundle: MTPKeyMaterialInput,
  ): MTPPublicKeyBundleKeys;
  encrypt(key: Uint8Array, input: Uint8Array): Promise<Uint8Array>;
  decrypt(key: Uint8Array, input: Uint8Array): Promise<Uint8Array>;
  encryptText(key: Uint8Array, plaintext: string): Promise<string>;
  decryptText(key: Uint8Array, ciphertext: string): Promise<string>;
  encapsulate(otherPublicKey: Uint8Array): WasmEncapsulated;
  decapsulate(ownPrivateKey: Uint8Array, ciphertext: Uint8Array): Uint8Array;
}

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

/** A textual key/blob input whose wire encoding is selected explicitly. */
export interface MTPEncodedBytesInput {
  value: string;
  encoding: "hex" | "base64";
}

export type MTPKeyMaterialInput = MTPBytesInput | MTPEncodedBytesInput;

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

export interface MTPCredentials {
  clientId: bigint | string | number | null;
  keyring: MTPBytesInput;
  hostPublicKey?: MTPKeyMaterialInput;
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

export interface MTPClientOptions<
  Registry extends MTPSchemaRegistry = MTPNoSchemas,
> {
  url: string;
  /** Native persistent identity name. Defaults to the credential storage key. */
  nativeName?: string;
  /** Create an independent ephemeral native identity and connection. */
  nativeFresh?: boolean;
  descriptor?: string;
  hostPublicKey?: MTPKeyMaterialInput;
  credentials?: MTPCredentials | string | null;
  credentialsStorageKey?: string;
  storage?: MTPCredentialStorage;
  serverCertificateHashes?: string[];
  maxMessageSize?: number;
  authTimeoutMs?: number;
  /** Require the hybrid PQ authentication proof when the host supports it. */
  requirePq?: boolean;
  requestTimeoutMs?: number;
  pings?: boolean | { intervalMs?: number };
  wasm?:
    | RawBindings.InitInput
    | Promise<RawBindings.InitInput>
    | {
        module_or_path: RawBindings.InitInput | Promise<RawBindings.InitInput>;
      };
  /** Optional application-owned logging for sent/received messages, state, and errors. */
  logger?: (event: MTPLogEvent) => void;
  /** Observe connection state independently of logging. */
  onStateChange?: (state: RawBindings.ConnectionState) => void;
  sessionStorage?: MTPSessionStorage;
  /**
   * Independent caller-managed encrypted-secret storage. Session state is not
   * routed through this provider automatically.
   */
  encryptedSecretProvider?: MTPEncryptedSecretProvider;
  /** Default receiver policy for protected signatures. */
  defaultSignatureVerificationPolicy?: MTPSignatureVerificationPolicy;
  /** Coherent security defaults for protected messages, encrypted pipes, and authentication. */
  securityProfile?: MTPSecurityProfile;
  /** One receive resource policy shared by frame and protected-value opening. */
  receiveLimits?: MTPReceiveLimits;
  /** Application request and response schemas, keyed by communication type. */
  schemas?: Registry;
  /** Reject `request()` when the correlated response is an `Error*` frame. */
  throwProtocolErrors?: boolean;
  /** Receives subscription validation failures. Request failures reject normally. */
  onValidationError?: (error: import("./schema.js").MTPValidationError) => void;
}

export interface MTPSecurityProfile {
  /** Signature suite used by protected-message and relay senders. */
  protectedSignatureSuite?: MTPProtectionSignatureSuite;
  /** Receiver policy for protected messages and relay metadata/content. */
  protectedSignaturePolicy?: MTPSignatureVerificationPolicy;
  /** Signature suite used by encrypted-pipe senders. */
  encryptedPipeSignatureSuite?: MTPProtectionSignatureSuite;
  /** Receiver policy used by encrypted-pipe acceptors. */
  encryptedPipeSignaturePolicy?: MTPSignatureVerificationPolicy;
  /** Authentication PQ requirement when the host supports the hybrid proof. */
  requirePq?: boolean;
}

export interface MTPEncodeLimits {
  maxDepth?: number;
  maxValues?: number;
  maxOutputSize?: number;
}

/** Resource limits forwarded to the bounded native/WASM receive decoder. */
export interface MTPReceiveLimits {
  maxDepth?: number;
  maxValues?: number;
  maxBlobSize?: number;
  maxRecipients?: number;
  maxAllocatedBytes?: number;
  /** Maximum reconstructed signed-value encoding size. */
  maxOutputSize?: number;
  maxMetadataEncodedBytes?: number;
  maxSignerKeyHistory?: number;
  maxDecryptionKeyHistory?: number;
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
  keyring: MTPKeyMaterialInput;
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
  keyring: MTPKeyMaterialInput;
  /**
   * Previously used recipient keyrings, ordered newest to oldest. The
   * current keyring is always attempted first.
   */
  keyringHistory?: MTPKeyMaterialInput[];
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
export type MTPResolvedSignerKeys = MTPKeyMaterialInput[];

/**
 * Resolve trusted public-key bundles for a claimed, unverified signer ID.
 * The ID is used only as a trusted-key lookup key and becomes authenticated
 * after the native protected codec verifies the signature.
 */
export type MTPSignerKeyResolver = (
  signerId: bigint,
) => MTPResolvedSignerKeys | Promise<MTPResolvedSignerKeys>;

export type MTPRelayTarget =
  | { kind: "user"; id: bigint | number | string }
  | { kind: "iota"; id: bigint | number | string };

export interface MTPRelayPlan {
  nextHop: MTPRelayTarget;
  finalRecipientId: bigint | number | string;
  metadataRecipients: MTPKeyMaterialInput[];
  contentRecipients: MTPKeyMaterialInput[];
  metadata?: MTPDataValueInput;
}

export interface MTPSendProtectedOptions extends MTPFrameIdOptions {
  receiverId: bigint | number | string;
  identity?: MTPProtectionIdentity;
  recipients: MTPKeyMaterialInput[];
  signaturePurpose: number;
  encryptionPurpose: number;
  signatureSuite?: MTPProtectionSignatureSuite;
  exposeSender?: boolean;
  /** Semantic protected-field limits applied before the WASM boundary. */
  limits?: MTPReceiveLimits;
}

export interface MTPSendSealedRelayOptions extends MTPRelayPlan {
  identity?: MTPProtectionIdentity;
  signatureSuite?: MTPProtectionSignatureSuite;
  /** Semantic protected/relay limits applied before the WASM boundary. */
  limits?: MTPReceiveLimits;
}

const RELAY_TARGET_ID_MASK = (1n << 48n) - 1n;
const RELAY_USER_TARGET_KIND = 0x4000_0000_0000_0000n;
const RELAY_IOTA_TARGET_KIND = 0x8000_0000_0000_0000n;

/*
 * The route target namespace is part of the relay wire value. Keeping this
 * conversion in the protocol SDK prevents application callers from encoding
 * u64 route values with JavaScript number operations.
 */
export function encodeMTPRelayTarget(target: MTPRelayTarget): bigint {
  const id = inputU64(target.id, "nextHop.id");
  if (id === 0n || id > RELAY_TARGET_ID_MASK) {
    throw new RangeError("nextHop.id must be a non-zero 48-bit integer");
  }

  return (
    (target.kind === "user"
      ? RELAY_USER_TARGET_KIND
      : RELAY_IOTA_TARGET_KIND) | id
  );
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
  /** Override the client's receive resource policy for this operation. */
  limits?: MTPReceiveLimits;
}

export interface MTPOpenRelayMetadataOptions extends MTPRelayVerificationOptions {
  /** Override the default process-local guard with an application-owned guard. */
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
  /** Override the client's receive resource policy for this operation. */
  limits?: MTPReceiveLimits;
}

/** Options for a protected-message subscription. */
export interface MTPProtectedSubscriptionOptions
  extends MTPOpenProtectedOptions, MTPSubscriptionOptions {}

export interface MTPVerifiedProtectedMessage<T = MTPDataValue> {
  type: string;

  /** Authenticated direct-message envelope schema version. */
  protectedVersion: number;

  signerId: bigint;

  /** Authenticated destination from the protected envelope. */
  finalRecipientId: bigint;

  /** Authenticated application message identifier. */
  messageId: bigint;

  /** Authenticated Unix epoch timestamp in milliseconds. */
  createdAt: bigint;

  receiver?: bigint;
  outerSender?: bigint;

  data: T;
}

export type MTPProtectedFrameInput = ParsedFrame | MTPBytesInput;

/** Options shared by the sealed-relay subscription APIs. */
export interface MTPEncryptedSubscriptionOptions
  extends MTPOpenRelayContentOptions, MTPSubscriptionOptions {
  /** Consume authenticated relay IDs while dispatching the subscription. */
  replayGuard?: MTPReplayGuard;
}

/** Options for a verified relay-metadata subscription. */
export interface MTPRelayMetadataSubscriptionOptions
  extends MTPOpenRelayMetadataOptions, MTPSubscriptionOptions {}

export type MTPProtectionSignatureSuite = "ed25519" | "dual";

export interface MTPReplayGuard {
  /**
   * Return true and atomically record the pair when it has not been seen.
   * `createdAt` is authenticated metadata for retention/observability; the
   * replay identity is only `(signerId, messageId)`.
   */
  accept(
    signerId: bigint,
    messageId: bigint,
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
export interface MTPVerifiedRelayContent {
  type: string;
  data: MTPDataValue;
  signerId: bigint;
  finalRecipientId: bigint;
  messageId: bigint;
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
  cancel(): Promise<void>;
}

export interface MTPCreateEncryptedPipeOptions {
  recipientId: bigint | number | string;
  recipientPublicKey?: MTPKeyMaterialInput;
  recipientPublicKeys?: MTPKeyMaterialInput[];
  description?: string;
  purpose?: number;
  direction?: number;
  signatureSuite?: MTPProtectionSignatureSuite;
}

export interface MTPAcceptEncryptedPipeOptions {
  senderId: bigint | number | string;
  senderPublicKey?: MTPKeyMaterialInput;
  senderPublicKeys?: MTPKeyMaterialInput[];
  purpose?: number;
  direction?: number;
  signaturePolicy?: MTPSignatureVerificationPolicy;
}

type NormalizedMTPClientOptions<Registry extends MTPSchemaRegistry> = Omit<
  MTPClientOptions<Registry>,
  "hostPublicKey" | "receiveLimits"
> & {
  hostPublicKey?: Uint8Array;
  receiveLimits?: MTPReceiveLimits;
  receiveLimitsExplicit: boolean;
  securityProfile: ResolvedSecurityProfile;
};

interface ResolvedSecurityProfile {
  protectedSignatureSuite: MTPProtectionSignatureSuite;
  protectedSignaturePolicy: MTPSignatureVerificationPolicy;
  encryptedPipeSignatureSuite: MTPProtectionSignatureSuite;
  encryptedPipeSignaturePolicy: MTPSignatureVerificationPolicy;
  requirePq: boolean;
}

const DEFAULT_CREDENTIALS_KEY = "mtp:credentials";
const DEFAULT_MAX_MESSAGE_SIZE = 16 * 1024 * 1024;
const DEFAULT_MAX_DEPTH = 64;
const DEFAULT_MAX_VALUES = 65_536;
const DEFAULT_MAX_RECIPIENTS = 64;
/** Must match codec::DEFAULT_TRANSPORT_ALLOCATION_FACTOR. */
export const DEFAULT_TRANSPORT_ALLOCATION_FACTOR = 4;

function createMessageId(): bigint {
  const bytes = new Uint8Array(16);
  globalThis.crypto.getRandomValues(bytes);
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  return value;
}

function createRequestId(): number {
  const value = new Uint32Array(1);
  globalThis.crypto.getRandomValues(value);
  return value[0] || 1;
}

function emit(
  logger: MTPClientOptions["logger"] | undefined,
  event: MTPLogEvent,
): void {
  if (typeof logger !== "function") return;
  try {
    logger(event);
  } catch {
    // Logging is diagnostic and must not affect protocol control flow.
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
  return bindings.keyring_generate_checked();
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

const RECEIVE_LIMIT_KEYS = [
  "maxDepth",
  "maxValues",
  "maxBlobSize",
  "maxRecipients",
  "maxAllocatedBytes",
  "maxOutputSize",
  "maxMetadataEncodedBytes",
  "maxSignerKeyHistory",
  "maxDecryptionKeyHistory",
] as const;

function normalizeReceiveLimits(
  value: MTPReceiveLimits | undefined,
  name: string,
): MTPReceiveLimits | undefined {
  if (value == null) return undefined;
  if (typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError(`${name} must be an object`);
  }
  const normalized: MTPReceiveLimits = {};
  for (const key of RECEIVE_LIMIT_KEYS) {
    const limit = value[key];
    if (limit == null) continue;
    if (!Number.isSafeInteger(limit) || limit < 0) {
      throw new TypeError(`${name}.${key} must be a non-negative safe integer`);
    }
    normalized[key] = limit;
  }
  return normalized;
}

function effectiveReceiveLimits(
  configured: MTPReceiveLimits | undefined,
  maxMessageSize: number,
): MTPReceiveLimits {
  const transportBlob = Math.min(
    Math.max(0, maxMessageSize - 4),
    0xffff_ffff,
  );
  const transportAllocated =
    maxMessageSize > Number.MAX_SAFE_INTEGER / DEFAULT_TRANSPORT_ALLOCATION_FACTOR
      ? Number.MAX_SAFE_INTEGER
      : maxMessageSize * DEFAULT_TRANSPORT_ALLOCATION_FACTOR;
  const intersect = (left: number | undefined, right: number): number =>
    Math.min(left ?? right, right);
  return {
    ...configured,
    maxDepth: intersect(configured?.maxDepth, DEFAULT_MAX_DEPTH),
    maxValues: intersect(configured?.maxValues, DEFAULT_MAX_VALUES),
    maxBlobSize: intersect(configured?.maxBlobSize, transportBlob),
    maxRecipients: intersect(configured?.maxRecipients, DEFAULT_MAX_RECIPIENTS),
    maxAllocatedBytes: intersect(
      configured?.maxAllocatedBytes,
      transportAllocated,
    ),
    maxOutputSize: intersect(configured?.maxOutputSize, maxMessageSize),
  };
}

function resolveSecurityProfile(options: MTPClientOptions): ResolvedSecurityProfile {
  const profile = options.securityProfile ?? {};
  const suite = (value: unknown, name: string): MTPProtectionSignatureSuite => {
    if (value == null) return "ed25519";
    if (value !== "ed25519" && value !== "dual") {
      throw new TypeError(`${name} must be 'ed25519' or 'dual'`);
    }
    return value;
  };
  const policy = (
    value: MTPSignatureVerificationPolicy | undefined,
    name: string,
  ): MTPSignatureVerificationPolicy => {
    try {
      return resolveSignatureVerificationPolicy(value, undefined);
    } catch (error) {
      throw new TypeError(`${name} is invalid`, { cause: error });
    }
  };
  if (profile.requirePq != null && typeof profile.requirePq !== "boolean") {
    throw new TypeError("securityProfile.requirePq must be a boolean");
  }
  return {
    protectedSignatureSuite: suite(
      profile.protectedSignatureSuite,
      "securityProfile.protectedSignatureSuite",
    ),
    protectedSignaturePolicy: policy(
      profile.protectedSignaturePolicy,
      "securityProfile.protectedSignaturePolicy",
    ),
    encryptedPipeSignatureSuite: suite(
      profile.encryptedPipeSignatureSuite,
      "securityProfile.encryptedPipeSignatureSuite",
    ),
    encryptedPipeSignaturePolicy: policy(
      profile.encryptedPipeSignaturePolicy,
      "securityProfile.encryptedPipeSignaturePolicy",
    ),
    requirePq: profile.requirePq ?? true,
  };
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
    keyring: bytesFrom(keyring, "credentials.keyring").slice(),
    hostPublicKey:
      normalized.hostPublicKey == null
        ? undefined
        : normalizeBytes(normalized.hostPublicKey, "credentials.hostPublicKey").slice(),
  };
}

function pipeWriter(raw: RawBindings.PipeWriter): MTPPipeWriter {
  return {
    pipeId: raw.pipe_id(),
    write: (data) => normalizeCommunicationError(raw.write(data)),
    close: () => normalizeCommunicationError(raw.close()),
    abort: () => {
      try {
        return raw.abort();
      } catch (error) {
        throw communicationError(error);
      }
    },
  };
}

function pipeReader(raw: RawBindings.PipeReader): MTPPipeReader {
  return {
    pipeId: raw.pipe_id(),
    description: raw.description(),
    read: async () =>
      (await normalizeCommunicationError(raw.read())) as Uint8Array | null,
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
  if (
    options.securityProfile != null &&
    (typeof options.securityProfile !== "object" ||
      Array.isArray(options.securityProfile))
  ) {
    throw new TypeError("securityProfile must be an object");
  }
  resolveSecurityProfile(options);
  normalizeReceiveLimits(options.receiveLimits, "receiveLimits");
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
  if (options.requirePq != null && typeof options.requirePq !== "boolean") {
    throw new TypeError("requirePq must be a boolean");
  }
  if (
    options.requestTimeoutMs != null &&
    (!Number.isSafeInteger(options.requestTimeoutMs) ||
      options.requestTimeoutMs <= 0)
  ) {
    throw new TypeError("requestTimeoutMs must be a positive safe integer");
  }
  if (options.schemas != null) {
    if (typeof options.schemas !== "object" || Array.isArray(options.schemas)) {
      throw new TypeError("schemas must be an object");
    }
    for (const [type, pair] of Object.entries(options.schemas)) {
      if (
        !pair ||
        typeof pair !== "object" ||
        typeof (pair as { request?: { parseAsync?: unknown } }).request
          ?.parseAsync !== "function" ||
        typeof (pair as { response?: { parseAsync?: unknown } }).response
          ?.parseAsync !== "function"
      ) {
        throw new TypeError(
          `schemas.${type} must contain request and response schemas with parseAsync()`,
        );
      }
    }
  }
}

export class MTPClient<Registry extends MTPSchemaRegistry = MTPNoSchemas> {
  #nextSealedRelayRequestId = createRequestId();
  static readonly crypto = crypto;
  static readonly codec = codec;

  #credentials: InternalCredentials | null;
  #options: NormalizedMTPClientOptions<Registry>;
  readonly #protocol: MTPProtocol<Registry> | undefined;
  readonly #protectedReplayGuard = new InMemoryReplayGuard();
  readonly #relayReplayGuard = new InMemoryReplayGuard();
  #sealedRelayContentSubscriptions = 0;
  readonly raw: MTPRaw;
  #native?: NativeTransport;
  #subscriptionDisposers = new Set<Unsubscribe>();

  readonly crypto = MTPClient.crypto;
  readonly codec = MTPClient.codec;

  readonly sessionManager: MTPSessionManager;
  /** Independent encrypted-secret storage selected by the caller. */
  readonly encryptedSecretProvider: MTPEncryptedSecretProvider;

  private constructor(
    options: NormalizedMTPClientOptions<Registry>,
    client: RawBindings.WasmClient,
  ) {
    this.#options = options;
    this.#protocol = options.schemas
      ? new MTPProtocol({
          schemas: options.schemas,
          throwProtocolErrors: options.throwProtocolErrors,
          onValidationError: options.onValidationError,
        })
      : undefined;
    this.#credentials = deserializeCredentials(options.credentials);
    this.raw = { client, bindings };
    this.encryptedSecretProvider =
      options.encryptedSecretProvider ?? new InMemoryEncryptedSecretProvider();
    this.sessionManager = new MTPSessionManager(
      options.sessionStorage ?? new InMemorySessionStorage(),
    );
  }

  static async create<
    const Registry extends MTPSchemaRegistry = MTPNoSchemas,
  >(
    options: MTPClientOptions<Registry>,
  ): Promise<MTPClient<Registry>> {
    validateOptions(options);
    await MTPClient.init(options.wasm);

    const normalizedOptions = {
      ...options,
      hostPublicKey:
        options.hostPublicKey == null
          ? undefined
          : normalizeBytes(options.hostPublicKey, "hostPublicKey").slice(),
      receiveLimits: effectiveReceiveLimits(
        normalizeReceiveLimits(options.receiveLimits, "receiveLimits"),
        options.maxMessageSize ?? DEFAULT_MAX_MESSAGE_SIZE,
      ),
      // Always retain and apply the effective transport policy. Even when the
      // caller did not provide overrides, protected/relay opening must not
      // fall back to a larger codec default after frame admission.
      receiveLimitsExplicit: true,
      securityProfile: resolveSecurityProfile(options),
    };

    const runtime = androidTauri();
    if (runtime) {
      if (options.nativeFresh != null && typeof options.nativeFresh !== "boolean") throw new TypeError("nativeFresh must be a boolean");
      if (options.nativeName != null && (typeof options.nativeName !== "string" || !options.nativeName.trim())) throw new TypeError("nativeName must be a non-empty string");
      if ((options.nativeFresh || options.credentials === null) && !normalizedOptions.hostPublicKey) throw new Error("fresh native clients require pinned hostPublicKey");
      const name = options.nativeFresh || options.credentials === null
        ? `mtp:temporary:${globalThis.crypto.randomUUID()}`
        : options.nativeName ?? options.credentialsStorageKey ?? DEFAULT_CREDENTIALS_KEY;
      let nativeSdk: MTPClient<Registry>;
      const native = new NativeTransport(runtime, name,
        (bytes) => decodeWithLimits(bytes, normalizedOptions.receiveLimits),
        (frame) => { if (nativeSdk) nativeSdk.#handleFrame(frame); },
        (error) => emit(normalizedOptions.logger, { hint: "error", type: "Native", error: String(error) }));
      await native.initialize(nativeOptions({
        url: options.url, descriptor: options.descriptor,
        hostPublicKey: normalizedOptions.hostPublicKey,
      credentials: options.credentials == null ? undefined : deserializeCredentials(options.credentials),
        fresh: options.nativeFresh || options.credentials === null,
        serverCertificateHashes: options.serverCertificateHashes,
        maxMessageSize: options.maxMessageSize ?? DEFAULT_MAX_MESSAGE_SIZE,
        authTimeoutMs: options.authTimeoutMs,
        requirePq: options.requirePq ?? normalizedOptions.securityProfile.requirePq,
        pings: options.pings ?? true,
        receiveLimits: normalizedOptions.receiveLimits,
      }) as Record<string, unknown>);
      nativeSdk = new MTPClient<Registry>({ ...normalizedOptions, credentials: null }, native as unknown as RawBindings.WasmClient);
      nativeSdk.#native = native;
      return nativeSdk;
    }

    let sdk: MTPClient<Registry> | undefined;
    const client = new WasmClient(
      (state) => {
        try {
          normalizedOptions.onStateChange?.(state);
        } catch {
          // Observers must not interrupt transport state changes.
        }
        emit(normalizedOptions.logger, {
          hint: "info",
          type: "state",
          data: ConnectionState[state] ?? state,
        });
      },
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

    client.set_receive_limits(normalizedOptions.receiveLimits);

    sdk = new MTPClient<Registry>(normalizedOptions, client);
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
    return !!androidTauri() || WasmClient.is_supported();
  }

  static async init(
    wasm?: MTPClientOptions["wasm"],
  ): Promise<Awaited<ReturnType<typeof initWasmOnce>>> {
    return await initWasmOnce(wasm);
  }

  get credentials(): MTPClientCredentials | null {
    if (this.#native) return null;
    return publicCredentials(this.#credentials);
  }

  /** Public identity information. Native secret keys never leave the plugin. */
  get nativeIdentity(): { name: string; clientId: bigint | null; publicKeys: Uint8Array } | null {
    return this.#native ? { name: this.#native.name, clientId: this.#native.clientId, publicKeys: this.#native.publicKeys.slice() } : null;
  }

  get defaultSignatureVerificationPolicy(): MTPSignatureVerificationPolicy {
    return resolveSignatureVerificationPolicy(
      undefined,
      this.#options.defaultSignatureVerificationPolicy ??
        this.#options.securityProfile.protectedSignaturePolicy,
    );
  }

  get state(): RawBindings.ConnectionState {
    return this.raw.client.state;
  }

  get pingMs(): number | null {
    return this.raw.client.ping_ms ?? null;
  }

  /** The dictionary accepted on this connection, not just its version label. */
  get dictionaryIdentity(): { version: string; fingerprint: string } | null {
    const version = this.raw.client.dictionary_version;
    const fingerprint = this.raw.client.dictionary_fingerprint;
    return version && fingerprint ? { version, fingerprint } : null;
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
    config.require_pq =
      this.#options.requirePq ?? this.#options.securityProfile.requirePq;
    if (this.#options.descriptor != null) {
      config.description = this.#options.descriptor;
    }
    return config;
  }

  async connect(): Promise<void> {
    if (this.#native) { await this.#native.connect("connect"); return; }
    if (this.#credentials?.clientId != null && this.#options.hostPublicKey) {
      await this.auth();
      return;
    }

    await this.connectUnauthenticated();
  }

  async connectUnauthenticated(): Promise<void> {
    if (this.#native) { await this.#native.connect("unauthenticated"); return; }
    const config = this.#connectionConfig();
    try {
      // The deprecated raw method clones its borrowed config synchronously and
      // remains safe when the SDK timeout wins the race. Keep using it here so
      // applications that instrument the historical raw API continue to work.
      await withTimeout(
        normalizeCommunicationError(this.raw.client.connect(config)),
        this.#options.authTimeoutMs,
        "connection timed out",
        () => this.raw.client.disconnect(),
      );
      const clientId = this.raw.client.client_id;
      this.#startPings(clientId);
    } finally {
      config.free();
    }
  }

  async auth(): Promise<bigint> {
    if (this.#native) return this.#native.connect("auth");
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
      // Keep the deprecated raw spelling as the compatibility path. The WASM
      // wrapper takes owned copies before entering its asynchronous handshake.
      const clientId = await withTimeout(
        normalizeCommunicationError(this.raw.client.auth_connect(
          config,
          this.#options.hostPublicKey,
          this.#credentials.keyring,
          this.#credentials.clientId,
        )),
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
    if (this.#native) return this.#native.connect("register");
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
        normalizeCommunicationError(this.raw.client.auth_register(
          config,
          this.#options.hostPublicKey,
          this.#credentials.keyring,
        )),
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
    if (this.#native) {
      await this.#native.call("clear_credentials");
      this.#native.clientId = null;
      this.#native.publicKeys = new Uint8Array();
      return;
    }
    zeroCredentials(this.#credentials);
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

  #encodeLimits(): MTPEncodeLimits {
    return {
      maxDepth: DEFAULT_MAX_DEPTH,
      maxValues: DEFAULT_MAX_VALUES,
      maxOutputSize:
        this.#options.maxMessageSize ?? DEFAULT_MAX_MESSAGE_SIZE,
    };
  }

  async #parseRequestData(
    type: MTPCommunicationType,
    data: unknown,
  ): Promise<Record<string, unknown>> {
    if (!this.#protocol || !this.#protocol.schemas[type]) {
      return (data ?? {}) as Record<string, unknown>;
    }
    const parsed = await this.#protocol.parseRequest(
      type as MTPMessageType<Registry>,
      data as never,
    );
    return (parsed ?? {}) as Record<string, unknown>;
  }

  async #parseResponseData(
    requestedType: MTPCommunicationType,
    frame: ParsedFrame,
    phase: "response" | "subscription" = "response",
  ): Promise<MTPFrame<unknown>> {
    if (!this.#protocol || !this.#protocol.schemas[requestedType]) {
      return frame;
    }
    return await this.#protocol.parseResponse(
      requestedType as MTPMessageType<Registry>,
      frame,
      phase,
    );
  }

  #buildFrame(typeOrFrame, data, options) {
    if (typeOrFrame instanceof Uint8Array) {
      if (
        typeOrFrame.length >
        (this.#options.maxMessageSize ?? DEFAULT_MAX_MESSAGE_SIZE)
      ) {
        throw new RangeError("MTP frame exceeds maxMessageSize");
      }
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
    const limits = this.#encodeLimits();
    validateMTPDataValue(data as MTPDataValueInput, limits);
    const frame = this.raw.bindings.build_frame_with_limits(
      typeOrFrame,
      data,
      options ?? {},
      limits,
    );
    if (frame.length > (limits.maxOutputSize ?? DEFAULT_MAX_MESSAGE_SIZE)) {
      throw new RangeError("MTP frame exceeds maxMessageSize");
    }
    return frame;
  }

  async send(message: Uint8Array): Promise<void>;
  async send<Type extends MTPMessageType<Registry>>(
    type: Type,
    data?: MTPRequestData<Registry, Type>,
    options?: MTPSendOptions,
  ): Promise<void>;
  async send(
    type: MTPCommunicationType,
    data: Record<string, unknown>,
    options?: MTPSendOptions,
  ): Promise<void>;
  async send(
    typeOrFrame: Uint8Array | MTPCommunicationType,
    data?: unknown,
    options?: MTPSendOptions,
  ): Promise<void> {
    const parsedData =
      typeof typeOrFrame === "string"
        ? await this.#parseRequestData(typeOrFrame, data)
        : data;
    const message = this.#buildFrame(typeOrFrame, parsedData, options);

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

    await normalizeCommunicationError(this.raw.client.send(message));
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
  async request<Type extends MTPMessageType<Registry>>(
    type: Type,
    data?: MTPRequestData<Registry, Type>,
    options?: MTPRequestOptions,
  ): Promise<MTPResponseFrame<Registry, Type>>;
  async request(
    type: MTPCommunicationType,
    data: Record<string, unknown>,
    options?: MTPRequestOptions,
  ): Promise<ParsedFrame>;
  async request(
    typeOrFrame: Uint8Array | MTPCommunicationType,
    data?: unknown,
    options: MTPRequestOptions = {},
  ): Promise<ParsedFrame | MTPFrame<unknown>> {
    const timeoutMs =
      options.timeoutMs ?? this.#options.requestTimeoutMs ?? 30_000;
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0) {
      throw new TypeError("request timeoutMs must be a positive safe integer");
    }
    const parsedData =
      typeof typeOrFrame === "string"
        ? await this.#parseRequestData(typeOrFrame, data)
        : data;
    const frame = this.#buildFrame(typeOrFrame, parsedData, options);
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
    let response: ParsedFrame;
    try {
      response = await this.raw.client.request(
        frame,
        options.responseType ?? null,
        timeoutMs,
      );
    } catch (error) {
      throw communicationError(error);
    }
    return typeof typeOrFrame === "string"
      ? await this.#parseResponseData(typeOrFrame, response)
      : response;
  }

  /**
   * Subscribe raw frames through the common bounded dispatcher used by every
   * capability-specific asynchronous subscription.
   */
  #subscribeBounded(
    type: MTPCommunicationType,
    handler: (frame: ParsedFrame) => void | Promise<void>,
    options: MTPSubscriptionOptions,
    errorType = "Subscription",
    onClose?: () => void,
  ): Unsubscribe {
    let closed = false;
    let id: number | undefined;
    const close = () => {
      if (closed) return;
      closed = true;
      dispatcher.close();
      this.#subscriptionDisposers.delete(close);
      if (id !== undefined) this.raw.client.unsubscribe(id);
      onClose?.();
    };
    const reportError = (error: unknown, frame: ParsedFrame) => {
      if (typeof options.onError === "function") {
        try {
          options.onError(error, frame);
        } catch {
          // Application error observers must not affect dispatch.
        }
        return;
      }
      emit(this.#options.logger, {
        hint: "error",
        type: frame.type,
        error: `${errorType}: ${String(error)}`,
        direction: "recv",
      });
    };
    const dispatcher = new SubscriptionDispatcher<ParsedFrame>({
      handler,
      concurrency: options.concurrency,
      queueCapacity: options.queueCapacity,
      reportError,
      onOverflow: close,
    });
    id = this.raw.client.subscribe(type, (frame) => dispatcher.enqueue(frame, frame));
    this.#subscriptionDisposers.add(close);
    return close;
  }

  subscribe<Type extends MTPMessageType<Registry>>(
    type: Type,
    handler: (
      message: MTPResponseFrame<Registry, Type>,
    ) => void | Promise<void>,
    options?: import("./subscription.js").MTPSubscriptionOptions,
  ): Unsubscribe;
  subscribe(
    type: MTPCommunicationType,
    handler: (message: ParsedFrame) => void | Promise<void>,
    options?: import("./subscription.js").MTPSubscriptionOptions,
  ): Unsubscribe;
  subscribe(
    type: MTPCommunicationType,
    handler: (message: any) => void | Promise<void>,
    options: import("./subscription.js").MTPSubscriptionOptions = {},
  ): Unsubscribe {
    if (typeof type !== "string" || !type) {
      throw new TypeError("subscription type must be a non-empty string");
    }
    if (typeof handler !== "function") {
      throw new TypeError("subscription handler must be a function");
    }
    let closed = false;
    let id: number | undefined;
    const close = () => {
      if (closed) return;
      closed = true;
      dispatcher.close();
      this.#subscriptionDisposers.delete(close);
      if (id !== undefined) this.raw.client.unsubscribe(id);
    };
    const reportError = (error: unknown, frame: ParsedFrame) => {
      if (typeof options.onError === "function") {
        try {
          options.onError(error, frame);
        } catch {
          // Application error observers must not affect dispatch.
        }
        return;
      }
      emit(this.#options.logger, {
        hint: "error",
        type: frame.type,
        error: String(error),
        data: frame.data,
        direction: "recv",
      });
    };
    const dispatcher = new SubscriptionDispatcher<ParsedFrame>({
      handler: async (message) => {
        if (!this.#protocol || !this.#protocol.schemas[type]) {
          await handler(message);
          return;
        }
        let parsed: MTPFrame<unknown>;
        try {
          parsed = await this.#parseResponseData(type, message, "subscription");
        } catch (error) {
          this.#protocol.reportValidationError(error);
          return;
        }
        await handler(parsed as ParsedFrame);
      },
      concurrency: options.concurrency,
      queueCapacity: options.queueCapacity,
      reportError,
      onOverflow: close,
    });
    id = this.raw.client.subscribe(type, (message) => dispatcher.enqueue(message, message));
    this.#subscriptionDisposers.add(close);
    return close;
  }

  #handleFrame(frame) {
    // Content relay subscriptions log the normalized inner message after
    // authenticated opening. Avoid logging the encrypted outer frame as an
    // application message as well while one is active.
    if (frame.type === "Relay" && this.#sealedRelayContentSubscriptions > 0) {
      return;
    }
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
        return bundle.try_to_bytes();
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
    if (this.#native?.clientId === signerId) return [this.#native.publicKeys.slice()];
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
    if (this.#native) return this.#openNativeRelayMetadata(frame, options);
    // The resolver is asynchronous. Keep an immutable byte snapshot so the
    // signer claim and the later native verification refer to one frame.
    const signaturePolicy = resolveSignatureVerificationPolicy(
      options.signaturePolicy,
      this.#options.defaultSignatureVerificationPolicy ??
        this.#options.securityProfile.protectedSignaturePolicy,
    );
    const requestedReceiveLimits = normalizeReceiveLimits(
      options.limits,
      "limits",
    );
    const receiveLimits = requestedReceiveLimits
      ? effectiveReceiveLimits(
          requestedReceiveLimits,
          this.#options.maxMessageSize ?? DEFAULT_MAX_MESSAGE_SIZE,
        )
      : this.#options.receiveLimits;
    const receiveLimitsExplicit =
      options.limits != null || this.#options.receiveLimitsExplicit;
    const frameBytes = frame.raw.slice();
    const frameSnapshot = receiveLimitsExplicit && receiveLimits
      ? decodeWithLimits(frameBytes, receiveLimits)
      : bindings.parse_frame(frameBytes);
    const recipient = this.#resolveDecryptionIdentity(options.recipient);
    let signerId: bigint;
    try {
      signerId = BigInt(
        bindings.relay_metadata_claimed_signer_id_with_limits(
          frameBytes,
          recipient.keyrings,
          receiveLimits ?? {},
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
      native = bindings.open_relay_metadata_with_keyrings_with_limits_without_replay(
        frameBytes,
        recipient.keyrings,
        signerId,
        signerBundles,
        signatureVerificationPolicyValue(signaturePolicy),
        receiveLimits ?? {},
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
            receiveLimits
              ? decodeDataValueWithLimits(metadataBytes, receiveLimits)
              : bindings.parse_data_value(metadataBytes),
          ) as MTPDataValue)
        : undefined;
      const nativeSignerId = BigInt(native.signer_id());
      const messageId = native.message_id();
      const createdAt = BigInt(native.created_at());
      const replayGuard = options.replayGuard ?? this.#relayReplayGuard;
      const accepted = await replayGuard.accept(
        nativeSignerId,
        messageId,
        createdAt,
      );
      if (!accepted) throw new MTPReplayError(nativeSignerId, messageId);

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
        receiveLimits: receiveLimits ? { ...receiveLimits } : undefined,
        receiveLimitsExplicit,
        disposed: false,
        finalizerToken: {},
      });
      // Register only after the JS wrapper owns the native handle. The
      // finally block below handles every failure before this transfer.
      const state = relayMetadataState.get(verified);
      if (!state) throw new Error("relay metadata state was not initialized");
      registerRelayMetadata(verified, native, state.finalizerToken);
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
    if (this.#native) {
      const state = relayMetadataState.get(metadata);
      if (!state || state.disposed) throw new Error("relay metadata has been disposed or is unauthenticated");
      this.#assertExpectedSignerId(state.signerId, options.expectedSignerId);
      const policy = resolveSignatureVerificationPolicy(options.signaturePolicy, state.signaturePolicy);
      if (policy !== state.signaturePolicy) throw new MTPSignatureVerificationError("policy-rejected", state.signerId);
      const keys = options.resolveSignerPublicKeys ? await this.#resolveSignerPublicKeys(state.signerId, options) : state.signerPublicKeys;
      if (state.disposed) throw new Error("relay metadata has been disposed");
      const limits = options.limits ? this.#nativeLimits(options.limits) : state.receiveLimits ?? {};
      try {
      const result = await this.#native.call<any>("open_relay_content", {
        handle: (state.native as any).nativeHandle,
        options: nativeOptions({ ...this.#nativeProtectionOptions(options), signerPublicKeys: keys, signaturePolicy: policy,
          expectedFinalRecipientId: options.expectedFinalRecipientId ?? options.recipient?.id ?? this.#native.clientId,
          limits }),
      });
      return { type: result.type, data: decodeDataValueWithLimits(Uint8Array.from(result.content), limits), signerId: BigInt(result.signerId), finalRecipientId: BigInt(result.finalRecipientId), messageId: state.messageId, createdAt: state.createdAt, metadata: state.metadata };
      } catch (error) {
        metadata.dispose();
        throw error;
      }
    }
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
    const requestedReceiveLimits = normalizeReceiveLimits(
      options.limits,
      "limits",
    );
    const receiveLimits = requestedReceiveLimits
      ? effectiveReceiveLimits(
          requestedReceiveLimits,
          this.#options.maxMessageSize ?? DEFAULT_MAX_MESSAGE_SIZE,
        )
      : state.receiveLimits;
    const receiveLimitsExplicit =
      options.limits != null || state.receiveLimitsExplicit;
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
      const nativeExpectedFinalRecipientId =
        expectedFinalRecipientId == null
          ? null
          : BigInt(expectedFinalRecipientId);
      nativeContent = bindings.open_relay_content_with_keyrings_with_limits_without_replay(
        state.native,
        recipient.keyrings,
        signerBundles,
        nativeExpectedFinalRecipientId,
        signatureVerificationPolicyValue(signaturePolicy),
        receiveLimits ?? {},
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
    const contentBytes = nativeContent.content();
    const data = state.receiveLimitsExplicit && state.receiveLimits
      ? decodeDataValueWithLimits(contentBytes, state.receiveLimits)
      : (bindings.parse_data_value(contentBytes) as MTPDataValue);

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
    if (this.#native) {
      if (typeof options?.resolveSignerPublicKeys !== "function") throw new TypeError("openProtected requires resolveSignerPublicKeys");
      validateApplicationProtectionPurpose(options.signaturePurpose);
      validateApplicationProtectionPurpose(options.encryptionPurpose);
      const limits = this.#nativeLimits(options.limits);
      const frame = cloneParsedFrame(parseProtectedFrame(frameInput, limits));
      assertKnownCommunicationType(frame);
      const bytes = protectedFrameBytes(frame, limits);
      const args = { bytes: Array.from(bytes), options: nativeOptions({ ...this.#nativeProtectionOptions(options), limits }) };
      const signerId = BigInt(await this.#native.call<string>("protected_claimed_signer", args));
      this.#assertExpectedSignerId(signerId, options.expectedSignerId);
      const keys = await this.#resolveSignerPublicKeys(signerId, options);
      const result = await this.#native.call<any>("open_protected", { ...args, options: nativeOptions({ ...this.#nativeProtectionOptions(options), limits, signerId, signerPublicKeys: keys,
        expectedReceiverId: options.expectedReceiverId ?? options.recipient?.id ?? this.#native.clientId,
        signaturePolicy: resolveSignatureVerificationPolicy(options.signaturePolicy, this.defaultSignatureVerificationPolicy) }) });
      const message = { type: result.type, protectedVersion: Number(result.protectedVersion), signerId: BigInt(result.signerId), finalRecipientId: BigInt(result.finalRecipientId), messageId: BigInt(result.messageId), createdAt: BigInt(result.createdAt), receiver: frame.receiver, outerSender: frame.sender, data: decodeDataValueWithLimits(Uint8Array.from(result.content), limits) };
      if (!await (options.replayGuard ?? this.#protectedReplayGuard).accept(message.signerId, message.messageId, message.createdAt)) throw new MTPReplayError(message.signerId, message.messageId);
      return { frame, message };
    }
    if (!options || typeof options !== "object") {
      throw new TypeError("openProtected requires an options object");
    }
    if (typeof options.resolveSignerPublicKeys !== "function") {
      throw new TypeError("openProtected requires resolveSignerPublicKeys");
    }

    // Detach parsed-object inputs before awaiting signer-key resolution. This
    // keeps the authenticated payload and routing fields bound to one
    // snapshot even when a caller reuses or mutates its frame object.
    const requestedReceiveLimits = normalizeReceiveLimits(
      options.limits,
      "limits",
    );
    const receiveLimits = requestedReceiveLimits
      ? effectiveReceiveLimits(
          requestedReceiveLimits,
          this.#options.maxMessageSize ?? DEFAULT_MAX_MESSAGE_SIZE,
        )
      : this.#options.receiveLimits;
    const receiveLimitsExplicit =
      options.limits != null || this.#options.receiveLimitsExplicit;
    const frame = cloneParsedFrame(
      parseProtectedFrame(
        frameInput,
        receiveLimitsExplicit ? receiveLimits : undefined,
      ),
    );
    assertKnownCommunicationType(frame);
    const frameBytes = protectedFrameBytes(frame, receiveLimits);
    validateApplicationProtectionPurpose(options.signaturePurpose);
    validateApplicationProtectionPurpose(options.encryptionPurpose);

    const recipient = this.#resolveDecryptionIdentity(options.recipient);
    const signaturePolicy = resolveSignatureVerificationPolicy(
      options.signaturePolicy,
      this.#options.defaultSignatureVerificationPolicy ??
        this.#options.securityProfile.protectedSignaturePolicy,
    );
    const expectedReceiverId =
      options.expectedReceiverId == null
        ? recipient.id
        : inputU64(options.expectedReceiverId, "expectedReceiverId");
    let signerId: bigint;
    try {
      signerId = BigInt(
        bindings.protected_claimed_signer_id_with_limits(
          frameBytes,
          recipient.keyrings,
          options.encryptionPurpose,
          receiveLimits ?? {},
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
      const nativeExpectedReceiverId =
        expectedReceiverId == null ? null : expectedReceiverId;
      native = bindings.open_protected_with_keyrings_with_limits_without_replay(
        frameBytes,
        recipient.keyrings,
        signerId,
        signerBundles,
        nativeExpectedReceiverId,
        options.signaturePurpose,
        options.encryptionPurpose,
        signatureVerificationPolicyValue(signaturePolicy),
        receiveLimits ?? {},
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

      const contentBytes = native.content();
      const data = receiveLimitsExplicit && receiveLimits
        ? decodeDataValueWithLimits(contentBytes, receiveLimits)
        : (bindings.parse_data_value(contentBytes) as MTPDataValue);
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
    options: MTPProtectedSubscriptionOptions,
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

    return this.#subscribeBounded(
      applicationType,
      async (frame: ParsedFrame) => {
        const opened = await this.#openProtectedFrame(
          frame,
          subscriptionOptions,
        );
        if (opened.message.type !== applicationType) return;
        await handler(
          opened.message as MTPVerifiedProtectedMessage<T>,
          opened.frame,
        );
      },
      subscriptionOptions,
      "E2EE",
    );
  }

  async sendProtected(
    type: MTPCommunicationType,
    data: MTPDataValueInput,
    options: MTPSendProtectedOptions,
  ): Promise<void> {
    await this.send(await this.#buildProtected(type, data, options));
  }

  /** Return the correlated ciphertext frame, ready for openProtected. */
  async requestProtected(
    type: MTPCommunicationType,
    data: MTPDataValueInput,
    options: MTPSendProtectedOptions,
    requestOptions?: MTPRequestOptions,
  ): Promise<ParsedFrame> {
    const frame = await this.#buildProtected(type, data, { ...options, id: options.id ?? this.#nextSealedRelayRequestId++ });
    return this.request(frame, undefined, requestOptions);
  }

  /** Subscribe to ciphertext frames without application plaintext schemas. */
  subscribeRaw(type: MTPCommunicationType, handler: (frame: ParsedFrame) => void | Promise<void>, options: MTPSubscriptionOptions = {}): Unsubscribe {
    return this.#subscribeBounded(type, handler, options);
  }

  async #buildProtected(
    type: MTPCommunicationType,
    data: MTPDataValueInput,
    options: MTPSendProtectedOptions,
  ): Promise<Uint8Array> {
    if (this.#native) {
      const messageType = assertApplicationCommunicationType(type);
      validateApplicationProtectionPurpose(options.signaturePurpose);
      validateApplicationProtectionPurpose(options.encryptionPurpose);
      const recipients = normalizeRecipientBundles(options.recipients, "recipients");
      const bytes = await this.#native.call<number[]>("build_protected", { type: messageType,
        content: Array.from(encodeMTPDataValue(data, this.#encodeLimits())),
        options: nativeOptions({ ...this.#nativeProtectionOptions(options), receiverId: inputU64(options.receiverId, "receiverId"), recipients,
          signatureSuite: options.signatureSuite ?? this.#options.securityProfile.protectedSignatureSuite,
          messageId: createMessageId(), createdAt: unixTimeMillis(), limits: { ...this.#encodeLimits(), ...normalizeReceiveLimits(options.limits, "limits") } }) });
      return Uint8Array.from(bytes);
    }
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
      options.signatureSuite ??
        this.#options.securityProfile.protectedSignatureSuite,
    );
    const encodeLimits = this.#encodeLimits();
    const protectedLimits = normalizeReceiveLimits(options.limits, "options.limits");
    const encodedContent = encodeMTPDataValue(data, encodeLimits);
    const builderLimits = { ...encodeLimits, ...protectedLimits };
    let frame: Uint8Array;
    try {
      frame = bindings.build_protected_frame_with_keyring_with_limits(
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
        builderLimits,
      );
    } catch (error) {
      throw protectedOpeningError(error, identity.signerId);
    }
    return frame;
  }

  async sendSealedRelay(
    type: MTPCommunicationType,
    data: MTPDataValueInput,
    options: MTPSendSealedRelayOptions,
  ): Promise<void> {
    await this.send(this.#native ? await this.#buildNativeRelay(type, data, options) : this.#buildSealedRelayFrame(type, data, options));
  }

  /** Send a sealed relay and await the response from its next hop. */
  async requestSealedRelay(
    type: MTPCommunicationType,
    data: MTPDataValueInput,
    options: MTPSendSealedRelayOptions,
    requestOptions?: MTPRequestOptions,
  ): Promise<ParsedFrame> {
    return this.request(
      this.#addSealedRelayRequestId(
        this.#native ? await this.#buildNativeRelay(type, data, options) : this.#buildSealedRelayFrame(type, data, options),
      ),
      undefined,
      requestOptions,
    );
  }

  #addSealedRelayRequestId(frame: Uint8Array): Uint8Array {
    const parsed = this.raw.bindings.parse_frame(frame);
    const data = parsed.data as { encoded?: unknown };
    if (!(data.encoded instanceof Uint8Array)) {
      throw new Error("sealed relay frame payload is not encrypted");
    }
    const id = this.#nextSealedRelayRequestId;
    this.#nextSealedRelayRequestId =
      id === 0xffff_ffff ? 1 : id + 1;
    return this.raw.bindings.build_frame_with_payload_with_limits(
      "Relay",
      data.encoded,
      {
        id,
        ...(parsed.receiver == null ? {} : { receiver: parsed.receiver }),
      },
      this.#encodeLimits(),
    );
  }

  #buildSealedRelayFrame(
    type: MTPCommunicationType,
    data: MTPDataValueInput,
    options: MTPSendSealedRelayOptions,
  ): Uint8Array {
    const messageType = assertApplicationCommunicationType(type);
    const identity = resolveProtectionIdentity(
      options.identity,
      this.#credentials,
    );
    const finalRecipientId = inputU64(
      options.finalRecipientId,
      "finalRecipientId",
    );
    const nextHopId = encodeMTPRelayTarget(options.nextHop);
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
      options.signatureSuite ??
        this.#options.securityProfile.protectedSignatureSuite,
    );
    const encodeLimits = this.#encodeLimits();
    const protectedLimits = normalizeReceiveLimits(options.limits, "options.limits");
    validateMTPDataValue(data, encodeLimits);
    const encodedMetadata =
      options.metadata === undefined
        ? undefined
        : encodeMTPDataValue(options.metadata, encodeLimits);
    if (
      encodedMetadata &&
      protectedLimits?.maxMetadataEncodedBytes != null &&
      encodedMetadata.length > protectedLimits.maxMetadataEncodedBytes
    ) {
      throw new RangeError("relay metadata exceeds maxMetadataEncodedBytes");
    }
    const builderLimits = { ...encodeLimits, ...protectedLimits };
    const messageId = createMessageId();
    const createdAt = unixTimeMillis();
    const frame = bindings.build_encrypted_relay_frame_with_keyring_with_limits(
      messageType,
      data,
      identity.signerId,
      finalRecipientId,
      nextHopId,
      messageId,
      createdAt,
      encodedMetadata,
      identity.keyring,
      protectionSignatureSuiteValue(signatureSuite),
      metadataRecipients,
      contentRecipients,
      builderLimits,
    );
    return frame;
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
    let active = true;
    this.#sealedRelayContentSubscriptions += 1;
    let unsubscribe: Unsubscribe;
    try {
      unsubscribe = this.#subscribeBounded(
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
            emit(this.#options.logger, {
              hint: "info",
              type: opened.type,
              data: opened.data,
              direction: "recv",
              relay: {
                signerId: opened.signerId,
                finalRecipientId: opened.finalRecipientId,
                messageId: opened.messageId,
                createdAt: opened.createdAt,
              },
            });
            const parsedFrame: ParsedFrame = {
              ...frame,
              type: opened.type,
              data: opened.data as ParsedFrame["data"],
            };
            await handler(opened, parsedFrame);
          } finally {
            metadata?.dispose();
          }
        },
        subscriptionOptions,
        "E2EE",
        () => {
          if (!active) return;
          active = false;
          this.#sealedRelayContentSubscriptions -= 1;
        },
      );
    } catch (error) {
      this.#sealedRelayContentSubscriptions -= 1;
      throw error;
    }
    return unsubscribe;
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
    options: MTPRelayMetadataSubscriptionOptions = {},
  ): Unsubscribe {
    if (typeof handler !== "function") {
      throw new TypeError("relay metadata handler must be a function");
    }
    const replayGuard = options.replayGuard ?? new InMemoryReplayGuard();
    const subscriptionOptions = { ...options, replayGuard };
    return this.#subscribeBounded(
      "Relay",
      async (frame: ParsedFrame) => {
        let metadata: MTPVerifiedRelayMetadata | undefined;
        try {
          metadata = await this.openRelayMetadata(frame, subscriptionOptions);
          await handler(metadata, frame);
        } finally {
          metadata?.dispose();
        }
      },
      subscriptionOptions,
      "E2EE",
    );
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

  #pipeContext() {
    return {
      raw: this.raw.client,
      credentials: this.#credentials,
      encryptedPipeSignatureSuite:
        this.#options.securityProfile.encryptedPipeSignatureSuite,
      encryptedPipeSignaturePolicy:
        this.#options.securityProfile.encryptedPipeSignaturePolicy,
      defaultSignatureVerificationPolicy:
        this.#options.defaultSignatureVerificationPolicy,
      report: (event: MTPLogEvent) => emit(this.#options.logger, event),
      normalizeError: normalizeCommunicationError,
    };
  }

  #nativeLimits(limits?: MTPReceiveLimits): MTPReceiveLimits {
    return limits ? effectiveReceiveLimits(normalizeReceiveLimits(limits, "limits"), this.#options.maxMessageSize ?? DEFAULT_MAX_MESSAGE_SIZE) : this.#options.receiveLimits ?? {};
  }

  #nativeProtectionOptions(options: { identity?: MTPProtectionIdentity; recipient?: MTPDecryptionIdentity }): Record<string, unknown> {
    return {
      ...options,
      ...(options.identity ? { identity: {
        signerId: inputU64(options.identity.signerId, "identity.signerId"),
        keyring: normalizeBytes(options.identity.keyring, "identity.keyring"),
      } } : {}),
      ...(options.recipient ? { recipient: {
        id: options.recipient.id == null ? undefined : inputU64(options.recipient.id, "recipient.id"),
        keyring: normalizeBytes(options.recipient.keyring, "recipient.keyring"),
        keyringHistory: options.recipient.keyringHistory?.map((key, index) => normalizeBytes(key, `recipient.keyringHistory[${index}]`)),
      } } : {}),
    };
  }

  async #buildNativeRelay(type: MTPCommunicationType, data: MTPDataValueInput, options: MTPSendSealedRelayOptions): Promise<Uint8Array> {
    const bytes = await this.#native!.call<number[]>("build_relay", {
      type: assertApplicationCommunicationType(type), content: Array.from(encodeMTPDataValue(data, this.#encodeLimits())),
      metadata: options.metadata === undefined ? null : Array.from(encodeMTPDataValue(options.metadata, this.#encodeLimits())),
      options: nativeOptions({ ...this.#nativeProtectionOptions(options), metadata: undefined, nextHopId: encodeMTPRelayTarget(options.nextHop),
        finalRecipientId: inputU64(options.finalRecipientId, "finalRecipientId"),
        metadataRecipients: normalizeRecipientBundles(options.metadataRecipients, "metadataRecipients"),
        contentRecipients: normalizeRecipientBundles(options.contentRecipients, "contentRecipients"),
        signatureSuite: options.signatureSuite ?? this.#options.securityProfile.protectedSignatureSuite,
        messageId: createMessageId(), createdAt: unixTimeMillis(), limits: { ...this.#encodeLimits(), ...normalizeReceiveLimits(options.limits, "limits") } }),
    });
    return Uint8Array.from(bytes);
  }

  async #openNativeRelayMetadata(frame: ParsedFrame, options: MTPOpenRelayMetadataOptions): Promise<MTPVerifiedRelayMetadata> {
    const transport = this.#native!;
    const limits = this.#nativeLimits(options.limits);
    const bytes = frame.raw.slice();
    const snapshot = decodeWithLimits(bytes, limits);
    const args = { bytes: Array.from(bytes), options: nativeOptions({ ...this.#nativeProtectionOptions(options), limits }) };
    const signerId = BigInt(await transport.call<string>("relay_claimed_signer", args));
    this.#assertExpectedSignerId(signerId, options.expectedSignerId);
    const keys = await this.#resolveSignerPublicKeys(signerId, options);
    if (!keys) throw signerKeysUnavailable(signerId);
    const signaturePolicy = resolveSignatureVerificationPolicy(options.signaturePolicy, this.defaultSignatureVerificationPolicy);
    const result = await transport.call<any>("open_relay_metadata", { ...args, options: nativeOptions({ ...this.#nativeProtectionOptions(options), limits, signerId, signerPublicKeys: keys, signaturePolicy }) });
    const native = { nativeHandle: result.handle, free: () => { void transport.call("release_relay", { handle: result.handle }).catch(() => {}); } } as unknown as RawBindings.WasmVerifiedRelayMetadata;
    let transferred = false;
    try {
      const messageId = BigInt(result.messageId), createdAt = BigInt(result.createdAt);
      if (!await (options.replayGuard ?? this.#relayReplayGuard).accept(BigInt(result.signerId), messageId, createdAt)) throw new MTPReplayError(signerId, messageId);
      if (!Number.isSafeInteger(result.matchedSignerKeyIndex) || result.matchedSignerKeyIndex < 0 || result.matchedSignerKeyIndex >= keys.length) throw new Error("invalid matched signer key index");
      const token = {};
      const metadata = new MTPVerifiedRelayMetadata(RELAY_METADATA_TOKEN, {
        frame: snapshot, native, relayVersion: Number(result.relayVersion), signerId: BigInt(result.signerId), finalRecipientId: BigInt(result.finalRecipientId), messageId, createdAt,
        hasMetadata: result.metadata != null, metadata: result.metadata == null ? undefined : decodeDataValueWithLimits(Uint8Array.from(result.metadata), limits),
        encryptedContent: Uint8Array.from(result.encryptedContent), signerPublicKeys: keys.map(key => key.slice()), matchedSignerKeyIndex: result.matchedSignerKeyIndex,
        signaturePolicy, receiveLimits: limits, receiveLimitsExplicit: true, disposed: false, finalizerToken: token,
      });
      registerRelayMetadata(metadata, native, token);
      transferred = true;
      return metadata;
    } finally { if (!transferred) native.free(); }
  }

  async #nativePipe(command: string, args: Record<string, unknown>): Promise<any> {
    const transport = this.#native!;
    const result = await transport.call<any>(command, nativeOptions(args) as Record<string, unknown>);
    if (result == null) return null;
    const handle = result.handle;
    let sequence = 0n;
    return {
      pipeId: result.pipeId, description: result.description,
      context: result.context == null ? undefined : new MTPPipeProtectionContext(Uint8Array.from(result.context.sessionId), result.context.purpose, result.context.direction, Uint8Array.from(result.context.transcriptHash)),
      get sequenceNumber() { return sequence; },
      writeRecord: async (data: Uint8Array) => {
        if (!(data instanceof Uint8Array)) throw new TypeError("pipe record must be a Uint8Array");
        await transport.call("pipe_write_record", { handle, bytes: Array.from(data) });
        sequence += 1n;
      },
      readRecord: async () => {
        const bytes = await transport.call<number[] | null>("pipe_read_record", { handle });
        if (bytes == null) return null;
        sequence += 1n;
        return Uint8Array.from(bytes);
      },
      write: (data: Uint8Array) => transport.call("pipe_write", { handle, bytes: Array.from(data) }),
      read: async () => { const bytes = await transport.call<number[] | null>("pipe_read", { handle }); return bytes == null ? null : Uint8Array.from(bytes); },
      close: () => transport.call("pipe_close", { handle }),
      abort: () => { void transport.call("pipe_abort", { handle }).catch(() => {}); },
      dispose: () => { void transport.call("pipe_abort", { handle }).catch(() => {}); },
      wait: () => this.#nativePipe("pipe_wait", { handle }),
      cancel: () => transport.call("pipe_cancel", { handle }),
    };
  }

  setOnPipeRequest(handler: ((request: MTPPipeRequest) => void) | null): void {
    setOnPipeRequestWithContext(this.#pipeContext(), handler);
  }

  async createPipe(description: string): Promise<MTPOutgoingPipeHandle> {
    if (this.#native) return this.#nativePipe("create_pipe", { description });
    return createPipeWithContext(this.#pipeContext(), description);
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
    if (this.#native) {
      if (options.recipientPublicKey != null && options.recipientPublicKeys != null) throw new Error("provide recipientPublicKey or recipientPublicKeys, not both");
      const recipients = normalizeRecipientBundles(options.recipientPublicKeys ?? (options.recipientPublicKey == null ? [] : [options.recipientPublicKey]), "recipientPublicKeys");
      this.#nativePipeProtection(options);
      return this.#nativePipe("create_encrypted_pipe", { options: { ...options, recipientId: inputU64(options.recipientId, "recipientId"), recipientPublicKey: undefined, recipientPublicKeys: recipients, purpose: options.purpose ?? 0x40, direction: options.direction ?? 0, signatureSuite: options.signatureSuite ?? this.#options.securityProfile.encryptedPipeSignatureSuite } });
    }
    return createEncryptedPipeWithContext(this.#pipeContext(), options);
  }

  async acceptPipe(pipeId: number): Promise<MTPPipeReader> {
    if (this.#native) return this.#nativePipe("accept_pipe", { pipeId });
    return acceptPipeWithContext(this.#pipeContext(), pipeId);
  }

  /** Accept a pipe and learn its authenticated session ID from the offer. */
  async acceptEncryptedPipe(
    request: MTPPipeRequest,
    options: MTPAcceptEncryptedPipeOptions,
  ): Promise<MTPEncryptedPipeReader> {
    if (this.#native) {
      const senderKeys = normalizeRecipientBundles(options.senderPublicKeys ?? (options.senderPublicKey == null ? [] : [options.senderPublicKey]), "senderPublicKeys");
      this.#nativePipeProtection(options);
      return this.#nativePipe("accept_encrypted_pipe", { request, options: { ...options, senderId: inputU64(options.senderId, "senderId"), senderPublicKey: undefined, senderPublicKeys: senderKeys, purpose: options.purpose ?? 0x40, direction: options.direction ?? 0, signaturePolicy: resolveSignatureVerificationPolicy(options.signaturePolicy, this.#options.defaultSignatureVerificationPolicy ?? this.#options.securityProfile.encryptedPipeSignaturePolicy) } });
    }
    return acceptEncryptedPipeWithContext(this.#pipeContext(), request, options);
  }

  async denyPipe(pipeId: number): Promise<void> {
    if (this.#native) { await this.#native.call("deny_pipe", { pipeId }); return; }
    return denyPipeWithContext(this.#pipeContext(), pipeId);
  }

  #nativePipeProtection(options: { purpose?: number; direction?: number }) {
    const purpose = validateApplicationProtectionPurpose(options.purpose ?? 0x40);
    const direction = options.direction ?? 0;
    if (!Number.isInteger(direction) || direction < 0 || direction > 0xff) {
      throw new RangeError("direction must be a u8");
    }
    return { purpose, direction };
  }

  disconnect(): void {
    if (this.#native) {
      for (const dispose of this.#subscriptionDisposers) dispose();
    }
    this.raw.client.stop_protocol_pings();
    this.raw.client.disconnect();
  }

  async setBackgroundEnabled(enabled: boolean): Promise<void> {
    if (!this.#native) throw new Error("background service is only available on Android Tauri");
    if (typeof enabled !== "boolean") throw new TypeError("enabled must be a boolean");
    await this.#native.call("set_background_enabled", { enabled });
  }
}

export { ConnectionState, bindings as raw };
export {
  crypto,
  codec,
  encode,
  decode,
  decodeDataValueWithLimits,
  decodeWithLimits,
  format,
  bytesToBase64,
  base64ToBytes,
  bytesFromEncodedString,
  strictHexDecode,
  strictBase64Decode,
  secretKeyFromBytes,
  secretKeyFromHex,
  secretKeyFromBase64,
  secretKeyFromString,
  legacySecretKeyFromStringV1,
  deriveKeyFromPassphrase,
  deriveKeyFromPassphraseSync,
  keyringToKeys,
  publicKeyBundleToKeys,
} from "./codec.js";
export {
  InMemoryReplayGuard,
  MTPReplayError,
  MTPMissingProtectedVersionError,
  MTPResourceLimitError,
  MTPUnsupportedProtectedVersionError,
} from "./protection.js";
export {
  MTPMissingRelayVersionError,
  MTPUnsupportedRelayVersionError,
  MTPVerifiedRelayMetadata,
} from "./relay.js";

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
