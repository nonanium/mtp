import initWasm, {
  ConnectionConfig,
  ConnectionState,
  WasmClient,
  WasmPipeHandle,
  keyring_generate,
} from "mtp/raw";
import * as bindings from "mtp/raw";
import type * as RawBindings from "../raw/index";
import type { MTPCommunicationType } from "../type-map/index";
import type { MTPSessionStorage, MTPSessionState } from "./session";
import {
  MTPSessionManager,
  getConversationId,
  deriveSessionKeys,
} from "./session.js";
import type {
  EncryptedDeviceSecretRecord,
  MTPEncryptedDeviceSecretProvider,
} from "./encrypted-device-secret";
import { InMemoryEncryptedDeviceSecretProvider } from "./encrypted-device-secret.js";
import { InMemorySessionStorage } from "./session.js";
import {
  parseEncryptedMessage,
  encryptPayload,
  decryptPayload,
  FLAG_INIT,
} from "./encrypted-message.js";

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
  publicKeyBundleToKeys(publicKeyBundle: string | MTPBytesInput): MTPPublicKeyBundleKeys;
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
  /** @deprecated Use keyring. Kept as a migration alias for existing callers. */
  keyringBytes?: MTPBytesInput;
  hostPublicKey?: MTPBytesInput | string;
}

export interface MTPClientCredentials {
  clientId: bigint | null;
  keyring: Uint8Array;
  /** @deprecated Use keyring. Kept as a migration alias for existing callers. */
  keyringBytes: Uint8Array;
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
  pings?: boolean | { intervalMs?: number };
  wasm?:
    | RawBindings.InitInput
    | Promise<RawBindings.InitInput>
    | {
        module_or_path: RawBindings.InitInput | Promise<RawBindings.InitInput>;
      };
  logger?: (event: MTPLogEvent) => void;
  sessionStorage?: MTPSessionStorage;
  encryptedDeviceSecretProvider?: MTPEncryptedDeviceSecretProvider;
}

export type Unsubscribe = () => void;

export interface MTPSendOptions {
  id?: number;
  sender?: bigint | number;
  receiver?: bigint | number;
}

export interface MTPRequestOptions extends MTPSendOptions {
  responseType?: MTPCommunicationType;
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

type InternalCredentials = Omit<
  MTPCredentials,
  "clientId" | "keyring" | "hostPublicKey"
> & {
  clientId: bigint | null;
  keyringBytes: Uint8Array;
  hostPublicKey?: Uint8Array;
};

type NormalizedMTPClientOptions = Omit<MTPClientOptions, "hostPublicKey"> & {
  hostPublicKey?: Uint8Array;
};

const DEFAULT_CREDENTIALS_KEY = "mtp:credentials";
let wasmInitPromise: Promise<Awaited<ReturnType<typeof initWasm>>> | undefined;

function emit(logger, event) {
  if (typeof logger === "function") {
    logger(event);
  }
}

function isErrorType(type) {
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

function errorMessage(frame) {
  const data = frame?.data ?? {};
  return String(
    data.ErrorMessage ??
      data.Error ??
      data.Description ??
      `Received ${frame?.type ?? "error"} frame`,
  );
}

async function storageGet(storage, key) {
  return storage ? await storage.getItem(key) : null;
}

async function storageSet(storage, key, value) {
  if (storage) {
    await storage.setItem(key, value);
  }
}

async function storageRemove(storage, key) {
  if (storage) {
    await storage.removeItem(key);
  }
}

function isBytes(value) {
  return value instanceof Uint8Array || Array.isArray(value);
}

function bytesFrom(value, name) {
  if (value instanceof Uint8Array) {
    return value;
  }
  if (Array.isArray(value)) {
    return new Uint8Array(value);
  }
  throw new TypeError(`${name} must be a Uint8Array or number[]`);
}

function bytesFromString(value, name) {
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

function bytesToHex(bytes) {
  let out = "";
  for (let i = 0; i < bytes.length; i += 1) {
    out += HEX_DIGITS[(bytes[i] >> 4) & 0xf] + HEX_DIGITS[bytes[i] & 0xf];
  }
  return out;
}

export function bytesToBase64(bytes) {
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

export function base64ToBytes(input) {
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

function utf8Encode(text) {
  if (typeof TextEncoder !== "undefined") {
    return new TextEncoder().encode(text);
  }
  if (typeof Buffer !== "undefined") {
    return new Uint8Array(Buffer.from(text, "utf-8"));
  }
  const bytes = new Uint8Array(text.length * 4);
  let len = 0;
  for (let i = 0; i < text.length; i += 1) {
    const code = text.codePointAt(i);
    if (code < 0x80) {
      bytes[len++] = code;
    } else if (code < 0x800) {
      bytes[len++] = 0xc0 | (code >> 6);
      bytes[len++] = 0x80 | (code & 0x3f);
    } else if (code < 0x10000) {
      bytes[len++] = 0xe0 | (code >> 12);
      bytes[len++] = 0x80 | ((code >> 6) & 0x3f);
      bytes[len++] = 0x80 | (code & 0x3f);
    } else {
      bytes[len++] = 0xf0 | (code >> 18);
      bytes[len++] = 0x80 | ((code >> 12) & 0x3f);
      bytes[len++] = 0x80 | ((code >> 6) & 0x3f);
      bytes[len++] = 0x80 | (code & 0x3f);
      i += 1;
    }
  }
  return bytes.subarray(0, len);
}

function utf8Decode(bytes) {
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

export function secretKeyFromString(secret) {
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

function normalizeBytes(value, name) {
  if (typeof value === "string") {
    return bytesFromString(value, name);
  }
  return bytesFrom(value, name);
}

function normalizeCredentials(value) {
  if (!value) {
    return null;
  }

  if (typeof value === "string") {
    return JSON.parse(value);
  }

  return value;
}

function toBigInt(value) {
  if (value == null || value === "") {
    return null;
  }
  return typeof value === "bigint" ? value : BigInt(value);
}

function generateKeyringBytes() {
  return keyring_generate();
}

export function keyringToKeys(keyring) {
  const bytes =
    typeof keyring === "string"
      ? bytesFromString(keyring, "keyring")
      : bytesFrom(keyring, "keyring");

  if (bytes.length < 12) {
    throw new TypeError("keyring data is too short to contain 6 keys");
  }

  let offset = 0;
  const readKey = () => {
    const len = (bytes[offset] << 8) | bytes[offset + 1];
    offset += 2;
    const key = bytes.slice(offset, offset + len);
    offset += len;
    return key;
  };

  return {
    kemPublicKey: readKey(),
    kemSecretKey: readKey(),
    sigPqPublicKey: readKey(),
    sigPqSecretKey: readKey(),
    sigClPublicKey: readKey(),
    sigClSecretKey: readKey(),
  };
}

export function publicKeyBundleToKeys(publicKeyBundle) {
  const bytes =
    typeof publicKeyBundle === "string"
      ? bytesFromString(publicKeyBundle, "publicKeyBundle")
      : bytesFrom(publicKeyBundle, "publicKeyBundle");

  if (bytes.length < 6) {
    throw new TypeError("public key bundle data is too short to contain 3 keys");
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

  return result;
}

function serializeCredentials(credentials) {
  return JSON.stringify({
    clientId: credentials.clientId?.toString() ?? null,
    keyring: Array.from(credentials.keyringBytes ?? []),
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

  const keyring = normalized.keyring ?? normalized.keyringBytes;
  if (!isBytes(keyring)) {
    throw new TypeError("credentials.keyring must be a Uint8Array or number[]");
  }

  return {
    clientId: toBigInt(normalized.clientId),
    keyringBytes: bytesFrom(keyring, "credentials.keyring"),
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
    keyring: credentials.keyringBytes,
    keyringBytes: credentials.keyringBytes,
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
}

async function withTimeout(promise, timeoutMs, message) {
  if (!timeoutMs) {
    return await promise;
  }

  let timeoutId;
  try {
    return await Promise.race([
      promise,
      new Promise((_resolve, reject) => {
        timeoutId = setTimeout(() => reject(new Error(message)), timeoutMs);
      }),
    ]);
  } finally {
    clearTimeout(timeoutId);
  }
}

export class MTPClient {
  static readonly crypto = crypto;
  static readonly codec = codec;

  #credentials: InternalCredentials | null;
  #options: NormalizedMTPClientOptions;
  readonly raw: MTPRaw;

  readonly crypto = MTPClient.crypto;
  readonly codec = MTPClient.codec;

  readonly sessionManager: MTPSessionManager;
  readonly encryptedDeviceSecretProvider: MTPEncryptedDeviceSecretProvider;

  private constructor(
    options: NormalizedMTPClientOptions,
    client: RawBindings.WasmClient,
  ) {
    this.#options = options;
    this.#credentials = deserializeCredentials(options.credentials);
    this.raw = { client, bindings };
    this.encryptedDeviceSecretProvider =
      options.encryptedDeviceSecretProvider ??
      new InMemoryEncryptedDeviceSecretProvider();
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
        keyringBytes: generateKeyringBytes(),
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

  get state(): RawBindings.ConnectionState {
    return this.raw.client.state;
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

    const config = this.#connectionConfig();
    try {
      await withTimeout(
        this.raw.client.connect(config),
        this.#options.authTimeoutMs,
        "connection timed out",
      );
      this.#startPings(0n);
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
      !this.#credentials?.keyringBytes?.length ||
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
          this.#credentials.keyringBytes,
          this.#credentials.clientId,
        ),
        this.#options.authTimeoutMs,
        "authentication timed out",
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
    if (!this.#credentials?.keyringBytes?.length) {
      this.#credentials = {
        clientId: null,
        keyringBytes: generateKeyringBytes(),
        hostPublicKey: this.#options.hostPublicKey,
      };
    }

    const config = this.#connectionConfig();
    try {
      const clientId = await withTimeout(
        this.raw.client.auth_register(
          config,
          this.#options.hostPublicKey,
          this.#credentials.keyringBytes,
        ),
        this.#options.authTimeoutMs,
        "authentication timed out",
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
    return await this.raw.client.request(frame, options.responseType ?? null);
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
    if (!this.#credentials?.keyringBytes?.length) {
      throw new Error("No keyring available");
    }
    const keys = keyringToKeys(this.#credentials.keyringBytes);
    return keys.kemPublicKey;
  }

  #getKemSecretKey(): Uint8Array {
    if (!this.#credentials?.keyringBytes?.length) {
      throw new Error("No keyring available");
    }
    const keys = keyringToKeys(this.#credentials.keyringBytes);
    return keys.kemSecretKey;
  }

  async sendEncrypted(
    type: number | string,
    data: Record<string, unknown>,
    options: MTPSendOptions & {
      recipientClientId: bigint | number | string;
      recipientPublicKey: string | MTPBytesInput;
      senderUserId?: string;
      recipientUserId?: string;
      recipientDeviceId?: string;
    },
  ): Promise<void> {
    const ownId = this.#credentials?.clientId;
    if (ownId == null) {
      throw new Error("Client not registered");
    }
    if (options.recipientClientId == null) {
      throw new Error("recipientClientId is required");
    }
    const recipientClientId = BigInt(options.recipientClientId);

    const plaintext = this.raw.bindings.build_frame(type as string, data, {
      sender: ownId,
      receiver: recipientClientId,
      ...options,
    });

    let session = await this.sessionManager.getSession(
      ownId,
      recipientClientId,
    );
    let kemCiphertext: Uint8Array | undefined;

    if (!session) {
      if (options.recipientPublicKey == null) {
        throw new Error("recipientPublicKey is required for new encrypted sessions");
      }
      const recipientPublicKey = publicKeyBundleToKeys(
        options.recipientPublicKey,
      );
      const enc = bindings.wasm_kem_encapsulate(
        recipientPublicKey.kemPublicKey,
      );
      kemCiphertext = enc.ciphertext;
      const conversationId = getConversationId(ownId, recipientClientId);

      session = await this.sessionManager.createSession({
        ownClientId: ownId,
        peerClientId: recipientClientId,
        peerPublicKey: recipientPublicKey.kemPublicKey,
        sharedSecret: enc.shared_secret,
        role: "initiator",
        transcriptContext: {
          senderUserId: (options as { senderUserId?: string }).senderUserId,
          senderClientId: ownId,
          recipientUserId: options.recipientUserId,
          recipientClientId,
          recipientPublicKey: recipientPublicKey.kemPublicKey,
          kemCiphertext,
          conversationId,
        },
      });
      enc.shared_secret.fill(0);
    }

    const { payload, session: newSession } = await encryptPayload({
      plaintext,
      session,
      kemCiphertext,
    });

    await this.sessionManager.saveSession(newSession);

    const messageId = String(Date.now());
    const createdAt = Date.now();
    const senderUserId = (options as { senderUserId?: string }).senderUserId;
    const frame = this.raw.bindings.build_frame(
      "EncryptedMessage",
      {
        MessageId: messageId,
        ConversationId: session.conversationId,
        SenderClientId: ownId,
        RecipientClientId: recipientClientId,
        SenderUserId: senderUserId,
        RecipientUserId: options.recipientUserId,
        CreatedAt: createdAt,
        EncryptionVersion: 1,
        EncryptedPayload: payload,
      },
      {
        sender: ownId,
        receiver: recipientClientId,
      },
    );
    await this.raw.client.send(frame);

    if (senderUserId && options.recipientUserId) {
      const ownKemPublicKey = this.#getKemPublicKey();
      const archiveEnc = bindings.wasm_kem_encapsulate(ownKemPublicKey);
      const archiveSession = await this.sessionManager.createSession({
        ownClientId: ownId,
        peerClientId: ownId,
        peerPublicKey: ownKemPublicKey,
        sharedSecret: archiveEnc.shared_secret,
        role: "initiator",
        transcriptContext: {
          senderUserId,
          senderClientId: ownId,
          recipientUserId: options.recipientUserId,
          recipientClientId: ownId,
          recipientPublicKey: ownKemPublicKey,
          kemCiphertext: archiveEnc.ciphertext,
          conversationId: `archive:${session.conversationId}:${messageId}`,
        },
      });
      archiveEnc.shared_secret.fill(0);
      const { payload: archivePayload } = await encryptPayload({
        plaintext,
        session: archiveSession,
        kemCiphertext: archiveEnc.ciphertext,
      });
      const archiveFrame = this.raw.bindings.build_frame(
        "EncryptedMessage",
        {
          MessageId: `${messageId}:sender`,
          ConversationId: session.conversationId,
          SenderClientId: ownId,
          RecipientClientId: ownId,
          SenderUserId: senderUserId,
          RecipientUserId: options.recipientUserId,
          CreatedAt: createdAt,
          EncryptionVersion: 1,
          EncryptedPayload: archivePayload,
        },
        {
          sender: ownId,
          receiver: ownId,
        },
      );
      await this.raw.client.send(archiveFrame);
    }
  }

  subscribeEncrypted(
    type: number | string,
    handler: (data: unknown, meta: ParsedFrame) => void | Promise<void>,
  ): Unsubscribe;
  subscribeEncrypted(
    handler: (data: {
      type: string;
      data: Record<string, unknown>;
      sender?: bigint;
      receiver?: bigint;
    }) => void | Promise<void>,
  ): Unsubscribe;
  subscribeEncrypted(
    typeOrHandler:
      | number
      | string
      | ((data: {
          type: string;
          data: Record<string, unknown>;
          sender?: bigint;
          receiver?: bigint;
        }) => void | Promise<void>),
    maybeHandler?: (data: unknown, meta: ParsedFrame) => void | Promise<void>,
  ): Unsubscribe {
    const expectedInnerType =
      typeof typeOrHandler === "function" ? null : String(typeOrHandler);
    const legacyHandler =
      typeof typeOrHandler === "function" ? typeOrHandler : null;
    const sub = this.raw.client.subscribe(
      "EncryptedMessage",
      async (frame: ParsedFrame) => {
        const raw =
          frame.data?.["encryptedPayload"] ??
          frame.data?.["EncryptedPayload"] ??
          frame.data?.["encrypted_payload"];
        if (!raw) return;

        let payloadBytes: Uint8Array;
        if (raw instanceof Uint8Array) {
          payloadBytes = raw;
        } else if (Array.isArray(raw)) {
          payloadBytes = new Uint8Array(raw);
        } else {
          return;
        }

        try {
          const parsed = parseEncryptedMessage(payloadBytes);

          const ownId = this.#credentials?.clientId;
          if (ownId == null) return;
          if (parsed.recipientClientId !== ownId) return;

          const peerClientId = parsed.senderClientId;
          let session = await this.sessionManager.getSession(
            ownId,
            peerClientId,
          );

          if (!session) {
            if (!(parsed.flags & FLAG_INIT) || !parsed.kemCiphertext) {
              return;
            }

            const ownKemSecret = this.#getKemSecretKey();
            const sharedSecret = bindings.wasm_kem_decapsulate(
              ownKemSecret,
              parsed.kemCiphertext,
            );

            session = await this.sessionManager.createSession({
              ownClientId: ownId,
              peerClientId,
              peerPublicKey: new Uint8Array(0),
              sharedSecret,
              role: "receiver",
              transcriptContext: {
                senderUserId: String(
                  frame.data?.["SenderUserId"] ??
                    frame.data?.["senderUserId"] ??
                    "",
                ),
                senderClientId: peerClientId,
                recipientUserId: String(
                  frame.data?.["RecipientUserId"] ??
                    frame.data?.["recipientUserId"] ??
                    "",
                ),
                recipientClientId: ownId,
                recipientPublicKey: this.#getKemPublicKey(),
                kemCiphertext: parsed.kemCiphertext,
                conversationId: getConversationId(peerClientId, ownId),
              },
            });
            sharedSecret.fill(0);
          }

          const { plaintext, session: newSession } = await decryptPayload({
            payload: payloadBytes,
            session,
            expectedRecipientClientId: ownId,
          });

          await this.sessionManager.saveSession(newSession);

          let parsedFrame: ParsedFrame;
          try {
            parsedFrame = this.raw.bindings.parse_frame(plaintext);
          } catch {
            return;
          }

          if (expectedInnerType && parsedFrame.type !== expectedInnerType) {
            return;
          }
          if (legacyHandler) {
            await legacyHandler({
              type: parsedFrame.type,
              data: parsedFrame.data,
              sender: parsedFrame.sender,
              receiver: parsedFrame.receiver,
            });
          } else if (maybeHandler) {
            await maybeHandler(parsedFrame.data, parsedFrame);
          }
        } catch (e) {
          emit(this.#options.logger, {
            hint: "error",
            type: "E2EE",
            error: String(e),
            direction: "recv",
          });
        }
      },
    );

    return () => this.raw.client.unsubscribe(sub);
  }

  async decryptEncryptedRecord(
    frameData: Record<string, unknown>,
  ): Promise<ParsedFrame> {
    const raw =
      frameData["encryptedPayload"] ??
      frameData["EncryptedPayload"] ??
      frameData["encrypted_payload"];
    if (!raw) throw new Error("EncryptedPayload is required");

    const payloadBytes =
      raw instanceof Uint8Array
        ? raw
        : Array.isArray(raw)
          ? new Uint8Array(raw)
          : bytesFrom(raw as MTPBytesInput, "EncryptedPayload");

    const parsed = parseEncryptedMessage(payloadBytes);
    const ownId = this.#credentials?.clientId;
    if (ownId == null) throw new Error("Client not registered");
    if (parsed.recipientClientId !== ownId) {
      throw new Error("Encrypted message recipient mismatch");
    }

    const peerClientId = parsed.senderClientId;
    let session = await this.sessionManager.getSession(ownId, peerClientId);

    const isSenderArchive =
      parsed.senderClientId === ownId && parsed.recipientClientId === ownId;

    if (isSenderArchive && (parsed.flags & FLAG_INIT) && parsed.kemCiphertext) {
      const ownKemSecret = this.#getKemSecretKey();
      const sharedSecret = bindings.wasm_kem_decapsulate(
        ownKemSecret,
        parsed.kemCiphertext,
      );
      const archiveMessageId = String(
        frameData["MessageId"] ?? frameData["messageId"] ?? "",
      ).replace(/:sender$/, "");
      session = await this.sessionManager.createSession({
        ownClientId: ownId,
        peerClientId: ownId,
        peerPublicKey: this.#getKemPublicKey(),
        sharedSecret,
        role: "receiver",
        transcriptContext: {
          senderUserId: String(
            frameData["SenderUserId"] ?? frameData["senderUserId"] ?? "",
          ),
          senderClientId: ownId,
          recipientUserId: String(
            frameData["RecipientUserId"] ?? frameData["recipientUserId"] ?? "",
          ),
          recipientClientId: ownId,
          recipientPublicKey: this.#getKemPublicKey(),
          kemCiphertext: parsed.kemCiphertext,
          conversationId: `archive:${String(frameData["ConversationId"] ?? frameData["conversationId"] ?? "")}:${archiveMessageId}`,
        },
      });
      sharedSecret.fill(0);
    } else if (!session) {
      if (!(parsed.flags & FLAG_INIT) || !parsed.kemCiphertext) {
        throw new Error("No session for non-init encrypted message");
      }
      const ownKemSecret = this.#getKemSecretKey();
      const sharedSecret = bindings.wasm_kem_decapsulate(
        ownKemSecret,
        parsed.kemCiphertext,
      );

      session = await this.sessionManager.createSession({
        ownClientId: ownId,
        peerClientId,
        peerPublicKey: new Uint8Array(0),
        sharedSecret,
        role: "receiver",
        transcriptContext: {
          senderUserId: String(
            frameData["SenderUserId"] ?? frameData["senderUserId"] ?? "",
          ),
          senderClientId: peerClientId,
          recipientUserId: String(
            frameData["RecipientUserId"] ?? frameData["recipientUserId"] ?? "",
          ),
          recipientClientId: ownId,
          recipientPublicKey: this.#getKemPublicKey(),
          kemCiphertext: parsed.kemCiphertext,
          conversationId: getConversationId(peerClientId, ownId),
        },
      });
      sharedSecret.fill(0);
    }

    const { plaintext, session: newSession } = await decryptPayload({
      payload: payloadBytes,
      session,
      expectedRecipientClientId: ownId,
    });
    if (!isSenderArchive) {
      await this.sessionManager.saveSession(newSession);
    }
    return this.raw.bindings.parse_frame(plaintext);
  }

  async setEncryptedDeviceSecret(
    record: EncryptedDeviceSecretRecord,
  ): Promise<void> {
    await this.encryptedDeviceSecretProvider.setEncryptedDeviceSecret(record);
  }

  async getEncryptedDeviceSecret(query: {
    userId: string;
    deviceId?: string;
    secretId?: string;
  }): Promise<EncryptedDeviceSecretRecord | null> {
    return this.encryptedDeviceSecretProvider.getEncryptedDeviceSecret(query);
  }

  setOnPipeRequest(
    handler: ((request: MTPPipeRequest) => void) | null,
  ): void {
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
    const handle: WasmPipeHandle = await this.raw.client.create_pipe(
      description,
    );
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
} from "./session";
export {
  MTPSessionManager,
  InMemorySessionStorage,
  getConversationId,
  deriveSessionKeys,
  buildSessionTranscript,
} from "./session.js";
export { MTPRatchet } from "./ratchet.js";
export type { RatchetStep } from "./ratchet.js";
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
  EncryptedDeviceSecretRecord,
  MTPEncryptedDeviceSecretProvider,
} from "./encrypted-device-secret";
export { InMemoryEncryptedDeviceSecretProvider } from "./encrypted-device-secret.js";
