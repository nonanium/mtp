import initWasm, {
  ConnectionConfig,
  ConnectionState,
  WasmClient,
  keyring_generate,
} from "mtp/raw";
import * as bindings from "mtp/raw";
import type * as RawBindings from "../raw/index";
import type { MTPCommunicationType } from "../type-map/index";

export type StorageValue = string | null;

export interface MTPCredentialStorage {
  getItem(key: string): StorageValue | Promise<StorageValue>;
  setItem(key: string, value: string): void | Promise<void>;
  removeItem(key: string): void | Promise<void>;
}

export type MTPStorage = MTPCredentialStorage;

export type MTPLogEvent =
  | { hint: "info" | "warning"; type: string; data: unknown }
  | { hint: "error"; type: string | "error"; error: string; data?: unknown };

export type ParsedFrame = RawBindings.ParsedFrame;

export type Ed25519GenerateResult = ReturnType<typeof bindings.ed25519_generate>;

export interface MTPCrypto {
  generateKeyring(): Uint8Array;
  generateEd25519(): Ed25519GenerateResult;
  keyringFromEd25519(secretKey: Uint8Array, publicKey: Uint8Array): Uint8Array;
  verifyEd25519(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): void;
  deriveEncryptionKey(ikm: Uint8Array, salt: Uint8Array, context: Uint8Array): Uint8Array;
  hkdfExpand(ikm: Uint8Array, salt: Uint8Array, info: Uint8Array, len: number): Uint8Array;
  sha256(data: Uint8Array): Uint8Array;
  sha256Double(data: Uint8Array): Uint8Array;
}

export const crypto: MTPCrypto = {
  generateKeyring: () => bindings.keyring_generate(),
  generateEd25519: () => bindings.ed25519_generate(),
  keyringFromEd25519: (secretKey, publicKey) => bindings.keyring_from_ed25519(secretKey, publicKey),
  verifyEd25519: (publicKey, message, signature) => bindings.ed25519_verify(publicKey, message, signature),
  deriveEncryptionKey: (ikm, salt, context) => bindings.wasm_derive_encryption_key(ikm, salt, context),
  hkdfExpand: (ikm, salt, info, len) => bindings.wasm_hkdf_expand(ikm, salt, info, len),
  sha256: (data) => bindings.wasm_sha256(data),
  sha256Double: (data) => bindings.wasm_sha256_double(data),
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
  encode(type: MTPCommunicationType, data: Record<string, unknown>, options?: MTPCodecOptions): Uint8Array;
  decode(frame: MTPBytesInput): ParsedFrame;
  format(frame: MTPBytesInput): string;
}

export function encode(type: MTPCommunicationType, data: Record<string, unknown>, options?: MTPCodecOptions): Uint8Array {
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
  wasm?: RawBindings.InitInput | Promise<RawBindings.InitInput> | { module_or_path: RawBindings.InitInput | Promise<RawBindings.InitInput> };
  logger?: (event: MTPLogEvent) => void;
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

type InternalCredentials = Omit<MTPCredentials, "clientId" | "keyring" | "hostPublicKey"> & {
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
  return type === "Error" || type.startsWith("Error") || [
    "BadRequest",
    "Unauthorized",
    "Forbidden",
    "NotFound",
    "TooManyRequests",
    "InternalServerError",
    "BadGateway",
    "ServiceUnavailable",
    "GatewayTimeout",
  ].includes(type);
}

function errorMessage(frame) {
  const data = frame?.data ?? {};
  return String(data.ErrorMessage ?? data.Error ?? data.Description ?? `Received ${frame?.type ?? "error"} frame`);
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

function serializeCredentials(credentials) {
  return JSON.stringify({
    clientId: credentials.clientId?.toString() ?? null,
    keyring: Array.from(credentials.keyringBytes ?? []),
    hostPublicKey: credentials.hostPublicKey ? Array.from(credentials.hostPublicKey) : undefined,
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
    hostPublicKey: normalized.hostPublicKey == null
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
  if (options.maxMessageSize != null && (!Number.isSafeInteger(options.maxMessageSize) || options.maxMessageSize <= 0)) {
    throw new TypeError("maxMessageSize must be a positive safe integer");
  }
  if (options.authTimeoutMs != null && (!Number.isSafeInteger(options.authTimeoutMs) || options.authTimeoutMs <= 0)) {
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

  private constructor(options: NormalizedMTPClientOptions, client: RawBindings.WasmClient) {
    this.#options = options;
    this.#credentials = deserializeCredentials(options.credentials);
    this.raw = { client, bindings };
  }

  static async create(options: MTPClientOptions): Promise<MTPClient> {
    validateOptions(options);
    await MTPClient.init(options.wasm);

    const normalizedOptions = {
      ...options,
      hostPublicKey: options.hostPublicKey == null
        ? undefined
        : normalizeBytes(options.hostPublicKey, "hostPublicKey"),
    };

    let sdk: MTPClient | undefined;
    const client = new WasmClient(
      (state) => emit(normalizedOptions.logger, {
        hint: "info",
        type: "state",
        data: ConnectionState[state] ?? state,
      }),
      (frame) => {
        if (sdk) {
          sdk.#handleFrame(frame);
        }
      },
      (error) => emit(normalizedOptions.logger, {
        hint: "error",
        type: "error",
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
    } else if (!sdk.#credentials.hostPublicKey && normalizedOptions.hostPublicKey) {
      sdk.#credentials = { ...sdk.#credentials, hostPublicKey: normalizedOptions.hostPublicKey };
    } else if (!normalizedOptions.hostPublicKey && sdk.#credentials.hostPublicKey) {
      sdk.#options = { ...sdk.#options, hostPublicKey: sdk.#credentials.hostPublicKey };
    }
    return sdk;
  }

  static isSupported(): boolean {
    return WasmClient.is_supported();
  }

  static async init(wasm?: MTPClientOptions["wasm"]): Promise<Awaited<ReturnType<typeof initWasm>>> {
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
      throw new Error("MTPClient.connect requires hostPublicKey for authenticated connections");
    }
    if (!this.#credentials?.keyringBytes?.length || this.#credentials.clientId == null) {
      throw new Error("MTPClient.connect requires credentials with clientId and keyring");
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
    const intervalMs = typeof pings === "object" ? pings.intervalMs ?? 30_000 : 30_000;
    this.raw.client.start_protocol_pings(intervalMs, clientId);
  }

  #buildFrame(typeOrFrame, data, options) {
    if (typeOrFrame instanceof Uint8Array) {
      return typeOrFrame;
    }
    if (typeof typeOrFrame !== "string" || !typeOrFrame) {
      throw new TypeError("message type must be a non-empty string or Uint8Array frame");
    }
    if (data == null || typeof data !== "object" || Array.isArray(data)) {
      throw new TypeError("message data must be an object");
    }
    return this.raw.bindings.build_frame(typeOrFrame, data, options ?? {});
  }

  async send(message: Uint8Array): Promise<void>;
  async send(type: MTPCommunicationType, data: Record<string, unknown>, options?: MTPSendOptions): Promise<void>;
  async send(typeOrFrame: Uint8Array | MTPCommunicationType, data?: Record<string, unknown>, options?: MTPSendOptions): Promise<void> {
    const message = this.#buildFrame(typeOrFrame, data, options);

    try {
      const frame = this.raw.bindings.parse_frame(message);
      emit(this.#options.logger, isErrorType(frame.type)
        ? { hint: "error", type: frame.type, error: errorMessage(frame), data: frame.data }
        : { hint: "info", type: frame.type, data: frame.data });
    } catch (error) {
      emit(this.#options.logger, {
        hint: "error",
        type: "error",
        error: String(error),
      });
    }

    await this.raw.client.send(message);
  }

  async request(message: Uint8Array, data?: never, options?: MTPRequestOptions): Promise<ParsedFrame>;
  async request(type: MTPCommunicationType, data: Record<string, unknown>, options?: MTPRequestOptions): Promise<ParsedFrame>;
  async request(typeOrFrame: Uint8Array | MTPCommunicationType, data?: Record<string, unknown>, options: MTPRequestOptions = {}): Promise<ParsedFrame> {
    const frame = this.#buildFrame(typeOrFrame, data, options);
    return await this.raw.client.request(frame, options.responseType ?? null);
  }

  subscribe(type: MTPCommunicationType, handler: (message: ParsedFrame) => void): Unsubscribe {
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
      });
    } else {
      emit(this.#options.logger, {
        hint: "info",
        type: frame.type,
        data: frame.data,
      });
    }
  }

  disconnect(): void {
    this.raw.client.stop_protocol_pings();
    this.raw.client.disconnect();
  }
}

export { ConnectionState, bindings as raw };
