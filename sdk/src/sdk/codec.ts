import * as bindings from "mtp/raw";
import type { MTPCommunicationType } from "../type-map/index";
import { RESERVED_COMMUNICATION_TYPE_IDS } from "../type-map/reserved.js";
import { utf8Encode } from "./utils.js";
import { initWasmOnce } from "./wasm-init.js";
import type {
  MTPBytesInput,
  MTPCodec,
  MTPCodecOptions,
  MTPDataValue,
  MTPDataValueInput,
  MTPEncodeLimits,
  MTPEncodedBytesInput,
  MTPKeyringKeys,
  MTPKeyMaterialInput,
  MTPReceiveLimits,
  MTPCrypto,
  MTPPublicKeyBundleKeys,
  MTPProtectedFrameInput,
  MTPProtectionSignatureSuite,
  ParsedFrame,
} from "./client.js";

export const crypto: MTPCrypto = {
  generateKeyring: () => bindings.keyring_generate_checked(),
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

export function encode(
  type: MTPCommunicationType,
  data: Record<string, unknown>,
  options?: MTPCodecOptions,
): Uint8Array {
  const limits: MTPEncodeLimits = {
    maxDepth: MAX_DATA_VALUE_DEPTH,
    maxValues: MAX_DATA_VALUE_VALUES,
    maxOutputSize: 16 * 1024 * 1024,
  };
  const maxOutputSize = limits.maxOutputSize ?? 16 * 1024 * 1024;
  validateMTPDataValue(data as MTPDataValueInput, limits);
  const frame = bindings.build_frame_with_limits(type, data, options ?? {}, limits);
  if (frame.length > maxOutputSize) {
    throw new RangeError("MTP frame encoded output limit exceeded");
  }
  return frame;
}

export function decode(frame: MTPBytesInput): ParsedFrame {
  return bindings.parse_frame(bytesFrom(frame, "frame"));
}

export interface MTPMergeOptions {
  conflicts?: "keep-left" | "keep-right" | "require-equal" | "reject";
  recursiveContainers?: boolean;
  receiveLimits?: MTPReceiveLimits;
  encodeLimits?: MTPEncodeLimits;
}

export type MTPMergePath = number[];

export interface MTPMergeReport {
  inserted: MTPMergePath[];
  preserved: MTPMergePath[];
  replaced: MTPMergePath[];
  matched: MTPMergePath[];
  recursed: MTPMergePath[];
}

export interface MTPMergeResult {
  frame: Uint8Array;
  report: MTPMergeReport;
}

/**
 * Merge clear payload fields from `source` into `destination`.
 *
 * Existing destination fields win. Source-only fields are appended in source
 * order, and frame identity/routing stays with the destination.
 */
export function mergePayloadFrom(
  destination: MTPBytesInput,
  source: MTPBytesInput,
): Uint8Array {
  return mergePayloadFromDetailed(destination, source).frame;
}

export function mergePayloadFromDetailed(
  destination: MTPBytesInput,
  source: MTPBytesInput,
  options: MTPMergeOptions = {},
): MTPMergeResult {
  return bindings.merge_frame_payload_from_detailed_with_limits(
    bytesFrom(destination, "destination"),
    bytesFrom(source, "source"),
    options,
    options.receiveLimits ?? {},
    options.encodeLimits ?? {},
  );
}

/** Merge serialized clear `DataValue::Container` content before protection. */
export function mergeDataValues(
  destination: MTPBytesInput,
  source: MTPBytesInput,
  options: MTPMergeOptions = {},
): Uint8Array {
  return mergeDataValuesDetailed(destination, source, options).frame;
}

/** Merge serialized clear `DataValue::Container` content with diagnostics. */
export function mergeDataValuesDetailed(
  destination: MTPBytesInput,
  source: MTPBytesInput,
  options: MTPMergeOptions = {},
): MTPMergeResult {
  return bindings.merge_data_value_containers_detailed_with_limits(
    bytesFrom(destination, "destination data value"),
    bytesFrom(source, "source data value"),
    options,
    options.receiveLimits ?? {},
    options.encodeLimits ?? {},
  );
}

export function decodeWithLimits(
  frame: MTPBytesInput,
  limits: MTPReceiveLimits,
): ParsedFrame {
  return bindings.parse_frame_with_limits(bytesFrom(frame, "frame"), limits);
}

export function decodeDataValueWithLimits(
  value: MTPBytesInput,
  limits: MTPReceiveLimits,
): MTPDataValue {
  return bindings.parse_data_value_with_limits(bytesFrom(value, "data value"), limits);
}

export function format(frame: MTPBytesInput): string {
  return bindings.format_frame(bytesFrom(frame, "frame"));
}

export const codec: MTPCodec = { encode, decode, format };

export function isBytes(value: unknown): value is MTPBytesInput {
  return value instanceof Uint8Array || Array.isArray(value);
}

export function bytesFrom(value: MTPBytesInput, name: string): Uint8Array {
  if (value instanceof Uint8Array) return value.slice();
  if (Array.isArray(value)) {
    for (const byte of value) {
      if (!Number.isInteger(byte) || byte < 0 || byte > 255) {
        throw new RangeError(`${name} contains a non-byte value`);
      }
    }
    return Uint8Array.from(value);
  }
  throw new TypeError(`${name} must be a Uint8Array or number[]`);
}

export function strictHexDecode(value: string, name = "value"): Uint8Array {
  if (typeof value !== "string") throw new TypeError(`${name} must be a string`);
  const text = value.replace(/^0x/i, "");
  if (text.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(text)) {
    throw new TypeError(`${name} must be an even-length hexadecimal string`);
  }
  const bytes = new Uint8Array(text.length / 2);
  for (let i = 0; i < bytes.length; i += 1) {
    bytes[i] = Number.parseInt(text.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

export function strictBase64Decode(value: string, name = "value"): Uint8Array {
  if (typeof value !== "string") throw new TypeError(`${name} must be a string`);
  if (value.length === 0) return new Uint8Array(0);
  if (
    value.length % 4 !== 0 ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(
      value,
    )
  ) {
    throw new TypeError(`${name} is not valid padded base64`);
  }

  let bytes: Uint8Array;
  try {
    if (typeof atob === "function") {
      const binary = atob(value);
      bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i += 1) {
        bytes[i] = binary.charCodeAt(i);
      }
    } else if (typeof Buffer !== "undefined") {
      bytes = new Uint8Array(Buffer.from(value, "base64"));
    } else {
      throw new TypeError("base64 decoding is not available in this environment");
    }
  } catch (error) {
    throw new TypeError(`${name} is not valid base64`, { cause: error });
  }

  if (bytesToBase64(bytes) !== value) {
    throw new TypeError(`${name} is not canonical padded base64`);
  }

  return bytes;
}

export function bytesFromEncodedString(
  value: string,
  encoding: "hex" | "base64",
  name: string,
): Uint8Array {
  return encoding === "hex"
    ? strictHexDecode(value, name)
    : strictBase64Decode(value, name);
}

/*
 * Compatibility parser for the historical format-detecting API. New callers
 * should select `bytesFromEncodedString` explicitly so a value cannot change
 * meaning when it happens to contain only hexadecimal characters.
 */
/** @deprecated Use `bytesFromEncodedString(value, encoding, name)`. */
export function bytesFromString(value: string, name: string): Uint8Array {
  const trimmed = value.trim();
  if (!trimmed) throw new TypeError(`${name} must not be empty`);

  const hex = trimmed.replace(/^(0x)/i, "").replace(/[\s:_-]/g, "");
  if (/^[0-9a-fA-F]+$/.test(hex)) {
    return strictHexDecode(hex, name);
  }
  return strictBase64Decode(trimmed, name);
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
  return strictBase64Decode(input, "base64");
}

function utf8Decode(bytes: Uint8Array): string {
  if (typeof TextDecoder !== "undefined") {
    try {
      return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    } catch (error) {
      throw new TypeError("invalid UTF-8", { cause: error });
    }
  }
  let out = "";
  let i = 0;
  while (i < bytes.length) {
    const b = bytes[i];
    if (b < 0x80) {
      out += String.fromCharCode(b);
      i += 1;
    } else if (b >= 0xc2 && b <= 0xdf) {
      if (i + 1 >= bytes.length || (bytes[i + 1] & 0xc0) !== 0x80) {
        throw new TypeError("invalid UTF-8");
      }
      out += String.fromCharCode(((b & 0x1f) << 6) | (bytes[i + 1] & 0x3f));
      i += 2;
    } else if (b >= 0xe0 && b <= 0xef) {
      if (
        i + 2 >= bytes.length ||
        (bytes[i + 1] & 0xc0) !== 0x80 ||
        (bytes[i + 2] & 0xc0) !== 0x80 ||
        (b === 0xe0 && bytes[i + 1] < 0xa0) ||
        (b === 0xed && bytes[i + 1] >= 0xa0)
      ) {
        throw new TypeError("invalid UTF-8");
      }
      out += String.fromCharCode(
        ((b & 0x0f) << 12) |
          ((bytes[i + 1] & 0x3f) << 6) |
          (bytes[i + 2] & 0x3f),
      );
      i += 3;
    } else if (b >= 0xf0 && b <= 0xf4) {
      if (
        i + 3 >= bytes.length ||
        (bytes[i + 1] & 0xc0) !== 0x80 ||
        (bytes[i + 2] & 0xc0) !== 0x80 ||
        (bytes[i + 3] & 0xc0) !== 0x80 ||
        (b === 0xf0 && bytes[i + 1] < 0x90) ||
        (b === 0xf4 && bytes[i + 1] >= 0x90)
      ) {
        throw new TypeError("invalid UTF-8");
      }
      const cp =
        ((b & 0x07) << 18) |
        ((bytes[i + 1] & 0x3f) << 12) |
        ((bytes[i + 2] & 0x3f) << 6) |
        (bytes[i + 3] & 0x3f);
      out += String.fromCodePoint(cp);
      i += 4;
    } else {
      throw new TypeError("invalid UTF-8");
    }
  }
  return out;
}

function requiredSecretKeyLength(): number {
  try {
    return bindings.mtp_symmetric_key_length();
  } catch {
    // The generated WASM wrapper is callable only after initialization. Keep
    // the historical size as a pre-initialization validation fallback.
    return 32;
  }
}

export function secretKeyFromBytes(value: MTPBytesInput): Uint8Array {
  const bytes = bytesFrom(value, "secret key");
  const requiredLength = requiredSecretKeyLength();
  if (bytes.length !== requiredLength) {
    throw new RangeError(`secret key must be exactly ${requiredLength} bytes`);
  }
  return bytes;
}

export function secretKeyFromHex(value: string): Uint8Array {
  return secretKeyFromBytes(strictHexDecode(value, "secret key"));
}

export function secretKeyFromBase64(value: string): Uint8Array {
  return secretKeyFromBytes(strictBase64Decode(value, "secret key"));
}

/*
 * Compatibility entry point. It now accepts only explicitly encoded key
 * material; arbitrary strings are no longer silently treated as passphrases.
 */
/** @deprecated Use `secretKeyFromBytes`, `secretKeyFromHex`, or `secretKeyFromBase64`. */
export function secretKeyFromString(secret: string): Uint8Array {
  if (typeof secret !== "string" || !secret.trim()) {
    throw new TypeError("secret must be a non-empty string");
  }
  const trimmed = secret.trim();
  const hex = trimmed.replace(/^(0x)/i, "");
  if (/^[0-9a-fA-F]+$/.test(hex)) return secretKeyFromHex(hex);
  return secretKeyFromBase64(trimmed);
}

/**
 * Reproduce the pre-v1 implicit-HKDF derivation for data migration only.
 *
 * @deprecated Do not use for new secrets. Replace this with explicit key
 * material or `deriveKeyFromPassphrase` and persist a password-KDF salt.
 */
export function legacySecretKeyFromStringV1(secret: string): Uint8Array {
  if (typeof secret !== "string" || !secret.trim()) {
    throw new TypeError("secret must be a non-empty string");
  }
  const trimmed = secret.trim();
  const hex = trimmed.replace(/^(0x)/i, "").replace(/[\s:_-]/g, "");
  if (/^[0-9a-fA-F]+$/.test(hex) && hex.length === 64) {
    return strictHexDecode(hex, "legacy secret key");
  }
  try {
    const decoded = bytesFromString(trimmed, "legacy secret key");
    if (decoded.length === requiredSecretKeyLength()) return decoded;
  } catch {
    // Preserve the historical fallback to HKDF for non-encoded strings.
  }
  const context = utf8Encode("mtp-symmetric-key");
  return bindings.wasm_derive_encryption_key(
    utf8Encode(trimmed),
    context,
    context,
  );
}

export interface PasswordKdfParameters {
  memoryKiB: number;
  iterations: number;
  lanes: number;
}

function validatePasswordKdfInput(
  passphrase: string,
  salt: MTPBytesInput,
  parameters: PasswordKdfParameters,
): { passphrase: string; salt: Uint8Array; parameters: PasswordKdfParameters } {
  if (typeof passphrase !== "string" || passphrase.length === 0) {
    throw new TypeError("passphrase must not be empty");
  }
  const saltBytes = bytesFrom(salt, "passphrase salt");
  if (saltBytes.length < 16) {
    throw new RangeError("passphrase salt must be at least 16 bytes");
  }
  if (
    !Number.isInteger(parameters.memoryKiB) ||
    parameters.memoryKiB < 8 * 1024 ||
    parameters.memoryKiB > 256 * 1024 ||
    !Number.isInteger(parameters.iterations) ||
    parameters.iterations < 1 ||
    parameters.iterations > 10 ||
    !Number.isInteger(parameters.lanes) ||
    parameters.lanes < 1 ||
    parameters.lanes > 8
  ) {
    throw new RangeError("invalid Argon2id password-KDF parameters");
  }
  return { passphrase, salt: saltBytes, parameters };
}

function deriveKeyFromPassphraseSyncImpl(
  passphrase: string,
  salt: MTPBytesInput,
  parameters: PasswordKdfParameters,
): Uint8Array {
  const validated = validatePasswordKdfInput(passphrase, salt, parameters);
  return bindings.wasm_argon2id(
    utf8Encode(validated.passphrase),
    validated.salt,
    validated.parameters.memoryKiB,
    validated.parameters.iterations,
    validated.parameters.lanes,
  );
}

/**
 * Derive a passphrase key without yielding. Prefer the asynchronous API in
 * browser applications; this form is retained for workers and synchronous
 * command-line migrations.
 */
/** @deprecated Use `deriveKeyFromPassphrase` in browser-facing code. */
export function deriveKeyFromPassphraseSync(
  passphrase: string,
  salt: MTPBytesInput,
  parameters: PasswordKdfParameters,
): Uint8Array {
  return deriveKeyFromPassphraseSyncImpl(passphrase, salt, parameters);
}

/**
 * Derive a passphrase key off the browser main thread when workers are
 * available. The worker imports the same generated WASM binding, so the
 * Argon2id computation does not block UI/event-loop work.
 */
export function deriveKeyFromPassphrase(
  passphrase: string,
  salt: MTPBytesInput,
  parameters: PasswordKdfParameters,
): Promise<Uint8Array> {
  const validated = validatePasswordKdfInput(passphrase, salt, parameters);
  if (typeof Worker === "undefined") {
    return initWasmOnce().then(
      () =>
        new Promise((resolve) => {
          setTimeout(
            () =>
              resolve(
                deriveKeyFromPassphraseSyncImpl(
                  validated.passphrase,
                  validated.salt,
                  validated.parameters,
                ),
              ),
            0,
          );
        }),
    );
  }

  const worker = new Worker(new URL("./passphrase-worker.js", import.meta.url), {
    type: "module",
  });
  return new Promise<Uint8Array>((resolve, reject) => {
    const cleanup = () => worker.terminate();
    worker.onmessage = (event: MessageEvent<Uint8Array | { error: string }>) => {
      cleanup();
      if (event.data && "error" in event.data) {
        reject(new Error(event.data.error));
      } else {
        resolve(new Uint8Array(event.data));
      }
    };
    worker.onerror = (event) => {
      cleanup();
      reject(new Error(event.message || "Argon2id worker failed"));
    };
    const passphraseBytes = utf8Encode(validated.passphrase);
    const saltBytes = validated.salt.slice();
    worker.postMessage(
      {
        passphrase: passphraseBytes,
        salt: saltBytes,
        parameters: validated.parameters,
      },
      [passphraseBytes.buffer, saltBytes.buffer],
    );
  });
}

export function normalizeBytes(
  value: string | MTPBytesInput | MTPEncodedBytesInput,
  name: string,
  encoding?: "hex" | "base64",
): Uint8Array {
  if (typeof value === "string") {
    if (!encoding) {
      throw new TypeError(
        `${name} string input requires an explicit 'hex' or 'base64' encoding`,
      );
    }
    return bytesFromEncodedString(value, encoding, name);
  }
  if (
    value !== null &&
    typeof value === "object" &&
    !(value instanceof Uint8Array) &&
    !Array.isArray(value)
  ) {
    const encoded = value as Partial<MTPEncodedBytesInput>;
    if (
      typeof encoded.value !== "string" ||
      (encoded.encoding !== "hex" && encoded.encoding !== "base64")
    ) {
      throw new TypeError(
        `${name} must be bytes or { value: string, encoding: 'hex' | 'base64' }`,
      );
    }
    return bytesFromEncodedString(encoded.value, encoded.encoding, name);
  }
  return bytesFrom(value, name);
}

export function inputU64(value: bigint | number | string, name: string): bigint {
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

export function toBigInt(
  value: bigint | string | number | null | undefined,
): bigint | null {
  if (value == null || value === "") return null;
  return inputU64(value, "clientId");
}

const KEM_PUBLIC_KEY_LEN = 1216;
const SIG_PQ_PUBLIC_KEY_LEN = 1952;
const SIG_CL_PUBLIC_KEY_LEN = 32;

export function keyringToKeys(keyring: MTPKeyMaterialInput): MTPKeyringKeys {
  const bytes = normalizeBytes(keyring, "keyring");
  if (bytes.length < 12) {
    throw new TypeError("keyring data is too short to contain 6 keys");
  }

  let offset = 0;
  const readKey = () => {
    if (offset + 2 > bytes.length) throw new TypeError("keyring is truncated");
    const len = (bytes[offset] << 8) | bytes[offset + 1];
    offset += 2;
    if (offset + len > bytes.length) throw new TypeError("keyring is truncated");
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
  if (offset !== bytes.length) throw new TypeError("keyring has trailing data");
  return result;
}

export function publicKeyBundleToKeys(
  publicKeyBundle: MTPKeyMaterialInput,
): MTPPublicKeyBundleKeys {
  const bytes = normalizeBytes(publicKeyBundle, "publicKeyBundle");
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
  if (
    result.kemPublicKey.length !== KEM_PUBLIC_KEY_LEN ||
    result.sigPqPublicKey.length !== SIG_PQ_PUBLIC_KEY_LEN ||
    result.sigClPublicKey.length !== SIG_CL_PUBLIC_KEY_LEN
  ) {
    throw new TypeError("public key bundle contains invalid suite key lengths");
  }
  return result;
}

export function cloneParsedValue(value: unknown): unknown {
  if (value instanceof Uint8Array) return value.slice();
  if (Array.isArray(value)) return value.map(cloneParsedValue);
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([key, entry]) => [key, cloneParsedValue(entry)]),
    );
  }
  return value;
}

export function cloneParsedFrame(frame: ParsedFrame): ParsedFrame {
  return cloneParsedValue(frame) as ParsedFrame;
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
  if (object.kind === "encrypted" || object.kind === "signed") return {};
  return object;
}

export function errorMessage(
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

export function parseProtectedFrame(
  frame: MTPProtectedFrameInput,
  limits?: MTPReceiveLimits,
): ParsedFrame {
  const parse = (bytes: Uint8Array): ParsedFrame =>
    limits ? decodeWithLimits(bytes, limits) : bindings.parse_frame(bytes);
  if (isBytes(frame)) return parse(bytesFrom(frame, "frame"));
  if (
    frame === null ||
    typeof frame !== "object" ||
    typeof frame.type !== "string"
  ) {
    throw new TypeError("frame must be a parsed MTP frame or serialized bytes");
  }
  if (frame.raw instanceof Uint8Array) return parse(frame.raw);
  return frame;
}

export function assertKnownCommunicationType(frame: ParsedFrame): void {
  if (!frame.type || /^[0-9]+$/.test(frame.type)) {
    throw new Error(`Unknown communication type: ${frame.type || "unknown"}`);
  }
  try {
    bindings.build_frame(frame.type, null, {});
  } catch (error) {
    throw new Error(`Unknown communication type: ${frame.type}`, { cause: error });
  }
}

export function protectedFrameBytes(
  frame: ParsedFrame,
  limits?: MTPReceiveLimits,
): Uint8Array {
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
  const options = {
    id: frame.id,
    ...(frame.sender == null ? {} : { sender: frame.sender }),
    ...(frame.receiver == null ? {} : { receiver: frame.receiver }),
  };
  return bindings.build_frame_with_payload_with_limits(
    frame.type,
    encoded,
    options,
    limits ?? {},
  );
}

export function assertApplicationCommunicationType(type: string): string {
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

export const MAX_DATA_VALUE_DEPTH = 64;
export const MAX_DATA_VALUE_VALUES = 65_536;

const DEFAULT_ENCODE_LIMITS: Required<MTPEncodeLimits> = {
  maxDepth: MAX_DATA_VALUE_DEPTH,
  maxValues: MAX_DATA_VALUE_VALUES,
  maxOutputSize: 16 * 1024 * 1024,
};

function normalizedEncodeLimits(
  limits: MTPEncodeLimits | undefined,
): Required<MTPEncodeLimits> {
  const result = { ...DEFAULT_ENCODE_LIMITS, ...(limits ?? {}) };
  for (const [key, value] of Object.entries(result)) {
    if (!Number.isSafeInteger(value) || value < 0) {
      throw new TypeError(`encode limits ${key} must be a non-negative safe integer`);
    }
  }
  return result as Required<MTPEncodeLimits>;
}

/** Validate a JS DataValue before crossing into the recursive WASM parser. */
export function validateMTPDataValue(
  value: MTPDataValueInput,
  limits?: MTPEncodeLimits,
): void {
  const effective = normalizedEncodeLimits(limits);
  const ancestors = new WeakSet<object>();
  let values = 0;
  const validate = (candidate: unknown, depth: number): void => {
    values += 1;
    if (values > effective.maxValues) {
      throw new RangeError("MTP DataValue value-count limit exceeded");
    }
    if (depth > effective.maxDepth) {
      throw new RangeError("MTP DataValue nesting-depth limit exceeded");
    }
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
        throw new TypeError("unsafe integral MTP DataValue inputs must use bigint");
      }
      return;
    }
    if (typeof candidate !== "object") {
      throw new TypeError(`unsupported MTP DataValue input: ${typeof candidate}`);
    }
    const object = candidate as object;
    if (ancestors.has(object)) throw new TypeError("MTP DataValue input must not be cyclic");
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
    try {
      for (const entry of entries) validate(entry, depth + 1);
    } finally {
      ancestors.delete(object);
    }
  };
  validate(value, 0);
}

export function encodeMTPDataValue(
  value: MTPDataValueInput,
  limits?: MTPEncodeLimits,
): Uint8Array {
  const effective = normalizedEncodeLimits(limits);
  validateMTPDataValue(value, effective);
  const encoded = bindings.encode_data_value_with_limits(value, effective);
  if (encoded.length > effective.maxOutputSize) {
    throw new RangeError("MTP DataValue encoded output limit exceeded");
  }
  return encoded;
}

export function inputDataValueBigInt(value: unknown, name: string): bigint {
  try {
    if (typeof value === "bigint") return value;
    if (typeof value === "number" && Number.isSafeInteger(value)) return BigInt(value);
    if (typeof value === "string" && value.length > 0) return BigInt(value);
  } catch {
    // Normalize malformed protected metadata below.
  }
  throw new Error(`protected metadata field ${name} is not an integer`);
}

export function inputDataValueString(value: unknown, name: string): string {
  if (typeof value === "string" && value.length > 0) return value;
  throw new Error(`protected metadata field ${name} is not a non-empty string`);
}

export function signatureSuiteValue(
  suite: MTPProtectionSignatureSuite,
): number {
  return suite === "dual"
    ? bindings.mtp_protection_signature_suite_dual()
    : bindings.mtp_protection_signature_suite_ed25519();
}

export function formatDataValue(value: MTPDataValue): MTPDataValue {
  return cloneParsedValue(value) as MTPDataValue;
}
