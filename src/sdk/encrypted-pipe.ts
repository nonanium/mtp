import * as bindings from "mtp/raw";
import type {
  MTPBytesInput,
  MTPPipeReader,
  MTPPipeWriter,
  MTPProtectionSignatureSuite,
} from "./index.js";
import {
  MTPSignatureVerificationError,
  resolveSignatureVerificationPolicy,
  signatureVerificationFailure,
  verifyDataValueWithPolicy,
} from "./signature-policy.js";
import type { MTPSignatureVerificationPolicy } from "./signature-policy.js";
import { concatBytes, utf8Encode, writeU64BE } from "./utils.js";

const PIPE_E2EE_DOMAIN = utf8Encode("MTP-PIPE-E2EE-1");
const PIPE_RECORD_KDF_DOMAIN = utf8Encode("MTP-PIPE-E2EE-1/KEY");
const PIPE_TRANSCRIPT_DOMAIN = utf8Encode("MTP-PIPE-TRANSCRIPT-1");
const PIPE_RECORD_MESSAGE_LABEL = utf8Encode("/message");
const PIPE_RECORD_NEXT_LABEL = utf8Encode("/next");
const XCHACHA_OVERHEAD = 24 + 16;
const MAX_SESSION_ID = 1024;
export const MAX_ENCRYPTED_PIPE_RECORD = 16 * 1024 * 1024;
export const MAX_PIPE_SESSION_OFFER = 64 * 1024;
const PIPE_SESSION_OFFER_DOMAIN = "MTP-PIPE-SESSION-1";
const FS_INIT_DOMAIN = "MTP-PIPE-FS-INIT-1";
const FS_RESPONSE_DOMAIN = "MTP-PIPE-FS-RESPONSE-1";
const FS_FINISH_DOMAIN = "MTP-PIPE-FS-FINISH-1";
const FS_ROOT_INFO = utf8Encode("MTP-PIPE-FS-ROOT-1");
const RECORD_TYPE_DATA = 0;
const RECORD_TYPE_FINAL = 1;
const MAX_PIPE_BUFFER = MAX_ENCRYPTED_PIPE_RECORD + 5;
// Session setup may leave one encrypted record in the same transport chunk
// after an offer. Bound that carry-over buffer before concatenating attacker-
// controlled chunks, just as the record reader bounds its input buffer.
const MAX_SESSION_BUFFER = MAX_PIPE_BUFFER + MAX_PIPE_SESSION_OFFER + 4;
const KEM_PUBLIC_KEY_LEN = 1216;
const SIG_PQ_PUBLIC_KEY_LEN = 1952;
const SIG_CL_PUBLIC_KEY_LEN = 32;

export function pipeSessionSignaturePurpose(): number {
  return bindings.mtp_pipe_session_signature_purpose();
}

export function pipeSessionEncryptionPurpose(): number {
  return bindings.mtp_pipe_session_encryption_purpose();
}

/**
 * Validate a purpose supplied for application pipe records. MTP-owned
 * purpose bytes come from the WASM protocol registry so browser callers do
 * not have to duplicate the numeric allocation.
 */
export function validateApplicationProtectionPurpose(purpose: number): number {
  if (!Number.isInteger(purpose) || purpose < 0 || purpose > 0xff) {
    throw new MTPEncryptedPipeError("context", "purpose must be a u8");
  }
  const reserved = new Set([
    bindings.mtp_relay_metadata_encryption_purpose(),
    bindings.mtp_relay_content_signature_purpose(),
    bindings.mtp_relay_content_encryption_purpose(),
    bindings.mtp_relay_metadata_signature_purpose(),
    bindings.mtp_pipe_session_signature_purpose(),
    bindings.mtp_pipe_session_encryption_purpose(),
  ]);
  if (reserved.has(purpose)) {
    throw new MTPEncryptedPipeError(
      "context",
      "purpose is reserved for an MTP protocol operation",
    );
  }
  return purpose;
}

export class MTPEncryptedPipeError extends Error {
  readonly code:
    | "context"
    | "record-length"
    | "sequence"
    | "truncated"
    | "authentication"
    | "io"
    | "setup"
    | "state";

  constructor(
    code: MTPEncryptedPipeError["code"],
    message: string,
    options?: ErrorOptions,
  ) {
    super(message, options);
    this.name = "MTPEncryptedPipeError";
    this.code = code;
  }
}

export class MTPPipeProtectionContext {
  readonly sessionId: Uint8Array;
  readonly purpose: number;
  readonly direction: number;
  readonly transcriptHash: Uint8Array;

  constructor(
    sessionId: Uint8Array,
    purpose: number,
    direction: number,
    transcriptHash?: Uint8Array,
  ) {
    if (
      !(sessionId instanceof Uint8Array) ||
      sessionId.length === 0 ||
      sessionId.length > MAX_SESSION_ID
    ) {
      throw new MTPEncryptedPipeError(
        "context",
        "sessionId must contain between 1 and 1024 bytes",
      );
    }
    validateApplicationProtectionPurpose(purpose);
    if (!Number.isInteger(direction) || direction < 0 || direction > 0xff) {
      throw new MTPEncryptedPipeError("context", "direction must be a u8");
    }
    this.sessionId = sessionId.slice();
    this.purpose = purpose;
    this.direction = direction;
    if (transcriptHash != null) {
      if (
        !(transcriptHash instanceof Uint8Array) ||
        transcriptHash.length !== 32
      ) {
        throw new MTPEncryptedPipeError(
          "context",
          "transcriptHash must be 32 bytes",
        );
      }
      this.transcriptHash = transcriptHash.slice();
    } else {
      this.transcriptHash = baseTranscriptHash(
        this.sessionId,
        purpose,
        direction,
      );
    }
  }
}

function u32(value: number): Uint8Array {
  const result = new Uint8Array(4);
  new DataView(result.buffer).setUint32(0, value, false);
  return result;
}

function sessionTranscriptHash(params: MTPPipeSessionParameters): Uint8Array {
  return bindings.wasm_sha256(
    concatBytes([
      PIPE_TRANSCRIPT_DOMAIN,
      u32(params.sessionId.length),
      params.sessionId,
      u32(params.pipeId),
      writeU64BE(params.senderId),
      writeU64BE(params.recipientId),
      new Uint8Array([params.purpose, params.direction]),
    ]),
  );
}

function baseTranscriptHash(
  sessionId: Uint8Array,
  purpose: number,
  direction: number,
): Uint8Array {
  return bindings.wasm_sha256(
    concatBytes([
      PIPE_TRANSCRIPT_DOMAIN,
      u32(sessionId.length),
      sessionId,
      new Uint8Array([purpose, direction]),
    ]),
  );
}

function recordLength(plaintextLength: number): number {
  const length = plaintextLength + XCHACHA_OVERHEAD;
  if (
    !Number.isSafeInteger(length) ||
    length < XCHACHA_OVERHEAD ||
    length > MAX_ENCRYPTED_PIPE_RECORD ||
    length > 0xffff_ffff
  ) {
    throw new MTPEncryptedPipeError(
      "record-length",
      `invalid encrypted pipe record length: ${length}`,
    );
  }
  return length;
}

function aad(
  context: MTPPipeProtectionContext,
  sequence: bigint,
  encodedLength: number,
  recordType: number,
): Uint8Array {
  return concatBytes([
    PIPE_E2EE_DOMAIN,
    new Uint8Array([context.purpose, context.direction]),
    context.transcriptHash,
    writeU64BE(sequence),
    u32(encodedLength),
    new Uint8Array([recordType]),
  ]);
}

function keyBytes(key: Uint8Array): Uint8Array {
  if (!(key instanceof Uint8Array) || key.length !== 32) {
    throw new MTPEncryptedPipeError(
      "context",
      "pipe session key must be 32 bytes",
    );
  }
  return key.slice();
}

function recordKeyInfo(
  context: MTPPipeProtectionContext,
  sequence: bigint,
  label: Uint8Array,
): Uint8Array {
  return concatBytes([
    PIPE_RECORD_KDF_DOMAIN,
    new Uint8Array([context.purpose, context.direction]),
    context.transcriptHash,
    writeU64BE(sequence),
    label,
  ]);
}

function deriveRecordKeys(
  chainKey: Uint8Array,
  context: MTPPipeProtectionContext,
  sequence: bigint,
): { messageKey: Uint8Array; nextChainKey: Uint8Array } {
  try {
    return {
      messageKey: bindings.wasm_hkdf_expand(
        chainKey,
        context.transcriptHash,
        recordKeyInfo(context, sequence, PIPE_RECORD_MESSAGE_LABEL),
        32,
      ),
      nextChainKey: bindings.wasm_hkdf_expand(
        chainKey,
        context.transcriptHash,
        recordKeyInfo(context, sequence, PIPE_RECORD_NEXT_LABEL),
        32,
      ),
    };
  } catch (error) {
    throw new MTPEncryptedPipeError(
      "authentication",
      "encrypted pipe record key derivation failed",
      { cause: error },
    );
  }
}

export interface MTPWritablePipe {
  write(data: Uint8Array): Promise<void>;
  close(): Promise<void>;
  abort(): void;
}

export interface MTPReadablePipe {
  read(): Promise<Uint8Array | null>;
}

/** Advanced duplex transport required by the forward-secure handshake. */
export interface MTPDuplexPipe extends MTPWritablePipe, MTPReadablePipe {
  readonly pipeId?: number;
}

export interface MTPPipeSessionParameters {
  sessionId: Uint8Array;
  pipeId: number;
  senderId: bigint;
  recipientId: bigint;
  purpose: number;
  direction: number;
}

/** Session fields the receiver can know before decrypting the offer. */
export type MTPPipeSessionExpectation = Omit<
  MTPPipeSessionParameters,
  "sessionId"
>;

function contextForSessionParameters(
  params: MTPPipeSessionParameters,
): MTPPipeProtectionContext {
  return new MTPPipeProtectionContext(
    params.sessionId,
    params.purpose,
    params.direction,
    sessionTranscriptHash(params),
  );
}

function sessionError(message: string, cause?: unknown): MTPEncryptedPipeError {
  return new MTPEncryptedPipeError("setup", message, { cause });
}

function bytesInput(value: MTPBytesInput, name: string): Uint8Array {
  if (value instanceof Uint8Array) return value.slice();
  if (Array.isArray(value)) return new Uint8Array(value);
  throw sessionError(`${name} must be a Uint8Array or number[]`);
}

function publicKeyBundleInputs(value: Uint8Array): void {
  let offset = 0;
  const lengths: number[] = [];
  for (let index = 0; index < 3; index += 1) {
    if (offset + 2 > value.length)
      throw sessionError("public key bundle is truncated");
    const length = new DataView(
      value.buffer,
      value.byteOffset,
      value.byteLength,
    ).getUint16(offset, false);
    offset += 2;
    if (offset + length > value.length) {
      throw sessionError("public key bundle is truncated");
    }
    lengths.push(length);
    offset += length;
  }
  if (
    offset !== value.length ||
    lengths[0] !== KEM_PUBLIC_KEY_LEN ||
    lengths[1] !== SIG_PQ_PUBLIC_KEY_LEN ||
    lengths[2] !== SIG_CL_PUBLIC_KEY_LEN
  ) {
    throw sessionError("public key bundle contains invalid suite key lengths");
  }
}

function recipientBundleInputs(
  value: MTPBytesInput | MTPBytesInput[],
): Uint8Array[] {
  // A number[] is one serialized bundle; an array whose first element is a
  // byte array is the multi-recipient form.
  if (value instanceof Uint8Array) return [value.slice()];
  if (
    Array.isArray(value) &&
    (value.length === 0 || typeof value[0] === "number")
  ) {
    return [bytesInput(value as MTPBytesInput, "recipientPublicKey")];
  }
  if (!Array.isArray(value)) {
    throw sessionError(
      "recipientPublicKey must be bytes or an array of bundles",
    );
  }
  const result = value.map((entry, index) =>
    bytesInput(entry, `recipientPublicKeys[${index}]`),
  );
  if (result.length === 0) {
    throw sessionError("at least one recipient public key is required");
  }
  return result;
}

function validateSessionParameters(
  params: MTPPipeSessionParameters,
): MTPPipeSessionParameters {
  if (
    !(params.sessionId instanceof Uint8Array) ||
    params.sessionId.length === 0 ||
    params.sessionId.length > MAX_SESSION_ID
  ) {
    throw sessionError("sessionId must contain between 1 and 1024 bytes");
  }
  if (
    !Number.isInteger(params.pipeId) ||
    params.pipeId <= 0 ||
    params.pipeId > 0xffff_ffff
  ) {
    throw sessionError("pipeId must be a non-zero u32");
  }
  if (params.senderId < 0n || params.senderId > 0xffff_ffff_ffff_ffffn) {
    throw sessionError("senderId must be a u64");
  }
  if (params.recipientId < 0n || params.recipientId > 0xffff_ffff_ffff_ffffn) {
    throw sessionError("recipientId must be a u64");
  }
  validateApplicationProtectionPurpose(params.purpose);
  if (
    !Number.isInteger(params.direction) ||
    params.direction < 0 ||
    params.direction > 0xff
  ) {
    throw sessionError("direction must be a u8");
  }
  return { ...params, sessionId: params.sessionId.slice() };
}

function serializedKeyring(keyring: MTPBytesInput): {
  bytes: Uint8Array;
  hasPqSigningKey: boolean;
} {
  const bytes = bytesInput(keyring, "keyring");
  let offset = 0;
  const fields: Uint8Array[] = [];
  for (let index = 0; index < 6; index += 1) {
    if (offset + 2 > bytes.length) throw sessionError("keyring is truncated");
    const length = new DataView(
      bytes.buffer,
      bytes.byteOffset,
      bytes.byteLength,
    ).getUint16(offset, false);
    offset += 2;
    if (offset + length > bytes.length)
      throw sessionError("keyring is truncated");
    fields.push(bytes.slice(offset, offset + length));
    offset += length;
  }
  if (offset !== bytes.length || fields[5].length !== 32) {
    throw sessionError("keyring does not contain a valid Ed25519 secret key");
  }
  const hasPqPublicKey = fields[2].length > 0;
  const hasPqSecretKey = fields[3].length > 0;
  return {
    bytes,
    hasPqSigningKey: hasPqPublicKey && hasPqSecretKey,
  };
}

function selectedSignatureSuite(
  keyring: ReturnType<typeof serializedKeyring>,
  requested: MTPProtectionSignatureSuite | undefined,
): MTPProtectionSignatureSuite {
  const suite = requested ?? "ed25519";
  if (suite !== "dual" && suite !== "ed25519") {
    throw sessionError("signatureSuite must be 'dual' or 'ed25519'");
  }
  if (suite === "dual" && !keyring.hasPqSigningKey) {
    throw sessionError(
      "dual protected signatures require a complete ML-DSA key pair; choose 'ed25519' for a partial keyring",
    );
  }
  return suite;
}

function asBigInt(value: unknown, name: string): bigint {
  try {
    if (typeof value === "bigint") return value;
    if (typeof value === "number" && Number.isSafeInteger(value))
      return BigInt(value);
    if (typeof value === "string" && value.length > 0) return BigInt(value);
  } catch (error) {
    throw sessionError(`${name} is not an integer`, error);
  }
  throw sessionError(`${name} is not an integer`);
}

function asBytes(value: unknown, name: string): Uint8Array {
  if (value instanceof Uint8Array) return value;
  throw sessionError(`${name} is not binary`);
}

function appendChunk(buffer: Uint8Array, chunk: Uint8Array): Uint8Array {
  if (
    buffer.length > MAX_SESSION_BUFFER ||
    chunk.length > MAX_SESSION_BUFFER - buffer.length
  ) {
    throw sessionError("encrypted pipe session input buffer is too large");
  }
  const combined = new Uint8Array(buffer.length + chunk.length);
  combined.set(buffer);
  combined.set(chunk, buffer.length);
  return combined;
}

async function readSessionOffer(reader: MTPReadablePipe): Promise<{
  offer: Uint8Array;
  remainder: Uint8Array;
}> {
  let buffer: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
  const ensure = async (length: number): Promise<void> => {
    while (buffer.length < length) {
      const chunk = await reader.read();
      if (chunk == null)
        throw sessionError("pipe ended before session setup completed");
      if (!(chunk instanceof Uint8Array))
        throw sessionError("pipe reader returned non-byte data");
      if (chunk.length > 0) buffer = appendChunk(buffer, chunk);
    }
  };

  await ensure(4);
  const offerLength = new DataView(
    buffer.buffer,
    buffer.byteOffset,
    buffer.byteLength,
  ).getUint32(0, false);
  if (offerLength === 0 || offerLength > MAX_PIPE_SESSION_OFFER) {
    throw sessionError(`invalid pipe session offer length: ${offerLength}`);
  }
  await ensure(4 + offerLength);
  return {
    offer: buffer.slice(4, 4 + offerLength),
    remainder: buffer.slice(4 + offerLength),
  };
}

class MTPSessionOfferReader {
  private buffered: Uint8Array<ArrayBufferLike> = new Uint8Array(0);

  constructor(private readonly reader: MTPReadablePipe) {}

  async read(): Promise<Uint8Array> {
    const result = await readSessionOfferWithBuffer(this.reader, this.buffered);
    this.buffered = result.remainder;
    return result.offer;
  }

  remainder(): Uint8Array {
    return this.buffered.slice();
  }
}

async function readSessionOfferWithBuffer(
  reader: MTPReadablePipe,
  initialBuffer: Uint8Array,
): Promise<{ offer: Uint8Array; remainder: Uint8Array }> {
  let buffer: Uint8Array<ArrayBufferLike> = initialBuffer.slice();
  const ensure = async (length: number): Promise<void> => {
    while (buffer.length < length) {
      const chunk = await reader.read();
      if (chunk == null)
        throw sessionError("pipe ended before session setup completed");
      if (!(chunk instanceof Uint8Array)) {
        throw sessionError("pipe reader returned non-byte data");
      }
      if (chunk.length > 0) buffer = appendChunk(buffer, chunk);
    }
  };

  await ensure(4);
  const offerLength = new DataView(
    buffer.buffer,
    buffer.byteOffset,
    buffer.byteLength,
  ).getUint32(0, false);
  if (offerLength === 0 || offerLength > MAX_PIPE_SESSION_OFFER) {
    throw sessionError(`invalid pipe session offer length: ${offerLength}`);
  }
  await ensure(4 + offerLength);
  return {
    offer: buffer.slice(4, 4 + offerLength),
    remainder: buffer.slice(4 + offerLength),
  };
}

async function writeSessionOffer(
  writer: MTPWritablePipe,
  offer: Uint8Array,
): Promise<void> {
  if (offer.length === 0 || offer.length > MAX_PIPE_SESSION_OFFER) {
    throw sessionError(`invalid pipe session offer length: ${offer.length}`);
  }
  const prefix = new Uint8Array(4);
  new DataView(prefix.buffer).setUint32(0, offer.length, false);
  await writer.write(concatBytes([prefix, offer]));
}

function handshakeHash(parts: readonly Uint8Array[]): Uint8Array {
  return bindings.wasm_sha256(
    concatBytes(parts.flatMap((part) => [u32(part.length), part])),
  );
}

function fsCommonFields(params: MTPPipeSessionParameters): unknown[] {
  return [
    params.sessionId,
    BigInt(params.pipeId),
    params.senderId,
    params.recipientId,
    BigInt(params.purpose),
    BigInt(params.direction),
  ];
}

function fsInitValue(
  params: MTPPipeSessionParameters,
  nonce: Uint8Array,
): unknown[] {
  return [FS_INIT_DOMAIN, ...fsCommonFields(params), nonce];
}

function fsResponseValue(
  params: MTPPipeSessionParameters,
  initHash: Uint8Array,
  ephemeralPublicKey: Uint8Array,
): unknown[] {
  return [
    FS_RESPONSE_DOMAIN,
    ...fsCommonFields(params),
    initHash,
    ephemeralPublicKey,
  ];
}

function fsFinishValue(
  params: MTPPipeSessionParameters,
  responseHash: Uint8Array,
  ciphertext: Uint8Array,
): unknown[] {
  return [
    FS_FINISH_DOMAIN,
    ...fsCommonFields(params),
    responseHash,
    ciphertext,
  ];
}

function signHandshakeValue(
  value: unknown,
  signerId: bigint,
  keyring: ReturnType<typeof serializedKeyring>,
  suite: MTPProtectionSignatureSuite,
): Uint8Array {
  return bindings.sign_data_value_with_keyring(
    bindings.encode_data_value(value),
    signerId,
    pipeSessionSignaturePurpose(),
    keyring.bytes,
    suite === "dual"
      ? bindings.mtp_protection_signature_suite_dual()
      : bindings.mtp_protection_signature_suite_ed25519(),
  );
}

function verifiedHandshakeValue(
  encoded: Uint8Array,
  expectedSignerId: bigint,
  senderPublicKey: Uint8Array,
  policy: MTPSignatureVerificationPolicy,
): unknown[] {
  return verifiedHandshakeValueWithKeys(
    encoded,
    expectedSignerId,
    [senderPublicKey],
    policy,
  );
}

function verifiedHandshakeValueWithKeys(
  encoded: Uint8Array,
  expectedSignerId: bigint,
  senderPublicKeys: Uint8Array[],
  policy: MTPSignatureVerificationPolicy,
): unknown[] {
  const errors: unknown[] = [];
  let verified = false;
  for (const senderPublicKey of senderPublicKeys) {
    try {
      verifyDataValueWithPolicy(
        encoded,
        senderPublicKey,
        expectedSignerId,
        pipeSessionSignaturePurpose(),
        policy,
      );
      verified = true;
      break;
    } catch (error) {
      errors.push(error);
    }
  }
  if (!verified) throw signatureVerificationFailure(errors, expectedSignerId);
  const parsed = bindings.parse_data_value(encoded);
  if (
    parsed === null ||
    typeof parsed !== "object" ||
    Array.isArray(parsed) ||
    (parsed as Record<string, unknown>).kind !== "signed"
  ) {
    throw sessionError("forward-secure handshake value is not signed");
  }
  const fields = (parsed as { value?: unknown }).value;
  if (!Array.isArray(fields)) {
    throw sessionError("forward-secure handshake value is not an array");
  }
  return fields;
}

function validateFsCommon(
  fields: unknown[],
  expected: MTPPipeSessionParameters,
  domain: string,
  length: number,
): void {
  if (fields.length !== length || fields[0] !== domain) {
    throw sessionError("forward-secure handshake domain or length mismatch");
  }
  const sessionId = asBytes(fields[1], "sessionId");
  if (
    sessionId.length !== expected.sessionId.length ||
    sessionId.some((byte, index) => byte !== expected.sessionId[index])
  ) {
    throw sessionError("forward-secure handshake session mismatch");
  }
  if (asBigInt(fields[2], "pipeId") !== BigInt(expected.pipeId)) {
    throw sessionError("forward-secure handshake pipe mismatch");
  }
  if (asBigInt(fields[3], "senderId") !== expected.senderId) {
    throw sessionError("forward-secure handshake sender mismatch");
  }
  if (asBigInt(fields[4], "recipientId") !== expected.recipientId) {
    throw sessionError("forward-secure handshake recipient mismatch");
  }
  if (asBigInt(fields[5], "purpose") !== BigInt(expected.purpose)) {
    throw sessionError("forward-secure handshake purpose mismatch");
  }
  if (asBigInt(fields[6], "direction") !== BigInt(expected.direction)) {
    throw sessionError("forward-secure handshake direction mismatch");
  }
}

function forwardSecureContext(
  params: MTPPipeSessionParameters,
  handshakeTranscript: Uint8Array,
): MTPPipeProtectionContext {
  return new MTPPipeProtectionContext(
    params.sessionId,
    params.purpose,
    params.direction,
    bindings.wasm_sha256(
      concatBytes([
        PIPE_TRANSCRIPT_DOMAIN,
        sessionTranscriptHash(params),
        handshakeTranscript,
      ]),
    ),
  );
}

function validateOfferFields(
  signedValue: unknown,
  expected: MTPPipeSessionParameters,
): Uint8Array {
  if (
    signedValue === null ||
    typeof signedValue !== "object" ||
    Array.isArray(signedValue) ||
    (signedValue as Record<string, unknown>).kind !== "signed"
  ) {
    throw sessionError("pipe session offer is not signed");
  }
  const fields = (signedValue as { value?: unknown }).value;
  if (!Array.isArray(fields) || fields.length !== 8) {
    throw sessionError("pipe session offer has invalid fields");
  }
  if (fields[0] !== PIPE_SESSION_OFFER_DOMAIN) {
    throw sessionError("pipe session offer domain mismatch");
  }
  if (asBytes(fields[1], "sessionId").length !== expected.sessionId.length) {
    throw sessionError("pipe session offer session mismatch");
  }
  const sessionId = asBytes(fields[1], "sessionId");
  if (sessionId.some((byte, index) => byte !== expected.sessionId[index])) {
    throw sessionError("pipe session offer session mismatch");
  }
  if (asBigInt(fields[2], "pipeId") !== BigInt(expected.pipeId)) {
    throw sessionError("pipe session offer pipe mismatch");
  }
  if (asBigInt(fields[3], "senderId") !== expected.senderId) {
    throw sessionError("pipe session offer sender mismatch");
  }
  if (asBigInt(fields[4], "recipientId") !== expected.recipientId) {
    throw sessionError("pipe session offer recipient mismatch");
  }
  if (asBigInt(fields[5], "purpose") !== BigInt(expected.purpose)) {
    throw sessionError("pipe session offer purpose mismatch");
  }
  if (asBigInt(fields[6], "direction") !== BigInt(expected.direction)) {
    throw sessionError("pipe session offer direction mismatch");
  }
  const key = asBytes(fields[7], "session key");
  if (key.length !== 32)
    throw sessionError("pipe session offer key is not 32 bytes");
  return key.slice();
}

function senderBundleInputs(
  value: MTPBytesInput | MTPBytesInput[],
): Uint8Array[] {
  const bundles = recipientBundleInputs(value);
  bundles.forEach((bundle) => publicKeyBundleInputs(bundle));
  return bundles;
}

function verifyPipeSessionValue(
  signed: Uint8Array,
  senderBundles: Uint8Array[],
  expectedSignerId: bigint,
  policy: MTPSignatureVerificationPolicy,
): void {
  const errors: unknown[] = [];
  for (const senderBundle of senderBundles) {
    try {
      verifyDataValueWithPolicy(
        signed,
        senderBundle,
        expectedSignerId,
        pipeSessionSignaturePurpose(),
        policy,
      );
      return;
    } catch (error) {
      errors.push(error);
    }
  }
  throw signatureVerificationFailure(errors, expectedSignerId);
}

function sessionIdFromOffer(parsed: unknown): Uint8Array {
  if (
    parsed === null ||
    typeof parsed !== "object" ||
    Array.isArray(parsed) ||
    (parsed as Record<string, unknown>).kind !== "signed"
  ) {
    throw sessionError("pipe session offer is not signed");
  }
  const fields = (parsed as { value?: unknown }).value;
  if (!Array.isArray(fields) || fields.length !== 8) {
    throw sessionError("pipe session offer has invalid fields");
  }
  const sessionId = asBytes(fields[1], "sessionId");
  if (sessionId.length === 0 || sessionId.length > MAX_SESSION_ID) {
    throw sessionError("pipe session offer session ID is invalid");
  }
  return sessionId.slice();
}

/** Send a signed/KEM-protected pipe session offer and return its record writer. */
export async function initiateMTPPipeSession(
  writer: MTPPipeWriter & MTPWritablePipe,
  params: MTPPipeSessionParameters,
  senderKeyring: MTPBytesInput,
  recipientPublicKey: MTPBytesInput | MTPBytesInput[],
  signatureSuite?: MTPProtectionSignatureSuite,
): Promise<MTPEncryptedPipeWriter> {
  const checked = validateSessionParameters(params);
  if (writer.pipeId != null && writer.pipeId !== checked.pipeId) {
    throw sessionError("pipeId does not match the actual writer pipe");
  }
  const recipientBundles = recipientBundleInputs(recipientPublicKey);
  const keyring = serializedKeyring(senderKeyring);
  const suite = selectedSignatureSuite(keyring, signatureSuite);
  const key = new Uint8Array(32);
  globalThis.crypto.getRandomValues(key);
  const payload = bindings.encode_data_value([
    PIPE_SESSION_OFFER_DOMAIN,
    checked.sessionId,
    BigInt(checked.pipeId),
    checked.senderId,
    checked.recipientId,
    checked.purpose,
    checked.direction,
    key,
  ]);
  const signed = bindings.sign_data_value_with_keyring(
    payload,
    checked.senderId,
    pipeSessionSignaturePurpose(),
    keyring.bytes,
    suite === "dual"
      ? bindings.mtp_protection_signature_suite_dual()
      : bindings.mtp_protection_signature_suite_ed25519(),
  );
  const encrypted = bindings.encrypt_data_value_for_recipients(
    signed,
    recipientBundles,
    pipeSessionEncryptionPurpose(),
  );
  if (encrypted.length > MAX_PIPE_SESSION_OFFER) {
    throw sessionError(`pipe session offer is too large: ${encrypted.length}`);
  }
  const prefix = new Uint8Array(4);
  new DataView(prefix.buffer).setUint32(0, encrypted.length, false);
  try {
    await writer.write(concatBytes([prefix, encrypted]));
    return new MTPEncryptedPipeWriter(
      writer,
      key,
      contextForSessionParameters(checked),
    );
  } catch (error) {
    key.fill(0);
    throw sessionError("failed to write pipe session offer", error);
  } finally {
    key.fill(0);
  }
}

/** Read and verify a pipe session offer, then return its record reader. */
export async function acceptMTPPipeSession(
  reader: MTPPipeReader & MTPReadablePipe,
  params: MTPPipeSessionParameters,
  recipientKeyring: MTPBytesInput,
  senderPublicKey: MTPBytesInput | MTPBytesInput[],
  signaturePolicy?: MTPSignatureVerificationPolicy,
): Promise<MTPEncryptedPipeReader> {
  const checked = validateSessionParameters(params);
  if (reader.pipeId != null && reader.pipeId !== checked.pipeId) {
    throw sessionError("pipeId does not match the actual reader pipe");
  }
  const { offer, remainder } = await readSessionOffer(reader);
  const signed = bindings.decrypt_data_value(
    offer,
    bytesInput(recipientKeyring, "recipientKeyring"),
    pipeSessionEncryptionPurpose(),
  );
  const senderBundles = senderBundleInputs(senderPublicKey);
  const policy = resolveSignatureVerificationPolicy(signaturePolicy);
  verifyPipeSessionValue(signed, senderBundles, checked.senderId, policy);
  const parsed = bindings.parse_data_value(signed);
  const key = validateOfferFields(parsed, checked);
  const result = new MTPEncryptedPipeReader(
    reader,
    key,
    contextForSessionParameters(checked),
    remainder,
  );
  key.fill(0);
  return result;
}

/**
 * Accept a pipe session without making the caller copy the sender's random
 * session ID out of band. The ID is learned only after recipient decryption
 * and signature verification, then all record context uses that ID.
 */
export async function acceptMTPPipeSessionAuto(
  reader: MTPPipeReader & MTPReadablePipe,
  expected: MTPPipeSessionExpectation,
  recipientKeyring: MTPBytesInput,
  senderPublicKey: MTPBytesInput | MTPBytesInput[],
  signaturePolicy?: MTPSignatureVerificationPolicy,
): Promise<MTPEncryptedPipeReader> {
  if (reader.pipeId != null && reader.pipeId !== expected.pipeId) {
    throw sessionError("pipeId does not match the actual reader pipe");
  }
  const { offer, remainder } = await readSessionOffer(reader);
  const signed = bindings.decrypt_data_value(
    offer,
    bytesInput(recipientKeyring, "recipientKeyring"),
    pipeSessionEncryptionPurpose(),
  );
  const senderBundles = senderBundleInputs(senderPublicKey);
  const policy = resolveSignatureVerificationPolicy(signaturePolicy);
  verifyPipeSessionValue(signed, senderBundles, expected.senderId, policy);
  const parsed = bindings.parse_data_value(signed);
  const sessionId = sessionIdFromOffer(parsed);
  const checked = validateSessionParameters({ ...expected, sessionId });
  const key = validateOfferFields(parsed, checked);
  const result = new MTPEncryptedPipeReader(
    reader,
    key,
    contextForSessionParameters(checked),
    remainder,
  );
  key.fill(0);
  return result;
}

/**
 * Establish a forward-secure encrypted pipe over a bidirectional transport.
 *
 * The responder contributes a fresh ephemeral hybrid-KEM key. Long-term
 * identity keys authenticate the three-message exchange, but are not used to
 * encrypt the resulting record chain, so later compromise of a long-term KEM
 * key does not recover recorded sessions.
 */
export async function initiateMTPForwardSecurePipeSession(
  stream: MTPDuplexPipe,
  params: MTPPipeSessionParameters,
  senderKeyring: MTPBytesInput,
  recipientPublicKey: MTPBytesInput,
  signatureSuite?: MTPProtectionSignatureSuite,
  signaturePolicy?: MTPSignatureVerificationPolicy,
): Promise<MTPEncryptedPipeWriter> {
  const checked = validateSessionParameters(params);
  if (stream.pipeId != null && stream.pipeId !== checked.pipeId) {
    throw sessionError("pipeId does not match the actual duplex pipe");
  }
  const recipientBundle = bytesInput(recipientPublicKey, "recipientPublicKey");
  publicKeyBundleInputs(recipientBundle);
  const keyring = serializedKeyring(senderKeyring);
  const suite = selectedSignatureSuite(keyring, signatureSuite);
  const policy = resolveSignatureVerificationPolicy(signaturePolicy);
  const nonce = new Uint8Array(32);
  globalThis.crypto.getRandomValues(nonce);
  const initBytes = signHandshakeValue(
    fsInitValue(checked, nonce),
    checked.senderId,
    keyring,
    suite,
  );
  await writeSessionOffer(stream, initBytes);

  const offerReader = new MTPSessionOfferReader(stream);
  const responseBytes = await offerReader.read();
  const responseFields = verifiedHandshakeValue(
    responseBytes,
    checked.recipientId,
    recipientBundle,
    policy,
  );
  validateFsCommon(responseFields, checked, FS_RESPONSE_DOMAIN, 9);
  const initHash = handshakeHash([initBytes]);
  const receivedInitHash = asBytes(responseFields[7], "initHash");
  if (
    receivedInitHash.length !== initHash.length ||
    receivedInitHash.some((byte, index) => byte !== initHash[index])
  ) {
    throw sessionError("forward-secure handshake init transcript mismatch");
  }
  const ephemeralPublicKey = asBytes(responseFields[8], "ephemeralPublicKey");
  let encapsulated:
    ReturnType<typeof bindings.wasm_kem_encapsulate> | undefined;
  try {
    encapsulated = bindings.wasm_kem_encapsulate(ephemeralPublicKey);
    const ciphertext = encapsulated.ciphertext;
    const finishBytes = signHandshakeValue(
      fsFinishValue(checked, handshakeHash([responseBytes]), ciphertext),
      checked.senderId,
      keyring,
      suite,
    );
    await writeSessionOffer(stream, finishBytes);
    const handshakeTranscript = handshakeHash([
      initBytes,
      responseBytes,
      finishBytes,
    ]);
    const chainKey = encapsulated.shared_secret;
    const recordKey = bindings.wasm_hkdf_expand(
      chainKey,
      handshakeTranscript,
      FS_ROOT_INFO,
      32,
    );
    try {
      return new MTPEncryptedPipeWriter(
        stream,
        recordKey,
        forwardSecureContext(checked, handshakeTranscript),
      );
    } finally {
      chainKey.fill(0);
      recordKey.fill(0);
    }
  } catch (error) {
    if (error instanceof MTPSignatureVerificationError) throw error;
    throw sessionError("forward-secure pipe handshake failed", error);
  } finally {
    encapsulated?.free();
    nonce.fill(0);
  }
}

/**
 * Accept the forward-secure handshake. The session ID is learned from the
 * authenticated initiator message; the remaining endpoint and pipe fields
 * are supplied as the pre-decryption expectation.
 */
export async function acceptMTPForwardSecurePipeSession(
  stream: MTPDuplexPipe,
  expected: MTPPipeSessionExpectation,
  recipientKeyring: MTPBytesInput,
  senderPublicKey: MTPBytesInput | MTPBytesInput[],
  signatureSuite?: MTPProtectionSignatureSuite,
  signaturePolicy?: MTPSignatureVerificationPolicy,
): Promise<MTPEncryptedPipeReader> {
  if (stream.pipeId != null && stream.pipeId !== expected.pipeId) {
    throw sessionError("pipeId does not match the actual duplex pipe");
  }
  const recipientKeys = serializedKeyring(recipientKeyring);
  const suite = selectedSignatureSuite(recipientKeys, signatureSuite);
  const policy = resolveSignatureVerificationPolicy(signaturePolicy);
  const senderBundles = senderBundleInputs(senderPublicKey);
  const offerReader = new MTPSessionOfferReader(stream);
  const initBytes = await offerReader.read();
  const initFields = verifiedHandshakeValueWithKeys(
    initBytes,
    expected.senderId,
    senderBundles,
    policy,
  );
  if (initFields.length !== 8 || initFields[0] !== FS_INIT_DOMAIN) {
    throw sessionError("forward-secure init message is malformed");
  }
  const sessionId = asBytes(initFields[1], "sessionId");
  const checked = validateSessionParameters({ ...expected, sessionId });
  validateFsCommon(initFields, checked, FS_INIT_DOMAIN, 8);
  const nonce = asBytes(initFields[7], "nonce");
  if (nonce.length !== 32)
    throw sessionError("forward-secure nonce is not 32 bytes");

  const ephemeral = bindings.wasm_kem_generate_keypair();
  try {
    const responseBytes = signHandshakeValue(
      fsResponseValue(
        checked,
        handshakeHash([initBytes]),
        ephemeral.public_key,
      ),
      checked.recipientId,
      recipientKeys,
      suite,
    );
    await writeSessionOffer(stream, responseBytes);
    const finishBytes = await offerReader.read();
    const finishFields = verifiedHandshakeValueWithKeys(
      finishBytes,
      checked.senderId,
      senderBundles,
      policy,
    );
    validateFsCommon(finishFields, checked, FS_FINISH_DOMAIN, 9);
    const responseHash = handshakeHash([responseBytes]);
    const receivedResponseHash = asBytes(finishFields[7], "responseHash");
    if (
      receivedResponseHash.length !== responseHash.length ||
      receivedResponseHash.some((byte, index) => byte !== responseHash[index])
    ) {
      throw sessionError(
        "forward-secure handshake response transcript mismatch",
      );
    }
    const sharedSecret = bindings.wasm_kem_decapsulate(
      ephemeral.secret_key,
      asBytes(finishFields[8], "ciphertext"),
    );
    const handshakeTranscript = handshakeHash([
      initBytes,
      responseBytes,
      finishBytes,
    ]);
    const recordKey = bindings.wasm_hkdf_expand(
      sharedSecret,
      handshakeTranscript,
      FS_ROOT_INFO,
      32,
    );
    try {
      return new MTPEncryptedPipeReader(
        stream,
        recordKey,
        forwardSecureContext(checked, handshakeTranscript),
        offerReader.remainder(),
      );
    } finally {
      sharedSecret.fill(0);
      recordKey.fill(0);
    }
  } catch (error) {
    if (error instanceof MTPSignatureVerificationError) throw error;
    throw sessionError("forward-secure pipe handshake failed", error);
  } finally {
    ephemeral.free();
  }
}

/** Encrypts ordered records on top of a negotiated MTP pipe. */
export class MTPEncryptedPipeWriter {
  readonly pipeId?: number;
  private chainKey: Uint8Array;
  private readonly context: MTPPipeProtectionContext;
  private sequence = 0n;
  private writeChain: Promise<void> = Promise.resolve();
  private state: "open" | "finalized" | "failed" = "open";

  constructor(
    private readonly writer: MTPWritablePipe,
    key: Uint8Array,
    context: MTPPipeProtectionContext,
  ) {
    this.chainKey = keyBytes(key);
    this.context = context;
    this.pipeId = (writer as MTPPipeWriter).pipeId;
  }

  get sequenceNumber(): bigint {
    return this.sequence;
  }

  writeRecord(plaintext: Uint8Array): Promise<void> {
    if (!(plaintext instanceof Uint8Array)) {
      return Promise.reject(new TypeError("pipe record must be a Uint8Array"));
    }
    if (this.state !== "open") {
      return Promise.reject(
        new MTPEncryptedPipeError(
          "state",
          "encrypted pipe is no longer writable",
        ),
      );
    }
    const input = plaintext.slice();
    const operation = this.writeChain.then(() =>
      this.writeRecordInternal(input),
    );
    this.writeChain = operation
      .catch((error) => {
        this.poison();
        throw error;
      })
      .catch(() => undefined);
    return operation;
  }

  private async writeRecordInternal(
    plaintext: Uint8Array,
    recordType = RECORD_TYPE_DATA,
  ): Promise<void> {
    if (this.state !== "open") {
      throw new MTPEncryptedPipeError(
        "state",
        "encrypted pipe is no longer writable",
      );
    }
    if (this.sequence === 0xffff_ffff_ffff_ffffn) {
      throw new MTPEncryptedPipeError(
        "sequence",
        "encrypted pipe sequence exhausted",
      );
    }
    const encodedLength = recordLength(plaintext.length);
    const { messageKey, nextChainKey } = deriveRecordKeys(
      this.chainKey,
      this.context,
      this.sequence,
    );
    let committed = false;
    let ciphertext: Uint8Array;
    try {
      try {
        const cipher = new bindings.WasmChaCha20Poly1305(messageKey);
        try {
          ciphertext = cipher.encrypt(
            plaintext,
            aad(this.context, this.sequence, encodedLength, recordType),
          );
        } finally {
          cipher.free();
        }
      } catch (error) {
        throw new MTPEncryptedPipeError(
          "authentication",
          "encrypted pipe record encryption failed",
          { cause: error },
        );
      }
      if (ciphertext.length !== encodedLength) {
        throw new MTPEncryptedPipeError(
          "record-length",
          `encrypted pipe cipher returned ${ciphertext.length} bytes, expected ${encodedLength}`,
        );
      }
      const prefix = new Uint8Array(4);
      new DataView(prefix.buffer).setUint32(0, encodedLength, false);
      try {
        await this.writer.write(
          concatBytes([prefix, new Uint8Array([recordType]), ciphertext]),
        );
      } catch (error) {
        throw new MTPEncryptedPipeError("io", "encrypted pipe write failed", {
          cause: error,
        });
      }
      this.chainKey.fill(0);
      this.chainKey = nextChainKey;
      this.sequence += 1n;
      committed = true;
    } finally {
      messageKey.fill(0);
      if (!committed) nextChainKey.fill(0);
    }
  }

  async close(): Promise<void> {
    if (this.state !== "open") {
      throw new MTPEncryptedPipeError(
        "state",
        "encrypted pipe is no longer open",
      );
    }
    const operation = this.writeChain.then(async () => {
      await this.writeRecordInternal(new Uint8Array(0), RECORD_TYPE_FINAL);
      this.state = "finalized";
      try {
        await this.writer.close();
      } catch (error) {
        throw new MTPEncryptedPipeError("io", "encrypted pipe close failed", {
          cause: error,
        });
      }
    });
    this.writeChain = operation
      .catch((error) => {
        this.poison();
        throw error;
      })
      .catch(() => undefined);
    await operation;
  }

  abort(): void {
    this.poison();
    this.writer.abort();
  }

  private poison(): void {
    this.chainKey.fill(0);
    this.state = "failed";
  }
}

/** Reads and authenticates ordered records on top of a negotiated MTP pipe. */
export class MTPEncryptedPipeReader {
  private chainKey: Uint8Array;
  private readonly context: MTPPipeProtectionContext;
  private sequence = 0n;
  private buffered = new Uint8Array(0);
  private ended = false;
  private readChain: Promise<void> = Promise.resolve();
  private state: "open" | "finalized" | "failed" = "open";

  constructor(
    private readonly reader: MTPReadablePipe,
    key: Uint8Array,
    context: MTPPipeProtectionContext,
    initialBuffer: Uint8Array = new Uint8Array(0),
  ) {
    this.chainKey = keyBytes(key);
    this.context = context;
    this.buffered = initialBuffer.slice();
  }

  get sequenceNumber(): bigint {
    return this.sequence;
  }

  private append(chunk: Uint8Array): void {
    if (this.buffered.length + chunk.length > MAX_PIPE_BUFFER) {
      throw new MTPEncryptedPipeError(
        "record-length",
        "encrypted pipe input buffer is too large",
      );
    }
    const combined = new Uint8Array(this.buffered.length + chunk.length);
    combined.set(this.buffered);
    combined.set(chunk, this.buffered.length);
    this.buffered = combined;
  }

  private async ensure(length: number): Promise<boolean> {
    while (this.buffered.length < length && !this.ended) {
      let chunk: Uint8Array | null;
      try {
        chunk = await this.reader.read();
      } catch (error) {
        throw new MTPEncryptedPipeError("io", "encrypted pipe read failed", {
          cause: error,
        });
      }
      if (chunk == null) {
        this.ended = true;
        break;
      }
      if (!(chunk instanceof Uint8Array)) {
        throw new MTPEncryptedPipeError(
          "io",
          "pipe reader returned a non-byte chunk",
        );
      }
      if (chunk.length > 0) this.append(chunk);
    }
    return this.buffered.length >= length;
  }

  readRecord(): Promise<Uint8Array | null> {
    if (this.state === "finalized") return Promise.resolve(null);
    if (this.state === "failed") {
      return Promise.reject(
        new MTPEncryptedPipeError(
          "state",
          "encrypted pipe is no longer readable",
        ),
      );
    }
    const operation = this.readChain.then(() => this.readRecordInternal());
    this.readChain = operation
      .catch((error) => {
        this.poison();
        throw error;
      })
      .then(
        () => undefined,
        () => undefined,
      );
    return operation;
  }

  private async readRecordInternal(): Promise<Uint8Array | null> {
    if (this.state !== "open") {
      if (this.state === "finalized") return null;
      throw new MTPEncryptedPipeError(
        "state",
        "encrypted pipe is no longer readable",
      );
    }
    if (this.sequence === 0xffff_ffff_ffff_ffffn) {
      throw new MTPEncryptedPipeError(
        "sequence",
        "encrypted pipe sequence exhausted",
      );
    }
    if (!(await this.ensure(4))) {
      throw new MTPEncryptedPipeError(
        "truncated",
        "encrypted pipe ended without an authenticated final record",
      );
    }
    const encodedLength = new DataView(
      this.buffered.buffer,
      this.buffered.byteOffset,
      this.buffered.byteLength,
    ).getUint32(0, false);
    if (
      encodedLength < XCHACHA_OVERHEAD ||
      encodedLength > MAX_ENCRYPTED_PIPE_RECORD
    ) {
      throw new MTPEncryptedPipeError(
        "record-length",
        `invalid encrypted pipe record length: ${encodedLength}`,
      );
    }
    const totalLength = 5 + encodedLength;
    if (!(await this.ensure(totalLength))) {
      throw new MTPEncryptedPipeError(
        "truncated",
        "truncated encrypted pipe record",
      );
    }
    const recordType = this.buffered[4];
    if (recordType !== RECORD_TYPE_DATA && recordType !== RECORD_TYPE_FINAL) {
      throw new MTPEncryptedPipeError(
        "record-length",
        `invalid encrypted pipe record type: ${recordType}`,
      );
    }
    const ciphertext = this.buffered.slice(5, totalLength);
    this.buffered = this.buffered.slice(totalLength);
    const { messageKey, nextChainKey } = deriveRecordKeys(
      this.chainKey,
      this.context,
      this.sequence,
    );
    let committed = false;
    let plaintext: Uint8Array;
    try {
      try {
        const cipher = new bindings.WasmChaCha20Poly1305(messageKey);
        try {
          plaintext = cipher.decrypt(
            ciphertext,
            aad(this.context, this.sequence, encodedLength, recordType),
          );
        } finally {
          cipher.free();
        }
      } catch (error) {
        throw new MTPEncryptedPipeError(
          "authentication",
          "encrypted pipe record authentication failed",
          { cause: error },
        );
      }
      this.chainKey.fill(0);
      this.chainKey = nextChainKey;
      this.sequence += 1n;
      committed = true;
      if (recordType === RECORD_TYPE_FINAL) {
        if (plaintext.length !== 0) {
          throw new MTPEncryptedPipeError(
            "record-length",
            "encrypted pipe final record must be empty",
          );
        }
        this.state = "finalized";
        return null;
      }
      return plaintext;
    } finally {
      messageKey.fill(0);
      if (!committed) nextChainKey.fill(0);
    }
  }

  private poison(): void {
    this.chainKey.fill(0);
    this.state = "failed";
  }
}

export type MTPEncryptedPipeWriterSource = MTPPipeWriter & MTPWritablePipe;
export type MTPEncryptedPipeReaderSource = MTPPipeReader & MTPReadablePipe;
