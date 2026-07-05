import * as bindings from "mtp/raw";
import { MTPRatchet } from "./ratchet.js";
import type { MTPSessionState } from "./session";

export const MTP_E2EE_VERSION = 1;
export const FLAG_INIT = 0x01;
export const FLAG_DEVICE_SECRET = 0x02;
export const FLAG_KEY_ROTATION = 0x04;
export const MAX_RATCHET_SKIP = 100;
const SUPPORTED_FLAGS = FLAG_INIT | FLAG_DEVICE_SECRET | FLAG_KEY_ROTATION;
const HEADER_FIXED_LEN = 1 + 1 + 8 + 8 + 4 + 2 + 4;

export interface ParsedEncryptedMessage {
  version: 1;
  flags: number;
  senderClientId: bigint;
  recipientClientId: bigint;
  messageNumber: number;
  kemCiphertext?: Uint8Array;
  ciphertext: Uint8Array;
  /** Compatibility alias for older SDK tests/callers. */
  header?: EncryptedMessageHeader;
  /** Compatibility alias for older SDK tests/callers. */
  aeadPayload?: Uint8Array;
}

export interface EncryptedMessageHeader {
  version: 1;
  flags: number;
  senderClientId: bigint;
  recipientClientId: bigint;
  messageNumber: number;
  kemCiphertext?: Uint8Array;
}
export interface SerializedEncryptedMessage {
  header: EncryptedMessageHeader;
  aeadPayload: Uint8Array;
}

function writeU64BE(value: bigint): Uint8Array {
  if (value < 0n || value > 0xffff_ffff_ffff_ffffn) {
    throw new Error("u64 value out of range");
  }
  const buf = new Uint8Array(8);
  for (let i = 7; i >= 0; i--) {
    buf[i] = Number(value & 0xffn);
    value >>= 8n;
  }
  return buf;
}

function readU64BE(bytes: Uint8Array, offset: number): bigint {
  let value = 0n;
  for (let i = 0; i < 8; i++) {
    value = (value << 8n) | BigInt(bytes[offset + i]);
  }
  return value;
}

function writeU32BE(value: number): Uint8Array {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffff_ffff) {
    throw new Error("u32 value out of range");
  }
  return new Uint8Array([
    (value >>> 24) & 0xff,
    (value >>> 16) & 0xff,
    (value >>> 8) & 0xff,
    value & 0xff,
  ]);
}

function concatBytes(parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function assertSupported(message: ParsedEncryptedMessage): void {
  if (message.version !== MTP_E2EE_VERSION) {
    throw new Error(
      `Unsupported encrypted message version: ${message.version}`,
    );
  }
  if ((message.flags & ~SUPPORTED_FLAGS) !== 0) {
    throw new Error(`Unsupported encrypted message flags: ${message.flags}`);
  }
  const isInit = (message.flags & FLAG_INIT) !== 0;
  if (isInit && !message.kemCiphertext?.length) {
    throw new Error("Init message must include KEM ciphertext");
  }
  if (!isInit && message.kemCiphertext?.length) {
    throw new Error("Non-init message must not include KEM ciphertext");
  }
  if (!message.ciphertext.length) {
    throw new Error("Encrypted message ciphertext must be non-empty");
  }
}

export function serializeEncryptedMessage(
  message: ParsedEncryptedMessage,
): Uint8Array;
export function serializeEncryptedMessage(
  message: SerializedEncryptedMessage,
): Uint8Array;
export function serializeEncryptedMessage(
  message: ParsedEncryptedMessage | SerializedEncryptedMessage,
): Uint8Array {
  const normalized: ParsedEncryptedMessage =
    "header" in message
      ? {
          ...message.header,
          ciphertext: message.aeadPayload,
        }
      : message;

  assertSupported(normalized);
  const kemCiphertext = normalized.kemCiphertext ?? new Uint8Array(0);
  if (kemCiphertext.length > 0xffff) {
    throw new Error("KEM ciphertext too long");
  }

  return concatBytes([
    new Uint8Array([normalized.version]),
    new Uint8Array([normalized.flags]),
    writeU64BE(normalized.senderClientId),
    writeU64BE(normalized.recipientClientId),
    writeU32BE(normalized.messageNumber),
    new Uint8Array([
      (kemCiphertext.length >>> 8) & 0xff,
      kemCiphertext.length & 0xff,
    ]),
    kemCiphertext,
    writeU32BE(normalized.ciphertext.length),
    normalized.ciphertext,
  ]);
}

export function parseEncryptedMessage(
  bytes: Uint8Array,
): ParsedEncryptedMessage {
  let offset = 0;
  if (!(bytes instanceof Uint8Array)) {
    throw new Error("Encrypted message must be bytes");
  }
  if (bytes.length < HEADER_FIXED_LEN) {
    throw new Error("Encrypted message too short");
  }

  const version = bytes[offset++];
  const flags = bytes[offset++];
  const senderClientId = readU64BE(bytes, offset);
  offset += 8;
  const recipientClientId = readU64BE(bytes, offset);
  offset += 8;
  const messageNumber =
    ((bytes[offset] << 24) |
      (bytes[offset + 1] << 16) |
      (bytes[offset + 2] << 8) |
      bytes[offset + 3]) >>>
    0;
  offset += 4;
  const kemLen = (bytes[offset] << 8) | bytes[offset + 1];
  offset += 2;

  let kemCiphertext: Uint8Array | undefined;
  if (kemLen > 0) {
    if (bytes.length < offset + kemLen + 4) {
      throw new Error("Encrypted message KEM ciphertext truncated");
    }
    kemCiphertext = bytes.slice(offset, offset + kemLen);
    offset += kemLen;
  }

  if (bytes.length < offset + 4) {
    throw new Error("Encrypted message missing ciphertext length");
  }
  const ciphertextLen =
    ((bytes[offset] << 24) |
      (bytes[offset + 1] << 16) |
      (bytes[offset + 2] << 8) |
      bytes[offset + 3]) >>>
    0;
  offset += 4;
  if (bytes.length < offset + ciphertextLen) {
    throw new Error("Encrypted message ciphertext truncated");
  }
  const ciphertext = bytes.slice(offset, offset + ciphertextLen);
  offset += ciphertextLen;
  if (offset !== bytes.length) {
    throw new Error("Encrypted message has trailing data");
  }

  const parsed: ParsedEncryptedMessage = {
    version: version as 1,
    flags,
    senderClientId,
    recipientClientId,
    messageNumber,
    kemCiphertext,
    ciphertext,
  };
  parsed.header = {
    version: parsed.version,
    flags: parsed.flags,
    senderClientId: parsed.senderClientId,
    recipientClientId: parsed.recipientClientId,
    messageNumber: parsed.messageNumber,
    kemCiphertext: parsed.kemCiphertext,
  };
  parsed.aeadPayload = parsed.ciphertext;
  assertSupported(parsed);
  return parsed;
}

function buildAAD(header: EncryptedMessageHeader): Uint8Array {
  return concatBytes([
    new Uint8Array([header.version]),
    new Uint8Array([header.flags]),
    writeU64BE(header.senderClientId),
    writeU64BE(header.recipientClientId),
    writeU32BE(header.messageNumber),
  ]);
}

export function encryptedMessageAAD(
  header: EncryptedMessageHeader,
  extra?: Uint8Array,
): Uint8Array {
  return extra?.length
    ? concatBytes([buildAAD(header), extra])
    : buildAAD(header);
}

export async function encryptPayload(args: {
  plaintext: Uint8Array;
  session: MTPSessionState;
  kemCiphertext?: Uint8Array;
  aad?: Uint8Array;
}): Promise<{
  payload: Uint8Array;
  session: MTPSessionState;
}> {
  const step = await MTPRatchet.stepSend(args.session.sendChainKey);
  const header: EncryptedMessageHeader = {
    version: 1,
    flags: args.kemCiphertext ? FLAG_INIT : 0,
    senderClientId: args.session.ownClientId,
    recipientClientId: args.session.peerClientId,
    messageNumber: args.session.sendCount,
    kemCiphertext: args.kemCiphertext,
  };
  const aad = args.aad ?? encryptedMessageAAD(header);
  const cipher = new bindings.WasmChaCha20Poly1305(step.key);
  let ciphertext: Uint8Array;
  try {
    ciphertext = cipher.encrypt(args.plaintext, aad);
  } finally {
    cipher.free();
    step.key.fill(0);
  }

  const payload = serializeEncryptedMessage({ ...header, ciphertext });
  return {
    payload,
    session: {
      ...args.session,
      sendChainKey: step.chainKey,
      sendCount: args.session.sendCount + 1,
      updatedAt: Date.now(),
    },
  };
}

export async function decryptPayload(args: {
  payload: Uint8Array;
  session: MTPSessionState;
  expectedRecipientClientId?: bigint;
  aad?: Uint8Array;
}): Promise<{
  plaintext: Uint8Array;
  session: MTPSessionState;
}> {
  const parsed = parseEncryptedMessage(args.payload);
  const expectedRecipientClientId =
    args.expectedRecipientClientId ?? args.session.ownClientId;
  if (parsed.recipientClientId !== expectedRecipientClientId) {
    throw new Error("Encrypted message recipient mismatch");
  }
  if (parsed.senderClientId !== args.session.peerClientId) {
    throw new Error("Encrypted message sender mismatch");
  }
  if (parsed.messageNumber < args.session.recvCount) {
    throw new Error("Encrypted message replay or out-of-order message number");
  }

  let chainKey = args.session.recvChainKey;
  let messageKey: Uint8Array | undefined;
  const gap = parsed.messageNumber - args.session.recvCount;
  if (gap > MAX_RATCHET_SKIP) {
    throw new Error(
      `Encrypted message receive gap exceeds max skip (${MAX_RATCHET_SKIP})`,
    );
  }

  const steps = gap + 1;
  for (let i = 0; i < steps; i += 1) {
    const step = await MTPRatchet.stepRecv(chainKey);
    if (i === steps - 1) {
      messageKey = step.key;
    } else {
      step.key.fill(0);
    }
    if (chainKey !== args.session.recvChainKey) chainKey.fill(0);
    chainKey = step.chainKey;
  }
  if (!messageKey) {
    throw new Error("Failed to derive receive message key");
  }

  const header: EncryptedMessageHeader = {
    version: parsed.version,
    flags: parsed.flags,
    senderClientId: parsed.senderClientId,
    recipientClientId: parsed.recipientClientId,
    messageNumber: parsed.messageNumber,
    kemCiphertext: parsed.kemCiphertext,
  };
  const aad = args.aad ?? encryptedMessageAAD(header);
  const cipher = new bindings.WasmChaCha20Poly1305(messageKey);
  let plaintext: Uint8Array;
  try {
    plaintext = cipher.decrypt(parsed.ciphertext, aad);
  } finally {
    cipher.free();
    messageKey.fill(0);
  }

  return {
    plaintext,
    session: {
      ...args.session,
      recvChainKey: chainKey,
      recvCount: parsed.messageNumber + 1,
      updatedAt: Date.now(),
    },
  };
}
