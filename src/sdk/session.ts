import * as bindings from "mtp/raw";
import { concatBytes, utf8Encode, writeU64BE } from "./utils.js";

export const HKDF_SALT_ROOT = "mtp-e2ee-v1-root";
const HKDF_INITIATOR_SEND = "mtp-e2ee-v1-initiator-send";
const HKDF_INITIATOR_RECV = "mtp-e2ee-v1-initiator-recv";
const SESSION_TRANSCRIPT_DOMAIN = "mtp-e2ee-session-transcript-v1";

export interface MTPSessionTranscriptContext {
  /** Application-selected identity for this stateful MTP session. */
  sessionId: string;
  /** MTP identity that initiated key establishment. */
  initiatorId: bigint;
  /** MTP identity that receives the key-establishment message. */
  recipientId: bigint;
  /** Public key used by the recipient for this key establishment. */
  recipientPublicKey: Uint8Array;
  /** KEM ciphertext used by the key establishment. */
  kemCiphertext: Uint8Array;
  /** Opaque, application-owned context included by hash only. */
  applicationContext?: Uint8Array;
}

export interface MTPSessionState {
  version: 1;
  sessionId: string;
  localId: bigint;
  remoteId: bigint;
  remotePublicKey: Uint8Array;
  sendChainKey: Uint8Array;
  recvChainKey: Uint8Array;
  sendCount: number;
  recvCount: number;
  /** Derived receive keys retained for bounded out-of-order delivery. */
  skippedMessageKeys?: SkippedMessageKey[];
  createdAt: number;
  updatedAt: number;
}

export interface SkippedMessageKey {
  messageNumber: number;
  key: Uint8Array;
}

export interface MTPSessionStorage {
  getSession(sessionId: string): Promise<MTPSessionState | null>;
  setSession(state: MTPSessionState): Promise<void>;
  deleteSession(sessionId: string): Promise<void>;
}

function requireSessionId(sessionId: string): string {
  if (typeof sessionId !== "string" || sessionId.length === 0) {
    throw new TypeError("sessionId must be a non-empty string");
  }
  return sessionId;
}

function requireMtpId(id: bigint, name: string): bigint {
  if (typeof id !== "bigint") {
    throw new TypeError(`${name} must be a bigint`);
  }
  // Validate the range once at the API boundary. The returned value is still
  // the original bigint so callers do not observe a representation change.
  writeU64BE(id);
  return id;
}

export class InMemorySessionStorage implements MTPSessionStorage {
  private store = new Map<string, MTPSessionState>();

  private cloneSession(state: MTPSessionState): MTPSessionState {
    return {
      ...state,
      remotePublicKey: state.remotePublicKey.slice(),
      sendChainKey: state.sendChainKey.slice(),
      recvChainKey: state.recvChainKey.slice(),
      skippedMessageKeys: (state.skippedMessageKeys ?? []).map((skipped) => ({
        messageNumber: skipped.messageNumber,
        key: skipped.key.slice(),
      })),
    };
  }

  private zeroizeSession(state: MTPSessionState): void {
    state.sendChainKey.fill(0);
    state.recvChainKey.fill(0);
    for (const skipped of state.skippedMessageKeys ?? []) skipped.key.fill(0);
  }

  async getSession(sessionId: string): Promise<MTPSessionState | null> {
    const state = this.store.get(requireSessionId(sessionId));
    return state ? this.cloneSession(state) : null;
  }

  async setSession(state: MTPSessionState): Promise<void> {
    const sessionId = requireSessionId(state.sessionId);
    const replacement = this.cloneSession(state);
    const previous = this.store.get(sessionId);
    if (previous) this.zeroizeSession(previous);
    this.store.set(sessionId, replacement);
  }

  async deleteSession(sessionId: string): Promise<void> {
    const key = requireSessionId(sessionId);
    const previous = this.store.get(key);
    if (previous) this.zeroizeSession(previous);
    this.store.delete(key);
  }
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

function transcriptField(label: string, value: Uint8Array): Uint8Array {
  const labelBytes = utf8Encode(label);
  return concatBytes([
    writeU32BE(labelBytes.length),
    labelBytes,
    writeU32BE(value.length),
    value,
  ]);
}

/**
 * Build a length-delimited transcript for one MTP session.
 *
 * Application context is intentionally hashed as an opaque byte string. MTP
 * therefore provides domain separation without parsing or naming any fields
 * owned by the consuming application.
 */
export function buildSessionTranscript(
  args: MTPSessionTranscriptContext,
): Uint8Array {
  const sessionId = requireSessionId(args.sessionId);
  const initiatorId = requireMtpId(args.initiatorId, "initiatorId");
  const recipientId = requireMtpId(args.recipientId, "recipientId");
  const recipientPublicKeyHash = bindings.wasm_sha256(args.recipientPublicKey);
  const kemHash = bindings.wasm_sha256(args.kemCiphertext);
  const applicationContextHash = bindings.wasm_sha256(
    args.applicationContext ?? new Uint8Array(0),
  );

  return concatBytes([
    transcriptField("domain", utf8Encode(SESSION_TRANSCRIPT_DOMAIN)),
    transcriptField("version", utf8Encode("1")),
    transcriptField("sessionId", utf8Encode(sessionId)),
    transcriptField("initiatorId", writeU64BE(initiatorId)),
    transcriptField("recipientId", writeU64BE(recipientId)),
    transcriptField("recipientPublicKeyHash", recipientPublicKeyHash),
    transcriptField("kemCiphertextHash", kemHash),
    transcriptField("applicationContextHash", applicationContextHash),
  ]);
}

export async function deriveSessionKeys(
  sharedSecret: Uint8Array,
  transcript: Uint8Array = new Uint8Array(0),
): Promise<{
  root: Uint8Array;
  initiatorSend: Uint8Array;
  initiatorRecv: Uint8Array;
}> {
  const rootInfo = concatBytes([utf8Encode(HKDF_SALT_ROOT), transcript]);
  const root = bindings.wasm_hkdf_expand(
    sharedSecret,
    new Uint8Array(0),
    rootInfo,
    32,
  );
  const initiatorSend = bindings.wasm_hkdf_expand(
    root,
    new Uint8Array(0),
    utf8Encode(HKDF_INITIATOR_SEND),
    32,
  );
  const initiatorRecv = bindings.wasm_hkdf_expand(
    root,
    new Uint8Array(0),
    utf8Encode(HKDF_INITIATOR_RECV),
    32,
  );
  return { root, initiatorSend, initiatorRecv };
}

/**
 * Derive a stable ID for the unordered pair of MTP identities.
 *
 * This helper is only a convenience. Session storage and the manager accept
 * caller-selected IDs directly, so applications can keep multiple sessions
 * between the same pair of identities.
 */
export function derivePeerSessionId(
  localId: bigint,
  remoteId: bigint,
): string {
  const ids = [
    requireMtpId(localId, "localId"),
    requireMtpId(remoteId, "remoteId"),
  ].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  return `${ids[0].toString(16)}:${ids[1].toString(16)}`;
}

export class MTPSessionManager {
  constructor(private storage: MTPSessionStorage) {}

  getSession(sessionId: string): Promise<MTPSessionState | null> {
    return this.storage.getSession(requireSessionId(sessionId));
  }

  async saveSession(state: MTPSessionState): Promise<void> {
    await this.storage.setSession({
      ...state,
      updatedAt: Date.now(),
    });
  }

  async deleteSession(sessionId: string): Promise<void> {
    await this.storage.deleteSession(requireSessionId(sessionId));
  }

  async createSession(args: {
    sessionId: string;
    localId: bigint;
    remoteId: bigint;
    remotePublicKey: Uint8Array;
    sharedSecret: Uint8Array;
    role: "initiator" | "receiver";
    transcript?: Uint8Array;
    transcriptContext?: MTPSessionTranscriptContext;
  }): Promise<MTPSessionState> {
    const sessionId = requireSessionId(args.sessionId);
    const localId = requireMtpId(args.localId, "localId");
    const remoteId = requireMtpId(args.remoteId, "remoteId");
    const transcript = args.transcript
      ? args.transcript.slice()
      : args.transcriptContext
        ? buildSessionTranscript(args.transcriptContext)
        : null;
    if (!transcript || transcript.length === 0) {
      throw new Error(
        "session creation requires a non-empty authenticated transcript or transcriptContext",
      );
    }
    const { root, initiatorSend, initiatorRecv } = await deriveSessionKeys(
      args.sharedSecret,
      transcript,
    );
    const now = Date.now();
    const state: MTPSessionState = {
      version: 1,
      sessionId,
      localId,
      remoteId,
      remotePublicKey: args.remotePublicKey.slice(),
      sendChainKey: args.role === "initiator" ? initiatorSend : initiatorRecv,
      recvChainKey: args.role === "initiator" ? initiatorRecv : initiatorSend,
      sendCount: 0,
      recvCount: 0,
      skippedMessageKeys: [],
      createdAt: now,
      updatedAt: now,
    };
    root.fill(0);
    return state;
  }
}
