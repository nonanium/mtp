import * as bindings from "mtp/raw";

function utf8Encode(text: string): Uint8Array {
  if (typeof TextEncoder !== "undefined") {
    return new TextEncoder().encode(text);
  }
  if (typeof Buffer !== "undefined") {
    return new Uint8Array(Buffer.from(text, "utf-8"));
  }
  const bytes = new Uint8Array(text.length * 4);
  let len = 0;
  for (let i = 0; i < text.length; i += 1) {
    const code = text.codePointAt(i) as number;
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

export const HKDF_SALT_ROOT = "mtp-e2ee-v1-root";
const HKDF_INITIATOR_SEND = "mtp-e2ee-v1-initiator-send";
const HKDF_INITIATOR_RECV = "mtp-e2ee-v1-initiator-recv";

export interface MTPSessionTranscriptContext {
  senderUserId?: string;
  senderClientId: bigint;
  recipientUserId?: string;
  recipientClientId: bigint;
  recipientPublicKey: Uint8Array;
  kemCiphertext: Uint8Array;
  conversationId: string;
}

export interface MTPSessionState {
  version: 1;
  conversationId: string;
  ownClientId: bigint;
  peerClientId: bigint;
  peerPublicKey: Uint8Array;
  sendChainKey: Uint8Array;
  recvChainKey: Uint8Array;
  sendCount: number;
  recvCount: number;
  createdAt: number;
  updatedAt: number;
}

export interface MTPSessionStorage {
  getSession(conversationId: string): Promise<MTPSessionState | null>;
  setSession(state: MTPSessionState): Promise<void>;
  deleteSession(conversationId: string): Promise<void>;
}

export class InMemorySessionStorage implements MTPSessionStorage {
  private store = new Map<string, MTPSessionState>();

  async getSession(conversationId: string): Promise<MTPSessionState | null> {
    return this.store.get(conversationId) ?? null;
  }

  async setSession(state: MTPSessionState): Promise<void> {
    this.store.set(state.conversationId, { ...state });
  }

  async deleteSession(conversationId: string): Promise<void> {
    this.store.delete(conversationId);
  }
}

function writeU32BE(value: number): Uint8Array {
  return new Uint8Array([
    (value >>> 24) & 0xff,
    (value >>> 16) & 0xff,
    (value >>> 8) & 0xff,
    value & 0xff,
  ]);
}

function writeU64BE(value: bigint): Uint8Array {
  if (value < 0n || value > 0xffff_ffff_ffff_ffffn)
    throw new Error("u64 out of range");
  const buf = new Uint8Array(8);
  for (let i = 7; i >= 0; i -= 1) {
    buf[i] = Number(value & 0xffn);
    value >>= 8n;
  }
  return buf;
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

function transcriptField(label: string, value: Uint8Array): Uint8Array {
  const labelBytes = utf8Encode(label);
  return concatBytes([
    writeU32BE(labelBytes.length),
    labelBytes,
    writeU32BE(value.length),
    value,
  ]);
}

export function buildSessionTranscript(
  args: MTPSessionTranscriptContext,
): Uint8Array {
  const recipientPublicKeyHash = bindings.wasm_sha256(args.recipientPublicKey);
  const kemHash = bindings.wasm_sha256(args.kemCiphertext);
  return concatBytes([
    transcriptField("domain", utf8Encode("mtp-e2ee-session-transcript-v1")),
    transcriptField("version", utf8Encode("1")),
    transcriptField("senderUserId", utf8Encode(args.senderUserId ?? "")),
    transcriptField("senderClientId", writeU64BE(args.senderClientId)),
    transcriptField("recipientUserId", utf8Encode(args.recipientUserId ?? "")),
    transcriptField("recipientClientId", writeU64BE(args.recipientClientId)),
    transcriptField("recipientPublicKeyHash", recipientPublicKeyHash),
    transcriptField("kemCiphertextHash", kemHash),
    transcriptField("conversationId", utf8Encode(args.conversationId)),
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

export function getConversationId(
  ownClientId: bigint,
  peerClientId: bigint,
): string {
  const ids = [ownClientId, peerClientId].sort((a, b) =>
    a < b ? -1 : a > b ? 1 : 0,
  );
  return `${ids[0].toString(16)}:${ids[1].toString(16)}`;
}

export class MTPSessionManager {
  constructor(private storage: MTPSessionStorage) {}

  getConversationId(
    ownClientId: bigint,
    peerClientId: bigint,
  ): Promise<string> {
    return Promise.resolve(getConversationId(ownClientId, peerClientId));
  }

  async getSession(
    ownClientId: bigint,
    peerClientId: bigint,
  ): Promise<MTPSessionState | null> {
    return this.storage.getSession(
      getConversationId(ownClientId, peerClientId),
    );
  }

  async saveSession(state: MTPSessionState): Promise<void> {
    await this.storage.setSession({ ...state, updatedAt: Date.now() });
  }

  async deleteSession(
    ownClientId: bigint,
    peerClientId: bigint,
  ): Promise<void> {
    await this.storage.deleteSession(
      getConversationId(ownClientId, peerClientId),
    );
  }

  async createSession(args: {
    ownClientId: bigint;
    peerClientId: bigint;
    peerPublicKey: Uint8Array;
    sharedSecret: Uint8Array;
    role: "initiator" | "receiver";
    transcript?: Uint8Array;
    transcriptContext?: MTPSessionTranscriptContext;
  }): Promise<MTPSessionState> {
    const transcript =
      args.transcript ??
      (args.transcriptContext
        ? buildSessionTranscript(args.transcriptContext)
        : undefined);
    const { root, initiatorSend, initiatorRecv } = await deriveSessionKeys(
      args.sharedSecret,
      transcript,
    );
    const now = Date.now();
    const state: MTPSessionState = {
      version: 1,
      conversationId: getConversationId(args.ownClientId, args.peerClientId),
      ownClientId: args.ownClientId,
      peerClientId: args.peerClientId,
      peerPublicKey: args.peerPublicKey,
      sendChainKey: args.role === "initiator" ? initiatorSend : initiatorRecv,
      recvChainKey: args.role === "initiator" ? initiatorRecv : initiatorSend,
      sendCount: 0,
      recvCount: 0,
      createdAt: now,
      updatedAt: now,
    };
    root.fill(0);
    return state;
  }
}
