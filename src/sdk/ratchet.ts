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

const HKDF_MESSAGE_KEY = "mtp-e2ee-v1-message-key";
const HKDF_NEXT_CHAIN = "mtp-e2ee-v1-next-chain";

export interface RatchetStep {
  key: Uint8Array;
  chainKey: Uint8Array;
}

export class MTPRatchet {
  static async stepSend(chainKey: Uint8Array): Promise<RatchetStep> {
    return this.step(chainKey);
  }

  static async stepRecv(chainKey: Uint8Array): Promise<RatchetStep> {
    return this.step(chainKey);
  }

  static async step(chainKey: Uint8Array): Promise<RatchetStep> {
    const messageKey = bindings.wasm_hkdf_expand(
      chainKey,
      new Uint8Array(0),
      utf8Encode(HKDF_MESSAGE_KEY),
      32,
    );
    const nextChainKey = bindings.wasm_hkdf_expand(
      chainKey,
      new Uint8Array(0),
      utf8Encode(HKDF_NEXT_CHAIN),
      32,
    );

    return {
      key: messageKey,
      chainKey: nextChainKey,
    };
  }
}
