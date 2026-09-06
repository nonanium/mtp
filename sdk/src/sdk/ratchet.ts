import * as bindings from "mtp/raw";
import { utf8Encode } from "./utils.js";

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
