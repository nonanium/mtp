import type {
  MTPDataValueInput,
  MTPOpenProtectedOptions,
  MTPProtectedFrameInput,
  MTPSendProtectedOptions,
  MTPVerifiedProtectedMessage,
} from "./client.js";
import { MTPProtocolError, type MTPFrame } from "./schema.js";

/** Minimal client surface required for protected request-response RPCs. */
export interface MTPProtectedTransport {
  subscribe(
    type: string,
    handler: (message: MTPFrame) => void | Promise<void>,
  ): () => void;
  subscribeRaw(
    type: string,
    handler: (message: MTPFrame) => void | Promise<void>,
  ): () => void;
  sendProtected(
    type: string,
    data: MTPDataValueInput,
    options: MTPSendProtectedOptions,
  ): Promise<void>;
  openProtected(
    frame: MTPProtectedFrameInput | MTPFrame,
    options: MTPOpenProtectedOptions,
  ): Promise<MTPVerifiedProtectedMessage>;
}

export type MTPRequestProtectedOptions = {
  /** Protected frame creation options; the request id is assigned here. */
  send: Omit<MTPSendProtectedOptions, "id">;
  /** Protected response opening options. */
  open: MTPOpenProtectedOptions;
  /** Expected protected response type; defaults to the request type. */
  responseType?: string;
  /**
   * Error frame types that should fail the request immediately when they
   * arrive with the request id. Error frames never match `responseType`,
   * so without this the request would only fail on timeout.
   */
  errorTypes?: readonly string[];
  timeoutMs?: number;
};

export const DEFAULT_PROTECTED_RPC_TIMEOUT_MS = 30_000;

let nextRequestId = 1;

/**
 * Protected request-response RPC: sends a protected frame with a nonzero
 * request id, correlates the protected response frame by id, and opens it
 * with signature and decryption verification.
 */
export async function requestProtected(
  client: MTPProtectedTransport,
  type: string,
  data: MTPDataValueInput,
  options: MTPRequestProtectedOptions,
): Promise<MTPVerifiedProtectedMessage> {
  const responseType = options.responseType ?? type;
  const id = nextRequestId++;

  return new Promise((resolve, reject) => {
    const unsubscribers: (() => void)[] = [];
    let settled = false;
    const finish = (settle: () => void) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      for (const unsubscribe of unsubscribers.splice(0)) unsubscribe();
      settle();
    };
    const timer = setTimeout(
      () =>
        finish(() =>
          reject(
            new Error(
              `Protected ${String(type)} request timed out after ${options.timeoutMs ?? DEFAULT_PROTECTED_RPC_TIMEOUT_MS}ms`,
            ),
          ),
        ),
      options.timeoutMs ?? DEFAULT_PROTECTED_RPC_TIMEOUT_MS,
    );
    unsubscribers.push(
      client.subscribeRaw(responseType, (message) => {
        if (message.id !== id) return;
        if (message.type.startsWith("Error")) {
          finish(() => reject(new MTPProtocolError(message)));
          return;
        }
        finish(() => {
          client.openProtected(message, options.open).then(resolve, reject);
        });
      }),
    );
    for (const errorType of options.errorTypes ?? []) {
      unsubscribers.push(
        client.subscribe(errorType, (message) => {
          if (message.id !== id) return;
          finish(() => reject(new MTPProtocolError(message)));
        }),
      );
    }
    client
      .sendProtected(type, data, { ...options.send, id })
      .catch((error: unknown) => finish(() => reject(error)));
  });
}
