import type { MTPClientCredentials } from "./index.js";

export type InternalCredentials = {
  clientId: bigint | null;
  keyring: Uint8Array;
  hostPublicKey?: Uint8Array;
};

export function publicCredentials(
  credentials: InternalCredentials | null,
): MTPClientCredentials | null {
  if (!credentials) {
    return null;
  }
  return {
    clientId: credentials.clientId,
    keyring: credentials.keyring.slice(),
    hostPublicKey: credentials.hostPublicKey?.slice(),
  };
}

export function zeroCredentials(credentials: InternalCredentials | null): void {
  // The host public key is intentionally not wiped: it is public configuration
  // and may also be retained by the connection options.
  credentials?.keyring.fill(0);
}
