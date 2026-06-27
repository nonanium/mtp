import { build_demo_message, build_ping_frame, parse_auth_response } from 'mtp-wasm';

export function buildAuthResponse(
  response: Uint8Array,
): {
  connected: boolean;
  clientNonce: Uint8Array;
  assignedId: bigint;
  timestamp: bigint;
  signature: Uint8Array;
} {
  return parse_auth_response(response);
}

export function buildDemoMessage(
  clientId: bigint,
  keyringBytes: Uint8Array,
  hostBundle: Uint8Array,
): Uint8Array {
  return build_demo_message(clientId, keyringBytes, hostBundle);
}

export function buildPingFrame(
  clientId: bigint,
  description: string,
  timestamp: bigint,
  data?: Uint8Array,
): Uint8Array {
  return build_ping_frame(clientId, description, timestamp, data ?? new Uint8Array());
}
