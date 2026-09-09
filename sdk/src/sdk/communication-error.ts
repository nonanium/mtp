export type MTPCommunicationErrorCode =
  | "timeout"
  | "delivery-unknown"
  | "peer-closed"
  | "local-closed"
  | "connection-lost"
  | "protocol-violation"
  | "authentication-failed"
  | "message-too-large"
  | "certificate"
  | "transport";

export type MTPTransportPhase =
  | "connect"
  | "handshake"
  | "open-stream"
  | "write-frame"
  | "finish-stream"
  | "read-frame"
  | "wait-response";

export class MTPCommunicationError extends Error {
  readonly code: MTPCommunicationErrorCode;
  readonly phase?: MTPTransportPhase;

  constructor(
    message: string,
    code: MTPCommunicationErrorCode,
    phase?: MTPTransportPhase,
  ) {
    super(message);
    this.name = "MTPCommunicationError";
    this.code = code;
    this.phase = phase;
  }
}

const codes = new Set<MTPCommunicationErrorCode>([
  "timeout", "delivery-unknown", "peer-closed", "local-closed",
  "connection-lost", "protocol-violation", "authentication-failed",
  "message-too-large", "certificate", "transport",
]);

const phases = new Set<MTPTransportPhase>([
  "connect", "handshake", "open-stream", "write-frame", "finish-stream",
  "read-frame", "wait-response",
]);

/** Converts structured errors emitted by the WASM transport into SDK errors. */
export function communicationError(error: unknown): unknown {
  if (
    error instanceof MTPCommunicationError ||
    typeof error !== "object" ||
    error === null
  ) return error;
  const structured = error as { message?: unknown; code?: unknown; phase?: unknown };
  if (typeof structured.code !== "string" || !codes.has(structured.code as MTPCommunicationErrorCode)) {
    return error;
  }
  return new MTPCommunicationError(
    typeof structured.message === "string" ? structured.message : String(error),
    structured.code as MTPCommunicationErrorCode,
    typeof structured.phase === "string" && phases.has(structured.phase as MTPTransportPhase)
      ? structured.phase as MTPTransportPhase
      : undefined,
  );
}
