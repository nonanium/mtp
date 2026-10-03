import * as bindings from "mtp/raw";
import type { MTPBytesInput, MTPPipeReader, MTPPipeWriter, MTPProtectionSignatureSuite } from "./index.js";
import { resolveSignatureVerificationPolicy, signatureVerificationPolicyValue } from "./signature-policy.js";
import type { MTPSignatureVerificationPolicy } from "./signature-policy.js";

export const MAX_ENCRYPTED_PIPE_RECORD = 16 * 1024 * 1024;
export const MAX_PIPE_SESSION_OFFER = 64 * 1024;
export const pipeSessionSignaturePurpose = () => bindings.mtp_pipe_session_signature_purpose();
export const pipeSessionEncryptionPurpose = () => bindings.mtp_pipe_session_encryption_purpose();
export class MTPEncryptedPipeError extends Error {
  constructor(readonly code: "context" | "record-length" | "sequence" | "truncated" | "authentication" | "io" | "setup" | "state", message: string, options?: ErrorOptions) {
    super(message, options); this.name = "MTPEncryptedPipeError";
  }
}
export function validateApplicationProtectionPurpose(purpose: number): number {
  if (!Number.isInteger(purpose) || purpose < 0 || purpose > 255) throw new MTPEncryptedPipeError("context", "purpose must be a u8");
  try { bindings.mtp_pipe_context_hash(new Uint8Array([1]), purpose, 0); }
  catch (cause) { throw new MTPEncryptedPipeError("context", String(cause), { cause }); }
  return purpose;
}
export class MTPPipeProtectionContext {
  readonly sessionId: Uint8Array;
  readonly transcriptHash: Uint8Array;
  constructor(sessionId: Uint8Array, readonly purpose: number, readonly direction: number, transcriptHash?: Uint8Array) {
    if (!Number.isInteger(direction) || direction < 0 || direction > 255) throw new MTPEncryptedPipeError("context", "direction must be a u8");
    validateApplicationProtectionPurpose(purpose);
    this.sessionId = sessionId.slice();
    this.transcriptHash = transcriptHash?.slice() ?? bindings.mtp_pipe_context_hash(sessionId, purpose, direction);
    if (this.transcriptHash.length !== 32) throw new MTPEncryptedPipeError("context", "transcriptHash must be 32 bytes");
  }
}
export interface MTPWritablePipe { write(data: Uint8Array): Promise<void>; close(): Promise<void>; abort(): void; }
export interface MTPReadablePipe { read(): Promise<Uint8Array | null>; }
export interface MTPDuplexPipe extends MTPWritablePipe, MTPReadablePipe { readonly pipeId?: number; }
export interface MTPPipeSessionParameters { sessionId: Uint8Array; pipeId: number; senderId: bigint; recipientId: bigint; purpose: number; direction: number; }
export type MTPPipeSessionExpectation = Omit<MTPPipeSessionParameters, "sessionId">;
export type MTPEncryptedPipeWriterSource = MTPPipeWriter & MTPWritablePipe;
export type MTPEncryptedPipeReaderSource = MTPPipeReader & MTPReadablePipe;

function bytes(input: MTPBytesInput): Uint8Array { return input instanceof Uint8Array ? input : Uint8Array.from(input); }
function bundles(input: MTPBytesInput | MTPBytesInput[]): Uint8Array[] {
  return input instanceof Uint8Array || typeof input[0] === "number" ? [bytes(input as MTPBytesInput)] : (input as MTPBytesInput[]).map(bytes);
}
function checkedPipe(stream: { readonly pipeId?: number }, params: MTPPipeSessionExpectation): void {
  if (stream.pipeId != null && stream.pipeId !== params.pipeId) throw new MTPEncryptedPipeError("setup", "pipeId does not match the actual pipe");
  validateApplicationProtectionPurpose(params.purpose);
}
function writerAdapter(writer: MTPWritablePipe) {
  return { write: (data: Uint8Array) => writer.write(data), close: () => writer.close(), abort: () => writer.abort() };
}
function readerAdapter(reader: MTPReadablePipe) { return { read: () => reader.read() }; }
function duplexAdapter(stream: MTPDuplexPipe) { return { ...writerAdapter(stream), ...readerAdapter(stream) }; }
function expectation(params: MTPPipeSessionExpectation): MTPPipeSessionParameters { return { ...params, sessionId: new Uint8Array([1]) }; }

export class MTPEncryptedPipeWriter {
  readonly pipeId?: number;
  private inner: bindings.WasmEncryptedPipeWriter;
  private chain: Promise<void> = Promise.resolve();
  constructor(writer: MTPWritablePipe, key: Uint8Array, context: MTPPipeProtectionContext) {
    this.pipeId = (writer as MTPPipeWriter).pipeId;
    this.inner = new bindings.WasmEncryptedPipeWriter(writerAdapter(writer), key, context.sessionId, context.purpose, context.direction, context.transcriptHash);
  }
  static fromBinding(inner: bindings.WasmEncryptedPipeWriter, pipeId?: number): MTPEncryptedPipeWriter {
    const result = Object.create(MTPEncryptedPipeWriter.prototype) as MTPEncryptedPipeWriter;
    Object.assign(result, { inner, pipeId, chain: Promise.resolve() }); return result;
  }
  get sequenceNumber(): bigint { return this.inner.sequence(); }
  writeRecord(data: Uint8Array): Promise<void> {
    const copy = data.slice();
    const operation = this.chain.then(() => this.inner.write_record(copy));
    this.chain = operation.catch(() => undefined); return operation;
  }
  close(): Promise<void> {
    const operation = this.chain.then(() => this.inner.close());
    this.chain = operation.catch(() => undefined); return operation;
  }
  abort(): void { this.inner.abort(); }
}
export class MTPEncryptedPipeReader {
  private inner: bindings.WasmEncryptedPipeReader;
  private chain: Promise<unknown> = Promise.resolve();
  constructor(reader: MTPReadablePipe, key: Uint8Array, context: MTPPipeProtectionContext, initialBuffer = new Uint8Array(0)) {
    this.inner = new bindings.WasmEncryptedPipeReader(readerAdapter(reader), key, context.sessionId, context.purpose, context.direction, context.transcriptHash, initialBuffer);
  }
  static fromBinding(inner: bindings.WasmEncryptedPipeReader): MTPEncryptedPipeReader {
    const result = Object.create(MTPEncryptedPipeReader.prototype) as MTPEncryptedPipeReader;
    Object.assign(result, { inner, chain: Promise.resolve() }); return result;
  }
  get sequenceNumber(): bigint { return this.inner.sequence(); }
  readRecord(): Promise<Uint8Array | null> {
    const operation = this.chain.then(() => this.inner.read_record() as Promise<Uint8Array | null>);
    this.chain = operation.catch(() => undefined); return operation;
  }
}
export async function initiateMTPPipeSession(writer: MTPEncryptedPipeWriterSource, params: MTPPipeSessionParameters, keys: MTPBytesInput, recipients: MTPBytesInput | MTPBytesInput[], suite: MTPProtectionSignatureSuite = "ed25519"): Promise<MTPEncryptedPipeWriter> {
  checkedPipe(writer, params);
  const inner = await bindings.mtp_initiate_pipe_session(writerAdapter(writer), params, bytes(keys), bundles(recipients), suite === "dual");
  return MTPEncryptedPipeWriter.fromBinding(inner, writer.pipeId);
}
export async function acceptMTPPipeSession(reader: MTPEncryptedPipeReaderSource, params: MTPPipeSessionParameters, keys: MTPBytesInput, senders: MTPBytesInput | MTPBytesInput[], policy?: MTPSignatureVerificationPolicy): Promise<MTPEncryptedPipeReader> {
  checkedPipe(reader, params);
  return MTPEncryptedPipeReader.fromBinding(await bindings.mtp_accept_pipe_session(readerAdapter(reader), params, bytes(keys), bundles(senders), signatureVerificationPolicyValue(resolveSignatureVerificationPolicy(policy)), false));
}
export async function acceptMTPPipeSessionAuto(reader: MTPEncryptedPipeReaderSource, params: MTPPipeSessionExpectation, keys: MTPBytesInput, senders: MTPBytesInput | MTPBytesInput[], policy?: MTPSignatureVerificationPolicy): Promise<MTPEncryptedPipeReader> {
  checkedPipe(reader, params);
  return MTPEncryptedPipeReader.fromBinding(await bindings.mtp_accept_pipe_session(readerAdapter(reader), expectation(params), bytes(keys), bundles(senders), signatureVerificationPolicyValue(resolveSignatureVerificationPolicy(policy)), true));
}
export async function initiateMTPForwardSecurePipeSession(stream: MTPDuplexPipe, params: MTPPipeSessionParameters, keys: MTPBytesInput, recipient: MTPBytesInput, _suite?: MTPProtectionSignatureSuite, policy?: MTPSignatureVerificationPolicy): Promise<MTPEncryptedPipeWriter> {
  checkedPipe(stream, params);
  return MTPEncryptedPipeWriter.fromBinding(await bindings.mtp_initiate_forward_secure_pipe_session(duplexAdapter(stream), params, bytes(keys), bytes(recipient), signatureVerificationPolicyValue(resolveSignatureVerificationPolicy(policy)), _suite === "dual"), stream.pipeId);
}
export async function acceptMTPForwardSecurePipeSession(stream: MTPDuplexPipe, params: MTPPipeSessionExpectation, keys: MTPBytesInput, senders: MTPBytesInput | MTPBytesInput[], _suite?: MTPProtectionSignatureSuite, policy?: MTPSignatureVerificationPolicy): Promise<MTPEncryptedPipeReader> {
  checkedPipe(stream, params);
  return MTPEncryptedPipeReader.fromBinding(await bindings.mtp_accept_forward_secure_pipe_session(duplexAdapter(stream), expectation(params), bytes(keys), bundles(senders), signatureVerificationPolicyValue(resolveSignatureVerificationPolicy(policy)), _suite === "dual"));
}
