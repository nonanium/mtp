import type * as RawBindings from "../raw/index";
import {
  acceptMTPPipeSessionAuto,
  initiateMTPPipeSession,
  validateApplicationProtectionPurpose,
} from "./encrypted-pipe.js";
import type {
  MTPAcceptEncryptedPipeOptions,
  MTPCreateEncryptedPipeOptions,
  MTPKeyMaterialInput,
  MTPLogEvent,
  MTPOutgoingPipeHandle,
  MTPPipeReader,
  MTPPipeRequest,
  MTPPipeWriter,
  MTPProtectionSignatureSuite,
} from "./client.js";
import type { InternalCredentials } from "./credentials.js";
import { inputU64, normalizeBytes, publicKeyBundleToKeys } from "./codec.js";
import { resolveSignatureVerificationPolicy } from "./signature-policy.js";
import type { MTPSignatureVerificationPolicy } from "./signature-policy.js";
import type { MTPEncryptedPipeReader, MTPEncryptedPipeWriter } from "./encrypted-pipe.js";

export interface PipeClientContext {
  raw: RawBindings.WasmClient;
  credentials: InternalCredentials | null;
  encryptedPipeSignatureSuite: MTPProtectionSignatureSuite;
  encryptedPipeSignaturePolicy: MTPSignatureVerificationPolicy;
  defaultSignatureVerificationPolicy?: MTPSignatureVerificationPolicy;
  report(event: MTPLogEvent): void;
  normalizeError<T>(operation: Promise<T>): Promise<T>;
}

function pipeWriter(
  raw: RawBindings.PipeWriter,
  normalizeError: PipeClientContext["normalizeError"],
): MTPPipeWriter {
  return {
    pipeId: raw.pipe_id(),
    write: (data) => normalizeError(raw.write(data)),
    close: () => normalizeError(raw.close()),
    abort: () => raw.abort(),
  };
}

function pipeReader(
  raw: RawBindings.PipeReader,
  normalizeError: PipeClientContext["normalizeError"],
): MTPPipeReader {
  return {
    pipeId: raw.pipe_id(),
    description: raw.description(),
    read: async () => (await normalizeError(raw.read())) as Uint8Array | null,
  };
}

export function setOnPipeRequest(
  context: PipeClientContext,
  handler: ((request: MTPPipeRequest) => void) | null,
): void {
  if (handler == null) {
    context.raw.set_on_pipe_request(null);
    return;
  }
  context.raw.set_on_pipe_request((event) => {
    context.report({ hint: "info", type: "PipeRequest", data: event, direction: "recv" });
    handler({ pipeId: event.pipeId, description: event.description });
  });
}

export async function createPipe(
  context: PipeClientContext,
  description: string,
): Promise<MTPOutgoingPipeHandle> {
  if (typeof description !== "string") throw new TypeError("description must be a string");
  const handle = await context.normalizeError(context.raw.create_pipe(description));
  return {
    pipeId: handle.pipe_id,
    description: handle.description,
    async wait(): Promise<MTPPipeWriter | null> {
      const result = await context.normalizeError(handle.wait());
      if (result == null) return null;
      context.report({ hint: "info", type: "PipeCreated", data: { pipeId: result.pipe_id() }, direction: "send" });
      return pipeWriter(result, context.normalizeError);
    },
    async cancel(): Promise<void> {
      await context.normalizeError(handle.cancel());
      context.report({ hint: "info", type: "PipeCancelled", data: { pipeId: handle.pipe_id }, direction: "send" });
    },
  };
}

export async function acceptPipe(context: PipeClientContext, pipeId: number): Promise<MTPPipeReader> {
  if (typeof pipeId !== "number" || !Number.isFinite(pipeId)) throw new TypeError("pipeId must be a finite number");
  const reader = pipeReader(await context.normalizeError(context.raw.accept_pipe(pipeId)), context.normalizeError);
  context.report({ hint: "info", type: "PipeAccepted", data: { pipeId: reader.pipeId, description: reader.description }, direction: "send" });
  return reader;
}

export async function createEncryptedPipe(
  context: PipeClientContext,
  options: MTPCreateEncryptedPipeOptions,
): Promise<MTPEncryptedPipeWriter | null> {
  const credentials = context.credentials;
  if (!credentials || credentials.clientId == null) throw new Error("Client not registered");
  const recipientId = inputU64(options.recipientId, "recipientId");
  if (options.recipientPublicKey != null && options.recipientPublicKeys != null) throw new Error("provide recipientPublicKey or recipientPublicKeys, not both");
  const rawRecipients = options.recipientPublicKeys ?? (options.recipientPublicKey != null ? [options.recipientPublicKey] : []);
  if (rawRecipients.length === 0) throw new Error("at least one recipient public key is required");
  const recipients = rawRecipients.map((value, index) => normalizeBytes(value, `recipientPublicKeys[${index}]`));
  recipients.forEach(publicKeyBundleToKeys);
  const purpose = options.purpose ?? 0x40;
  const direction = options.direction ?? 0;
  validateApplicationProtectionPurpose(purpose);
  if (!Number.isInteger(direction) || direction < 0 || direction > 0xff) throw new RangeError("direction must be a u8");
  const handle = await createPipe(context, options.description ?? "encrypted pipe");
  const writer = await handle.wait();
  if (!writer) return null;
  if (writer.pipeId !== handle.pipeId) throw new Error("created pipe ID does not match the accepted writer");
  const sessionId = new Uint8Array(32);
  globalThis.crypto.getRandomValues(sessionId);
  return initiateMTPPipeSession(writer, { sessionId, pipeId: writer.pipeId, senderId: credentials.clientId, recipientId, purpose, direction }, credentials.keyring, recipients, options.signatureSuite ?? context.encryptedPipeSignatureSuite);
}

export async function acceptEncryptedPipe(
  context: PipeClientContext,
  request: MTPPipeRequest,
  options: MTPAcceptEncryptedPipeOptions,
): Promise<MTPEncryptedPipeReader> {
  const credentials = context.credentials;
  if (!credentials || credentials.clientId == null) throw new Error("Client not registered");
  if (!Number.isSafeInteger(request.pipeId) || request.pipeId <= 0) throw new TypeError("request.pipeId must be a non-zero safe integer");
  const senderId = inputU64(options.senderId, "senderId");
  const purpose = options.purpose ?? 0x40;
  const direction = options.direction ?? 0;
  validateApplicationProtectionPurpose(purpose);
  if (!Number.isInteger(direction) || direction < 0 || direction > 0xff) throw new RangeError("direction must be a u8");
  if (options.senderPublicKeys != null && options.senderPublicKeys.length === 0) throw new Error("senderPublicKeys must contain at least one key");
  if (options.senderPublicKeys == null && options.senderPublicKey == null) throw new Error("senderPublicKey or senderPublicKeys is required");
  const senderPublicKey: MTPKeyMaterialInput | MTPKeyMaterialInput[] = options.senderPublicKeys ?? options.senderPublicKey!;
  const normalizedSenderKeys = Array.isArray(senderPublicKey)
    ? senderPublicKey.map((value, index) => normalizeBytes(value, `senderPublicKeys[${index}]`))
    : normalizeBytes(senderPublicKey, "senderPublicKey");
  const reader = await acceptPipe(context, request.pipeId);
  if (reader.pipeId !== request.pipeId) throw new Error("accepted pipe ID does not match the requested pipe");
  const signaturePolicy = resolveSignatureVerificationPolicy(options.signaturePolicy, context.defaultSignatureVerificationPolicy ?? context.encryptedPipeSignaturePolicy);
  return acceptMTPPipeSessionAuto(reader, { pipeId: reader.pipeId, senderId, recipientId: credentials.clientId, purpose, direction }, credentials.keyring, normalizedSenderKeys, signaturePolicy);
}

export async function denyPipe(context: PipeClientContext, pipeId: number): Promise<void> {
  if (typeof pipeId !== "number" || !Number.isFinite(pipeId)) throw new TypeError("pipeId must be a finite number");
  await context.normalizeError(context.raw.deny_pipe(pipeId));
  context.report({ hint: "info", type: "PipeDenied", data: { pipeId }, direction: "send" });
}
