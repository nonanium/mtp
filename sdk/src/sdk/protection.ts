import type { InternalCredentials } from "./credentials.js";
import {
  inputU64,
  keyringToKeys,
  normalizeBytes,
  publicKeyBundleToKeys,
  signatureSuiteValue,
} from "./codec.js";
import {
  MTPSignatureVerificationError,
  signerKeysUnavailable,
} from "./signature-policy.js";
import type { MTPSignatureVerificationPolicy } from "./signature-policy.js";
import type {
  MTPDecryptionIdentity,
  MTPProtectionIdentity,
  MTPProtectionSignatureSuite,
  MTPReplayGuard,
  MTPSignerKeyResolver,
  MTPBytesInput,
  MTPKeyMaterialInput,
} from "./client.js";

export class InMemoryReplayGuard implements MTPReplayGuard {
  #accepted = new Set<string>();
  readonly #capacity = 10_000;

  accept(signerId: bigint, messageId: string, _createdAt: bigint): boolean {
    const key = `${signerId}:${messageId}`;
    if (this.#accepted.has(key)) return false;
    this.#accepted.add(key);
    if (this.#accepted.size > this.#capacity) {
      const oldest = this.#accepted.values().next().value;
      if (oldest !== undefined) this.#accepted.delete(oldest);
    }
    return true;
  }
}

export class MTPReplayError extends Error {
  readonly signerId: bigint;
  readonly messageId: string;

  constructor(signerId: bigint, messageId: string) {
    super(`message ${messageId} from signer ${signerId} was already accepted`);
    this.name = "MTPReplayError";
    this.signerId = signerId;
    this.messageId = messageId;
  }
}

export class MTPMissingProtectedVersionError extends Error {
  constructor() {
    super("protected message does not declare a protected version");
    this.name = "MTPMissingProtectedVersionError";
  }
}

export class MTPUnsupportedProtectedVersionError extends Error {
  readonly protectedVersion: bigint;

  constructor(protectedVersion: bigint) {
    super(`unsupported protected message version ${protectedVersion}`);
    this.name = "MTPUnsupportedProtectedVersionError";
    this.protectedVersion = protectedVersion;
  }
}

export class MTPResourceLimitError extends Error {
  constructor(message = "MTP receive resource limit exceeded") {
    super(message);
    this.name = "MTPResourceLimitError";
  }
}

export interface ResolvedProtectionIdentity {
  signerId: bigint;
  keyring: Uint8Array;
}

export interface ResolvedDecryptionIdentity {
  id?: bigint;
  keyrings: Uint8Array[];
}

export interface SignerResolutionOptions {
  expectedSignerId?: bigint | number | string;
  resolveSignerPublicKeys?: MTPSignerKeyResolver;
}

export function protectionSignatureSuiteValue(
  suite: MTPProtectionSignatureSuite,
): number {
  return signatureSuiteValue(suite);
}

export function effectiveProtectionSignatureSuite(
  keyring: Uint8Array,
  requested?: MTPProtectionSignatureSuite,
): MTPProtectionSignatureSuite {
  const keys = keyringToKeys(keyring);
  const hasPqPublicKey = keys.sigPqPublicKey.length > 0;
  const hasPqSecretKey = keys.sigPqSecretKey.length > 0;
  const suite = requested ?? "ed25519";
  if (suite !== "ed25519" && suite !== "dual") {
    throw new Error("signatureSuite must be 'ed25519' or 'dual'");
  }
  if (suite === "dual" && !(hasPqPublicKey && hasPqSecretKey)) {
    throw new Error(
      "dual protected signatures require a complete ML-DSA key pair; choose 'ed25519' for a partial keyring",
    );
  }
  return suite;
}

function sameBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  for (let index = 0; index < left.length; index += 1) {
    if (left[index] !== right[index]) return false;
  }
  return true;
}

function normalizeDecryptionKeyrings(
  identity: MTPDecryptionIdentity,
): Uint8Array[] {
  const current = normalizeBytes(identity.keyring, "recipient.keyring");
  if (current.length === 0) throw new Error("recipient.keyring must not be empty");
  if (
    identity.keyringHistory !== undefined &&
    !Array.isArray(identity.keyringHistory)
  ) {
    throw new TypeError("recipient.keyringHistory must be an array");
  }

  const keyrings: Uint8Array[] = [];
  const add = (value: MTPKeyMaterialInput, name: string): void => {
    const bytes = normalizeBytes(value, name);
    if (bytes.length === 0) throw new Error(`${name} must not be empty`);
    if (!keyrings.some((existing) => sameBytes(existing, bytes))) {
      keyrings.push(bytes.slice());
    }
  };
  add(current, "recipient.keyring");
  for (const [index, history] of (identity.keyringHistory ?? []).entries()) {
    add(history, `recipient.keyringHistory[${index}]`);
  }
  if (keyrings.length === 0) throw new Error("recipient must contain at least one keyring");
  return keyrings;
}

export function normalizeRecipientBundles(
  recipients: MTPKeyMaterialInput[],
  name: string,
): Uint8Array[] {
  if (!Array.isArray(recipients) || recipients.length === 0) {
    throw new TypeError(`${name} must contain at least one public key bundle`);
  }
  return recipients.map((value, index) => {
    const bundle = normalizeBytes(value, `${name}[${index}]`);
    publicKeyBundleToKeys(bundle);
    return bundle.slice();
  });
}

export function resolveProtectionIdentity(
  explicit: MTPProtectionIdentity | undefined,
  stored: InternalCredentials | null,
): ResolvedProtectionIdentity {
  if (explicit) {
    return {
      signerId: inputU64(explicit.signerId, "identity.signerId"),
      keyring: normalizeBytes(explicit.keyring, "identity.keyring").slice(),
    };
  }
  if (stored?.clientId != null && stored.keyring.length > 0) {
    return { signerId: stored.clientId, keyring: stored.keyring.slice() };
  }
  throw new Error(
    "protected send requires an explicit protection identity or stored registered credentials",
  );
}

export function resolveDecryptionIdentity(
  explicit: MTPDecryptionIdentity | undefined,
  stored: InternalCredentials | null,
): ResolvedDecryptionIdentity {
  if (explicit) {
    return {
      id: explicit.id == null ? undefined : inputU64(explicit.id, "recipient.id"),
      keyrings: normalizeDecryptionKeyrings(explicit),
    };
  }
  if (stored?.clientId != null && stored.keyring.length > 0) {
    return {
      id: stored.clientId,
      keyrings: normalizeDecryptionKeyrings({
        id: stored.clientId,
        keyring: stored.keyring,
      }),
    };
  }
  throw new Error(
    "protected receive requires an explicit decryption identity or stored registered credentials",
  );
}

export function protectedOpeningError(error: unknown, signerId?: bigint): Error {
  if (error !== null && typeof error === "object") {
    const structured = error as { code?: unknown; protectedVersion?: unknown };
    if (typeof structured.code === "string") {
      switch (structured.code) {
        case "missing-protected-version":
          return new MTPMissingProtectedVersionError();
        case "unsupported-protected-version":
          if (
            typeof structured.protectedVersion === "bigint" ||
            typeof structured.protectedVersion === "number" ||
            typeof structured.protectedVersion === "string"
          ) {
            return new MTPUnsupportedProtectedVersionError(
              inputU64(structured.protectedVersion, "protectedVersion"),
            );
          }
          break;
        case "no-matching-recipient":
          return new Error("Unable to decrypt protected value with supplied recipient keyrings");
        case "reserved-application-type":
          return new Error("MTP control communication types cannot be used as application content");
        case "signature-policy-mismatch":
          return new MTPSignatureVerificationError("policy-rejected", signerId);
        case "unsupported-signature-suite":
          return new MTPSignatureVerificationError("unsupported-suite", signerId);
        case "invalid-signature":
          return new MTPSignatureVerificationError("invalid-signature", signerId);
        case "signer-id-mismatch":
          return new Error("protected signer ID mismatch");
        case "receiver-id-mismatch":
          return new Error("protected frame receiver ID mismatch");
        case "message-type-mismatch":
          return new Error("protected message type does not match outer routing");
        case "final-recipient-mismatch":
          return new Error("protected final recipient does not match outer routing receiver");
        case "sender-id-mismatch":
          return new Error("protected frame sender does not match authenticated signer");
        case "signer-key-not-found":
          return signerKeysUnavailable(signerId);
        case "replay":
          return new Error("protected message was already accepted");
        case "resource-limit":
          return new MTPResourceLimitError();
      }
    }
  }
  return error instanceof Error ? error : new Error(String(error));
}

export type { MTPSignatureVerificationPolicy };
