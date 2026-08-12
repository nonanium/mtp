import * as bindings from "mtp/raw";

export type MTPSignatureVerificationPolicy =
  | "ed25519"
  | "dual"
  | "any-supported";

/**
 * The SDK default is deliberately fixed. Senders also default to the
 * interoperable Ed25519 suite; dual signatures require an explicit sender
 * suite and receiver policy.
 */
export const DEFAULT_SIGNATURE_VERIFICATION_POLICY: MTPSignatureVerificationPolicy =
  "ed25519";

export type MTPSignatureVerificationErrorCode =
  | "unsupported-suite"
  | "policy-rejected"
  | "invalid-signature"
  | "signer-keys-unavailable";

const POLICY_NAMES: Record<
  MTPSignatureVerificationErrorCode,
  string
> = {
  "unsupported-suite": "unsupported signature suite",
  "policy-rejected": "signature rejected by policy",
  "invalid-signature": "signature cryptographically invalid",
  "signer-keys-unavailable": "signer public keys unavailable",
};

/** Caller-facing signature verification failure without cryptographic detail. */
export class MTPSignatureVerificationError extends Error {
  readonly code: MTPSignatureVerificationErrorCode;
  readonly signerId?: bigint;

  constructor(
    code: MTPSignatureVerificationErrorCode,
    signerId?: bigint,
  ) {
    super(
      signerId == null
        ? POLICY_NAMES[code]
        : `${POLICY_NAMES[code]} for signer ${signerId}`,
    );
    this.name = "MTPSignatureVerificationError";
    this.code = code;
    this.signerId = signerId;
  }
}

function validPolicy(
  value: unknown,
): value is MTPSignatureVerificationPolicy {
  return (
    value === "ed25519" ||
    value === "dual" ||
    value === "any-supported"
  );
}

/**
 * Resolve receiver policy in operation, client, library order.
 */
export function resolveSignatureVerificationPolicy(
  operationPolicy: MTPSignatureVerificationPolicy | undefined,
  clientDefaultPolicy?: MTPSignatureVerificationPolicy,
): MTPSignatureVerificationPolicy {
  if (operationPolicy != null && !validPolicy(operationPolicy)) {
    throw new TypeError(
      "signaturePolicy must be 'ed25519', 'dual', or 'any-supported'",
    );
  }
  if (clientDefaultPolicy != null && !validPolicy(clientDefaultPolicy)) {
    throw new TypeError(
      "defaultSignatureVerificationPolicy must be 'ed25519', 'dual', or 'any-supported'",
    );
  }
  return (
    operationPolicy ??
    clientDefaultPolicy ??
    DEFAULT_SIGNATURE_VERIFICATION_POLICY
  );
}

/** Convert the SDK policy into the raw WASM verifier's policy value. */
export function signatureVerificationPolicyValue(
  policy: MTPSignatureVerificationPolicy,
): number {
  switch (policy) {
    case "ed25519":
      return bindings.mtp_protection_signature_suite_ed25519();
    case "dual":
      return bindings.mtp_protection_signature_suite_dual();
    case "any-supported":
      return 0;
  }
}

/** Verify one protected value and sanitize raw WASM failure details. */
export function verifyDataValueWithPolicy(
  value: Uint8Array,
  publicKeyBundle: Uint8Array,
  expectedSignerId: bigint,
  expectedPurpose: number,
  policy: MTPSignatureVerificationPolicy,
): void {
  try {
    bindings.verify_data_value_with_policy(
      value,
      publicKeyBundle,
      expectedSignerId,
      expectedPurpose,
      signatureVerificationPolicyValue(policy),
    );
  } catch (error) {
    throw classifySignatureVerificationFailure(error, expectedSignerId);
  }
}

function rawErrorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/** Classify a raw verifier failure without returning its cryptographic cause. */
export function classifySignatureVerificationFailure(
  error: unknown,
  signerId?: bigint,
): MTPSignatureVerificationError {
  const message = rawErrorMessage(error).toLowerCase();
  if (message.includes("unknown") && message.includes("signature suite")) {
    return new MTPSignatureVerificationError("unsupported-suite", signerId);
  }
  if (message.includes("policy")) {
    return new MTPSignatureVerificationError("policy-rejected", signerId);
  }
  return new MTPSignatureVerificationError("invalid-signature", signerId);
}

/** Select the most useful sanitized error after trying key history. */
export function signatureVerificationFailure(
  errors: readonly unknown[],
  signerId?: bigint,
): MTPSignatureVerificationError {
  const classified = errors.map((error) =>
    error instanceof MTPSignatureVerificationError
      ? error
      : classifySignatureVerificationFailure(error, signerId),
  );
  const preferredCode = [
    "unsupported-suite",
    "policy-rejected",
    "invalid-signature",
  ].find((code) =>
    classified.some((error) => error.code === code),
  ) as MTPSignatureVerificationErrorCode | undefined;
  return new MTPSignatureVerificationError(
    preferredCode ?? "invalid-signature",
    signerId,
  );
}

export function signerKeysUnavailable(
  signerId?: bigint,
): MTPSignatureVerificationError {
  return new MTPSignatureVerificationError(
    "signer-keys-unavailable",
    signerId,
  );
}
