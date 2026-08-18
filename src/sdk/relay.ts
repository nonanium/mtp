import type * as RawBindings from "../raw/index";
import { cloneParsedFrame, cloneParsedValue, inputU64 } from "./codec.js";
import {
  MTPSignatureVerificationError,
  signerKeysUnavailable,
} from "./signature-policy.js";
import { MTPResourceLimitError } from "./protection.js";
import type { MTPSignatureVerificationPolicy } from "./signature-policy.js";
import type {
  MTPDataValue,
  MTPReceiveLimits,
  MTPVerifiedRelayContent,
  ParsedFrame,
} from "./client.js";

export class MTPMissingRelayVersionError extends Error {
  constructor() {
    super("relay frame does not declare a relay version");
    this.name = "MTPMissingRelayVersionError";
  }
}

export class MTPUnsupportedRelayVersionError extends Error {
  readonly relayVersion: bigint;

  constructor(relayVersion: bigint) {
    super(`unsupported relay version ${relayVersion}`);
    this.name = "MTPUnsupportedRelayVersionError";
    this.relayVersion = relayVersion;
  }
}

export function relayOpeningError(error: unknown, signerId?: bigint): Error {
  if (error !== null && typeof error === "object") {
    const structured = error as { code?: unknown; relayVersion?: unknown };
    if (typeof structured.code === "string") {
      switch (structured.code) {
        case "missing-relay-version":
          return new MTPMissingRelayVersionError();
        case "unsupported-relay-version":
          if (
            typeof structured.relayVersion === "bigint" ||
            typeof structured.relayVersion === "number" ||
            typeof structured.relayVersion === "string"
          ) {
            return new MTPUnsupportedRelayVersionError(
              inputU64(structured.relayVersion, "relayVersion"),
            );
          }
          break;
        case "no-matching-recipient":
          return new Error("Unable to decrypt protected value with supplied recipient keyrings");
        case "not-final-recipient":
          return new Error("relay content is addressed to a different final recipient");
        case "reserved-application-type":
          return new Error("relay application message type is reserved for MTP control");
        case "signature-policy-mismatch":
          return new MTPSignatureVerificationError("policy-rejected", signerId);
        case "unsupported-signature-suite":
          return new MTPSignatureVerificationError("unsupported-suite", signerId);
        case "invalid-signature":
          return new MTPSignatureVerificationError("invalid-signature", signerId);
        case "signer-id-mismatch":
          return new Error("relay signer ID mismatch");
        case "purpose-mismatch":
          return new Error("relay protection purpose mismatch");
        case "signer-key-not-found":
          return signerKeysUnavailable(signerId);
        case "replay":
          return new Error("relay message was already accepted");
        case "resource-limit":
          return new MTPResourceLimitError();
      }
    }
  }
  return error instanceof Error ? error : new Error(String(error));
}

export interface MTPRelayMetadataState {
  frame: ParsedFrame;
  native: RawBindings.WasmVerifiedRelayMetadata;
  relayVersion: number;
  signerId: bigint;
  finalRecipientId: bigint;
  messageId: string;
  createdAt: bigint;
  hasMetadata: boolean;
  metadata?: MTPDataValue;
  encryptedContent: Uint8Array;
  signerPublicKeys: Uint8Array[];
  matchedSignerKeyIndex: number;
  signaturePolicy: MTPSignatureVerificationPolicy;
  receiveLimits?: MTPReceiveLimits;
  receiveLimitsExplicit: boolean;
  disposed: boolean;
  finalizerToken: object;
}

export const relayMetadataState = new WeakMap<
  MTPVerifiedRelayMetadata,
  MTPRelayMetadataState
>();

const relayMetadataFinalizer = new FinalizationRegistry<
  RawBindings.WasmVerifiedRelayMetadata
>((native) => {
  try {
    native.free();
  } catch {
    // The WASM instance may already have been torn down during page unload.
  }
});

export const RELAY_METADATA_TOKEN = Symbol("mtp-authenticated-relay-metadata");

export class MTPVerifiedRelayMetadata {
  constructor(
    token: typeof RELAY_METADATA_TOKEN,
    state: MTPRelayMetadataState,
  ) {
    if (token !== RELAY_METADATA_TOKEN) {
      throw new Error("relay metadata must be created by authenticated opening");
    }
    relayMetadataState.set(this, state);
  }

  private get state(): MTPRelayMetadataState {
    const state = relayMetadataState.get(this);
    if (!state) throw new Error("relay metadata authentication state is missing");
    if (state.disposed) throw new Error("relay metadata has been disposed");
    return state;
  }

  dispose(): void {
    const state = relayMetadataState.get(this);
    if (!state || state.disposed) return;
    state.disposed = true;
    relayMetadataFinalizer.unregister(state.finalizerToken);
    try {
      state.native.free();
    } catch {
      // The WASM instance may already have been torn down during page unload.
    }
  }

  free(): void {
    this.dispose();
  }

  [Symbol.dispose](): void {
    this.dispose();
  }

  get frame(): ParsedFrame {
    return cloneParsedFrame(this.state.frame);
  }
  get signerId(): bigint {
    return this.state.signerId;
  }
  get relayVersion(): number {
    return this.state.relayVersion;
  }
  get finalRecipientId(): bigint {
    return this.state.finalRecipientId;
  }
  get messageId(): string {
    return this.state.messageId;
  }
  get createdAt(): bigint {
    return this.state.createdAt;
  }
  get metadata(): MTPDataValue | undefined {
    return this.state.hasMetadata
      ? (cloneParsedValue(this.state.metadata) as MTPDataValue)
      : undefined;
  }
  get encryptedContent(): Uint8Array {
    return this.state.encryptedContent.slice();
  }
  get signerPublicKeys(): Uint8Array[] {
    return this.state.signerPublicKeys.map((bundle) => bundle.slice());
  }
  get matchedSignerKeyIndex(): number {
    return this.state.matchedSignerKeyIndex;
  }
  get matchedSignerPublicKey(): Uint8Array {
    const key = this.state.signerPublicKeys[this.state.matchedSignerKeyIndex];
    if (!key) throw new Error("relay verification matched an unavailable signer key");
    return key.slice();
  }
  get signaturePolicy(): MTPSignatureVerificationPolicy {
    return this.state.signaturePolicy;
  }
}

export function registerRelayMetadata(
  metadata: MTPVerifiedRelayMetadata,
  native: RawBindings.WasmVerifiedRelayMetadata,
  finalizerToken: object,
): void {
  relayMetadataFinalizer.register(metadata, native, finalizerToken);
}

export type { MTPVerifiedRelayContent };
