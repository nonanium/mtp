import type {
  MTPDataValueInput,
  MTPClientOptions,
  MTPOpenRelayMetadataOptions,
  MTPOpenRelayContentOptions,
  MTPClient,
  MTPMergeOptions,
  MTPMergePath,
  MTPMergeReport,
  MTPMergeResult,
  MTPRelayTarget,
  MTPSendProtectedOptions,
  MTPSendSealedRelayOptions,
} from "../../sdk/src/sdk/index.js";

const recipients = [new Uint8Array([1])];

const clientOptions: MTPClientOptions = {
  url: "https://example.invalid",
  credentials: {
    clientId: 1,
    keyring: recipients[0],
    // @ts-expect-error keyringBytes was removed from the stable credential API
    keyringBytes: recipients[0],
  },
};

const protectedOptions: MTPSendProtectedOptions = {
  receiverId: 2,
  recipients,
  signaturePurpose: 32,
  encryptionPurpose: 33,
  // @ts-expect-error sendProtected has only receiverId
  receiver: 3,
};

const relayOptions: MTPSendSealedRelayOptions = {
  finalRecipientId: 2,
  nextHop: { kind: "iota", id: 3 },
  metadataRecipients: recipients,
  contentRecipients: recipients,
  // @ts-expect-error sealed relay frames never expose an outer sender
  sender: 1,
};

const relayTarget: MTPRelayTarget = { kind: "user", id: 3 };

const legacyRelayTarget: MTPSendSealedRelayOptions = {
  finalRecipientId: 2,
  // @ts-expect-error relay routes require a typed target
  nextHopId: 3,
  metadataRecipients: recipients,
  contentRecipients: recipients,
};

const metadataValues: MTPDataValueInput[] = [
  null,
  true,
  42,
  42n,
  "metadata",
  new Uint8Array([1, 2]),
  ["nested", false],
  { Metadata: "typed container" },
];

const relayReceiveOptions: MTPOpenRelayMetadataOptions = {
  resolveSignerPublicKeys: () => recipients,
};

const contentReceiveOptions: MTPOpenRelayContentOptions = {
  // @ts-expect-error replayGuard belongs to metadata opening or subscriptions
  replayGuard: { accept: () => true },
};

declare const client: MTPClient;
void client.sendProtected("ProtectedMessage", "scalar protected content", protectedOptions);
void client.sendSealedRelay("ProtectedMessage", new Uint8Array([1, 2, 3]), relayOptions);
void client.requestSealedRelay(
  "ProtectedMessage",
  new Uint8Array([1, 2, 3]),
  relayOptions,
);

// @ts-expect-error sealed relay subscriptions accept application type names, not numeric IDs
client.subscribeSealedRelay(32, () => {});

// @ts-expect-error relay receive uses the key-history resolver API
relayReceiveOptions.senderPublicKey = recipients[0];
// @ts-expect-error relay receive selects a verification policy, not a signature suite
relayReceiveOptions.signatureSuite = "dual";

void protectedOptions;
void relayOptions;
void metadataValues;
void relayReceiveOptions;
void contentReceiveOptions;

const mergePath: MTPMergePath = [1, 2];
const mergeReport: MTPMergeReport = {
  inserted: [mergePath],
  preserved: [],
  replaced: [],
  matched: [],
  recursed: [[1]],
};
const mergeOptions: MTPMergeOptions = { recursiveContainers: true };
declare const mergeResult: MTPMergeResult;
void mergeReport;
void mergeOptions;
void mergeResult;
void clientOptions;
void relayTarget;
void legacyRelayTarget;
