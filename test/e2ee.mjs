import { initSync } from "../dist/raw/index.js";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import assert from "node:assert/strict";
import { describe, it } from "node:test";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const wasmPath = path.resolve(__dirname, "../wasm/pkg/mtp_wasm_bg.wasm");
const wasmBytes = fs.readFileSync(wasmPath);
const wasmModule = new WebAssembly.Module(wasmBytes);
initSync(wasmModule);

const relayFixtureCreatedAtMillis = BigInt(
  fs
    .readFileSync(
      path.resolve(__dirname, "../fixtures/relay-created-at-ms.txt"),
      "utf8",
    )
    .trim(),
);

const sdk = await import("../dist/sdk/index.js");
const { MTPRatchet } = await import("../dist/sdk/ratchet.js");
const {
  serializeEncryptedMessage,
  parseEncryptedMessage,
  encryptPayload,
  decryptPayload,
  FLAG_INIT,
  MTP_E2EE_VERSION,
} = await import("../dist/sdk/encrypted-message.js");
const {
  MTPSessionManager,
  InMemorySessionStorage,
  deriveSessionKeys,
  derivePeerSessionId,
  buildSessionTranscript,
} = await import("../dist/sdk/session.js");

const bindings = sdk.raw;

class MemoryEndpoint {
  constructor(pipeId) {
    this.pipeId = pipeId;
    this.queue = [];
    this.waiters = [];
    this.peer = null;
    this.closed = false;
  }

  write(data) {
    if (this.closed || !this.peer || this.peer.closed) {
      return Promise.reject(new Error("memory pipe is closed"));
    }
    const chunk = data.slice();
    const waiter = this.peer.waiters.shift();
    if (waiter) waiter(chunk);
    else this.peer.queue.push(chunk);
    return Promise.resolve();
  }

  read() {
    if (this.queue.length > 0) return Promise.resolve(this.queue.shift());
    if (this.closed) return Promise.resolve(null);
    return new Promise((resolve) => this.waiters.push(resolve));
  }

  close() {
    this.closed = true;
    for (const resolve of this.waiters.splice(0)) resolve(null);
    if (this.peer) {
      this.peer.closed = true;
      for (const resolve of this.peer.waiters.splice(0)) resolve(null);
    }
    return Promise.resolve();
  }

  abort() {
    this.closed = true;
    for (const resolve of this.waiters.splice(0)) resolve(null);
    if (this.peer) {
      this.peer.closed = true;
      for (const resolve of this.peer.waiters.splice(0)) resolve(null);
    }
  }
}

function memoryDuplexPair(pipeId = 77) {
  const left = new MemoryEndpoint(pipeId);
  const right = new MemoryEndpoint(pipeId);
  left.peer = right;
  right.peer = left;
  return [left, right];
}

function publicBundle(keyring) {
  const keys = sdk.crypto.keyringToKeys(keyring);
  return concat(
    new Uint8Array([keys.kemPublicKey.length >> 8, keys.kemPublicKey.length & 0xff]),
    keys.kemPublicKey,
    new Uint8Array([keys.sigPqPublicKey.length >> 8, keys.sigPqPublicKey.length & 0xff]),
    keys.sigPqPublicKey,
    new Uint8Array([keys.sigClPublicKey.length >> 8, keys.sigClPublicKey.length & 0xff]),
    keys.sigClPublicKey,
  );
}

function ed25519OnlyEncryptionKeyring(keyring) {
  const keys = sdk.crypto.keyringToKeys(keyring);
  const fields = [
    keys.kemPublicKey,
    keys.kemSecretKey,
    new Uint8Array(0),
    new Uint8Array(0),
    keys.sigClPublicKey,
    keys.sigClSecretKey,
  ];
  return concat(
    ...fields.flatMap((field) => [
      new Uint8Array([field.length >> 8, field.length & 0xff]),
      field,
    ]),
  );
}

function concat(...arrays) {
  const totalLen = arrays.reduce((sum, a) => sum + a.length, 0);
  const result = new Uint8Array(totalLen);
  let offset = 0;
  for (const a of arrays) {
    result.set(a, offset);
    offset += a.length;
  }
  return result;
}

function setupSessions(sharedSecret, aliceId = 1n, bobId = 2n) {
  const aliceStorage = new InMemorySessionStorage();
  const aliceManager = new MTPSessionManager(aliceStorage);
  const bobStorage = new InMemorySessionStorage();
  const bobManager = new MTPSessionManager(bobStorage);
  const sessionId = derivePeerSessionId(aliceId, bobId);

  return {
    aliceManager,
    aliceStorage,
    bobManager,
    bobStorage,
    async initSessions() {
      const transcript = new Uint8Array([0x73, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e]);
      const { initiatorSend, initiatorRecv } = await deriveSessionKeys(
        sharedSecret,
        transcript,
      );
      const aliceSession = await aliceManager.createSession({
        sessionId,
        localId: aliceId,
        remoteId: bobId,
        remotePublicKey: new Uint8Array(32),
        sharedSecret,
        role: "initiator",
        transcript,
      });
      const bobSession = await bobManager.createSession({
        sessionId,
        localId: bobId,
        remoteId: aliceId,
        remotePublicKey: new Uint8Array(32),
        sharedSecret,
        role: "receiver",
        transcript,
      });
      return { aliceSession, bobSession, initiatorSend, initiatorRecv };
    },
  };
}

await describe("E2EE Session Derivation", async () => {
  await it("Both sides derive same shared secret", async () => {
    const sharedSecret = sdk.crypto.sha256(new Uint8Array([1, 2, 3, 4, 5]));
    const transcript = new Uint8Array(0);

    const aliceKeys = await deriveSessionKeys(sharedSecret, transcript);
    const bobKeys = await deriveSessionKeys(sharedSecret, transcript);

    // Deterministic: same inputs → same outputs
    assert.deepEqual(aliceKeys.initiatorSend, bobKeys.initiatorSend);
    assert.deepEqual(aliceKeys.initiatorRecv, bobKeys.initiatorRecv);

    // Init and recv keys are different
    assert.notDeepEqual(aliceKeys.initiatorSend, aliceKeys.initiatorRecv);
  });

  await it("Session manager assigns correct chain keys per role", async () => {
    const ss = sdk.crypto.sha256(new Uint8Array([1]));
    const { initSessions } = setupSessions(ss);
    const { aliceSession, bobSession, initiatorSend, initiatorRecv } =
      await initSessions();

    // Alice (initiator): send = initiatorSend, recv = initiatorRecv
    assert.deepEqual(aliceSession.sendChainKey, initiatorSend);
    assert.deepEqual(aliceSession.recvChainKey, initiatorRecv);

    // Bob (receiver): send = initiatorRecv, recv = initiatorSend
    assert.deepEqual(bobSession.sendChainKey, initiatorRecv);
    assert.deepEqual(bobSession.recvChainKey, initiatorSend);

    // Alice's send chain = Bob's recv chain
    assert.deepEqual(aliceSession.sendChainKey, bobSession.recvChainKey);
    // Alice's recv chain = Bob's send chain
    assert.deepEqual(aliceSession.recvChainKey, bobSession.sendChainKey);
  });

  await it("Different transcripts produce different keys", async () => {
    const ss = sdk.crypto.sha256(new Uint8Array([99]));
    const aliceKeys1 = await deriveSessionKeys(ss, new Uint8Array(0));
    const aliceKeys2 = await deriveSessionKeys(
      ss,
      sdk.crypto.sha256(new Uint8Array([42])),
    );
    assert.notDeepEqual(aliceKeys1.initiatorSend, aliceKeys2.initiatorSend);
  });
});

await describe("MTP Session Transcript", async () => {
  const base = {
    sessionId: "session-a",
    initiatorId: 1n,
    recipientId: 2n,
    recipientPublicKey: new Uint8Array([1, 2, 3]),
    kemCiphertext: new Uint8Array([4, 5, 6]),
  };

  await it("binds generic session identity and MTP key-establishment values", () => {
    const transcript = buildSessionTranscript(base);
    assert.notDeepEqual(
      transcript,
      buildSessionTranscript({ ...base, sessionId: "session-b" }),
    );
    assert.notDeepEqual(
      transcript,
      buildSessionTranscript({ ...base, initiatorId: 3n }),
    );
    assert.notDeepEqual(
      transcript,
      buildSessionTranscript({
        ...base,
        recipientPublicKey: new Uint8Array([1, 2, 4]),
      }),
    );
  });

  await it("hashes opaque application context into the transcript", () => {
    const withoutContext = buildSessionTranscript(base);
    const withContext = buildSessionTranscript({
      ...base,
      applicationContext: new Uint8Array([0x63, 0x6f, 0x6e, 0x74, 0x65, 0x78, 0x74]),
    });
    assert.notDeepEqual(withoutContext, withContext);
  });
});

await describe("E2EE Ratchet", async () => {
  await it("Repeated sends produce different message keys", async () => {
    const chainKey = sdk.crypto.sha256(new Uint8Array([42]));
    const step1 = await MTPRatchet.step(chainKey);
    const step2 = await MTPRatchet.step(step1.chainKey);
    const step3 = await MTPRatchet.step(step2.chainKey);

    assert.notDeepEqual(step1.key, step2.key);
    assert.notDeepEqual(step2.key, step3.key);
    assert.notDeepEqual(step1.key, step3.key);
    assert.notDeepEqual(chainKey, step1.chainKey);
  });

  await it("Receiver can decrypt messages sent by sender in order", async () => {
    const chainKey = sdk.crypto.sha256(new Uint8Array([7]));

    const send1 = await MTPRatchet.step(chainKey);
    const send2 = await MTPRatchet.step(send1.chainKey);
    const send3 = await MTPRatchet.step(send2.chainKey);

    const recv1 = await MTPRatchet.step(chainKey);
    const recv2 = await MTPRatchet.step(recv1.chainKey);
    const recv3 = await MTPRatchet.step(recv2.chainKey);

    assert.deepEqual(send1.key, recv1.key);
    assert.deepEqual(send2.key, recv2.key);
    assert.deepEqual(send3.key, recv3.key);
  });
});

await describe("E2EE Serialization", async () => {
  await it("Roundtrips a basic message", () => {
    const msg = {
      header: {
        version: 1,
        flags: 0,
        senderId: 0x1234567890abcdefn,
        recipientId: 0xfedcba0987654321n,
        messageNumber: 42,
      },
      aeadPayload: new Uint8Array([1, 2, 3, 4, 5]),
    };
    const bytes = serializeEncryptedMessage(msg);
    const parsed = parseEncryptedMessage(bytes);
    assert.equal(parsed.header.version, 1);
    assert.equal(parsed.header.flags, 0);
    assert.equal(parsed.header.senderId, msg.header.senderId);
    assert.equal(parsed.header.recipientId, msg.header.recipientId);
    assert.equal(parsed.header.messageNumber, 42);
    assert.equal(parsed.header.kemCiphertext, undefined);
    assert.deepEqual(parsed.aeadPayload, msg.aeadPayload);
  });

  await it("Roundtrips an init message with KEM ciphertext", () => {
    const msg = {
      header: {
        version: 1,
        flags: FLAG_INIT,
        senderId: 1n,
        recipientId: 2n,
        messageNumber: 0,
        kemCiphertext: new Uint8Array([0xde, 0xad, 0xbe, 0xef]),
      },
      aeadPayload: new Uint8Array([10, 20, 30]),
    };
    const bytes = serializeEncryptedMessage(msg);
    const parsed = parseEncryptedMessage(bytes);
    assert.equal(parsed.header.flags & FLAG_INIT, FLAG_INIT);
    assert.deepEqual(parsed.header.kemCiphertext, msg.header.kemCiphertext);
  });

  await it("Roundtrip: serialize(parse(x)) === x", () => {
    const msg = {
      header: {
        version: 1,
        flags: 0,
        senderId: 0xaaaabbbbccccddddn,
        recipientId: 0xffff000011112222n,
        messageNumber: 65535,
      },
      aeadPayload: new Uint8Array(100).fill(0x42),
    };
    const bytes = serializeEncryptedMessage(msg);
    const parsed = parseEncryptedMessage(bytes);
    const bytes2 = serializeEncryptedMessage(parsed);
    assert.deepEqual(bytes, bytes2);
  });

  await it("Rejects malformed payloads", () => {
    assert.throws(() => parseEncryptedMessage(new Uint8Array(0)));
    assert.throws(() => parseEncryptedMessage(new Uint8Array([0x01])));
    assert.throws(() =>
      parseEncryptedMessage(
        new Uint8Array([0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
      ),
    );
  });

  await it("Rejects unsupported version", () => {
    const msg = {
      header: {
        version: 1,
        flags: 0,
        senderId: 0n,
        recipientId: 0n,
        messageNumber: 0,
      },
      aeadPayload: new Uint8Array([1]),
    };
    const bytes = serializeEncryptedMessage(msg);
    bytes[0] = 99;
    assert.throws(() => parseEncryptedMessage(bytes));
  });

  await it("Rejects trailing data", () => {
    const msg = {
      header: {
        version: 1,
        flags: 0,
        senderId: 0n,
        recipientId: 0n,
        messageNumber: 0,
      },
      aeadPayload: new Uint8Array([1]),
    };
    const bytes = concat(
      serializeEncryptedMessage(msg),
      new Uint8Array([0xff]),
    );
    assert.throws(() => parseEncryptedMessage(bytes));
  });
});

await describe("E2EE Encrypt/Decrypt", async () => {
  await it("Alice encrypts and Bob decrypts successfully", async () => {
    const keyring = sdk.crypto.generateKeyring();
    const bobKeys = sdk.crypto.keyringToKeys(keyring);

    // Alice encapsulates to Bob's KEM public key
    const enc = sdk.crypto.encapsulate(bobKeys.kemPublicKey);
    // Bob decapsulates the ciphertext
    const bobSS = sdk.crypto.decapsulate(bobKeys.kemSecretKey, enc.ciphertext);
    assert.deepEqual(bobSS, enc.shared_secret);

    const ss = enc.shared_secret;
    const { initSessions } = setupSessions(ss);
    const { aliceSession, bobSession } = await initSessions();

    // Alice encrypts a message to Bob
    const plaintext = sdk.codec.encode(
      "Ping",
      { Version: "hello from Alice" },
      { sender: 1n, receiver: 2n },
    );

    const { payload, session: aliceNewSession } = await encryptPayload({
      plaintext,
      session: aliceSession,
      kemCiphertext: enc.ciphertext,
    });

    // Bob decrypts the message
    const { plaintext: decrypted, session: bobNewSession } =
      await decryptPayload({
        payload,
        session: bobSession,
      });

    const frame = sdk.codec.decode(decrypted);
    assert.equal(frame.type, "Ping");
    assert.equal(frame.data["Version"], "hello from Alice");

    // Chain keys advanced correctly
    assert.deepEqual(aliceNewSession.sendChainKey, bobNewSession.recvChainKey);
    assert.equal(aliceNewSession.sendCount, 1);
    assert.equal(bobNewSession.recvCount, 1);
    assert.notDeepEqual(
      aliceNewSession.sendChainKey,
      aliceSession.sendChainKey,
    );
  });

  await it("Encrypt-decrypt multiple messages with chain advance", async () => {
    const ss = sdk.crypto.sha256(new Uint8Array([1, 2, 3]));
    const { initSessions } = setupSessions(ss);
    let { aliceSession, bobSession } = await initSessions();

    // Message 1
    const { payload: p1, session: aliceAfter1 } = await encryptPayload({
      plaintext: sdk.codec.encode("Ping", { Version: "msg1" }),
      session: aliceSession,
    });
    const { plaintext: d1, session: bobAfter1 } = await decryptPayload({
      payload: p1,
      session: bobSession,
    });
    assert.equal(sdk.codec.decode(d1).data["Version"], "msg1");
    assert.equal(bobAfter1.recvCount, 1);

    // Message 2
    const { payload: p2, session: aliceAfter2 } = await encryptPayload({
      plaintext: sdk.codec.encode("Ping", { Version: "msg2" }),
      session: aliceAfter1,
    });
    const { plaintext: d2, session: bobAfter2 } = await decryptPayload({
      payload: p2,
      session: bobAfter1,
    });
    assert.equal(sdk.codec.decode(d2).data["Version"], "msg2");
    assert.equal(bobAfter2.recvCount, 2);

    // Chain keys match after two messages
    assert.deepEqual(aliceAfter2.sendChainKey, bobAfter2.recvChainKey);
    assert.equal(aliceAfter2.sendCount, 2);
  });

  await it("decrypts messages delivered out of order exactly once", async () => {
    const ss = sdk.crypto.sha256(new Uint8Array([4, 5, 6]));
    const { initSessions } = setupSessions(ss);
    let { aliceSession, bobSession } = await initSessions();

    const sent = [];
    for (const label of ["first", "second", "third"]) {
      const encrypted = await encryptPayload({
        plaintext: sdk.codec.encode("Ping", { Version: label }),
        session: aliceSession,
      });
      sent.push(encrypted.payload);
      aliceSession = encrypted.session;
    }

    const third = await decryptPayload({ payload: sent[2], session: bobSession });
    bobSession = third.session;
    assert.equal(sdk.codec.decode(third.plaintext).data["Version"], "third");
    assert.equal(bobSession.recvCount, 3);
    assert.deepEqual(
      bobSession.skippedMessageKeys.map(({ messageNumber }) => messageNumber),
      [0, 1],
    );

    const first = await decryptPayload({ payload: sent[0], session: bobSession });
    bobSession = first.session;
    assert.equal(sdk.codec.decode(first.plaintext).data["Version"], "first");
    assert.deepEqual(
      bobSession.skippedMessageKeys.map(({ messageNumber }) => messageNumber),
      [1],
    );

    const second = await decryptPayload({ payload: sent[1], session: bobSession });
    bobSession = second.session;
    assert.equal(sdk.codec.decode(second.plaintext).data["Version"], "second");
    assert.equal(bobSession.skippedMessageKeys.length, 0);
    await assert.rejects(
      decryptPayload({ payload: sent[0], session: bobSession }),
      /replay/,
    );
  });
});

await describe("E2EE Public Key Bundle", async () => {
  await it("parses public key bundles from GetUserData.PublicKey", () => {
    const keyring = sdk.crypto.generateKeyring();
    const keys = sdk.crypto.keyringToKeys(keyring);
    const bundle = concat(
      new Uint8Array([keys.kemPublicKey.length >> 8, keys.kemPublicKey.length & 0xff]),
      keys.kemPublicKey,
      new Uint8Array([keys.sigPqPublicKey.length >> 8, keys.sigPqPublicKey.length & 0xff]),
      keys.sigPqPublicKey,
      new Uint8Array([keys.sigClPublicKey.length >> 8, keys.sigClPublicKey.length & 0xff]),
      keys.sigClPublicKey,
    );

    const parsed = sdk.crypto.publicKeyBundleToKeys(bundle);
    assert.deepEqual(parsed.kemPublicKey, keys.kemPublicKey);
    assert.deepEqual(parsed.sigPqPublicKey, keys.sigPqPublicKey);
    assert.deepEqual(parsed.sigClPublicKey, keys.sigClPublicKey);
  });
});

await describe("Protected-value policy", async () => {
  await it("enforces the receiver-selected signature suite", () => {
    const keyring = sdk.crypto.generateKeyring();
    const bundle = publicBundle(keyring);
    const value = bindings.encode_data_value("policy-check");
    const edSigned = bindings.sign_data_value_with_keyring(
      value,
      7n,
      0x40,
      keyring,
      bindings.mtp_protection_signature_suite_ed25519(),
    );
    assert.doesNotThrow(() =>
      bindings.verify_data_value_with_policy(
        edSigned,
        bundle,
        7n,
        0x40,
        bindings.mtp_protection_signature_suite_ed25519(),
      ),
    );
    assert.throws(() =>
      bindings.verify_data_value_with_policy(
        edSigned,
        bundle,
        7n,
        0x40,
        bindings.mtp_protection_signature_suite_dual(),
      ),
    );

    const dualSigned = bindings.sign_data_value_with_keyring(
      value,
      7n,
      0x40,
      keyring,
      bindings.mtp_protection_signature_suite_dual(),
    );
    assert.doesNotThrow(() =>
      bindings.verify_data_value_with_policy(
        dualSigned,
        bundle,
        7n,
        0x40,
        bindings.mtp_protection_signature_suite_dual(),
      ),
    );
  });
});

await describe("Relay recipient separation", async () => {
  await it("lets a metadata recipient open metadata but not content", async () => {
    const senderKeyring = sdk.crypto.generateKeyring();
    const metadataKeyring = sdk.crypto.generateKeyring();
    const finalKeyring = sdk.crypto.generateKeyring();
    const metadataRecipients = [
      publicBundle(metadataKeyring),
      publicBundle(finalKeyring),
    ];
    const contentRecipients = [publicBundle(finalKeyring)];

    const frameBytes = bindings.build_encrypted_relay_frame_with_keyring(
      "ProtectedMessage",
      { ExampleType: "hello" },
      11n,
      42n,
      7n,
      "message-1",
      123n,
      bindings.encode_data_value({ ExampleType: "metadata" }),
      senderKeyring,
      bindings.mtp_protection_signature_suite_dual(),
      metadataRecipients,
      contentRecipients,
    );
    const frame = bindings.parse_frame(frameBytes);
    assert.equal(frame.type, "Relay");
    assert.equal(frame.sender, undefined);
    assert.equal(frame.receiver, 7n);

    const metadataBytes = frame.data.encoded;
    const openedMetadata = bindings.decrypt_data_value(
      metadataBytes,
      metadataKeyring,
      bindings.mtp_relay_metadata_encryption_purpose(),
    );
    const metadata = bindings.parse_data_value(openedMetadata);
    assert.equal(metadata.kind, "signed");
    assert.equal(BigInt(metadata.value.RelayVersion), 1n);
    assert.equal(BigInt(metadata.value.FinalRecipientId), 42n);
    assert.equal(metadata.value.Metadata.ExampleType, "metadata");

    const metadataClient = await sdk.MTPClient.create({
      url: "https://example.invalid",
      credentials: { clientId: 7n, keyring: metadataKeyring },
      pings: false,
    });
    const verifiedMetadata = await metadataClient.openRelayMetadata(frame, {
      expectedSignerId: 11n,
      resolveSignerPublicKeys: () => [publicBundle(senderKeyring)],
      signaturePolicy: "dual",
    });
    assert.equal(verifiedMetadata.relayVersion, 1);
    assert.equal(verifiedMetadata.finalRecipientId, 42n);
    assert.deepEqual(verifiedMetadata.metadata, {
      ExampleType: "metadata",
    });
    await assert.rejects(
      () => metadataClient.openRelayContent(verifiedMetadata),
      /different final recipient/,
    );

    const encryptedContent = metadata.value.Content.encoded;
    assert.throws(() =>
      bindings.decrypt_data_value(
        encryptedContent,
        metadataKeyring,
        bindings.mtp_relay_content_encryption_purpose(),
      ),
    );

    const forwardedBytes = bindings.forward_encrypted_relay_frame(frameBytes, 42n);
    const forwarded = bindings.parse_frame(forwardedBytes);
    assert.deepEqual(forwarded.data.encoded, frame.data.encoded);
    const finalMetadata = bindings.parse_data_value(
      bindings.decrypt_data_value(
        forwarded.data.encoded,
        finalKeyring,
        bindings.mtp_relay_metadata_encryption_purpose(),
      ),
    );
    assert.equal(BigInt(finalMetadata.value.RelayVersion), 1n);
    const content = bindings.parse_data_value(
      bindings.decrypt_data_value(
        finalMetadata.value.Content.encoded,
        finalKeyring,
        bindings.mtp_relay_content_encryption_purpose(),
      ),
    );
    assert.equal(content.kind, "signed");
    assert.equal(content.value.MessageType, "ProtectedMessage");
    assert.equal(content.value.Content.ExampleType, "hello");
  });

  await it("opens forwarded relay data with explicit identities", async () => {
    const senderKeyring = sdk.crypto.generateKeyring();
    const metadataKeyring = sdk.crypto.generateKeyring();
    const finalKeyring = sdk.crypto.generateKeyring();
    const frameBytes = bindings.build_encrypted_relay_frame_with_keyring(
      "ProtectedMessage",
      { ExampleType: "explicit-identity" },
      11n,
      42n,
      7n,
      "message-explicit-identity",
      456n,
      bindings.encode_data_value({ ExampleType: "forwarded" }),
      senderKeyring,
      bindings.mtp_protection_signature_suite_dual(),
      [publicBundle(metadataKeyring), publicBundle(finalKeyring)],
      [publicBundle(finalKeyring)],
    );
    const forwarded = bindings.parse_frame(
      bindings.forward_encrypted_relay_frame(frameBytes, 99n),
    );
    const verification = {
      expectedSignerId: 11n,
      resolveSignerPublicKeys: () => [publicBundle(senderKeyring)],
      signaturePolicy: "dual",
    };

    const metadataClient = await sdk.MTPClient.create({
      url: "https://example.invalid",
      pings: false,
    });
    const metadata = await metadataClient.openRelayMetadata(forwarded, {
      ...verification,
      recipient: { keyring: metadataKeyring },
    });
    assert.equal(metadata.finalRecipientId, 42n);
    assert.deepEqual(metadata.metadata, { ExampleType: "forwarded" });

    const wrongKeyring = sdk.crypto.generateKeyring();
    await assert.rejects(
      () =>
        metadataClient.openRelayMetadata(forwarded, {
          ...verification,
          recipient: { keyring: wrongKeyring },
        }),
    );

    const registeredClient = await sdk.MTPClient.create({
      url: "https://example.invalid",
      credentials: { clientId: 7n, keyring: metadataKeyring },
      pings: false,
    });
    const finalIdentity = { id: 42n, keyring: finalKeyring };
    const finalMetadata = await registeredClient.openRelayMetadata(
      forwarded,
      {
        ...verification,
        recipient: finalIdentity,
      },
    );
    const content = await registeredClient.openRelayContent(finalMetadata, {
      ...verification,
      recipient: finalIdentity,
    });
    assert.equal(content.signerId, 11n);
    assert.equal(content.finalRecipientId, 42n);
    assert.equal(content.data.ExampleType, "explicit-identity");

    await assert.rejects(
      () =>
        registeredClient.openRelayContent(finalMetadata, {
          ...verification,
          recipient: finalIdentity,
          expectedFinalRecipientId: 99n,
        }),
      /different final recipient/,
    );
  });
});

await describe("Relay recipient key history", async () => {
  function verificationOptions(recipient) {
    return {
      recipient,
      expectedSignerId: 11n,
      resolveSignerPublicKeys: () => [publicBundle(senderKeyring)],
      signaturePolicy: "dual",
    };
  }

  let senderKeyring;

  await it("uses the current keyring and accepts an empty history", async () => {
    senderKeyring = sdk.crypto.generateKeyring();
    const recipientKeyring = sdk.crypto.generateKeyring();
    const frame = bindings.parse_frame(
      bindings.build_encrypted_relay_frame_with_keyring(
        "ProtectedMessage",
        { ExampleType: "current-key" },
        11n,
        42n,
        42n,
        "message-current-key",
        1n,
        null,
        senderKeyring,
        bindings.mtp_protection_signature_suite_dual(),
        [publicBundle(recipientKeyring)],
        [publicBundle(recipientKeyring)],
      ),
    );
    const client = await sdk.MTPClient.create({
      url: "https://example.invalid",
      pings: false,
    });
    const options = verificationOptions({
      id: 42n,
      keyring: recipientKeyring,
      keyringHistory: [],
    });

    const metadata = await client.openRelayMetadata(frame, options);
    const content = await client.openRelayContent(metadata, options);
    assert.equal(content.data.ExampleType, "current-key");
  });

  await it(
    "tries rotated metadata and content recipients newest to oldest without duplicates",
    async () => {
      senderKeyring = sdk.crypto.generateKeyring();
      const currentKeyring = sdk.crypto.generateKeyring();
      const newerPreviousKeyring = sdk.crypto.generateKeyring();
      const previousKeyring = sdk.crypto.generateKeyring();
      const history = [
        newerPreviousKeyring,
        previousKeyring,
        previousKeyring,
      ];
      const historySnapshot = history.map((keyring) => keyring.slice());
      const frame = bindings.parse_frame(
        bindings.build_encrypted_relay_frame_with_keyring(
          "ProtectedMessage",
          { ExampleType: "rotated-key" },
          11n,
          42n,
          7n,
          "message-rotated-key",
          2n,
          bindings.encode_data_value({ ExampleType: "rotated-metadata" }),
          senderKeyring,
          bindings.mtp_protection_signature_suite_dual(),
          [publicBundle(previousKeyring)],
          [publicBundle(previousKeyring)],
        ),
      );
      const client = await sdk.MTPClient.create({
        url: "https://example.invalid",
        pings: false,
      });
      const options = verificationOptions({
        id: 42n,
        keyring: currentKeyring,
        keyringHistory: history,
      });

      const metadata = await client.openRelayMetadata(frame, options);
      const content = await client.openRelayContent(metadata, options);
      assert.equal(content.data.ExampleType, "rotated-key");
      assert.equal(metadata.matchedSignerKeyIndex, 0);
      assert.equal(metadata.signerPublicKeys.length, 1);
      assert.deepEqual(
        metadata.matchedSignerPublicKey,
        publicBundle(senderKeyring),
      );
      assert.deepEqual(history, historySnapshot);
    },
  );

  await it("does not expose individual key failures when all keyrings fail", async () => {
    senderKeyring = sdk.crypto.generateKeyring();
    const recipientKeyring = sdk.crypto.generateKeyring();
    const wrongCurrentKeyring = sdk.crypto.generateKeyring();
    const wrongPreviousKeyring = sdk.crypto.generateKeyring();
    const frame = bindings.parse_frame(
      bindings.build_encrypted_relay_frame_with_keyring(
        "ProtectedMessage",
        { ExampleType: "wrong-key" },
        11n,
        42n,
        42n,
        "message-wrong-key",
        3n,
        null,
        senderKeyring,
        bindings.mtp_protection_signature_suite_dual(),
        [publicBundle(recipientKeyring)],
        [publicBundle(recipientKeyring)],
      ),
    );
    const client = await sdk.MTPClient.create({
      url: "https://example.invalid",
      pings: false,
    });

    await assert.rejects(
      () =>
        client.openRelayMetadata(frame, {
          ...verificationOptions({
            keyring: wrongCurrentKeyring,
            keyringHistory: [wrongPreviousKeyring],
          }),
        }),
      (error) =>
        error.message ===
        "Unable to decrypt protected value with supplied recipient keyrings",
    );
  });
});

await describe("Protected send APIs", async () => {
  function captureSend(client) {
    const frames = [];
    client.raw.client.send = async (frame) => {
      frames.push(frame.slice());
    };
    return frames;
  }

  await it("round trips with interoperable Ed25519 defaults", async () => {
    const signerKeyring = sdk.crypto.generateKeyring();
    const recipientKeyring = sdk.crypto.generateKeyring();
    const client = await sdk.MTPClient.create({
      url: "https://example.invalid",
      pings: false,
    });
    const frames = captureSend(client);
    const signerPublicKey = publicBundle(signerKeyring);
    const recipientPublicKey = publicBundle(recipientKeyring);

    await client.sendProtected(
      "ProtectedMessage",
      { ExampleType: "default-direct" },
      {
        receiverId: 22n,
        identity: { signerId: 11n, keyring: signerKeyring },
        recipients: [recipientPublicKey],
        signaturePurpose: 0x40,
        encryptionPurpose: 0x41,
      },
    );
    const directFrame = sdk.codec.decode(frames.shift());
    const direct = await client.openProtected(directFrame, {
      recipient: { id: 22n, keyring: recipientKeyring },
      expectedSignerId: 11n,
      expectedReceiverId: 22n,
      resolveSignerPublicKeys: () => [signerPublicKey],
      signaturePurpose: 0x40,
      encryptionPurpose: 0x41,
    });
    assert.equal(direct.data.ExampleType, "default-direct");

    await client.sendSealedRelay(
      "ProtectedMessage",
      { ExampleType: "default-relay" },
      {
        finalRecipientId: 22n,
        nextHopId: 7n,
        identity: { signerId: 11n, keyring: signerKeyring },
        metadataRecipients: [recipientPublicKey],
        contentRecipients: [recipientPublicKey],
        metadata: { ExampleType: "default-metadata" },
      },
    );
    const relayFrame = sdk.codec.decode(frames.shift());
    const relayOptions = {
      recipient: { id: 22n, keyring: recipientKeyring },
      expectedSignerId: 11n,
      resolveSignerPublicKeys: () => [signerPublicKey],
    };
    const metadata = await client.openRelayMetadata(relayFrame, relayOptions);
    const content = await client.openRelayContent(metadata, relayOptions);
    assert.equal(metadata.metadata.ExampleType, "default-metadata");
    assert.equal(content.data.ExampleType, "default-relay");
    metadata.dispose();
  });

  await it("builds direct protected frames without a Relay hop", async () => {
    const signerKeyring = sdk.crypto.generateKeyring();
    const recipientKeyring = sdk.crypto.generateKeyring();
    const client = await sdk.MTPClient.create({
      url: "https://example.invalid",
      pings: false,
    });
    const frames = captureSend(client);

    await client.sendProtected(
      "ProtectedMessage",
      { ExampleType: "direct" },
      {
        receiverId: 22n,
        id: 123,
        identity: { signerId: 11n, keyring: signerKeyring },
        recipients: [publicBundle(recipientKeyring)],
        signaturePurpose: 0x40,
        encryptionPurpose: 0x41,
        signatureSuite: "dual",
        exposeSender: true,
      },
    );

    assert.equal(frames.length, 1);
    const frame = bindings.parse_frame(frames[0]);
    assert.equal(frame.type, "ProtectedMessage");
    assert.equal(frame.id, 123);
    assert.equal(frame.sender, 11n);
    assert.equal(frame.receiver, 22n);
    assert.equal(frame.data.kind, "encrypted");

    const signedBytes = bindings.decrypt_data_value(
      frame.data.encoded,
      recipientKeyring,
      0x41,
    );
    const signed = bindings.parse_data_value(signedBytes);
    assert.equal(signed.kind, "signed");
    assert.equal(signed.signerId, 11n);
    assert.equal(signed.value.Content.ExampleType, "direct");
    assert.equal(signed.value.MessageType, "ProtectedMessage");
    assert.equal(BigInt(signed.value.FinalRecipientId), 22n);
    assert.equal(typeof signed.value.MessageId, "string");
    assert.equal(BigInt(signed.value.CreatedAt) > 0n, true);
    bindings.verify_data_value_with_policy(
      signedBytes,
      publicBundle(signerKeyring),
      11n,
      0x40,
      bindings.mtp_protection_signature_suite_dual(),
    );

    await assert.rejects(
      () =>
        client.sendProtected("Ping", { ExampleType: "reserved" }, {
          receiverId: 22n,
          identity: { signerId: 11n, keyring: signerKeyring },
          recipients: [publicBundle(recipientKeyring)],
          signaturePurpose: 0x40,
          encryptionPurpose: 0x41,
        }),
      /control communication type/,
    );
  });

  await it("builds sealed relay frames from exact generic recipient sets", async () => {
    const signerKeyring = sdk.crypto.generateKeyring();
    const metadataKeyring = sdk.crypto.generateKeyring();
    const contentKeyring = sdk.crypto.generateKeyring();
    const client = await sdk.MTPClient.create({
      url: "https://example.invalid",
      pings: false,
    });
    const frames = captureSend(client);

    await client.sendSealedRelay(
      "ProtectedMessage",
      { ExampleType: "content" },
      {
        finalRecipientId: 42n,
        nextHopId: 7n,
        identity: { signerId: 11n, keyring: signerKeyring },
        metadataRecipients: [publicBundle(metadataKeyring)],
        contentRecipients: [publicBundle(contentKeyring)],
        metadata: { ExampleType: "metadata" },
        signatureSuite: "dual",
      },
    );

    assert.equal(frames.length, 1);
    const frame = bindings.parse_frame(frames[0]);
    assert.equal(frame.type, "Relay");
    assert.equal(frame.sender, undefined);
    assert.equal(frame.receiver, 7n);

    const metadataBytes = bindings.decrypt_data_value(
      frame.data.encoded,
      metadataKeyring,
      bindings.mtp_relay_metadata_encryption_purpose(),
    );
    const metadata = bindings.parse_data_value(metadataBytes);
    assert.equal(metadata.kind, "signed");
    assert.equal(metadata.signerId, 11n);
    assert.equal(BigInt(metadata.value.FinalRecipientId), 42n);
    assert.equal(metadata.value.Metadata.ExampleType, "metadata");
    assert.equal(metadata.value.Content.kind, "encrypted");

    assert.throws(() =>
      bindings.decrypt_data_value(
        metadata.value.Content.encoded,
        metadataKeyring,
        bindings.mtp_relay_content_encryption_purpose(),
      ),
    );
    const contentBytes = bindings.decrypt_data_value(
      metadata.value.Content.encoded,
      contentKeyring,
      bindings.mtp_relay_content_encryption_purpose(),
    );
    const content = bindings.parse_data_value(contentBytes);
    assert.equal(content.kind, "signed");
    assert.equal(content.value.Content.ExampleType, "content");

    await assert.rejects(
      () =>
        client.sendSealedRelay("Relay", { ExampleType: "reserved" }, {
          finalRecipientId: 42n,
          nextHopId: 7n,
          identity: { signerId: 11n, keyring: signerKeyring },
          metadataRecipients: [publicBundle(metadataKeyring)],
          contentRecipients: [publicBundle(contentKeyring)],
        }),
      /control communication type/,
    );
  });

  await it("round trips generic relay content and metadata presence", async () => {
    const signerKeyring = sdk.crypto.generateKeyring();
    const recipientKeyring = sdk.crypto.generateKeyring();
    const client = await sdk.MTPClient.create({
      url: "https://example.invalid",
      pings: false,
    });
    const frames = captureSend(client);
    const openOptions = {
      recipient: { id: 42n, keyring: recipientKeyring },
      expectedSignerId: 11n,
      resolveSignerPublicKeys: () => [publicBundle(signerKeyring)],
      signaturePolicy: "dual",
    };

    const sendAndOpen = async (data, metadata, includeMetadata) => {
      const options = {
        finalRecipientId: 42n,
        nextHopId: 42n,
        identity: { signerId: 11n, keyring: signerKeyring },
        metadataRecipients: [publicBundle(recipientKeyring)],
        contentRecipients: [publicBundle(recipientKeyring)],
        signatureSuite: "dual",
        ...(includeMetadata ? { metadata } : {}),
      };
      await client.sendSealedRelay("ProtectedMessage", data, options);
      const frame = sdk.codec.decode(frames.pop());
      const verifiedMetadata = await client.openRelayMetadata(
        frame,
        openOptions,
      );
      const content = await client.openRelayContent(
        verifiedMetadata,
        openOptions,
      );
      return { verifiedMetadata, content };
    };

    const explicitNull = await sendAndOpen(
      new Uint8Array([1, 2, 3]),
      null,
      true,
    );
    assert.equal(explicitNull.verifiedMetadata.metadata, null);
    assert.deepEqual(explicitNull.content.data, new Uint8Array([1, 2, 3]));

    const absent = await sendAndOpen(
      ["array", 7, false],
      undefined,
      false,
    );
    assert.equal(absent.verifiedMetadata.metadata, undefined);
    assert.deepEqual(absent.content.data, ["array", 7, false]);

    const scalar = await sendAndOpen("scalar content", "scalar metadata", true);
    assert.equal(scalar.verifiedMetadata.metadata, "scalar metadata");
    assert.equal(scalar.content.data, "scalar content");
  });

  await it("opens an unauthenticated connection without discarding credentials", async () => {
    const keyring = sdk.crypto.generateKeyring();
    const client = await sdk.MTPClient.create({
      url: "https://example.invalid",
      hostPublicKey: new Uint8Array([1]),
      credentials: { clientId: 99n, keyring },
      pings: false,
    });
    let connectCalls = 0;
    let authCalls = 0;
    client.raw.client.connect = async () => {
      connectCalls += 1;
    };
    client.raw.client.auth_connect = async () => {
      authCalls += 1;
      return 99n;
    };

    await client.connectUnauthenticated();

    assert.equal(connectCalls, 1);
    assert.equal(authCalls, 0);
    assert.equal(client.credentials.clientId, 99n);
  });

  await it("opens an authenticated connection when transport credentials are available", async () => {
    const transportKeyring = sdk.crypto.generateKeyring();
    const client = await sdk.MTPClient.create({
      url: "https://example.invalid",
      hostPublicKey: new Uint8Array([1]),
      credentials: { clientId: 99n, keyring: transportKeyring },
      pings: false,
    });
    let connectCalls = 0;
    let authCalls = 0;
    client.raw.client.connect = async () => {
      connectCalls += 1;
    };
    client.raw.client.auth_connect = async (
      _config,
      hostPublicKey,
      keyring,
      clientId,
    ) => {
      authCalls += 1;
      assert.deepEqual(hostPublicKey, new Uint8Array([1]));
      assert.deepEqual(keyring, transportKeyring);
      assert.equal(clientId, 99n);
      return 99n;
    };

    await client.connect();

    assert.equal(connectCalls, 0);
    assert.equal(authCalls, 1);
    assert.equal(client.credentials.clientId, 99n);
  });

  await it("keeps a protected signer independent from transport authentication", async () => {
    const transportKeyring = sdk.crypto.generateKeyring();
    const signerKeyring = sdk.crypto.generateKeyring();
    const recipientKeyring = sdk.crypto.generateKeyring();
    const client = await sdk.MTPClient.create({
      url: "https://example.invalid",
      hostPublicKey: new Uint8Array([1]),
      credentials: { clientId: 99n, keyring: transportKeyring },
      pings: false,
    });
    client.raw.client.auth_connect = async () => 99n;
    await client.connect();
    const frames = captureSend(client);

    await client.sendProtected(
      "ProtectedMessage",
      { ExampleType: "transport-independent" },
      {
        receiverId: 22n,
        identity: { signerId: 11n, keyring: signerKeyring },
        recipients: [publicBundle(recipientKeyring)],
        signaturePurpose: 0x40,
        encryptionPurpose: 0x41,
        signatureSuite: "dual",
      },
    );

    const frame = bindings.parse_frame(frames[0]);
    assert.equal(client.credentials.clientId, 99n);
    assert.equal(frame.sender, undefined);
    const signedBytes = bindings.decrypt_data_value(
      frame.data.encoded,
      recipientKeyring,
      0x41,
    );
    const signed = bindings.parse_data_value(signedBytes);
    assert.equal(signed.kind, "signed");
    assert.equal(signed.signerId, 11n);
    assert.equal(signed.value.Content.ExampleType, "transport-independent");
  });
});

await describe("Protected receive APIs", async () => {
  async function buildDirectFrame({
    signerKeyring,
    recipientKeyring,
    data = { ExampleType: "direct-receive" },
    exposeSender = true,
    receiverId = 22n,
    signaturePurpose = 0x40,
    encryptionPurpose = 0x41,
    signatureSuite = "dual",
  }) {
    const client = await sdk.MTPClient.create({
      url: "https://example.invalid",
      pings: false,
    });
    const frames = [];
    client.raw.client.send = async (frame) => frames.push(frame.slice());
    await client.sendProtected(
      "ProtectedMessage",
      data,
      {
        receiverId,
        identity: { signerId: 11n, keyring: signerKeyring },
        recipients: [publicBundle(recipientKeyring)],
        signaturePurpose,
        encryptionPurpose,
        signatureSuite,
        exposeSender,
      },
    );
    return frames[0];
  }

  function openOptions(signerKeyring, recipientKeyring, overrides = {}) {
    return {
      recipient: { id: 22n, keyring: recipientKeyring },
      expectedSignerId: 11n,
      expectedReceiverId: 22n,
      resolveSignerPublicKeys: (signerId) => {
        assert.equal(signerId, 11n);
        return [publicBundle(signerKeyring)];
      },
      signaturePolicy: "dual",
      signaturePurpose: 0x40,
      encryptionPurpose: 0x41,
      ...overrides,
    };
  }

  await it("opens exposed and hidden outer senders", async () => {
    const signerKeyring = sdk.crypto.generateKeyring();
    const recipientKeyring = sdk.crypto.generateKeyring();
    const client = await sdk.MTPClient.create({
      url: "https://example.invalid",
      pings: false,
    });

    const exposed = await client.openProtected(
      await buildDirectFrame({ signerKeyring, recipientKeyring }),
      openOptions(signerKeyring, recipientKeyring),
    );
    assert.equal(exposed.type, "ProtectedMessage");
    assert.equal(exposed.protectedVersion, 1);
    assert.equal(exposed.signerId, 11n);
    assert.equal(exposed.finalRecipientId, 22n);
    assert.equal(exposed.receiver, 22n);
    assert.equal(exposed.outerSender, 11n);
    assert.equal(typeof exposed.messageId, "string");
    assert.equal(typeof exposed.createdAt, "bigint");
    assert.deepEqual(exposed.data, {
      ExampleType: "direct-receive",
    });

    const hidden = await client.openProtected(
      await buildDirectFrame({
        signerKeyring,
        recipientKeyring,
        exposeSender: false,
      }),
      openOptions(signerKeyring, recipientKeyring),
    );
    assert.equal(hidden.outerSender, undefined);
    assert.equal(hidden.signerId, 11n);
  });

  await it("authenticates direct routing fields and rejects direct replays", async () => {
    const signerKeyring = sdk.crypto.generateKeyring();
    const recipientKeyring = sdk.crypto.generateKeyring();
    const client = await sdk.MTPClient.create({
      url: "https://example.invalid",
      pings: false,
    });
    const frame = await buildDirectFrame({ signerKeyring, recipientKeyring });

    const changedType = frame.slice();
    changedType[4] = 0;
    changedType[5] = 33;
    await assert.rejects(
      () =>
        client.openProtected(
          changedType,
          openOptions(signerKeyring, recipientKeyring),
        ),
      /protected message type does not match outer routing/,
    );

    const parsed = bindings.parse_frame(frame);
    const changedSender = bindings.build_frame_with_payload(
      "ProtectedMessage",
      parsed.data.encoded,
      { receiver: 22n, sender: 12n },
    );
    await assert.rejects(
      () =>
        client.openProtected(
          changedSender,
          openOptions(signerKeyring, recipientKeyring),
        ),
      /protected frame sender does not match authenticated signer/,
    );

    const changedReceiver = await buildDirectFrame({
      signerKeyring,
      recipientKeyring,
      exposeSender: false,
    });
    // The frame has an ID and receiver but no sender, so the receiver's final
    // byte is at offset 18 in the MTP wire header.
    changedReceiver[18] ^= 1;
    await assert.rejects(
      () =>
        client.openProtected(
          changedReceiver,
          openOptions(signerKeyring, recipientKeyring, {
            recipient: { keyring: recipientKeyring },
            expectedReceiverId: undefined,
          }),
        ),
      /protected final recipient does not match outer routing receiver/,
    );

    const replayOptions = openOptions(signerKeyring, recipientKeyring);
    await client.openProtected(frame, replayOptions);
    await assert.rejects(
      () => client.openProtected(frame, replayOptions),
      (error) => error instanceof sdk.MTPReplayError,
    );
  });

  await it("snapshots parsed direct frames before async signer resolution", async () => {
    const signerKeyring = sdk.crypto.generateKeyring();
    const recipientKeyring = sdk.crypto.generateKeyring();
    const serialized = await buildDirectFrame({
      signerKeyring,
      recipientKeyring,
    });
    const parsed = bindings.parse_frame(serialized);
    delete parsed.raw;

    let releaseKeys;
    const keysReady = new Promise((resolve) => {
      releaseKeys = resolve;
    });
    const client = await sdk.MTPClient.create({
      url: "https://example.invalid",
      pings: false,
    });
    const opening = client.openProtected(parsed, {
      recipient: { id: 22n, keyring: recipientKeyring },
      resolveSignerPublicKeys: async () => {
        await keysReady;
        return [publicBundle(signerKeyring)];
      },
      signaturePolicy: "dual",
      signaturePurpose: 0x40,
      encryptionPurpose: 0x41,
    });

    parsed.receiver = 23n;
    releaseKeys();
    const message = await opening;
    assert.equal(message.receiver, 22n);
  });

  await it("validates the expected signer and outer receiver", async () => {
    const signerKeyring = sdk.crypto.generateKeyring();
    const recipientKeyring = sdk.crypto.generateKeyring();
    const frame = await buildDirectFrame({ signerKeyring, recipientKeyring });
    const client = await sdk.MTPClient.create({
      url: "https://example.invalid",
      pings: false,
    });

    let resolverCalls = 0;
    await assert.rejects(
      () =>
        client.openProtected(
          frame,
          openOptions(signerKeyring, recipientKeyring, {
            expectedSignerId: 99n,
            resolveSignerPublicKeys: () => {
              resolverCalls += 1;
              return [publicBundle(signerKeyring)];
            },
          }),
        ),
      /protected signer ID mismatch/,
    );
    assert.equal(
      resolverCalls,
      0,
      "expected signer mismatch must precede signer-key resolution",
    );
    await assert.rejects(
      () =>
        client.openProtected(
          frame,
          openOptions(signerKeyring, recipientKeyring, {
            expectedReceiverId: 23n,
          }),
        ),
      /protected frame receiver ID mismatch/,
    );
  });

  await it("uses current and historical recipient keyrings", async () => {
    const signerKeyring = sdk.crypto.generateKeyring();
    const currentRecipientKeyring = sdk.crypto.generateKeyring();
    const historicalRecipientKeyring = sdk.crypto.generateKeyring();
    const client = await sdk.MTPClient.create({
      url: "https://example.invalid",
      pings: false,
    });

    const currentFrame = await buildDirectFrame({
      signerKeyring,
      recipientKeyring: currentRecipientKeyring,
    });
    const current = await client.openProtected(
      currentFrame,
      openOptions(signerKeyring, currentRecipientKeyring),
    );
    assert.equal(current.data.ExampleType, "direct-receive");

    const historicalFrame = await buildDirectFrame({
      signerKeyring,
      recipientKeyring: historicalRecipientKeyring,
    });
    const historical = await client.openProtected(
      historicalFrame,
      openOptions(signerKeyring, currentRecipientKeyring, {
        recipient: {
          id: 22n,
          keyring: currentRecipientKeyring,
          keyringHistory: [historicalRecipientKeyring],
        },
      }),
    );
    assert.equal(historical.data.ExampleType, "direct-receive");

    await assert.rejects(
      () =>
        client.openProtected(
          historicalFrame,
          openOptions(signerKeyring, sdk.crypto.generateKeyring()),
        ),
      /Unable to decrypt protected value with supplied recipient keyrings/,
    );
  });

  await it("round trips non-container application DataValues", async () => {
    const signerKeyring = sdk.crypto.generateKeyring();
    const recipientKeyring = sdk.crypto.generateKeyring();
    const client = await sdk.MTPClient.create({
      url: "https://example.invalid",
      pings: false,
    });
    const options = openOptions(signerKeyring, recipientKeyring);

    const stringMessage = await client.openProtected(
      await buildDirectFrame({
        signerKeyring,
        recipientKeyring,
        data: "direct string",
      }),
      options,
    );
    assert.equal(stringMessage.data, "direct string");

    const arrayMessage = await client.openProtected(
      await buildDirectFrame({
        signerKeyring,
        recipientKeyring,
        data: ["direct array", 7, false],
      }),
      options,
    );
    assert.deepEqual(arrayMessage.data, ["direct array", 7, false]);

    const bytesMessage = await client.openProtected(
      await buildDirectFrame({
        signerKeyring,
        recipientKeyring,
        data: new Uint8Array([3, 1, 4]),
      }),
      options,
    );
    assert.deepEqual(bytesMessage.data, new Uint8Array([3, 1, 4]));

    const largeIntegerMessage = await client.openProtected(
      await buildDirectFrame({
        signerKeyring,
        recipientKeyring,
        data: 9_007_199_254_740_992n,
      }),
      options,
    );
    assert.equal(largeIntegerMessage.data, 9_007_199_254_740_992n);

    const safeIntegerMessage = await client.openProtected(
      await buildDirectFrame({
        signerKeyring,
        recipientKeyring,
        data: 9_007_199_254_740_991,
      }),
      options,
    );
    assert.equal(safeIntegerMessage.data, 9_007_199_254_740_991);

    const largeSignedMessage = await client.openProtected(
      await buildDirectFrame({
        signerKeyring,
        recipientKeyring,
        data: -9_007_199_254_740_992n,
      }),
      options,
    );
    assert.equal(largeSignedMessage.data, -9_007_199_254_740_992n);

    const largeUnsignedMessage = await client.openProtected(
      await buildDirectFrame({
        signerKeyring,
        recipientKeyring,
        data: 18_446_744_073_709_551_615n,
      }),
      options,
    );
    assert.equal(largeUnsignedMessage.data, 18_446_744_073_709_551_615n);

    await assert.rejects(
      () =>
        client.sendProtected(
          "ProtectedMessage",
          9_007_199_254_740_992,
          {
            receiverId: 22n,
            identity: { signerId: 11n, keyring: signerKeyring },
            recipients: [publicBundle(recipientKeyring)],
            signaturePurpose: 0x40,
            encryptionPurpose: 0x41,
            signatureSuite: "dual",
          },
        ),
      /unsafe integral MTP DataValue inputs must use bigint/,
    );
  });

  await it("requires the configured purposes and verifies the protected signature", async () => {
    const signerKeyring = sdk.crypto.generateKeyring();
    const recipientKeyring = sdk.crypto.generateKeyring();
    const client = await sdk.MTPClient.create({
      url: "https://example.invalid",
      pings: false,
    });
    const frame = await buildDirectFrame({ signerKeyring, recipientKeyring });

    await assert.rejects(
      () =>
        client.openProtected(
          frame,
          openOptions(signerKeyring, recipientKeyring, {
            signaturePurpose: 0x42,
          }),
        ),
    );
    await assert.rejects(
      () =>
        client.openProtected(
          frame,
          openOptions(signerKeyring, recipientKeyring, {
            encryptionPurpose: 0x42,
          }),
        ),
    );

    const parsed = bindings.parse_frame(frame);
    const signedBytes = bindings.decrypt_data_value(
      parsed.data.encoded,
      recipientKeyring,
      0x41,
    );
    const tamperedSigned = signedBytes.slice();
    tamperedSigned[1 + 4 + 1 + 1 + 8] ^= 0xff;
    const tamperedPayload = bindings.encrypt_data_value_for_recipients(
      tamperedSigned,
      [publicBundle(recipientKeyring)],
      0x41,
    );
    const tamperedFrame = bindings.build_frame_with_payload(
      "ProtectedMessage",
      tamperedPayload,
      { receiver: 22n, sender: 11n },
    );
    await assert.rejects(() =>
      client.openProtected(
        tamperedFrame,
        openOptions(signerKeyring, recipientKeyring),
      ),
    );
  });

  await it("resolves policy independently from recipient signing capabilities", async () => {
    const signerKeyring = sdk.crypto.generateKeyring();
    const recipientKeyring = sdk.crypto.generateKeyring();
    const edOnlyRecipientKeyring = ed25519OnlyEncryptionKeyring(recipientKeyring);
    const client = await sdk.MTPClient.create({
      url: "https://example.invalid",
      defaultSignatureVerificationPolicy: "dual",
      pings: false,
    });
    const dualFrame = await buildDirectFrame({
      signerKeyring,
      recipientKeyring,
      signatureSuite: "dual",
    });
    const defaultOpened = await client.openProtected(
      dualFrame,
      openOptions(signerKeyring, edOnlyRecipientKeyring, {
        signaturePolicy: undefined,
      }),
    );
    assert.equal(defaultOpened.data.ExampleType, "direct-receive");

    const edFrame = await buildDirectFrame({
      signerKeyring,
      recipientKeyring,
      signatureSuite: "ed25519",
    });
    const overridden = await client.openProtected(
      edFrame,
      openOptions(signerKeyring, edOnlyRecipientKeyring, {
        signaturePolicy: "ed25519",
      }),
    );
    assert.equal(overridden.data.ExampleType, "direct-receive");

    await assert.rejects(
      () =>
        client.openProtected(
          edFrame,
          openOptions(signerKeyring, edOnlyRecipientKeyring, {
            signaturePolicy: undefined,
          }),
        ),
      (error) =>
        error instanceof sdk.MTPSignatureVerificationError &&
        error.code === "policy-rejected",
    );

    const libraryDefaultClient = await sdk.MTPClient.create({
      url: "https://example.invalid",
      pings: false,
    });
    const libraryDefault = await libraryDefaultClient.openProtected(
      edFrame,
      openOptions(signerKeyring, edOnlyRecipientKeyring, {
        signaturePolicy: undefined,
      }),
    );
    assert.equal(libraryDefaultClient.defaultSignatureVerificationPolicy, "ed25519");
    assert.equal(libraryDefault.data.ExampleType, "direct-receive");
  });

  await it("reports unavailable signer keys and invalid signatures separately", async () => {
    const signerKeyring = sdk.crypto.generateKeyring();
    const recipientKeyring = sdk.crypto.generateKeyring();
    const client = await sdk.MTPClient.create({
      url: "https://example.invalid",
      pings: false,
    });
    const frame = await buildDirectFrame({ signerKeyring, recipientKeyring });

    await assert.rejects(
      () =>
        client.openProtected(
          frame,
          openOptions(signerKeyring, recipientKeyring, {
            resolveSignerPublicKeys: () => [],
          }),
        ),
      (error) =>
        error instanceof sdk.MTPSignatureVerificationError &&
        error.code === "signer-keys-unavailable",
    );

    await assert.rejects(
      () =>
        client.openProtected(
          frame,
          openOptions(signerKeyring, recipientKeyring, {
            resolveSignerPublicKeys: async () => {
              throw new Error("signer key store unavailable");
            },
          }),
        ),
      (error) =>
        error instanceof sdk.MTPSignatureVerificationError &&
        error.code === "signer-keys-unavailable",
    );

    const parsed = bindings.parse_frame(frame);
    const signedBytes = bindings.decrypt_data_value(
      parsed.data.encoded,
      recipientKeyring,
      0x41,
    );
    const tamperedSigned = signedBytes.slice();
    tamperedSigned[1 + 4 + 1 + 1 + 8] ^= 0xff;
    const tamperedPayload = bindings.encrypt_data_value_for_recipients(
      tamperedSigned,
      [publicBundle(recipientKeyring)],
      0x41,
    );
    const tamperedFrame = bindings.build_frame_with_payload(
      "ProtectedMessage",
      tamperedPayload,
      { receiver: 22n, sender: 11n },
    );
    await assert.rejects(
      () =>
        client.openProtected(
          tamperedFrame,
          openOptions(signerKeyring, recipientKeyring),
        ),
      (error) =>
        error instanceof sdk.MTPSignatureVerificationError &&
        error.code === "invalid-signature",
    );
  });

  await it("rejects an unresolved communication type", async () => {
    const signerKeyring = sdk.crypto.generateKeyring();
    const recipientKeyring = sdk.crypto.generateKeyring();
    const frame = await buildDirectFrame({ signerKeyring, recipientKeyring });
    const unknownTypeFrame = frame.slice();
    unknownTypeFrame[4] = 0;
    unknownTypeFrame[5] = 0xff;
    const client = await sdk.MTPClient.create({
      url: "https://example.invalid",
      pings: false,
    });

    await assert.rejects(
      () =>
        client.openProtected(
          unknownTypeFrame,
          openOptions(signerKeyring, recipientKeyring),
        ),
      /Unknown communication type/,
    );
  });

  await it("uses the shared opening path for subscriptions", async () => {
    const signerKeyring = sdk.crypto.generateKeyring();
    const recipientKeyring = sdk.crypto.generateKeyring();
    const frame = bindings.parse_frame(
      await buildDirectFrame({ signerKeyring, recipientKeyring }),
    );
    const client = await sdk.MTPClient.create({
      url: "https://example.invalid",
      pings: false,
    });
    const originalSubscribe = client.raw.client.subscribe;
    const originalUnsubscribe = client.raw.client.unsubscribe;
    let subscribedType;
    let subscribedHandler;
    let unsubscribedId;
    client.raw.client.subscribe = (type, handler) => {
      subscribedType = type;
      subscribedHandler = handler;
      return 23;
    };
    client.raw.client.unsubscribe = (id) => {
      unsubscribedId = id;
      return true;
    };

    try {
      const received = [];
      const unsubscribe = client.subscribeProtected(
        "ProtectedMessage",
        (message, receivedFrame) => received.push({ message, receivedFrame }),
        openOptions(signerKeyring, recipientKeyring),
      );
      assert.equal(subscribedType, "ProtectedMessage");
      await subscribedHandler(frame);
      assert.equal(received.length, 1);
      assert.equal(received[0].message.signerId, 11n);
      assert.equal(received[0].receivedFrame.type, "ProtectedMessage");
      unsubscribe();
      assert.equal(unsubscribedId, 23);
    } finally {
      client.raw.client.subscribe = originalSubscribe;
      client.raw.client.unsubscribe = originalUnsubscribe;
    }
  });

  await it("keeps protected subscription replay guards independent", async () => {
    const signerKeyring = sdk.crypto.generateKeyring();
    const recipientKeyring = sdk.crypto.generateKeyring();
    const frame = bindings.parse_frame(
      await buildDirectFrame({
        signerKeyring,
        recipientKeyring,
        signatureSuite: "dual",
      }),
    );
    const client = await sdk.MTPClient.create({
      url: "https://example.invalid",
      pings: false,
    });
    const originalSubscribe = client.raw.client.subscribe;
    const originalUnsubscribe = client.raw.client.unsubscribe;
    const subscriptions = [];
    client.raw.client.subscribe = (type, handler) => {
      const id = subscriptions.length + 1;
      subscriptions.push({ type, handler, id });
      return id;
    };
    client.raw.client.unsubscribe = () => true;

    try {
      const received = [0, 0];
      const options = openOptions(signerKeyring, recipientKeyring);
      client.subscribeProtected(
        "ProtectedMessage",
        () => {
          received[0] += 1;
        },
        options,
      );
      client.subscribeProtected(
        "ProtectedMessage",
        () => {
          received[1] += 1;
        },
        options,
      );

      assert.equal(subscriptions.length, 2);
      await subscriptions[0].handler(frame);
      await subscriptions[1].handler(frame);
      assert.deepEqual(received, [1, 1]);
    } finally {
      client.raw.client.subscribe = originalSubscribe;
      client.raw.client.unsubscribe = originalUnsubscribe;
    }
  });
});

await describe("E2EE Session Manager", async () => {
  await it("derivePeerSessionId is consistent regardless of order", () => {
    const id1 = derivePeerSessionId(5n, 10n);
    const id2 = derivePeerSessionId(10n, 5n);
    assert.equal(id1, id2);
  });

  await it("stores independent sessions by explicit session ID", async () => {
    const ss = sdk.crypto.sha256(new Uint8Array([1, 2, 3]));
    const storage = new InMemorySessionStorage();
    const manager = new MTPSessionManager(storage);
    const sessionId = "independent-session";

    assert.equal(await manager.getSession(sessionId), null);

    const session = await manager.createSession({
      sessionId,
      localId: 1n,
      remoteId: 2n,
      remotePublicKey: new Uint8Array(32),
      sharedSecret: ss,
      role: "initiator",
      transcriptContext: {
        sessionId,
        initiatorId: 1n,
        recipientId: 2n,
        recipientPublicKey: new Uint8Array(32),
        kemCiphertext: new Uint8Array([1]),
        applicationContext: new Uint8Array([2]),
      },
    });
    assert.equal(session.version, 1);
    assert.equal(session.sendCount, 0);
    assert.equal(session.recvCount, 0);

    await manager.saveSession(session);
    const retrieved = await manager.getSession(sessionId);
    assert.notEqual(retrieved, null);
    assert.equal(retrieved.sessionId, session.sessionId);

    const otherSession = await manager.createSession({
      sessionId: "another-session",
      localId: 1n,
      remoteId: 2n,
      remotePublicKey: new Uint8Array(32),
      sharedSecret: ss,
      role: "initiator",
      transcript: new Uint8Array([2]),
    });
    await manager.saveSession(otherSession);
    assert.notEqual(await manager.getSession(sessionId), null);
    assert.notEqual(await manager.getSession(otherSession.sessionId), null);

    await manager.deleteSession(sessionId);
    assert.equal(await manager.getSession(sessionId), null);
    assert.notEqual(await manager.getSession(otherSession.sessionId), null);
  });
});

await describe("E2EE Full Flow: KEM + Session + Ratchet + AEAD", async () => {
  await it("Alice encapsulates to Bob, both derive matching sessions, encrypt-decrypt works", async () => {
    // Bob generates keyring
    const bobKeyring = sdk.crypto.generateKeyring();
    const bobKeys = sdk.crypto.keyringToKeys(bobKeyring);

    // Alice encapsulates to Bob's KEM public key
    const enc = sdk.crypto.encapsulate(bobKeys.kemPublicKey);

    // Bob decapsulates
    const bobSharedSecret = sdk.crypto.decapsulate(
      bobKeys.kemSecretKey,
      enc.ciphertext,
    );
    assert.deepEqual(bobSharedSecret, enc.shared_secret);

    const ss = enc.shared_secret;
    const { initSessions } = setupSessions(ss);
    const { aliceSession, bobSession } = await initSessions();

    // Alice sends encrypted init message with KEM ciphertext
    const msg1 = new Uint8Array([0x48, 0x65, 0x6c, 0x6c, 0x6f]); // "Hello"
    const { payload: p1, session: aliceAfter1 } = await encryptPayload({
      plaintext: msg1,
      session: aliceSession,
      kemCiphertext: enc.ciphertext,
    });

    // Bob receives and decrypts
    const { plaintext: d1, session: bobAfter1 } = await decryptPayload({
      payload: p1,
      session: bobSession,
    });
    assert.deepEqual(d1, msg1);
    assert.deepEqual(aliceAfter1.sendChainKey, bobAfter1.recvChainKey);
    assert.equal(aliceAfter1.sendCount, 1);
    assert.equal(bobAfter1.recvCount, 1);

    // Second message (no KEM ciphertext)
    const msg2 = new Uint8Array([0x57, 0x6f, 0x72, 0x6c, 0x64]); // "World"
    const { payload: p2, session: aliceAfter2 } = await encryptPayload({
      plaintext: msg2,
      session: aliceAfter1,
    });

    const { plaintext: d2, session: bobAfter2 } = await decryptPayload({
      payload: p2,
      session: bobAfter1,
    });
    assert.deepEqual(d2, msg2);
    assert.deepEqual(aliceAfter2.sendChainKey, bobAfter2.recvChainKey);
    assert.equal(aliceAfter2.sendCount, 2);
    assert.equal(bobAfter2.recvCount, 2);
  });
});

await describe("E2EE Tamper Detection", async () => {
  await it("Rejects modified ciphertext", async () => {
    const ss = sdk.crypto.sha256(new Uint8Array([42]));
    const { initSessions } = setupSessions(ss);
    const { aliceSession, bobSession } = await initSessions();

    const plaintext = new Uint8Array([0x01, 0x02, 0x03]);
    const { payload } = await encryptPayload({
      plaintext,
      session: aliceSession,
    });

    // Tamper with AEAD payload
    const tampered = new Uint8Array(payload);
    tampered[tampered.length - 1] ^= 0xff;

    await assert.rejects(
      () => decryptPayload({ payload: tampered, session: bobSession }),
      /decrypt failed/,
    );
  });

  await it("Rejects out-of-order message numbers", async () => {
    const ss = sdk.crypto.sha256(new Uint8Array([7]));
    const { initSessions } = setupSessions(ss);
    const { aliceSession, bobSession } = await initSessions();

    // Send two messages
    const { payload: p1, session: aliceAfter1 } = await encryptPayload({
      plaintext: sdk.codec.encode("Ping", { Version: "a" }),
      session: aliceSession,
    });
    await encryptPayload({
      plaintext: sdk.codec.encode("Ping", { Version: "b" }),
      session: aliceAfter1,
    });

    // Bob decrypts p1
    const { session: bobAfter1 } = await decryptPayload({
      payload: p1,
      session: bobSession,
    });

    // Now bob expects msgNumber 1, but we try to replay msgNumber 0
    await assert.rejects(
      () => decryptPayload({ payload: p1, session: bobAfter1 }),
      /replay|out of order/,
    );
  });
});

await describe("Encrypted Pipe", async () => {
  await it("rejects MTP-reserved application purposes", () => {
    assert.throws(
      () => new sdk.MTPPipeProtectionContext(new Uint8Array([1]), 0x30, 0),
      /reserved/,
    );
  });

  await it("authenticates records and requires a final record", async () => {
    const [writerPipe, readerPipe] = memoryDuplexPair();
    const context = new sdk.MTPPipeProtectionContext(
      new Uint8Array([1, 2, 3]),
      0x40,
      0,
    );
    const writer = new sdk.MTPEncryptedPipeWriter(
      writerPipe,
      new Uint8Array(32).fill(7),
      context,
    );
    const reader = new sdk.MTPEncryptedPipeReader(
      readerPipe,
      new Uint8Array(32).fill(7),
      context,
    );

    await writer.writeRecord(new Uint8Array([1, 2, 3]));
    assert.deepEqual(await reader.readRecord(), new Uint8Array([1, 2, 3]));
    await writer.close();
    assert.equal(await reader.readRecord(), null);
    assert.equal(await reader.readRecord(), null);
  });

  await it("poisons the reader after a truncated stream", async () => {
    const [writerPipe, readerPipe] = memoryDuplexPair();
    const context = new sdk.MTPPipeProtectionContext(
      new Uint8Array([4, 5, 6]),
      0x40,
      0,
    );
    const writer = new sdk.MTPEncryptedPipeWriter(
      writerPipe,
      new Uint8Array(32).fill(8),
      context,
    );
    const reader = new sdk.MTPEncryptedPipeReader(
      readerPipe,
      new Uint8Array(32).fill(8),
      context,
    );
    await writer.writeRecord(new Uint8Array([9]));
    writerPipe.abort();
    assert.deepEqual(await reader.readRecord(), new Uint8Array([9]));
    await assert.rejects(() => reader.readRecord(), /final|truncated/i);
    await assert.rejects(() => reader.readRecord(), /state|readable/i);
  });

  await it("poisons the writer after a transport write failure", async () => {
    const [writerPipe] = memoryDuplexPair();
    const context = new sdk.MTPPipeProtectionContext(
      new Uint8Array([7, 8, 9]),
      0x40,
      0,
    );
    const writer = new sdk.MTPEncryptedPipeWriter(
      writerPipe,
      new Uint8Array(32).fill(6),
      context,
    );
    writerPipe.abort();
    await assert.rejects(() => writer.writeRecord(new Uint8Array([1])), /write|closed/i);
    await assert.rejects(() => writer.writeRecord(new Uint8Array([2])), /state|writable/i);
  });

  await it("establishes a forward-secure authenticated duplex session", async () => {
    const senderKeyring = sdk.crypto.generateKeyring();
    const currentSenderKeyring = sdk.crypto.generateKeyring();
    const recipientKeyring = sdk.crypto.generateKeyring();
    const senderBundle = publicBundle(senderKeyring);
    const currentSenderBundle = publicBundle(currentSenderKeyring);
    const recipientBundle = publicBundle(recipientKeyring);
    const [initiatorPipe, responderPipe] = memoryDuplexPair(91);
    const sessionId = new Uint8Array(32).fill(0x42);
    const params = {
      sessionId,
      pipeId: 91,
      senderId: 11n,
      recipientId: 22n,
      purpose: 0x40,
      direction: 0,
    };

    const responder = sdk.acceptMTPForwardSecurePipeSession(
      responderPipe,
      {
        pipeId: params.pipeId,
        senderId: params.senderId,
        recipientId: params.recipientId,
        purpose: params.purpose,
        direction: params.direction,
      },
      recipientKeyring,
      [currentSenderBundle, senderBundle],
      "dual",
      "dual",
    );
    const initiator = await sdk.initiateMTPForwardSecurePipeSession(
      initiatorPipe,
      params,
      senderKeyring,
      recipientBundle,
      "dual",
      "dual",
    );
    const receiver = await responder;
    await initiator.writeRecord(new Uint8Array([0xaa, 0xbb]));
    assert.deepEqual(await receiver.readRecord(), new Uint8Array([0xaa, 0xbb]));
    await initiator.close();
    assert.equal(await receiver.readRecord(), null);
  });

  await it("uses interoperable Ed25519 defaults for pipe handshakes", async () => {
    const senderKeyring = sdk.crypto.generateKeyring();
    const recipientKeyring = sdk.crypto.generateKeyring();
    const [initiatorPipe, responderPipe] = memoryDuplexPair(93);
    const params = {
      sessionId: new Uint8Array([9, 3]),
      pipeId: 93,
      senderId: 11n,
      recipientId: 22n,
      purpose: 0x40,
      direction: 0,
    };

    const responder = sdk.acceptMTPForwardSecurePipeSession(
      responderPipe,
      params,
      recipientKeyring,
      publicBundle(senderKeyring),
    );
    const initiator = await sdk.initiateMTPForwardSecurePipeSession(
      initiatorPipe,
      params,
      senderKeyring,
      publicBundle(recipientKeyring),
    );
    const receiver = await responder;
    await initiator.writeRecord(new Uint8Array([0x55]));
    assert.deepEqual(await receiver.readRecord(), new Uint8Array([0x55]));
    await initiator.close();
    assert.equal(await receiver.readRecord(), null);
  });

  await it("accepts a dual sender with an Ed25519-only recipient keyring", async () => {
    const senderKeyring = sdk.crypto.generateKeyring();
    const recipientKeyring = sdk.crypto.generateKeyring();
    const recipientEncryptionKeyring = ed25519OnlyEncryptionKeyring(
      recipientKeyring,
    );
    const [writerPipe, readerPipe] = memoryDuplexPair(92);
    const params = {
      sessionId: new Uint8Array([9, 2]),
      pipeId: 92,
      senderId: 11n,
      recipientId: 22n,
      purpose: 0x40,
      direction: 0,
    };
    const readerPromise = sdk.acceptMTPPipeSession(
      readerPipe,
      params,
      recipientEncryptionKeyring,
      publicBundle(senderKeyring),
      "dual",
    );
    const writer = await sdk.initiateMTPPipeSession(
      writerPipe,
      params,
      senderKeyring,
      publicBundle(recipientKeyring),
      "dual",
    );
    const reader = await readerPromise;
    await writer.writeRecord(new Uint8Array([0x11]));
    assert.deepEqual(await reader.readRecord(), new Uint8Array([0x11]));
  });
});

await describe("Relay API invariants", async () => {
  await it("exposes stable codes for raw relay operation errors", () => {
    const ping = bindings.build_ping_frame(
      7n,
      "not-a-relay",
      1n,
      new Uint8Array(),
    );
    assert.throws(
      () => bindings.forward_encrypted_relay_frame(ping, 9n),
      (error) => error?.code === "not-relay",
    );

    assert.throws(
      () => bindings.forward_encrypted_relay_frame(new Uint8Array([0xff]), 9n),
      (error) => error?.code === "invalid-frame",
    );
  });

  await it("uses the client default for metadata and content independently of recipient PQ keys", async () => {
    const senderKeyring = sdk.crypto.generateKeyring();
    const recipientKeyring = sdk.crypto.generateKeyring();
    const frame = sdk.codec.decode(
      bindings.build_encrypted_relay_frame_with_keyring(
        "ProtectedMessage",
        { ExampleType: "default-policy" },
        11n,
        42n,
        42n,
        "message-default-policy",
        456n,
        null,
        senderKeyring,
        bindings.mtp_protection_signature_suite_ed25519(),
        [publicBundle(recipientKeyring)],
        [publicBundle(recipientKeyring)],
      ),
    );
    const client = await sdk.MTPClient.create({
      url: "https://example.invalid",
      defaultSignatureVerificationPolicy: "ed25519",
      pings: false,
    });
    const options = {
      recipient: { id: 42n, keyring: recipientKeyring },
      expectedSignerId: 11n,
      resolveSignerPublicKeys: () => [publicBundle(senderKeyring)],
    };
    const metadata = await client.openRelayMetadata(frame, options);
    assert.equal(metadata.signaturePolicy, "ed25519");
    const content = await client.openRelayContent(metadata, options);
    assert.equal(content.data.ExampleType, "default-policy");
  });

  await it("inherits the authenticated metadata policy for relay content", async () => {
    const senderKeyring = sdk.crypto.generateKeyring();
    const recipientKeyring = sdk.crypto.generateKeyring();
    const frame = sdk.codec.decode(
      bindings.build_encrypted_relay_frame_with_keyring(
        "ProtectedMessage",
        { ExampleType: "inherited-policy" },
        11n,
        42n,
        42n,
        "message-inherited-policy",
        456n,
        null,
        senderKeyring,
        bindings.mtp_protection_signature_suite_dual(),
        [publicBundle(recipientKeyring)],
        [publicBundle(recipientKeyring)],
      ),
    );
    const client = await sdk.MTPClient.create({
      url: "https://example.invalid",
      defaultSignatureVerificationPolicy: "ed25519",
      pings: false,
    });
    const metadataOptions = {
      recipient: { id: 42n, keyring: recipientKeyring },
      expectedSignerId: 11n,
      resolveSignerPublicKeys: () => [publicBundle(senderKeyring)],
      signaturePolicy: "dual",
    };
    const metadata = await client.openRelayMetadata(frame, metadataOptions);
    const content = await client.openRelayContent(metadata, {
      recipient: metadataOptions.recipient,
      expectedSignerId: metadataOptions.expectedSignerId,
      resolveSignerPublicKeys: metadataOptions.resolveSignerPublicKeys,
    });
    assert.equal(content.data.ExampleType, "inherited-policy");
  });

  await it("reports the shared relay CreatedAt fixture as bigint", async () => {
    const senderKeyring = sdk.crypto.generateKeyring();
    const recipientKeyring = sdk.crypto.generateKeyring();
    const frame = sdk.codec.decode(
      bindings.build_encrypted_relay_frame_with_keyring(
        "ProtectedMessage",
        { ExampleType: "generic" },
        11n,
        42n,
        42n,
        "message-generic",
        relayFixtureCreatedAtMillis,
        bindings.encode_data_value({ ExampleType: "opaque-to-content-only-relays" }),
        senderKeyring,
        bindings.mtp_protection_signature_suite_dual(),
        [publicBundle(recipientKeyring)],
        [publicBundle(recipientKeyring)],
      ),
    );
    const client = await sdk.MTPClient.create({
      url: "https://example.invalid",
      pings: false,
    });
    const options = {
      recipient: { id: 42n, keyring: recipientKeyring },
      expectedSignerId: 11n,
      resolveSignerPublicKeys: () => [publicBundle(senderKeyring)],
      signaturePolicy: "dual",
    };

    const metadata = await client.openRelayMetadata(frame, options);
    assert.ok(metadata);
    assert.equal(metadata.signerId, 11n);
    assert.equal(metadata.finalRecipientId, 42n);
    assert.equal(metadata.messageId, "message-generic");
    assert.equal(metadata.createdAt, relayFixtureCreatedAtMillis);
    assert.deepEqual(metadata.metadata, {
      ExampleType: "opaque-to-content-only-relays",
    });

    const content = await client.openRelayContent(metadata, options);
    assert.deepEqual(content, {
      type: "ProtectedMessage",
      data: { ExampleType: "generic" },
      signerId: 11n,
      finalRecipientId: 42n,
      messageId: "message-generic",
      createdAt: relayFixtureCreatedAtMillis,
      metadata: { ExampleType: "opaque-to-content-only-relays" },
    });
  });

  await it("preserves scalar metadata and byte content values", async () => {
    const senderKeyring = sdk.crypto.generateKeyring();
    const recipientKeyring = sdk.crypto.generateKeyring();
    const frame = sdk.codec.decode(
      bindings.build_encrypted_relay_frame_with_keyring(
        "ProtectedMessage",
        new Uint8Array([0xde, 0xad, 0xbe, 0xef]),
        11n,
        42n,
        42n,
        "message-scalar-values",
        456n,
        bindings.encode_data_value("opaque metadata"),
        senderKeyring,
        bindings.mtp_protection_signature_suite_dual(),
        [publicBundle(recipientKeyring)],
        [publicBundle(recipientKeyring)],
      ),
    );
    const client = await sdk.MTPClient.create({
      url: "https://example.invalid",
      pings: false,
    });
    const options = {
      recipient: { id: 42n, keyring: recipientKeyring },
      expectedSignerId: 11n,
      resolveSignerPublicKeys: () => [publicBundle(senderKeyring)],
      signaturePolicy: "dual",
    };

    const metadata = await client.openRelayMetadata(frame, options);
    assert.equal(metadata.metadata, "opaque metadata");
    const content = await client.openRelayContent(metadata, options);
    assert.deepEqual(content.data, new Uint8Array([0xde, 0xad, 0xbe, 0xef]));
  });

  await it("subscribes through the explicit sealed-relay API", async () => {
    const senderKeyring = sdk.crypto.generateKeyring();
    const recipientKeyring = sdk.crypto.generateKeyring();
    const frame = sdk.codec.decode(
      bindings.build_encrypted_relay_frame_with_keyring(
        "ProtectedMessage",
        { ExampleType: "subscription" },
        11n,
        42n,
        42n,
        "message-subscription",
        789n,
        bindings.encode_data_value({ ExampleType: "subscription" }),
        senderKeyring,
        bindings.mtp_protection_signature_suite_dual(),
        [publicBundle(recipientKeyring)],
        [publicBundle(recipientKeyring)],
      ),
    );
    const client = await sdk.MTPClient.create({
      url: "https://example.invalid",
      pings: false,
    });
    const originalSubscribe = client.raw.client.subscribe;
    const originalUnsubscribe = client.raw.client.unsubscribe;
    let subscribedType;
    let subscribedHandler;
    let unsubscribedId;
    client.raw.client.subscribe = (type, handler) => {
      subscribedType = type;
      subscribedHandler = handler;
      return 17;
    };
    client.raw.client.unsubscribe = (id) => {
      unsubscribedId = id;
    };

    try {
      const received = [];
      const unsubscribe = client.subscribeSealedRelay(
        "ProtectedMessage",
        (content, parsedFrame) => {
          received.push({ content, parsedFrame });
        },
        {
          recipient: { id: 42n, keyring: recipientKeyring },
          expectedSignerId: 11n,
          resolveSignerPublicKeys: () => [publicBundle(senderKeyring)],
          signaturePolicy: "dual",
        },
      );

      assert.equal(subscribedType, "Relay");
      assert.equal(typeof subscribedHandler, "function");
      await subscribedHandler(frame);
      assert.equal(received.length, 1);
      assert.equal(received[0].content.messageId, "message-subscription");
      assert.deepEqual(received[0].content.metadata, {
        ExampleType: "subscription",
      });
      assert.equal(received[0].parsedFrame.type, "ProtectedMessage");
      assert.deepEqual(received[0].parsedFrame.data, {
        ExampleType: "subscription",
      });
      await subscribedHandler(frame);
      assert.equal(received.length, 1);

      unsubscribe();
      assert.equal(unsubscribedId, 17);
    } finally {
      client.raw.client.subscribe = originalSubscribe;
      client.raw.client.unsubscribe = originalUnsubscribe;
    }
  });

  await it("keeps relay subscription replay guards independent", async () => {
    const senderKeyring = sdk.crypto.generateKeyring();
    const recipientKeyring = sdk.crypto.generateKeyring();
    const frame = sdk.codec.decode(
      bindings.build_encrypted_relay_frame_with_keyring(
        "ProtectedMessage",
        { ExampleType: "fanout" },
        11n,
        42n,
        42n,
        "message-relay-fanout",
        789n,
        bindings.encode_data_value({ ExampleType: "fanout-metadata" }),
        senderKeyring,
        bindings.mtp_protection_signature_suite_dual(),
        [publicBundle(recipientKeyring)],
        [publicBundle(recipientKeyring)],
      ),
    );
    const client = await sdk.MTPClient.create({
      url: "https://example.invalid",
      pings: false,
    });
    const originalSubscribe = client.raw.client.subscribe;
    const originalUnsubscribe = client.raw.client.unsubscribe;
    const subscriptions = [];
    client.raw.client.subscribe = (type, handler) => {
      const id = subscriptions.length + 1;
      subscriptions.push({ type, handler, id });
      return id;
    };
    client.raw.client.unsubscribe = () => true;

    try {
      const options = {
        recipient: { id: 42n, keyring: recipientKeyring },
        expectedSignerId: 11n,
        resolveSignerPublicKeys: () => [publicBundle(senderKeyring)],
        signaturePolicy: "dual",
      };
      let mismatched = 0;
      let matched = 0;
      let metadataOnly = 0;
      client.subscribeSealedRelay(
        "AlternateMessage",
        () => {
          mismatched += 1;
        },
        options,
      );
      client.subscribeSealedRelay(
        "ProtectedMessage",
        () => {
          matched += 1;
        },
        options,
      );
      client.subscribeRelayMetadata(
        () => {
          metadataOnly += 1;
        },
        options,
      );

      const relaySubscriptions = subscriptions.filter(
        ({ type }) => type === "Relay",
      );
      assert.equal(relaySubscriptions.length, 3);
      for (const subscription of relaySubscriptions) {
        await subscription.handler(frame);
      }
      assert.equal(mismatched, 0);
      assert.equal(matched, 1);
      assert.equal(metadataOnly, 1);
    } finally {
      client.raw.client.subscribe = originalSubscribe;
      client.raw.client.unsubscribe = originalUnsubscribe;
    }
  });

  await it("consumes authenticated relay IDs through the caller's replay guard", async () => {
    const senderKeyring = sdk.crypto.generateKeyring();
    const recipientKeyring = sdk.crypto.generateKeyring();
    const frame = sdk.codec.decode(
      bindings.build_encrypted_relay_frame_with_keyring(
        "ProtectedMessage",
        { ExampleType: "replay" },
        11n,
        42n,
        42n,
        "message-replay",
        123n,
        null,
        senderKeyring,
        bindings.mtp_protection_signature_suite_dual(),
        [publicBundle(recipientKeyring)],
        [publicBundle(recipientKeyring)],
      ),
    );
    const client = await sdk.MTPClient.create({
      url: "https://example.invalid",
      credentials: { clientId: 42n, keyring: recipientKeyring },
      pings: false,
    });
    const accepted = new Set();
    const replayGuard = {
      accept(signerId, messageId) {
        const key = `${signerId}:${messageId}`;
        if (accepted.has(key)) return false;
        accepted.add(key);
        return true;
      },
    };
    const options = {
      expectedSignerId: 11n,
      resolveSignerPublicKeys: () => [publicBundle(senderKeyring)],
      signaturePolicy: "dual",
      replayGuard,
    };
    const metadata = await client.openRelayMetadata(frame, options);
    assert.equal(metadata.messageId, "message-replay");
    await assert.rejects(
      () => client.openRelayMetadata(frame, options),
      (error) => error instanceof sdk.MTPReplayError,
    );
    metadata.dispose();
    metadata.free();
    await assert.rejects(
      () => client.openRelayContent(metadata, options),
      /disposed/,
    );
  });

  await it("disposes metadata after relay metadata subscription handlers complete", async () => {
    const senderKeyring = sdk.crypto.generateKeyring();
    const recipientKeyring = sdk.crypto.generateKeyring();
    const frame = sdk.codec.decode(
      bindings.build_encrypted_relay_frame_with_keyring(
        "ProtectedMessage",
        { ExampleType: "metadata-subscription" },
        11n,
        42n,
        42n,
        "message-metadata-subscription",
        123n,
        null,
        senderKeyring,
        bindings.mtp_protection_signature_suite_dual(),
        [publicBundle(recipientKeyring)],
        [publicBundle(recipientKeyring)],
      ),
    );
    const client = await sdk.MTPClient.create({
      url: "https://example.invalid",
      pings: false,
    });
    const originalSubscribe = client.raw.client.subscribe;
    let subscribedHandler;
    client.raw.client.subscribe = (_type, handler) => {
      subscribedHandler = handler;
      return 19;
    };

    try {
      let receivedMetadata;
      client.subscribeRelayMetadata(
        (metadata) => {
          receivedMetadata = metadata;
          assert.equal(metadata.messageId, "message-metadata-subscription");
        },
        {
          recipient: { id: 42n, keyring: recipientKeyring },
          expectedSignerId: 11n,
          resolveSignerPublicKeys: () => [publicBundle(senderKeyring)],
          signaturePolicy: "dual",
        },
      );

      await subscribedHandler(frame);
      assert.throws(() => receivedMetadata.messageId, /disposed/);
    } finally {
      client.raw.client.subscribe = originalSubscribe;
    }
  });

  await it("rejects relay content opening when metadata is disposed during resolution", async () => {
    const senderKeyring = sdk.crypto.generateKeyring();
    const recipientKeyring = sdk.crypto.generateKeyring();
    const frame = sdk.codec.decode(
      bindings.build_encrypted_relay_frame_with_keyring(
        "ProtectedMessage",
        { ExampleType: "dispose-race" },
        11n,
        42n,
        42n,
        "message-dispose-race",
        123n,
        null,
        senderKeyring,
        bindings.mtp_protection_signature_suite_dual(),
        [publicBundle(recipientKeyring)],
        [publicBundle(recipientKeyring)],
      ),
    );
    const client = await sdk.MTPClient.create({
      url: "https://example.invalid",
      pings: false,
    });
    const signerPublicKey = publicBundle(senderKeyring);
    const metadata = await client.openRelayMetadata(frame, {
      recipient: { id: 42n, keyring: recipientKeyring },
      expectedSignerId: 11n,
      resolveSignerPublicKeys: () => [signerPublicKey],
      signaturePolicy: "dual",
    });

    let signalResolverStarted;
    let releaseResolver;
    const resolverStarted = new Promise((resolve) => {
      signalResolverStarted = resolve;
    });
    const resolverRelease = new Promise((resolve) => {
      releaseResolver = resolve;
    });
    const opening = client.openRelayContent(metadata, {
      recipient: { id: 42n, keyring: recipientKeyring },
      expectedSignerId: 11n,
      resolveSignerPublicKeys: async () => {
        signalResolverStarted();
        await resolverRelease;
        return [signerPublicKey];
      },
      signaturePolicy: "dual",
    });

    await resolverStarted;
    metadata.dispose();
    releaseResolver();
    await assert.rejects(opening, /relay metadata has been disposed/);
  });

  await it("does not permit callers to construct verified metadata", () => {
    assert.throws(
      () => new sdk.MTPVerifiedRelayMetadata(Symbol(), {}),
      /authenticated opening/,
    );
  });
});
