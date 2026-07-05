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
  getConversationId,
} = await import("../dist/sdk/session.js");

const bindings = sdk.raw;

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

  return {
    aliceManager,
    aliceStorage,
    bobManager,
    bobStorage,
    async initSessions() {
      const { initiatorSend, initiatorRecv } = await deriveSessionKeys(
        sharedSecret,
        new Uint8Array(0),
      );
      const aliceSession = await aliceManager.createSession({
        ownClientId: aliceId,
        peerClientId: bobId,
        peerPublicKey: new Uint8Array(32),
        sharedSecret,
        role: "initiator",
      });
      const bobSession = await bobManager.createSession({
        ownClientId: bobId,
        peerClientId: aliceId,
        peerPublicKey: new Uint8Array(32),
        sharedSecret,
        role: "receiver",
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
        senderClientId: 0x1234567890abcdefn,
        recipientClientId: 0xfedcba0987654321n,
        messageNumber: 42,
      },
      aeadPayload: new Uint8Array([1, 2, 3, 4, 5]),
    };
    const bytes = serializeEncryptedMessage(msg);
    const parsed = parseEncryptedMessage(bytes);
    assert.equal(parsed.header.version, 1);
    assert.equal(parsed.header.flags, 0);
    assert.equal(parsed.header.senderClientId, msg.header.senderClientId);
    assert.equal(parsed.header.recipientClientId, msg.header.recipientClientId);
    assert.equal(parsed.header.messageNumber, 42);
    assert.equal(parsed.header.kemCiphertext, undefined);
    assert.deepEqual(parsed.aeadPayload, msg.aeadPayload);
  });

  await it("Roundtrips an init message with KEM ciphertext", () => {
    const msg = {
      header: {
        version: 1,
        flags: FLAG_INIT,
        senderClientId: 1n,
        recipientClientId: 2n,
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
        senderClientId: 0xaaaabbbbccccddddn,
        recipientClientId: 0xffff000011112222n,
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
        senderClientId: 0n,
        recipientClientId: 0n,
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
        senderClientId: 0n,
        recipientClientId: 0n,
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

await describe("E2EE Session Manager", async () => {
  await it("getConversationId is consistent regardless of order", () => {
    const id1 = getConversationId(5n, 10n);
    const id2 = getConversationId(10n, 5n);
    assert.equal(id1, id2);
  });

  await it("MTPSessionManager creates, retrieves, and deletes sessions", async () => {
    const ss = sdk.crypto.sha256(new Uint8Array([1, 2, 3]));
    const storage = new InMemorySessionStorage();
    const manager = new MTPSessionManager(storage);

    assert.equal(await manager.getSession(1n, 2n), null);

    const session = await manager.createSession({
      ownClientId: 1n,
      peerClientId: 2n,
      peerPublicKey: new Uint8Array(32),
      sharedSecret: ss,
      role: "initiator",
    });
    assert.equal(session.version, 1);
    assert.equal(session.sendCount, 0);
    assert.equal(session.recvCount, 0);

    await manager.saveSession(session);
    const retrieved = await manager.getSession(1n, 2n);
    assert.notEqual(retrieved, null);
    assert.equal(retrieved.conversationId, session.conversationId);

    await manager.deleteSession(1n, 2n);
    assert.equal(await manager.getSession(1n, 2n), null);
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
