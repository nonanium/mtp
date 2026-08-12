import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import { InMemoryEncryptedSecretProvider } from "../dist/sdk/encrypted-secret.js";

function record(id, bytes, updatedAt = 2) {
  return {
    id,
    encryptedSecret: new Uint8Array(bytes),
    formatVersion: 1,
    wrappingScheme: "test-wrap-v1",
    wrappingKeyId: "wrapping-key-1",
    createdAt: 1,
    updatedAt,
  };
}

test("encrypted secret provider stores, reads, replaces, and deletes", async () => {
  const provider = new InMemoryEncryptedSecretProvider();
  const initial = record("session-secret:alpha", [1, 2, 3]);

  await provider.set(initial);
  initial.encryptedSecret[0] = 99;

  assert.deepEqual(await provider.get("session-secret:alpha"), record(
    "session-secret:alpha",
    [1, 2, 3],
  ));

  const replacement = record("session-secret:alpha", [4, 5], 3);
  await provider.set(replacement);
  assert.deepEqual(
    await provider.get("session-secret:alpha"),
    replacement,
  );

  const fetched = await provider.get("session-secret:alpha");
  fetched.encryptedSecret[0] = 88;
  assert.deepEqual(
    await provider.get("session-secret:alpha"),
    replacement,
  );

  await provider.delete("session-secret:alpha");
  assert.equal(await provider.get("session-secret:alpha"), null);
  await provider.delete("session-secret:missing");
});

test("encrypted secret provider isolates unrelated opaque IDs", async () => {
  const provider = new InMemoryEncryptedSecretProvider();
  const session = record("session-secret:one", [1]);
  const pipe = record("pipe-secret:one", [2]);

  await provider.set(session);
  await provider.set(pipe);

  assert.deepEqual(await provider.get(session.id), session);
  assert.deepEqual(await provider.get(pipe.id), pipe);
  assert.equal(await provider.get("identity-secret:one"), null);
});

test("encrypted secret provider has no application identity hierarchy", async () => {
  const source = await readFile(
    new URL("../src/sdk/encrypted-secret.ts", import.meta.url),
    "utf8",
  );

  const forbiddenFields = [
    ["user", "Id"],
    ["device", "Id"],
    ["chat", "Id"],
    ["conversation", "Id"],
  ].map(([prefix, suffix]) => `${prefix}${suffix}`);
  for (const field of forbiddenFields) {
    assert.doesNotMatch(source, new RegExp(`\\b${field}\\b`));
  }
});

test("encrypted secret provider validates IDs and records", async () => {
  const provider = new InMemoryEncryptedSecretProvider();

  await assert.rejects(() => provider.get(""), /non-empty string/);
  await assert.rejects(() => provider.delete(""), /non-empty string/);
  await assert.rejects(
    () => provider.set(record("", [1])),
    /non-empty string/,
  );
  await assert.rejects(
    () => provider.set({
      ...record("invalid", [1]),
      encryptedSecret: new Uint8Array(),
    }),
    /non-empty encryptedSecret bytes/,
  );
});
