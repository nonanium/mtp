import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { initSync, compiled_dictionary_identity } from "../../sdk/bindings/wasm/pkg/mtp_wasm.js";
import { MTPClient } from "../../sdk/dist/sdk/index.js";

initSync({ module: readFileSync(new URL("../../sdk/bindings/wasm/pkg/mtp_wasm_bg.wasm", import.meta.url)) });
const compiled = compiled_dictionary_identity();

async function fixture({ connected = true, dictionary = compiled, beforeDictionary, beforeAttach, userAgent = "Android" } = {}) {
  const calls = [];
  const previousNavigator = Object.getOwnPropertyDescriptor(globalThis, "navigator");
  const previousRuntime = Object.getOwnPropertyDescriptor(globalThis, "__TAURI_INTERNALS__");
  Object.defineProperty(globalThis, "navigator", { configurable: true, value: { userAgent } });
  Object.defineProperty(globalThis, "__TAURI_INTERNALS__", { configurable: true, value: {
    transformCallback: () => 1,
    unregisterCallback: () => {},
    async invoke(command, args) {
      calls.push([command, args]);
      if (command === "plugin:event|listen") return 1;
      if (command === "plugin:event|unlisten" || command === "plugin:mtp|mtp_detach") return;
      if (command === "plugin:mtp|mtp_attach") { await beforeAttach?.(); return; }
      if (command === "plugin:mtp|mtp_initialize") return { clientId: "7", publicKeys: [] };
      if (command === "plugin:mtp|mtp_status") return connected;
      if (command === "plugin:mtp|mtp_connect") return { clientId: "7", state: 2 };
      if (command === "plugin:mtp|mtp_dictionary_identity") { await beforeDictionary?.(); return dictionary; }
      throw new Error(`Unexpected native command: ${command}`);
    },
  } });
  let client;
  try {
    client = await MTPClient.create({ url: "https://native.example.org", nativeName: "native-dictionary-fixture" });
  } catch (error) {
    restore();
    throw error;
  }
  function restore() {
    if (previousNavigator) Object.defineProperty(globalThis, "navigator", previousNavigator);
    else delete globalThis.navigator;
    if (previousRuntime) Object.defineProperty(globalThis, "__TAURI_INTERNALS__", previousRuntime);
    else delete globalThis.__TAURI_INTERNALS__;
  }
  return { client, calls, close() { client.disconnect(); restore(); } };
}

test("native SDK exposes the negotiated dictionary only after verifying its WASM encoder", async () => {
  for (const connected of [true, false]) {
    const { client, calls, close } = await fixture({ connected });
    try {
      assert.equal(client.dictionaryIdentity, null);
      await client.connect();
      assert.deepEqual(client.dictionaryIdentity, compiled);
      assert.equal(calls.filter(([command]) => command === "plugin:mtp|mtp_connect").length, connected ? 0 : 1);
      assert.equal(calls.filter(([command]) => command === "plugin:mtp|mtp_dictionary_identity").length, 1);
      client.disconnect();
      assert.equal(client.dictionaryIdentity, null);
    } finally { close(); }
  }
});

test("a matching version label cannot hide a different native dictionary", async () => {
  for (const dictionary of [null, {}, { ...compiled, fingerprint: "0".repeat(64) }, { ...compiled, version: "99.99" }]) {
    const { client, calls, close } = await fixture({ dictionary });
    try {
      await assert.rejects(client.connect(), /does not match the WASM codec/);
      assert.equal(client.dictionaryIdentity, null);
      assert.equal(calls.some(([command]) => command === "plugin:mtp|mtp_attach"), false);
    } finally { close(); }
  }
});

test("Tauri desktop views use the same native dictionary boundary as Android", async () => {
  for (const userAgent of ["Linux", "Windows", "Macintosh"]) {
    const { client, close } = await fixture({ userAgent });
    try {
      await client.connect();
      assert.deepEqual(client.dictionaryIdentity, compiled);
    } finally { close(); }
  }
});

test("a dictionary reply cannot revive a disposed native view", async () => {
  let client;
  const context = await fixture({ beforeDictionary: () => client.disconnect() });
  client = context.client;
  try {
    await assert.rejects(client.connect(), /disposed during connection/);
    assert.equal(client.dictionaryIdentity, null);
    assert.equal(context.calls.some(([command]) => command === "plugin:mtp|mtp_attach"), false);
  } finally { context.close(); }
});

test("failed revalidation cannot retain an earlier negotiated identity", async () => {
  const dictionary = { ...compiled };
  const { client, close } = await fixture({ dictionary });
  try {
    await client.connect();
    dictionary.fingerprint = "0".repeat(64);
    await assert.rejects(client.connect(), /does not match the WASM codec/);
    assert.equal(client.dictionaryIdentity, null);
    assert.equal(client.state, 0);
  } finally { close(); }
});

test("a late native attachment cannot detach or revive its replacement", async () => {
  let client;
  let replacing = false;
  const context = await fixture({ beforeAttach: async () => {
    if (replacing) return;
    replacing = true;
    client.disconnect();
    await client.connect();
  } });
  client = context.client;
  try {
    await assert.rejects(client.connect(), /disposed during attachment/);
    assert.deepEqual(client.dictionaryIdentity, compiled);
    const attached = context.calls.filter(([command]) => command === "plugin:mtp|mtp_attach");
    const detached = context.calls.filter(([command]) => command === "plugin:mtp|mtp_detach");
    assert.equal(attached.length, 2);
    assert.notEqual(attached[0][1].attachmentId, attached[1][1].attachmentId);
    assert.equal(detached.at(-1)[1].attachmentId, attached[0][1].attachmentId);
  } finally { context.close(); }
});
