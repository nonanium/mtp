import assert from "node:assert/strict";
import { test } from "node:test";
import { createWasmInitializer } from "../../sdk/dist/sdk/wasm-init.js";

test("WASM initialization can retry after a rejected attempt", async () => {
  let attempts = 0;
  const expected = { initialized: true };
  const init = createWasmInitializer(async () => {
    attempts += 1;
    if (attempts === 1) {
      throw new Error("initialization failed");
    }
    return expected;
  });

  await assert.rejects(init(), /initialization failed/);
  assert.equal(await init(), expected);
  assert.equal(await init(), expected);
  assert.equal(attempts, 2);
});
