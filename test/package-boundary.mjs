import { access, readFile } from "node:fs/promises";
import assert from "node:assert/strict";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const repositoryRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
);

async function requireFile(relativePath) {
  try {
    await access(path.join(repositoryRoot, relativePath));
  } catch {
    assert.fail(`missing release file: ${relativePath}`);
  }
}

async function readJson(relativePath) {
  return JSON.parse(
    await readFile(path.join(repositoryRoot, relativePath), "utf8"),
  );
}

test("published package boundary contains all release entry points", async () => {
  const packageJson = await readJson("package.json");
  const wasmPackageJson = await readJson("wasm/pkg/package.json");

  for (const relativePath of [
    "dist/raw/index.js",
    "dist/raw/index.d.ts",
    "dist/sdk/index.js",
    "dist/sdk/index.d.ts",
    "dist/type-map/index.js",
    "dist/type-map/index.d.ts",
    "dist/vite/index.js",
    "dist/vite/index.d.ts",
    "wasm/pkg/mtp_wasm.js",
    "wasm/pkg/mtp_wasm.d.ts",
    "wasm/pkg/mtp_wasm_bg.wasm",
  ]) {
    await requireFile(relativePath);
  }

  let wasmIgnoreExists = true;
  try {
    await access(path.join(repositoryRoot, "wasm/pkg/.gitignore"));
  } catch {
    wasmIgnoreExists = false;
  }
  assert.equal(
    wasmIgnoreExists,
    false,
    "wasm/pkg/.gitignore would cause npm pack to omit the WASM files",
  );

  assert.equal(
    packageJson.version,
    wasmPackageJson.version,
    "package and WASM versions must match",
  );

  const rawModule = await readFile(
    path.join(repositoryRoot, "dist/raw/index.js"),
    "utf8",
  );
  assert.match(
    rawModule,
    /\.\.\/\.\.\/wasm\/pkg\/mtp_wasm\.js/,
    "dist/raw must point at the packaged WASM module",
  );

  for (const target of Object.values(packageJson.exports)) {
    const entry = typeof target === "string" ? target : target.import;
    await requireFile(entry.replace(/^\.\//, ""));
    if (typeof target === "object" && target.types) {
      await requireFile(target.types.replace(/^\.\//, ""));
    }
  }
});
