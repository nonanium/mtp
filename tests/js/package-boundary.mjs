import { access, readFile } from "node:fs/promises";
import assert from "node:assert/strict";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const repositoryRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../..",
);
const sdkRoot = path.join(repositoryRoot, "sdk");

async function requireFile(relativePath) {
  try {
    await access(path.join(sdkRoot, relativePath));
  } catch {
    assert.fail(`missing release file: ${relativePath}`);
  }
}

async function readJson(relativePath) {
  return JSON.parse(
    await readFile(path.join(sdkRoot, relativePath), "utf8"),
  );
}

test("published package boundary contains all release entry points", async () => {
  const packageJson = await readJson("package.json");
  const wasmPackageJson = await readJson("bindings/wasm/pkg/package.json");

  for (const relativePath of [
    "dist/raw/index.js",
    "dist/raw/index.d.ts",
    "dist/sdk/index.js",
    "dist/sdk/index.d.ts",
    "dist/type-map/index.js",
    "dist/type-map/index.d.ts",
    "dist/vite/index.js",
    "dist/vite/index.d.ts",
    "bindings/wasm/pkg/mtp_wasm.js",
    "bindings/wasm/pkg/mtp_wasm.d.ts",
    "bindings/wasm/pkg/mtp_wasm_bg.wasm",
  ]) {
    await requireFile(relativePath);
  }

  let wasmIgnoreExists = true;
  try {
    await access(path.join(sdkRoot, "bindings/wasm/pkg/.gitignore"));
  } catch {
    wasmIgnoreExists = false;
  }
  assert.equal(
    wasmIgnoreExists,
    false,
    "bindings/wasm/pkg/.gitignore would cause npm pack to omit the WASM files",
  );

  assert.equal(
    packageJson.version,
    wasmPackageJson.version,
    "package and WASM versions must match",
  );
  const cargoManifest = await readFile(path.join(repositoryRoot, "Cargo.toml"), "utf8");
  const cargoVersion = cargoManifest.match(/\[workspace\.package\][\s\S]*?version = "([^"]+)"/)?.[1];
  assert.equal(packageJson.version, cargoVersion, "Cargo workspace and SDK versions must match");

  const rawModule = await readFile(
    path.join(sdkRoot, "dist/raw/index.js"),
    "utf8",
  );
  assert.match(
    rawModule,
    /\.\.\/\.\.\/bindings\/wasm\/pkg\/mtp_wasm\.js/,
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
