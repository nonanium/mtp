import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import {
  chmod,
  mkdir,
  mkdtemp,
  readdir,
  readFile,
  rename,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { existsSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import {
  copyWasmBuildInputs,
  generateTypeMapModule,
  hashPackageInputs,
  parseTypeMapYaml,
  wasmWorkspaceManifest,
} from "../../sdk/dist/vite/index.js";

const run = promisify(execFile);
const repositoryRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../..",
);

const repeatedNames = `
protocol_version: "2.0"
type_maps:
  "1.0":
    CommunicationTypes:
      Message: 32
      LegacyMessage: 33
    DataTypes:
      Payload: 32
      LegacyPayload: 33
  "2.0":
    CommunicationTypes:
      Message: 35
      CurrentMessage: 36
    DataTypes:
      Payload: 35
      CurrentPayload: 36
`;

const selected = parseTypeMapYaml(repeatedNames, "repeated.yaml");
assert.ok(selected.communicationTypes.includes("Message"));
assert.ok(selected.communicationTypes.includes("CurrentMessage"));
assert.ok(!selected.communicationTypes.includes("LegacyMessage"));
assert.ok(selected.dataTypes.includes("Payload"));
assert.ok(selected.dataTypes.includes("CurrentPayload"));
assert.ok(!selected.dataTypes.includes("LegacyPayload"));
assert.ok(selected.communicationTypes.includes("Ping"));
assert.ok(selected.dataTypes.includes("Version"));

const generated = generateTypeMapModule(selected);
assert.match(generated.dts, /"Message"/);
assert.match(generated.dts, /"CurrentMessage"/);
assert.doesNotMatch(generated.dts, /LegacyMessage/);
assert.doesNotMatch(generated.dts, /LegacyPayload/);

assert.throws(
  () =>
    parseTypeMapYaml(
      `protocol_version: "1.0"\ntype_maps:\n  "1.0":\n    CommunicationTypes:\n      Ping: 32\n`,
      "reserved.yaml",
    ),
  /uses a reserved type name/,
);
assert.throws(
  () =>
    parseTypeMapYaml(
      `protocol_version: "2.0"\ntype_maps:\n  "1.0": {}\n`,
      "missing-version.yaml",
    ),
  /is not defined in type_maps/,
);
assert.throws(
  () => parseTypeMapYaml(`protocol_version: "1.0"\ntype_maps: {}`, "empty.yaml"),
  /is not defined in type_maps/,
);
assert.throws(
  () =>
    parseTypeMapYaml(
      `protocol_version: "latest"\ntype_maps:\n  "latest": {}\n`,
      "invalid-version.yaml",
    ),
  /protocol_version must be a string/,
);

const temporaryBuildRoot = await mkdtemp(path.join(os.tmpdir(), "mtp-vite-inputs-"));
try {
  await copyWasmBuildInputs(temporaryBuildRoot);
  for (const requiredInput of [
    "Cargo.lock",
    "bindings/wasm/Cargo.toml",
    "bindings/wasm/src/lib.rs",
    "common/Cargo.toml",
    "core/Cargo.toml",
    "codec/Cargo.toml",
    "crypto/Cargo.toml",
    "type-map/Cargo.toml",
    "type-map/build.rs",
    "type-map/reserved.json",
  ]) {
    assert.equal(
      existsSync(path.join(temporaryBuildRoot, requiredInput)),
      true,
      `temporary WASM build input is missing: ${requiredInput}`,
    );
  }
  assert.equal(
    await readFile(path.join(temporaryBuildRoot, "type-map/reserved.json"), "utf8"),
    await readFile(path.join(repositoryRoot, "type-map/reserved.json"), "utf8"),
  );
  assert.match(
    await readFile(path.join(temporaryBuildRoot, "type-map/build.rs"), "utf8"),
    /include_str!\("reserved\.json"\)/,
  );
  const temporaryManifest = await readFile(
    path.join(temporaryBuildRoot, "Cargo.toml"),
    "utf8",
  );
  assert.equal(
    temporaryManifest,
    wasmWorkspaceManifest(
      await readFile(path.join(repositoryRoot, "Cargo.toml"), "utf8"),
    ),
  );
  assert.match(temporaryManifest, /^\[workspace\]$/m);
  assert.match(temporaryManifest, /^\[workspace\.package\]$/m);
  assert.match(temporaryManifest, /^\[workspace\.dependencies\]$/m);
  assert.doesNotMatch(temporaryManifest, /^\[(package|dependencies|features)\]$/m);
  assert.doesNotMatch(temporaryManifest, /^\s*"\.",?$/m);
  await run("cargo", ["metadata", "--format-version", "1", "--no-deps"], {
    cwd: temporaryBuildRoot,
  });
} finally {
  await rm(temporaryBuildRoot, { recursive: true, force: true });
}

const hashTestRoot = await mkdtemp(path.join(os.tmpdir(), "mtp-vite-hash-"));
try {
  await mkdir(path.join(hashTestRoot, "type-map"), { recursive: true });
  const manifestPath = path.join(hashTestRoot, "type-map/reserved.json");
  await writeFile(manifestPath, "{\"version\":1}");
  const firstHash = await hashPackageInputs(hashTestRoot);
  await writeFile(manifestPath, "{\"version\":2}");
  const secondHash = await hashPackageInputs(hashTestRoot);
  assert.notEqual(firstHash, secondHash);
} finally {
  await rm(hashTestRoot, { recursive: true, force: true });
}

const viteCandidates = [
  path.join(repositoryRoot, "tests/fixtures/example/web-client/node_modules/.bin/vite"),
  path.join(repositoryRoot, "node_modules/.bin/vite"),
];
const viteBin = viteCandidates.find((candidate) => existsSync(candidate));
if (!viteBin) {
  console.warn("Skipping packed Vite smoke test: Vite is not installed");
} else {
  const temporaryPackageRoot = await mkdtemp(path.join(os.tmpdir(), "mtp-vite-package-"));
  try {
    await run(
      "npm",
      ["pack", "--pack-destination", temporaryPackageRoot],
      {
        cwd: path.join(repositoryRoot, "sdk"),
        env: {
          ...process.env,
          npm_config_cache: path.join(temporaryPackageRoot, "npm-cache"),
        },
      },
    );
    const packageName = (await readdir(temporaryPackageRoot)).find((entry) =>
      entry.endsWith(".tgz"),
    );
    assert.ok(packageName, "npm pack did not report a tarball");

    const extractedRoot = path.join(temporaryPackageRoot, "extracted");
    const appRoot = path.join(temporaryPackageRoot, "app");
    await mkdir(extractedRoot, { recursive: true });
    await run("tar", ["-xzf", path.join(temporaryPackageRoot, packageName), "-C", extractedRoot]);
    await mkdir(path.join(appRoot, "node_modules"), { recursive: true });
    await rename(path.join(extractedRoot, "package"), path.join(appRoot, "node_modules/mtp"));
    await symlink(
      path.join(repositoryRoot, "sdk/node_modules/yaml"),
      path.join(appRoot, "node_modules/yaml"),
      "dir",
    );
    await symlink(
      path.join(path.dirname(path.dirname(viteBin)), "vite"),
      path.join(appRoot, "node_modules/vite"),
      "dir",
    );

    await writeFile(
      path.join(appRoot, "package.json"),
      JSON.stringify({ type: "module", private: true }),
    );
    await writeFile(
      path.join(appRoot, "index.html"),
      '<script type="module" src="/main.js"></script>',
    );
    await writeFile(
      path.join(appRoot, "main.js"),
      'import { communicationTypes } from "mtp/type-map";\n' +
        'if (!communicationTypes.includes("CurrentMessage") || communicationTypes.includes("LegacyMessage")) throw new Error("wrong browser type-map selection");\n',
    );
    await writeFile(
      path.join(appRoot, "type-maps.yaml"),
      repeatedNames,
    );
    await writeFile(
      path.join(appRoot, "vite.config.mjs"),
      'import { defineConfig } from "vite";\n' +
        'import { mtp } from "mtp/vite";\n' +
        'export default defineConfig({ plugins: [mtp({ typeMaps: "./type-maps.yaml", release: false })] });\n',
    );

    const fakeBin = path.join(temporaryPackageRoot, "bin");
    const fakeWasmPack = path.join(fakeBin, "wasm-pack");
    await mkdir(fakeBin, { recursive: true });
    await writeFile(
      fakeWasmPack,
      `#!/usr/bin/env node
const fs = require("node:fs");
const path = require("node:path");
const args = process.argv.slice(2);
const outIndex = args.indexOf("--out-dir");
if (outIndex < 0) throw new Error("fake wasm-pack did not receive --out-dir");
if (!fs.existsSync(path.join(process.cwd(), "type-map", "reserved.json"))) {
  throw new Error("temporary wasm build is missing type-map/reserved.json");
}
const outDir = args[outIndex + 1];
fs.mkdirSync(outDir, { recursive: true });
fs.writeFileSync(path.join(outDir, "mtp_wasm.js"), "export default function init() {}\\n");
fs.writeFileSync(path.join(outDir, "mtp_wasm_bg.wasm"), Buffer.from([0, 97, 115, 109, 1, 0, 0, 0]));
`,
    );
    await chmod(fakeWasmPack, 0o755);

    await run(viteBin, ["build", "--config", "vite.config.mjs"], {
      cwd: appRoot,
      env: {
        ...process.env,
        PATH: `${fakeBin}${path.delimiter}${process.env.PATH ?? ""}`,
      },
    });
    assert.equal(existsSync(path.join(appRoot, "dist/index.html")), true);
  } finally {
    await rm(temporaryPackageRoot, { recursive: true, force: true });
  }
}

console.log("Vite type-map tests passed");
