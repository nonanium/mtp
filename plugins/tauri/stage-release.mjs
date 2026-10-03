import { cp, mkdir, rm } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";

const plugin = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(plugin, "../..");
const destination = process.argv[2];
if (!destination) throw new Error("Usage: node plugins/tauri/stage-release.mjs <destination>");
const output = path.resolve(destination);
if (output === root || root.startsWith(`${output}${path.sep}`)) throw new Error("Destination must not contain the repository");
if (output.startsWith(`${root}${path.sep}`)) throw new Error("Destination must be outside the repository");
await mkdir(output, { recursive: true });
const stage = path.join(output, "mtp-native");
await rm(stage, { recursive: true, force: true });
await mkdir(stage);
await cp(path.join(root, "docs"), path.join(stage, "docs"), { recursive: true });
for (const input of ["Cargo.toml", "Cargo.lock", "src", "common", "core", "pipes", "crypto", "type-map", "codec", "client", "host", "files", "webserver", "bindings/native", "bindings/h3", "bindings/wasm", "plugins/tauri", "tests/rust", "tests/fixtures/example/type-maps.yaml", "tests/fixtures/example/client", "tests/fixtures/example/server", "tests/fixtures/example/keygen"]) {
  await cp(path.join(root, input), path.join(stage, input), {
    recursive: true,
    filter: (entry) => !["target", "node_modules", ".gradle", ".tauri", "build", "pkg"].includes(path.basename(entry)),
  });
}
console.log(stage);
