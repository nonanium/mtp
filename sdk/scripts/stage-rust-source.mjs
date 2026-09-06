import { cp, mkdir, rm } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const sdkRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const repositoryRoot = path.resolve(sdkRoot, "..");
const stageRoot = path.join(sdkRoot, ".rust");
const inputs = [
  "Cargo.lock",
  "bindings/wasm/.cargo",
  "bindings/wasm/Cargo.toml",
  "bindings/wasm/src",
  "codec/Cargo.toml",
  "codec/src",
  "common/Cargo.toml",
  "common/src",
  "core/Cargo.toml",
  "core/src",
  "crypto/Cargo.toml",
  "crypto/src",
  "type-map/Cargo.toml",
  "type-map/build.rs",
  "type-map/reserved.json",
  "type-map/src",
];

await rm(stageRoot, { recursive: true, force: true });
await mkdir(stageRoot, { recursive: true });
for (const input of inputs) {
  await mkdir(path.dirname(path.join(stageRoot, input)), { recursive: true });
  await cp(path.join(repositoryRoot, input), path.join(stageRoot, input), {
    recursive: true,
  });
}
await cp(
  path.join(sdkRoot, "rust-workspace.Cargo.toml"),
  path.join(stageRoot, "Cargo.toml"),
);
await cp(path.join(repositoryRoot, "README.md"), path.join(sdkRoot, "README.md"));
