import { cp, mkdir } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const sdkRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
await mkdir(path.join(sdkRoot, "type-map"), { recursive: true });
await cp(
  path.join(sdkRoot, "..", "type-map", "reserved.json"),
  path.join(sdkRoot, "type-map", "reserved.json"),
);
