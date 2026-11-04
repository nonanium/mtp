import crypto from "node:crypto";
import fs from "node:fs/promises";
import { spawn } from "node:child_process";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import YAML from "yaml";
import {
  FIRST_USER_TYPE_ID,
  RESERVED_COMMUNICATION_TYPES,
  RESERVED_DATA_TYPES,
  RESERVED_COMMUNICATION_TYPE_IDS,
  RESERVED_DATA_TYPE_IDS,
} from "../type-map/reserved.js";

export interface MTPVitePluginOptions {
  typeMaps: string;
  release?: boolean;
  wasmPackArgs?: string[];
  outDir?: string;
}

export interface VitePlugin {
  name: string;
  config?: (...args: any[]) => unknown;
  buildStart?: (...args: any[]) => unknown;
  configureServer?: (...args: any[]) => unknown;
  addWatchFile?: (file: string) => void;
}

const packageRoot = process.env.MTP_PACKAGE_ROOT
  ? path.resolve(process.env.MTP_PACKAGE_ROOT)
  : path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const repositoryRoot = path.resolve(packageRoot, "..");
const sourceRoot = await pathExists(
  path.join(repositoryRoot, "bindings/wasm/Cargo.toml"),
)
  ? repositoryRoot
  : path.join(packageRoot, ".rust");
const rawEntryName = "mtp_wasm.js";
const wasmEntryName = "mtp_wasm_bg.wasm";
const typeMapEntryName = "mtp_type_map.js";

function normalizeOptions(options) {
  if (!options?.typeMaps) {
    throw new Error(
      "mtp/vite requires a typeMaps option, for example mtp({ typeMaps: './type-maps.yaml' })",
    );
  }

  return options;
}

async function pathExists(filePath) {
  try {
    await fs.access(filePath);
    return true;
  } catch {
    return false;
  }
}

function devServerPath(root: string, filePath: string) {
  const relativePath = path.relative(root, filePath);
  if (relativePath.startsWith("..") || path.isAbsolute(relativePath)) {
    return null;
  }

  return `/${relativePath.split(path.sep).join("/")}`;
}

export async function hashPackageInputs(root = sourceRoot) {
  const hash = crypto.createHash("sha256");
  const inputs = [
    "Cargo.lock",
    "bindings/wasm/Cargo.toml",
    "bindings/wasm/.cargo/config.toml",
    "bindings/wasm/src",
    "core/Cargo.toml",
    "core/src",
    "pipes/Cargo.toml",
    "pipes/src",
    "common/Cargo.toml",
    "common/src",
    "codec/Cargo.toml",
    "codec/src",
    "crypto/Cargo.toml",
    "crypto/src",
    "type-map/Cargo.toml",
    "type-map/build.rs",
    "type-map/reserved.json",
    "type-map/src",
  ];

  async function addPath(relativePath) {
    const absolutePath = path.join(root, relativePath);
    const stat = await fs.stat(absolutePath).catch(() => null);
    if (!stat) {
      return;
    }

    if (stat.isDirectory()) {
      const entries = await fs.readdir(absolutePath);
      for (const entry of entries.sort()) {
        await addPath(path.join(relativePath, entry));
      }
      return;
    }

    hash.update(relativePath);
    hash.update(await fs.readFile(absolutePath));
  }

  for (const input of inputs) {
    await addPath(input);
  }

  return hash.digest("hex");
}

function quoteList(values: string[]): string {
  return values.length === 0
    ? "never"
    : values.map((value) => JSON.stringify(value)).join(" | ");
}

export function parseTypeMapYaml(source: string, filePath: string) {
  const document = YAML.parseDocument(source, { prettyErrors: false, merge: true });
  if (document.errors.length) {
    const error = document.errors[0];
    const line =
      error.pos?.[0] === undefined
        ? 1
        : source.slice(0, error.pos[0]).split("\n").length;
    throw new Error(`${filePath}:${line}: ${error.message}`);
  }
  const root = document.toJS() as {
    protocol_version?: unknown;
    type_maps?: unknown;
  };
  if (
    root === null ||
    typeof root !== "object" ||
    Array.isArray(root) ||
    typeof root.protocol_version !== "string" ||
    !/^\d+\.\d+$/.test(root.protocol_version)
  ) {
    throw new Error(
      `${filePath}: protocol_version must be a string matching '<major>.<minor>'`,
    );
  }
  if (
    root.type_maps === null ||
    typeof root.type_maps !== "object" ||
    Array.isArray(root.type_maps)
  ) {
    throw new Error(`${filePath}: type_maps must be a mapping`);
  }
  const typeMaps = root.type_maps as Record<string, unknown>;
  if (!Object.prototype.hasOwnProperty.call(typeMaps, root.protocol_version)) {
    throw new Error(
      `${filePath}: protocol_version '${root.protocol_version}' is not defined in type_maps`,
    );
  }

  const reservedCommunicationTypes = new Set(RESERVED_COMMUNICATION_TYPES);
  const reservedDataTypes = new Set(RESERVED_DATA_TYPES);
  const communicationTypes = new Set<string>(RESERVED_COMMUNICATION_TYPES);
  const dataTypes = new Set<string>(RESERVED_DATA_TYPES);
  for (const [version, rawMap] of Object.entries(typeMaps)) {
    if (!/^\d+\.\d+$/.test(version))
      throw new Error(`${filePath}: unparseable type-map version '${version}'`);
    if (
      rawMap === null ||
      typeof rawMap !== "object" ||
      Array.isArray(rawMap)
    ) {
      throw new Error(`${filePath}: ${version} must be a mapping`);
    }
    const map = rawMap as {
      CommunicationTypes?: unknown;
      DataTypes?: unknown;
    };
    for (const { section, reserved, selected } of [
      {
        section: "CommunicationTypes",
        reserved: reservedCommunicationTypes,
        selected: communicationTypes,
      },
      {
        section: "DataTypes",
        reserved: reservedDataTypes,
        selected: dataTypes,
      },
    ]) {
      const sectionValue = map[section as "CommunicationTypes" | "DataTypes"];
      if (
        sectionValue !== undefined &&
        (sectionValue === null ||
          typeof sectionValue !== "object" ||
          Array.isArray(sectionValue))
      ) {
        throw new Error(`${filePath}: ${version}.${section} must be a mapping`);
      }
      const ids = new Map<number, string>();
      for (const [name, value] of Object.entries(sectionValue ?? {})) {
        if (reserved.has(name)) {
          throw new Error(
            `${filePath}: ${version}.${section}.${name} uses a reserved type name`,
          );
        }
        if (!Number.isInteger(value) || (value as number) < FIRST_USER_TYPE_ID || (value as number) > 65535)
          throw new Error(
            `${filePath}: ${version}.${section}.${name} must use an integer id >= ${FIRST_USER_TYPE_ID}`,
          );
        const id = value as number;
        const previous = ids.get(id);
        if (previous && previous !== name)
          throw new Error(
            `${filePath}: duplicate type id ${id} in ${section} (${previous} and ${name})`,
          );
        ids.set(id, name);
        if (version === root.protocol_version) {
          selected.add(name);
        }
      }
    }
  }
  return {
    communicationTypes: [...communicationTypes].sort(),
    dataTypes: [...dataTypes].sort(),
    dictionaryIdentities: Object.fromEntries(Object.entries(typeMaps).map(([version, map]) => [version, dictionaryFingerprint(version, map as { CommunicationTypes?: Record<string, number>; DataTypes?: Record<string, number> })])),
  };
}

/** Byte-for-byte equivalent to mtp-type-map's V1 dictionary serialization. */
export function dictionaryFingerprint(version: string, map: { CommunicationTypes?: Record<string, number>; DataTypes?: Record<string, number> }): string {
  const chunks: Buffer[] = [Buffer.from("mtp-type-dictionary\0v1\0", "utf8")];
  const string = (value: string) => {
    const bytes = Buffer.from(value, "utf8");
    const length = Buffer.alloc(4);
    length.writeUInt32BE(bytes.length);
    chunks.push(length, bytes);
  };
  string(version);
  for (const [tag, reserved, application] of [
    [1, RESERVED_COMMUNICATION_TYPE_IDS, map.CommunicationTypes],
    [2, RESERVED_DATA_TYPE_IDS, map.DataTypes],
  ] as const) {
    const entries = Object.entries({ ...reserved, ...application }).sort(([a], [b]) => Buffer.compare(Buffer.from(a, "utf8"), Buffer.from(b, "utf8")));
    const header = Buffer.alloc(5);
    header.writeUInt8(tag);
    header.writeUInt32BE(entries.length, 1);
    chunks.push(header);
    for (const [name, id] of entries) {
      string(name);
      const bytes = Buffer.alloc(2);
      bytes.writeUInt16BE(id);
      chunks.push(bytes);
    }
  }
  return crypto.createHash("sha256").update(Buffer.concat(chunks)).digest("hex");
}

export function generateTypeMapModule(metadata: {
  communicationTypes: string[];
  dataTypes: string[];
  dictionaryIdentities?: Record<string, string>;
}) {
  const js = `export const communicationTypes = ${JSON.stringify(metadata.communicationTypes, null, 2)};\nexport const dataTypes = ${JSON.stringify(metadata.dataTypes, null, 2)};\nexport const dictionaryIdentities = ${JSON.stringify(metadata.dictionaryIdentities ?? {}, null, 2)};\n`;
  const dts = `export type MTPCommunicationType = ${quoteList(metadata.communicationTypes)};\nexport type MTPDataType = ${quoteList(metadata.dataTypes)};\nexport declare const communicationTypes: readonly MTPCommunicationType[];\nexport declare const dataTypes: readonly MTPDataType[];\nexport declare const dictionaryIdentities: Readonly<Record<string, string>>;\n`;
  return { js, dts };
}

export async function writeTypeMapModule(outDir, typeMapsPath) {
  const source = await fs.readFile(typeMapsPath, "utf8").catch((error) => {
    throw new Error(
      `Failed to read type map '${typeMapsPath}': ${error.message}`,
    );
  });
  const metadata = parseTypeMapYaml(source, typeMapsPath);
  const module = generateTypeMapModule(metadata);
  await fs.mkdir(outDir, { recursive: true });
  await fs.writeFile(path.join(outDir, typeMapEntryName), module.js);
  await fs.writeFile(path.join(outDir, "mtp_type_map.d.ts"), module.dts);
  await fs.writeFile(path.join(outDir, `${typeMapEntryName}.d.ts`), module.dts);
  return source;
}

const wasmWorkspaceMembers = [
  "bindings/wasm",
  "codec",
  "common",
  "core",
  "pipes",
  "crypto",
  "type-map",
];
const wasmWorkspaceDependencies = new Set([
  "mtp-codec",
  "mtp-common",
  "mtp-core",
  "mtp-pipes",
  "mtp-crypto",
  "mtp-type-map",
]);

function manifestSection(source: string, name: string) {
  const header = `[${name}]`;
  const start = source.indexOf(header);
  if (start < 0) {
    throw new Error(`Cargo manifest is missing ${header}`);
  }
  const next = source.indexOf("\n[", start + header.length);
  return source.slice(start, next < 0 ? source.length : next).trim();
}

export function wasmWorkspaceManifest(source: string) {
  const workspace = manifestSection(source, "workspace");
  const resolver = workspace.match(/^resolver\s*=\s*"([^"]+)"/m)?.[1] ?? "3";
  const workspacePackage = manifestSection(source, "workspace.package");
  const dependencies = manifestSection(source, "workspace.dependencies")
    .split("\n")
    .filter(
      (line, index) =>
        index === 0 ||
        wasmWorkspaceDependencies.has(line.match(/^([^\s=]+)\s*=/)?.[1] ?? ""),
    )
    .join("\n");
  const members = wasmWorkspaceMembers
    .map((member) => `    ${JSON.stringify(member)},`)
    .join("\n");
  const defaultMembers = wasmWorkspaceMembers
    .filter((member) => member !== "bindings/wasm")
    .map((member) => `    ${JSON.stringify(member)},`)
    .join("\n");

  return `[workspace]\nmembers = [\n${members}\n]\ndefault-members = [\n${defaultMembers}\n]\nresolver = "${resolver}"\n\n${workspacePackage}\n\n${dependencies}\n`;
}

export async function copyWasmBuildInputs(buildRoot) {
  const inputs = [
    "Cargo.lock",
    "bindings/wasm",
    "common",
    "core",
    "pipes",
    "codec",
    "crypto",
    "type-map",
  ];

  for (const input of inputs) {
    const source = path.join(sourceRoot, input);
    if (!(await pathExists(source))) {
      continue;
    }

    await fs.cp(source, path.join(buildRoot, input), { recursive: true });
  }

  const rootManifest = await fs.readFile(path.join(sourceRoot, "Cargo.toml"), "utf8");
  await fs.writeFile(
    path.join(buildRoot, "Cargo.toml"),
    wasmWorkspaceManifest(rootManifest),
  );
}

async function runWasmPack({ outDir, typeMapsPath, release, wasmPackArgs }) {
  const buildRoot = await fs.mkdtemp(path.join(os.tmpdir(), "mtp-wasm-"));
  const args = [
    "build",
    path.join(buildRoot, "bindings/wasm"),
    "--target",
    "web",
    "--out-dir",
    outDir,
  ];
  if (release) {
    args.push("--release");
  } else {
    args.push("--dev");
  }
  args.push(...wasmPackArgs);

  try {
    await copyWasmBuildInputs(buildRoot);
    await new Promise<void>((resolve, reject) => {
      const child = spawn("wasm-pack", args, {
        cwd: buildRoot,
        env: {
          ...process.env,
          MTP_TYPE_MAPS: typeMapsPath,
          RUSTFLAGS: [process.env.RUSTFLAGS, "--cfg web_sys_unstable_apis"]
            .filter(Boolean)
            .join(" "),
        },
        stdio: ["ignore", "pipe", "pipe"],
      });

      let stdout = "";
      let stderr = "";
      child.stdout.on("data", (chunk) => {
        stdout += chunk;
      });
      child.stderr.on("data", (chunk) => {
        stderr += chunk;
      });
      child.on("error", (error) => {
        if ((error as NodeJS.ErrnoException).code === "ENOENT") {
          reject(
            new Error(
              "Failed to run wasm-pack. Install wasm-pack or enter the project Nix dev shell, then retry.",
            ),
          );
        } else {
          reject(error);
        }
      });
      child.on("close", (code) => {
        if (code === 0) {
          resolve();
        } else {
          reject(
            new Error(
              `wasm-pack failed with exit code ${code}.\n${stdout}${stderr}`.trim(),
            ),
          );
        }
      });
    });
  } finally {
    await fs.rm(buildRoot, { recursive: true, force: true });
  }
}

async function buildIfNeeded(state, force = false) {
  if (state.buildPromise) {
    return state.buildPromise;
  }

  state.buildPromise = (async () => {
    const typeMapSource = await writeTypeMapModule(
      state.outDir,
      state.typeMapsPath,
    );
    const packageInputs = await hashPackageInputs();
    const fingerprint = crypto
      .createHash("sha256")
      .update(
        JSON.stringify({
          packageRoot,
          packageInputs,
          typeMapsPath: state.typeMapsPath,
          typeMapSource,
          release: state.release,
          wasmPackArgs: state.wasmPackArgs,
        }),
      )
      .digest("hex");
    const stampPath = path.join(state.outDir, ".mtp-build.json");
    const rawEntryPath = path.join(state.outDir, rawEntryName);
    const wasmPath = path.join(state.outDir, wasmEntryName);
    let previousFingerprint = null;
    try {
      previousFingerprint = JSON.parse(
        await fs.readFile(stampPath, "utf8"),
      ).fingerprint;
    } catch {
      previousFingerprint = null;
    }

    if (
      !force &&
      previousFingerprint === fingerprint &&
      (await pathExists(rawEntryPath)) &&
      (await pathExists(wasmPath))
    ) {
      return;
    }

    console.info(
      "\x1b[1m\x1b[35mmtp\x1b[0m compiling wasm... (this could take a minute)",
    );
    await runWasmPack(state);
    console.log(
      "\x1b[1m\x1b[35mmtp\x1b[0m \x1b[32mcompilation finished.\x1b[0m",
    );
    await fs.writeFile(
      stampPath,
      JSON.stringify(
        { fingerprint, builtAt: new Date().toISOString() },
        null,
        2,
      ),
    );
  })().finally(() => {
    state.buildPromise = null;
  });

  return state.buildPromise;
}

export function mtp(options: MTPVitePluginOptions): VitePlugin {
  const normalized = normalizeOptions(options);
  const state: any = {
    outDir: null,
    typeMapsPath: null,
    release: true,
    wasmPackArgs: normalized.wasmPackArgs ?? [],
    buildPromise: null,
  };

  return {
    name: "mtp",
    async config(config, env) {
      const root = path.resolve(config.root ?? process.cwd());
      state.typeMapsPath = path.resolve(root, normalized.typeMaps);
      state.outDir = path.resolve(
        root,
        normalized.outDir ?? path.join("node_modules", ".vite", "mtp"),
      );
      state.release = normalized.release ?? env.command === "build";

      if (!(await pathExists(state.typeMapsPath))) {
        throw new Error(
          `mtp/vite could not find typeMaps file: ${state.typeMapsPath}`,
        );
      }

      await buildIfNeeded(state);

      return {
        // The generated wasm-bindgen JavaScript imports its sibling `.wasm`
        // by a relative URL. Prebundling it independently lets Vite retain an
        // older wrapper while the plugin has rebuilt the wasm binary, which
        // produces missing closure-export errors at runtime.
        optimizeDeps: {
          exclude: ["mtp", "mtp/raw", "mtp/type-map"],
        },
        resolve: {
          preserveSymlinks: true,
          alias: {
            "mtp/raw": path.join(state.outDir, rawEntryName),
            "mtp/type-map": path.join(state.outDir, typeMapEntryName),
          },
        },
      };
    },
    buildStart() {
      (this as any).addWatchFile(state.typeMapsPath);
    },
    async configureServer(server) {
      const wasmPath = path.join(state.outDir, wasmEntryName);
      const wasmUrl = devServerPath(server.config.root, wasmPath);
      if (wasmUrl) {
        server.middlewares.use(async (req, res, next) => {
          if (
            !req.url ||
            new URL(req.url, "http://localhost").pathname !== wasmUrl
          ) {
            next();
            return;
          }

          try {
            res.setHeader("Content-Type", "application/wasm");
            res.setHeader(
              "Cache-Control",
              "no-cache, no-store, must-revalidate",
            );
            res.end(await fs.readFile(wasmPath));
          } catch (error) {
            next(error);
          }
        });
      }

      const sourceWatchPaths = [
        "bindings/wasm/src",
        "common/src",
        "codec/src",
        "crypto/src",
        "type-map/src",
        "type-map/reserved.json",
      ].map((rel) => path.join(sourceRoot, rel));

      server.watcher.add(state.typeMapsPath);
      for (const sourcePath of sourceWatchPaths) {
        if (await pathExists(sourcePath)) {
          server.watcher.add(sourcePath);
        }
      }

      let rebuildTimer: ReturnType<typeof setTimeout> | null = null;
      const scheduleRebuild = (changedPath: string) => {
        const resolved = path.resolve(changedPath);
        const isTypeMap = resolved === state.typeMapsPath;
        const isSource = sourceWatchPaths.some(
          (sourcePath) =>
            resolved === sourcePath ||
            resolved.startsWith(`${sourcePath}${path.sep}`),
        );
        if (!isTypeMap && !isSource) {
          return;
        }

        if (rebuildTimer) {
          clearTimeout(rebuildTimer);
        }

        rebuildTimer = setTimeout(() => {
          rebuildTimer = null;
          void (async () => {
            try {
              await server.restart();
            } catch (error) {
              server.config.logger.error(
                error instanceof Error ? error.message : String(error),
              );
            }
          })();
        }, 200);
      };

      server.watcher.on("change", scheduleRebuild);
      server.watcher.on("add", scheduleRebuild);
    },
  };
}

export const mtpVitePlugin = mtp;
export default mtpVitePlugin;
