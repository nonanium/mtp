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

async function hashPackageInputs() {
  const hash = crypto.createHash("sha256");
  const inputs = [
    "wasm/Cargo.toml",
    "wasm/src",
    "common/Cargo.toml",
    "common/src",
    "codec/Cargo.toml",
    "codec/src",
    "crypto/Cargo.toml",
    "crypto/src",
    "type-map/Cargo.toml",
    "type-map/build.rs",
    "type-map/src",
  ];

  async function addPath(relativePath) {
    const absolutePath = path.join(packageRoot, relativePath);
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

function parseTypeMapYaml(source: string, filePath: string) {
  const document = YAML.parseDocument(source, { prettyErrors: false });
  if (document.errors.length) {
    const error = document.errors[0];
    const line =
      error.pos?.[0] === undefined
        ? 1
        : source.slice(0, error.pos[0]).split("\n").length;
    throw new Error(`${filePath}:${line}: ${error.message}`);
  }
  const root = document.toJS() as {
    type_maps?: Record<
      string,
      {
        CommunicationTypes?: Record<string, unknown>;
        DataTypes?: Record<string, unknown>;
      }
    >;
  };
  const communicationTypes = new Set<string>(RESERVED_COMMUNICATION_TYPES);
  const dataTypes = new Set<string>(RESERVED_DATA_TYPES);
  for (const [version, map] of Object.entries(root.type_maps ?? {})) {
    if (!/^\d+\.\d+$/.test(version))
      throw new Error(`${filePath}: unparseable type-map version '${version}'`);
    for (const [section, target] of [
      ["CommunicationTypes", communicationTypes],
      ["DataTypes", dataTypes],
    ] as const) {
      const ids = new Map<number, string>();
      for (const [name, value] of Object.entries(
        map[section as "CommunicationTypes" | "DataTypes"] ?? {},
      )) {
        if (!Number.isInteger(value) || (value as number) < FIRST_USER_TYPE_ID)
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
        target.add(name);
      }
    }
  }
  return {
    communicationTypes: [...communicationTypes].sort(),
    dataTypes: [...dataTypes].sort(),
  };
}

function generateTypeMapModule(metadata: {
  communicationTypes: string[];
  dataTypes: string[];
}) {
  const js = `export const communicationTypes = ${JSON.stringify(metadata.communicationTypes, null, 2)};\nexport const dataTypes = ${JSON.stringify(metadata.dataTypes, null, 2)};\n`;
  const dts = `export type MTPCommunicationType = ${quoteList(metadata.communicationTypes)};\nexport type MTPDataType = ${quoteList(metadata.dataTypes)};\nexport declare const communicationTypes: readonly MTPCommunicationType[];\nexport declare const dataTypes: readonly MTPDataType[];\n`;
  return { js, dts };
}

async function writeTypeMapModule(outDir, typeMapsPath) {
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

async function copyWasmBuildInputs(buildRoot) {
  const inputs = [
    "Cargo.lock",
    "wasm",
    "common",
    "codec",
    "crypto",
    "type-map",
  ];

  for (const input of inputs) {
    const source = path.join(packageRoot, input);
    if (!(await pathExists(source))) {
      continue;
    }

    await fs.cp(source, path.join(buildRoot, input), { recursive: true });
  }
}

async function runWasmPack({ outDir, typeMapsPath, release, wasmPackArgs }) {
  const buildRoot = await fs.mkdtemp(path.join(os.tmpdir(), "mtp-wasm-"));
  const args = [
    "build",
    path.join(buildRoot, "wasm"),
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

      const sourceWatchDirs = [
        "wasm/src",
        "common/src",
        "codec/src",
        "crypto/src",
        "type-map/src",
      ].map((rel) => path.join(packageRoot, rel));

      server.watcher.add(state.typeMapsPath);
      for (const dir of sourceWatchDirs) {
        if (await pathExists(dir)) {
          server.watcher.add(dir);
        }
      }

      let rebuildTimer: ReturnType<typeof setTimeout> | null = null;
      const scheduleRebuild = (changedPath: string) => {
        const resolved = path.resolve(changedPath);
        const isTypeMap = resolved === state.typeMapsPath;
        const isSource = sourceWatchDirs.some((dir) =>
          resolved.startsWith(`${dir}${path.sep}`),
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
