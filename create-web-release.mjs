#!/usr/bin/env node

import { execFile, spawn } from "node:child_process";
import { access, cp, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";

const execFileAsync = promisify(execFile);
const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), ".");
const packageJsonPath = path.join(repositoryRoot, "package.json");

function usage() {
  return `Usage: node create-web-release.mjs [options]

Build and pack the browser package using the version of the root Cargo package.

Options:
  --skip-build          Pack the existing dist/ and wasm/pkg/ artifacts
  --output-dir <path>   Write the archive to this directory (default: repository root)
  --help                Show this help
`;
}

function parseArguments(arguments_) {
  const options = {
    outputDir: repositoryRoot,
    skipBuild: false,
  };

  for (let index = 0; index < arguments_.length; index += 1) {
    const argument = arguments_[index];
    if (argument === "--help") {
      options.help = true;
    } else if (argument === "--skip-build") {
      options.skipBuild = true;
    } else if (argument === "--output-dir") {
      const outputDir = arguments_[index + 1];
      if (!outputDir || outputDir.startsWith("--")) {
        throw new Error("--output-dir requires a directory path");
      }
      options.outputDir = path.resolve(repositoryRoot, outputDir);
      index += 1;
    } else if (argument.startsWith("--output-dir=")) {
      const outputDir = argument.slice("--output-dir=".length);
      if (!outputDir) {
        throw new Error("--output-dir requires a directory path");
      }
      options.outputDir = path.resolve(repositoryRoot, outputDir);
    } else {
      throw new Error(`Unknown option: ${argument}`);
    }
  }

  return options;
}

async function readJson(filePath) {
  const source = await readFile(filePath, "utf8");
  try {
    return JSON.parse(source);
  } catch (error) {
    throw new Error(`Invalid JSON in ${path.relative(repositoryRoot, filePath)}`, {
      cause: error,
    });
  }
}

async function run(command, arguments_, options = {}) {
  const renderedArguments = arguments_.map((argument) => JSON.stringify(argument)).join(" ");
  console.log(`\n> ${command}${renderedArguments ? ` ${renderedArguments}` : ""}`);

  await new Promise((resolve, reject) => {
    const child = spawn(command, arguments_, {
      cwd: options.cwd ?? repositoryRoot,
      env: options.env ?? process.env,
      stdio: "inherit",
    });

    child.once("error", (error) => {
      reject(new Error(`Failed to run ${command}: ${error.message}`, { cause: error }));
    });
    child.once("exit", (code, signal) => {
      if (code === 0) {
        resolve();
        return;
      }

      const reason = signal ? `signal ${signal}` : `exit code ${code}`;
      reject(new Error(`${command} failed with ${reason}`));
    });
  });
}

async function readCargoVersion() {
  let stdout;
  try {
    ({ stdout } = await execFileAsync(
      "cargo",
      [
        "metadata",
        "--no-deps",
        "--format-version",
        "1",
        "--manifest-path",
        path.join(repositoryRoot, "Cargo.toml"),
      ],
      { cwd: repositoryRoot, maxBuffer: 1024 * 1024 },
    ));
  } catch (error) {
    throw new Error(`Unable to read the root Cargo package version: ${error.message}`, {
      cause: error,
    });
  }

  let metadata;
  try {
    metadata = JSON.parse(stdout);
  } catch (error) {
    throw new Error("cargo metadata returned invalid JSON", { cause: error });
  }

  const rootPackage = metadata.packages?.find((packageMetadata) => packageMetadata.name === "mtp");
  if (!rootPackage || typeof rootPackage.version !== "string") {
    throw new Error("The root Cargo package named 'mtp' was not found");
  }

  return rootPackage.version;
}

function packageRelativePath(entry) {
  if (typeof entry !== "string" || entry.length === 0) {
    throw new Error("package.json files entries must be non-empty strings");
  }

  const relativePath = entry.replace(/\/$/, "");
  if (
    !relativePath ||
    path.isAbsolute(relativePath) ||
    relativePath.split(/[\\/]/u).includes("..") ||
    relativePath.includes("*")
  ) {
    throw new Error(`Unsupported package file entry: ${entry}`);
  }

  return relativePath;
}

async function copyPackageFiles(stageRoot, packageJson) {
  if (!Array.isArray(packageJson.files)) {
    throw new Error("package.json must declare a files array for Web releases");
  }

  for (const entry of packageJson.files) {
    const relativePath = packageRelativePath(entry);
    const sourcePath = path.join(repositoryRoot, relativePath);
    const destinationPath = path.join(stageRoot, relativePath);

    try {
      await access(sourcePath);
    } catch (error) {
      throw new Error(`Release file is missing: ${relativePath}`, { cause: error });
    }

    await mkdir(path.dirname(destinationPath), { recursive: true });
    await cp(sourcePath, destinationPath, { recursive: true });
  }
}

async function createRelease({ outputDir, packageJson, version }) {
  const stageRoot = await mkdtemp(path.join(os.tmpdir(), "mtp-web-release-"));
  const stagedPackageJson = {
    ...packageJson,
    version,
  };

  try {
    await writeFile(
      path.join(stageRoot, "package.json"),
      `${JSON.stringify(stagedPackageJson, null, 2)}\n`,
    );
    await copyPackageFiles(stageRoot, packageJson);

    const stagedWasmPackagePath = path.join(stageRoot, "wasm", "pkg", "package.json");
    const stagedWasmPackageJson = await readJson(stagedWasmPackagePath);
    stagedWasmPackageJson.version = version;
    await writeFile(
      stagedWasmPackagePath,
      `${JSON.stringify(stagedWasmPackageJson, null, 2)}\n`,
    );

    await mkdir(outputDir, { recursive: true });
    const archiveName = `${packageJson.name}-${version}.tgz`;
    const archivePath = path.join(outputDir, archiveName);
    await rm(archivePath, { force: true });

    await run("npm", ["pack", "--pack-destination", outputDir], { cwd: stageRoot });

    try {
      await access(archivePath);
    } catch (error) {
      throw new Error(`npm pack did not create ${archiveName}`, { cause: error });
    }

    return archivePath;
  } finally {
    await rm(stageRoot, { recursive: true, force: true });
  }
}

async function main() {
  const options = parseArguments(process.argv.slice(2));
  if (options.help) {
    console.log(usage());
    return;
  }

  const packageJson = await readJson(packageJsonPath);
  if (packageJson.name !== "mtp") {
    throw new Error("package.json must describe the 'mtp' Web package");
  }

  const version = await readCargoVersion();
  console.log(`Using Cargo package version ${version}`);

  if (!options.skipBuild) {
    await run("pnpm", ["run", "clean"]);
    await run("pnpm", ["run", "build"]);
  }

  const archivePath = await createRelease({
    outputDir: options.outputDir,
    packageJson,
    version,
  });
  console.log(`\nCreated ${path.relative(repositoryRoot, archivePath) || archivePath}`);
}

main().catch((error) => {
  console.error(`\n${error.message}`);
  process.exitCode = 1;
});
