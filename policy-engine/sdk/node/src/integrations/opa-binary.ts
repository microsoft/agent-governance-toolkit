import { accessSync, constants } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";

/**
 * Disable resolution of the bundled per-platform `opa` binary (the
 * `agent-control-specification-opa-*` optional dependencies). When set to a
 * truthy value, only an explicit `opaPath`/`$ACS_OPA_PATH` or a system `opa`
 * on `PATH` is used. Useful for forcing a specific system opa or for tests.
 */
export const DISABLE_BUNDLED_OPA_ENV = "ACS_OPA_NO_BUNDLE";

interface PlatformOpa {
  pkg: string;
  bin: string;
}

// process.platform-process.arch -> the optional dependency that ships opa for
// it. Mirrors the packages declared in package.json `optionalDependencies` and
// the directories under `npm/`.
const PLATFORM_OPA: Record<string, PlatformOpa> = {
  "linux-x64": { pkg: "agent-control-specification-opa-linux-x64", bin: "opa" },
  "linux-arm64": { pkg: "agent-control-specification-opa-linux-arm64", bin: "opa" },
  "darwin-x64": { pkg: "agent-control-specification-opa-darwin-x64", bin: "opa" },
  "darwin-arm64": { pkg: "agent-control-specification-opa-darwin-arm64", bin: "opa" },
  "win32-x64": { pkg: "agent-control-specification-opa-win32-x64", bin: "opa.exe" },
};

export function platformOpaKey(): string {
  return `${process.platform}-${process.arch}`;
}

/**
 * Locate the vendored `opa` binary for the current platform, or `undefined` if
 * none is available (unsupported platform, optional dependency not installed,
 * or explicitly disabled via {@link DISABLE_BUNDLED_OPA_ENV}). Resolution
 * tries the installed optional dependency first, then a sibling `npm/` package
 * (the in-repo/monorepo layout, where the published optional deps are absent).
 */
export function resolveBundledOpa(): string | undefined {
  const disabled = process.env[DISABLE_BUNDLED_OPA_ENV];
  if (disabled !== undefined && disabled !== "" && disabled !== "0" && disabled !== "false") {
    return undefined;
  }

  const entry = PLATFORM_OPA[platformOpaKey()];
  if (entry === undefined) return undefined;

  // 1) Installed optional dependency (the production install path).
  try {
    const require = createRequire(__filename);
    const pkgManifest = require.resolve(`${entry.pkg}/package.json`);
    const candidate = join(dirname(pkgManifest), "bin", entry.bin);
    if (isExecutable(candidate)) return candidate;
  } catch {
    // Not installed for this platform; fall through to the in-repo layout.
  }

  // 2) Sibling `npm/<pkg>/bin/<bin>` relative to this compiled module
  //    (dist/src/integrations/opa-binary.js -> ../../../npm). Only present in
  //    the monorepo, where the optional deps are not published/installed.
  const sibling = join(__dirname, "..", "..", "..", "npm", entry.pkg, "bin", entry.bin);
  if (isExecutable(sibling)) return sibling;

  return undefined;
}

function isExecutable(path: string): boolean {
  try {
    accessSync(path, process.platform === "win32" ? constants.F_OK : constants.X_OK);
    return true;
  } catch {
    return false;
  }
}
