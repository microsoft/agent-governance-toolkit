import { accessSync, constants, statSync } from "node:fs";
import { createRequire } from "node:module";
import { delimiter, dirname, join } from "node:path";

/**
 * Disable resolution of the bundled per-platform `opa` binary (the
 * `agent-control-specification-opa-*` optional dependencies). When set to a
 * truthy value, only an explicit `opaPath`/`$ACS_OPA_PATH` or a system `opa`
 * on `PATH` is used. Useful for forcing a specific system opa or for tests.
 */
export const DISABLE_BUNDLED_OPA_ENV = "ACS_OPA_NO_BUNDLE";
export const OPA_PATH_ENV = "ACS_OPA_PATH";

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

/**
 * Prepend an explicit or bundled OPA location to PATH when one is available.
 *
 * This is intentionally non-throwing so generic construction surfaces can keep
 * the native runtime's own policy validation errors, such as "only Rego", while
 * still making the optional dependency work for zero-config Rego manifests.
 */
export function configureOpaPath(opaHint: string | undefined = process.env[OPA_PATH_ENV]): string | undefined {
  if (opaHint !== undefined && opaHint !== "") {
    const st = statSafe(opaHint);
    if (st === undefined) return undefined;
    const dir = st.isDirectory() ? opaHint : dirname(opaHint);
    prependToPath(dir);
  } else {
    const bundled = resolveBundledOpa();
    if (bundled !== undefined) prependToPath(dirname(bundled));
  }
  return findOnPath("opa");
}

/**
 * Ensure OPA is available and return its resolved path. Bootstrap surfaces use
 * this to fail early with an actionable error when neither a bundled nor host
 * binary can be found.
 */
export function ensureOpaResolvable(opaHint: string | undefined = process.env[OPA_PATH_ENV]): string {
  if (opaHint !== undefined && opaHint !== "") {
    const st = statSafe(opaHint);
    if (st === undefined) {
      throw new Error(`ACS: opa not found at the path provided (options.opaPath / $${OPA_PATH_ENV}): ${opaHint}`);
    }
  }

  const resolved = configureOpaPath(opaHint);
  if (resolved === undefined) {
    throw new Error(
      "ACS: the bundled policy dispatcher requires the 'opa' binary, which could not be located. " +
        "Normally a vendored copy ships via the agent-control-specification-opa-* optional dependency; " +
        "if that is unavailable for your platform, install Open Policy Agent " +
        "(https://www.openpolicyagent.org/docs/latest/#running-opa) and add it to PATH, " +
        `or set $${OPA_PATH_ENV} to the binary or its directory.`,
    );
  }
  return resolved;
}

function isExecutable(path: string): boolean {
  try {
    accessSync(path, process.platform === "win32" ? constants.F_OK : constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

function prependToPath(dir: string): void {
  const current = process.env.PATH ?? "";
  const entries = current.split(delimiter);
  if (entries.includes(dir)) return;
  process.env.PATH = current === "" ? dir : `${dir}${delimiter}${current}`;
}

function findOnPath(binary: string): string | undefined {
  const pathValue = process.env.PATH ?? "";
  const candidates = process.platform === "win32" ? [binary, `${binary}.exe`, `${binary}.cmd`] : [binary];
  for (const dir of pathValue.split(delimiter)) {
    if (dir === "") continue;
    for (const name of candidates) {
      const candidate = join(dir, name);
      if (isExecutable(candidate)) return candidate;
    }
  }
  return undefined;
}

function statSafe(path: string): ReturnType<typeof statSync> | undefined {
  try {
    return statSync(path);
  } catch {
    return undefined;
  }
}
