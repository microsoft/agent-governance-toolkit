import { statSync } from "node:fs";
import { dirname, isAbsolute, join, parse, resolve } from "node:path";

import { AgentControl, PerfTelemetry } from "../index";
import type { ApprovalResolver } from "../index";
import { createGhcpExtension, GhcpExtension, GhcpHooksOptions } from "./ghcp";
import { ensureOpaResolvable, OPA_PATH_ENV } from "./opa-binary";

const DEFAULT_MANIFEST_ENV = "ACS_MANIFEST";
const DEFAULT_OPA_ENV = OPA_PATH_ENV;
// Deliberately ACS-specific: a guardrail extension must never silently pick up
// an unrelated `manifest.yaml` from an ancestor directory. Adopters who want a
// generic name can pass `options.manifestNames` or `options.manifestPath`.
const DEFAULT_MANIFEST_NAMES = [
  "acs.manifest.yaml",
  "acs.manifest.yml",
  "acs.yaml",
  "acs.yml",
  ".acs/manifest.yaml",
  ".acs/manifest.yml",
  ".github/acs/manifest.yaml",
  ".github/acs/manifest.yml",
];

export interface BundledGhcpOptions {
  /** Explicit manifest path. Wins over the env var and conventional search. */
  manifestPath?: string;
  /** Env var to read the manifest path from (default `ACS_MANIFEST`). */
  manifestEnv?: string;
  /** Directory to begin the upward conventional-name search (default `process.cwd()`). */
  searchFrom?: string;
  /** Conventional manifest filenames searched for, relative to each ancestor dir. */
  manifestNames?: string[];
  /**
   * Path to the `opa` binary or the directory containing it. Falls back to the
   * `ACS_OPA_PATH` env var, then to whatever `opa` resolves to on `PATH`. The
   * bundled policy dispatcher shells out to `opa`, and a forked extension
   * process does not inherit an interactive shell `PATH`, so this is prepended
   * to `process.env.PATH` for the runtime's child processes.
   */
  opaPath?: string;
  /**
   * Load environment variables from `.env` file(s) before constructing the
   * runtime (annotators read provider keys by name). Default `false` — the host
   * is expected to provide credentials. `true` loads `.env` next to the
   * manifest and in the cwd; a string or array loads exactly those files.
   */
  loadEnv?: boolean | string | string[];
  /** Forwarded to `AgentControl.fromPath`. */
  approvalResolver?: ApprovalResolver;
  /** Forwarded to `AgentControl.fromPath`. */
  perfTelemetry?: PerfTelemetry;
  /** Forwarded to `createGhcpExtension` (governed tools, logger, escalate, mode, snapshot). */
  hooks?: Omit<GhcpHooksOptions, "approvalResolver">;
}

export interface BundledGhcpResult {
  extension: GhcpExtension;
  control: AgentControl;
  manifestPath: string;
  opaPath: string;
}

/**
 * One-call setup for a GitHub Copilot CLI guardrail extension: discover the
 * ACS manifest, make `opa` resolvable, optionally load credentials, build the
 * runtime, and return a wired extension. Adopters drop in a manifest + policy
 * and write a thin extension that forwards these hooks — no glue.
 */
export function createBundledGhcpExtension(options: BundledGhcpOptions = {}): BundledGhcpResult {
  const manifestPath = resolveManifestPath(options);
  const opaPath = ensureOpaResolvable(options.opaPath ?? process.env[DEFAULT_OPA_ENV]);
  maybeLoadEnv(options.loadEnv ?? false, manifestPath);

  const control = AgentControl.fromPath(
    manifestPath,
    undefined,
    undefined,
    options.approvalResolver,
    options.perfTelemetry ?? PerfTelemetry.Off,
  );

  const hookOptions: GhcpHooksOptions = { ...(options.hooks ?? {}) };
  if (options.approvalResolver !== undefined) hookOptions.approvalResolver = options.approvalResolver;
  const extension = createGhcpExtension(control, hookOptions);

  return { extension, control, manifestPath, opaPath };
}

function resolveManifestPath(options: BundledGhcpOptions): string {
  const explicit = options.manifestPath;
  if (explicit !== undefined) {
    const abs = isAbsolute(explicit) ? explicit : resolve(process.cwd(), explicit);
    if (!isFile(abs)) {
      throw new Error(`ACS: manifest not found at the path provided in options.manifestPath: ${abs}`);
    }
    return abs;
  }

  const envName = options.manifestEnv ?? DEFAULT_MANIFEST_ENV;
  const fromEnv = process.env[envName];
  if (fromEnv !== undefined && fromEnv !== "") {
    const abs = isAbsolute(fromEnv) ? fromEnv : resolve(process.cwd(), fromEnv);
    if (!isFile(abs)) {
      throw new Error(`ACS: manifest not found at the path in $${envName}: ${abs}`);
    }
    return abs;
  }

  const names = options.manifestNames ?? DEFAULT_MANIFEST_NAMES;
  const found = searchUpward(resolve(options.searchFrom ?? process.cwd()), names);
  if (found !== undefined) return found;

  throw new Error(
    `ACS: could not locate a manifest. Set $${envName} to its path, pass options.manifestPath, ` +
      `or place one of [${names.join(", ")}] in the working directory or an ancestor.`,
  );
}

function searchUpward(startDir: string, names: string[]): string | undefined {
  let dir = startDir;
  const root = parse(dir).root;
  for (;;) {
    for (const name of names) {
      const candidate = join(dir, name);
      if (isFile(candidate)) return candidate;
    }
    if (dir === root) return undefined;
    const parent = dirname(dir);
    if (parent === dir) return undefined;
    dir = parent;
  }
}

function maybeLoadEnv(loadEnv: boolean | string | string[], manifestPath: string): void {
  if (loadEnv === false) return;
  const loader = (process as unknown as { loadEnvFile?: (path: string) => void }).loadEnvFile;
  if (typeof loader !== "function") {
    throw new Error("ACS: options.loadEnv requires Node >= 20.12 (process.loadEnvFile). Provide credentials via the host environment instead.");
  }
  const files =
    loadEnv === true
      ? [resolve(dirname(manifestPath), ".env"), resolve(process.cwd(), ".env")]
      : Array.isArray(loadEnv)
        ? loadEnv
        : [loadEnv];
  const seen = new Set<string>();
  for (const file of files) {
    const abs = isAbsolute(file) ? file : resolve(process.cwd(), file);
    if (seen.has(abs) || !isFile(abs)) continue;
    seen.add(abs);
    loader.call(process, abs);
  }
}

function isFile(path: string): boolean {
  const st = statSafe(path);
  return st !== undefined && st.isFile();
}

function statSafe(path: string): ReturnType<typeof statSync> | undefined {
  try {
    return statSync(path);
  } catch {
    return undefined;
  }
}
