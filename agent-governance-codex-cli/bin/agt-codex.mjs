#!/usr/bin/env node
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * @file Installer CLI for the AGT Codex governance plugin (`agt-codex`).
 *
 * This package ships as a Codex plugin: `.codex-plugin/plugin.json` (the plugin
 * manifest) plus `hooks/hooks.json`, whose commands reference `${PLUGIN_ROOT}` —
 * which Codex expands to the plugin's install directory at runtime. The package
 * is also its own single-plugin marketplace (`.agents/plugins/marketplace.json`,
 * `source: "."`), so installation registers it with Codex's plugin system via
 * `codex plugin marketplace add` + `codex plugin add`, and Codex then discovers
 * the plugin and loads its hooks. There is no editing of the host `hooks.json`
 * and no path substitution — Codex resolves `${PLUGIN_ROOT}` itself.
 *
 * Usage: `agt-codex <install|uninstall|status> [--codex-home <dir>]`
 */
import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const PLUGIN_NAME = "agt-governance";
// MARKETPLACE_NAME must match the "name" in .agents/plugins/marketplace.json.
const MARKETPLACE_NAME = "agt";
const PLUGIN_SELECTOR = `${PLUGIN_NAME}@${MARKETPLACE_NAME}`;
const PACKAGE_ROOT = dirname(dirname(fileURLToPath(import.meta.url)));

/**
 * Resolve the target Codex home directory.
 * @param {string[]} args CLI args after the subcommand.
 * @returns {string} The `--codex-home` value, else `$CODEX_HOME`, else `~/.codex`.
 */
function resolveCodexHome(args) {
  const flagIndex = args.indexOf("--codex-home");
  if (flagIndex !== -1) {
    const value = args[flagIndex + 1];
    if (!value) {
      throw new Error("--codex-home requires a directory argument.");
    }
    return value;
  }
  return process.env.CODEX_HOME ?? join(homedir(), ".codex");
}

/**
 * Run a `codex` subcommand against a target home. Never throws on a non-zero
 * exit (an "already registered" re-add is not fatal); the caller decides how to
 * treat failure. Throws only if the `codex` CLI itself is missing.
 * @param {string[]} args
 * @param {string} codexHome
 * @returns {{ok: boolean, stdout: string, stderr: string}}
 */
function codex(args, codexHome) {
  try {
    const stdout = execFileSync("codex", args, {
      env: { ...process.env, CODEX_HOME: codexHome },
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });
    return { ok: true, stdout, stderr: "" };
  } catch (error) {
    if (error?.code === "ENOENT") {
      throw new Error("`codex` CLI not found on PATH. Install the Codex CLI, then re-run.");
    }
    return {
      ok: false,
      stdout: error?.stdout?.toString() ?? "",
      stderr: error?.stderr?.toString() ?? String(error?.message ?? error),
    };
  }
}

/**
 * Read back the plugin's state from `codex plugin list`. Install and uninstall
 * both gate on this read-back rather than on subcommand exit codes, because
 * `codex plugin add`/`remove` can fail (or no-op) while still exiting zero.
 * The `^`-anchored multiline match keeps a similarly named plugin (e.g.
 * `other-agt-governance@agt`) from satisfying the check, and `installed`
 * requires the status column to start with `installed` because Codex also
 * lists known-but-uninstalled marketplace plugins (`<selector>  not installed`).
 * `row` is the plugin's own list line (null when absent) — `status` reports it
 * verbatim; an unanchored substring search could hit the marketplace path
 * header that `codex plugin list` prints above the table.
 * @returns {{installed: boolean, enabled: boolean, row: string | null, listOutput: string}}
 */
function readPluginState(codexHome) {
  const list = codex(["plugin", "list"], codexHome);
  const selector = PLUGIN_SELECTOR.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return {
    installed: new RegExp(`^${selector}\\s+installed\\b`, "m").test(list.stdout),
    enabled: new RegExp(`^${selector}\\s+installed,\\s*enabled\\b`, "m").test(list.stdout),
    row: list.stdout.match(new RegExp(`^${selector}(?=\\s|$).*$`, "m"))?.[0].trim() ?? null,
    listOutput: list.stdout,
  };
}

/** Seed the editable default policy the hooks enforce, if none exists yet. */
async function seedPolicy(codexHome) {
  const policyPath = join(codexHome, "agt", "policy.json");
  if (existsSync(policyPath)) {
    return { seeded: false, policyPath };
  }
  const defaultPolicy = await readFile(join(PACKAGE_ROOT, "config", "default-policy.json"), "utf8");
  await mkdir(dirname(policyPath), { recursive: true });
  await writeFile(policyPath, defaultPolicy, "utf8");
  return { seeded: true, policyPath };
}

/**
 * Register this package as a Codex plugin marketplace, install + enable the
 * plugin, and seed a default policy. Fails loudly (non-zero exit) if Codex did
 * not actually enable the plugin, so install never reports success on a no-op.
 * @param {string} codexHome Target Codex home directory.
 * @returns {Promise<void>}
 */
async function install(codexHome) {
  // Register the package as a marketplace, then install the plugin from it.
  // Both are safe to re-run; correctness is confirmed by the list check below.
  codex(["plugin", "marketplace", "add", PACKAGE_ROOT], codexHome);
  const add = codex(["plugin", "add", PLUGIN_SELECTOR], codexHome);

  const { enabled, listOutput } = readPluginState(codexHome);
  if (!enabled) {
    throw new Error(
      `plugin did not register as installed+enabled.\n` +
        `\`codex plugin add\` output:\n${add.stderr || add.stdout || "(none)"}\n` +
        `\`codex plugin list\`:\n${listOutput || "(empty)"}`,
    );
  }

  const { seeded, policyPath } = await seedPolicy(codexHome);
  process.stdout.write(
    [
      `Installed AGT governance plugin (${PLUGIN_SELECTOR}) — installed, enabled.`,
      seeded
        ? `Seeded default policy at ${policyPath}`
        : `Kept existing policy at ${policyPath}`,
      "",
      "Next step: Codex requires a one-time trust review before plugin hooks run.",
      "Open Codex against this home and run /plugins to review and trust the AGT plugin.",
      "",
    ].join("\n"),
  );
}

/**
 * Remove the plugin and its marketplace registration. Policy and audit files
 * are preserved. Mirrors install's read-back gate: uninstall fails loudly
 * (non-zero exit) if Codex still lists the plugin afterwards, so a failed
 * removal is never reported as success.
 * @param {string} codexHome Target Codex home directory.
 * @returns {Promise<void>}
 */
async function uninstall(codexHome) {
  // Snapshot before removing so the success message can distinguish "removed
  // it" from "was never installed" — the remove command's exit code cannot,
  // because it also fails when the plugin is simply absent.
  const before = readPluginState(codexHome);
  const removed = codex(["plugin", "remove", PLUGIN_SELECTOR], codexHome);
  codex(["plugin", "marketplace", "remove", MARKETPLACE_NAME], codexHome);

  const after = readPluginState(codexHome);
  if (after.installed) {
    throw new Error(
      `plugin still reports as installed after removal.\n` +
        `\`codex plugin remove\` output:\n${removed.stderr || removed.stdout || "(none)"}\n` +
        `\`codex plugin list\`:\n${after.listOutput || "(empty)"}`,
    );
  }

  process.stdout.write(
    [
      before.installed
        ? `Removed AGT governance plugin (${PLUGIN_SELECTOR}) and its marketplace.`
        : `AGT plugin was not installed; removed any marketplace registration.`,
      `Policy and audit files under ${join(codexHome, "agt")} were kept; delete them manually if desired.`,
      "",
    ].join("\n"),
  );
}

/**
 * Report whether the plugin is installed/enabled, the policy path, and the
 * audit-log entry count and chain validity.
 * @param {string} codexHome Target Codex home directory.
 * @returns {Promise<void>}
 */
async function status(codexHome) {
  const line = readPluginState(codexHome).row ?? "not installed";
  const policyPath = join(codexHome, "agt", "policy.json");
  const auditPath = join(codexHome, "agt", "audit-log.json");
  const { getAuditStatus } = await import("../lib/audit.mjs");
  const audit = await getAuditStatus(auditPath);

  process.stdout.write(
    [
      `Codex home:      ${codexHome}`,
      `AGT plugin:      ${line}`,
      `Policy file:     ${existsSync(policyPath) ? policyPath : "missing (default policy will apply)"}`,
      `Audit log:       ${audit.count} entries, chain ${audit.valid ? "valid" : `INVALID (${audit.error})`}`,
      "",
    ].join("\n"),
  );
}

const [command, ...rest] = process.argv.slice(2);
try {
  const codexHome = resolveCodexHome(rest);
  if (command === "install") {
    await install(codexHome);
  } else if (command === "uninstall") {
    await uninstall(codexHome);
  } else if (command === "status") {
    await status(codexHome);
  } else {
    process.stdout.write("Usage: agt-codex <install|uninstall|status> [--codex-home <dir>]\n");
    process.exit(command ? 1 : 0);
  }
} catch (error) {
  process.stderr.write(`agt-codex ${command ?? ""} failed: ${error instanceof Error ? error.message : String(error)}\n`);
  process.exit(1);
}
