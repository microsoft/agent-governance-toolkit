#!/usr/bin/env node
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * @file Installer CLI for the AGT Codex governance plugin (`agt-codex`).
 *
 * This package ships as a Codex plugin: a `plugin.json` manifest plus
 * `hooks/hooks.json` whose commands reference `${PLUGIN_ROOT}`, which Codex
 * expands to the plugin's own install directory at runtime. Installation
 * therefore only registers the plugin with a Codex home (and seeds a default
 * policy) — there is no per-path substitution and no merge into the host
 * `hooks.json`, because Codex loads the plugin's own hooks and resolves the
 * root itself. This mirrors the Claude Code package, which relies on the host
 * to expand `${CLAUDE_PLUGIN_ROOT}` rather than baking absolute paths.
 *
 * Usage: `agt-codex <install|uninstall|status> [--codex-home <dir>]`
 */
import { existsSync } from "node:fs";
import { mkdir, readFile, writeFile, symlink, rm } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const PLUGIN_NAME = "agt-governance";
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
 * Directory Codex discovers this plugin from: `<codexHome>/plugins/<name>`.
 * @param {string} codexHome Target Codex home directory.
 * @returns {string} The plugin registration path.
 */
function pluginDir(codexHome) {
  return join(codexHome, "plugins", PLUGIN_NAME);
}

/**
 * Register the plugin with a Codex home and seed a default policy.
 *
 * Registration links this package into `<codexHome>/plugins/<name>`; Codex reads
 * the `plugin.json` manifest there and loads `hooks/hooks.json`, expanding
 * `${PLUGIN_ROOT}` to the linked directory. No hook substitution or host
 * `hooks.json` merge is performed. (The exact registration contract — link vs.
 * `codex plugin add` — should be confirmed against the target Codex version.)
 * @param {string} codexHome Target Codex home directory.
 * @returns {Promise<void>}
 */
async function install(codexHome) {
  const dest = pluginDir(codexHome);
  await mkdir(dirname(dest), { recursive: true });
  if (existsSync(dest)) {
    await rm(dest, { recursive: true, force: true });
  }
  // Junction (not "dir") so the link is created without elevation on Windows.
  await symlink(PACKAGE_ROOT, dest, "junction");

  const policyPath = join(codexHome, "agt", "policy.json");
  let seededPolicy = false;
  if (!existsSync(policyPath)) {
    const defaultPolicy = await readFile(join(PACKAGE_ROOT, "config", "default-policy.json"), "utf8");
    await mkdir(dirname(policyPath), { recursive: true });
    await writeFile(policyPath, defaultPolicy, "utf8");
    seededPolicy = true;
  }

  process.stdout.write(
    [
      `Registered AGT governance plugin at ${dest}`,
      seededPolicy
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
 * Unregister the plugin from a Codex home. The policy file and audit log are
 * preserved.
 * @param {string} codexHome Target Codex home directory.
 * @returns {Promise<void>}
 */
async function uninstall(codexHome) {
  const dest = pluginDir(codexHome);
  if (!existsSync(dest)) {
    process.stdout.write(`No AGT plugin registered at ${dest}; nothing to uninstall.\n`);
    return;
  }
  await rm(dest, { recursive: true, force: true });
  process.stdout.write(
    [
      `Unregistered AGT governance plugin from ${dest}`,
      `Policy and audit files under ${join(codexHome, "agt")} were kept; delete them manually if desired.`,
      "",
    ].join("\n"),
  );
}

/**
 * Report whether the plugin is registered for a Codex home, the policy path,
 * and the audit-log entry count and chain validity.
 * @param {string} codexHome Target Codex home directory.
 * @returns {Promise<void>}
 */
async function status(codexHome) {
  const dest = pluginDir(codexHome);
  const policyPath = join(codexHome, "agt", "policy.json");
  const auditPath = join(codexHome, "agt", "audit-log.json");
  const { getAuditStatus } = await import("../lib/audit.mjs");
  const audit = await getAuditStatus(auditPath);

  process.stdout.write(
    [
      `Codex home:      ${codexHome}`,
      `AGT plugin:      ${existsSync(dest) ? `registered (${dest})` : "not registered"}`,
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
