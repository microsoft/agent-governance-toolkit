#!/usr/bin/env node
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * @file Installer CLI for the AGT Codex governance hooks (`agt-codex`).
 *
 * Codex discovers hooks from `<CODEX_HOME>/hooks.json`, so installation means
 * merging AGT's hook entries into that file rather than copying a plugin
 * bundle. Entries owned by AGT are identified by their `statusMessage` prefix,
 * so install stays idempotent and uninstall never touches user-defined hooks.
 *
 * Usage: `agt-codex <install|uninstall|status> [--codex-home <dir>]`
 */
import { existsSync } from "node:fs";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const AGT_MARKER = "AGT governance";
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
 * Read and parse a JSON file.
 * @param {string} path File path.
 * @param {unknown} fallback Value returned when the file does not exist.
 * @returns {Promise<unknown>} Parsed JSON, or `fallback`.
 */
async function loadJson(path, fallback) {
  if (!existsSync(path)) {
    return fallback;
  }
  return JSON.parse(await readFile(path, "utf8"));
}

/**
 * Write a value as pretty-printed JSON, creating parent directories as needed.
 * @param {string} path Destination file path.
 * @param {unknown} value JSON-serializable value.
 * @returns {Promise<void>}
 */
async function writeJson(path, value) {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

/**
 * Whether a hook entry is AGT-owned (its `statusMessage` carries the AGT marker).
 * @param {{statusMessage?: string}} hook A single hook command entry.
 * @returns {boolean}
 */
function isAgtHook(hook) {
  return typeof hook?.statusMessage === "string" && hook.statusMessage.startsWith(AGT_MARKER);
}

/**
 * Return a copy of a Codex hooks config with every AGT-owned entry removed,
 * preserving all user-defined hooks and empty-event pruning.
 * @param {{hooks?: Record<string, Array<{hooks?: object[]}>>}} hooksConfig Parsed hooks.json.
 * @returns {object} The config without AGT-owned entries.
 */
function withoutAgtEntries(hooksConfig) {
  const events = hooksConfig.hooks ?? {};
  const cleaned = {};
  for (const [event, matcherGroups] of Object.entries(events)) {
    const keptGroups = [];
    for (const group of matcherGroups) {
      const keptHooks = (group.hooks ?? []).filter((hook) => !isAgtHook(hook));
      if (keptHooks.length > 0) {
        keptGroups.push({ ...group, hooks: keptHooks });
      }
    }
    if (keptGroups.length > 0) {
      cleaned[event] = keptGroups;
    }
  }
  return { ...hooksConfig, hooks: cleaned };
}

/**
 * Load this package's hook template and resolve `${AGT_PACKAGE_ROOT}` to the
 * installed package path so the written commands use absolute paths.
 * @returns {Promise<Record<string, object[]>>} The resolved per-event hook entries.
 */
async function loadAgtHookEntries() {
  const templatePath = join(PACKAGE_ROOT, "hooks", "hooks.json");
  const template = await readFile(templatePath, "utf8");
  const rendered = template.replaceAll("${AGT_PACKAGE_ROOT}", PACKAGE_ROOT);
  return JSON.parse(rendered).hooks;
}

/**
 * Merge AGT governance hooks into `<codexHome>/hooks.json` (idempotently, by
 * first stripping any prior AGT entries) and seed a default policy if none
 * exists. Existing user hooks and any existing policy are left untouched.
 * @param {string} codexHome Target Codex home directory.
 * @returns {Promise<void>}
 */
async function install(codexHome) {
  const hooksPath = join(codexHome, "hooks.json");
  const existing = await loadJson(hooksPath, { hooks: {} });
  const cleaned = withoutAgtEntries(existing);
  const agtHooks = await loadAgtHookEntries();

  for (const [event, matcherGroups] of Object.entries(agtHooks)) {
    cleaned.hooks[event] = [...(cleaned.hooks[event] ?? []), ...matcherGroups];
  }
  await writeJson(hooksPath, cleaned);

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
      `Installed AGT governance hooks into ${hooksPath}`,
      seededPolicy
        ? `Seeded default policy at ${policyPath}`
        : `Kept existing policy at ${policyPath}`,
      "",
      "Next step: Codex requires a one-time trust review before hooks run.",
      "Open Codex against this home and run /hooks to review and trust the AGT hooks.",
      "",
    ].join("\n"),
  );
}

/**
 * Remove only AGT-owned hook entries from `<codexHome>/hooks.json`. User-defined
 * hooks, the policy file, and the audit log are all preserved.
 * @param {string} codexHome Target Codex home directory.
 * @returns {Promise<void>}
 */
async function uninstall(codexHome) {
  const hooksPath = join(codexHome, "hooks.json");
  if (!existsSync(hooksPath)) {
    process.stdout.write(`No hooks.json at ${hooksPath}; nothing to uninstall.\n`);
    return;
  }
  const cleaned = withoutAgtEntries(await loadJson(hooksPath, { hooks: {} }));
  await writeJson(hooksPath, cleaned);
  process.stdout.write(
    [
      `Removed AGT governance hooks from ${hooksPath}`,
      `Policy and audit files under ${join(codexHome, "agt")} were kept; delete them manually if desired.`,
      "",
    ].join("\n"),
  );
}

/**
 * Print which AGT hooks are installed for a Codex home, the policy path, and the
 * audit-log entry count and chain validity.
 * @param {string} codexHome Target Codex home directory.
 * @returns {Promise<void>}
 */
async function status(codexHome) {
  const hooksPath = join(codexHome, "hooks.json");
  const config = await loadJson(hooksPath, { hooks: {} });
  const installedEvents = Object.entries(config.hooks ?? {})
    .filter(([, groups]) => groups.some((group) => (group.hooks ?? []).some(isAgtHook)))
    .map(([event]) => event);

  const policyPath = join(codexHome, "agt", "policy.json");
  const auditPath = join(codexHome, "agt", "audit-log.json");
  const { getAuditStatus } = await import("../lib/audit.mjs");
  const audit = await getAuditStatus(auditPath);

  process.stdout.write(
    [
      `Codex home:      ${codexHome}`,
      `AGT hooks:       ${installedEvents.length > 0 ? installedEvents.join(", ") : "not installed"}`,
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
