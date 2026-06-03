// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawn } from "node:child_process";
import test from "node:test";
import { fileURLToPath } from "node:url";

const scriptPath = fileURLToPath(
  new URL("../../scripts/sync-claude-marketplace-version.mjs", import.meta.url),
);

async function runScript(fixtureRoot, args = []) {
  return new Promise((resolve) => {
    const proc = spawn(process.execPath, [scriptPath, ...args], {
      env: {
        ...process.env,
        AGT_TEST_REPO_ROOT: fixtureRoot,
      },
      stdio: "pipe",
    });
    let stdout = "";
    let stderr = "";
    proc.stdout.on("data", (chunk) => { stdout += chunk; });
    proc.stderr.on("data", (chunk) => { stderr += chunk; });
    proc.on("close", (code) => resolve({ code, stdout, stderr }));
  });
}

async function buildFixture(root, { version, pluginVersion, marketplaceVersion, omitPlugin = false }) {
  const claudePlugin = join(root, "agent-governance-claude-code", ".claude-plugin");
  const marketplaceDir = join(root, ".claude-plugin");

  await mkdir(claudePlugin, { recursive: true });
  await mkdir(marketplaceDir, { recursive: true });

  await writeFile(
    join(root, "agent-governance-claude-code", "package.json"),
    JSON.stringify({ name: "agent-governance-toolkit", version }, null, 2) + "\n",
  );

  await writeFile(
    join(claudePlugin, "plugin.json"),
    JSON.stringify({ name: "agt-governance", version: pluginVersion }, null, 2) + "\n",
  );

  const plugins = omitPlugin
    ? []
    : [{ name: "agt-governance", version: marketplaceVersion }];

  await writeFile(
    join(marketplaceDir, "marketplace.json"),
    JSON.stringify({ version: marketplaceVersion, plugins }, null, 2) + "\n",
  );
}

test("check mode exits 0 when all versions match", async () => {
  const root = await mkdtemp(join(tmpdir(), "agt-mkt-ok-"));
  try {
    await buildFixture(root, {
      version: "1.2.3",
      pluginVersion: "1.2.3",
      marketplaceVersion: "1.2.3",
    });
    const { code, stdout } = await runScript(root, ["--check"]);
    assert.equal(code, 0, `expected exit 0, got ${code}`);
    assert.match(stdout, /OK/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("check mode exits non-zero when marketplace.json version drifts", async () => {
  const root = await mkdtemp(join(tmpdir(), "agt-mkt-drift-"));
  try {
    await buildFixture(root, {
      version: "1.2.3",
      pluginVersion: "1.2.3",
      marketplaceVersion: "1.0.0",
    });
    const { code, stderr } = await runScript(root, ["--check"]);
    assert.notEqual(code, 0, "expected non-zero exit when marketplace version drifts");
    assert.match(stderr, /out of sync/i);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("check mode exits non-zero when plugin entry is missing from marketplace.json", async () => {
  const root = await mkdtemp(join(tmpdir(), "agt-mkt-missing-"));
  try {
    await buildFixture(root, {
      version: "1.2.3",
      pluginVersion: "1.2.3",
      marketplaceVersion: "1.2.3",
      omitPlugin: true,
    });
    const { code, stderr } = await runScript(root, ["--check"]);
    assert.notEqual(code, 0, "expected non-zero exit when plugin entry is absent");
    assert.match(stderr, /missing plugin entry/i);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("sync mode writes updated versions without check flag", async () => {
  const root = await mkdtemp(join(tmpdir(), "agt-mkt-sync-"));
  try {
    await buildFixture(root, {
      version: "2.0.0",
      pluginVersion: "1.0.0",
      marketplaceVersion: "1.0.0",
    });
    const { code } = await runScript(root, []);
    assert.equal(code, 0, `sync mode should exit 0, got ${code}`);

    const { readFile } = await import("node:fs/promises");
    const plugin = JSON.parse(await readFile(join(root, "agent-governance-claude-code", ".claude-plugin", "plugin.json"), "utf8"));
    const marketplace = JSON.parse(await readFile(join(root, ".claude-plugin", "marketplace.json"), "utf8"));

    assert.equal(plugin.version, "2.0.0");
    assert.equal(marketplace.version, "2.0.0");
    assert.equal(marketplace.plugins[0].version, "2.0.0");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
