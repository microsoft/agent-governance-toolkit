// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Installer tests at the same process boundary users hit: spawn
// `bin/agt-codex.mjs` as a subprocess with a fake `codex` CLI on PATH.
// The fake is env-driven so each test controls what `codex plugin list`
// reports and whether `codex plugin remove` succeeds — the failure paths a
// real Codex install can't produce on demand.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { chmod, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const binScript = join(here, "..", "bin", "agt-codex.mjs");

const INSTALLED_LINE = "agt-governance@agt  installed, enabled";

// The fake `codex`:
//   `plugin list`   — prints $FAKE_CODEX_LIST_LINE while $FAKE_CODEX_MARKER
//                     exists (or unconditionally when no marker is set); after
//                     removal it prints $FAKE_CODEX_LIST_LINE_GONE, so tests can
//                     model Codex's real habit of still listing a known
//                     marketplace plugin as `not installed`.
//   `plugin remove` — deletes the marker (a removal that works), or with
//                     FAKE_CODEX_REMOVE=fail exits 1 with stderr (one that doesn't).
//   everything else — exits 0.
const FAKE_CODEX_SOURCE = `#!/usr/bin/env node
const { existsSync, unlinkSync } = require("node:fs");
const args = process.argv.slice(2).join(" ");
const marker = process.env.FAKE_CODEX_MARKER;
if (args === "plugin list") {
  const installed = marker ? existsSync(marker) : true;
  const line = installed
    ? (process.env.FAKE_CODEX_LIST_LINE ?? "")
    : (process.env.FAKE_CODEX_LIST_LINE_GONE ?? "");
  process.stdout.write(line + "\\n");
  process.exit(0);
}
if (args.startsWith("plugin remove")) {
  if (process.env.FAKE_CODEX_REMOVE === "fail") {
    process.stderr.write("fake codex: remove blew up\\n");
    process.exit(1);
  }
  if (marker && existsSync(marker)) unlinkSync(marker);
  process.exit(0);
}
process.exit(0);
`;

function runInstaller(command, codexHome, shimDir, env) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [binScript, command, "--codex-home", codexHome], {
      env: { ...process.env, PATH: `${shimDir}${delimiter}${process.env.PATH}`, ...env },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => (stdout += d));
    child.stderr.on("data", (d) => (stderr += d));
    child.on("error", reject);
    child.on("close", (code) => resolve({ code, stdout, stderr }));
  });
}

async function withFakeCodex(run) {
  const root = await mkdtemp(join(tmpdir(), "agt-codex-installer-"));
  try {
    const shimDir = join(root, "bin");
    const codexHome = join(root, "home");
    const shimPath = join(shimDir, "codex");
    await mkdir(shimDir, { recursive: true });
    await writeFile(join(root, "marker"), "installed");
    await writeFile(shimPath, FAKE_CODEX_SOURCE);
    await chmod(shimPath, 0o755);
    return await run({ shimDir, codexHome, marker: join(root, "marker") });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

test("uninstall fails loudly when codex still lists the plugin as installed after remove", async () => {
  await withFakeCodex(async ({ shimDir, codexHome, marker }) => {
    const { code, stderr } = await runInstaller("uninstall", codexHome, shimDir, {
      FAKE_CODEX_LIST_LINE: INSTALLED_LINE,
      FAKE_CODEX_MARKER: marker,
      FAKE_CODEX_REMOVE: "fail",
    });

    assert.equal(code, 1, "a removal the read-back does not confirm must not exit 0");
    assert.match(stderr, /still reports as installed/);
    assert.match(stderr, /remove blew up/, "the remove command's stderr must be surfaced, not swallowed");
  });
});

test("uninstall reports removal only after read-back confirms the plugin is gone", async () => {
  await withFakeCodex(async ({ shimDir, codexHome, marker }) => {
    const { code, stdout } = await runInstaller("uninstall", codexHome, shimDir, {
      FAKE_CODEX_LIST_LINE: INSTALLED_LINE,
      FAKE_CODEX_MARKER: marker,
    });

    assert.equal(code, 0);
    assert.match(stdout, /Removed AGT governance plugin/);
    assert.equal(existsSync(marker), false, "the fake removal should have consumed the marker");
  });
});

test("uninstall treats a lingering `not installed` marketplace row as removed", async () => {
  await withFakeCodex(async ({ shimDir, codexHome, marker }) => {
    // Real `codex plugin list` keeps showing known marketplace plugins as
    // `<selector>  not installed` after removal; the read-back must not
    // mistake that row for a still-installed plugin and fail a good uninstall.
    const { code, stdout } = await runInstaller("uninstall", codexHome, shimDir, {
      FAKE_CODEX_LIST_LINE: INSTALLED_LINE,
      FAKE_CODEX_LIST_LINE_GONE: "agt-governance@agt  not installed  5.0.0  /elsewhere",
      FAKE_CODEX_MARKER: marker,
    });

    assert.equal(code, 0);
    assert.match(stdout, /Removed AGT governance plugin/);
  });
});

test("uninstall on a home without the plugin succeeds and says so", async () => {
  await withFakeCodex(async ({ shimDir, codexHome, marker }) => {
    await rm(marker, { force: true });
    const { code, stdout } = await runInstaller("uninstall", codexHome, shimDir, {
      FAKE_CODEX_LIST_LINE: INSTALLED_LINE,
      FAKE_CODEX_MARKER: marker,
      FAKE_CODEX_REMOVE: "fail",
    });

    assert.equal(code, 0, "removing an absent plugin is a no-op, not a failure");
    assert.match(stdout, /was not installed/);
  });
});

test("install's read-back rejects a similarly named plugin", async () => {
  await withFakeCodex(async ({ shimDir, codexHome }) => {
    // The anchored regex must not accept `other-agt-governance@agt` as ours.
    const { code, stderr } = await runInstaller("install", codexHome, shimDir, {
      FAKE_CODEX_LIST_LINE: `other-${INSTALLED_LINE}`,
    });

    assert.equal(code, 1);
    assert.match(stderr, /did not register as installed\+enabled/);
  });
});
