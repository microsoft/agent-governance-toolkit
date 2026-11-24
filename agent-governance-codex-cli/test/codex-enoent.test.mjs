// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const PACKAGE_ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const CLI = join(PACKAGE_ROOT, "bin", "agt-codex.mjs");

// On Windows the CLI spawns through ComSpec, so a missing ComSpec is the
// exact analogue of a missing `codex` shim interpreter on POSIX.
test("ENOENT reports the executable that could not be started", { skip: process.platform !== "win32" }, () => {
  const missing = join(tmpdir(), "agt-codex-no-such-comspec", "cmd.exe");
  const result = spawnSync(
    process.execPath,
    [CLI, "status", "--codex-home", mkdtempSync(join(tmpdir(), "agt-codex-home-"))],
    {
      env: { ...process.env, ComSpec: missing },
      encoding: "utf8",
    },
  );
  assert.equal(result.status, 1);
  assert.match(result.stderr, /could not be started/);
  assert.ok(result.stderr.includes(missing), result.stderr);
  assert.match(result.stderr, /caused by \(ENOENT\)/, result.stderr);
});
