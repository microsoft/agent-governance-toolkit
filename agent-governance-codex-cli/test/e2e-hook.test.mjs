// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// End-to-end test at the process boundary Codex actually uses: spawn the hook
// script exactly as `codex` would (JSON on stdin, JSON on stdout, exit code),
// using fixtures shaped like real Codex PreToolUse payloads. This is the
// headless, deterministic form of the live denial demo — it needs no model,
// no network, and no hook-trust grant, so it runs in CI.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const hookScript = join(here, "..", "hooks", "pre-tool-use.mjs");

function runHook(payload, env) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [hookScript], {
      env: { ...process.env, ...env },
      stdio: ["pipe", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => (stdout += d));
    child.stderr.on("data", (d) => (stderr += d));
    child.on("error", reject);
    child.on("close", (code) => resolve({ code, stdout, stderr }));
    child.stdin.write(JSON.stringify(payload));
    child.stdin.end();
  });
}

async function withAuditHome(run) {
  const home = await mkdtemp(join(tmpdir(), "agt-codex-e2e-"));
  try {
    return await run({
      CODEX_HOME: home,
      AGT_CODEX_AUDIT_PATH: join(home, "agt", "audit-log.json"),
    });
  } finally {
    await rm(home, { recursive: true, force: true });
  }
}

const loadFixture = async (name) =>
  JSON.parse(await readFile(join(here, "fixtures", name), "utf8"));

test("PreToolUse denies a secret-file read and records the decision", async () => {
  await withAuditHome(async (env) => {
    const payload = await loadFixture("pre-tool-use.deny-secret-read.json");
    const { code, stdout } = await runHook(payload, env);

    assert.equal(code, 0, "a policy deny is a successful hook run, not a hook crash");
    const out = JSON.parse(stdout);
    assert.equal(out.hookSpecificOutput.hookEventName, "PreToolUse");
    assert.equal(out.hookSpecificOutput.permissionDecision, "deny");
    assert.match(out.hookSpecificOutput.permissionDecisionReason, /credential|secret/i);

    const audit = JSON.parse(await readFile(env.AGT_CODEX_AUDIT_PATH, "utf8"));
    assert.equal(audit.at(-1).decision, "deny");
  });
});

test("PreToolUse allows a plain file read with no deny decision", async () => {
  await withAuditHome(async (env) => {
    const payload = await loadFixture("pre-tool-use.allow-read.json");
    const { code, stdout } = await runHook(payload, env);

    assert.equal(code, 0);
    const out = JSON.parse(stdout);
    assert.notEqual(out.hookSpecificOutput?.permissionDecision, "deny");
  });
});

test("malformed hook input fails closed with a deny exit code", async () => {
  await withAuditHome(async (env) => {
    // Not valid JSON — the shim must exit 2 (deny) rather than throw uncaught.
    const child = spawn(process.execPath, [hookScript], {
      env: { ...process.env, ...env },
      stdio: ["pipe", "pipe", "pipe"],
    });
    child.stdin.write("this is not json");
    child.stdin.end();
    const code = await new Promise((resolve) => child.on("close", resolve));
    assert.equal(code, 2, "invalid input must fail closed (exit 2), not fail open");
  });
});
