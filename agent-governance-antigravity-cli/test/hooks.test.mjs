// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";

import { installPackage } from "../lib/cli.mjs";

const PACKAGE_ROOT = dirname(fileURLToPath(new URL("../package.json", import.meta.url)));

test("before-tool fails closed with an Antigravity system block when hook bootstrap breaks", async () => {
  const root = await mkdtemp(join(tmpdir(), "agt-antigravity-hook-block-"));
  const antigravityHome = join(root, ".antigravity");

  await installPackage({ antigravityHome, packageRoot: PACKAGE_ROOT });
  const extensionRoot = join(antigravityHome, "extensions", "agt-global-policy");
  await rm(
    join(
      extensionRoot,
      "vendor",
      "agent-governance-sdk",
      "node_modules",
      "@microsoft",
      "agent-governance-sdk",
    ),
    { recursive: true, force: true },
  );

  const hookResult = await runNodeScript(
    join(extensionRoot, "hooks", "before-tool.mjs"),
    {
      cwd: root,
      session_id: "session-1",
      tool_input: { command: "git status" },
      tool_name: "run_shell_command",
    },
  );

  assert.equal(hookResult.code, 2);
  assert.equal(hookResult.stdout, "");
  assert.match(hookResult.stderr, /failed closed/i);

  await rm(root, { recursive: true, force: true });
});

test("audit history survives reloads of the installed extension runtime", async () => {
  const root = await mkdtemp(join(tmpdir(), "agt-antigravity-audit-history-"));
  const antigravityHome = join(root, ".antigravity");

  await installPackage({ antigravityHome, packageRoot: PACKAGE_ROOT });
  const extensionRoot = join(antigravityHome, "extensions", "agt-global-policy");
  const policyModule = await import(pathToFileURL(join(extensionRoot, "lib", "policy.mjs")).href);
  const previousPolicyEnv = process.env[policyModule.USER_POLICY_ENV];
  const previousAuditEnv = process.env[policyModule.AUDIT_PATH_ENV];

  process.env[policyModule.USER_POLICY_ENV] = join(antigravityHome, "agt", "policy.json");
  process.env[policyModule.AUDIT_PATH_ENV] = join(antigravityHome, "agt", "audit-log.json");

  try {
    const firstState = await policyModule.loadPolicy({
      extensionRoot,
    });
    await policyModule.evaluatePreToolUse(
      firstState,
      {
        toolArgs: { file_path: join(root, "README.md") },
        toolName: "read_file",
      },
      { sessionId: "session-1" },
    );

    const secondState = await policyModule.loadPolicy({
      extensionRoot,
    });
    await policyModule.evaluatePreToolUse(
      secondState,
      {
        toolArgs: { file_path: join(root, "README.md") },
        toolName: "read_file",
      },
      { sessionId: "session-2" },
    );

    const reloadedState = await policyModule.loadPolicy({
      extensionRoot,
    });
    const status = policyModule.getPolicyStatus(reloadedState);
    assert.equal(status.auditEntries, 2);
    assert.equal(status.auditValid, true);
    assert.equal(JSON.parse(await readFile(join(antigravityHome, "agt", "audit-log.json"), "utf8")).length, 2);
  } finally {
    if (previousPolicyEnv === undefined) {
      delete process.env[policyModule.USER_POLICY_ENV];
    } else {
      process.env[policyModule.USER_POLICY_ENV] = previousPolicyEnv;
    }
    if (previousAuditEnv === undefined) {
      delete process.env[policyModule.AUDIT_PATH_ENV];
    } else {
      process.env[policyModule.AUDIT_PATH_ENV] = previousAuditEnv;
    }
  }

  await rm(root, { recursive: true, force: true });
});

async function runNodeScript(scriptPath, input) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [scriptPath], {
      stdio: ["pipe", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";

    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
      stdout += chunk;
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
    });
    child.on("error", reject);
    child.on("close", (code) => {
      resolve({ code, stderr, stdout });
    });

    child.stdin.end(`${JSON.stringify(input)}\n`);
  });
}
