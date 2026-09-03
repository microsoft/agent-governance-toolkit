// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Codex adapter: control flow is identical to the Claude Code shim because
// Codex adopted the same hook payload and response schema. The only
// host-specific concern is where AGT state lives — Codex sessions anchor to
// CODEX_HOME (default ~/.codex) rather than Claude Code's ~/.claude, so we
// default the policy and audit paths there unless the caller has overridden them.
import { homedir } from "node:os";
import { join } from "node:path";
import { readHookInput, writeHookOutput } from "./common.mjs";
import { evaluatePreToolUse, loadPolicy } from "../lib/policy.mjs";

const codexHome = process.env.CODEX_HOME ?? join(homedir(), ".codex");
process.env.AGT_CODEX_POLICY_PATH ??= join(codexHome, "agt", "policy.json");
process.env.AGT_CODEX_AUDIT_PATH ??= join(codexHome, "agt", "audit-log.json");

try {
  const input = await readHookInput();
  const state = await loadPolicy();
  writeHookOutput(await evaluatePreToolUse(state, input));
} catch (error) {
  process.stderr.write(
    `AGT governance denied the tool call because policy evaluation failed closed: ${error instanceof Error ? error.message : String(error)}\n`,
  );
  process.exit(2);
}
