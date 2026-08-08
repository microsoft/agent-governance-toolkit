// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Codex adapter: see pre-tool-use.mjs for why only the state paths differ
// from the Claude Code shim.
import { homedir } from "node:os";
import { join } from "node:path";
import { readHookInput, writeHookOutput } from "./common.mjs";
import { buildSessionStartResult, loadPolicy } from "../lib/policy.mjs";

const codexHome = process.env.CODEX_HOME ?? join(homedir(), ".codex");
process.env.AGT_CODEX_POLICY_PATH ??= join(codexHome, "agt", "policy.json");
process.env.AGT_CODEX_AUDIT_PATH ??= join(codexHome, "agt", "audit-log.json");

try {
  const input = await readHookInput();
  const state = await loadPolicy();
  writeHookOutput(buildSessionStartResult(state, input));
} catch (error) {
  process.stderr.write(
    `AGT governance could not initialize the Codex session because startup evaluation failed closed: ${error instanceof Error ? error.message : String(error)}\n`,
  );
  process.exit(2);
}
