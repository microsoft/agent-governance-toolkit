// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// The package's `./server` export. OpenCode 2.x, and OpenCode 1.x from 1.3.4,
// load a package's `./server` export before its root. Both accept a default
// definition object: 1.x calls `server`, 2.x calls `setup`, and each ignores
// the other key. The package root keeps the plugin function as its default
// export for earlier 1.x releases, which call every root export as a plugin.

import { AgtGovernance } from "./index.mjs";
import { loadPolicy } from "../lib/opencode-policy.mjs";

export default {
  id: "@microsoft/agent-governance-opencode",
  server: AgtGovernance,
  setup: setupOpenCodeV2,
};

/**
 * OpenCode 2.x entry point. The V2 loader accepts only a default
 * `{ id, setup }` (or `{ id, effect }`) definition from the module it loads,
 * and `setup` receives a context whose domains register hooks instead of a
 * returned hook object. This wires the same governance hooks into it:
 *
 *  - tool `execute.before` — enforce policy; a throw rejects the call
 *  - tool `execute.after`  — scan the text the model reads and redact it
 *  - `agt_policy_status` and `agt_policy_check_text` as direct V2 tools
 *
 * V2 delivers events through `ctx.event.subscribe` with different names and
 * payloads, so the event-based prompt scan and session-state lifecycle
 * handling are not wired here yet.
 */
async function setupOpenCodeV2(ctx) {
  const hooks = await AgtGovernance({ directory: ctx.location.directory });
  rejectShellToolName(await loadPolicy());

  await ctx.tool.hook("execute.before", (event) =>
    hooks["tool.execute.before"](
      { tool: policyToolName(event.tool), sessionID: event.sessionID, callID: event.id },
      { args: event.input },
    ),
  );

  await ctx.tool.hook("execute.after", async (event) => {
    if (event.status !== "completed") {
      return;
    }
    const text = toolResultText(event.result);
    const output = { output: text, metadata: event.result.metadata };
    try {
      await hooks["tool.execute.after"](
        { tool: policyToolName(event.tool), sessionID: event.sessionID, callID: event.id },
        output,
      );
    } finally {
      // The 1.x hook redacts `output` before it throws on a session-state
      // audit failure, so apply the redaction before that error propagates.
      replaceResultText(event, text, output.output);
    }
  });

  await ctx.tool.transform((tools) => {
    for (const [name, tool] of Object.entries(hooks.tool)) {
      tools.add({
        name,
        description: tool.description,
        input: { type: "object", properties: tool.args },
        // Code Mode tools are reachable only through the `execute` tool, which
        // the bundled policy does not allow, so register these as direct tools
        // like OpenCode's built-ins.
        options: { codemode: false },
        execute: async (args) => ({ content: await tool.execute(args) }),
      });
    }
  });
}

// OpenCode 2.x renamed the 1.x `bash` tool to `shell`. AGT policies, the
// bundled one included, name shell rules after `bash`, so evaluate a 2.x
// `shell` call under that name.
function policyToolName(tool) {
  return tool === "shell" ? "bash" : tool;
}

// A policy entry naming `shell` would never match once `shell` calls are
// evaluated as `bash`, so refuse it instead of ignoring it.
function rejectShellToolName(state) {
  const raw = state.policy.raw ?? {};
  const list = (value) => (Array.isArray(value) ? value : []);
  const names = [
    ...list(raw.toolPolicies?.allowedTools),
    ...list(raw.toolPolicies?.blockedTools),
    ...list(raw.toolPolicies?.reviewTools),
    ...list(raw.blockedToolCalls).map((rule) => rule?.tool),
    ...list(raw.sessionState?.transitions).map((transition) => transition?.tool),
    ...list(raw.sessionState?.rules).flatMap((rule) => list(rule?.tools)),
  ];
  if (names.some((name) => typeof name === "string" && name.trim().toLowerCase() === "shell")) {
    throw new Error(
      `AGT policy at ${state.path} names the tool 'shell'. On OpenCode 2.x the shell tool is ` +
        "evaluated under its OpenCode 1.x name 'bash', so name it 'bash' in the policy.",
    );
  }
}

// The scan covered every text part (or the structured output the host would
// show instead), so replace them all with the redacted text and drop the
// structured output so no unredacted copy reaches the model.
function replaceResultText(event, text, redacted) {
  if (redacted === text) {
    return;
  }
  const files = Array.isArray(event.result.content)
    ? event.result.content.filter((part) => part.type !== "text")
    : [];
  event.result = {
    content: [{ type: "text", text: redacted }, ...files],
    ...(event.result.metadata === undefined ? {} : { metadata: event.result.metadata }),
  };
}

// Mirrors how OpenCode 2.x builds the text the model reads from a tool result:
// the text parts, or the structured output when there is no content.
function toolResultText(result) {
  if (typeof result.content === "string") {
    return result.content;
  }
  if (Array.isArray(result.content) && result.content.length > 0) {
    return result.content
      .filter((part) => part.type === "text")
      .map((part) => part.text)
      .join("\n");
  }
  if (result.output === undefined || typeof result.output === "string") {
    return result.output ?? "";
  }
  return JSON.stringify(result.output);
}
