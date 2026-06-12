// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import {
  checkArbitraryText,
  evaluateOpenCodePrompt,
  evaluateOpenCodeTool,
  evaluateOpenCodeToolOutput,
  getPolicyStatus,
  loadPolicy,
} from "../lib/policy.mjs";

/**
 * AGT governance plugin for OpenCode.
 *
 * Loads the AGT policy once per OpenCode process and wires it into the
 * OpenCode plugin contract:
 *
 *  - session.created           — log AGT governance status at session start
 *  - event (chat.params/start) — scan submitted prompts; throw to block
 *  - tool.execute.before       — enforce policy; throw to deny, mark args
 *                                for OpenCode's permission prompt on review
 *  - tool.execute.after        — scan tool output for known secret patterns
 *                                and redact in enforce mode
 *  - tool.agt_policy_status    — return current policy snapshot
 *  - tool.agt_policy_check_text — inspect arbitrary text for poisoning
 *
 * The plugin fails closed: if AGT cannot evaluate a request and the active
 * policy has `denyOnPolicyError: true` (the default), the request is denied.
 *
 * @typedef {(context: object) => Promise<object>} Plugin
 * @type {Plugin}
 */
export const AgtGovernance = async (ctx) => {
  // OpenCode loads plugins once per process. Cache the compiled policy so we
  // don't re-read it on every hook invocation.
  let stateCache;
  let stateError;

  async function getState() {
    if (stateCache) {
      return stateCache;
    }
    if (stateError) {
      throw stateError;
    }
    try {
      stateCache = await loadPolicy();
      return stateCache;
    } catch (error) {
      stateError = error instanceof Error ? error : new Error(String(error));
      throw stateError;
    }
  }

  return {
    "session.created": async () => {
      try {
        const state = await getState();
        const status = await getPolicyStatus(state);
        if (typeof ctx?.client?.app?.log === "function") {
          await ctx.client.app.log({
            body: {
              service: "agt-governance",
              level: "info",
              message:
                `[AGT] OpenCode governance active — mode=${status.mode} source=${status.source} ` +
                `promptDefense=${status.promptDefenseGrade} audit=${status.auditEntries}`,
            },
          });
        }
      } catch {
        // best-effort — do not block session creation
      }
    },

    event: async ({ event } = {}) => {
      // OpenCode emits a wide range of events. Only inspect prompt-bearing
      // events; ignore the rest cheaply.
      const prompt = extractPromptFromEvent(event);
      if (!prompt) {
        return;
      }

      const state = await getState();
      const result = await evaluateOpenCodePrompt(state, {
        prompt,
        sessionId: event?.properties?.sessionID ?? event?.properties?.sessionId,
      });

      if (result.effect === "deny") {
        // throwing here silently breaks the OpenCode session. Exception message is never displayed to the user, this is not the way to go...       
        throw new Error(result.reason || "AGT governance blocked the submitted prompt.");
      }
    },
    "tool.execute.before": async (input, output) => {
      const state = await getState();
      const result = await evaluateOpenCodeTool(state, {
        tool: input?.tool,
        args: output?.args,
        cwd: ctx?.directory ?? ctx?.worktree,
        sessionId: input?.sessionID,
      });

      if (result.effect === "deny") {
        throw new Error(result.reason || `AGT policy denied tool '${input?.tool}'.`);
      }
      if (result.effect === "review") {
        // OpenCode does not currently expose a server-side "ask"
        // permission decision from inside a plugin hook. We mark the
        // request as requiring review by appending a hint to the args
        // so downstream permission integrations can pick it up, and we
        // still record the audit entry. Operators who want hard-deny
        // behaviour on review should switch the policy mode or set
        // `defaultEffect` to `deny`.
        if (output && typeof output === "object" && output.args && typeof output.args === "object") {
          output.args.__agt_review_reason = result.reason || "AGT review required.";
        }
      }
    },

    "tool.execute.after": async (input, output) => {
      if (!output || typeof output !== "object") {
        return;
      }
      const state = await getState();
      const text = typeof output.output === "string" ? output.output : "";
      const result = await evaluateOpenCodeToolOutput(state, {
        tool: input?.tool,
        output: text,
        sessionId: input?.sessionID,
      });
      if (result.redact && typeof result.redactedOutput === "string") {
        output.output = result.redactedOutput;
        if (typeof output.metadata === "object" && output.metadata !== null) {
          output.metadata.agtRedacted = true;
          output.metadata.agtRedactionReason = result.reason;
        }
      }
    },

    tool: {
      agt_policy_status: {
        description: "Return the active AGT OpenCode governance policy status and source.",
        args: {},
        async execute() {
          const state = await getState();
          return JSON.stringify(await getPolicyStatus(state), null, 2);
        },
      },
      agt_policy_check_text: {
        description:
          "Check text against AGT prompt, context-poisoning, and MCP-style threat detectors.",
          args: {
            text: { type: "string", description: "Text to inspect." },
          },
        async execute(args) {
          const state = await getState();
          const text = typeof args?.text === "string" ? args.text : "";
          return JSON.stringify(checkArbitraryText(state, text, "opencode-check"), null, 2);
        },
      },
    },
  };
};

export default AgtGovernance;

function extractPromptFromEvent(event) {
  if (!event || typeof event !== "object") {
    return "";
  }
  if (event.type === "message.part.updated") {
    const part = event.properties?.part;
    if (part?.type === "text" && typeof part.text === "string") {
      return part.text.trim();
    }
  }
  return "";
}
