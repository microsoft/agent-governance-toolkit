// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { dirname } from "node:path";
import { fileURLToPath } from "node:url";

import {
  checkArbitraryText,
  evaluateOpenCodePrompt,
  evaluateOpenCodeTool,
  evaluateOpenCodeToolOutput,
  getPolicyStatus,
  loadPolicy,
} from "../lib/policy.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));

/**
 * AGT governance plugin for OpenCode.
 *
 * Loads the AGT policy once per OpenCode process and wires it into the
 * OpenCode plugin contract:
 *
 *  - session.start             — inject AGT governance context for the run
 *  - event (chat.params/start) — scan submitted prompts; throw to block
 *  - tool.execute.before       — enforce policy; throw to deny, mark args
 *                                for OpenCode's permission prompt on review
 *  - tool.execute.after        — scan tool output for known secret patterns
 *                                and redact in enforce mode
 *  - tool.execute.error        — record audit entry for failed tool calls
 *  - tools.agt_policy_status   — return current policy snapshot
 *  - tools.agt_policy_check_text — inspect arbitrary text for poisoning
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
    session: {
      async start(input) {
        try {
          const state = await getState();
          const status = await getPolicyStatus(state);
          if (typeof ctx?.app?.log === "function") {
            ctx.app.log(
              `[AGT] OpenCode governance active — mode=${status.mode} source=${status.source} ` +
                `promptDefense=${status.promptDefenseGrade} audit=${status.auditEntries}`,
            );
          }
          return {
            additionalContext: [
              `AGT governance mode: ${status.mode}.`,
              `Policy source: ${status.source}.`,
              ...state.policy.additionalContext,
              `Prompt defense grade: ${status.promptDefenseGrade} (${status.promptDefenseCoverage}).`,
            ].join("\n"),
            sessionId: input?.sessionID,
          };
        } catch (error) {
          // Fail closed on session boot: surface the failure via context so
          // operators can see it, but do not throw because OpenCode may not
          // have a permission prompt available at session start.
          return {
            additionalContext: `AGT governance failed to initialize: ${
              error instanceof Error ? error.message : String(error)
            }`,
          };
        }
      },
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
        throw new Error(result.reason || "AGT governance blocked the submitted prompt.");
      }
    },

    tool: {
      execute: {
        before: async (input, output) => {
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
        after: async (input, output) => {
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
        error: async (input, output) => {
          // Record an audit entry without re-running policy. We swallow any
          // audit failure here because the tool already errored upstream.
          try {
            const state = await getState();
            await evaluateOpenCodeToolOutput(state, {
              tool: input?.tool,
              output: String(output?.error ?? ""),
              sessionId: input?.sessionID,
            });
          } catch {
            // best-effort
          }
        },
      },
    },

    tools: {
      agt_policy_status: {
        description: "Return the active AGT OpenCode governance policy status and source.",
        parameters: {
          type: "object",
          properties: {},
          additionalProperties: false,
        },
        async execute() {
          const state = await getState();
          return {
            content: [
              {
                type: "text",
                text: JSON.stringify(await getPolicyStatus(state), null, 2),
              },
            ],
          };
        },
      },
      agt_policy_check_text: {
        description:
          "Check text against AGT prompt, context-poisoning, and MCP-style threat detectors.",
        parameters: {
          type: "object",
          properties: {
            text: { type: "string", description: "Text to inspect." },
          },
          required: ["text"],
          additionalProperties: false,
        },
        async execute(args) {
          const state = await getState();
          const text = typeof args?.text === "string" ? args.text : "";
          return {
            content: [
              {
                type: "text",
                text: JSON.stringify(checkArbitraryText(state, text, "opencode-check"), null, 2),
              },
            ],
          };
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
  const type = String(event.type ?? "");
  if (!type) {
    return "";
  }
  // OpenCode emits chat.* events when the user sends a message. Different
  // versions may key the prompt under different paths; check the common ones.
  if (!/^(chat|message|prompt|user)\b/.test(type)) {
    return "";
  }
  const props = event.properties ?? event.data ?? {};
  const candidates = [
    props.prompt,
    props.message,
    props.text,
    props.content,
    typeof props.message === "object" ? props.message?.content : undefined,
  ];
  for (const candidate of candidates) {
    if (typeof candidate === "string" && candidate.trim()) {
      return candidate;
    }
    if (Array.isArray(candidate)) {
      const joined = candidate
        .map((part) => (typeof part === "string" ? part : part?.text ?? ""))
        .filter(Boolean)
        .join("\n");
      if (joined.trim()) {
        return joined;
      }
    }
  }
  return "";
}
