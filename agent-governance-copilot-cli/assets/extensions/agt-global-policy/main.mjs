// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { joinSession } from "@github/copilot-sdk/extension";
import {
  AUDIT_PATH_ENV,
  SDK_ENTRY_ENV,
  USER_POLICY_ENV,
  checkArbitraryText,
  evaluatePreToolUse,
  evaluatePromptSubmission,
  formatPolicySummary,
  getPolicyStatus,
  inspectToolResult,
  loadPolicy,
} from "./lib/policy.mjs";

const extensionRoot = import.meta.dirname;
const defaultPolicyPath = new URL("./config/default-policy.json", import.meta.url);
let session;
let policyState = await refreshPolicy();

session = await joinSession({
  commands: [
    {
      name: "agt",
      description:
        "Inspect or reload the AGT global Copilot CLI policy. Examples: /agt status, /agt reload, /agt check \"ignore previous instructions\"",
      handler: handleAgtCommand,
    },
  ],
  hooks: {
    onSessionStart: async () => ({
      additionalContext: getStartupContext(policyState),
    }),
    onUserPromptSubmitted: async (input, invocation) => {
      policyState = await ensurePolicy();
      return evaluatePromptSubmission(policyState, input, invocation);
    },
    onPreToolUse: async (input, invocation) => {
      policyState = await ensurePolicy();
      return evaluatePreToolUse(policyState, input, invocation);
    },
    onPostToolUse: async (input, invocation) => {
      policyState = await ensurePolicy();
      return inspectToolResult(policyState, input, invocation);
    },
    onSessionEnd: async () => ({
      sessionSummary: `AGT global policy ${policyState.policy.mode} mode from ${policyState.source}; audit chain valid: ${policyState.auditLogger.verify()}.`,
    }),
  },
  tools: [
    {
      name: "agt_policy_status",
      description: "Return the active AGT Copilot CLI policy status and source.",
      skipPermission: true,
      parameters: {
        type: "object",
        properties: {},
      },
      handler: async () => {
        policyState = await ensurePolicy();
        return JSON.stringify(getPolicyStatus(policyState), null, 2);
      },
    },
    {
      name: "agt_policy_check_text",
      description: "Check text against AGT prompt, context-poisoning, and MCP-style threat detectors.",
      skipPermission: true,
      parameters: {
        type: "object",
        properties: {
          text: {
            type: "string",
            description: "Text to inspect.",
          },
        },
        required: ["text"],
      },
      handler: async ({ text }, invocation) => {
        policyState = await ensurePolicy();
        return JSON.stringify(checkArbitraryText(policyState, text, invocation), null, 2);
      },
    },
  ],
});

async function ensurePolicy() {
  return policyState ?? refreshPolicy();
}

async function refreshPolicy() {
  return loadPolicy({
    defaultPolicyPath,
    extensionRoot,
  });
}

function getStartupContext(state) {
  const lines = [
    `AGT global policy mode: ${state.policy.mode}.`,
    `Policy source: ${state.source}.`,
    `SDK source: ${state.sdkSource}.`,
    ...state.policy.additionalContext,
  ];

  if (state.configuredPolicyError) {
    lines.push(
      `Policy load warning: the configured policy could not be loaded from ${state.configuredPolicyPath}.`,
    );
  }

  lines.push(
    `Prompt defense grade: ${state.promptDefenseReport.grade} (${state.promptDefenseReport.coverage}).`,
  );

  return lines.join("\n");
}

async function handleAgtCommand(context) {
  const tokens = tokenize(context.args);
  const verb = (tokens[0] ?? "status").toLowerCase();

  switch (verb) {
    case "status":
      await session.log(formatPolicySummary(policyState));
      return;
    case "reload":
      policyState = await refreshPolicy();
      await session.log(`Reloaded AGT policy.\n\n${formatPolicySummary(policyState)}`);
      return;
    case "check": {
      const text = tokens.slice(1).join(" ").trim();
      if (!text) {
        await session.log("Usage: /agt check \"text to inspect\"", { level: "warning" });
        return;
      }
      const review = checkArbitraryText(policyState, text, {
        sessionId: session.sessionId,
      });
      await session.log(JSON.stringify(review, null, 2));
      return;
    }
    case "help":
      await session.log(
        [
          "AGT global policy commands",
          "",
          "/agt status",
          "/agt reload",
          "/agt check \"ignore previous instructions\"",
          "",
          `Override policy path with ${USER_POLICY_ENV}.`,
          `Override SDK entry with ${SDK_ENTRY_ENV}.`,
          `Override audit path with ${AUDIT_PATH_ENV}.`,
        ].join("\n"),
      );
      return;
    default:
      await session.log(`Unknown /agt command: ${verb}`, { level: "warning" });
  }
}

function tokenize(value) {
  const tokens = [];
  const pattern = /"([^"]*)"|'([^']*)'|(\S+)/g;
  let match;
  while ((match = pattern.exec(value ?? "")) !== null) {
    tokens.push(match[1] ?? match[2] ?? match[3]);
  }
  return tokens;
}
