import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
const assert = require("node:assert/strict");
const test = require("node:test");
const { AgentControl, Decision, InterventionPoint, createGhcpExtension, createGhcpHooks } = require("../dist/index.js");

class StubRuntimeClient {
  constructor(handler = () => ({})) {
    this.handler = handler;
    this.requests = [];
    this.policyInputs = [];
  }

  async evaluateInterventionPoint(request) {
    this.requests.push(request);
    const result = await this.handler(request);
    const policyInput = result.policyInput ?? {
      intervention_point: request.interventionPoint,
      snapshot: request.snapshot,
    };
    this.policyInputs.push(policyInput);
    // AGT D1: auto-pick Decision.Transform when a transformedPolicyTarget
    // is present so the new mutation gate applies it.
    const verdict =
      result.verdict ??
      (result.transformedPolicyTarget !== undefined
        ? { decision: Decision.Transform }
        : { decision: Decision.Allow });
    const response = { verdict, policyInput };
    if (result.transformedPolicyTarget !== undefined) response.transformedPolicyTarget = result.transformedPolicyTarget;
    if (result.actionIdentity !== undefined) response.actionIdentity = result.actionIdentity;
    return response;
  }
}

function makeExtension(handler, options) {
  const client = new StubRuntimeClient(handler);
  return { extension: createGhcpExtension(new AgentControl(client), options), client };
}

function toolRequestEvent(sessionId, messages) {
  return {
    type: "assistant.message",
    sessionId,
    data: {
      messages,
      toolRequests: [{ toolCallId: "tc-1", name: "lookup", arguments: { q: "hi" } }],
    },
  };
}

test("GHCP extension guards allow hook flow and threads captured messages into policy input", async () => {
  const messages = [{ role: "user", content: "find hi" }];
  const assistantMessages = [
    ...messages,
    { role: "assistant", tool_calls: [{ id: "tc-1", name: "lookup", arguments: { q: "hi" } }] },
  ];
  const { extension, client } = makeExtension(() => ({}), { snapshot: { tenant: "acme" } });

  assert.equal(
    await extension.hooks.onUserPromptSubmitted({ prompt: "find hi", messages }, { sessionId: "s1" }),
    undefined,
  );
  extension.onEvent(toolRequestEvent("s1", assistantMessages));
  assert.equal(await extension.hooks.onPreToolUse({ toolName: "lookup", toolArgs: { q: "hi" } }, { sessionId: "s1" }), undefined);
  assert.equal(
    await extension.hooks.onPostToolUse({
      toolName: "lookup",
      toolArgs: { q: "hi" },
      toolResult: { textResultForLlm: "ok", resultType: "success" },
    }, { sessionId: "s1" }),
    undefined,
  );

  assert.equal(client.requests[0].interventionPoint, InterventionPoint.Input);
  assert.deepEqual(client.policyInputs[0].snapshot.messages, messages);
  assert.deepEqual(client.policyInputs[1].snapshot.messages, assistantMessages);
  assert.deepEqual(client.policyInputs[1].snapshot.model_request.messages, assistantMessages);
  assert.equal(client.requests[1].snapshot.tool_call.id, "tc-1");
  assert.equal(client.requests[1].snapshot.tool_call.name, "lookup");
  assert.deepEqual(client.requests[1].snapshot.tool_call.args, { q: "hi" });
  assert.equal(client.requests[1].snapshot.tenant, "acme");
  assert.equal(client.requests[2].snapshot.tool_call.id, "tc-1");
});

test("GHCP pre-tool deny returns a Copilot deny decision with captured messages", async () => {
  const messages = [{ role: "user", content: "find hi" }];
  const { extension, client } = makeExtension(({ interventionPoint }) => ({
    verdict: {
      decision: interventionPoint === InterventionPoint.PreToolCall ? Decision.Deny : Decision.Allow,
      reason: "tool blocked",
    },
  }));

  extension.onEvent(toolRequestEvent("s1", messages));
  const result = await extension.hooks.onPreToolUse({ toolName: "lookup", toolArgs: { q: "hi" } }, { sessionId: "s1" });

  assert.equal(result.permissionDecision, "deny");
  assert.match(result.permissionDecisionReason, /tool blocked/);
  assert.deepEqual(client.policyInputs[0].snapshot.messages, messages);
});

test("GHCP pre-tool hook evaluates without a prior assistant event and omits tool_call.id", async () => {
  const { extension, client } = makeExtension(() => ({}));
  const result = await extension.hooks.onPreToolUse({ toolName: "lookup", toolArgs: { q: "hi" } }, { sessionId: "s1" });

  assert.equal(result, undefined);
  assert.equal(client.requests.length, 1);
  assert.equal(client.requests[0].interventionPoint, InterventionPoint.PreToolCall);
  assert.equal("id" in client.requests[0].snapshot.tool_call, false);
});

test("GHCP parses JSON-string tool args into an object for the policy target", async () => {
  const { extension, client } = makeExtension(() => ({}));
  await extension.hooks.onPreToolUse(
    { toolName: "lookup", toolArgs: JSON.stringify({ q: "hi" }) },
    { sessionId: "s1" },
  );

  assert.deepEqual(client.requests[0].snapshot.tool_call.args, { q: "hi" });
});

test("GHCP escalate maps to a Copilot ask decision by default", async () => {
  const { extension } = makeExtension(({ interventionPoint }) => ({
    verdict: {
      decision: interventionPoint === InterventionPoint.PreToolCall ? Decision.Escalate : Decision.Allow,
      message: "needs approval",
    },
  }));
  extension.onEvent(toolRequestEvent("s1", [{ role: "user", content: "x" }]));
  const result = await extension.hooks.onPreToolUse({ toolName: "lookup", toolArgs: { q: "hi" } }, { sessionId: "s1" });

  assert.equal(result.permissionDecision, "ask");
  assert.match(result.permissionDecisionReason, /needs approval/);
});

test("GHCP escalate maps to deny when escalate option is 'deny'", async () => {
  const { extension } = makeExtension(
    ({ interventionPoint }) => ({
      verdict: {
        decision: interventionPoint === InterventionPoint.PreToolCall ? Decision.Escalate : Decision.Allow,
        message: "needs approval",
      },
    }),
    { escalate: "deny" },
  );
  extension.onEvent(toolRequestEvent("s1", [{ role: "user", content: "x" }]));
  const result = await extension.hooks.onPreToolUse({ toolName: "lookup", toolArgs: { q: "hi" } }, { sessionId: "s1" });

  assert.equal(result.permissionDecision, "deny");
});

test("GHCP warn is non-blocking and proceeds as allow", async () => {
  const { extension } = makeExtension(({ interventionPoint }) => ({
    verdict: {
      decision: interventionPoint === InterventionPoint.PreToolCall ? Decision.Warn : Decision.Allow,
      message: "heads up",
    },
  }));
  extension.onEvent(toolRequestEvent("s1", [{ role: "user", content: "x" }]));
  const result = await extension.hooks.onPreToolUse({ toolName: "lookup", toolArgs: { q: "hi" } }, { sessionId: "s1" });

  assert.equal(result, undefined);
});

test("GHCP tool scoping skips evaluation for tools outside the governed set", async () => {
  const { extension, client } = makeExtension(
    () => ({ verdict: { decision: Decision.Deny, reason: "blocked" } }),
    { tools: ["bash"] },
  );
  const result = await extension.hooks.onPreToolUse({ toolName: "web-fetch", toolArgs: { url: "x" } }, { sessionId: "s1" });

  assert.equal(result, undefined);
  assert.equal(client.requests.length, 0);
});

test("GHCP logger receives a structured decision entry", async () => {
  const entries = [];
  const { extension } = makeExtension(
    ({ interventionPoint }) => ({
      verdict: {
        decision: interventionPoint === InterventionPoint.PreToolCall ? Decision.Deny : Decision.Allow,
        reason: "blocked",
      },
    }),
    { logger: (entry) => entries.push(entry) },
  );
  extension.onEvent(toolRequestEvent("s1", [{ role: "user", content: "x" }]));
  await extension.hooks.onPreToolUse({ toolName: "lookup", toolArgs: { q: "hi" } }, { sessionId: "s1" });

  const denied = entries.find((e) => e.decision === Decision.Deny);
  assert.ok(denied, "expected a deny log entry");
  assert.equal(denied.interventionPoint, InterventionPoint.PreToolCall);
  assert.equal(denied.toolName, "lookup");
  assert.equal(denied.sessionId, "s1");
});

test("GHCP hook-only helper remains available for existing imports", async () => {
  const client = new StubRuntimeClient(() => ({}));
  const hooks = createGhcpHooks(new AgentControl(client));
  assert.equal(await hooks.onUserPromptSubmitted({ prompt: "hello" }, { sessionId: "s1" }), undefined);
  assert.equal(client.requests[0].interventionPoint, InterventionPoint.Input);
  assert.equal(client.requests[0].snapshot.input, "hello");
});
