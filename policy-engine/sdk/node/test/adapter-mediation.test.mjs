import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
const assert = require("node:assert/strict");
const test = require("node:test");
const {
  AgentControl,
  AgentControlBlockedError,
  Decision,
  InterventionPoint,
  createAnthropicAdapter,
  createLangChainAdapter,
  createMcpToolProviderAdapter,
  createModelMiddleware,
  createOpenAIAgentsAdapter,
  createOpenClawAdapter,
  wrapModel,
} = require("../dist/index.js");

class StubRuntimeClient {
  constructor(handler) {
    this.handler = handler;
    this.requests = [];
  }

  async evaluateInterventionPoint(request) {
    this.requests.push(request);
    const result = await this.handler(request);
    // AGT D1: auto-pick Decision.Transform when the handler provided
    // a transformedPolicyTarget so the canonical mutation gate fires.
    const verdict =
      result.verdict ??
      (result.transformedPolicyTarget !== undefined
        ? { decision: Decision.Transform }
        : { decision: Decision.Allow });
    return {
      verdict,
      ...(result.transformedPolicyTarget === undefined ? {} : { transformedPolicyTarget: result.transformedPolicyTarget }),
    };
  }
}

function makeControl(handler) {
  const client = new StubRuntimeClient(handler);
  return { control: new AgentControl(client), client };
}

test("model middleware and model proxy mediate calls", async () => {
  const denied = makeControl(() => ({ verdict: { decision: Decision.Deny, reason: "blocked" } }));
  let called = false;
  await assert.rejects(
    () => createModelMiddleware(denied.control).run({ prompt: "raw" }, () => { called = true; return { text: "no" }; }),
    AgentControlBlockedError,
  );
  assert.equal(called, false);

  const { control, client } = makeControl(({ interventionPoint }) => {
    if (interventionPoint === InterventionPoint.PreModelCall) return { transformedPolicyTarget: { prompt: "safe" } };
    if (interventionPoint === InterventionPoint.PostModelCall) return { transformedPolicyTarget: { text: "checked" } };
    return {};
  });
  const wrapped = wrapModel(control, async (request) => {
    called = true;
    assert.deepEqual(request, { prompt: "safe" });
    return { text: "raw" };
  });
  assert.deepEqual(await wrapped({ prompt: "raw" }), { text: "checked" });
  assert.equal(called, true);
  assert.deepEqual(client.requests.map((request) => request.interventionPoint), [InterventionPoint.PreModelCall, InterventionPoint.PostModelCall]);
});

test("framework model adapters block before inner execution on deny", async () => {
  const { control } = makeControl(({ interventionPoint }) => ({
    verdict: { decision: interventionPoint === InterventionPoint.PreModelCall || interventionPoint === InterventionPoint.Input ? Decision.Deny : Decision.Allow },
  }));

  const runnable = { calls: 0, async invoke() { this.calls += 1; return {}; } };
  await assert.rejects(() => createLangChainAdapter(control).guard(runnable).invoke({ q: "raw" }), AgentControlBlockedError);
  assert.equal(runnable.calls, 0);

  const runner = { calls: 0, async run() { this.calls += 1; return {}; } };
  await assert.rejects(() => createOpenAIAgentsAdapter(control).wrapRunner(runner).run({}, { q: "raw" }), AgentControlBlockedError);
  assert.equal(runner.calls, 0);

  const anthropic = { messages: { calls: 0, async create() { this.calls += 1; return {}; } } };
  await assert.rejects(() => createAnthropicAdapter(control).wrapClient(anthropic).messages.create({ messages: [] }), AgentControlBlockedError);
  assert.equal(anthropic.messages.calls, 0);
});

test("tool adapters block before inner execution and pass transformed values", async () => {
  const denied = makeControl(({ interventionPoint }) => ({
    verdict: { decision: interventionPoint === InterventionPoint.PreToolCall ? Decision.Deny : Decision.Allow },
  }));
  const provider = { calls: 0, async callTool() { this.calls += 1; return {}; } };
  await assert.rejects(() => createMcpToolProviderAdapter(denied.control, { toolCallId: "mcp-deny" }).wrapProvider(provider).callTool({ name: "lookup", arguments: {} }), AgentControlBlockedError);
  assert.equal(provider.calls, 0);

  const { control, client } = makeControl(({ interventionPoint }) => {
    if (interventionPoint === InterventionPoint.PreToolCall) return { transformedPolicyTarget: { q: "safe" } };
    if (interventionPoint === InterventionPoint.PostToolCall) return { transformedPolicyTarget: { value: "checked" } };
    return {};
  });
  const tool = createAnthropicAdapter(control, { toolCallId: "tool-allow" }).wrapTool(async (args) => {
    assert.deepEqual(args, { q: "safe" });
    return { value: "raw" };
  }, { toolName: "lookup" });
  assert.deepEqual(await tool({ q: "raw" }), { value: "checked" });
  assert.deepEqual(client.requests.map((request) => request.interventionPoint), [InterventionPoint.PreToolCall, InterventionPoint.PostToolCall]);
});

test("tool helpers preserve non-empty whitespace tool call ids", async () => {
  const { control, client } = makeControl(() => ({}));

  await control.runTool("lookup", { q: "raw" }, (args) => args, { toolCallId: " " });

  assert.equal(client.requests[0].snapshot.tool_call.id, " ");
  assert.equal(client.requests[1].snapshot.tool_call.id, " ");
});

test("OpenClaw hooks expose explicit mediation and no hidden callable", async () => {
  const denied = makeControl(({ interventionPoint }) => ({
    verdict: { decision: interventionPoint === InterventionPoint.PreToolCall ? Decision.Deny : Decision.Allow },
  }));
  let called = false;
  const tool = createOpenClawAdapter(denied.control).plugin().wrapTool("lookup", () => {
    called = true;
    return {};
  });
  await assert.rejects(() => tool({}, { toolCallId: "openclaw-deny" }), AgentControlBlockedError);
  assert.equal(called, false);
});

test("proxy adapters leave original object reachable only by host-retained references", () => {
  const { control } = makeControl(() => ({}));
  const runnable = { async invoke(value) { return value; } };
  const guarded = createLangChainAdapter(control).guard(runnable);
  assert.notEqual(guarded, runnable);
  assert.equal(typeof runnable.invoke, "function");
});
