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
  createUnsupportedFrameworkAdapter,
  runModel,
  wrapAnthropicClient,
  wrapAnthropicTool,
} = require("../dist/index.js");

class StubRuntimeClient {
  constructor(handler = () => ({})) {
    this.handler = handler;
    this.requests = [];
  }

  async evaluateInterventionPoint(request) {
    this.requests.push(request);
    const result = await this.handler(request);
    const response = { verdict: result.verdict ?? { decision: Decision.Allow } };
    if (result.transformedPolicyTarget !== undefined) response.transformedPolicyTarget = result.transformedPolicyTarget;
    if (result.policyInput !== undefined) response.policyInput = result.policyInput;
    return response;
  }
}

function makeControl(handler) {
  const client = new StubRuntimeClient(handler);
  return { control: new AgentControl(client), client };
}

test("model middleware evaluates pre/post and blocks enforcement decisions", async () => {
  const { control } = makeControl(({ interventionPoint }) => {
    if (interventionPoint === InterventionPoint.PreModelCall) {
      return { transformedPolicyTarget: { prompt: "safe" } };
    }
    if (interventionPoint === InterventionPoint.PostModelCall) {
      return { transformedPolicyTarget: { text: "checked" } };
    }
    return {};
  });

  const result = await runModel(control, { prompt: "raw" }, (request) => {
    assert.deepEqual(request, { prompt: "safe" });
    return { text: "model" };
  });
  assert.deepEqual(result.value, { text: "checked" });
  assert.equal(result.preModelCallResult.verdict.decision, Decision.Allow);

  const middleware = createModelMiddleware(control);
  assert.deepEqual(
    await middleware.run({ prompt: "raw" }, (request) => ({ echoed: request })),
    {
      value: { text: "checked" },
      preModelCallResult: result.preModelCallResult,
      postModelCallResult: result.postModelCallResult,
    },
  );

  const { control: blockingControl } = makeControl(({ interventionPoint }) => ({
    verdict: {
      decision: interventionPoint === InterventionPoint.PreModelCall ? Decision.Deny : Decision.Allow,
      reason: "blocked",
    },
  }));
  await assert.rejects(
    () => runModel(blockingControl, { prompt: "raw" }, () => ({ text: "never" })),
    AgentControlBlockedError,
  );
});

test("LangChain runnable adapter guards invoke with input, model, and output checks", async () => {
  const { control, client } = makeControl(({ interventionPoint, snapshot }) => {
    if (interventionPoint === InterventionPoint.Input) {
      return { transformedPolicyTarget: { q: `${snapshot.input.q}-input` } };
    }
    if (interventionPoint === InterventionPoint.PostModelCall) {
      return { transformedPolicyTarget: { answer: "post" } };
    }
    if (interventionPoint === InterventionPoint.Output) {
      return { transformedPolicyTarget: { answer: "output" } };
    }
    return {};
  });
  const runnable = {
    async invoke(input) {
      assert.deepEqual(input, { q: "raw-input" });
      return { answer: "model" };
    },
  };

  const adapter = createLangChainAdapter(control, { snapshot: { defaultTrace: "d" } });
  const guarded = adapter.guard(runnable);
  assert.deepEqual(
    await guarded.invoke({ q: "raw" }, { agentControl: { snapshot: { callTrace: "c" } } }),
    { answer: "output" },
  );
  assert.deepEqual(
    client.requests.map((request) => request.interventionPoint),
    [
      InterventionPoint.Input,
      InterventionPoint.PreModelCall,
      InterventionPoint.PostModelCall,
      InterventionPoint.Output,
    ],
  );
  assert.equal(client.requests[1].snapshot.defaultTrace, "d");
  assert.equal(client.requests[1].snapshot.callTrace, "c");
  assert.deepEqual(client.requests[1].snapshot.input, { q: "raw-input" });
});

test("OpenAI Agents runner adapter wraps runner.run", async () => {
  const { control } = makeControl(({ interventionPoint, snapshot }) => {
    if (interventionPoint === InterventionPoint.Input) {
      return { transformedPolicyTarget: `${snapshot.input}-checked` };
    }
    return {};
  });
  const runner = {
    async run(agent, input, options) {
      assert.deepEqual(agent, { name: "assistant" });
      assert.equal(input, "hello-checked");
      assert.deepEqual(options.metadata, { id: "run-1" });
      return { final: input };
    },
  };

  const wrapped = createOpenAIAgentsAdapter(control).wrapRunner(runner);
  assert.deepEqual(
    await wrapped.run({ name: "assistant" }, "hello", { metadata: { id: "run-1" } }),
    { final: "hello-checked" },
  );
});

test("Anthropic adapter wraps client messages and tool calls", async () => {
  const { control, client } = makeControl(({ interventionPoint, snapshot }) => {
    if (interventionPoint === InterventionPoint.PreModelCall) {
      return { transformedPolicyTarget: { ...snapshot.model_request, system: "safe" } };
    }
    if (interventionPoint === InterventionPoint.PreToolCall) {
      return { transformedPolicyTarget: { city: "Paris" } };
    }
    if (interventionPoint === InterventionPoint.PostToolCall) {
      return { transformedPolicyTarget: { ok: true } };
    }
    return {};
  });
  const anthropic = {
    messages: {
      async create(request) {
        assert.equal(request.system, "safe");
        return { content: request.messages };
      },
    },
  };
  const wrappedClient = wrapAnthropicClient(control, anthropic);
  assert.deepEqual(await wrappedClient.messages.create({ messages: ["hi"] }), { content: ["hi"] });

  const tool = wrapAnthropicTool(control, async (args) => {
    assert.deepEqual(args, { city: "Paris" });
    return { weather: "sunny" };
  }, { toolName: "weather", toolCallId: "anthropic-tool-1" });
  assert.deepEqual(await tool({ city: "London" }), { ok: true });
  assert.deepEqual(client.requests.at(-2).snapshot.tool_call.id, "anthropic-tool-1");

  const adapter = createAnthropicAdapter(control);
  assert.deepEqual(await adapter.run(anthropic, { messages: ["bye"] }), { content: ["bye"] });
});

test("MCP tool-provider adapter wraps object and positional calls", async () => {
  const { control, client } = makeControl(({ interventionPoint, snapshot }) => {
    if (interventionPoint === InterventionPoint.PreToolCall) {
      return { transformedPolicyTarget: { query: "safe" } };
    }
    return {};
  });
  const provider = {
    async callTool(request) {
      assert.deepEqual(request.arguments, { query: "safe" });
      return { result: request.name };
    },
    async call_tool(name, args) {
      assert.equal(name, "lookup");
      assert.deepEqual(args, { query: "safe" });
      return { result: name };
    },
  };

  const wrapped = createMcpToolProviderAdapter(control, { toolCallId: "mcp-1" }).wrapProvider(provider);
  assert.deepEqual(await wrapped.callTool({ name: "search", arguments: { query: "raw" } }), { result: "search" });
  assert.deepEqual(await wrapped.call_tool("lookup", { query: "raw" }), { result: "lookup" });
  assert.equal(client.requests[0].snapshot.tool_call.name, "search");
  assert.equal(client.requests[2].snapshot.tool_call.name, "lookup");
});

test("OpenClaw hook plugin exposes explicit model and tool hooks", async () => {
  const { control } = makeControl(({ interventionPoint }) => {
    if (interventionPoint === InterventionPoint.PreModelCall) {
      return { transformedPolicyTarget: { prompt: "safe" } };
    }
    if (interventionPoint === InterventionPoint.PostToolCall) {
      return { transformedPolicyTarget: { wrapped: true } };
    }
    return {};
  });
  const plugin = createOpenClawAdapter(control, { toolCallId: "openclaw-tool-1" }).plugin();

  assert.deepEqual(await plugin.beforeModelCall({ prompt: "raw" }), {
    value: { prompt: "safe" },
    result: { verdict: { decision: Decision.Allow }, transformedPolicyTarget: { prompt: "safe" } },
  });
  const tool = plugin.wrapTool("lookup", (args) => ({ seen: args }));
  assert.deepEqual((await tool({ id: 1 }, { toolCallId: "openclaw-tool-2" })).value, { wrapped: true });
});

test("unsupported framework adapter fails loudly", () => {
  const unsupported = createUnsupportedFrameworkAdapter("ExampleAI");
  assert.throws(() => unsupported.guardAgent({}), /Full-coverage ExampleAI adapter is not implemented/);
  assert.throws(() => unsupported.wrapModel({}), /Model middleware for ExampleAI is not implemented/);
  assert.throws(() => createLangChainAdapter({}).guard({}), /control must expose/);
});
