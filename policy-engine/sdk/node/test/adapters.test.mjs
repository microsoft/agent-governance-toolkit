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
  guardLangChainRunnable,
  guardLangChainTool,
  runModel,
  wrapMcpToolProvider,
  wrapModel,
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
    // AGT D1: TRANSFORM is the only mutating decision. Helper auto-
    // picks Decision.Transform when the handler supplied a
    // transformedPolicyTarget so existing call sites exercise the
    // canonical mutation path under the new gate.
    const verdict =
      result.verdict ??
      (result.transformedPolicyTarget !== undefined
        ? { decision: Decision.Transform }
        : { decision: Decision.Allow });
    const response = { verdict };
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
  // AGT D1.1: the runtime auto-marks a result with a
  // transformedPolicyTarget as Decision.Transform (the only mutating
  // verdict under AGT). Pre-AGT this defaulted to Decision.Allow.
  assert.equal(result.preModelCallResult.verdict.decision, Decision.Transform);

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

test("model wrappers fail closed for stream requests before upstream execution", async () => {
  const { control } = makeControl();
  let calls = 0;
  const wrapped = wrapModel(control, {
    async create(request) {
      calls += 1;
      return request;
    },
  }, { methods: ["create"] });

  await assert.rejects(
    () => wrapped.create({ stream: true, messages: [{ content: "hi" }] }),
    (error) => {
      assert.ok(error instanceof AgentControlBlockedError);
      assert.equal(error.interventionPoint, InterventionPoint.PreModelCall);
      assert.equal(error.result.verdict.reason, "runtime_error:streaming_unsupported");
      return true;
    },
  );
  assert.equal(calls, 0);
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

test("LangChain runnable adapter blocks unsupported batch and stream methods", async () => {
  const { control } = makeControl();
  let batchCalls = 0;
  let streamCalls = 0;
  const runnable = {
    async invoke(input) {
      return input;
    },
    async batch(inputs) {
      batchCalls += 1;
      return inputs;
    },
    async stream(input) {
      streamCalls += 1;
      return [input];
    },
  };
  const guarded = guardLangChainRunnable(control, runnable);

  for (const method of ["batch", "stream"]) {
    await assert.rejects(
      () => guarded[method]([{ q: "secret" }]),
      (error) => {
        assert.ok(error instanceof AgentControlBlockedError);
        assert.equal(error.result.verdict.reason, "runtime_error:adapter_unsupported");
        return true;
      },
    );
  }
  assert.equal(batchCalls, 0);
  assert.equal(streamCalls, 0);
});

test("LangChain runnable adapter fails closed for unsupported shapes", () => {
  const { control } = makeControl();

  assert.throws(
    () => guardLangChainRunnable(control, {}),
    (error) => {
      assert.ok(error instanceof AgentControlBlockedError);
      assert.equal(error.interventionPoint, InterventionPoint.PreModelCall);
      assert.equal(error.result.verdict.reason, "runtime_error:adapter_unsupported");
      return true;
    },
  );
});

test("LangChain tool adapter blocks unsupported batch and stream methods", async () => {
  const { control } = makeControl();
  let batchCalls = 0;
  let streamCalls = 0;
  const tool = {
    name: "retriever",
    async invoke(args) {
      return args;
    },
    async batch(argsList) {
      batchCalls += 1;
      return argsList;
    },
    async stream(args) {
      streamCalls += 1;
      return [args];
    },
  };
  const guarded = guardLangChainTool(control, tool);

  for (const method of ["batch", "stream"]) {
    await assert.rejects(
      () => guarded[method]([{ q: "secret" }]),
      (error) => {
        assert.ok(error instanceof AgentControlBlockedError);
        assert.equal(error.interventionPoint, InterventionPoint.PreToolCall);
        assert.equal(error.result.verdict.reason, "runtime_error:adapter_unsupported");
        return true;
      },
    );
  }
  assert.equal(batchCalls, 0);
  assert.equal(streamCalls, 0);
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

test("OpenAI Agents runner adapter blocks unsupported runner methods", async () => {
  const { control } = makeControl();
  const calls = [];
  const runner = {
    async run() {
      calls.push("run");
      return { final: "ok" };
    },
    runSync() {
      calls.push("runSync");
      return { final: "sync leak" };
    },
    stream() {
      calls.push("stream");
      return [{ final: "stream leak" }];
    },
    bypass() {
      calls.push("bypass");
      return { final: "bypass leak" };
    },
  };
  const wrapped = createOpenAIAgentsAdapter(control).wrapRunner(runner);

  for (const method of ["runSync", "stream", "bypass"]) {
    await assert.rejects(
      () => wrapped[method]({ name: "assistant" }, "secret"),
      (error) => {
        assert.ok(error instanceof AgentControlBlockedError);
        assert.equal(error.interventionPoint, InterventionPoint.Input);
        assert.equal(error.result.verdict.reason, "runtime_error:adapter_unsupported");
        return true;
      },
    );
  }
  assert.deepEqual(calls, []);
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

test("Anthropic adapter fails closed for streaming requests before upstream execution", async () => {
  const { control } = makeControl();
  let calls = 0;
  const anthropic = {
    messages: {
      async create() {
        calls += 1;
        return {};
      },
    },
  };
  const wrappedClient = wrapAnthropicClient(control, anthropic);

  await assert.rejects(
    () => wrappedClient.messages.create({ stream: true, messages: ["hi"] }),
    (error) => {
      assert.ok(error instanceof AgentControlBlockedError);
      assert.equal(error.interventionPoint, InterventionPoint.PostModelCall);
      assert.equal(error.result.verdict.reason, "runtime_error:streaming_unsupported");
      return true;
    },
  );
  assert.equal(calls, 0);
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

test("MCP tool-provider adapter blocks unsupported provider methods", async () => {
  const { control, client } = makeControl();
  const calls = [];
  const provider = {
    async callTool(request) {
      calls.push(["callTool", request]);
      return { result: request.name };
    },
    async readResource(request) {
      calls.push(["readResource", request]);
      return { content: "raw" };
    },
    async getPrompt(request) {
      calls.push(["getPrompt", request]);
      return { prompt: "raw" };
    },
    async stream(request) {
      calls.push(["stream", request]);
      return { chunk: "raw" };
    },
    async initialize() {
      calls.push(["initialize"]);
      return { ok: true };
    },
  };

  const wrapped = createMcpToolProviderAdapter(control).wrapProvider(provider);
  for (const method of ["readResource", "getPrompt", "stream", "initialize"]) {
    await assert.rejects(
      () => wrapped[method]({}),
      (error) => {
        assert.ok(error instanceof AgentControlBlockedError);
        assert.equal(error.interventionPoint, InterventionPoint.PreToolCall);
        assert.equal(error.result.verdict.reason, "runtime_error:adapter_unsupported");
        return true;
      },
    );
  }
  assert.deepEqual(calls, []);
  assert.deepEqual(client.requests, []);
});

test("MCP tool-provider adapter fails closed for unsupported shapes", () => {
  const { control } = makeControl();
  const provider = { async callTool() {} };

  assert.throws(
    () => wrapMcpToolProvider(control, {}),
    (error) => {
      assert.ok(error instanceof AgentControlBlockedError);
      assert.equal(error.interventionPoint, InterventionPoint.PreToolCall);
      assert.equal(error.result.verdict.reason, "runtime_error:adapter_unsupported");
      return true;
    },
  );
  assert.throws(
    () => wrapMcpToolProvider({}, provider),
    (error) => {
      assert.ok(error instanceof AgentControlBlockedError);
      assert.equal(error.interventionPoint, InterventionPoint.PreToolCall);
      assert.equal(error.result.verdict.reason, "runtime_error:adapter_unsupported");
      return true;
    },
  );
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
    // AGT D1: the stub auto-marks transformed responses as
    // Decision.Transform so the canonical mutation gate fires.
    result: { verdict: { decision: Decision.Transform }, transformedPolicyTarget: { prompt: "safe" } },
  });
  const tool = plugin.wrapTool("lookup", (args) => ({ seen: args }));
  assert.deepEqual((await tool({ id: 1 }, { toolCallId: "openclaw-tool-2" })).value, { wrapped: true });
});

test("OpenClaw hooks omit tool_call.id when no host id is supplied", async () => {
  const { control, client } = makeControl(() => ({}));
  const plugin = createOpenClawAdapter(control).plugin();

  await plugin.hooks.before_tool_call({ toolName: "lookup", params: { q: "hi" } }, {});
  await plugin.hooks.after_tool_call({ toolName: "lookup", params: { q: "hi" }, result: "ok" }, {});

  assert.equal("id" in client.requests[0].snapshot.tool_call, false);
  assert.equal("id" in client.requests[1].snapshot.tool_call, false);
});

test("OpenClaw hooks carry a supplied host tool_call.id", async () => {
  const { control, client } = makeControl(() => ({}));
  const plugin = createOpenClawAdapter(control).plugin();

  await plugin.hooks.before_tool_call({ toolName: "lookup", params: { q: "hi" }, toolCallId: "oc-1" }, {});

  assert.equal(client.requests[0].snapshot.tool_call.id, "oc-1");
});

test("adapter helper subpath is exported", () => {
  const adapters = require("agent-control-specification/adapters");

  assert.equal(adapters.wrapModel, wrapModel);
  assert.equal(adapters.createAnthropicAdapter, createAnthropicAdapter);
  assert.equal(adapters.createMcpToolProviderAdapter, createMcpToolProviderAdapter);
});

test("unsupported framework adapter fails loudly", () => {
  const unsupported = createUnsupportedFrameworkAdapter("ExampleAI");
  assert.throws(() => unsupported.guardAgent({}), (error) => {
    assert.ok(error instanceof AgentControlBlockedError);
    assert.equal(error.result.verdict.reason, "runtime_error:adapter_unsupported");
    return true;
  });
  assert.throws(() => unsupported.wrapModel({}), (error) => {
    assert.ok(error instanceof AgentControlBlockedError);
    assert.equal(error.result.verdict.reason, "runtime_error:adapter_unsupported");
    return true;
  });
  assert.throws(() => createLangChainAdapter({}).guard({}), /control must expose/);
});
