import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
const require = createRequire(import.meta.url);
const assert = require("node:assert/strict");
const test = require("node:test");
const {
  AgentControl,
  AgentControlBlockedError,
  createAnthropicAdapter,
  createLangChainAdapter,
  createOpenAIAgentsAdapter,
  createOpenClawAdapter,
} = require("../dist/index.js");

const policyPath = process.env.ACS_SMOKE_POLICY ?? fileURLToPath(new URL("../../../tests/fixtures/smoke/manifest.yaml", import.meta.url));

function control() {
  return AgentControl.fromPath(policyPath);
}

async function assertBlockedBy(point, fn) {
  await assert.rejects(
    fn,
    (error) => error instanceof AgentControlBlockedError && error.result.verdict.reason === `${point}_sentinel_detected`,
  );
}

test("LangChain real RunnableLambda is enforced through the real adapter", async () => {
  const { RunnableLambda } = await import("@langchain/core/runnables");
  let calls = 0;
  let response = "safe response";
  const runnable = RunnableLambda.from(async (input) => {
    calls += 1;
    return response;
  });
  const guarded = createLangChainAdapter(control()).guard(runnable);

  assert.equal(await guarded.invoke("benign"), "safe response");
  await assertBlockedBy("input", () => guarded.invoke("BLOCKME"));
  assert.equal(calls, 1);

  response = "BLOCKME";
  await assertBlockedBy("post_model_call", () => guarded.invoke("benign"));
});

test("OpenAI Agents real Agent and Runner are enforced through the real adapter", async () => {
  const { default: OpenAI } = await import("openai");
  const { Agent, OpenAIChatCompletionsModel, Runner } = await import("@openai/agents");
  let calls = 0;
  let text = "safe response";
  const client = new OpenAI({
    apiKey: "test-key",
    baseURL: "https://example.invalid/v1",
    maxRetries: 0,
    fetch: async (_url, init) => {
      calls += 1;
      assert.ok(String(init.body).includes("benign"));
      return new Response(JSON.stringify({
        id: "chatcmpl_test",
        object: "chat.completion",
        created: 0,
        model: "gpt-test",
        choices: [{ index: 0, message: { role: "assistant", content: text }, finish_reason: "stop" }],
        usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 },
      }), { status: 200, headers: { "content-type": "application/json" } });
    },
  });
  const model = new OpenAIChatCompletionsModel(client, "gpt-test");
  const agent = new Agent({ name: "acs-real-openai-agent", instructions: "echo", model });
  const runner = new Runner({ tracingDisabled: true });
  const guarded = createOpenAIAgentsAdapter(control()).wrapRunner(runner);

  const allowed = await guarded.run(agent, "benign", { maxTurns: 1 });
  assert.equal(allowed.finalOutput, "safe response");
  await assertBlockedBy("input", () => guarded.run(agent, "BLOCKME", { maxTurns: 1 }));
  assert.equal(calls, 1);

  text = "BLOCKME";
  await assertBlockedBy("post_model_call", () => guarded.run(agent, "benign", { maxTurns: 1 }));
});

test("Anthropic real client is enforced through the real adapter", async () => {
  const { default: Anthropic } = await import("@anthropic-ai/sdk");
  let calls = 0;
  let text = "safe response";
  const client = new Anthropic({
    apiKey: "test-key",
    maxRetries: 0,
    fetch: async () => {
      calls += 1;
      return new Response(JSON.stringify({
        id: "msg_test",
        type: "message",
        role: "assistant",
        model: "claude-test",
        content: [{ type: "text", text }],
        stop_reason: "end_turn",
        stop_sequence: null,
        usage: { input_tokens: 1, output_tokens: 1 },
      }), { status: 200, headers: { "content-type": "application/json" } });
    },
  });
  const guarded = createAnthropicAdapter(control()).wrapClient(client);
  const request = { model: "claude-3-haiku-20240307", max_tokens: 16, messages: [{ role: "user", content: "benign" }] };

  assert.equal((await guarded.messages.create(request)).content[0].text, "safe response");
  await assertBlockedBy("input", () => guarded.messages.create({ ...request, messages: [{ role: "user", content: "BLOCKME" }] }));
  assert.equal(calls, 1);

  text = "BLOCKME";
  await assertBlockedBy("post_model_call", () => guarded.messages.create(request));
});

test("OpenClaw real plugin entry registers ACS hooks that enforce through the real adapter", async () => {
  const { definePluginEntry } = await import("openclaw/plugin-sdk/core");
  const hooks = new Map();
  const adapterPlugin = createOpenClawAdapter(control()).plugin();
  const pluginEntry = definePluginEntry({
    id: "acs-real-openclaw",
    name: "ACS real OpenClaw test",
    description: "ACS real OpenClaw hook registration test",
    register(api) {
      adapterPlugin.register(api);
    },
  });
  pluginEntry.register({ on: (hookName, handler) => hooks.set(hookName, handler) });

  await hooks.get("session_start")({ sessionId: "safe-session" }, {});
  await assertBlockedBy("agent_startup", () => hooks.get("session_start")({ sessionId: "BLOCKME" }, {}));

  assert.deepEqual(await hooks.get("before_agent_run")({ prompt: "benign", messages: [] }, {}), { outcome: "pass" });
  await assertBlockedBy("input", () => hooks.get("before_agent_run")({ prompt: "BLOCKME", messages: [] }, {}));

  await hooks.get("llm_input")({ prompt: "benign" }, {});
  await assertBlockedBy("pre_model_call", () => hooks.get("llm_input")({ prompt: "BLOCKME" }, {}));

  await hooks.get("llm_output")({ text: "benign" }, {});
  await assertBlockedBy("post_model_call", () => hooks.get("llm_output")({ text: "BLOCKME" }, {}));

  assert.deepEqual(
    await hooks.get("before_tool_call")({ toolName: "echo_tool", params: { q: "benign" }, toolCallId: "tool-1" }, {}),
    { params: { q: "benign" } },
  );
  await assertBlockedBy("pre_tool_call", () =>
    hooks.get("before_tool_call")({ toolName: "echo_tool", params: { q: "BLOCKME" }, toolCallId: "tool-2" }, {}),
  );

  await hooks.get("after_tool_call")({ toolName: "echo_tool", params: {}, result: "benign", toolCallId: "tool-3" }, {});
  await assertBlockedBy("post_tool_call", () =>
    hooks.get("after_tool_call")({ toolName: "echo_tool", params: {}, result: "BLOCKME", toolCallId: "tool-4" }, {}),
  );

  await hooks.get("before_agent_finalize")({ text: "benign" }, {});
  await assertBlockedBy("output", () => hooks.get("before_agent_finalize")({ text: "BLOCKME" }, {}));

  await hooks.get("session_end")({ sessionId: "safe-session", messageCount: 1 }, {});
  await assertBlockedBy("agent_shutdown", () => hooks.get("session_end")({ sessionId: "BLOCKME", messageCount: 1 }, {}));
});
