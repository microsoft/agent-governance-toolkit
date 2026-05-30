#!/usr/bin/env node
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const {
  AgentControl,
  AgentControlBlockedError,
  createAnthropicAdapter,
  createLangChainAdapter,
  createOpenAIAgentsAdapter,
  createOpenClawAdapter,
} = require("../dist/index.js");

const manifest = process.env.ACS_SMOKE_POLICY ?? fileURLToPath(new URL("../../../tests/fixtures/smoke/manifest.yaml", import.meta.url));

async function assertBlocked(point, fn) {
  await assert.rejects(
    fn,
    (error) => error instanceof AgentControlBlockedError && error.result.verdict.reason === `${point}_sentinel_detected`,
  );
}

async function runLangChainStandalone() {
  const { RunnableLambda } = await import("@langchain/core/runnables");
  let text = "safe response";
  const realRunnable = RunnableLambda.from(async () => text);

  const control = AgentControl.fromPath(manifest);
  const guarded = createLangChainAdapter(control).guard(realRunnable);

  assert.equal(await guarded.invoke("benign"), "safe response");
  await assertBlocked("input", () => guarded.invoke("BLOCKME"));
  text = "BLOCKME";
  await assertBlocked("post_model_call", () => guarded.invoke("benign"));
}

async function runOpenAIAgentsStandalone() {
  const { default: OpenAI } = await import("openai");
  const { Agent, OpenAIChatCompletionsModel, Runner } = await import("@openai/agents");
  let text = "safe response";
  const client = new OpenAI({
    apiKey: "test-key",
    baseURL: "https://example.invalid/v1",
    maxRetries: 0,
    fetch: async () => new Response(JSON.stringify({
      id: "chatcmpl_test",
      object: "chat.completion",
      created: 0,
      model: "gpt-test",
      choices: [{ index: 0, message: { role: "assistant", content: text }, finish_reason: "stop" }],
      usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 },
    }), { status: 200, headers: { "content-type": "application/json" } }),
  });
  const realAgent = new Agent({
    name: "acs-standalone-openai-agent",
    instructions: "echo",
    model: new OpenAIChatCompletionsModel(client, "gpt-test"),
  });
  const realRunner = new Runner({ tracingDisabled: true });

  const control = AgentControl.fromPath(manifest);
  const guardedRunner = createOpenAIAgentsAdapter(control).wrapRunner(realRunner);

  assert.equal((await guardedRunner.run(realAgent, "benign", { maxTurns: 1 })).finalOutput, "safe response");
  await assertBlocked("input", () => guardedRunner.run(realAgent, "BLOCKME", { maxTurns: 1 }));
  text = "BLOCKME";
  await assertBlocked("post_model_call", () => guardedRunner.run(realAgent, "benign", { maxTurns: 1 }));
}

async function runAnthropicStandalone() {
  const { default: Anthropic } = await import("@anthropic-ai/sdk");
  let text = "safe response";
  const realClient = new Anthropic({
    apiKey: "test-key",
    maxRetries: 0,
    fetch: async () => new Response(JSON.stringify({
      id: "msg_test",
      type: "message",
      role: "assistant",
      model: "claude-test",
      content: [{ type: "text", text }],
      stop_reason: "end_turn",
      stop_sequence: null,
      usage: { input_tokens: 1, output_tokens: 1 },
    }), { status: 200, headers: { "content-type": "application/json" } }),
  });
  const request = { model: "claude-3-haiku-20240307", max_tokens: 16, messages: [{ role: "user", content: "benign" }] };

  const control = AgentControl.fromPath(manifest);
  const guardedClient = createAnthropicAdapter(control).wrapClient(realClient);

  assert.equal((await guardedClient.messages.create(request)).content[0].text, "safe response");
  await assertBlocked("input", () =>
    guardedClient.messages.create({ ...request, messages: [{ role: "user", content: "BLOCKME" }] }),
  );
  text = "BLOCKME";
  await assertBlocked("post_model_call", () => guardedClient.messages.create(request));
}

async function runOpenClawStandalone() {
  const { definePluginEntry } = await import("openclaw/plugin-sdk/core");
  const hooks = new Map();

  const control = AgentControl.fromPath(manifest);
  const acs = createOpenClawAdapter(control).plugin();

  const realPluginEntry = definePluginEntry({
    id: "acs-standalone-openclaw",
    name: "ACS standalone OpenClaw",
    description: "ACS standalone OpenClaw adapter proof",
    register(api) {
      acs.register(api);
    },
  });
  realPluginEntry.register({ on: (hookName, handler) => hooks.set(hookName, handler) });

  await hooks.get("before_agent_run")({ prompt: "benign", messages: [] }, {});
  await assertBlocked("input", () => hooks.get("before_agent_run")({ prompt: "BLOCKME", messages: [] }, {}));
  await hooks.get("llm_input")({ prompt: "benign" }, {});
  await assertBlocked("pre_model_call", () => hooks.get("llm_input")({ prompt: "BLOCKME" }, {}));
  await hooks.get("llm_output")({ text: "benign" }, {});
  await assertBlocked("post_model_call", () => hooks.get("llm_output")({ text: "BLOCKME" }, {}));
}

await runLangChainStandalone();
await runOpenAIAgentsStandalone();
await runAnthropicStandalone();
await runOpenClawStandalone();
console.log("standalone real framework adapter proof passed");
