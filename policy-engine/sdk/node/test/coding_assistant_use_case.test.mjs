import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
const assert = require("node:assert/strict");
const test = require("node:test");
const {
  AgentControl,
  AgentControlBlockedError,
  ApprovalResolution,
  Decision,
  InterventionPoint,
  actionIdentity,
  assembleSseStream,
  runModel,
  runModelStream,
  wrapMcpToolProvider,
} = require("../dist/index.js");

const manifest = `agent_control_specification_version: 0.3.1-beta
metadata:
  name: coding-assistant-node-use-case
policies:
  coding_policy:
    type: custom
    adapter: coding_mock
intervention_points:
  pre_model_call:
    policy_target_kind: model_request
    policy:
      id: coding_policy
    policy_target: $.model_request
    annotations:
      prompt_normalizer:
        from: $policy_target.prompt
  post_model_call:
    policy_target_kind: model_response
    policy:
      id: coding_policy
    policy_target: $.model_response
  pre_tool_call:
    policy_target_kind: tool_args
    tool_name_from: $.tool_call.name
    policy:
      id: coding_policy
    policy_target: $.tool_call.args
    annotations:
      command_normalizer:
        from: $policy_target.command
  post_tool_call:
    policy_target_kind: tool_result
    tool_name_from: $.tool_call.name
    policy:
      id: coding_policy
    policy_target: $.tool_result
tools:
  shell:
    type: Tool
  file_write:
    type: Tool
annotators:
  prompt_normalizer:
    type: classifier
  command_normalizer:
    type: classifier`;

function chatChunk(content, id = "cmpl-use-case") {
  return Buffer.from(
    `data: {"id":"${id}","object":"chat.completion.chunk","created":1,"model":"gpt-x","choices":[{"index":0,"delta":{"role":"assistant"},"finish_reason":null}]}\n\n` +
    `data: {"id":"${id}","object":"chat.completion.chunk","created":1,"model":"gpt-x","choices":[{"index":0,"delta":{"content":${JSON.stringify(content)}},"finish_reason":null}]}\n\n` +
    `data: {"id":"${id}","object":"chat.completion.chunk","created":1,"model":"gpt-x","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}\n\n` +
    "data: [DONE]\n\n",
  );
}

function contentOf(response) {
  return response.choices[0].message.content;
}

function redactedResponse(response, replacement) {
  const clone = JSON.parse(JSON.stringify(response));
  clone.choices[0].message.content = replacement;
  return clone;
}

function targetOf(invocation) {
  return invocation.input.policy_target.value;
}

function pointOf(invocation) {
  return invocation.input.intervention_point;
}

function decision(decisionValue, extra = {}) {
  return { decision: decisionValue, ...extra };
}

// AGT D1.1: TRANSFORM with a single-target transform payload is the
// canonical mutation path. The pre-AGT `effects: [{ type: 'replace',
// path: '$policy_target', value }]` shape is rejected by the strict
// runtime per 1d8fcb64, so this helper now produces the transform
// payload directly.
function rootTransform(value) {
  return { path: "$policy_target", value };
}

function makeCodingControl({ approvalResolver, annotatorDelay = async () => {}, policyOverride } = {}) {
  const invocations = [];
  const annotations = [];
  const control = AgentControl.fromNative(
    manifest,
    {
      async dispatch(annotatorName, _annotatorConfig, preliminaryPolicyInput) {
        await annotatorDelay(annotatorName, preliminaryPolicyInput);
        const value = preliminaryPolicyInput.policy_target.value;
        if (annotatorName === "command_normalizer") {
          const normalized = String(value?.command ?? value ?? "").trim().replace(/\s+/g, " ").toLowerCase();
          annotations.push({ annotatorName, normalized });
          return { normalized_command: normalized };
        }
        const normalized = String(value?.prompt ?? value ?? "").replace(/SECRET_PROMPT/g, "[REDACTED_PROMPT]");
        annotations.push({ annotatorName, normalized });
        return { normalized_prompt: normalized };
      },
    },
    {
      async evaluate(invocation) {
        invocations.push(invocation);
        if (policyOverride) return policyOverride(invocation);
        const point = pointOf(invocation);
        const target = targetOf(invocation);
        if (point === InterventionPoint.PreModelCall) {
          const normalizedPrompt = invocation.input.annotations.prompt_normalizer.normalized_prompt;
          if (String(target.prompt ?? "").includes("SECRET_PROMPT")) {
            assert.equal(normalizedPrompt.includes("SECRET_PROMPT"), false);
            return decision(Decision.Transform, {
              reason: "prompt_redacted",
              transform: rootTransform({ ...target, prompt: normalizedPrompt }),
            });
          }
          return decision(Decision.Allow);
        }
        if (point === InterventionPoint.PostModelCall) {
          const content = contentOf(target);
          if (content.includes("needs human approval")) {
            return decision(Decision.Escalate, { reason: "sensitive_model_action" });
          }
          if (content.includes("ghp_secret123")) {
            return decision(Decision.Transform, {
              reason: "secret_redacted",
              transform: rootTransform(redactedResponse(target, content.replace(/ghp_secret123/g, "[REDACTED]"))),
            });
          }
          return decision(Decision.Allow);
        }
        if (point === InterventionPoint.PreToolCall) {
          const normalizedCommand = invocation.input.annotations.command_normalizer.normalized_command;
          if (normalizedCommand.includes("rm -rf")) {
            return decision(Decision.Deny, { reason: "dangerous_command" });
          }
          if (normalizedCommand === "cat sensitive.txt") {
            return decision(Decision.Escalate, { reason: "sensitive_file_read" });
          }
          if (target.env?.TOKEN === "ghp_secret123") {
            return decision(Decision.Transform, {
              reason: "tool_secret_redacted",
              transform: rootTransform({ ...target, env: { ...target.env, TOKEN: "[REDACTED]" } }),
            });
          }
          return decision(Decision.Allow);
        }
        if (point === InterventionPoint.PostToolCall) {
          if (String(target.stdout ?? "").includes("internal")) {
            return decision(Decision.Transform, {
              reason: "tool_output_redacted",
              transform: rootTransform({ ...target, stdout: String(target.stdout).replace(/internal/g, "[redacted]") }),
            });
          }
          return decision(Decision.Allow);
        }
        return decision(Decision.Allow);
      },
    },
    approvalResolver,
  );
  return { control, invocations, annotations };
}

function assertRuntimeBlock(error) {
  assert.ok(error instanceof AgentControlBlockedError);
  assert.match(error.result.verdict.reason, /^runtime_error/);
  return true;
}

test("coding assistant stream redacts model output before guarded tool dispatch", async () => {
  const { control, invocations, annotations } = makeCodingControl();
  let modelSawRequest;
  const streamResult = await runModelStream(control, { prompt: "fix bug with SECRET_PROMPT" }, (request) => {
    modelSawRequest = request;
    return chatChunk("Use shell TOKEN=[REDACTED] and never reveal ghp_secret123");
  });

  assert.deepEqual(modelSawRequest, { prompt: "fix bug with [REDACTED_PROMPT]" });
  const transformedResponse = streamResult.value;
  assert.equal(contentOf(transformedResponse).includes("ghp_secret123"), false);
  assert.equal(Buffer.from(streamResult.bytes).includes("ghp_secret123"), false);
  assert.equal(contentOf(assembleSseStream(streamResult.bytes)), "Use shell TOKEN=[REDACTED] and never reveal [REDACTED]");

  let toolSawArgs;
  const toolResult = await control.runTool(
    "shell",
    { command: "echo safe", env: { TOKEN: contentOf(transformedResponse).includes("[REDACTED]") ? "[REDACTED]" : "ghp_secret123" } },
    (args) => {
      toolSawArgs = args;
      return { stdout: "safe internal note" };
    },
    { toolCallId: "shell-redacted" },
  );
  assert.deepEqual(toolSawArgs.env, { TOKEN: "[REDACTED]" });
  assert.deepEqual(toolResult.value, { stdout: "safe [redacted] note" });
  assert.deepEqual(invocations.map(pointOf), [
    InterventionPoint.PreModelCall,
    InterventionPoint.PostModelCall,
    InterventionPoint.PreToolCall,
    InterventionPoint.PostToolCall,
  ]);
  assert.deepEqual(annotations.map((entry) => entry.annotatorName), ["prompt_normalizer", "command_normalizer"]);
});

test("coding assistant denies dangerous tools and escalates sensitive actions", async () => {
  let approvalContext;
  const { control } = makeCodingControl({
    approvalResolver(point, result) {
      approvalContext = { point, policyInput: result.policyInput, actionIdentity: result.actionIdentity };
      assert.equal(result.actionIdentity, actionIdentity(result.policyInput));
      return ApprovalResolution.allow(result.actionIdentity);
    },
  });

  let dangerousExecuted = false;
  await assert.rejects(
    () => control.runTool("shell", { command: "rm -rf /" }, () => { dangerousExecuted = true; return {}; }, { toolCallId: "deny-rm" }),
    (error) => {
      assert.ok(error instanceof AgentControlBlockedError);
      assert.equal(error.result.verdict.reason, "dangerous_command");
      return true;
    },
  );
  assert.equal(dangerousExecuted, false);

  const approved = await control.runTool("shell", { command: "cat sensitive.txt" }, () => ({ stdout: "approved" }), { toolCallId: "escalate-cat" });
  assert.deepEqual(approved.value, { stdout: "approved" });
  assert.equal(approvalContext.point, InterventionPoint.PreToolCall);
  assert.equal(approvalContext.policyInput.policy_target.value.command, "cat sensitive.txt");

  const rejectedControl = makeCodingControl({ approvalResolver: () => ApprovalResolution.deny() }).control;
  let first;
  await assert.rejects(
    () => rejectedControl.runTool("shell", { command: "cat sensitive.txt" }, () => ({ stdout: "never" }), { toolCallId: "reject-cat" }),
    (error) => {
      first = error;
      return error instanceof AgentControlBlockedError;
    },
  );
  let second;
  await assert.rejects(
    () => rejectedControl.runTool("shell", { command: "cat sensitive.txt" }, () => ({ stdout: "never" }), { toolCallId: "reject-cat" }),
    (error) => {
      second = error;
      return error instanceof AgentControlBlockedError;
    },
  );
  assert.equal(first.result.actionIdentity, second.result.actionIdentity);
});

test("MCP tool provider receives transformed arguments and returns transformed results", async () => {
  const { control } = makeCodingControl();
  let providerSawRequest;
  const provider = {
    async callTool(request) {
      providerSawRequest = request;
      return { stdout: `wrote ${request.arguments.path} with internal marker` };
    },
  };
  const wrapped = wrapMcpToolProvider(control, provider, { toolCallId: "mcp-file" });
  const result = await wrapped.callTool({
    name: "file_write",
    arguments: { command: "write file", path: "README.md", env: { TOKEN: "ghp_secret123" } },
  });
  assert.equal(providerSawRequest.arguments.env.TOKEN, "[REDACTED]");
  assert.deepEqual(result, { stdout: "wrote README.md with [redacted] marker" });
});

test("runtime and streaming failures fail closed without releasing stream bytes", async () => {
  const policyFailure = makeCodingControl({ policyOverride: () => { throw new Error("policy boom"); } }).control;
  await assert.rejects(() => runModel(policyFailure, { prompt: "x" }, () => ({ text: "never" })), assertRuntimeBlock);

  const invalidPolicy = makeCodingControl({ policyOverride: () => ({ decision: "bogus" }) }).control;
  await assert.rejects(() => runModel(invalidPolicy, { prompt: "x" }, () => ({ text: "never" })), assertRuntimeBlock);

  const serializationFailure = makeCodingControl({ policyOverride: () => ({ decision: Decision.Allow, unserializable: 1n }) }).control;
  await assert.rejects(() => runModel(serializationFailure, { prompt: "x" }, () => ({ text: "never" })), assertRuntimeBlock);

  const approvalThrowing = makeCodingControl({ approvalResolver: () => { throw new Error("approval boom"); } }).control;
  await assert.rejects(
    () => approvalThrowing.runTool("shell", { command: "cat sensitive.txt" }, () => ({ stdout: "never" }), { toolCallId: "approval-throws" }),
    (error) => {
      assert.ok(error instanceof AgentControlBlockedError);
      assert.ok(error.cause instanceof Error);
      assert.equal(error.cause.message, "approval boom");
      return true;
    },
  );

  const upstreamFailure = makeCodingControl().control;
  await assert.rejects(
    () => runModelStream(upstreamFailure, { prompt: "x" }, async function* () {
      yield Buffer.from("data: ");
      throw new Error("upstream ended early");
    }),
    (error) => {
      assert.ok(error instanceof AgentControlBlockedError);
      assert.equal(error.result.verdict.message, "Streaming response failed closed.");
      return true;
    },
  );
});

test("concurrent streams keep buffers, approvals, and annotator state isolated", async () => {
  const approvals = [];
  const { control, annotations } = makeCodingControl({
    annotatorDelay: async (_name, preliminaryPolicyInput) => {
      if (String(preliminaryPolicyInput.policy_target.value).includes("slow")) {
        await new Promise((resolve) => setTimeout(resolve, 5));
      }
    },
    approvalResolver(point, result) {
      approvals.push({ point, content: contentOf(result.policyInput.policy_target.value) });
      return ApprovalResolution.allow(result.actionIdentity);
    },
  });

  const safeInput = chatChunk("safe response", "cmpl-safe");
  const sensitiveInput = chatChunk("needs human approval for deploy", "cmpl-sensitive");
  const [safe, sensitive] = await Promise.all([
    runModelStream(control, { prompt: "safe" }, () => safeInput),
    runModelStream(control, { prompt: "slow sensitive" }, () => sensitiveInput),
  ]);

  assert.equal(Buffer.compare(Buffer.from(safe.bytes), safeInput), 0);
  assert.equal(Buffer.compare(Buffer.from(sensitive.bytes), sensitiveInput), 0);
  assert.deepEqual(approvals, [{ point: InterventionPoint.PostModelCall, content: "needs human approval for deploy" }]);
  assert.equal(annotations.filter((entry) => entry.annotatorName === "prompt_normalizer").length, 2);
});

test("supplied tool ids flow unchanged through pre and post tool mediation", async () => {
  const { control, invocations } = makeCodingControl();
  const first = await control.runTool(
    "shell",
    { command: "echo unicode", nested: { value: "\u03bb" } },
    (args) => ({ stdout: args.nested.value }),
    { toolCallId: "call-unicode-1" },
  );
  const second = await control.runTool(
    "shell",
    { nested: { value: "\u03bb" }, command: "echo unicode" },
    (args) => ({ stdout: args.nested.value }),
    { toolCallId: "call-unicode-2" },
  );

  const [firstPre, firstPost, secondPre] = invocations;
  assert.equal(firstPre.input.snapshot.tool_call.id, "call-unicode-1");
  assert.equal(firstPost.input.snapshot.tool_call.id, "call-unicode-1");
  assert.equal(secondPre.input.snapshot.tool_call.id, "call-unicode-2");
  assert.equal(first.preToolCallResult.policyInput.snapshot.tool_call.id, "call-unicode-1");
  assert.equal(first.preToolCallResult.actionIdentity, actionIdentity(first.preToolCallResult.policyInput));
  assert.deepEqual(first.value, { stdout: "\u03bb" });
  assert.deepEqual(second.value, { stdout: "\u03bb" });
});

test("tool callback exceptions propagate to the caller without post tool mediation", async () => {
  const { control, invocations } = makeCodingControl();
  const callbackError = new Error("disk failed");
  await assert.rejects(
    () => control.runTool("shell", { command: "echo safe" }, () => { throw callbackError; }, { toolCallId: "callback-throws" }),
    (error) => {
      assert.equal(error, callbackError);
      assert.equal(error instanceof AgentControlBlockedError, false);
      return true;
    },
  );
  assert.deepEqual(invocations.map(pointOf), [InterventionPoint.PreToolCall]);
});

test("omitting the tool_call_id evaluates with tool_call.id omitted from the snapshot", async () => {
  const { control, invocations } = makeCodingControl();
  const result = await control.runTool("shell", { command: "echo safe" }, () => ({ stdout: "ok" }));

  assert.equal(result.value.stdout, "ok");
  assert.deepEqual(invocations.map(pointOf), [InterventionPoint.PreToolCall, InterventionPoint.PostToolCall]);
  assert.equal("id" in invocations[0].input.snapshot.tool_call, false);
  assert.equal("id" in invocations[1].input.snapshot.tool_call, false);
});

test("a blank tool_call_id is rejected before any mediation runs", async () => {
  const { control, invocations } = makeCodingControl();
  await assert.rejects(
    () => control.runTool("shell", { command: "echo safe" }, () => ({ stdout: "never" }), { toolCallId: "" }),
    (error) => {
      assert.equal(error instanceof AgentControlBlockedError, false);
      assert.match(String(error.message), /non-empty/i);
      return true;
    },
  );
  assert.deepEqual(invocations, []);
});
