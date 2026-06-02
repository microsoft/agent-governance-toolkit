import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
const require = createRequire(import.meta.url);
const assert = require("node:assert/strict");
const test = require("node:test");
const {
  AgentControl,
  AgentControlBlockedError,
  AgentControlSuspendedError,
  ApprovalResolution,
  Decision,
  actionIdentity,
  assembleSseStream,
  runModelStream,
  synthesizeSseStream,
} = require("../dist/index.js");

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, "../../..");
const fixtureRoot = resolve(repoRoot, "tests/conformance/streaming");
const manifest = JSON.parse(readFileSync(resolve(fixtureRoot, "manifest.json"), "utf8"));
const limits = {
  maxStreamBytes: manifest.limits.max_stream_bytes,
  maxStreamEvents: manifest.limits.max_stream_events,
};

class StubRuntimeClient {
  constructor(handler) {
    this.handler = handler;
  }

  async evaluateInterventionPoint(request) {
    const result = await this.handler(request);
    return { verdict: result.verdict ?? { decision: Decision.Allow }, ...result };
  }
}

function allowControl() {
  return new AgentControl(new StubRuntimeClient(() => ({ verdict: { decision: Decision.Allow } })));
}

function transformedControl(transformedPolicyTarget) {
  // AGT D1: TRANSFORM is the only mutating decision; pre-AGT this used
  // Decision.Warn which is now a non-mutating verdict under AGT.
  return new AgentControl(new StubRuntimeClient(({ interventionPoint }) => ({
    verdict: { decision: interventionPoint === "post_model_call" ? Decision.Transform : Decision.Allow },
    ...(interventionPoint === "post_model_call" ? { transformedPolicyTarget } : {}),
  })));
}

function readFixture(relativePath) {
  return readFileSync(resolve(fixtureRoot, relativePath));
}

function errorMessage(error) {
  return error?.result?.verdict?.message ?? String(error?.message ?? error);
}

test("streaming conformance assemble cases and verbatim allow re-emission", async () => {
  assert.ok(manifest.assemble.length >= 14);
  let asserted = 0;
  for (const caseDef of manifest.assemble) {
    const input = readFixture(caseDef.input);
    if (caseDef.outcome === "ok") {
      const assembled = assembleSseStream(input, limits);
      assert.deepEqual(assembled, caseDef.assembled, caseDef.name);
      const result = await runModelStream(allowControl(), { messages: [] }, () => input, limits);
      assert.deepEqual(result.assembledResponse, caseDef.assembled, caseDef.name);
      assert.equal(Buffer.compare(Buffer.from(result.bytes), input), 0, caseDef.name);
    } else {
      assert.throws(() => assembleSseStream(input, limits), (error) => {
        assert.equal(error.message, caseDef.error_message, caseDef.name);
        return true;
      });
      await assert.rejects(
        () => runModelStream(allowControl(), { messages: [] }, () => input, limits),
        (error) => {
          assert.ok(error instanceof AgentControlBlockedError, caseDef.name);
          assert.equal(errorMessage(error), caseDef.error_message, caseDef.name);
          return true;
        },
      );
    }
    asserted += 1;
  }
  assert.equal(asserted, manifest.assemble.length);
});

test("streaming conformance synthesized transforms match fixtures", async () => {
  assert.equal(manifest.synthesize.length, 2);
  let asserted = 0;
  for (const caseDef of manifest.synthesize) {
    const expected = readFixture(caseDef.expected_output);
    const direct = synthesizeSseStream(caseDef.response, caseDef.template);
    assert.equal(Buffer.compare(Buffer.from(direct), expected), 0, caseDef.name);

    const source = readFixture("inputs/allow_text_only.sse");
    const result = await runModelStream(transformedControl(caseDef.response), { messages: [] }, () => source, limits);
    assert.equal(Buffer.compare(Buffer.from(result.bytes), expected), 0, caseDef.name);
    asserted += 1;
  }
  assert.equal(asserted, manifest.synthesize.length);
});

test("streaming conformance limits are enforced", async () => {
  const input = readFixture("inputs/allow_text_only.sse");
  assert.throws(
    () => assembleSseStream(input, { maxStreamBytes: input.byteLength - 1, maxStreamEvents: limits.maxStreamEvents }),
    /Streaming response exceeded the buffering byte limit/,
  );
  assert.throws(
    () => assembleSseStream(input, { maxStreamBytes: limits.maxStreamBytes, maxStreamEvents: 0 }),
    /Streaming response exceeded the buffered event limit/,
  );
  await assert.rejects(
    () => runModelStream(allowControl(), { messages: [] }, async function* () { yield input.subarray(0, 1); yield input.subarray(1); }, { maxStreamBytes: input.byteLength - 1 }),
    (error) => {
      assert.ok(error instanceof AgentControlBlockedError);
      assert.equal(errorMessage(error), "Streaming response exceeded the buffering byte limit.");
      return true;
    },
  );
});

test("streaming preserves suspended escalation handles", async () => {
  const policyInput = { intervention_point: "post_model_call", snapshot: { model_response: "pending" } };
  const identity = actionIdentity(policyInput);
  const control = new AgentControl(
    new StubRuntimeClient(({ interventionPoint }) => interventionPoint === "post_model_call"
      ? {
        verdict: { decision: Decision.Escalate, reason: "human_review" },
        policyInput,
        actionIdentity: identity,
      }
      : { verdict: { decision: Decision.Allow } }),
    () => ApprovalResolution.suspend({ ticket: "T-1" }, identity),
  );

  await assert.rejects(
    () => runModelStream(control, { messages: [] }, () => readFixture("inputs/allow_text_only.sse"), limits),
    (error) => {
      assert.ok(error instanceof AgentControlSuspendedError);
      assert.deepEqual(error.handle, { ticket: "T-1" });
      return true;
    },
  );
});
