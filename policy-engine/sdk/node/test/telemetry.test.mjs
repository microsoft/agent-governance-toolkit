// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
const assert = require("node:assert/strict");
const test = require("node:test");
const {
  AgentControl,
  Decision,
  EnforcementMode,
  InMemoryTelemetrySink,
  InterventionPoint,
  MultiSink,
  OtelMetricsTelemetrySink,
  PerfTelemetry,
  TelemetryEvent,
  TelemetryEventType,
  errorClassFor,
  safeReasonCode,
} = require("../dist/index.js");

class StubRuntimeClient {
  constructor(handler) {
    this.handler = handler;
    this.requests = [];
  }

  async evaluateInterventionPoint(request) {
    this.requests.push(request);
    return this.handler(request);
  }
}

class RaisingSink {
  emit() {
    throw new Error("sink boom");
  }

  forceFlush() {}

  shutdown() {}
}

function makeControl(handler, telemetrySink) {
  return new AgentControl(new StubRuntimeClient(handler), undefined, telemetrySink);
}

async function captureWarnings(body) {
  const warnings = [];
  const originalWarn = console.warn;
  console.warn = (...args) => {
    warnings.push(args);
  };
  try {
    return { value: await body(), warnings };
  } finally {
    console.warn = originalWarn;
  }
}

test("emits exactly one redaction-safe decision event per evaluation", async () => {
  const sink = new InMemoryTelemetrySink();
  const control = makeControl(
    () => ({
      verdict: {
        decision: Decision.Warn,
        reason: "rate_limited",
        evidence: {
          artefact: "sha256:proofblob",
          verificationPointers: {
            policy_registry: "https://registry.example/policy",
            issuer_pubkey: "https://keys.example/issuer",
          },
        },
      },
      policyInput: {
        annotations: {
          prompt_classifier: { value: "withheld" },
          pii_scan: { value: "withheld" },
        },
      },
      actionIdentity: "sha256:deadbeef",
    }),
    sink,
  );

  const result = await control.evaluateInterventionPoint(
    InterventionPoint.PreToolCall,
    { tool_call: { name: "search", args: { q: "secret" } } },
  );

  assert.equal(result.verdict.decision, Decision.Warn);
  assert.equal(sink.events.length, 1);
  const event = sink.events[0];
  assert.equal(event.eventType, TelemetryEventType.Decision);
  assert.equal(event.interventionPoint, InterventionPoint.PreToolCall);
  assert.equal(event.decision, Decision.Warn);
  assert.equal(event.reasonCode, "rate_limited");
  assert.equal(event.errorClass, null);
  assert.equal(event.enforcementMode, EnforcementMode.Enforce);
  assert.equal(event.actionIdentity, "sha256:deadbeef");
  assert.equal(event.evidenceArtefact, "sha256:proofblob");
  assert.deepEqual(event.evidenceVerificationPointerKeys, ["issuer_pubkey", "policy_registry"]);
  assert.deepEqual(event.annotators, ["pii_scan", "prompt_classifier"]);
  assert.equal(typeof event.durationMs, "number");
  assert.ok(event.durationMs >= 0);
});

test("InMemoryTelemetrySink captures allow deny warn escalate and transform", async () => {
  const decisions = [
    Decision.Allow,
    Decision.Deny,
    Decision.Warn,
    Decision.Escalate,
    Decision.Transform,
  ];
  const sink = new InMemoryTelemetrySink();
  const control = makeControl(
    () => ({ verdict: { decision: decisions[sink.events.length] } }),
    sink,
  );

  for (const _decision of decisions) {
    await control.evaluateInterventionPoint(
      InterventionPoint.Input,
      { input: { text: "hi" } },
      EnforcementMode.EvaluateOnly,
    );
  }

  assert.deepEqual(sink.events.map((event) => event.decision), decisions);
  assert.deepEqual(sink.events.map((event) => event.eventType), decisions.map(() => TelemetryEventType.Decision));
});

test("TelemetryEvent redacts policy target payloads and pointer URL values", async () => {
  const rawPrompt = "ATTACK leak this secret prompt";
  const pointerUrl = "https://registry.example/secret-path";
  const sink = new InMemoryTelemetrySink();
  const control = makeControl(
    () => ({
      verdict: {
        decision: Decision.Deny,
        reason: `blocked because the input was unsafe ${rawPrompt}`,
        message: `human readable ${rawPrompt}`,
        evidence: {
          artefact: "sha256:safe",
          verificationPointers: { policy_registry: pointerUrl },
        },
      },
      policyInput: {
        policy_target: { value: { text: rawPrompt } },
        snapshot: { input: { text: rawPrompt } },
        annotations: { classifier: { verdict: rawPrompt } },
      },
      actionIdentity: "sha256:abc",
    }),
    sink,
  );

  await control.evaluateInterventionPoint(InterventionPoint.Input, {
    input: { text: rawPrompt },
  });

  const event = sink.events[0].toObject();
  assert.deepEqual(Object.keys(event).sort(), [
    "actionIdentity",
    "annotators",
    "decision",
    "durationMs",
    "enforcementMode",
    "errorClass",
    "eventType",
    "evidenceArtefact",
    "evidenceVerificationPointerKeys",
    "interventionPoint",
    "metadata",
    "policyId",
    "reasonCode",
  ]);
  assert.equal(event.reasonCode, "policy_reason");
  assert.equal(event.errorClass, null);
  assert.deepEqual(event.evidenceVerificationPointerKeys, ["policy_registry"]);
  const serialized = JSON.stringify(event);
  assert.doesNotMatch(serialized, /ATTACK/);
  assert.doesNotMatch(serialized, /secret prompt/);
  assert.doesNotMatch(serialized, /registry\.example/);
  assert.doesNotMatch(serialized, new RegExp(pointerUrl.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
});

test("safeReasonCode and errorClassFor mirror the core redaction rules", () => {
  assert.equal(safeReasonCode("runtime_error:request_invalid"), "runtime_error:request_invalid");
  assert.equal(safeReasonCode("account_number_redacted"), "account_number_redacted");
  assert.equal(safeReasonCode("blocked because the input was unsafe"), "policy_reason");
  assert.equal(safeReasonCode("a".repeat(97)), "policy_reason");
  assert.equal(safeReasonCode("café"), "policy_reason");
  assert.equal(safeReasonCode(null), null);
  assert.equal(errorClassFor("runtime_error:annotation_failed"), "runtime_error");
  assert.equal(errorClassFor("account_number_redacted"), null);
  assert.equal(errorClassFor(null), null);
});

test("a raising sink does not change the verdict or propagate", async () => {
  const result = { verdict: { decision: Decision.Allow, reason: "ok" } };
  const control = makeControl(() => result, new RaisingSink());

  const { value: returned, warnings } = await captureWarnings(() =>
    control.evaluateInterventionPoint(
      InterventionPoint.Output,
      { output: { text: "hi" } },
    ),
  );

  assert.equal(returned, result);
  assert.equal(returned.verdict.decision, Decision.Allow);
  assert.equal(warnings.length, 1);
});

test("MultiSink isolates a failing child sink", async () => {
  const good = new InMemoryTelemetrySink();
  const control = makeControl(
    () => ({ verdict: { decision: Decision.Allow } }),
    new MultiSink([new RaisingSink(), good]),
  );

  const { warnings } = await captureWarnings(() =>
    control.evaluateInterventionPoint(InterventionPoint.Input, { input: 1 }),
  );

  assert.equal(good.events.length, 1);
  assert.equal(warnings.length, 1);
});

test("telemetry construction errors are swallowed", async () => {
  const sink = new InMemoryTelemetrySink();
  const result = { verdict: { decision: Decision.Allow, reason: 123 } };
  const control = makeControl(() => result, sink);

  const { value: returned, warnings } = await captureWarnings(() =>
    control.evaluateInterventionPoint(InterventionPoint.Input, { input: 1 }),
  );

  assert.equal(returned, result);
  assert.equal(sink.events.length, 0);
  assert.equal(warnings.length, 1);
});

test("an invalid telemetry sink raises at construction", () => {
  assert.throws(
    () => new AgentControl(new StubRuntimeClient(() => ({ verdict: { decision: Decision.Allow } })), undefined, "not-a-sink"),
    TypeError,
  );
  assert.throws(
    () =>
      new AgentControl(
        new StubRuntimeClient(() => ({ verdict: { decision: Decision.Allow } })),
        undefined,
        [new InMemoryTelemetrySink(), {}],
      ),
    TypeError,
  );
});

test("the default no-sink path emits nothing and preserves the result", async () => {
  const result = { verdict: { decision: Decision.Allow } };
  const control = makeControl(() => result);
  let warned = false;
  const originalWarn = console.warn;
  console.warn = () => {
    warned = true;
  };
  try {
    const returned = await control.evaluateInterventionPoint(InterventionPoint.Input, { input: 1 });
    assert.equal(returned, result);
  } finally {
    console.warn = originalWarn;
  }
  assert.equal(warned, false);
});

test("fromNative indexes JSON manifest policy id and annotators", async () => {
  const manifest = {
    agent_control_specification_version: "0.3.1-beta",
    policies: {
      input_policy: {
        type: "custom",
        adapter: "unit_test",
      },
    },
    intervention_points: {
      input: {
        policy_target_kind: "user_input",
        policy: { id: "input_policy" },
        policy_target: "$.input",
        annotations: {
          pii_scan: { from: "$.input.text" },
          prompt_classifier: { from: "$.input.text" },
        },
      },
    },
    annotators: {
      pii_scan: { type: "classifier" },
      prompt_classifier: { type: "classifier" },
    },
  };
  const sink = new InMemoryTelemetrySink();
  const control = AgentControl.fromNative(
    manifest,
    {
      dispatch() {
        return { ok: true };
      },
    },
    {
      evaluate() {
        return { decision: Decision.Allow, reason: "ok" };
      },
    },
    undefined,
    PerfTelemetry.Off,
    sink,
  );

  await control.evaluateInterventionPoint(InterventionPoint.Input, {
    input: { text: "hello" },
  });

  assert.equal(sink.events[0].policyId, "input_policy");
  assert.deepEqual(sink.events[0].annotators, ["pii_scan", "prompt_classifier"]);
});

test("OtelMetricsTelemetrySink no-ops when @opentelemetry/api is absent", (t) => {
  try {
    require.resolve("@opentelemetry/api");
  } catch {
    const originalWarn = console.warn;
    console.warn = () => {};
    try {
      const sink = new OtelMetricsTelemetrySink();
      assert.equal(sink.available, false);
      sink.emit(new TelemetryEvent({
        eventType: TelemetryEventType.Decision,
        interventionPoint: InterventionPoint.Input,
        decision: Decision.Deny,
        durationMs: 1,
      }));
      sink.forceFlush();
      sink.shutdown();
    } finally {
      console.warn = originalWarn;
    }
    return;
  }
  t.skip("@opentelemetry/api is installed");
});

test("OtelMetricsTelemetrySink increments the decision counter when OpenTelemetry is present", (t) => {
  try {
    require.resolve("@opentelemetry/api");
  } catch {
    t.skip("@opentelemetry/api is not installed");
    return;
  }

  const added = [];
  const recorded = [];
  const provider = {
    getMeter(name) {
      assert.equal(name, "agent_control_specification");
      return {
        createCounter(metricName) {
          return {
            add(value, attributes) {
              added.push({ metricName, value, attributes });
            },
          };
        },
        createHistogram(metricName) {
          return {
            record(value, attributes) {
              recorded.push({ metricName, value, attributes });
            },
          };
        },
      };
    },
  };
  const sink = new OtelMetricsTelemetrySink("agent_control_specification", { meterProvider: provider });
  assert.equal(sink.available, true);

  sink.emit(new TelemetryEvent({
    eventType: TelemetryEventType.Decision,
    interventionPoint: InterventionPoint.PreToolCall,
    decision: Decision.Deny,
    reasonCode: "runtime_error:policy_invocation_failed",
    errorClass: "runtime_error",
    policyId: "content_policy",
    annotators: ["prompt_classifier"],
    enforcementMode: EnforcementMode.Enforce,
    durationMs: 3.2,
    evidenceArtefact: "sha256:proof",
    evidenceVerificationPointerKeys: ["issuer_pubkey"],
    actionIdentity: "sha256:identity",
  }));

  assert.equal(added.length, 1);
  assert.equal(added[0].metricName, "acs_intervention_deny_total");
  assert.equal(added[0].value, 1);
  assert.equal(added[0].attributes.actionIdentity, undefined);
  assert.equal(added[0].attributes.decision, "deny");
  assert.equal(added[0].attributes.reasonCode, "runtime_error:policy_invocation_failed");
  assert.equal(added[0].attributes.annotators, "prompt_classifier");
  assert.equal(added[0].attributes.evidenceVerificationPointerKeys, "issuer_pubkey");
  assert.equal(recorded.length, 1);
  assert.equal(recorded[0].metricName, "acs_intervention_duration_ms");
  assert.equal(recorded[0].value, 3.2);
});
