import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
const assert = require("node:assert/strict");
const test = require("node:test");
const {
  AgentControl,
  Decision,
  EnforcementMode,
  InterventionPoint,
} = require("../dist/index.js");
const {
  appliesEffects,
  appliesTransform,
  transformedOr,
} = require("../dist/src/adapter-helpers.js");

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

function makeControl(handler) {
  return new AgentControl(new StubRuntimeClient(handler));
}

// AGT D1.1: Decision.Transform must exist on the wire enum.
test("Decision union includes 'transform' per AGT D1", () => {
  assert.equal(Decision.Transform, "transform");
});

// AGT D1: only transform mutates the policy target. allow|warn|deny|
// escalate MUST NOT mutate.
test("appliesTransform is true only for Decision.Transform", () => {
  assert.equal(appliesTransform(Decision.Allow), false);
  assert.equal(appliesTransform(Decision.Warn), false);
  assert.equal(appliesTransform(Decision.Deny), false);
  assert.equal(appliesTransform(Decision.Escalate), false);
  assert.equal(appliesTransform(Decision.Transform), true);
});

// AGT D1: appliesEffects is retained as a deprecated alias that now
// delegates to appliesTransform.
test("appliesEffects is a back-compat alias of appliesTransform", () => {
  for (const decision of Object.values(Decision)) {
    assert.equal(appliesEffects(decision), appliesTransform(decision), decision);
  }
});

// AGT D1.1: transformedOr returns transformedPolicyTarget only when the
// verdict is transform in enforce mode. Pre-AGT the fallback was applied
// for allow|warn|escalate too; the new gate strips that incorrect path.
test("transformedOr applies only TRANSFORM in enforce mode", () => {
  const fallback = { text: "raw" };
  const transformedTarget = { text: "redacted" };
  for (const decision of [Decision.Allow, Decision.Warn, Decision.Deny, Decision.Escalate]) {
    const result = {
      verdict: { decision },
      transformedPolicyTarget: transformedTarget,
    };
    assert.deepEqual(
      transformedOr(result, fallback, EnforcementMode.Enforce),
      fallback,
      `${decision} must not mutate the policy target`,
    );
  }
  const transformResult = {
    verdict: { decision: Decision.Transform },
    transformedPolicyTarget: transformedTarget,
  };
  assert.deepEqual(
    transformedOr(transformResult, fallback, EnforcementMode.Enforce),
    transformedTarget,
  );
});

test("transformedOr returns fallback in evaluate_only even for transform", () => {
  const fallback = { text: "raw" };
  const transformResult = {
    verdict: { decision: Decision.Transform },
    transformedPolicyTarget: { text: "redacted" },
  };
  assert.deepEqual(
    transformedOr(transformResult, fallback, EnforcementMode.EvaluateOnly),
    fallback,
  );
});

// AGT D1.4: bisected identity. The Node SDK SHOULD surface input and
// enforced identities verbatim, and keep actionIdentity as a back-compat
// alias for enforcedIdentity.
test("InterventionPointResult surfaces inputIdentity, enforcedIdentity, actionIdentity", async () => {
  const control = makeControl(() => ({
    verdict: { decision: Decision.Transform, transform: { path: "$policy_target", value: "redacted" } },
    transformedPolicyTarget: "redacted",
    inputIdentity: "sha256:input",
    enforcedIdentity: "sha256:enforced",
    actionIdentity: "sha256:enforced",
  }));
  const result = await control.evaluateInterventionPoint(InterventionPoint.Input, { input: "raw" });
  assert.equal(result.inputIdentity, "sha256:input");
  assert.equal(result.enforcedIdentity, "sha256:enforced");
  assert.equal(result.actionIdentity, "sha256:enforced");
});

// AGT D2: verdict.evidence rides verbatim through the SDK.
test("Verdict.evidence propagates verbatim from runtime client", async () => {
  const control = makeControl(() => ({
    verdict: {
      decision: Decision.Allow,
      evidence: {
        artefact: "sha256:proof",
        verificationPointers: {
          issuer_pubkey: "https://example.com/keys/2026.pem",
          policy_registry: "https://example.com/policies/v1/",
        },
      },
    },
  }));
  const result = await control.evaluateInterventionPoint(InterventionPoint.Input, { input: "x" });
  assert.equal(result.verdict.evidence.artefact, "sha256:proof");
  assert.deepEqual(result.verdict.evidence.verificationPointers, {
    issuer_pubkey: "https://example.com/keys/2026.pem",
    policy_registry: "https://example.com/policies/v1/",
  });
});

// AGT D1.1: control.run uses the engine's transformedPolicyTarget end
// to end when the verdict is TRANSFORM, and does NOT consult an
// approval resolver.
test("control.run routes TRANSFORM through transformedPolicyTarget without an approval resolver", async () => {
  let consulted = false;
  const queue = [
    {
      verdict: {
        decision: Decision.Transform,
        reason: "redact_pii",
        transform: { path: "$policy_target.text", value: "redacted" },
      },
      transformedPolicyTarget: { text: "redacted" },
    },
    { verdict: { decision: Decision.Allow } },
  ];
  const control = new AgentControl(
    new StubRuntimeClient(() => queue.shift()),
    () => {
      consulted = true;
      return { outcome: "allow", actionIdentity: "sha256:x" };
    },
  );
  const seen = [];
  const result = await control.run({ text: "raw" }, (value) => {
    seen.push(value);
    return { answer: "ok" };
  });
  assert.equal(consulted, false);
  assert.deepEqual(seen, [{ text: "redacted" }]);
  assert.deepEqual(result.value, { answer: "ok" });
});

// AGT D1: defence in depth. Even when an upstream client mistakenly
// attaches a transformedPolicyTarget to a non-transform verdict, the
// SDK MUST NOT apply it.
test("control.run ignores transformedPolicyTarget on non-TRANSFORM verdicts", async () => {
  const queue = [
    {
      verdict: { decision: Decision.Warn, reason: "audited" },
      transformedPolicyTarget: { text: "leaked" },
    },
    { verdict: { decision: Decision.Allow } },
  ];
  const control = new AgentControl(new StubRuntimeClient(() => queue.shift()));
  const seen = [];
  await control.run({ text: "raw" }, (value) => {
    seen.push(value);
    return value;
  });
  assert.deepEqual(seen, [{ text: "raw" }]);
});
