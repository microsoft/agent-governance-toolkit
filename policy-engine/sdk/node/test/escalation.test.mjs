import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
const assert = require("node:assert/strict");
const test = require("node:test");
const {
  AgentControl,
  actionIdentity,
  AgentControlBlockedError,
  AgentControlSuspendedError,
  ApprovalOutcome,
  ApprovalResolution,
  Decision,
  EnforcementMode,
  InterventionPoint,
} = require("../dist/index.js");

class StubRuntimeClient {
  constructor(verdictFor) {
    this.verdictFor = verdictFor;
  }

  async evaluateInterventionPoint(request) {
    const outcome = this.verdictFor(request.interventionPoint) ?? {};
    const policyInput = outcome.policyInput ?? { intervention_point: request.interventionPoint, snapshot: request.snapshot };
    const response = {
      verdict: outcome.verdict ?? { decision: Decision.Allow },
      policyInput,
      actionIdentity: outcome.actionIdentity ?? actionIdentity(policyInput),
    };
    if (outcome.transformedPolicyTarget !== undefined) {
      response.transformedPolicyTarget = outcome.transformedPolicyTarget;
    }
    return response;
  }
}

function controlWith(verdictFor, approvalResolver) {
  return new AgentControl(new StubRuntimeClient(verdictFor), approvalResolver);
}

function escalateAt(point) {
  return (interventionPoint) =>
    interventionPoint === point ? { verdict: { decision: Decision.Escalate, reason: "needs_approval" } } : {};
}

const allowResolver = (_point, result) => ApprovalResolution.allow(result.actionIdentity);
const denyResolver = () => ApprovalResolution.deny();
const throwingResolver = () => {
  throw new Error("resolver boom");
};

test("deny does not consult the resolver and blocks", async () => {
  let consulted = false;
  const control = controlWith(
    (point) => (point === InterventionPoint.Input ? { verdict: { decision: Decision.Deny } } : {}),
    (_point, result) => {
      consulted = true;
      return ApprovalResolution.allow(result.actionIdentity);
    },
  );
  await assert.rejects(
    control.run("hi", (input) => input),
    (error) => error instanceof AgentControlBlockedError,
  );
  assert.equal(consulted, false);
});

test("escalate with no resolver fails closed to a block", async () => {
  const control = controlWith(escalateAt(InterventionPoint.Input));
  await assert.rejects(
    control.run("hi", (input) => input),
    (error) => error instanceof AgentControlBlockedError,
  );
});

test("transform verdict routes through transformedPolicyTarget without an approval resolver", async () => {
  // AGT D1.1: TRANSFORM is the canonical mutation path; ESCALATE
  // MUST NOT mutate the policy target. Pre-AGT this case exercised
  // escalate + transformedPolicyTarget routed through an approval
  // resolver, but that combination is no longer producible by the
  // runtime per AGT D1. Migrate to a TRANSFORM verdict and assert the
  // SDK uses the engine transform without consulting any resolver.
  let consulted = false;
  const control = controlWith(
    (point) =>
      point === InterventionPoint.Input
        ? {
            verdict: {
              decision: Decision.Transform,
              reason: "redact_pii",
              transform: { path: "$policy_target", value: "REDACTED" },
            },
            transformedPolicyTarget: "REDACTED",
          }
        : {},
    (_point, result) => {
      consulted = true;
      return ApprovalResolution.allow(result.actionIdentity);
    },
  );
  const result = await control.run("original", (input) => input);
  assert.equal(result.value, "REDACTED");
  assert.equal(consulted, false);
});

test("escalate resolved to allow does not apply transforms after approval", async () => {
  const control = controlWith(
    (point) =>
      point === InterventionPoint.Input
        ? {
            verdict: { decision: Decision.Escalate },
            transformedPolicyTarget: "REDACTED",
          }
        : {},
    allowResolver,
  );
  const result = await control.run("original", (input) => input);
  assert.equal(result.value, "original");
});

test("run splices nested output transforms into the original output shape", async () => {
  const control = controlWith((point) =>
    point === InterventionPoint.Output
      ? {
          verdict: {
            decision: Decision.Transform,
            reason: "redact_pii",
            transform: { path: "$policy_target", value: "deployment complete [REDACTED]" },
          },
          transformedPolicyTarget: "deployment complete [REDACTED]",
          policyInput: {
            policy_target: { path: "$.output.message" },
            snapshot: {},
          },
        }
      : {},
  );

  const result = await control.run("deploy", () => ({
    message: "deployment complete DEPLOY-ABCDEFGH",
    meta: { env: "prod", preserved: true },
  }));

  assert.deepEqual(result.value, {
    message: "deployment complete [REDACTED]",
    meta: { env: "prod", preserved: true },
  });
});


test("approval receives a stable action identity", async () => {
  let seenIdentity;
  const control = controlWith(escalateAt(InterventionPoint.Input), (_point, result) => {
    seenIdentity = result.actionIdentity;
    assert.equal(result.actionIdentity, actionIdentity(result.policyInput));
    return ApprovalResolution.allow(result.actionIdentity);
  });
  const first = await control.evaluateInterventionPoint(InterventionPoint.Input, { input: "hi" });
  const second = await control.evaluateInterventionPoint(InterventionPoint.Input, { input: "hi" });
  assert.equal(first.actionIdentity, second.actionIdentity);
  await control.run("hi", (input) => input);
  assert.equal(seenIdentity, first.actionIdentity);
});

test("approval action mismatch fails closed", async () => {
  const control = controlWith(escalateAt(InterventionPoint.Input), (_point, result) => {
    const approved = result.actionIdentity;
    result.policyInput.snapshot.input = "mutated";
    return ApprovalResolution.allow(approved);
  });
  await assert.rejects(
    control.run("hi", (input) => input),
    (error) => {
      assert.ok(error instanceof AgentControlBlockedError);
      assert.equal(error.result.verdict.reason, "runtime_error:approval_action_mismatch");
      return true;
    },
  );
});

test("escalate resolved to deny blocks", async () => {
  const control = controlWith(escalateAt(InterventionPoint.Input), denyResolver);
  await assert.rejects(
    control.run("hi", (input) => input),
    (error) => error instanceof AgentControlBlockedError,
  );
});

test("escalate resolved to suspend raises with the host handle", async () => {
  const control = controlWith(escalateAt(InterventionPoint.Input), (_point, result) =>
    ApprovalResolution.suspend({ ticket: "T-1" }, result.actionIdentity),
  );
  await assert.rejects(
    control.run("hi", (input) => input),
    (error) => {
      assert.ok(error instanceof AgentControlSuspendedError);
      assert.deepEqual(error.handle, { ticket: "T-1" });
      return true;
    },
  );
});

test("evaluate_only never consults the resolver and never raises", async () => {
  let consulted = false;
  const control = controlWith(escalateAt(InterventionPoint.Input), () => {
    consulted = true;
    return ApprovalResolution.allow(result.actionIdentity);
  });
  const result = await control.run("hi", (input) => input, { mode: EnforcementMode.EvaluateOnly });
  assert.equal(result.value, "hi");
  assert.equal(consulted, false);
});

test("post-tool escalate runs the tool but blocks the result", async () => {
  let executed = false;
  const control = controlWith(escalateAt(InterventionPoint.PostToolCall), denyResolver);
  await assert.rejects(
    control.runTool(
      "lookup",
      { q: "x" },
      () => {
        executed = true;
        return { ok: true };
      },
      { toolCallId: "call-1" },
    ),
    (error) => error instanceof AgentControlBlockedError,
  );
  assert.equal(executed, true);
});

test("per-call resolver overrides the instance resolver", async () => {
  const control = controlWith(escalateAt(InterventionPoint.Input), denyResolver);
  const result = await control.run("hi", (input) => input, { approvalResolver: allowResolver });
  assert.equal(result.value, "hi");
});

test("an invalid resolution fails closed to a block", async () => {
  const control = controlWith(escalateAt(InterventionPoint.Input), () => ({ outcome: "bogus" }));
  await assert.rejects(
    control.run("hi", (input) => input),
    (error) => error instanceof AgentControlBlockedError,
  );
});

test("a throwing resolver fails closed and preserves the cause", async () => {
  const control = controlWith(escalateAt(InterventionPoint.Input), throwingResolver);
  await assert.rejects(
    control.run("hi", (input) => input),
    (error) => {
      assert.ok(error instanceof AgentControlBlockedError);
      assert.equal(error.result.verdict.reason, "runtime_error:approval_resolver_failed");
      assert.equal(error.result.verdict.message, "Approval resolver failed closed.");
      assert.equal(error.result.actionIdentity, actionIdentity(error.result.policyInput));
      assert.ok(error.cause instanceof Error);
      assert.equal(error.cause.message, "resolver boom");
      return true;
    },
  );
});

test("a resolver returning null or malformed fails closed with resolver-failed reason", async () => {
  for (const bad of [() => null, () => undefined, () => "not-a-resolution"]) {
    const control = controlWith(escalateAt(InterventionPoint.Input), bad);
    await assert.rejects(
      control.run("hi", (input) => input),
      (error) => {
        assert.ok(error instanceof AgentControlBlockedError);
        assert.equal(error.result.verdict.reason, "runtime_error:approval_resolver_failed");
        assert.equal(error.result.verdict.message, "Approval resolver failed closed.");
        assert.equal(error.result.actionIdentity, actionIdentity(error.result.policyInput));
        return true;
      },
    );
  }
});

test("a synchronous resolver is awaited correctly", async () => {
  const control = controlWith(escalateAt(InterventionPoint.Input), (_point, result) => ({
    outcome: ApprovalOutcome.Allow,
    actionIdentity: result.actionIdentity,
  }));
  const result = await control.run("hi", (input) => input);
  assert.equal(result.value, "hi");
});

test("bare allow is treated as allow", async () => {
  const control = controlWith(escalateAt(InterventionPoint.Input), (_point, result) => ApprovalResolution.allow(result.actionIdentity));
  const result = await control.run("hi", (input) => input);
  assert.equal(result.value, "hi");
});
