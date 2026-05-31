import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
const assert = require("node:assert/strict");
const test = require("node:test");
const { AgentControl, Decision, InterventionPoint } = require("../dist/index.js");

const manifest = `agent_control_specification_version: 0.3.0-alpha
metadata:
  name: basic-host-node-test
policies:
  input_custom_policy:
    type: custom
    adapter: basic_host_mock
intervention_points:
  input:
    policy_target_kind: user_input
    policy:
      id: input_custom_policy
    policy_target: $.input
    annotations:
      prompt_classifier:
        from: $.input.text
annotators:
  prompt_classifier:
    type: classifier`;

const baseManifest = `agent_control_specification_version: 0.3.0-alpha
policies:
  input_custom_policy:
    type: custom
    adapter: basic_host_mock
intervention_points:
  input:
    policy_target_kind: user_input
    policy:
      id: input_custom_policy
    policy_target: $.input`;

const overlayManifest = `agent_control_specification_version: 0.3.0-alpha
metadata:
  name: node-chain-test
intervention_points:
  input:
    policy_target_kind: user_input
    policy:
      id: input_custom_policy
    policy_target: $.input
    annotations:
      prompt_classifier:
        from: $.input.text
annotators:
  prompt_classifier:
    type: classifier`;

function policyForAccountNumber(invocation) {
  assert.equal(invocation.type, "custom");
  const containsAccountNumber =
    invocation.input.annotations.prompt_classifier.contains_account_number;
  if (!containsAccountNumber) return { decision: Decision.Allow };
  // AGT D1: effects[] is rejected by the runtime. The canonical
  // mutation path is decision: 'transform' with a single-target
  // transform payload, mirroring core/src/verdict.rs::Transform.
  return {
    decision: Decision.Transform,
    reason: "account_number_redacted",
    message: "Account number was redacted before continuing.",
    transform: {
      path: "$policy_target.text",
      value: "Please summarize account [REDACTED].",
    },
  };
}

function makeAccountControl({ annotatorDelay = async () => {} } = {}) {
  return AgentControl.fromNative(
    manifest,
    {
      async dispatch(annotatorName, annotatorConfig, preliminaryPolicyInput) {
        assert.equal(annotatorName, "prompt_classifier");
        assert.equal(annotatorConfig.type, "classifier");
        const text = preliminaryPolicyInput.policy_target.value.text;
        await annotatorDelay();
        return {
          annotator: annotatorName,
          contains_account_number: text.includes("1234"),
        };
      },
    },
    {
      async evaluate(invocation) {
        await Promise.resolve();
        return policyForAccountNumber(invocation);
      },
    },
  );
}

async function evaluateText(agentControl, text) {
  return agentControl.evaluateInterventionPoint(InterventionPoint.Input, {
    input: { text },
    actor: { id: "user-123" },
    transport: { kind: "api_gateway", route: "/chat" },
  });
}

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function assertRuntimeErrorVerdict(result) {
  assert.equal(result.verdict.decision, Decision.Deny);
  assert.match(result.verdict.reason, /^runtime_error/);
}

test("native runtime supports async JS dispatchers and applies transform decision", async () => {
  // AGT D1.1: TRANSFORM is the canonical mutation path. Previously this
  // test exercised warn + effects[] which is now rejected as
  // runtime_error:policy_output_invalid by the strict runtime per
  // 1d8fcb64. The dispatcher now emits a transform verdict so the
  // runtime produces transformedPolicyTarget by applying transform.path.
  const agentControl = makeAccountControl();
  const result = await evaluateText(agentControl, "Please summarize account 1234.");
  assert.equal(result.verdict.decision, Decision.Transform);
  assert.equal(result.verdict.reason, "account_number_redacted");
  assert.deepEqual(result.transformedPolicyTarget, { text: "Please summarize account [REDACTED]." });
  // AGT D1.4: bisected identity. A transform mutates the policy
  // target so input_identity MUST differ from enforced_identity, and
  // the legacy actionIdentity slot MUST alias enforced_identity.
  assert.ok(typeof result.inputIdentity === "string" && result.inputIdentity.startsWith("sha256:"));
  assert.ok(typeof result.enforcedIdentity === "string" && result.enforcedIdentity.startsWith("sha256:"));
  assert.notEqual(result.inputIdentity, result.enforcedIdentity);
  assert.equal(result.actionIdentity, result.enforcedIdentity);
});

test("native runtime handles concurrent async dispatcher round trips", async () => {
  const agentControl = makeAccountControl({
    annotatorDelay: () => delay(Math.floor(Math.random() * 5)),
  });
  const results = await Promise.all(
    Array.from({ length: 50 }, (_, index) =>
      evaluateText(
        agentControl,
        index % 2 === 0 ? `Please summarize account 1234 (${index}).` : `Hello ${index}.`,
      ),
    ),
  );

  for (const [index, result] of results.entries()) {
    assert.equal(result.verdict.decision, index % 2 === 0 ? Decision.Transform : Decision.Allow);
  }
});

test("native runtime supports sequential re-entry after awaited evaluate", async () => {
  const agentControl = makeAccountControl();
  const first = await evaluateText(agentControl, "Please summarize account 1234.");
  const second = await evaluateText(agentControl, "No account number here.");

  assert.equal(first.verdict.decision, Decision.Transform);
  assert.equal(second.verdict.decision, Decision.Allow);
});

test("dispatcher sync throw and async rejection resolve to runtime-error verdicts", async () => {
  const policyDispatcher = { evaluate: policyForAccountNumber };

  const throwingControl = AgentControl.fromNative(
    manifest,
    {
      dispatch() {
        throw new Error("sync boom");
      },
    },
    policyDispatcher,
  );
  assertRuntimeErrorVerdict(await evaluateText(throwingControl, "Please summarize account 1234."));

  const rejectingControl = AgentControl.fromNative(
    manifest,
    {
      async dispatch() {
        throw new Error("async boom");
      },
    },
    policyDispatcher,
  );
  assertRuntimeErrorVerdict(await evaluateText(rejectingControl, "Please summarize account 1234."));
});

test("native runtime composes manifest chains", async () => {
  const agentControl = AgentControl.fromManifestChain(
    [baseManifest, overlayManifest],
    {
      dispatch(annotatorName, annotatorConfig, preliminaryPolicyInput) {
        assert.equal(annotatorName, "prompt_classifier");
        assert.equal(annotatorConfig.type, "classifier");
        return {
          annotator: annotatorName,
          contains_account_number: preliminaryPolicyInput.policy_target.value.text.includes("1234"),
        };
      },
    },
    { evaluate: policyForAccountNumber },
  );

  const result = await evaluateText(agentControl, "Please summarize account 1234.");
  assert.equal(result.verdict.decision, Decision.Transform);
  assert.equal(result.verdict.transform.path, "$policy_target.text");
  assert.deepEqual(result.transformedPolicyTarget, { text: "Please summarize account [REDACTED]." });
});

import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { existsSync, mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";

const __dirname = dirname(fileURLToPath(import.meta.url));
const supportManifest = join(__dirname, "..", "..", "..", "examples", "support_agent", "manifest.yaml");

function opaAvailable() {
  try {
    execFileSync("opa", ["version"], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

const nonRegoManifest = `agent_control_specification_version: 0.3.0-alpha
metadata:
  name: zero-config-non-rego
policies:
  p:
    type: custom
    adapter: host_mock
intervention_points:
  input:
    policy_target_kind: user_input
    policy:
      id: p
    policy_target: $.input`;

test("zero-config fromPath builds with bundled defaults", { skip: !opaAvailable() }, async () => {
  assert.ok(existsSync(supportManifest));
  // No host dispatchers: the bundled OPA policy and annotator defaults are used.
  const agentControl = AgentControl.fromPath(supportManifest);
  assert.ok(agentControl);
});

test("zero-config default policy dispatcher rejects non-rego", async () => {
  const dir = mkdtempSync(join(tmpdir(), "acs-zc-"));
  const path = join(dir, "manifest.yaml");
  writeFileSync(path, nonRegoManifest);
  try {
    assert.throws(() => AgentControl.fromPath(path), /only Rego/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("native runtime returns policy result_labels for IFC propagation", async () => {
  const agentControl = AgentControl.fromNative(
    manifest,
    {
      async dispatch() {
        return { annotator: "prompt_classifier", contains_account_number: false };
      },
    },
    {
      async evaluate() {
        return { decision: Decision.Allow, result_labels: ["confidential"] };
      },
    },
  );
  const result = await evaluateText(agentControl, "hello");
  assert.equal(result.verdict.decision, Decision.Allow);
  assert.deepEqual(result.verdict.result_labels, ["confidential"]);
});
