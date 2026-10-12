// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import assert from "node:assert/strict";
import { createRequire } from "node:module";
import test from "node:test";

const require = createRequire(import.meta.url);
const { AgentControl, Decision, InterventionPoint } = require("../dist/index.js");

const manifest = `agent_control_specification_version: 0.4.0-alpha.1
policies:
  rule:
    type: rego
    query: '{"decision":"allow"}'
intervention_points:
  input:
    policy_target: $.input
    policy: {id: rule}
`;

const annotatedManifest = `agent_control_specification_version: 0.5.0-alpha.1
policies:
  rule: {type: custom, adapter: host}
annotators:
  judge:
    type: llm
    system_prompt_url:
      url: https://prompts.example/prompt.txt
      sha256: ${"a".repeat(64)}
intervention_points:
  input:
    policy_target: $.input
    annotations:
      judge: {from: $target}
    policy: {id: rule}
`;

test("production artifact evaluates both contracts without annotators", async () => {
  for (const version of ["0.4.0-alpha.1", "0.5.0-alpha.1"]) {
    const control = AgentControl.fromNative(manifest.replace("0.4.0-alpha.1", version));
    const result = await control.evaluateInterventionPoint(
      InterventionPoint.Input, { input: "hello" },
    );
    assert.equal(result.verdict.decision, Decision.Allow);
  }
});

test("production artifact requires an explicit annotator dispatcher", () => {
  assert.throws(
    () => AgentControl.fromNative(annotatedManifest),
    /bundled dispatchers are not enabled/,
  );
});

test("production artifact preserves restored sources for custom dispatchers", async () => {
  let calls = 0;
  const control = AgentControl.fromNative(annotatedManifest, {
    async dispatch(name, config) {
      assert.equal(name, "judge");
      assert.equal(config.system_prompt_url.url, "https://prompts.example/prompt.txt");
      calls += 1;
      return { label: "safe" };
    },
  }, {
    async evaluate(invocation) {
      assert.equal(invocation.input.annotations.judge.label, "safe");
      return { decision: Decision.Allow };
    },
  });
  const result = await control.evaluateInterventionPoint(
    InterventionPoint.Input, { input: "hello" },
  );
  assert.equal(result.verdict.decision, Decision.Allow);
  assert.equal(calls, 1);
});
