import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
const require = createRequire(import.meta.url);
const assert = require("node:assert/strict");
const test = require("node:test");
const { AgentControl, Decision } = require("../dist/index.js");

const here = dirname(fileURLToPath(import.meta.url));
const fixturePath = resolve(here, "../../../tests/conformance/fail_closed_error_parity.json");
const fixture = JSON.parse(readFileSync(fixturePath, "utf8"));

function reasonFromError(error) {
  const match = String(error?.message ?? error).match(/runtime_error:[a-z_]+/);
  return match?.[0];
}

function controlForCase(caseDef) {
  return AgentControl.fromNative(
    caseDef.manifest_yaml,
    {
      dispatch() {
        if (caseDef.annotator_behavior === "timeout") {
          throw new Error("runtime_error:annotation_timeout");
        }
        if (caseDef.annotator_behavior === "error") {
          throw new Error("annotation failed");
        }
        return { ok: true };
      },
    },
    {
      evaluate() {
        if (caseDef.policy_behavior === "error") {
          throw new Error("policy failed");
        }
        return caseDef.policy_response ?? { decision: Decision.Allow };
      },
    },
  );
}

test("native runtime fail closed errors match shared fixture", async () => {
  assert.equal(fixture.reserved_reasons.length, 12);
  assert.deepEqual(new Set(fixture.cases.map((caseDef) => caseDef.expected_reason)), new Set(fixture.reserved_reasons));
  for (const caseDef of fixture.cases) {
    if (caseDef.operation === "build") {
      assert.throws(
        () => controlForCase(caseDef),
        (error) => reasonFromError(error) === caseDef.expected_reason,
        caseDef.id,
      );
      continue;
    }

    const control = controlForCase(caseDef);
    const result = await control.evaluateInterventionPoint(caseDef.intervention_point, caseDef.snapshot);
    assert.equal(result.verdict.decision, Decision.Deny, caseDef.id);
    assert.equal(result.verdict.reason, caseDef.expected_reason, caseDef.id);
  }
});
