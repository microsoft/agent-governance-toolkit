from __future__ import annotations

import asyncio
import json
import unittest
from pathlib import Path

from agent_control_specification import (
    AgentControl,
    AgentControlBlocked,
    ApprovalResolution,
    Decision,
    EnforcementMode,
    InterventionPoint,
    InterventionPointResult,
    Verdict,
    action_identity,
)

try:
    from agent_control_specification import _native  # noqa: F401
except ImportError:
    _NATIVE_AVAILABLE = False
else:
    _NATIVE_AVAILABLE = True

ROOT = Path(__file__).resolve().parents[3]
PARITY = ROOT / "tests" / "parity"


def load_fixture(name: str):
    return json.loads((PARITY / name).read_text())


class EmptyAnnotator:
    def dispatch(self, annotator_name, annotator_config, preliminary_policy_input):
        return {"ok": True}


class AllowPolicy:
    def evaluate(self, invocation):
        return {"decision": "allow"}


class PythonCanonicalParityTests(unittest.TestCase):
    def test_decision_surface_matches_verdict_dispatch_fixture(self):
        fixture = load_fixture("verdict_dispatch_canonical.json")
        for row in fixture["rows"]:
            if row["expected_error_reason"] is not None:
                continue
            decision = Decision(row["normalized_decision"])
            self.assertEqual(decision.applies_effects, row["effects_applied_on_enforce"])

    def test_error_mapping_fixture_covers_sdk_approval_mismatch_reason(self):
        fixture = load_fixture("error_mapping_canonical.json")
        reasons = {row["reason"] for row in fixture["runtime_errors"]}
        fail_closed = json.loads((ROOT / "tests" / "conformance" / "fail_closed_error_parity.json").read_text())
        self.assertEqual(set(fail_closed["reserved_reasons"]) | {"runtime_error:approval_action_mismatch"}, reasons)

        policy_input = {"policy_target": {"value": "x"}}
        result = InterventionPointResult(
            Verdict(Decision.ESCALATE),
            policy_input=policy_input,
            action_identity=action_identity(policy_input),
        )
        control = AgentControl(runtime_client=None)  # type: ignore[arg-type]
        with self.assertRaises(AgentControlBlocked) as raised:
            asyncio.run(
                control.enforce(
                    InterventionPoint.INPUT,
                    result,
                    EnforcementMode.ENFORCE,
                    approval_resolver=lambda _point, _result: ApprovalResolution.allow("sha256:wrong"),
                )
            )
        self.assertEqual(raised.exception.result.verdict.reason, "runtime_error:approval_action_mismatch")

    @unittest.skipUnless(_NATIVE_AVAILABLE, "agent_control_specification._native extension is not built")
    def test_native_runtime_uses_canonical_resource_limit_defaults(self):
        fixture = load_fixture("resource_limits_canonical.json")
        annotator_count = fixture["defaults"]["max_annotators_per_point"] + 1
        annotations = "\n".join(f"      a{i}:\n        from: $policy_target" for i in range(annotator_count))
        annotators = "\n".join(f"  a{i}:\n    type: classifier" for i in range(annotator_count))
        manifest = f"""agent_control_specification_version: 0.3.0-alpha
policies:
  p:
    type: test
intervention_points:
  input:
    policy:
      id: p
    policy_target: $snap.input
    annotations:
{annotations}
annotators:
{annotators}
"""
        control = AgentControl.from_native(manifest, EmptyAnnotator(), AllowPolicy())
        result = asyncio.run(control.evaluate_intervention_point("input", {"input": "hello"}))
        self.assertEqual(result.verdict.decision, Decision.DENY)
        self.assertEqual(result.verdict.reason, "runtime_error:resource_limit_exceeded")


if __name__ == "__main__":
    unittest.main()
