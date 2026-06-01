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
        """Per AGT D1 the dispatch fixture replaced
        ``effects_applied_on_enforce`` with ``permits`` because effects[]
        was removed and only the new ``transform`` decision mutates. The
        SDK MUST surface ``permits == applies_transform`` semantics
        through ``Decision.permits`` (allow|warn|transform) and route
        through ``applies_transform`` only for the transform case.
        """

        fixture = load_fixture("verdict_dispatch_canonical.json")
        seen_decisions = set()
        for row in fixture["rows"]:
            if row["expected_error_reason"] is not None:
                continue
            decision = Decision(row["normalized_decision"])
            seen_decisions.add(decision)
            self.assertEqual(decision.permits, row["permits"], decision.value)
            # AGT D1: only TRANSFORM is allowed to mutate the policy
            # target. Every other permitting decision does not mutate.
            self.assertEqual(
                decision.applies_transform,
                decision is Decision.TRANSFORM,
                decision.value,
            )
        # Ensure the fixture exercises the new AGT TRANSFORM decision so
        # this test fails closed if the parity row is ever dropped.
        self.assertIn(Decision.TRANSFORM, seen_decisions)

    def test_error_mapping_fixture_covers_sdk_approval_mismatch_reason(self):
        """The error_mapping_canonical fixture grew from 13 to 18 rows in
        1d8fcb64: it drops the legacy ``effect_*`` reasons and adds the
        seven AGT D5/D6 reserved reasons. Verify the SDK accepts every
        fixture reason without choking on the new ones.
        """

        fixture = load_fixture("error_mapping_canonical.json")
        reasons = {row["reason"] for row in fixture["runtime_errors"]}
        fail_closed = json.loads((ROOT / "tests" / "conformance" / "fail_closed_error_parity.json").read_text())
        agt_extension_reasons = {
            "runtime_error:approval_action_mismatch",
            "runtime_error:resolution_path_traversal",
            "runtime_error:resolution_cycle",
            "runtime_error:resolution_invalid_governance",
            "runtime_error:resolution_merge_conflict",
            "runtime_error:approval_resolver_missing",
        }
        expected = set(fail_closed["reserved_reasons"]) | agt_extension_reasons
        self.assertEqual(expected, reasons)

        # AGT D6: the SDK MUST surface every fixture reason as a deny
        # Verdict whose reason round-trips byte for byte, so audit
        # consumers can dispatch on the reserved namespace without
        # tripping on the new AGT-era reasons.
        for reason in sorted(reasons):
            verdict = Verdict(Decision.DENY, reason=reason)
            self.assertEqual(verdict.reason, reason)

        policy_input = {"policy_target": {"value": "x"}}
        identity = action_identity(policy_input)
        result = InterventionPointResult(
            Verdict(Decision.ESCALATE),
            policy_input=policy_input,
            input_identity=identity,
            enforced_identity=identity,
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
        manifest = f"""agent_control_specification_version: 0.3.1-beta
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
