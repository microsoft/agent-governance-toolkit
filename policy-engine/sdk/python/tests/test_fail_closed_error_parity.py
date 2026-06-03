from __future__ import annotations

import asyncio
import json
import re
import unittest
from pathlib import Path

from agent_control_specification import AgentControl, Decision

try:
    from agent_control_specification import _native  # noqa: F401
except ImportError:
    _NATIVE_AVAILABLE = False
else:
    _NATIVE_AVAILABLE = True

FIXTURE = json.loads(
    (Path(__file__).resolve().parents[3] / "tests" / "conformance" / "fail_closed_error_parity.json").read_text()
)


class FixtureAnnotator:
    def __init__(self, case):
        self.case = case

    def dispatch(self, annotator_name, annotator_config, preliminary_policy_input):
        if self.case.get("annotator_behavior") == "timeout":
            raise TimeoutError("runtime_error:annotation_timeout")
        if self.case.get("annotator_behavior") == "error":
            raise RuntimeError("annotation failed")
        return {"ok": True}


class FixturePolicy:
    def __init__(self, case):
        self.case = case

    def evaluate(self, invocation):
        if self.case.get("policy_behavior") == "error":
            raise RuntimeError("policy failed")
        return self.case.get("policy_response", {"decision": "allow"})


def reason_from_error(error: BaseException) -> str | None:
    match = re.search(r"runtime_error:[a-z_]+", str(error))
    return match.group(0) if match else None


def control_for_case(case):
    return AgentControl.from_native(case["manifest_yaml"], FixtureAnnotator(case), FixturePolicy(case))


@unittest.skipUnless(_NATIVE_AVAILABLE, "agent_control_specification._native extension is not built")
class FailClosedErrorParityTests(unittest.TestCase):
    def test_native_runtime_fail_closed_errors_match_shared_fixture(self):
        self.assertEqual(len(FIXTURE["reserved_reasons"]), 12)
        self.assertEqual({case["expected_reason"] for case in FIXTURE["cases"]}, set(FIXTURE["reserved_reasons"]))
        for case in FIXTURE["cases"]:
            with self.subTest(case=case["id"]):
                if case["operation"] == "build":
                    with self.assertRaises(RuntimeError) as raised:
                        control_for_case(case)
                    self.assertEqual(reason_from_error(raised.exception), case["expected_reason"])
                    continue

                result = asyncio.run(
                    control_for_case(case).evaluate_intervention_point(
                        case["intervention_point"],
                        case["snapshot"],
                    )
                )
                self.assertEqual(result.verdict.decision, Decision.DENY)
                self.assertEqual(result.verdict.reason, case["expected_reason"])


if __name__ == "__main__":
    unittest.main()
