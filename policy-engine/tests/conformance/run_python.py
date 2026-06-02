#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio
import json
import re
import sys
import unittest
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
CASES_DIR = REPO / "tests" / "conformance" / "cases"

try:
    from agent_control_specification import (
        AgentControl,
        AgentControlBlocked,
        ApprovalResolution,
        Decision,
        InterventionPointResult,
        Verdict,
        action_identity,
    )
    from agent_control_specification import _native  # noqa: F401
except ImportError:
    NATIVE_AVAILABLE = False
else:
    NATIVE_AVAILABLE = True


class FixtureAnnotator:
    def __init__(self, case):
        self.case = case
        self.seen: list[str] = []

    def dispatch(self, annotator_name, annotator_config, preliminary_policy_input):
        self.seen.append(annotator_name)
        return self.case.get("annotator_outputs", {}).get(annotator_name, {"ok": True})


class FixturePolicy:
    def __init__(self, case):
        self.case = case

    def evaluate(self, invocation):
        if self.case.get("policy_behavior") == "error":
            raise RuntimeError("policy failed")
        return self.case["policy_response"]


class QueueRuntime:
    async def evaluate_intervention_point(self, request):
        policy_input = {"intervention_point": request.intervention_point.value, "snapshot": dict(request.snapshot)}
        return InterventionPointResult(
            Verdict(Decision.ESCALATE, reason="human_review"),
            policy_input=policy_input,
            input_identity=action_identity(policy_input),
            enforced_identity=action_identity(policy_input),
        )


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def load_cases() -> list[dict]:
    return [json.loads(path.read_text(encoding="utf-8")) for path in sorted(CASES_DIR.glob("*.json"))]


def decision_value(decision) -> str:
    return getattr(decision, "value", str(decision))


def result_item(case: dict, status: str, detail: str | None = None) -> dict:
    return {"case": case["id"], "status": status, "detail": detail}


async def run_evaluate(case: dict) -> dict:
    annotator = FixtureAnnotator(case)
    control = AgentControl.from_native(case["manifest_yaml"], annotator, FixturePolicy(case))
    result = await control.evaluate_intervention_point(
        case["intervention_point"],
        case["snapshot"],
        case.get("mode", "enforce"),
    )
    expected = case["expected"]
    if decision_value(result.verdict.decision) != expected["decision"]:
        return result_item(case, "fail", f"decision {result.verdict.decision!r}")
    if "reason" in expected and result.verdict.reason != expected.get("reason"):
        return result_item(case, "fail", f"reason {result.verdict.reason!r}")
    if "transformed_policy_target" in expected and result.transformed_policy_target != expected["transformed_policy_target"]:
        return result_item(case, "fail", "transformed target mismatch")
    if "policy_target" in expected and result.policy_input["policy_target"]["value"] != expected["policy_target"]:
        return result_item(case, "fail", "policy target mismatch")
    if "annotations" in expected and result.policy_input["annotations"] != expected["annotations"]:
        return result_item(case, "fail", "annotations mismatch")
    if "annotator_order" in expected and annotator.seen != expected["annotator_order"]:
        return result_item(case, "fail", f"annotator order {annotator.seen!r}")
    return result_item(case, "pass")


async def run_approval_mismatch(case: dict) -> dict:
    async def resolver(intervention_point, result):
        approved = result.action_identity
        result.policy_input["snapshot"]["input"] = "mutated"
        return ApprovalResolution.allow(approved)

    control = AgentControl(QueueRuntime(), approval_resolver=resolver)
    try:
        await control.run("hi", lambda value: value)
    except AgentControlBlocked as exc:
        if exc.result.verdict.reason == case["expected"].get("reason"):
            return result_item(case, "pass")
        return result_item(case, "fail", f"reason {exc.result.verdict.reason!r}")
    return result_item(case, "fail", "approval mismatch did not block")


async def run_case(case: dict) -> dict:
    if case.get("sdk_support", {}).get("python") == "skip":
        return result_item(case, "skip", "case excludes python")
    if not NATIVE_AVAILABLE and case["operation"] == "evaluate":
        return result_item(case, "skip", "native extension is not built")
    try:
        if case["operation"] == "evaluate":
            return await run_evaluate(case)
        if case["operation"] == "approval_action_mismatch":
            return await run_approval_mismatch(case)
        return result_item(case, "skip", f"unsupported operation {case['operation']}")
    except Exception as exc:  # noqa: BLE001
        reason = re.search(r"runtime_error:[a-z_]+", str(exc))
        expected = case.get("expected", {})
        if expected.get("decision") == "deny" and reason and reason.group(0) == expected.get("reason"):
            return result_item(case, "pass")
        return result_item(case, "error", str(exc))


async def run_all() -> list[dict]:
    return [await run_case(case) for case in load_cases()]


def write_report(results: list[dict], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps({"sdk": "python", "timestamp": now_iso(), "results": results}, indent=2) + "\n",
        encoding="utf-8",
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default=str(REPO / "tests" / "conformance" / "results" / "python.json"))
    args = parser.parse_args(argv)
    results = asyncio.run(run_all())
    write_report(results, Path(args.output))
    for item in results:
        print(f"python {item['status']} {item['case']}{': ' + item['detail'] if item.get('detail') else ''}")
    return 0 if all(item["status"] in {"pass", "skip"} for item in results) else 1


class PythonConformanceRunnerTests(unittest.TestCase):
    def test_python_runner_cases_pass_or_skip(self):
        results = asyncio.run(run_all())
        failing = [item for item in results if item["status"] not in {"pass", "skip"}]
        self.assertEqual(failing, [])


if __name__ == "__main__":
    raise SystemExit(main())
