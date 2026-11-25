# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Evaluate one ACS intervention point for the Agent Governance Verify action.

Uses the ACS runtime (``agent_control_specification.AgentControl``). Toolkit
releases up to 5.0.0 only ship the removed ``agt.policies.AgtRuntime`` wrapper,
so that is used as a fallback when the ACS SDK is absent.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from typing import Any


def _evaluate_acs(policy: str, point: str, snapshot: dict[str, Any]) -> dict[str, Any]:
    from agent_control_specification import AgentControl

    control = AgentControl.from_path(policy)
    result = asyncio.run(control.evaluate_intervention_point(point, snapshot))
    verdict = result.verdict
    return {
        "allowed": bool(verdict.decision.permits),
        "verdict": verdict.decision.value,
        "reason_code": verdict.reason,
        "message": verdict.message,
        "runtime": "agent_control_specification",
    }


def _evaluate_legacy(policy: str, point: str, snapshot: dict[str, Any]) -> dict[str, Any]:
    from agt.policies import AgtRuntime  # toolkit <= 5.0.0

    decision = AgtRuntime(policy).evaluate(point, snapshot)
    return {
        "allowed": decision.is_allowed(),
        "verdict": decision.verdict,
        "reason_code": decision.reason_code,
        "message": decision.message,
        "runtime": "agt.policies",
    }


def evaluate(policy: str, point: str, context: str) -> dict[str, Any]:
    snapshot = json.loads(context) if context else {}
    if not isinstance(snapshot, dict):
        raise ValueError("context-json must be a JSON object")
    try:
        import agent_control_specification  # noqa: F401
    except ImportError:
        return _evaluate_legacy(policy, point, snapshot)
    return _evaluate_acs(policy, point, snapshot)


def main() -> int:
    try:
        result = evaluate(os.environ["AGT_POLICY"], os.environ.get("AGT_IP") or "pre_tool_call",
                          os.environ.get("AGT_CONTEXT", ""))
    except Exception as exc:  # noqa: BLE001 - any evaluation failure must fail the check
        print(json.dumps({"allowed": False, "verdict": "error", "message": f"{type(exc).__name__}: {exc}"}, indent=2))
        return 1
    print(json.dumps(result, indent=2))
    return 0 if result["allowed"] else 1


if __name__ == "__main__":
    sys.exit(main())
