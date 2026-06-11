#!/usr/bin/env python3
"""Deterministic ACS runtime demo for the ported azure-content-safety policy."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any, Mapping

from agent_control_specification import (
    AgentControl,
    AgentControlBlocked,
    EnforcementMode,
    InterventionPoint,
)

MANIFEST = Path(__file__).resolve().parents[1] / "manifest.yaml"
OBSERVED: set[str] = set()


class ClassifierAnnotator:
    """Deterministic host stand-in for the external classifier."""

    def dispatch(self, annotator_name: str, annotator_config: Mapping[str, Any], preliminary_policy_input: Mapping[str, Any]) -> Mapping[str, Any]:
        if annotator_name != "aacs":
            return {}
        target = preliminary_policy_input["policy_target"]["value"] or {}
        text = str(target.get("text", target) if isinstance(target, Mapping) else target).lower()
        if "hate" in text:
            return {"scores": {"Hate": 2}}
        if "self harm" in text:
            return {"scores": {"SelfHarm": 2}}
        if "sexual" in text:
            return {"scores": {"Sexual": 4}}
        if "violence" in text:
            return {"scores": {"Violence": 2}}
        return {"scores": {}}


def decision_of(result) -> str:
    decision = result.verdict.decision
    return getattr(decision, "value", decision)


async def check(control: AgentControl, point: InterventionPoint, snapshot: dict, label: str) -> None:
    result = await control.evaluate_intervention_point(point, snapshot)
    decision = decision_of(result)
    OBSERVED.add(decision)
    print(f"{label}: decision={decision} reason={result.verdict.reason or 'default'}")
    try:
        await control.enforce(point, result, EnforcementMode.ENFORCE)
    except AgentControlBlocked as blocked:
        print(f"  BLOCKED: {blocked}")


async def main() -> None:
    control = AgentControl.from_path(str(MANIFEST), annotator_dispatcher=ClassifierAnnotator())
    print("ACS azure-content-safety demo")
    print(f"manifest={MANIFEST.relative_to(MANIFEST.parents[4])}\n")
    await check(control, InterventionPoint.INPUT, {"input": {"text": "hello, please help with my account"}}, "input: benign (allow)")
    await check(control, InterventionPoint.INPUT, {"input": {"text": "hate speech sample"}}, "input: harmful (deny)")
    await check(control, InterventionPoint.POST_TOOL_CALL, {"tool_result": {"text": "violence sample from tool"}}, "post_tool_call: harmful tool result (deny)")
    await check(control, InterventionPoint.OUTPUT, {"output": {"text": "self harm sample"}}, "output: harmful response (deny)")

    expected = {"allow", "deny"}
    missing = expected - OBSERVED
    if missing:
        raise SystemExit(f"demo verification: FAIL (outcomes not demonstrated: {sorted(missing)})")
    print(f"\ndemo verification: PASS (demonstrated {sorted(expected)})")


if __name__ == "__main__":
    asyncio.run(main())
