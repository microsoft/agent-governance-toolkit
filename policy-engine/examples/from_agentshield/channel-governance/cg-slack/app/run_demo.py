#!/usr/bin/env python3
"""Deterministic ACS runtime demo for the ported Slack channel governance policy."""

from __future__ import annotations

import asyncio
import re
from pathlib import Path
from typing import Any, Mapping

from agent_control_specification import (
    AgentControl,
    AgentControlBlocked,
    ApprovalResolution,
    EnforcementMode,
    InterventionPoint,
)

MANIFEST = Path(__file__).resolve().parents[1] / "manifest.yaml"
OBSERVED: set[str] = set()

SECRET_PATTERNS = [
    ("slack_token", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}", re.IGNORECASE)),

]


class MessageDlpAnnotator:
    def dispatch(self, annotator_name: str, annotator_config: Mapping[str, Any], preliminary_policy_input: Mapping[str, Any]) -> Mapping[str, Any]:
        if annotator_name != "message_dlp":
            return {}
        args = preliminary_policy_input["policy_target"]["value"] or {}
        text = str(args.get("message", "")) if isinstance(args, Mapping) else str(args)
        for category, pattern in SECRET_PATTERNS:
            if pattern.search(text):
                return {"category": category, "secret_present": True}
        return {"category": "clear", "secret_present": False}


def decision_of(result) -> str:
    decision = result.verdict.decision
    return getattr(decision, "value", decision)


async def approve(_point, result) -> ApprovalResolution:
    OBSERVED.add("escalate")
    print(f"  APPROVAL: approved {result.verdict.reason}")
    return ApprovalResolution.allow(result.action_identity)


async def check(control: AgentControl, snapshot: dict, label: str) -> None:
    result = await control.evaluate_intervention_point(InterventionPoint.PRE_TOOL_CALL, snapshot)
    decision = decision_of(result)
    OBSERVED.add(decision)
    print(f"{label}: decision={decision} reason={result.verdict.reason or 'default'}")
    try:
        await control.enforce(InterventionPoint.PRE_TOOL_CALL, result, EnforcementMode.ENFORCE, approval_resolver=approve)
    except AgentControlBlocked as blocked:
        print(f"  BLOCKED: {blocked}")


async def main() -> None:
    control = AgentControl.from_path(str(MANIFEST), annotator_dispatcher=MessageDlpAnnotator())
    print("ACS Slack channel governance demo")
    print(f"manifest={MANIFEST.relative_to(MANIFEST.parents[4])}\n")

    await check(control, {"tool_call": {"name": "slack.send_message", "args": {"destination": "C-ENG", "operation": "send", "message": "routine update"}}}, "allowlisted send requires approval (escalate)")
    await check(control, {"tool_call": {"name": "slack.send_message", "args": {"destination": "outside-destination", "operation": "send", "message": "routine update"}}}, "non-allowlisted destination (deny)")
    await check(control, {"tool_call": {"name": "slack.send_message", "args": {"destination": "C-ENG", "operation": "delete", "message": "routine update"}}}, "dangerous operation (deny)")
    await check(control, {"tool_call": {"name": "slack.send_message", "args": {"destination": "C-ENG", "operation": "send", "message": "xoxb-1234567890-token"}}}, "secret-bearing message (deny)")

    expected = {"deny", "escalate"}
    missing = expected - OBSERVED
    if missing:
        raise SystemExit(f"demo verification: FAIL (outcomes not demonstrated: {sorted(missing)})")
    print(f"\ndemo verification: PASS (demonstrated {sorted(expected)})")


if __name__ == "__main__":
    asyncio.run(main())
