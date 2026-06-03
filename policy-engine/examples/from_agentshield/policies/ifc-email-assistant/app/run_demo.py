#!/usr/bin/env python3
"""Deterministic ACS runtime demo for ifc-email-assistant."""

from __future__ import annotations

import asyncio
from pathlib import Path

from agent_control_specification import AgentControl, AgentControlBlocked, EnforcementMode, InterventionPoint

MANIFEST = Path(__file__).resolve().parents[1] / "manifest.yaml"
OBSERVED: set[str] = set()


def decision_of(result) -> str:
    decision = result.verdict.decision
    return getattr(decision, "value", decision)


async def check(control: AgentControl, snapshot: dict, label: str) -> None:
    result = await control.evaluate_intervention_point(InterventionPoint.PRE_TOOL_CALL, snapshot)
    decision = decision_of(result)
    OBSERVED.add(decision)
    print(f"{label}: decision={decision} reason={result.verdict.reason or 'default'}")
    try:
        await control.enforce(InterventionPoint.PRE_TOOL_CALL, result, EnforcementMode.ENFORCE)
    except AgentControlBlocked as blocked:
        print(f"  BLOCKED: {blocked}")


async def main() -> None:
    control = AgentControl.from_path(str(MANIFEST))
    print("ACS ifc-email-assistant demo")
    print(f"manifest={MANIFEST.relative_to(MANIFEST.parents[4])}\n")

    await check(control, {"tool_call": {"name": "read_invoice", "args": {}}}, "read tool (allow)")
    await check(control, {"exposure": ["pii"], "destination_clearance": "internal", "tool_call": {"name": "send_email", "args": {"to": "hr@company.internal"}}}, "PII to internal recipient (allow)")
    await check(control, {"exposure": ["financial"], "destination_clearance": "internal", "tool_call": {"name": "send_email", "args": {"to": "all@company.internal"}}}, "financial to internal recipient (deny)")
    await check(control, {"exposure": ["health"], "destination_clearance": "confidential", "tool_call": {"name": "send_email", "args": {"to": "legal@company.internal"}}}, "health to confidential recipient (deny)")
    await check(control, {"destination_clearance": "restricted", "tool_call": {"name": "send_email", "args": {"to": "board@company.internal"}}}, "missing exposure snapshot (deny)")

    expected = {"allow", "deny"}
    missing = expected - OBSERVED
    if missing:
        raise SystemExit(f"demo verification: FAIL (outcomes not demonstrated: {sorted(missing)})")
    print(f"\ndemo verification: PASS (demonstrated {sorted(expected)})")


if __name__ == "__main__":
    asyncio.run(main())
