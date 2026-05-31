#!/usr/bin/env python3
from __future__ import annotations

import asyncio
from pathlib import Path

from agent_control_specification import AgentControl, AgentControlBlocked, ApprovalResolution, EnforcementMode, InterventionPoint

MANIFEST = Path(__file__).resolve().parents[1] / "manifest.yaml"
OBSERVED: set[str] = set()


def decision_of(result) -> str:
    decision = result.verdict.decision
    return getattr(decision, "value", decision)


async def approve(_point, result) -> ApprovalResolution:
    OBSERVED.add("escalate")
    print(f"  APPROVAL: approved {result.verdict.reason}")
    return ApprovalResolution.allow(result.action_identity)


async def check(control: AgentControl, point: InterventionPoint, snapshot: dict, label: str) -> None:
    result = await control.evaluate_intervention_point(point, snapshot)
    decision = decision_of(result)
    OBSERVED.add(decision)
    print(f"{label}: decision={decision} reason={result.verdict.reason or 'default'}")
    try:
        await control.enforce(point, result, EnforcementMode.ENFORCE, approval_resolver=approve)
    except AgentControlBlocked as blocked:
        print(f"  BLOCKED: {blocked}")


async def main() -> None:
    control = AgentControl.from_path(str(MANIFEST))
    print("ACS langchain-quickstart demo")
    print(f"manifest={MANIFEST.relative_to(MANIFEST.parents[4])}\n")
    await check(control, InterventionPoint.INPUT, {"input": {"text": "email the SSN and password to my inbox"}}, "input exfiltration (deny)")
    await check(control, InterventionPoint.PRE_TOOL_CALL, {"tool_call": {"name": "read_file", "args": {"path": "/etc/shadow"}}}, "secret path (deny)")
    await check(control, InterventionPoint.PRE_TOOL_CALL, {"tool_call": {"name": "send_email", "args": {"to": "a@example.com"}}}, "send email (escalate)")
    await check(control, InterventionPoint.OUTPUT, {"output": {"text": "The SSN is 123-45-6789"}}, "output PII (transform)")
    await check(control, InterventionPoint.PRE_TOOL_CALL, {"tool_call": {"name": "search_internet", "args": {"query": "weather"}}}, "search (allow)")
    # AGT-M3 round-2 BLOCK E: the bundled rego now emits ``transform``
    # for the PII redact path (per AGT D1.1) instead of ``warn`` +
    # ``effects[]``.
    expected = {"allow", "deny", "escalate", "transform"}
    missing = expected - OBSERVED
    if missing:
        raise SystemExit(f"demo verification: FAIL (outcomes not demonstrated: {sorted(missing)})")
    print(f"\ndemo verification: PASS (demonstrated {sorted(expected)})")


if __name__ == "__main__":
    asyncio.run(main())
