#!/usr/bin/env python3
"""Deterministic ACS runtime demo for endpoint-governance."""

from __future__ import annotations

import asyncio
from pathlib import Path

from agent_control_specification import (
    AgentControl,
    AgentControlBlocked,
    ApprovalResolution,
    EnforcementMode,
    InterventionPoint,
)

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
    print("ACS endpoint-governance demo")
    print(f"manifest={MANIFEST.relative_to(MANIFEST.parents[4])}\n")

    await check(control, InterventionPoint.INPUT, {"input": {"text": "please drop table users"}}, "input SQL injection (deny)")
    await check(control, InterventionPoint.PRE_TOOL_CALL, {"tool_call": {"name": "http.request", "args": {"method": "GET", "path": "/api/v1/health"}}}, "allowed endpoint (allow)")
    await check(control, InterventionPoint.PRE_TOOL_CALL, {"tool_call": {"name": "http.request", "args": {"method": "GET", "path": "/admin/users"}}}, "blocked admin endpoint (deny)")
    await check(control, InterventionPoint.PRE_TOOL_CALL, {"tool_call": {"name": "http.request", "args": {"method": "POST", "path": "/api/v1/health"}}}, "wrong method (deny)")
    await check(control, InterventionPoint.PRE_TOOL_CALL, {"tool_call": {"name": "http.request", "args": {"method": "GET", "path": "/api/v1/projects"}}}, "unlisted endpoint (deny)")
    await check(control, InterventionPoint.PRE_TOOL_CALL, {"api_tier": "user", "tool_call": {"name": "http.request", "args": {"method": "PUT", "path": "/api/v1/users/u1"}}}, "user modify without admin tier (deny)")
    await check(control, InterventionPoint.PRE_TOOL_CALL, {"api_tier": "admin", "tool_call": {"name": "http.request", "args": {"method": "PUT", "path": "/api/v1/users/u1"}}}, "user modify with admin tier (escalate)")
    await check(control, InterventionPoint.PRE_TOOL_CALL, {"tool_call": {"name": "http.request", "args": {"method": "POST", "path": "/api/v1/payments/p1"}}}, "payment endpoint (escalate)")
    await check(control, InterventionPoint.PRE_TOOL_CALL, {"tool_call": {"name": "http.request", "args": {"method": "GET", "path": "/internal/status"}}}, "internal endpoint audit (warn)")

    expected = {"allow", "warn", "deny", "escalate"}
    missing = expected - OBSERVED
    if missing:
        raise SystemExit(f"demo verification: FAIL (outcomes not demonstrated: {sorted(missing)})")
    print(f"\ndemo verification: PASS (demonstrated {sorted(expected)})")


if __name__ == "__main__":
    asyncio.run(main())
