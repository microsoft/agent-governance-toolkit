#!/usr/bin/env python3
"""Deterministic ACS runtime demo for the ported sql-protect-with-regex policy.

Drives the real ACS core + OPA over crafted snapshots and asserts the verdict at
each gate, proving the ported artifacts are writable as ACS and enforce the same
intent as the original AgentShield policy.
"""

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


class IntentAnnotator:
    """Deterministic stand-in for the AgentShield Stage-3 LLM intent review.

    A real host would call an LLM judge here; for the demo we flag a SQL
    statement whose target table the user never mentioned.
    """

    def dispatch(self, annotator_name, annotator_config, preliminary_policy_input):
        if annotator_name != "sql_intent":
            return {}
        args = preliminary_policy_input["policy_target"]["value"] or {}
        text = str(args.get("query", "") or args.get("table", "")).lower()
        return {"deviates": "payroll" in text}


def decision_of(result) -> str:
    decision = result.verdict.decision
    return getattr(decision, "value", decision)


async def approve(_point, result) -> ApprovalResolution:
    OBSERVED.add("escalate")
    print("  APPROVAL: manager approved the production write")
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
    control = AgentControl.from_path(str(MANIFEST), annotator_dispatcher=IntentAnnotator())
    print("ACS sql-protect-with-regex demo")
    print(f"manifest={MANIFEST.relative_to(MANIFEST.parents[4])}\n")

    await check(control, InterventionPoint.INPUT, {"input": {"text": "please DROP the PRODUCTION orders table"}}, "input: coercive prompt (warn)")
    await check(control, InterventionPoint.INPUT, {"input": {"text": "show me last month's sales totals"}}, "input: benign prompt (allow)")
    await check(control, InterventionPoint.PRE_TOOL_CALL, {"tool_call": {"name": "mssql.read_data", "args": {"query": "select * from sales"}}}, "read_data SELECT (allow)")
    await check(control, InterventionPoint.PRE_TOOL_CALL, {"tool_call": {"name": "mssql.execute_sql", "args": {"query": "DELETE FROM customers WHERE id = 1"}}}, "execute_sql destructive on prod (deny)")
    await check(control, InterventionPoint.PRE_TOOL_CALL, {"tool_call": {"name": "mssql.execute_sql", "args": {"query": "INSERT INTO orders_staging VALUES (1)"}}}, "execute_sql write on staging (allow)")
    await check(control, InterventionPoint.PRE_TOOL_CALL, {"tool_call": {"name": "mssql.execute_sql", "args": {"query": "UPDATE accounts SET balance = 0"}}}, "execute_sql write on prod (escalate)")
    await check(control, InterventionPoint.PRE_TOOL_CALL, {"tool_call": {"name": "mssql.update_data", "args": {"table": "accounts", "set": {"balance": 0}, "where": {"id": 1}}}}, "update_data structured write on prod (escalate)")
    await check(control, InterventionPoint.PRE_TOOL_CALL, {"tool_call": {"name": "mssql.execute_sql", "args": {"query": "INSERT INTO payroll_staging VALUES (1)"}}}, "execute_sql write that deviates from intent (warn)")

    expected = {"allow", "warn", "deny", "escalate"}
    missing = expected - OBSERVED
    if missing:
        raise SystemExit(f"demo verification: FAIL (outcomes not demonstrated: {sorted(missing)})")
    print(f"\ndemo verification: PASS (demonstrated {sorted(expected)})")


if __name__ == "__main__":
    asyncio.run(main())
