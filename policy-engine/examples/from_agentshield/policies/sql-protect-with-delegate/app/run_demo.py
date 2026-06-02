#!/usr/bin/env python3
"""Deterministic ACS runtime demo for sql-protect-with-delegate."""

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
    print(f"  APPROVAL: manager approved {result.verdict.reason}")
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


def sql_snapshot(operation: str, tables: list[str]) -> dict:
    return {"prod_tables": ["dbo.customers", "dbo.orders"], "parsed_sql": {"operation": operation, "tables": tables, "is_ddl": False, "has_where": True}}


async def main() -> None:
    control = AgentControl.from_path(str(MANIFEST), annotator_dispatcher=IntentAnnotator())
    print("ACS sql-protect-with-delegate demo")
    print(f"manifest={MANIFEST.relative_to(MANIFEST.parents[4])}\n")

    await check(control, InterventionPoint.INPUT, {"input": {"text": "please DELETE FROM production customers"}}, "input destructive prompt (warn)")
    await check(control, InterventionPoint.PRE_TOOL_CALL, {**sql_snapshot("select", ["dbo.customers"]), "tool_call": {"name": "mssql.execute_sql", "args": {"query": "SELECT * FROM dbo.customers"}}}, "execute_sql select (allow)")
    await check(control, InterventionPoint.PRE_TOOL_CALL, {**sql_snapshot("delete", ["dbo.customers"]), "tool_call": {"name": "mssql.execute_sql", "args": {"query": "DELETE FROM dbo.customers WHERE id = 1"}}}, "destructive production SQL (deny)")
    await check(control, InterventionPoint.PRE_TOOL_CALL, {**sql_snapshot("update", ["dbo.orders"]), "tool_call": {"name": "mssql.execute_sql", "args": {"query": "UPDATE dbo.orders SET status = 'hold'"}}}, "write production SQL (escalate)")
    await check(control, InterventionPoint.PRE_TOOL_CALL, {"prod_tables": ["dbo.customers"], "tool_call": {"name": "mssql.update_data", "args": {"table": "dbo.customers", "set": {"name": "Jane"}}}}, "structured production write (escalate)")
    await check(control, InterventionPoint.PRE_TOOL_CALL, {**sql_snapshot("insert", ["dev.payroll"]), "tool_call": {"name": "mssql.execute_sql", "args": {"query": "INSERT INTO dev.payroll VALUES (1)"}}}, "intent mismatch (warn)")
    await check(control, InterventionPoint.PRE_TOOL_CALL, {"prod_tables": ["dbo.customers"], "tool_call": {"name": "mssql.execute_sql", "args": {"query": "UPDATE dbo.customers SET name = 'Jane'"}}}, "missing parser snapshot (deny)")

    expected = {"allow", "warn", "deny", "escalate"}
    missing = expected - OBSERVED
    if missing:
        raise SystemExit(f"demo verification: FAIL (outcomes not demonstrated: {sorted(missing)})")
    print(f"\ndemo verification: PASS (demonstrated {sorted(expected)})")


if __name__ == "__main__":
    asyncio.run(main())
