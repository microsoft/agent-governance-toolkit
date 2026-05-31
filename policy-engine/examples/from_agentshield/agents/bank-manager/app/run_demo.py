#!/usr/bin/env python3
from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any, Mapping

from agent_control_specification import AgentControl, AgentControlBlocked, ApprovalResolution, EnforcementMode, InterventionPoint

MANIFEST = Path(__file__).resolve().parents[1] / "manifest.yaml"
OBSERVED: set[str] = set()


class HostAnnotators:
    def dispatch(self, annotator_name: str, _config: Mapping[str, Any], preliminary_policy_input: Mapping[str, Any]) -> Any:
        target = preliminary_policy_input["policy_target"]["value"]
        text = json.dumps(target, sort_keys=True).lower()
        if annotator_name == "input_security":
            return {"flagged": "social-engineer" in text or "jailbreak" in text}
        if annotator_name == "tool_adherence":
            return {"flagged": "override_limits" in text}
        if annotator_name == "fraud_classifier":
            return {"label": "fraud" if "mule" in text else "clear"}
        return {}


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
    control = AgentControl.from_path(str(MANIFEST), annotator_dispatcher=HostAnnotators())
    print("ACS bank-manager demo")
    print(f"manifest={MANIFEST.relative_to(MANIFEST.parents[4])}\n")
    await check(control, InterventionPoint.INPUT, {"input": {"text": "Use unauthorized transfer and bypass approval"}}, "input fraud/PII regex (deny)")
    await check(control, InterventionPoint.PRE_TOOL_CALL, {"tool_call": {"name": "create_transfer", "args": {"amount": 100}}, "mode": "restricted", "transfer_approved": True, "customer_ack_token": "ack"}, "restricted mode tool (deny)")
    await check(control, InterventionPoint.PRE_TOOL_CALL, {"tool_call": {"name": "prepare_transfer", "args": {"amount": 12000}}, "transfer_amount": 12000}, "high-value prepare (escalate)")
    await check(control, InterventionPoint.POST_TOOL_CALL, {"tool_result": {"text": "Account SSN 123-45-6789"}}, "tool result PII (transform)")
    await check(control, InterventionPoint.PRE_TOOL_CALL, {"tool_call": {"name": "read_account", "args": {"account_id": "A-1"}}}, "read account (allow)")
    # AGT-M3 round-2 BLOCK E: the bundled rego now emits ``transform``
    # for the PII redact path (per AGT D1.1) instead of ``warn`` +
    # ``effects[]``. Track the new wire string in the expected set.
    expected = {"allow", "deny", "escalate", "transform"}
    missing = expected - OBSERVED
    if missing:
        raise SystemExit(f"demo verification: FAIL (outcomes not demonstrated: {sorted(missing)})")
    print(f"\ndemo verification: PASS (demonstrated {sorted(expected)})")


if __name__ == "__main__":
    asyncio.run(main())
