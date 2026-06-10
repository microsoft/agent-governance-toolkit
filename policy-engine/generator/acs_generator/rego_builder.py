from __future__ import annotations

import json
from collections import defaultdict
from typing import Any

from .plan import PolicyPlan, RulePlan
from .vocabulary import INTERVENTION_POINT_NAMES, POLICY_INPUT_POINT_KEY

INDENT = "    "

# Higher value wins when more than one rule body matches the same intervention point.
_DECISION_SEVERITY = {"deny": 3, "escalate": 2, "warn": 1, "allow": 0}


def build_rego(plan: PolicyPlan, slug: str) -> str:
    rules_by_point: dict[str, list[RulePlan]] = defaultdict(list)
    for rule in plan.rules:
        rules_by_point[rule.point].append(rule)
    lines = [
        f"package agent_control_specification.{slug}",
        "",
        "import rego.v1",
        "",
        'default verdict := {"decision": "allow"}',
    ]
    lines.extend(f'default {point}_verdict := {{"decision": "allow"}}' for point in INTERVENTION_POINT_NAMES)
    lines.append("")
    lines.extend(
        f'verdict := {point}_verdict if {{ input.{POLICY_INPUT_POINT_KEY} == "{point}" }}'
        for point in INTERVENTION_POINT_NAMES
    )
    for point in INTERVENTION_POINT_NAMES:
        rules = rules_by_point.get(point)
        if rules:
            lines.extend(["", *_render_point(point, rules)])
    lines.append("")
    return "\n".join(lines)


def _render_point(point: str, rules: list[RulePlan]) -> list[str]:
    # Emit a single else-chain so OPA never sees conflicting complete-rule outputs.
    # Order by decision severity (deny > escalate > warn > allow), stable within a tier,
    # so the most restrictive matching rule wins deterministically regardless of plan order.
    ordered = sorted(rules, key=lambda rule: -_DECISION_SEVERITY.get(rule.decision, 0))
    lines: list[str] = []
    for index, rule in enumerate(ordered):
        head = f"{point}_verdict := {_render_verdict(rule)}" if index == 0 else f"else := {_render_verdict(rule)}"
        lines.append(f"{head} if {{")
        lines.append(f'{INDENT}input.{POLICY_INPUT_POINT_KEY} == "{point}"')
        for condition in rule.conditions:
            for line in condition.splitlines():
                if line.strip():
                    lines.append(f"{INDENT}{line.strip()}")
        lines.append("}")
    return lines


def _render_verdict(rule: RulePlan) -> str:
    verdict: dict[str, Any] = {"decision": rule.decision, "reason": rule.reason, "message": rule.message}
    if rule.effects:
        verdict["effects"] = list(rule.effects)
    return json.dumps(verdict, indent=4)
