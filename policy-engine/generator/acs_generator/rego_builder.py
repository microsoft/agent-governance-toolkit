from __future__ import annotations

import json
import re
from collections import defaultdict
from typing import Any

from .plan import PolicyPlan, RulePlan
from .vocabulary import INTERVENTION_POINT_NAMES, POLICY_INPUT_POINT_KEY

INDENT = "    "

# Core transform-path grammar, verified empirically against the runtime: $policy_target
# followed by zero or more `.field` (object key) or `[N]` (numeric list index) segments.
# The core REJECTS quoted/string bracket keys like $policy_target["k"]
# (runtime_error:policy_invocation_failed) and a trailing-dot/empty segment, so we
# accept only dotted identifiers and numeric indices and reset anything else to root.
_TRANSFORM_PATH_RE = re.compile(r"^\$policy_target(\.[A-Za-z_][A-Za-z0-9_]*|\[[0-9]+\])*$")

# Higher value wins when more than one rule body matches the same intervention point.
# `transform` (mutation/redaction) outranks `warn` so a redact rule is never shadowed
# by a warn rule at the same point, but stays below `escalate`/`deny` which halt the action.
_DECISION_SEVERITY = {"deny": 4, "escalate": 3, "transform": 2, "warn": 1, "allow": 0}


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
    # Order by decision severity (deny > escalate > transform > warn > allow), stable
    # within a tier, so the most restrictive matching rule wins deterministically.
    ordered = sorted(rules, key=lambda rule: -_DECISION_SEVERITY.get(rule.decision, 0))
    lines: list[str] = []
    for index, rule in enumerate(ordered):
        verdict_str, extra_body = _render_verdict(rule)
        head = f"{point}_verdict := {verdict_str}" if index == 0 else f"else := {verdict_str}"
        lines.append(f"{head} if {{")
        lines.append(f'{INDENT}input.{POLICY_INPUT_POINT_KEY} == "{point}"')
        for condition in rule.conditions:
            for line in condition.splitlines():
                if line.strip():
                    lines.append(f"{INDENT}{line.strip()}")
        for line in extra_body:
            lines.append(f"{INDENT}{line}")
        lines.append("}")
    return lines


def _render_verdict(rule: RulePlan) -> tuple[str, list[str]]:
    """Render a verdict object plus any extra Rego body lines it needs.

    AGT D1 removed the verdict ``effects`` array. Only a ``transform`` decision
    may carry a payload, and it is a single object rooted at ``$policy_target``.
    ``allow``/``warn``/``deny``/``escalate`` must never mutate, so any effects on
    those decisions are dropped. A ``transform`` decision renders a
    ``transform`` object; a regex redaction is computed in the rule body.
    """
    verdict: dict[str, Any] = {"decision": rule.decision, "reason": rule.reason, "message": rule.message}
    if rule.decision != "transform":
        return json.dumps(verdict, indent=4), []
    return _render_transform_verdict(verdict, rule)


def _redaction_replacement(effect: dict[str, Any]) -> str:
    # Prefer the explicit replacement; allow an empty string (deletion-style
    # redaction), so use `is None` rather than truthiness.
    replacement = "[REDACTED]"
    for key in ("value", "replacement"):
        if effect.get(key) is not None:
            replacement = str(effect[key])
            break
    # OPA's regex.replace expands `$1`/`$name` in the replacement as capture-group
    # references (Go semantics), which could re-insert the matched secret. The
    # replacement is meant as literal text, so escape `$` to `$$`.
    return replacement.replace("$", "$$")


def _read_expr_for_path(path: str) -> str:
    # Translate a $policy_target transform path to the Rego read expression for
    # the same location: $policy_target -> input.policy_target.value,
    # $policy_target.text -> input.policy_target.value.text, [0] -> ...[0].
    return "input.policy_target.value" + path[len("$policy_target"):]


def _render_transform_verdict(verdict: dict[str, Any], rule: RulePlan) -> tuple[str, list[str]]:
    # Route by effect TYPE, not by the presence of a `pattern` field: a `replace`
    # effect that carries an extraneous `pattern` must still be a whole-value
    # replacement, not a regex redaction.
    redacts = [e for e in rule.effects if str(e.get("type")) == "redact"]
    if redacts:
        # Redaction at the rule's target path (default $policy_target). Chain
        # regex.replace over the rule's own patterns only. We deliberately do NOT
        # union patterns across sibling rules: a rule's redaction is gated by its
        # own conditions, and applying another rule's pattern when that rule's
        # condition is false would be unauthorized over-redaction. ACS applies one
        # transform per evaluation; author a single rule (as guided-init does) to
        # redact multiple patterns together.
        path = _normalize_transform_path(str(redacts[0].get("path") or "$policy_target"))
        read_expr = _read_expr_for_path(path)
        extra_body = [f"is_string({read_expr})"]
        expr = read_expr
        for effect in redacts:
            replacement = _redaction_replacement(effect)
            expr = f"regex.replace({expr}, {json.dumps(str(effect['pattern']))}, {json.dumps(replacement)})"
        extra_body.append(f"__transform_value := {expr}")
        return _verdict_with_value_ref(verdict, path, "__transform_value"), extra_body
    effect = rule.effects[0] if rule.effects else {}
    path = _normalize_transform_path(str(effect.get("path") or "$policy_target"))
    if "value" in effect:
        verdict["transform"] = {"path": path, "value": effect["value"]}
        return json.dumps(verdict, indent=4), []
    # Identity transform (transform decision with no usable effect): replace the
    # target with itself so the verdict is core-valid rather than unsafe Rego.
    extra_body = [f"__transform_value := {_read_expr_for_path(path)}"]
    return _verdict_with_value_ref(verdict, path, "__transform_value"), extra_body


def _normalize_transform_path(path: str) -> str:
    # Models routinely append `.value`, conflating the transform root with the
    # input.policy_target.value read path; the policy target *is* the value, so
    # `$policy_target.value` indexes into it and the core rejects it on a scalar
    # target. Correct that one common literal case before grammar validation,
    # leaving deeper nested paths ($policy_target.a.b, $policy_target[0]) intact.
    if path == "$policy_target.value":
        return "$policy_target"
    # Anything that is not a well-formed $policy_target path (a bad root such as
    # "$policy_target" with an unexpected suffix, or a trailing-dot/empty segment) is
    # reset to the root so the core never fails closed on a malformed path.
    if not _TRANSFORM_PATH_RE.match(path):
        return "$policy_target"
    return path


def _verdict_with_value_ref(verdict: dict[str, Any], path: str, value_ref: str) -> str:
    # Build the verdict object with an unquoted Rego variable as transform.value.
    fields = ", ".join(f"{json.dumps(key)}: {json.dumps(value)}" for key, value in verdict.items())
    transform = f'"transform": {{"path": {json.dumps(path)}, "value": {value_ref}}}'
    return "{" + fields + ", " + transform + "}"
