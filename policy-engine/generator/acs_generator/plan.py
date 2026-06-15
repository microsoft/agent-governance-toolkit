from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from .vocabulary import ANNOTATOR_TYPES, DECISIONS, EFFECT_TYPES, INTERVENTION_POINT_NAMES


@dataclass(frozen=True)
class AnnotatorPlan:
    name: str
    type: str
    labels: tuple[str, ...] = ()


@dataclass(frozen=True)
class AnnotationBindingPlan:
    point: str
    annotator: str
    from_path: str


@dataclass(frozen=True)
class RulePlan:
    point: str
    decision: str
    reason: str
    message: str
    conditions: tuple[str, ...] = ()
    effects: tuple[dict[str, Any], ...] = ()


@dataclass(frozen=True)
class PolicyPlan:
    name: str
    guarded_points: tuple[str, ...]
    annotators: tuple[AnnotatorPlan, ...] = ()
    annotations: tuple[AnnotationBindingPlan, ...] = ()
    tools: tuple[str, ...] = ()
    rules: tuple[RulePlan, ...] = ()
    warnings: tuple[str, ...] = field(default_factory=tuple)


class PlanError(ValueError):
    pass


def redact_patterns(plan: PolicyPlan) -> tuple[str, ...]:
    """Every redact-effect regex that will appear in the rendered policy, for RE2
    validity checking. Only transform rules carry effects into the Rego, and only
    `redact`-type effects render a regex (a `replace` effect's `pattern`, if any,
    is ignored by the renderer), so other effects are excluded."""
    return tuple(
        str(effect["pattern"])
        for rule in plan.rules
        if rule.decision == "transform"
        for effect in rule.effects
        if str(effect.get("type")) == "redact" and effect.get("pattern")
    )


def parse_policy_plan(raw: str) -> PolicyPlan:
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise PlanError(f"LLM response is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise PlanError("LLM response must be a JSON object")
    return PolicyPlan(
        name=str(data.get("name") or data.get("metadata_name") or "generated_policy"),
        guarded_points=tuple(str(point) for point in data.get("guarded_points", [])),
        annotators=tuple(_annotator(item) for item in data.get("annotators", [])),
        annotations=tuple(_annotation(item) for item in data.get("annotations", [])),
        tools=tuple(name for name in (_tool_name(tool) for tool in data.get("tools", [])) if name),
        rules=tuple(_rule(item) for item in data.get("rules", [])),
        warnings=tuple(str(item) for item in data.get("warnings", [])),
    )


def _tool_name(tool: Any) -> str:
    if isinstance(tool, dict):
        return str(tool.get("id") or tool.get("name") or "")
    return str(tool)


def _annotator(item: Any) -> AnnotatorPlan:
    if not isinstance(item, dict):
        raise PlanError("annotators entries must be objects")
    annotator_type = str(item.get("type", ""))
    if annotator_type not in ANNOTATOR_TYPES:
        raise PlanError(f"unsupported annotator type: {annotator_type}")
    labels = item.get("labels", [])
    if not isinstance(labels, list):
        raise PlanError("annotator labels must be a list")
    return AnnotatorPlan(name=str(item.get("name", "")), type=annotator_type, labels=tuple(str(label) for label in labels))


def _annotation(item: Any) -> AnnotationBindingPlan:
    if not isinstance(item, dict):
        raise PlanError("annotations entries must be objects")
    return AnnotationBindingPlan(
        point=str(item.get("point", "")),
        annotator=str(item.get("annotator", "")),
        from_path=str(item.get("from", item.get("from_path", ""))),
    )


def _rule(item: Any) -> RulePlan:
    if not isinstance(item, dict):
        raise PlanError("rules entries must be objects")
    point = str(item.get("point", ""))
    if point not in INTERVENTION_POINT_NAMES:
        raise PlanError(
            f"unsupported rule point '{point}'; every rule must set point to one of: "
            + ", ".join(INTERVENTION_POINT_NAMES)
        )
    decision = str(item.get("decision", ""))
    if decision not in DECISIONS:
        raise PlanError(f"unsupported decision: {decision}")
    effects = item.get("effects", [])
    if not isinstance(effects, list):
        raise PlanError("rule effects must be a list")
    if decision == "transform":
        # Only a transform decision carries effects into the rendered Rego;
        # effects on allow/warn/deny/escalate are dropped (and surfaced as a
        # generation warning), so they are not validated here to avoid failing
        # generation over an effect that never appears in the output.
        for effect in effects:
            _validate_effect(effect)
        # ACS applies exactly one transform (one path, one value) per verdict, so
        # a transform rule whose effects target different paths cannot be compiled
        # faithfully. Require a single target path; author separate rules for
        # separate locations.
        paths = {str(effect.get("path") or "$policy_target") for effect in effects}
        if len(paths) > 1:
            raise PlanError(
                "a transform rule's effects must target a single path; got " + ", ".join(sorted(paths))
            )
        # A single verdict yields a single value, so contradictory effect
        # combinations (a whole-value replace mixed with a regex redact, or two
        # replaces) cannot be honored together and would be silently miscompiled.
        replaces = [effect for effect in effects if str(effect.get("type")) == "replace"]
        redacts = [effect for effect in effects if str(effect.get("type")) == "redact"]
        if replaces and redacts:
            raise PlanError("a transform rule cannot mix replace and redact effects; use one or the other")
        if len(replaces) > 1:
            raise PlanError("a transform rule may carry at most one replace effect")
    conditions = item.get("conditions", [])
    if not isinstance(conditions, list):
        raise PlanError("rule conditions must be a list")
    condition_tuple = tuple(str(condition) for condition in conditions if str(condition).strip())
    if decision != "allow" and not condition_tuple:
        raise PlanError(
            f"rule for '{point}' with decision '{decision}' must define at least one condition; "
            "an unconditional rule would fire on every request at this intervention point"
        )
    return RulePlan(
        point=point,
        decision=decision,
        reason=str(item.get("reason", decision)),
        message=str(item.get("message", "")),
        conditions=condition_tuple,
        effects=tuple(effects),
    )


def _validate_effect(effect: Any) -> None:
    if not isinstance(effect, dict):
        raise PlanError("effects must be objects")
    effect_type = str(effect.get("type", ""))
    if effect_type not in EFFECT_TYPES:
        raise PlanError(f"unsupported effect type: {effect_type}")
    path = str(effect.get("path", ""))
    if not path.startswith("$policy_target"):
        raise PlanError(f"effect path must start with $policy_target: {path}")
    # Only redact and replace are expressible as a single AGT D1.1 transform.
    # `append` has no faithful single-target transform form (string vs array,
    # path semantics), so reject it rather than miscompile it.
    if effect_type == "append":
        raise PlanError("append effect is not expressible as an AGT D1.1 transform; use replace or redact")
    if effect_type == "redact":
        pattern = effect.get("pattern")
        if not pattern:
            raise PlanError("redact effect requires a 'pattern'")
        if not isinstance(pattern, str):
            raise PlanError("redact effect 'pattern' must be a string")
        # Regex validity is checked against RE2 (OPA's engine) in
        # validation._validate_regex_patterns. We deliberately do NOT pre-validate
        # with Python's `re`, which both accepts patterns RE2 rejects (lookaround,
        # backrefs) and rejects RE2-valid patterns (e.g. \p{L}); RE2 is authoritative.
    if effect_type == "replace" and "value" not in effect:
        raise PlanError("replace effect requires a 'value'")
