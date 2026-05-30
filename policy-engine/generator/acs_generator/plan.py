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
    for effect in effects:
        _validate_effect(effect)
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
