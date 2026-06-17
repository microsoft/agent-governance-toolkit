from __future__ import annotations

import re
from typing import Any

from .plan import PolicyPlan
from .util import slugify
from .vocabulary import ACS_VERSION, INTERVENTION_POINT_BY_NAME, POLICY_BUNDLE, POLICY_TYPE

# A Rego string literal: double-quoted "..." or raw-string `...`. `_STR` captures
# the content of either form via two alternative groups (one will be None).
_DQ = r'"([^"]+)"'
_BT = r"`([^`]+)`"
_STR = rf"(?:{_DQ}|{_BT})"  # group A = double-quoted content, group B = raw content
# Tool name/id read, in dot (input.tool.id) or bracket (input.tool["id"]/`id`) form.
_TOOL_FIELD = r"""input\.tool(?:\.(?:name|id)|\[\s*(?:"(?:name|id)"|`(?:name|id)`)\s*\])"""
_TOOL_NAME_CONDITION = re.compile(rf"{_TOOL_FIELD}\s*==\s*{_STR}")
# The generator's own tool-id idiom: object.get(input.tool, "id", object.get(
# input.tool, "name", "")) == "wire_transfer". Capture the compared tool name.
_TOOL_GET_CONDITION = re.compile(rf"object\.get\(\s*input\.tool\b[^=]*==\s*{_STR}")
# Set/array-membership gate: input.tool.id in {"wire_transfer", ...} or [...] (or
# an object.get(...) on the left). Capture the whole set; names extracted below.
_TOOL_IN_CONDITION = re.compile(
    rf'(?:{_TOOL_FIELD}|object\.get\(\s*input\.tool\b[^{{\[]*?)\s+in\s+[\{{\[]([^}}\]]*)[\}}\]]'
)
_SET_STRING = re.compile(_STR)
# Annotation references in dot form (input.annotations.name), bracket form
# (input.annotations["name"]/`name`), or object.get(input.annotations, "name", default).
_ANNOTATION_REF = re.compile(
    rf"input\.annotations(?:\.([A-Za-z_][A-Za-z0-9_]*)|\[\s*{_STR}\s*\])"
)
_ANNOTATION_GET = re.compile(rf"object\.get\(\s*input\.annotations\s*,\s*{_STR}")


def _match_string(match: "re.Match[str]", first_group: int) -> str:
    # Given a match whose string-literal occupies two alternative groups
    # (double-quoted, then raw), return whichever content matched.
    return match.group(first_group) if match.group(first_group) is not None else match.group(first_group + 1)


def _annotation_names(text: str) -> set[str]:
    names: set[str] = set()
    for m in _ANNOTATION_REF.finditer(text):
        # group(1) = dot identifier; groups(2,3) = bracket string literal (dq, raw).
        names.add(m.group(1) if m.group(1) is not None else _match_string(m, 2))
    for m in _ANNOTATION_GET.finditer(text):
        names.add(_match_string(m, 1))
    return names


def referenced_annotators_by_point(plan: PolicyPlan) -> dict[str, set[str]]:
    # An annotator a rule reads must be wired into that point via the manifest
    # `annotations` map, otherwise input.annotations.<name> is always empty and
    # the rule can never fire (a silent fail-open). Derive the wiring from the
    # rules so the manifest is self-sufficient regardless of what bindings the
    # plan happened to declare.
    by_point: dict[str, set[str]] = {}
    for rule in plan.rules:
        names = _annotation_names(" ".join(rule.conditions))
        if names:
            by_point.setdefault(rule.point, set()).update(names)
    return by_point


def referenced_tool_names(plan: PolicyPlan) -> list[str]:
    # A tool intervention point requires every gated tool to be declared, otherwise the
    # core rejects the call as tool_unknown. Collect names the plan lists plus any name the
    # rules gate on, so the manifest is self-sufficient regardless of the inventory.
    names: dict[str, None] = {name: None for name in plan.tools if name}
    for rule in plan.rules:
        for condition in rule.conditions:
            for match in _TOOL_NAME_CONDITION.finditer(condition):
                names.setdefault(_match_string(match, 1), None)
            for match in _TOOL_GET_CONDITION.finditer(condition):
                names.setdefault(_match_string(match, 1), None)
            for match in _TOOL_IN_CONDITION.finditer(condition):
                for str_match in _SET_STRING.finditer(match.group(1)):
                    names.setdefault(_match_string(str_match, 1), None)
    return sorted(names)


def build_manifest(plan: PolicyPlan, tool_inventory: dict[str, dict[str, Any]]) -> tuple[dict[str, Any], str]:
    slug = slugify(plan.name)
    policy_id = slug
    annotators_by_point = referenced_annotators_by_point(plan)
    manifest: dict[str, Any] = {
        "agent_control_specification_version": ACS_VERSION,
        "metadata": {"name": slug},
        "extends": [],
        "policies": {
            policy_id: {
                "type": POLICY_TYPE,
                "bundle": POLICY_BUNDLE,
                "query": f"data.agent_control_specification.{slug}.verdict",
            }
        },
        "intervention_points": {},
    }
    # Reconcile guarded points with the points the rules actually target: a rule
    # whose point is not guarded would be emitted in the Rego but never queried by
    # the manifest, leaving it silently unenforced. Guard every point that has a
    # rule, preserving the declared order then appending any extras.
    guarded = list(dict.fromkeys(plan.guarded_points))
    for rule in plan.rules:
        if rule.point not in guarded and rule.point in INTERVENTION_POINT_BY_NAME:
            guarded.append(rule.point)
    for point_name in guarded:
        spec = INTERVENTION_POINT_BY_NAME.get(point_name)
        if spec is None:
            continue
        config: dict[str, Any] = {
            "policy_target": spec.policy_target,
            "policy_target_kind": spec.policy_target_kind,
            "policy": {
                "id": policy_id,
                "query": f"data.agent_control_specification.{slug}.{point_name}_verdict",
            },
        }
        if spec.tool_name_from:
            config["tool_name_from"] = spec.tool_name_from
        # Start from any explicit plan bindings, then add every annotator the
        # point's rules actually read so no reference is left dead-wired.
        annotations = {
            binding.annotator: {"from": binding.from_path or "$policy_target"}
            for binding in plan.annotations
            if binding.point == point_name and binding.annotator
        }
        for name in sorted(annotators_by_point.get(point_name, set())):
            annotations.setdefault(name, {"from": "$policy_target"})
        if annotations:
            config["annotations"] = annotations
        manifest["intervention_points"][point_name] = config
    # Declare every annotator the plan names plus any a rule reads, so a wired
    # binding always resolves to a declared annotator.
    referenced_annotators = {name for names in annotators_by_point.values() for name in names}
    annotator_types = {annotator.name: annotator.type for annotator in plan.annotators if annotator.name}
    annotators = {
        name: _annotator_config(annotator_types.get(name, "classifier"))
        for name in sorted(set(annotator_types) | referenced_annotators)
    }
    if annotators:
        manifest["annotators"] = annotators
    selected_tools = {
        name: tool_inventory.get(name, {"type": "Tool", "id": name}) for name in referenced_tool_names(plan)
    }
    if selected_tools:
        manifest["tools"] = selected_tools
    return manifest, slug


def _annotator_config(annotator_type: str) -> dict[str, Any]:
    return {"type": annotator_type}
