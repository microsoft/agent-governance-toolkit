from __future__ import annotations

import re
from typing import Any

from .plan import PolicyPlan
from .util import slugify
from .vocabulary import ACS_VERSION, INTERVENTION_POINT_BY_NAME, POLICY_BUNDLE, POLICY_TYPE

_TOOL_NAME_CONDITION = re.compile(r'input\.tool\.(?:name|id)\s*==\s*"([^"]+)"')


def referenced_tool_names(plan: PolicyPlan) -> list[str]:
    # A tool intervention point requires every gated tool to be declared, otherwise the
    # core rejects the call as tool_unknown. Collect names the plan lists plus any name the
    # rules gate on, so the manifest is self-sufficient regardless of the inventory.
    names: dict[str, None] = {name: None for name in plan.tools if name}
    for rule in plan.rules:
        for condition in rule.conditions:
            for match in _TOOL_NAME_CONDITION.finditer(condition):
                names.setdefault(match.group(1), None)
    return sorted(names)


def build_manifest(plan: PolicyPlan, tool_inventory: dict[str, dict[str, Any]]) -> tuple[dict[str, Any], str]:
    slug = slugify(plan.name)
    policy_id = slug
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
    for point_name in plan.guarded_points:
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
        annotations = {
            binding.annotator: {"from": binding.from_path or "$policy_target"}
            for binding in plan.annotations
            if binding.point == point_name and binding.annotator
        }
        if annotations:
            config["annotations"] = annotations
        manifest["intervention_points"][point_name] = config
    annotators = {
        annotator.name: _annotator_config(annotator.type)
        for annotator in plan.annotators
        if annotator.name
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
