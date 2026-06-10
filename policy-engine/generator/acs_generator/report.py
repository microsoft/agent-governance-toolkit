from __future__ import annotations

from typing import Any

from .plan import PolicyPlan
from .vocabulary import INTERVENTION_POINT_BY_NAME


def build_report(plan: PolicyPlan, slug: str, manifest: dict[str, Any], warnings: list[str]) -> str:
    lines = [f"# ACS generator report: {slug}", "", "## Assumptions", ""]
    if plan.annotators:
        lines.append("### Annotators")
        for annotator in plan.annotators:
            labels = ", ".join(annotator.labels) or "none declared"
            lines.append(f"- `{annotator.name}` ({annotator.type}) expected labels/outputs: {labels}")
        lines.append("")
    lines.append("### JSONPaths")
    for point_name in manifest["intervention_points"]:
        spec = INTERVENTION_POINT_BY_NAME[point_name]
        lines.append(f"- `{point_name}` policy_target `{spec.policy_target_kind}` at `{spec.policy_target}`")
        if spec.tool_name_from:
            lines.append(f"  - tool name from `{spec.tool_name_from}`")
    lines.append("")
    tools = manifest.get("tools", {})
    lines.append("### Tools")
    if tools:
        for name in tools:
            lines.append(f"- `{name}` from provided inventory")
    else:
        lines.append("- No tools emitted; none were both requested and present in the provided inventory.")
    lines.extend(["", "## Not statically verified", "", "- Classifier labels and scores match real annotator outputs."])
    lines.append("- Policy intent fully captures the natural-language prompt.")
    if warnings or plan.warnings:
        lines.extend(["", "## Warnings", ""])
        for warning in [*plan.warnings, *warnings]:
            lines.append(f"- {warning}")
    lines.append("")
    return "\n".join(lines)
