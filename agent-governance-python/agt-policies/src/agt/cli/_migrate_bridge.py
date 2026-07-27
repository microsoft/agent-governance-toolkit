# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Private one-way v4 GovernancePolicy to ACS migration translator."""

from __future__ import annotations

import json
import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from agt.policies.manifest import AgtManifest
from agt.policies._re2 import glob_to_re2, validate_re2

ACS_VERSION = "0.3.0-alpha-agt"
_REASON_PATTERN = "blocked_pattern_input"


@dataclass
class MigrationPolicyInput:
    """Strict literal v4 shape accepted by the one-way migrator."""

    name: str = "default"
    max_tokens: int = 4096
    max_tool_calls: int = 10
    allowed_tools: list[str] = field(default_factory=list)
    blocked_patterns: list[str | tuple[str, str]] = field(default_factory=list)
    require_human_approval: bool = False
    confidence_threshold: float = 0.8
    version: str = "1.0.0"

    def __post_init__(self) -> None:
        if (
            isinstance(self.max_tokens, bool)
            or not isinstance(self.max_tokens, int)
            or self.max_tokens <= 0
        ):
            raise ValueError("max_tokens must be a positive integer")
        if (
            isinstance(self.max_tool_calls, bool)
            or not isinstance(self.max_tool_calls, int)
            or self.max_tool_calls < 0
        ):
            raise ValueError("max_tool_calls must be a non-negative integer")
        if isinstance(self.confidence_threshold, bool) or not isinstance(
            self.confidence_threshold, (int, float)
        ) or not (
            0.0 <= self.confidence_threshold <= 1.0
        ):
            raise ValueError(
                "confidence_threshold must be between 0.0 and 1.0"
            )
        if not isinstance(self.require_human_approval, bool):
            raise ValueError("require_human_approval must be a boolean")
        if not isinstance(self.version, str) or not self.version:
            raise ValueError("version must be a non-empty string")
        if not isinstance(self.allowed_tools, list):
            raise ValueError("allowed_tools must be a list")
        for tool in self.allowed_tools:
            if not isinstance(tool, str):
                raise ValueError("allowed_tools entries must be strings")
        if not isinstance(self.blocked_patterns, list):
            raise ValueError("blocked_patterns must be a list")
        for pattern in self.blocked_patterns:
            _pattern_to_regex(pattern)


def build_migrated_manifest(
    policy: MigrationPolicyInput,
    *,
    bundle_dir: Path,
    policy_id: str,
    stock_rego_root: Path | None = None,
) -> dict[str, Any]:
    """Materialize and validate the ACS manifest for one v4 policy."""
    bundle_dir = Path(bundle_dir).resolve()
    bundle_dir.mkdir(parents=True, exist_ok=True)
    stock_root = stock_rego_root or _find_stock_rego_root()
    for rego_file in stock_root.glob("*.rego"):
        if not rego_file.name.endswith("_test.rego"):
            shutil.copy(rego_file, bundle_dir / rego_file.name)

    patterns = [_pattern_to_regex(pattern) for pattern in policy.blocked_patterns]
    rego_source = _render_rego(
        package="agt.governance_policy",
        max_tokens=policy.max_tokens if policy.max_tokens > 0 else None,
        max_tool_calls=(
            policy.max_tool_calls if policy.max_tool_calls >= 0 else None
        ),
        confidence_threshold=(
            policy.confidence_threshold
            if policy.confidence_threshold > 0
            else None
        ),
        blocked_patterns=patterns,
        require_human_approval=policy.require_human_approval,
    )
    (bundle_dir / f"{policy_id}.rego").write_text(rego_source, encoding="utf-8")

    bind_tools = (
        bool(policy.allowed_tools)
        or policy.max_tool_calls >= 0
        or policy.require_human_approval
    )
    intervention_points = _build_intervention_points(
        policy_id,
        bind_input=bool(policy.blocked_patterns),
        bind_tools=bind_tools,
        bind_output=bool(policy.blocked_patterns),
        bind_post_model_call=policy.confidence_threshold > 0,
        bind_tools_with_catalog=bool(policy.allowed_tools),
    )
    if not intervention_points:
        intervention_points["pre_tool_call"] = {
            "policy_target": "$.tool_call.args",
            "policy_target_kind": "tool_args",
            "policy": {"id": policy_id},
        }

    manifest: dict[str, Any] = {
        "agent_control_specification_version": ACS_VERSION,
        "metadata": {
            "name": policy.name,
            "source": "agt.cli._migrate_bridge.build_migrated_manifest",
            "policy_version": policy.version,
        },
        "extends": [],
        "policies": {
            policy_id: {
                "type": "rego",
                "bundle": str(bundle_dir),
                "query": "data.agt.governance_policy.verdict",
            }
        },
        "intervention_points": intervention_points,
    }
    if policy.allowed_tools:
        manifest["tools"] = {
            tool: {"clearance": "public"} for tool in policy.allowed_tools
        }
    if policy.require_human_approval:
        manifest["approval"] = {}

    return AgtManifest.from_document(manifest).to_document()


def _find_stock_rego_root() -> Path:
    packaged = Path(__file__).with_name("_stock_rego")
    if packaged.is_dir():
        return packaged
    here = Path(__file__).resolve()
    for parent in here.parents:
        candidate = parent / "policy-engine" / "policy" / "lib"
        if candidate.is_dir():
            return candidate
    raise FileNotFoundError(
        "could not locate policy-engine/policy/lib stock Rego root"
    )


def _pattern_to_regex(pattern: str | tuple[str, str]) -> str:
    if isinstance(pattern, str):
        return re.escape(pattern)
    value, kind = pattern
    if kind == "SUBSTRING":
        return re.escape(value)
    if kind == "REGEX":
        validate_re2(value, require_opa=True)
        return value
    if kind == "GLOB":
        return glob_to_re2(value, require_opa=True)
    raise ValueError(f"unsupported PatternType: {kind!r}")


def _render_rego(
    *,
    package: str,
    max_tokens: int | None,
    max_tool_calls: int | None,
    confidence_threshold: float | None,
    blocked_patterns: Iterable[str],
    require_human_approval: bool,
) -> str:
    lines: list[str] = [
        "# Copyright (c) Microsoft Corporation.",
        "# Licensed under the MIT License.",
        "# AUTO-GENERATED by agt migrate v4-to-v5.",
        f"package {package}",
        "import data.agt.approval",
        "import data.agt.budgets",
        "import data.agt.confidence",
        "import data.agt.patterns",
        "import rego.v1",
        "",
        'default verdict := {"decision": "allow"}',
        "",
        "policy_text := value if {",
        "\tvalue := input.policy_target.value",
        "\tis_string(value)",
        "} else := value if {",
        "\ttarget := input.policy_target.value",
        "\tnot is_string(target)",
        "\tvalue := json.marshal(target)",
        "}",
        "",
    ]
    branches: list[str] = []
    pattern_list = list(blocked_patterns)
    if pattern_list:
        rendered = ", ".join(json.dumps(pattern) for pattern in pattern_list)
        branches.append(
            "v := patterns.deny_if_pattern(policy_text, "
            f"[{rendered}], {json.dumps(_REASON_PATTERN)})"
        )
    thresholds: dict[str, Any] = {}
    if max_tool_calls is not None:
        thresholds["tool_call_count"] = max_tool_calls
    if max_tokens is not None:
        thresholds["token_count"] = max_tokens
    if thresholds:
        branches.append(
            f"v := budgets.deny_if_budget_exceeded({json.dumps(thresholds)})"
        )
    if confidence_threshold is not None and confidence_threshold > 0:
        branches.append(
            "v := confidence.deny_if_low_confidence("
            f"{json.dumps(confidence_threshold)})"
        )
    if require_human_approval:
        branches.append(
            'v := approval.escalate_if_approver_required(["human"])'
        )
    for index, branch in enumerate(branches):
        lines.append("verdict := v if {" if index == 0 else "else := v if {")
        lines.append(f"\t{branch}")
        lines.append("}")
    lines.append("")
    return "\n".join(lines)


def _build_intervention_points(
    policy_id: str,
    *,
    bind_input: bool,
    bind_tools: bool,
    bind_output: bool,
    bind_post_model_call: bool,
    bind_tools_with_catalog: bool,
) -> dict[str, Any]:
    bindings: dict[str, Any] = {}
    if bind_tools:
        pre_tool: dict[str, Any] = {
            "policy_target": "$.tool_call.args",
            "policy_target_kind": "tool_args",
            "policy": {"id": policy_id},
        }
        if bind_tools_with_catalog:
            pre_tool["tool_name_from"] = "$.tool_call.name"
        bindings["pre_tool_call"] = pre_tool
    if bind_input:
        bindings["input"] = {
            "policy_target": "$.input.body",
            "policy_target_kind": "user_input",
            "policy": {"id": policy_id},
        }
    if bind_output:
        bindings["output"] = {
            "policy_target": "$.response.content",
            "policy_target_kind": "assistant_output",
            "policy": {"id": policy_id},
        }
    if bind_post_model_call:
        bindings["post_model_call"] = {
            "policy_target": "$.response.content",
            "policy_target_kind": "assistant_output",
            "policy": {"id": policy_id},
        }
    return bindings


__all__ = ["MigrationPolicyInput", "build_migrated_manifest"]
