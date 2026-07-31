# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Private one-way v4 GovernancePolicy to ACS migration translator."""

from __future__ import annotations

import yaml

import json
import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from agent_control_specification import validate_manifest

from ._migrate_re2 import glob_to_re2, validate_re2

ACS_VERSION = "0.3.0-alpha-agt"
_REASON_PATTERN = "blocked_pattern_input"
_CASE_INSENSITIVE = "(?i)"


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

    intervention_points = _build_intervention_points(
        policy_id,
        bind_tools_with_catalog=bool(policy.allowed_tools),
    )

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

    # Validate against the runtime's own contract so the migrator cannot emit
    # a manifest the engine would refuse to load.
    validate_manifest(yaml.safe_dump(manifest, sort_keys=False))
    return manifest


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
    # v4 matched case-insensitively for every pattern kind: substrings via
    # ``pat.lower() in text.lower()``, and REGEX/GLOB via ``re.IGNORECASE``
    # (agent_os/integrations/base.py:406,413 before the v4 removal). RE2 supports
    # the inline ``(?i)`` flag, so carry that across for all four kinds rather
    # than silently tightening migrated policies into case-sensitive matches that
    # let ``PASSWORD``, ``RM -RF`` or ``SETUP.EXE`` through.
    if isinstance(pattern, str):
        return _CASE_INSENSITIVE + re.escape(pattern)
    value, kind = pattern
    if kind == "SUBSTRING":
        return _CASE_INSENSITIVE + re.escape(value)
    if kind == "REGEX":
        composed = _CASE_INSENSITIVE + value
        validate_re2(composed, require_opa=True)
        return composed
    if kind == "GLOB":
        composed = _CASE_INSENSITIVE + glob_to_re2(value, require_opa=True)
        validate_re2(composed, require_opa=True)
        return composed
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
        "# Each string the target carries, matched separately. Collecting leaves",
        "# rather than json.marshal-ing avoids marshal's escaping of \" \\\\ < > and &,",
        "# which would stop a pattern containing any of them from matching. Keeping",
        "# them separate rather than joining preserves whole-string (GLOB) anchors,",
        "# which against a joined text could only ever match the final leaf.",
        "policy_texts := [value] if {",
        "\tvalue := input.policy_target.value",
        "\tis_string(value)",
        "} else := texts if {",
        "\ttarget := input.policy_target.value",
        "\tnot is_string(target)",
        "\ttexts := [s | walk(target, [_, s]); is_string(s)]",
        "}",
        "",
    ]
    branches: list[str] = []
    pattern_list = list(blocked_patterns)
    if pattern_list:
        rendered = ", ".join(json.dumps(pattern) for pattern in pattern_list)
        # Select the matching leaves first, then build one verdict from the
        # first of them. ``verdict`` is a complete rule, so binding it inside
        # ``some ... in`` would produce a different object per matching leaf
        # (deny_if_pattern embeds the match offset) and OPA would raise
        # eval_conflict_error. matches_any also short-circuits, where
        # deny_if_pattern scores every pattern against every leaf.
        lines.extend(
            [
                "matched_texts := [t |",
                "\tsome t in policy_texts",
                f"\tpatterns.matches_any(t, [{rendered}])",
                "]",
                "",
            ]
        )
        branches.append(
            "count(matched_texts) > 0\n"
            "\tv := patterns.deny_if_pattern(matched_texts[0], "
            f"[{rendered}], {json.dumps(_REASON_PATTERN)})"
        )
    if max_tool_calls is not None:
        # v4 checked the tool-call budget only when intercepting a tool call
        # (PolicyInterceptor compared context.call_count at tool interception),
        # so an exhausted budget must gate the next tool call and nothing
        # else; letting it fire at input/pre_model_call/agent_startup would
        # stop the agent from ever emitting its final model response. It also
        # cannot fire at post_tool_call: the runtime charges the attempt
        # during pre_tool_call, so a >= check there would deny the result of
        # the last permitted call after its side effects committed.
        branches.append(
            'input.intervention_point == "pre_tool_call"\n'
            "\tv := budgets.deny_if_budget_exceeded("
            f'{json.dumps({"tool_call_count": max_tool_calls})})'
        )
    if max_tokens is not None:
        # The cumulative token budget gates new consumption, so evaluate it
        # only where the agent is about to spend tokens (model and tool
        # calls). Denying input or agent_startup on an exhausted budget would
        # strand the session, and post-action points cannot un-run the spend.
        branches.append(
            'input.intervention_point in ["pre_model_call", "pre_tool_call"]\n'
            "\tv := budgets.deny_if_budget_exceeded("
            f'{json.dumps({"token_count": max_tokens})})'
        )
    if confidence_threshold is not None and confidence_threshold > 0:
        branches.append(
            "v := confidence.deny_if_low_confidence("
            f"{json.dumps(confidence_threshold)})"
        )
    if require_human_approval:
        # v4 gated human approval on tool interception only (PolicyInterceptor
        # checked require_human_approval when a tool was about to run), so the
        # migrated escalation stays scoped to pre_tool_call. Escalating at
        # every bound point would, absent an approver, deny all traffic.
        branches.append(
            'input.intervention_point == "pre_tool_call"\n'
            '\tv := approval.escalate_if_approver_required(["human"])'
        )
    for index, branch in enumerate(branches):
        lines.append("verdict := v if {" if index == 0 else "else := v if {")
        lines.append(f"\t{branch}")
        lines.append("}")
    lines.append("")
    return "\n".join(lines)


# The engine denies any point a manifest leaves unbound
# (``runtime_error:intervention_point_unknown``), so a migrated manifest has to
# bind every point an adapter evaluates or the agent stops working the moment it
# produces output or calls a tool. Each target below is the JSONPath for the
# envelope the adapter runtime actually sends for that point; the generated Rego
# carries ``default verdict := {"decision": "allow"}``, so binding a point the v4
# policy said nothing about permits it rather than inventing a new rule.
_POINT_TARGETS: dict[str, tuple[str, str]] = {
    "input": ("$.input.body", "user_input"),
    "output": ("$.response.content", "assistant_output"),
    "pre_model_call": ("$.messages", "model_request"),
    "post_model_call": ("$.response", "assistant_output"),
    "pre_tool_call": ("$.tool_call.args", "tool_args"),
    "post_tool_call": ("$.tool_result.value", "tool_result"),
    # AGT-SNAPSHOT-1.0 §2.1 names this field `agent_init`, but both SDK seams
    # (HostSession.agent_startup and AgentControl.agent_startup) emit `agent`,
    # and `agent_init` appears nowhere in the runtime. Bind what the hosts
    # actually send; reconciling the spec with the SDK is a separate decision.
    # A spec-conformant third-party host fails closed here rather than open.
    "agent_startup": ("$.agent", "agent_lifecycle"),
    "agent_shutdown": ("$.summary", "agent_lifecycle"),
}


def _build_intervention_points(
    policy_id: str,
    *,
    bind_tools_with_catalog: bool,
) -> dict[str, Any]:
    bindings: dict[str, Any] = {}
    for point, (target, kind) in _POINT_TARGETS.items():
        config: dict[str, Any] = {
            "policy_target": target,
            "policy_target_kind": kind,
            "policy": {"id": policy_id},
        }
        if point == "pre_tool_call" and bind_tools_with_catalog:
            config["tool_name_from"] = "$.tool_call.name"
        bindings[point] = config
    return bindings


__all__ = ["MigrationPolicyInput", "build_migrated_manifest"]
