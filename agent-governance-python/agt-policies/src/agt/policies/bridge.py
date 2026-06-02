# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""GovernancePolicy bridge — translate a v4 ``GovernancePolicy`` to an AGT manifest.

The bridge is the compatibility seam that lets host code constructed
around v4 ``agent_os.integrations.base.GovernancePolicy`` ride the v5
ACS-backed engine without rewriting their constraints. It maps each
v4 field to the AGT stock Rego library helper that enforces it and
emits a flat AGT manifest (``policy-engine/spec/agt/AGT-MANIFEST-1.0.md``)
ready to feed :class:`agt.policies.runtime.AgtRuntime`.

Mapping (per ``architecture-exploration.md`` Q3 and the AGT stock
library at ``policy-engine/policy/lib``):

- ``max_tokens`` -> ``agt.budgets.deny_if_budget_exceeded``
  (``token_count`` threshold).
- ``max_tool_calls`` -> ``agt.budgets.deny_if_budget_exceeded``
  (``tool_call_count`` threshold).
- ``allowed_tools`` -> ACS ``tools`` catalog entries plus the engine's
  fail-closed ``runtime_error:tool_unknown`` deny for unlisted tools.
  An empty list maps to "no allowlist" (v4 semantics) and the bridge
  omits the catalog so the host can populate it later.
- ``blocked_patterns`` -> ``agt.patterns.deny_if_pattern`` with the
  literal pattern strings rendered into the generated Rego bundle.
- ``require_human_approval`` -> ``agt.approval.escalate_if_approver_required``
  plus an ``approval`` manifest section per AGT-DELTA D5.
- ``confidence_threshold`` -> ``agt.confidence.deny_if_low_confidence``
  with the literal threshold rendered into the generated Rego bundle.

The bridge materialises a small Rego module that imports the stock
helpers and calls them with literals captured from the policy. The
stock library files are copied alongside the generated module so OPA
can resolve the ``data.agt.*`` imports without external configuration.

Importing the bridge module does not require the v4 ``agent_os``
package to be installed. The :func:`governance_to_acs_manifest`
function accepts duck-typed inputs (anything with the v4 attribute
surface) so callers that already have a v4 ``GovernancePolicy``
instance pass it directly, and unit tests can pass a small dataclass
fixture without dragging the whole v4 dependency tree in. The bridge
imports the canonical v4 dataclass lazily for an ``isinstance`` check
only when ``agent_os`` is available.
"""

from __future__ import annotations

import json
import logging
import shutil
import tempfile
from pathlib import Path
from typing import Any, Iterable, Protocol, runtime_checkable

logger = logging.getLogger(__name__)

ACS_VERSION = "0.3.0-alpha-agt"

# Reason string used by the v4 ``blocked_patterns`` rule. The other v4
# wire strings (``max_tool_calls``, ``max_tokens``,
# ``confidence_threshold``, ``human_approval_required``) cannot be
# threaded through the stock Rego helpers because
# ``agt.budgets.deny_if_budget_exceeded``,
# ``agt.confidence.deny_if_low_confidence``, and
# ``agt.approval.escalate_if_approver_required`` hardcode their own
# v5 reason strings (``budget_tool_calls_exceeded``,
# ``budget_tokens_exceeded``, ``confidence_below_threshold``,
# ``approval_required``). v5 reasons therefore differ from the v4
# ``ViolationCategory`` wire values for those rules; audit consumers
# that bucket on ``reason`` MUST update to the v5 strings or run a
# host-side translation layer.
_REASON_PATTERN = "blocked_pattern_input"


@runtime_checkable
class _GovernancePolicyLike(Protocol):
    name: str
    max_tokens: int
    max_tool_calls: int
    allowed_tools: list[str]
    blocked_patterns: list[Any]
    require_human_approval: bool
    confidence_threshold: float


def _find_stock_rego_root() -> Path:
    """Locate the AGT stock Rego library directory inside the repo."""
    here = Path(__file__).resolve()
    for parent in here.parents:
        candidate = parent / "policy-engine" / "policy" / "lib"
        if candidate.is_dir():
            return candidate
    raise FileNotFoundError(
        "could not locate policy-engine/policy/lib stock Rego root; "
        "pass stock_rego_root explicitly to governance_to_acs_manifest"
    )


def _pattern_to_regex(pattern: Any) -> str:
    """Normalise a v4 ``blocked_patterns`` entry to a Go RE2 regex string.

    v4 entries are either a bare string (substring match) or a
    ``(pattern, PatternType)`` tuple where ``PatternType`` is one of
    ``SUBSTRING``, ``REGEX``, ``GLOB``. The bridge emits a Go RE2
    regex literal in every case so the stock ``agt.patterns`` library
    can match it.
    """
    import re

    if isinstance(pattern, str):
        return re.escape(pattern)

    if isinstance(pattern, tuple) and len(pattern) == 2:
        value, kind = pattern
        if not isinstance(value, str):
            raise ValueError(f"pattern value must be a string, got {value!r}")
        kind_name = kind.name if hasattr(kind, "name") else str(kind)
        if kind_name == "SUBSTRING":
            return re.escape(value)
        if kind_name == "REGEX":
            return value
        if kind_name == "GLOB":
            import fnmatch

            return fnmatch.translate(value)
        raise ValueError(f"unsupported PatternType: {kind!r}")

    raise ValueError(f"unsupported blocked_patterns entry: {pattern!r}")


def _render_rego(
    *,
    package: str,
    max_tokens: int | None,
    max_tool_calls: int | None,
    confidence_threshold: float | None,
    blocked_patterns: Iterable[str],
    require_human_approval: bool,
) -> str:
    """Render the bridge Rego module body."""
    lines: list[str] = [
        "# Copyright (c) Microsoft Corporation.",
        "# Licensed under the MIT License.",
        "# AUTO-GENERATED by agt.policies.bridge.governance_to_acs_manifest.",
        "# Mirrors a v4 GovernancePolicy into AGT stock-library calls.",
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
        rendered_patterns = ", ".join(json.dumps(p) for p in pattern_list)
        branches.append(
            "v := patterns.deny_if_pattern(policy_text, "
            f"[{rendered_patterns}], {json.dumps(_REASON_PATTERN)})"
        )

    budget_thresholds: dict[str, Any] = {}
    if max_tool_calls is not None:
        budget_thresholds["tool_call_count"] = max_tool_calls
    if max_tokens is not None:
        budget_thresholds["token_count"] = max_tokens
    if budget_thresholds:
        branches.append(
            "v := budgets.deny_if_budget_exceeded("
            f"{json.dumps(budget_thresholds)})"
        )

    if confidence_threshold is not None and confidence_threshold > 0.0:
        branches.append(
            f"v := confidence.deny_if_low_confidence({json.dumps(confidence_threshold)})"
        )

    if require_human_approval:
        branches.append(
            'v := approval.escalate_if_approver_required(["human"])'
        )

    for index, branch in enumerate(branches):
        if index == 0:
            lines.append("verdict := v if {")
        else:
            lines.append("else := v if {")
        lines.append(f"\t{branch}")
        lines.append("}")

    lines.append("")
    return "\n".join(lines)


def _build_tools_section(allowed_tools: list[str]) -> dict[str, Any] | None:
    """Return an AGT manifest ``tools`` section from ``allowed_tools``.

    v4 semantics: an empty allowed_tools list means "no allowlist".
    Returning ``None`` signals the bridge to omit the catalog so the
    host can supply tool entries itself.
    """
    if not allowed_tools:
        return None
    return {tool: {"clearance": "public"} for tool in allowed_tools}


def _build_intervention_points(
    policy_id: str,
    *,
    bind_input: bool,
    bind_tools: bool,
    bind_output: bool,
    bind_post_model_call: bool,
    bind_tools_with_catalog: bool,
) -> dict[str, Any]:
    """Bind the bridge policy at the intervention points that match
    the v4 GovernancePolicy fields.

    pre_tool_call covers allowed_tools / blocked_patterns on tool args
    / budgets / approval. input and output cover blocked_patterns on
    text bodies. post_model_call covers confidence_threshold (the host
    surfaces a confidence score via the snapshot's annotations layer).

    ``bind_tools_with_catalog`` flips ``tool_name_from`` on the
    pre_tool_call binding so the engine's fail-closed tool-known check
    fires (AGT-M3 bridge gap fix). When false the bridge omits
    ``tool_name_from`` entirely so the engine does NOT project the tool
    name, which means budgets / approval / patterns can run end-to-end
    without a tool catalog (matching v4's ``allowed_tools=[]`` semantic
    of "no allowlist enforced; let other rules decide").
    """
    bindings: dict[str, Any] = {}
    if bind_tools:
        pre_tool_call: dict[str, Any] = {
            "policy_target": "$.tool_call.args",
            "policy_target_kind": "tool_args",
            "policy": {"id": policy_id},
        }
        if bind_tools_with_catalog:
            pre_tool_call["tool_name_from"] = "$.tool_call.name"
        bindings["pre_tool_call"] = pre_tool_call
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


def governance_to_acs_manifest(
    policy: _GovernancePolicyLike,
    *,
    bundle_dir: Path | None = None,
    stock_rego_root: Path | None = None,
    policy_id: str = "agt_governance_policy",
) -> dict[str, Any]:
    """Translate a v4 :class:`GovernancePolicy` to an AGT manifest dict.

    Args:
        policy: A v4 ``GovernancePolicy`` (or any object with the
            same attribute surface — see :class:`_GovernancePolicyLike`).
        bundle_dir: Where to materialise the generated Rego bundle.
            Defaults to a fresh temp directory.
        stock_rego_root: Override the lookup for the AGT stock library
            (used in tests). Defaults to ``policy-engine/policy/lib``.
        policy_id: Identifier for the generated policy entry. Lets the
            caller wire the bridge result into an existing manifest
            with multiple policy definitions.

    Returns:
        A flat AGT manifest dict that validates against
        AGT-MANIFEST-1.0. ``policies.<policy_id>`` is a ``type: rego``
        entry whose ``bundle`` directory contains the generated
        bridge module and the stock library copies. ``tools`` mirrors
        ``policy.allowed_tools``. ``approval`` is set when
        ``require_human_approval`` is true.
    """
    bundle_dir = (
        Path(bundle_dir).resolve()
        if bundle_dir is not None
        else Path(tempfile.mkdtemp(prefix="agt_bridge_")).resolve()
    )
    bundle_dir.mkdir(parents=True, exist_ok=True)

    stock_root = stock_rego_root or _find_stock_rego_root()
    for rego_file in stock_root.glob("*.rego"):
        if rego_file.name.endswith("_test.rego"):
            continue
        shutil.copy(rego_file, bundle_dir / rego_file.name)

    blocked_pattern_regexes = [_pattern_to_regex(p) for p in policy.blocked_patterns]

    # AGT-M3 round-2 BLOCK A: ``max_tool_calls=0`` is the v4 sentinel for
    # "deny every tool call", not "no constraint". Forward 0 through to the
    # ``budgets.deny_if_budget_exceeded`` helper. The helper compares
    # ``tool_call_count >= limit`` so with ``limit=0`` and the default
    # ``tool_call_count=0`` the first call is denied with
    # ``budget_tool_calls_exceeded``, which preserves the v4 contract end-to-end
    # for any caller that loads the bridge manifest into AgtRuntime directly
    # (not just through the AdapterRuntimeBridge host fallback). Previously a
    # ``GovernancePolicy(max_tool_calls=0, confidence_threshold=0.0)`` slipped
    # through to the default ``allow`` verdict because the budget rule was
    # omitted and the fallback ``pre_tool_call`` binding (no ``tool_name_from``)
    # never tripped any deny rule. Keep ``max_tokens`` at ``> 0`` because the v4
    # dataclass validation rejects ``max_tokens <= 0`` and there is no v4 wire
    # value to preserve there.
    rego_source = _render_rego(
        package="agt.governance_policy",
        max_tokens=policy.max_tokens if policy.max_tokens > 0 else None,
        max_tool_calls=policy.max_tool_calls if policy.max_tool_calls >= 0 else None,
        confidence_threshold=(
            policy.confidence_threshold
            if policy.confidence_threshold and policy.confidence_threshold > 0
            else None
        ),
        blocked_patterns=blocked_pattern_regexes,
        require_human_approval=policy.require_human_approval,
    )
    rego_path = bundle_dir / f"{policy_id}.rego"
    rego_path.write_text(rego_source, encoding="utf-8")

    # bind_tools must also cover the case where the policy has a budget
    # or human-approval requirement but no explicit tool allowlist; without
    # this the pre_tool_call binding is never created and the host's tool
    # calls bypass enforcement (AGT-M3 bridge gap fix). ``max_tool_calls >= 0``
    # covers the AGT-M3 round-2 BLOCK A case where ``max_tool_calls == 0`` is a
    # v4 deny-every-call constraint that previously did not bind the
    # intervention point (and thereby silently allowed every call when no other
    # rule fired).
    bind_tools = (
        bool(policy.allowed_tools)
        or policy.max_tool_calls >= 0
        or policy.require_human_approval
    )
    # Only enable the engine's fail-closed tool-known check when the v4
    # policy declared an explicit allowlist. With v4 semantics
    # ``allowed_tools=[]`` means "no allowlist", so leaving the catalog
    # off and dropping ``tool_name_from`` from the binding stops the
    # engine from emitting ``runtime_error:tool_unknown`` for every
    # call (which would mask the budget / approval / patterns rules)
    # (AGT-M3 bridge gap fix).
    bind_tools_with_catalog = bool(policy.allowed_tools)
    bind_input = bool(policy.blocked_patterns)
    bind_output = bool(policy.blocked_patterns)
    bind_post_model_call = (
        policy.confidence_threshold is not None and policy.confidence_threshold > 0
    )

    intervention_points = _build_intervention_points(
        policy_id,
        bind_input=bind_input,
        bind_tools=bind_tools,
        bind_output=bind_output,
        bind_post_model_call=bind_post_model_call,
        bind_tools_with_catalog=bind_tools_with_catalog,
    )

    # At least one binding is required by AGT-MANIFEST §3; fall back to
    # binding pre_tool_call (without a tool catalog so the no-allowlist
    # rule path stays open) so even a no-constraint policy produces a
    # valid manifest.
    if not intervention_points:
        intervention_points["pre_tool_call"] = {
            "policy_target": "$.tool_call.args",
            "policy_target_kind": "tool_args",
            "policy": {"id": policy_id},
        }

    manifest: dict[str, Any] = {
        "agent_control_specification_version": ACS_VERSION,
        "metadata": {
            "name": getattr(policy, "name", "governance_policy"),
            "source": "agt.policies.bridge.governance_to_acs_manifest",
            "policy_version": getattr(policy, "version", "1.0.0"),
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

    tools_section = _build_tools_section(list(policy.allowed_tools))
    if tools_section is not None:
        manifest["tools"] = tools_section

    if policy.require_human_approval:
        # AGT-M3 bridge gap fix: emit a v5-shaped approval section the
        # engine actually accepts (ApprovalSection uses deny_unknown_fields).
        # The v4 ``require_human_approval=True`` semantic maps to
        # "fire escalate on tool calls and route through the host's
        # approval_resolver". The host wires the resolver on the
        # AgtRuntime constructor (per AGT-DELTA D5); the manifest just
        # needs an empty section so the Rego's escalate verdict reaches
        # the host approval path instead of failing manifest validation.
        manifest["approval"] = {}

    return manifest


__all__ = ["governance_to_acs_manifest"]
