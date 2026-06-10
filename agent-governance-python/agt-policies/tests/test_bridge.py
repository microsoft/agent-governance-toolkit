# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for :mod:`agt.policies.bridge` and the v4-compat helpers on
:class:`agt.policies.EvaluationResult`.

The bridge module is skipped when ``agent_os`` is not importable so the
suite degrades gracefully outside the agent-governance-python workspace;
when ``agent_os`` IS available the bridge tests construct a real
:class:`agent_os.integrations.base.GovernancePolicy` and walk the
generated manifest end-to-end through OPA.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

pytest.importorskip("agent_os")

from agent_os.integrations.base import GovernancePolicy, PatternType  # noqa: E402
from agent_os.policies.decision import ViolationCategory  # noqa: E402

from agt.policies import EvaluationResult, SnapshotBuilder  # noqa: E402
from agt.policies.bridge import governance_to_acs_manifest  # noqa: E402


# ── manifest-shape tests ────────────────────────────────────────────


def _bridge(tmp_path: Path, **policy_kwargs: Any) -> dict[str, Any]:
    policy = GovernancePolicy(**policy_kwargs)
    bundle_dir = tmp_path / "bundle"
    return governance_to_acs_manifest(policy, bundle_dir=bundle_dir)


def test_bridge_validates_against_agt_manifest_1_0(tmp_path: Path) -> None:
    """The bridge MUST emit a manifest that satisfies the AGT-MANIFEST-1.0
    structural invariants (version string, empty extends, at least one
    intervention-point binding, every policy_id referenced by a binding
    is declared, generated Rego bundle exists on disk)."""
    manifest = _bridge(
        tmp_path,
        max_tokens=2048,
        max_tool_calls=3,
        allowed_tools=["lookup", "write_record"],
        blocked_patterns=["password"],
        require_human_approval=True,
        confidence_threshold=0.7,
    )

    assert manifest["agent_control_specification_version"].endswith("-agt")
    assert manifest["extends"] == []
    assert manifest["intervention_points"], "manifest needs at least one binding"

    declared_policy_ids = set(manifest["policies"].keys())
    for binding in manifest["intervention_points"].values():
        assert binding["policy"]["id"] in declared_policy_ids

    policy_entry = manifest["policies"]["agt_governance_policy"]
    assert policy_entry["type"] == "rego"
    bundle = Path(policy_entry["bundle"])
    assert bundle.is_dir()
    # The generated bundle module must be on disk and reference the
    # stock helpers it depends on (copied alongside).
    rego = (bundle / "agt_governance_policy.rego").read_text(encoding="utf-8")
    assert "package agt.governance_policy" in rego
    assert "import data.agt.patterns" in rego
    assert "import data.agt.budgets" in rego
    assert "import data.agt.confidence" in rego
    assert "import data.agt.approval" in rego
    assert (bundle / "budgets.rego").exists()
    assert (bundle / "patterns.rego").exists()
    assert (bundle / "confidence.rego").exists()
    assert (bundle / "approval.rego").exists()


def test_bridge_translates_max_tokens_and_max_tool_calls(tmp_path: Path) -> None:
    manifest = _bridge(tmp_path, max_tokens=512, max_tool_calls=4)

    rego = Path(manifest["policies"]["agt_governance_policy"]["bundle"]) / "agt_governance_policy.rego"
    body = rego.read_text(encoding="utf-8")
    assert "budgets.deny_if_budget_exceeded" in body
    # Literal values from the GovernancePolicy must land in the rendered Rego.
    assert '"tool_call_count": 4' in body
    assert '"token_count": 512' in body


def test_bridge_translates_allowed_tools_to_catalog(tmp_path: Path) -> None:
    manifest = _bridge(
        tmp_path, allowed_tools=["lookup", "issue_refund"], max_tool_calls=2
    )

    assert manifest["tools"] == {
        "lookup": {"clearance": "public"},
        "issue_refund": {"clearance": "public"},
    }
    # Engine fail-closes on a tool not in the catalog by emitting
    # runtime_error:tool_unknown; this is the AGT-DELTA D6 semantic
    # that subsumes v4's ViolationCategory.NOT_ALLOWED_TOOL.
    assert "pre_tool_call" in manifest["intervention_points"]


def test_bridge_empty_allowed_tools_omits_catalog(tmp_path: Path) -> None:
    manifest = _bridge(tmp_path, allowed_tools=[], max_tool_calls=2)
    # v4 semantic: empty allowed_tools = no allowlist. We omit the
    # tools section so the host can populate it post-bridge with their
    # actual tool catalog without overriding allowlist semantics.
    assert "tools" not in manifest


def test_bridge_translates_blocked_patterns_via_patterns_library(tmp_path: Path) -> None:
    manifest = _bridge(
        tmp_path,
        blocked_patterns=[
            "password",
            ("rm\\s+-rf", PatternType.REGEX),
            ("*.exe", PatternType.GLOB),
        ],
    )

    rego = Path(manifest["policies"]["agt_governance_policy"]["bundle"]) / "agt_governance_policy.rego"
    body = rego.read_text(encoding="utf-8")
    assert "patterns.deny_if_pattern" in body
    # Substring is escaped to a literal regex.
    assert "password" in body
    # Regex is passed through verbatim.
    assert "rm\\\\s+-rf" in body or "rm\\s+-rf" in body
    # Bound at input and output for body-level scanning.
    assert "input" in manifest["intervention_points"]
    assert "output" in manifest["intervention_points"]


def test_bridge_blocked_patterns_match_stringified_tool_args(tmp_path: Path) -> None:
    opa = shutil.which("opa") or str(Path.home() / ".local" / "bin" / "opa")
    if not Path(opa).exists():
        pytest.skip("opa binary required for bridge Rego repro")

    manifest = _bridge(
        tmp_path,
        max_tokens=1000,
        max_tool_calls=10,
        allowed_tools=[],
        blocked_patterns=["secret"],
        require_human_approval=False,
        confidence_threshold=0.0,
    )
    pre = manifest["intervention_points"]["pre_tool_call"]
    assert pre["policy_target"] == "$.tool_call.args"

    bundle = Path(manifest["policies"]["agt_governance_policy"]["bundle"])
    cases = {
        "string": {"policy_target": {"value": "contains secret here"}},
        "dict": {"policy_target": {"value": {"arg": "contains secret here"}}},
        "list": {"policy_target": {"value": ["contains secret here"]}},
    }

    for name, policy_input in cases.items():
        input_path = tmp_path / f"{name}.json"
        input_path.write_text(json.dumps(policy_input), encoding="utf-8")
        completed = subprocess.run(
            [
                opa,
                "eval",
                "-f",
                "values",
                "-d",
                str(bundle),
                "-i",
                str(input_path),
                "data.agt.governance_policy.verdict",
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        verdict = json.loads(completed.stdout)[0]
        assert verdict["decision"] == "deny"
        assert verdict["reason"] == "blocked_pattern_input"


def test_bridge_translates_require_human_approval_to_escalate(tmp_path: Path) -> None:
    manifest = _bridge(tmp_path, require_human_approval=True)

    # AGT-M3 bridge gap fix: emit a v5-shaped approval section the
    # engine actually accepts. The engine's ApprovalSection uses
    # ``deny_unknown_fields``; emitting v4's ``{required, approvers,
    # reason}`` shape made every approval manifest fail to load.
    assert manifest["approval"] == {}
    rego = Path(manifest["policies"]["agt_governance_policy"]["bundle"]) / "agt_governance_policy.rego"
    body = rego.read_text(encoding="utf-8")
    assert "approval.escalate_if_approver_required" in body
    # AGT-M3 bridge gap fix: require_human_approval MUST bind
    # pre_tool_call so the escalate rule actually fires somewhere.
    assert "pre_tool_call" in manifest["intervention_points"]
    # When there is no explicit allowlist the bridge MUST NOT set
    # ``tool_name_from`` on the binding; otherwise the engine's
    # fail-closed tool-known check fires before the approval rule.
    assert "tool_name_from" not in manifest["intervention_points"]["pre_tool_call"]


def test_bridge_translates_confidence_threshold(tmp_path: Path) -> None:
    manifest = _bridge(tmp_path, confidence_threshold=0.85)

    rego = Path(manifest["policies"]["agt_governance_policy"]["bundle"]) / "agt_governance_policy.rego"
    body = rego.read_text(encoding="utf-8")
    assert "confidence.deny_if_low_confidence(0.85)" in body
    # Confidence is enforced at post_model_call where the host
    # supplies a confidence score annotation.
    assert "post_model_call" in manifest["intervention_points"]


def test_bridge_end_to_end_through_runtime(tmp_path: Path) -> None:
    """Loaded into AgtRuntime, the bridged manifest must allow a tool
    call that satisfies every constraint and deny one that violates the
    tool catalog."""
    import shutil

    if shutil.which("opa") is None:
        pytest.skip("opa binary required for runtime end-to-end test")

    from agt.policies.runtime import AgtRuntime

    manifest = _bridge(
        tmp_path,
        max_tokens=1000,
        max_tool_calls=10,
        allowed_tools=["lookup"],
        blocked_patterns=[],
        require_human_approval=False,
        confidence_threshold=0.0,
    )
    manifest_path = tmp_path / "manifest.yaml"
    manifest_path.write_text(yaml.safe_dump(manifest), encoding="utf-8")

    runtime = AgtRuntime(manifest_path)

    snap = SnapshotBuilder(agent_id="bot").pre_tool_call(tool_name="lookup", args={})
    allowed = runtime.evaluate_intervention_point("pre_tool_call", snap)
    assert allowed.verdict == "allow"

    snap2 = SnapshotBuilder(agent_id="bot").pre_tool_call(tool_name="rm", args={})
    denied = runtime.evaluate_intervention_point("pre_tool_call", snap2)
    assert denied.verdict == "deny"
    # The engine's tool-known check supplies runtime_error:tool_unknown
    # so v4's NOT_ALLOWED_TOOL semantic is preserved without a custom
    # rule in the generated Rego.
    assert "tool_unknown" in denied.reason


# ── EvaluationResult v4 back-compat ────────────────────────────────


def test_evaluation_result_to_v4_check_result_allow_round_trip() -> None:
    result = EvaluationResult(verdict="allow", input_identity="sha256:abc")
    v4 = result.to_v4_check_result()
    assert v4.allowed is True
    assert v4.action == "allow"
    assert v4.audit_entry["verdict"] == "allow"
    assert v4.audit_entry["input_identity"] == "sha256:abc"


def test_evaluation_result_to_v4_check_result_escalate_maps_human_approval() -> None:
    result = EvaluationResult(
        verdict="escalate",
        reason="approval_required",
        message="needs sign-off",
        enforced_identity="sha256:xyz",
    )
    v4 = result.to_v4_check_result()
    assert v4.allowed is False
    assert v4.action == "block"
    assert v4.category is ViolationCategory.HUMAN_APPROVAL
    assert v4.reason == "approval_required"


def test_evaluation_result_to_v4_check_result_transform_mirrors_payload() -> None:
    result = EvaluationResult(
        verdict="transform",
        transform={"path": "$policy_target.text", "value": "[REDACTED]"},
        evidence={"artefact": "sha256:proof", "verification_pointers": {}},
        input_identity="sha256:before",
        enforced_identity="sha256:after",
    )
    v4 = result.to_v4_check_result()
    assert v4.allowed is True
    assert v4.action == "allow"
    assert v4.audit_entry["transform"] == {
        "path": "$policy_target.text",
        "value": "[REDACTED]",
    }
    assert v4.audit_entry["evidence"]["artefact"] == "sha256:proof"
    assert v4.audit_entry["input_identity"] == "sha256:before"
    assert v4.audit_entry["enforced_identity"] == "sha256:after"


def test_evaluation_result_to_v4_check_result_warn_uses_audit_action() -> None:
    result = EvaluationResult(verdict="warn", reason="drift_detected")
    v4 = result.to_v4_check_result()
    assert v4.allowed is True
    # v4 used PolicyAction.AUDIT for permit+log; the bridge mirrors
    # that wire string so existing audit pipelines keep bucketing.
    assert v4.action == "audit"
    assert v4.audit_entry["verdict"] == "warn"


# ── M3 bridge gap regression tests ───────────────────────────────────


def test_bridge_empty_allowed_tools_with_budget_drops_tool_name_from(tmp_path: Path) -> None:
    """AGT-M3 bridge gap fix: with no allowlist + a budget, the bridge
    MUST bind pre_tool_call (so the budget rule has a binding) but MUST
    omit ``tool_name_from`` so the engine does not fail-close on every
    call with ``runtime_error:tool_unknown`` before the budget rule runs.
    """
    manifest = _bridge(tmp_path, allowed_tools=[], max_tool_calls=2)

    assert "tools" not in manifest
    pre = manifest["intervention_points"]["pre_tool_call"]
    assert "tool_name_from" not in pre
    assert pre["policy_target"] == "$.tool_call.args"


def test_bridge_allowed_tools_keeps_tool_name_from(tmp_path: Path) -> None:
    """When the v4 policy DID declare an allowlist the bridge must keep
    ``tool_name_from`` so the engine's fail-closed check fires for
    unknown tools (preserving v4 ``NOT_ALLOWED_TOOL`` semantics)."""
    manifest = _bridge(tmp_path, allowed_tools=["lookup"], max_tool_calls=2)

    assert manifest["tools"] == {"lookup": {"clearance": "public"}}
    pre = manifest["intervention_points"]["pre_tool_call"]
    assert pre["tool_name_from"] == "$.tool_call.name"


def test_bridge_require_human_approval_alone_binds_pre_tool_call(tmp_path: Path) -> None:
    """AGT-M3 bridge gap fix: a v4 policy whose only constraint is
    ``require_human_approval=True`` MUST still bind an intervention
    point so the approval rule fires. Before the fix ``bind_tools``
    was false in this case and the fallback binding kept
    ``tool_name_from`` set, both of which were wrong."""
    manifest = _bridge(tmp_path, require_human_approval=True)

    assert "pre_tool_call" in manifest["intervention_points"]
    pre = manifest["intervention_points"]["pre_tool_call"]
    assert "tool_name_from" not in pre


def test_bridge_approval_section_validates_against_engine_schema(tmp_path: Path) -> None:
    """AGT-M3 bridge gap fix: the engine's ``ApprovalSection`` uses
    ``deny_unknown_fields`` and accepts ``default_resolver``,
    ``timeout_seconds``, ``on_timeout``, ``fatigue_threshold``,
    ``fatigue_window_seconds``, and a ``resolvers`` map only. Emitting
    v4's ``{required, approvers, reason}`` made every approval manifest
    fail to load. Verify the bridge emits a v5-valid section.
    """
    manifest = _bridge(tmp_path, require_human_approval=True)
    accepted_keys = {
        "default_resolver",
        "timeout_seconds",
        "on_timeout",
        "fatigue_threshold",
        "fatigue_window_seconds",
        "resolvers",
    }
    extra_keys = set(manifest["approval"].keys()) - accepted_keys
    assert not extra_keys, f"approval section carries unknown fields: {extra_keys}"


def test_bridge_end_to_end_approval_path_loads_manifest(tmp_path: Path) -> None:
    """End-to-end regression for the M3 approval gap: a manifest where
    the only v4 constraint is ``require_human_approval=True`` must
    actually LOAD through ``AgtRuntime.from_path`` (not crash on
    manifest parse with ``deny_unknown_fields``) and must surface an
    ``escalate`` verdict on pre_tool_call.
    """
    import shutil

    if shutil.which("opa") is None:
        pytest.skip("opa binary required for runtime end-to-end test")

    pytest.importorskip("agent_control_specification")

    from agt.policies.runtime import AgtRuntime

    manifest = _bridge(tmp_path, require_human_approval=True)
    manifest_path = tmp_path / "manifest.yaml"
    manifest_path.write_text(yaml.safe_dump(manifest), encoding="utf-8")

    runtime = AgtRuntime(manifest_path)

    snap = SnapshotBuilder(agent_id="bot").pre_tool_call(
        tool_name="any_tool", args={"x": 1}
    )
    # evaluate_only so we see the raw escalate (enforce would route
    # through a missing approval resolver and surface as deny).
    result = runtime.evaluate_intervention_point(
        "pre_tool_call", snap, mode="evaluate_only"
    )
    assert result.verdict == "escalate", (
        f"expected escalate verdict, got {result.verdict!r} (reason={result.reason!r})"
    )


# ── AGT-M3 round-2 BLOCK A regression tests ─────────────────────────


def test_bridge_max_tool_calls_zero_emits_budget_rule(tmp_path: Path) -> None:
    """AGT-M3 round-2 BLOCK A: ``max_tool_calls=0`` is a v4 deny-every-call
    sentinel, not "no constraint". The bridge MUST render the budget rule
    with ``tool_call_count: 0`` so the stock helper denies on the very
    first call. Before the fix the bridge dropped the rule entirely
    because the threshold guard was ``> 0``, leaving every call to fall
    through to the synthetic ``pre_tool_call`` fallback (allow)."""
    manifest = _bridge(tmp_path, max_tool_calls=0)

    rego = (
        Path(manifest["policies"]["agt_governance_policy"]["bundle"])
        / "agt_governance_policy.rego"
    )
    body = rego.read_text(encoding="utf-8")
    assert "budgets.deny_if_budget_exceeded" in body
    assert '"tool_call_count": 0' in body
    # And the pre_tool_call binding must exist so the rule actually fires.
    assert "pre_tool_call" in manifest["intervention_points"]


def test_bridge_max_tool_calls_zero_with_zero_confidence_denies_every_call(
    tmp_path: Path,
) -> None:
    """AGT-M3 round-2 BLOCK A end-to-end through AgtRuntime: a v4
    ``GovernancePolicy(max_tool_calls=0, confidence_threshold=0.0)``
    must deny EVERY tool call when the manifest is loaded into the AGT
    runtime directly. ``confidence_threshold=0.0`` is the critical
    masking case the existing ``test_tool_call_limit_cancels_run`` did
    not exercise because that test relied on the default 0.8 confidence
    threshold to hide the bug."""
    import shutil

    if shutil.which("opa") is None:
        pytest.skip("opa binary required for runtime end-to-end test")

    from agt.policies.runtime import AgtRuntime

    manifest = _bridge(
        tmp_path,
        max_tokens=1000,
        max_tool_calls=0,
        allowed_tools=[],
        blocked_patterns=[],
        require_human_approval=False,
        confidence_threshold=0.0,
    )
    manifest_path = tmp_path / "manifest.yaml"
    manifest_path.write_text(yaml.safe_dump(manifest), encoding="utf-8")

    runtime = AgtRuntime(manifest_path)

    snap = SnapshotBuilder(agent_id="bot").pre_tool_call(
        tool_name="any_tool", args={"x": 1}
    )
    denied = runtime.evaluate_intervention_point("pre_tool_call", snap)
    assert denied.verdict == "deny", (
        f"expected deny for max_tool_calls=0 + confidence_threshold=0.0, "
        f"got {denied.verdict!r} (reason={denied.reason!r})"
    )
    assert "budget_tool_calls_exceeded" in (denied.reason or "")


def test_bridge_max_tool_calls_zero_alone_denies(tmp_path: Path) -> None:
    """AGT-M3 round-2 BLOCK A: ``GovernancePolicy(max_tool_calls=0)``
    with the default ``confidence_threshold=0.8`` must still deny on
    the ``pre_tool_call`` intervention point because of the budget
    rule, not because of the confidence rule (which fires at
    ``post_model_call``). The previous bridge fallback returned
    ``allow`` for ``pre_tool_call`` here."""
    import shutil

    if shutil.which("opa") is None:
        pytest.skip("opa binary required for runtime end-to-end test")

    from agt.policies.runtime import AgtRuntime

    manifest = _bridge(tmp_path, max_tool_calls=0)
    manifest_path = tmp_path / "manifest.yaml"
    manifest_path.write_text(yaml.safe_dump(manifest), encoding="utf-8")

    runtime = AgtRuntime(manifest_path)

    snap = SnapshotBuilder(agent_id="bot").pre_tool_call(
        tool_name="any_tool", args={}
    )
    denied = runtime.evaluate_intervention_point("pre_tool_call", snap)
    assert denied.verdict == "deny"
    assert "budget_tool_calls_exceeded" in (denied.reason or "")
