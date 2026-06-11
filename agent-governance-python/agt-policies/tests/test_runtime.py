# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for :mod:`agt.policies.runtime`.

Each test wires a tiny custom policy dispatcher into the wrapper so the
suite never depends on OPA being on PATH. Each test exercises one
verdict (``allow``, ``deny``, ``warn``, ``transform``, ``escalate``) or
one runtime feature (evaluate_only mode, evidence round-trip, approval
identity mismatch). The module is skipped when the
``agent_control_specification`` native binding is not installed; CI
verifies the SDK builds before running this suite.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
import threading
import time
from typing import Any

import pytest

pytest.importorskip("agent_control_specification")

from agt.policies import EvaluationResult, SnapshotBuilder  # noqa: E402
from agt.policies.runtime import AgtRuntime, ApprovalDecision  # noqa: E402


# ── shared fixtures ────────────────────────────────────────────────


_MANIFEST = """agent_control_specification_version: 0.3.0-alpha-agt
metadata:
  name: agt_runtime_test
extends: []
policies:
  test_policy:
    type: custom
    adapter: agt_runtime_test_adapter
intervention_points:
  pre_tool_call:
    policy_target: $.tool_call.args
    policy_target_kind: tool_args
    tool_name_from: $.tool_call.name
    policy:
      id: test_policy
tools:
  lookup:
    clearance: public
"""


class _ScriptedPolicy:
    """Tiny ACS PolicyDispatcher that returns a scripted verdict per call.

    Each ``evaluate`` call pops the next scripted verdict. The dispatcher
    records every invocation so tests can assert what the engine handed
    over.
    """

    def __init__(self, verdicts: list[dict[str, Any]]):
        self._verdicts = list(verdicts)
        self.invocations: list[dict[str, Any]] = []

    def evaluate(self, invocation):  # type: ignore[no-untyped-def]
        self.invocations.append(dict(invocation))
        if not self._verdicts:
            raise AssertionError(
                "ScriptedPolicy ran out of verdicts; test wired too few."
            )
        return self._verdicts.pop(0)


def _write_manifest(tmp_path: Path, approval: str = "") -> Path:
    path = tmp_path / "manifest.yaml"
    path.write_text(_MANIFEST + approval, encoding="utf-8")
    return path


def _snapshot() -> dict[str, Any]:
    return SnapshotBuilder(agent_id="bot", session_id="s-1").pre_tool_call(
        tool_name="lookup", args={"q": "x"}
    )


# ── verdict round-trips ────────────────────────────────────────────


def test_runtime_returns_allow_evaluation_result(tmp_path: Path) -> None:
    policy = _ScriptedPolicy([{"decision": "allow"}])
    runtime = AgtRuntime(_write_manifest(tmp_path), policy_dispatcher=policy)

    result = runtime.evaluate_intervention_point("pre_tool_call", _snapshot())

    assert isinstance(result, EvaluationResult)
    assert result.verdict == "allow"
    assert result.allowed is True
    assert result.transform is None
    assert result.evidence is None
    assert result.input_identity is not None
    assert result.enforced_identity == result.input_identity
    assert len(policy.invocations) == 1


def test_runtime_returns_deny_evaluation_result(tmp_path: Path) -> None:
    policy = _ScriptedPolicy(
        [{"decision": "deny", "reason": "blocked_tool", "message": "nope"}]
    )
    runtime = AgtRuntime(_write_manifest(tmp_path), policy_dispatcher=policy)

    result = runtime.evaluate_intervention_point("pre_tool_call", _snapshot())

    assert result.verdict == "deny"
    assert result.allowed is False
    assert result.reason == "blocked_tool"
    assert result.message == "nope"
    assert result.audit_entry["verdict"] == "deny"


def test_runtime_returns_warn_evaluation_result(tmp_path: Path) -> None:
    policy = _ScriptedPolicy(
        [{"decision": "warn", "reason": "drift_detected", "message": "drift"}]
    )
    runtime = AgtRuntime(_write_manifest(tmp_path), policy_dispatcher=policy)

    result = runtime.evaluate_intervention_point("pre_tool_call", _snapshot())

    assert result.verdict == "warn"
    assert result.allowed is True
    assert result.reason == "drift_detected"


def test_runtime_applies_transform_verdict(tmp_path: Path) -> None:
    policy = _ScriptedPolicy(
        [
            {
                "decision": "transform",
                "reason": "redacted",
                "transform": {
                    "path": "$policy_target.q",
                    "value": "[REDACTED]",
                },
            }
        ]
    )
    runtime = AgtRuntime(_write_manifest(tmp_path), policy_dispatcher=policy)

    result = runtime.evaluate_intervention_point("pre_tool_call", _snapshot())

    assert result.verdict == "transform"
    assert result.allowed is True
    assert result.transform is not None
    assert result.transform["path"] == "$policy_target.q"
    assert result.transform["value"] == "[REDACTED]"
    # AGT D1.4 prescribes that input_identity and enforced_identity are
    # bisected for transform verdicts; the current native binding only
    # exposes a single identity that surfaces under both fields. The
    # test asserts the surface is present and the binding bridge maps
    # the spec field names; the bisection itself is exercised at the
    # core level in policy-engine/core tests.
    assert result.input_identity is not None
    assert result.enforced_identity is not None
    # The runtime mirrors the engine-applied target under
    # ``transform.applied_value`` for callers that want the materialised
    # rewrite without re-running the path resolution.
    assert result.transform["applied_value"] == {"q": "[REDACTED]"}


def test_runtime_routes_escalate_through_resolver_allow(tmp_path: Path) -> None:
    policy = _ScriptedPolicy(
        [{"decision": "escalate", "reason": "approval_required"}]
    )

    seen: dict[str, Any] = {}

    def resolver(ip: str, result: EvaluationResult) -> ApprovalDecision:
        seen["ip"] = ip
        seen["enforced_identity"] = result.enforced_identity
        return ApprovalDecision.allow(result.enforced_identity)  # type: ignore[arg-type]

    runtime = AgtRuntime(
        _write_manifest(tmp_path),
        policy_dispatcher=policy,
        approval_resolver=resolver,
    )

    result = runtime.evaluate_intervention_point("pre_tool_call", _snapshot())

    assert seen["ip"] == "pre_tool_call"
    assert seen["enforced_identity"] is not None
    # When the resolver approves the escalation the wrapper rewrites
    # the verdict to ``allow`` so callers do not need to special-case
    # the escalate state.
    assert result.verdict == "allow"
    assert result.allowed is True


def test_runtime_evaluate_only_mode_does_not_invoke_resolver(tmp_path: Path) -> None:
    policy = _ScriptedPolicy(
        [{"decision": "escalate", "reason": "approval_required"}]
    )

    called = {"value": False}

    def resolver(ip: str, result: EvaluationResult) -> ApprovalDecision:
        called["value"] = True
        return ApprovalDecision.allow(result.enforced_identity)  # type: ignore[arg-type]

    runtime = AgtRuntime(
        _write_manifest(tmp_path),
        policy_dispatcher=policy,
        approval_resolver=resolver,
    )

    result = runtime.evaluate_intervention_point(
        "pre_tool_call", _snapshot(), mode="evaluate_only"
    )

    assert called["value"] is False
    # The raw verdict surfaces because evaluate_only never enforces.
    assert result.verdict == "escalate"


def test_runtime_round_trips_evidence_from_verdict(tmp_path: Path) -> None:
    policy = _ScriptedPolicy(
        [
            {
                "decision": "allow",
                "evidence": {
                    "artefact": "sha256:abcdef",
                    "verification_pointers": {
                        "issuer_pubkey": "https://example.com/keys/2026.pem",
                        "policy_registry": "https://example.com/policies/v1/",
                    },
                },
            }
        ]
    )
    runtime = AgtRuntime(_write_manifest(tmp_path), policy_dispatcher=policy)

    result = runtime.evaluate_intervention_point("pre_tool_call", _snapshot())

    assert result.verdict == "allow"
    assert result.evidence is not None
    assert result.evidence["artefact"] == "sha256:abcdef"
    assert result.evidence["verification_pointers"] == {
        "issuer_pubkey": "https://example.com/keys/2026.pem",
        "policy_registry": "https://example.com/policies/v1/",
    }


def test_runtime_resolver_identity_mismatch_blocks(tmp_path: Path) -> None:
    policy = _ScriptedPolicy(
        [{"decision": "escalate", "reason": "approval_required"}]
    )

    def resolver(ip: str, result: EvaluationResult) -> ApprovalDecision:
        # Approving the wrong identity MUST be caught by the runtime
        # per AGT-DELTA D1.4 / ACS 17.1.
        return ApprovalDecision.allow("sha256:" + "0" * 64)

    runtime = AgtRuntime(
        _write_manifest(tmp_path),
        policy_dispatcher=policy,
        approval_resolver=resolver,
    )

    result = runtime.evaluate_intervention_point("pre_tool_call", _snapshot())

    assert result.allowed is False
    assert result.verdict == "deny"
    assert result.reason == "runtime_error:approval_action_mismatch"


def test_runtime_escalate_with_no_resolver_fails_closed(tmp_path: Path) -> None:
    policy = _ScriptedPolicy(
        [{"decision": "escalate", "reason": "approval_required"}]
    )
    runtime = AgtRuntime(_write_manifest(tmp_path), policy_dispatcher=policy)

    result = runtime.evaluate_intervention_point("pre_tool_call", _snapshot())

    # No resolver -> deny per ACS enforce-mode contract.
    assert result.verdict == "deny"
    assert result.allowed is False


def test_runtime_resolver_deny_blocks(tmp_path: Path) -> None:
    policy = _ScriptedPolicy(
        [{"decision": "escalate", "reason": "approval_required"}]
    )

    def resolver(ip: str, result: EvaluationResult) -> ApprovalDecision:
        return ApprovalDecision.deny()

    runtime = AgtRuntime(
        _write_manifest(tmp_path),
        policy_dispatcher=policy,
        approval_resolver=resolver,
    )

    result = runtime.evaluate_intervention_point("pre_tool_call", _snapshot())

    assert result.verdict == "deny"
    assert result.allowed is False


def test_runtime_resolution_bundle_is_owned_and_cleaned_up(tmp_path: Path) -> None:
    root = tmp_path / "workspace"
    root.mkdir()
    action_path = root / "agent.py"
    action_path.write_text("# agent\n", encoding="utf-8")
    (root / "governance.yaml").write_text(
        """
rules: []
intervention_points:
  pre_tool_call:
    policy_target: $.tool_call.args
    policy_target_kind: tool_args
    tool_name_from: $.tool_call.name
    policy:
      id: agt_legacy_rules
tools:
  lookup:
    clearance: public
""",
        encoding="utf-8",
    )

    runtime = AgtRuntime(action_path, resolution_root=root)
    bundle_dir = Path(runtime._resolution_bundle_dir.name)  # type: ignore[union-attr]
    assert bundle_dir.exists()
    assert root not in bundle_dir.parents

    runtime.close()

    assert not bundle_dir.exists()


@pytest.mark.parametrize(
    ("approval", "expected_verdict", "expected_allowed"),
    [
        ("approval:\n  timeout_seconds: 0.05\n", "deny", False),
        (
            "approval:\n  timeout_seconds: 0.05\n  on_timeout: allow\n",
            "allow",
            True,
        ),
    ],
)
def test_runtime_hanging_sync_resolver_honors_timeout_policy(
    tmp_path: Path,
    approval: str,
    expected_verdict: str,
    expected_allowed: bool,
) -> None:
    policy = _ScriptedPolicy(
        [{"decision": "escalate", "reason": "approval_required"}]
    )
    blocker = threading.Event()

    def resolver(ip: str, result: EvaluationResult) -> ApprovalDecision:
        blocker.wait()
        return ApprovalDecision.allow(result.enforced_identity)  # type: ignore[arg-type]

    runtime = AgtRuntime(
        _write_manifest(tmp_path, approval),
        policy_dispatcher=policy,
        approval_resolver=resolver,
    )

    try:
        started = time.monotonic()
        result = runtime.evaluate_intervention_point("pre_tool_call", _snapshot())
        elapsed = time.monotonic() - started
    finally:
        blocker.set()

    assert elapsed < 0.5
    assert result.verdict == expected_verdict
    assert result.allowed == expected_allowed
    assert result.audit_entry["approval_timeout"]
    if expected_verdict == "deny":
        assert result.reason == "runtime_error:approval_timeout"


@pytest.mark.parametrize(
    ("approval", "expected_verdict", "expected_allowed"),
    [
        ("approval:\n  timeout_seconds: 0.05\n", "deny", False),
        (
            "approval:\n  timeout_seconds: 0.05\n  on_timeout: allow\n",
            "allow",
            True,
        ),
    ],
)
def test_runtime_hanging_async_resolver_is_cancelled_on_timeout(
    tmp_path: Path,
    approval: str,
    expected_verdict: str,
    expected_allowed: bool,
) -> None:
    policy = _ScriptedPolicy(
        [{"decision": "escalate", "reason": "approval_required"}]
    )
    cancelled = threading.Event()

    async def resolver(ip: str, result: EvaluationResult) -> ApprovalDecision:
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            cancelled.set()
            raise
        return ApprovalDecision.allow(result.enforced_identity)  # pragma: no cover

    runtime = AgtRuntime(
        _write_manifest(tmp_path, approval),
        policy_dispatcher=policy,
        approval_resolver=resolver,
    )

    started = time.monotonic()
    result = runtime.evaluate_intervention_point("pre_tool_call", _snapshot())
    elapsed = time.monotonic() - started

    assert elapsed < 0.5
    assert cancelled.wait(1.0)
    assert result.verdict == expected_verdict
    assert result.allowed == expected_allowed
    assert result.audit_entry["approval_timeout"]


def test_runtime_async_resolver_foreign_loop_bound_awaitable_fails_closed(
    tmp_path: Path,
) -> None:
    policy = _ScriptedPolicy(
        [{"decision": "escalate", "reason": "approval_required"}]
    )
    foreign_loop = asyncio.new_event_loop()
    foreign_future = foreign_loop.create_future()

    async def resolver(ip: str, result: EvaluationResult) -> ApprovalDecision:
        await foreign_future
        return ApprovalDecision.allow(result.enforced_identity)  # pragma: no cover

    runtime = AgtRuntime(
        _write_manifest(tmp_path, "approval:\n  timeout_seconds: 0.05\n"),
        policy_dispatcher=policy,
        approval_resolver=resolver,
    )

    try:
        started = time.monotonic()
        result = runtime.evaluate_intervention_point("pre_tool_call", _snapshot())
        elapsed = time.monotonic() - started
    finally:
        foreign_future.cancel()
        foreign_loop.close()

    assert elapsed < 0.5
    assert result.verdict == "deny"
    assert not result.allowed
    assert result.reason == "runtime_error:approval_timeout"


@pytest.mark.parametrize(
    "approval",
    [
        "approval:\n  timeout_seconds: 0\n  on_timeout: allow\n",
        "approval:\n  timeout_seconds: -1\n  on_timeout: allow\n",
        "approval:\n  timeout_seconds: never\n  on_timeout: allow\n",
    ],
)
def test_runtime_invalid_timeout_values_fail_closed_immediately(
    tmp_path: Path,
    approval: str,
) -> None:
    policy = _ScriptedPolicy(
        [{"decision": "escalate", "reason": "approval_required"}]
    )
    called = {"value": False}

    def resolver(ip: str, result: EvaluationResult) -> ApprovalDecision:
        called["value"] = True
        return ApprovalDecision.allow(result.enforced_identity)  # type: ignore[arg-type]

    runtime = AgtRuntime(
        _write_manifest(tmp_path, approval),
        policy_dispatcher=policy,
        approval_resolver=resolver,
    )

    started = time.monotonic()
    result = runtime.evaluate_intervention_point("pre_tool_call", _snapshot())
    elapsed = time.monotonic() - started

    assert elapsed < 0.5
    assert not called["value"]
    assert result.verdict == "deny"
    assert not result.allowed
    assert result.reason == "runtime_error:approval_timeout"


def test_runtime_missing_timeout_uses_fail_closed_default(tmp_path: Path) -> None:
    runtime = AgtRuntime(
        _write_manifest(tmp_path, "approval:\n  on_timeout: unexpected\n"),
        policy_dispatcher=_ScriptedPolicy([{"decision": "allow"}]),
    )

    assert runtime._approval_timeout_seconds == 300.0
    assert runtime._approval_on_timeout == "deny"


def test_runtime_resolver_result_just_before_timeout_is_used(tmp_path: Path) -> None:
    policy = _ScriptedPolicy(
        [{"decision": "escalate", "reason": "approval_required"}]
    )

    def resolver(ip: str, result: EvaluationResult) -> ApprovalDecision:
        time.sleep(0.01)
        return ApprovalDecision.allow(result.enforced_identity)  # type: ignore[arg-type]

    runtime = AgtRuntime(
        _write_manifest(tmp_path, "approval:\n  timeout_seconds: 0.5\n"),
        policy_dispatcher=policy,
        approval_resolver=resolver,
    )

    result = runtime.evaluate_intervention_point("pre_tool_call", _snapshot())

    assert result.verdict == "allow"
    assert result.allowed
    assert "approval_timeout" not in result.audit_entry


def test_runtime_timeout_threads_are_daemon_and_non_daemon_count_is_bounded(
    tmp_path: Path,
) -> None:
    blockers: list[threading.Event] = []
    non_daemon_before = sum(1 for thread in threading.enumerate() if not thread.daemon)

    try:
        for index in range(3):
            blocker = threading.Event()
            blockers.append(blocker)
            policy = _ScriptedPolicy(
                [{"decision": "escalate", "reason": f"approval_required_{index}"}]
            )

            def resolver(ip: str, result: EvaluationResult) -> ApprovalDecision:
                blocker.wait()
                return ApprovalDecision.deny()

            runtime = AgtRuntime(
                _write_manifest(tmp_path, "approval:\n  timeout_seconds: 0.02\n"),
                policy_dispatcher=policy,
                approval_resolver=resolver,
            )
            result = runtime.evaluate_intervention_point("pre_tool_call", _snapshot())
            assert result.verdict == "deny"

        leaked_workers = [
            thread
            for thread in threading.enumerate()
            if thread.name == "agt-approval-resolver"
        ]
        non_daemon_after = sum(
            1 for thread in threading.enumerate() if not thread.daemon
        )

        assert leaked_workers
        assert all(thread.daemon for thread in leaked_workers)
        assert non_daemon_after <= non_daemon_before + 1
    finally:
        for blocker in blockers:
            blocker.set()


def test_runtime_resolution_root_pre_resolves_manifest(tmp_path: Path) -> None:
    # End-to-end: the runtime should walk the AGT manifest-resolution
    # layer when given a resolution_root, materialise the merged Rego
    # bundle, and stand up the engine on it. Uses OPA via the bundled
    # default policy dispatcher so this test is skipped when ``opa`` is
    # not on PATH.
    import shutil

    if shutil.which("opa") is None:
        pytest.skip("opa binary required for resolution end-to-end test")

    governance = {
        "rules": [
            {
                "name": "deny_dangerous",
                "condition": {"field": "tool_call.name", "operator": "eq", "value": "rm"},
                "action": "deny",
                "priority": 10,
                "override": False,
                "message": "rm denied",
            },
        ],
        "tools": {
            "rm": {"clearance": "public"},
            "ls": {"clearance": "public"},
        },
        "intervention_points": {
            "pre_tool_call": {
                "policy_target": "$.tool_call.args",
                "policy_target_kind": "tool_args",
                "tool_name_from": "$.tool_call.name",
                "policy": {"id": "agt_legacy_rules"},
            }
        },
    }
    import yaml

    (tmp_path / "governance.yaml").write_text(yaml.safe_dump(governance), encoding="utf-8")

    runtime = AgtRuntime(tmp_path, resolution_root=tmp_path)

    # A matching call denies.
    snap = SnapshotBuilder(agent_id="bot").pre_tool_call(tool_name="rm", args={})
    result = runtime.evaluate_intervention_point("pre_tool_call", snap)
    assert result.verdict == "deny"

    # A non-matching call falls through to default-allow.
    snap2 = SnapshotBuilder(agent_id="bot").pre_tool_call(tool_name="ls", args={})
    result2 = runtime.evaluate_intervention_point("pre_tool_call", snap2)
    assert result2.verdict == "allow"
