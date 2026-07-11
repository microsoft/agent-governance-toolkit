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
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import threading
import time
from typing import Any

import pytest
import yaml

pytest.importorskip("agent_control_specification")

from agt.policies import (  # noqa: E402
    AgtManifest,
    EvaluationResult,
    PolicyEvaluation,
    SnapshotBuilder,
)
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


def _manifest_mapping() -> dict[str, Any]:
    manifest = yaml.safe_load(_MANIFEST)
    assert isinstance(manifest, dict)
    return manifest


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


def test_native_evaluate_returns_only_v5_contract(tmp_path: Path) -> None:
    policy = _ScriptedPolicy(
        [
            {
                "decision": "deny",
                "reason": "blocked_tool",
                "message": "blocked",
                "result_labels": ["security", "tool"],
            }
        ]
    )
    runtime = AgtRuntime.from_manifest(
        _manifest_mapping(),
        base_dir=tmp_path,
        policy_dispatcher=policy,
    )

    result = runtime.evaluate("pre_tool_call", _snapshot())

    assert isinstance(result, PolicyEvaluation)
    assert result.verdict == "deny"
    assert result.reason_code == "policy:blocked_tool"
    assert result.intervention_point == "pre_tool_call"
    assert result.result_labels == ("security", "tool")
    assert result.audit_record()["schema"] == "agt.policy_evaluation.v1"
    assert "allowed" not in PolicyEvaluation.model_fields
    assert "category" not in PolicyEvaluation.model_fields
    assert "policy_id" not in PolicyEvaluation.model_fields
    assert "rule_id" not in PolicyEvaluation.model_fields


@pytest.mark.parametrize("source_kind", ["path", "mapping", "typed", "text"])
def test_from_manifest_accepts_all_native_sources(
    tmp_path: Path, source_kind: str
) -> None:
    policy = _ScriptedPolicy([{"decision": "allow"}])
    path = _write_manifest(tmp_path)
    mapping = _manifest_mapping()
    if source_kind == "path":
        source: Any = path
        kwargs: dict[str, Any] = {}
    elif source_kind == "mapping":
        source = mapping
        kwargs = {"base_dir": tmp_path}
    elif source_kind == "typed":
        source = AgtManifest.from_document(mapping, base_dir=tmp_path)
        kwargs = {}
    else:
        source = _MANIFEST
        kwargs = {"base_dir": tmp_path}

    runtime = AgtRuntime.from_manifest(
        source,
        policy_dispatcher=policy,
        **kwargs,
    )

    assert runtime.manifest is not None
    assert runtime.evaluate("pre_tool_call", _snapshot()).verdict == "allow"


def test_from_manifest_rejects_provenance_free_relative_refs() -> None:
    manifest = _manifest_mapping()
    manifest["policies"]["test_policy"]["bundle"] = "./policy"

    with pytest.raises(ValueError, match="base_dir is required"):
        AgtRuntime.from_manifest(manifest)


def test_from_manifest_refuses_unenforced_limits(tmp_path: Path) -> None:
    manifest = _manifest_mapping()
    manifest["limits"] = {"max_snapshot_bytes": 1024}

    with pytest.raises(ValueError, match="refusing to accept unenforced limits"):
        AgtRuntime.from_manifest(manifest, base_dir=tmp_path)


def test_runtime_is_shareable_when_host_dispatchers_are_thread_safe(
    tmp_path: Path,
) -> None:
    class _ThreadSafeAllowPolicy:
        def __init__(self) -> None:
            self.lock = threading.Lock()
            self.calls = 0

        def evaluate(self, invocation):  # type: ignore[no-untyped-def]
            with self.lock:
                self.calls += 1
            return {"decision": "allow"}

    policy = _ThreadSafeAllowPolicy()
    runtime = AgtRuntime.from_manifest(
        _manifest_mapping(),
        base_dir=tmp_path,
        policy_dispatcher=policy,
    )

    def evaluate(session: int) -> str:
        snapshot = SnapshotBuilder(
            agent_id="bot", session_id=f"s-{session}"
        ).pre_tool_call(tool_name="lookup", args={"q": session})
        result = runtime.evaluate("pre_tool_call", snapshot)
        assert result.input_identity is not None
        return result.input_identity

    with ThreadPoolExecutor(max_workers=8) as pool:
        identities = list(pool.map(evaluate, range(16)))

    assert len(set(identities)) == 16
    assert policy.calls == 16


def test_shared_runtime_keeps_concurrent_approval_identities_isolated(
    tmp_path: Path,
) -> None:
    class _ThreadSafeEscalatePolicy:
        def evaluate(self, invocation):  # type: ignore[no-untyped-def]
            return {"decision": "escalate", "reason": "approval_required"}

    seen: list[str] = []
    seen_lock = threading.Lock()

    def resolver(ip: str, result: EvaluationResult) -> ApprovalDecision:
        assert ip == "pre_tool_call"
        assert result.enforced_identity is not None
        with seen_lock:
            seen.append(result.enforced_identity)
        return ApprovalDecision.allow(result.enforced_identity)

    manifest = _manifest_mapping()
    manifest["approval"] = {}
    runtime = AgtRuntime.from_manifest(
        manifest,
        base_dir=tmp_path,
        policy_dispatcher=_ThreadSafeEscalatePolicy(),
        approval_resolver=resolver,
    )

    def evaluate(session: int) -> str:
        snapshot = SnapshotBuilder(
            agent_id="bot", session_id=f"approval-{session}"
        ).pre_tool_call(tool_name="lookup", args={"q": session})
        result = runtime.evaluate("pre_tool_call", snapshot)
        assert result.verdict == "allow"
        assert result.enforced_identity is not None
        return result.enforced_identity

    with ThreadPoolExecutor(max_workers=8) as pool:
        identities = list(pool.map(evaluate, range(12)))

    assert len(set(identities)) == 12
    assert set(seen) == set(identities)


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
