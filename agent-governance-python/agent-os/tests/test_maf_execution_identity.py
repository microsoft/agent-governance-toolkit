# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Native identity mapping and hash-covered MAF tool audit evidence."""

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from agentmesh.governance.audit import AuditLog

from agent_os.integrations.maf_adapter import (
    CapabilityGuardMiddleware,
    MiddlewareTermination,
    RuntimeGovernanceMiddleware,
    create_governance_middleware,
)


def function_context(call_id="call-native", session_id="session-native"):
    return SimpleNamespace(
        function=SimpleNamespace(name="approve_invoice"),
        arguments={"invoice_id": "sensitive-123"},
        metadata={"call_id": call_id},
        session=SimpleNamespace(session_id=session_id) if session_id is not None else None,
        result="sensitive-result",
    )


@pytest.fixture
def guard():
    kernel = MagicMock()
    kernel.evaluate_pre_tool_call.return_value = SimpleNamespace(
        allowed=True,
        applies_to=lambda kind: True,
        transform=None,
        input_identity="sha256:input",
        enforced_identity="sha256:enforced",
    )
    return CapabilityGuardMiddleware(kernel=kernel, audit_log=AuditLog())


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", [None, RuntimeError, asyncio.CancelledError])
async def test_tool_audit_preserves_native_identity_and_closes_start(guard, failure):
    ctx = function_context()
    call_next = AsyncMock(side_effect=failure("private-error") if failure else None)
    if failure:
        with pytest.raises(failure):
            await guard.process(ctx, call_next)
    else:
        await guard.process(ctx, call_next)
    assert guard.kernel.evaluate_pre_tool_call.call_args.kwargs["call_id"] == "call-native"
    entries = guard.audit_log.get_entries_by_type("tool_invocation")
    assert len(entries) == 2
    start, terminal = entries
    assert start.action == "start"
    assert terminal.action == ("error" if failure else "complete")
    assert terminal.data["start_entry_id"] == start.entry_id
    assert (
        terminal.data["correlation"]
        == start.data["correlation"]
        == {
            "framework": "microsoft-agent-framework",
            "call_id": "call-native",
            "session_id": "session-native",
            "input_identity": "sha256:input",
            "enforced_identity": "sha256:enforced",
        }
    )
    assert start.session_id == terminal.session_id == "session-native"
    assert start.to_cloudevent()["sessionid"] == "session-native"
    assert "sensitive" not in terminal.model_dump_json()
    assert "private-error" not in terminal.model_dump_json()
    assert guard.audit_log.verify_integrity()[0]
    terminal.data["correlation"]["call_id"] = "tampered"
    assert not guard.audit_log.verify_integrity()[0]


@pytest.mark.asyncio
@pytest.mark.parametrize("call_id", [None, "", 7, "a" * 257, "line\nbreak", "non-ascii-é"])
async def test_invalid_call_identity_blocks_before_evaluation(guard, call_id):
    call_next = AsyncMock()
    with pytest.raises(MiddlewareTermination, match="native call_id"):
        await guard.process(function_context(call_id=call_id), call_next)
    call_next.assert_not_awaited()
    guard.kernel.evaluate_pre_tool_call.assert_not_called()
    entry = guard.audit_log.get_entries_by_type("tool_blocked")[0]
    assert "call_id" not in entry.data["correlation"]
    assert entry.outcome == "denied"


@pytest.mark.asyncio
@pytest.mark.parametrize("session_id", [None, "", 42, "s" * 257, "bad\nvalue"])
async def test_sessionless_or_invalid_session_does_not_block(guard, session_id):
    call_next = AsyncMock()
    # A valid boundary-length call ID is forwarded without normalization.
    call_id = " " + "x" * 255
    await guard.process(function_context(call_id, session_id), call_next)
    call_next.assert_awaited_once()
    assert guard.kernel.evaluate_pre_tool_call.call_args.kwargs["call_id"] == call_id
    for entry in guard.audit_log.get_entries_by_type("tool_invocation"):
        assert entry.session_id is None
        assert "session_id" not in entry.data["correlation"]


@pytest.mark.asyncio
async def test_policy_denial_records_the_same_native_evidence(guard):
    guard.kernel.evaluate_pre_tool_call.return_value.allowed = False
    guard.kernel.evaluate_pre_tool_call.return_value.reason = "invoice_limit"
    call_next = AsyncMock()
    with pytest.raises(MiddlewareTermination):
        await guard.process(function_context(), call_next)
    call_next.assert_not_awaited()
    entry = guard.audit_log.get_entries_by_type("tool_blocked")[0]
    assert entry.data["correlation"]["call_id"] == "call-native"
    assert entry.data["correlation"]["enforced_identity"] == "sha256:enforced"
    assert entry.session_id == "session-native"
    assert not guard.audit_log.get_entries_by_type("tool_invocation")


def test_factory_shares_real_host_session_but_isolates_separate_runs():
    def layers():
        stack = create_governance_middleware(runtime=MagicMock(), enable_rogue_detection=False)
        return (
            next(m for m in stack if isinstance(m, RuntimeGovernanceMiddleware)),
            next(m for m in stack if isinstance(m, CapabilityGuardMiddleware)),
        )

    runtime, capability = layers()
    other_runtime, other_capability = layers()
    first = runtime.kernel.bridge._session_for(runtime._ensure_v5_context())
    same = capability.kernel.bridge._session_for(capability._ensure_v5_context())
    other = other_capability.kernel.bridge._session_for(other_capability._ensure_v5_context())
    assert first is same
    assert first is not other
    assert runtime._ensure_v5_context().session_id != other_runtime._ensure_v5_context().session_id
    first.builder.record_tool_call()
    assert same.builder.tool_call_count == 1
    assert other.builder.tool_call_count == 0


@pytest.mark.asyncio
async def test_transform_write_failure_records_correlated_denial(guard):
    class ReadOnlyArguments:
        function = SimpleNamespace(name="approve_invoice")
        metadata = {"call_id": "call-transform"}
        session = None

        @property
        def arguments(self):
            return {"invoice_id": "original"}

    result = guard.kernel.evaluate_pre_tool_call.return_value
    result.transform = object()
    result.transformed_value = {"invoice_id": "sanitized"}
    call_next = AsyncMock()
    with pytest.raises(MiddlewareTermination, match="write to the tool arguments"):
        await guard.process(ReadOnlyArguments(), call_next)
    call_next.assert_not_awaited()
    entry = guard.audit_log.get_entries_by_type("tool_blocked")[0]
    assert entry.data["reason"] == "transform_not_applied"
    assert entry.data["correlation"]["call_id"] == "call-transform"
    assert not guard.audit_log.get_entries_by_type("tool_invocation")


@pytest.mark.asyncio
async def test_concurrent_calls_keep_their_own_audit_correlation(guard):
    entered = asyncio.Event()
    count = 0

    async def tool():
        nonlocal count
        count += 1
        if count == 2:
            entered.set()
        await entered.wait()

    await asyncio.gather(
        guard.process(function_context("call-a", "session-a"), tool),
        guard.process(function_context("call-b", "session-b"), tool),
    )
    entries = guard.audit_log.get_entries_by_type("tool_invocation")
    assert len(entries) == 4
    by_id = {entry.entry_id: entry for entry in entries}
    for terminal in (entry for entry in entries if entry.action == "complete"):
        start = by_id[terminal.data["start_entry_id"]]
        assert start.data["correlation"] == terminal.data["correlation"]
        assert start.session_id == terminal.session_id
    assert guard.audit_log.verify_integrity()[0]
