# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Native integration lifecycle and host-control tests."""

from __future__ import annotations

from typing import Any

import pytest
from agt.policies import PolicyEvaluation

from agent_os.integrations.base import (
    AdapterExecutionState,
    BaseIntegration,
    BoundedSemaphore,
    CompositeInterceptor,
    ContentHashInterceptor,
    ToolCallRequest,
)


class _Runtime:
    manifest = None

    def __init__(self, verdict: str = "allow") -> None:
        self.verdict = verdict
        self.points: list[str] = []

    def evaluate(self, intervention_point: str, snapshot: dict[str, Any]) -> PolicyEvaluation:
        self.points.append(intervention_point)
        return PolicyEvaluation(verdict=self.verdict, intervention_point=intervention_point)


class _Integration(BaseIntegration):
    def wrap(self, agent: Any) -> Any:
        return agent


def test_native_lifecycle_updates_state_after_allowed_output() -> None:
    source = _Runtime()
    integration = _Integration(runtime=source)
    state = integration.create_context("agent")

    assert integration.pre_execute(state, "hello") == (True, None)
    assert integration.post_execute(state, "world") == (True, None)
    assert state.call_count == 1
    assert source.points == ["input", "output"]


def test_native_lifecycle_denial_does_not_record_completion() -> None:
    integration = _Integration(runtime=_Runtime("deny"))
    state = integration.create_context("agent")

    allowed, _ = integration.post_execute(state, "blocked")
    assert allowed is False
    assert state.call_count == 0


def test_execution_state_validates_identity_and_limits() -> None:
    with pytest.raises(ValueError):
        AdapterExecutionState(agent_id="bad id", session_id="session")
    with pytest.raises(ValueError):
        AdapterExecutionState(agent_id="agent", session_id="", call_count=0)


def test_content_hash_and_composite_interceptors_fail_closed() -> None:
    interceptor = ContentHashInterceptor({"lookup": "abc"})
    request = ToolCallRequest("lookup", {}, metadata={"content_hash": "wrong"})
    result = CompositeInterceptor([interceptor]).intercept(request)
    assert result.allowed is False
    assert "mismatch" in (result.reason or "")


def test_bounded_semaphore_reports_pressure_and_rejection() -> None:
    semaphore = BoundedSemaphore(max_concurrent=1, backpressure_threshold=1)
    assert semaphore.try_acquire() == (True, None)
    assert semaphore.is_under_pressure is True
    allowed, reason = semaphore.try_acquire()
    assert allowed is False
    assert "Max concurrency" in (reason or "")
    semaphore.release()
    assert semaphore.active == 0
