# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Host-lifecycle tests for the native Agent Shield adapter."""

from __future__ import annotations

from typing import Any

from agt.policies import PolicyEvaluation

from agent_os.integrations.agentshield_adapter import (
    AgentShieldKernel,
    ShieldVerdict,
    ValidationStage,
)


class _AllowRuntime:
    manifest = None

    def evaluate(
        self, intervention_point: str, snapshot: dict[str, Any]
    ) -> PolicyEvaluation:
        return PolicyEvaluation(
            verdict="allow",
            intervention_point=intervention_point,
        )

    def close(self) -> None:
        pass


def _kernel(**kwargs: Any) -> AgentShieldKernel:
    return AgentShieldKernel.mock(agt_runtime=_AllowRuntime(), **kwargs)


def test_mock_kernel_allows_each_validation_stage() -> None:
    kernel = _kernel()

    assert kernel.validate_input("hello").allowed
    assert kernel.validate_tool_call("search", {"q": "x"}).allowed
    assert kernel.validate_tool_result("search", {"result": "x"}).allowed
    assert kernel.validate_output("done").allowed


def test_session_and_turn_lifecycle() -> None:
    kernel = _kernel()

    kernel.start_session("session-1")
    kernel.begin_turn()
    assert kernel._session_id == "session-1"
    assert kernel._turn_active

    kernel.end_session()
    assert kernel._session is None
    assert not kernel._turn_active


def test_trust_and_agent_identity_are_injected() -> None:
    kernel = _kernel()
    kernel.set_trust_score(700)
    kernel.set_agent_id("did:mesh:agent-a")
    kernel.start_session("session-1")

    assert kernel._session._variables["agt_trust_score"] == 700
    assert kernel._session._variables["agt_agent_id"] == "did:mesh:agent-a"


def test_history_and_stats_track_all_stages() -> None:
    kernel = _kernel()

    kernel.validate_input("hello")
    kernel.validate_output("done")

    assert len(kernel.get_history()) == 2
    stats = kernel.get_stats()
    assert stats["total_validations"] == 2
    assert stats["blocked"] == 0


def test_reset_clears_history_and_session() -> None:
    kernel = _kernel()
    kernel.validate_input("hello")

    kernel.reset()

    assert kernel.get_history() == []


def test_shield_verdict_serializes_native_fields() -> None:
    verdict = ShieldVerdict(
        allowed=False,
        stage=ValidationStage.INPUT,
        reason="blocked",
        policy_name="host-rule",
        elapsed_ms=1.5,
    )

    data = verdict.to_dict()
    assert data["allowed"] is False
    assert data["stage"] == "input"
    assert data["reason"] == "blocked"


def test_violation_callback_receives_host_denial() -> None:
    received: list[ShieldVerdict] = []

    class _DenySession:
        class _Verdict:
            allowed = False
            reason = "host denied"
            policy_name = "host"

            def __bool__(self) -> bool:
                return self.allowed

        def begin_turn(self) -> None:
            pass

        def end_turn(self) -> None:
            pass

        def validate_input(self, text: str) -> Any:
            return self._Verdict()

        def set_variable(self, name: str, value: Any) -> None:
            pass

    class _HostRuntime:
        def new_session(self, **kwargs: Any) -> _DenySession:
            return _DenySession()

    kernel = AgentShieldKernel(
        _HostRuntime(),
        agt_runtime=_AllowRuntime(),
        on_violation=received.append,
    )

    verdict = kernel.validate_input("hello")
    assert not verdict.allowed
    assert received == [verdict]
