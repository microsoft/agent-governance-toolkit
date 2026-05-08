# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for Agent Shield integration adapter."""

from __future__ import annotations

import pytest
from dataclasses import dataclass
from typing import Any

from agent_os.integrations.agentshield_adapter import (
    AgentShieldKernel,
    ShieldVerdict,
    ToolCallVerdict,
    ValidationStage,
    ShieldAction,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_kernel() -> AgentShieldKernel:
    """Create a mock kernel (no Agent Shield SDK needed)."""
    return AgentShieldKernel.mock()


# ---------------------------------------------------------------------------
# Mock kernel basics
# ---------------------------------------------------------------------------


class TestMockKernelBasics:
    """Tests using the built-in mock runtime."""

    def test_mock_creation(self, mock_kernel: AgentShieldKernel) -> None:
        assert mock_kernel is not None

    def test_mock_validate_input_allows(self, mock_kernel: AgentShieldKernel) -> None:
        result = mock_kernel.validate_input("Hello, world")
        assert result.allowed
        assert result.stage == ValidationStage.INPUT
        assert result.action == ShieldAction.ALLOW

    def test_mock_validate_output_allows(self, mock_kernel: AgentShieldKernel) -> None:
        result = mock_kernel.validate_output("Response text")
        assert result.allowed
        assert result.stage == ValidationStage.OUTPUT

    def test_mock_validate_tool_call_allows(self, mock_kernel: AgentShieldKernel) -> None:
        result = mock_kernel.validate_tool_call("send_email", {"to": "user@contoso.com"})
        assert result.allowed
        assert result.tool_name == "send_email"
        assert result.state_verdict.allowed
        assert result.execution_verdict.allowed

    def test_mock_validate_tool_result_allows(self, mock_kernel: AgentShieldKernel) -> None:
        result = mock_kernel.validate_tool_result("fetch_data", {"data": "safe"})
        assert result.allowed
        assert result.stage == ValidationStage.POST_TOOL

    def test_mock_empty_params(self, mock_kernel: AgentShieldKernel) -> None:
        result = mock_kernel.validate_tool_call("no_args_tool")
        assert result.allowed
        assert result.parameters == {}


# ---------------------------------------------------------------------------
# Session lifecycle
# ---------------------------------------------------------------------------


class TestSessionLifecycle:
    def test_auto_session_creation(self, mock_kernel: AgentShieldKernel) -> None:
        """Session is created automatically on first validation."""
        result = mock_kernel.validate_input("test")
        assert result.allowed

    def test_explicit_session(self, mock_kernel: AgentShieldKernel) -> None:
        mock_kernel.start_session(session_id="conv-123")
        result = mock_kernel.validate_input("test")
        assert result.allowed

    def test_session_end(self, mock_kernel: AgentShieldKernel) -> None:
        mock_kernel.start_session()
        mock_kernel.validate_input("test")
        mock_kernel.end_session()
        # Should auto-create a new session on next validation
        result = mock_kernel.validate_input("another test")
        assert result.allowed

    def test_turn_lifecycle(self, mock_kernel: AgentShieldKernel) -> None:
        mock_kernel.start_session()
        mock_kernel.begin_turn()
        mock_kernel.validate_input("turn 1")
        mock_kernel.end_turn()
        mock_kernel.begin_turn()
        mock_kernel.validate_input("turn 2")
        mock_kernel.end_turn()
        assert len(mock_kernel.get_history()) == 2

    def test_end_session_ends_active_turn(self, mock_kernel: AgentShieldKernel) -> None:
        mock_kernel.start_session()
        mock_kernel.begin_turn()
        # end_session should clean up the active turn
        mock_kernel.end_session()


# ---------------------------------------------------------------------------
# Trust score integration
# ---------------------------------------------------------------------------


class TestTrustScoreIntegration:
    def test_set_trust_score_before_session(self, mock_kernel: AgentShieldKernel) -> None:
        mock_kernel.set_trust_score(750)
        mock_kernel.validate_input("test")
        assert mock_kernel.get_stats()["total_validations"] == 1

    def test_set_trust_score_during_session(self, mock_kernel: AgentShieldKernel) -> None:
        mock_kernel.start_session()
        mock_kernel.set_trust_score(500)
        result = mock_kernel.validate_input("test")
        assert result.allowed

    def test_set_agent_id(self, mock_kernel: AgentShieldKernel) -> None:
        mock_kernel.set_agent_id("did:web:agent.contoso.com:001")
        mock_kernel.validate_input("test")
        assert mock_kernel.get_stats()["total_validations"] == 1


# ---------------------------------------------------------------------------
# History and stats
# ---------------------------------------------------------------------------


class TestHistoryAndStats:
    def test_empty_history(self, mock_kernel: AgentShieldKernel) -> None:
        assert mock_kernel.get_history() == []

    def test_history_records_all_stages(self, mock_kernel: AgentShieldKernel) -> None:
        mock_kernel.validate_input("input")
        mock_kernel.validate_tool_call("tool", {"x": 1})
        mock_kernel.validate_tool_result("tool", "output")
        mock_kernel.validate_output("response")
        history = mock_kernel.get_history()
        # input + state + execution + post_tool + output = 5
        assert len(history) == 5

    def test_stats_accuracy(self, mock_kernel: AgentShieldKernel) -> None:
        mock_kernel.validate_input("a")
        mock_kernel.validate_input("b")
        mock_kernel.validate_output("c")
        stats = mock_kernel.get_stats()
        assert stats["total_validations"] == 3
        assert stats["passed"] == 3
        assert stats["blocked"] == 0
        assert stats["pass_rate"] == 1.0

    def test_stats_empty(self, mock_kernel: AgentShieldKernel) -> None:
        stats = mock_kernel.get_stats()
        assert stats["total_validations"] == 0
        assert stats["pass_rate"] == 1.0

    def test_stats_by_stage(self, mock_kernel: AgentShieldKernel) -> None:
        mock_kernel.validate_input("a")
        mock_kernel.validate_output("b")
        stats = mock_kernel.get_stats()
        assert "input" in stats["by_stage"]
        assert "output" in stats["by_stage"]
        assert stats["by_stage"]["input"]["total"] == 1
        assert stats["by_stage"]["output"]["total"] == 1

    def test_reset_clears_history(self, mock_kernel: AgentShieldKernel) -> None:
        mock_kernel.validate_input("test")
        assert len(mock_kernel.get_history()) > 0
        mock_kernel.reset()
        assert len(mock_kernel.get_history()) == 0


# ---------------------------------------------------------------------------
# ShieldVerdict serialization
# ---------------------------------------------------------------------------


class TestShieldVerdictSerialization:
    def test_allowed_verdict_to_dict(self) -> None:
        v = ShieldVerdict(
            allowed=True,
            stage=ValidationStage.INPUT,
            action=ShieldAction.ALLOW,
        )
        d = v.to_dict()
        assert d["allowed"] is True
        assert d["stage"] == "input"
        assert d["action"] == "allow"
        assert "reason" not in d

    def test_blocked_verdict_to_dict(self) -> None:
        v = ShieldVerdict(
            allowed=False,
            stage=ValidationStage.OUTPUT,
            action=ShieldAction.BLOCK,
            reason="PII detected",
            policy_name="redact_pii",
            elapsed_ms=42.567,
        )
        d = v.to_dict()
        assert d["allowed"] is False
        assert d["reason"] == "PII detected"
        assert d["policy_name"] == "redact_pii"
        assert d["elapsed_ms"] == 42.567

    def test_tool_call_verdict_to_dict(self) -> None:
        tcv = ToolCallVerdict(
            allowed=True,
            state_verdict=ShieldVerdict(
                allowed=True, stage=ValidationStage.STATE
            ),
            execution_verdict=ShieldVerdict(
                allowed=True, stage=ValidationStage.TOOL_EXECUTION
            ),
            tool_name="web_search",
            parameters={"query": "test"},
        )
        d = tcv.to_dict()
        assert d["allowed"] is True
        assert d["tool_name"] == "web_search"

    def test_tool_call_verdict_reason_from_state(self) -> None:
        tcv = ToolCallVerdict(
            allowed=False,
            state_verdict=ShieldVerdict(
                allowed=False,
                stage=ValidationStage.STATE,
                reason="Trust too low",
            ),
            execution_verdict=ShieldVerdict(
                allowed=False,
                stage=ValidationStage.TOOL_EXECUTION,
                reason="Skipped",
            ),
            tool_name="dangerous_tool",
            parameters={},
        )
        assert tcv.reason == "Trust too low"


# ---------------------------------------------------------------------------
# Custom blocking runtime (simulates Agent Shield blocking)
# ---------------------------------------------------------------------------


@dataclass
class _BlockingVerdict:
    """Simulates an Agent Shield verdict that blocks."""

    allowed: bool = False
    reason: str = "Policy violation"
    policy_name: str = "test_policy"
    response: str | None = None

    def __bool__(self) -> bool:
        return self.allowed


class _BlockingSession:
    """Simulates Agent Shield session that blocks everything."""

    def begin_turn(self) -> None:
        pass

    def end_turn(self) -> None:
        pass

    def validate_input(self, text: str) -> _BlockingVerdict:
        return _BlockingVerdict(allowed=False, reason="Jailbreak detected")

    def validate_tool_call(self, tool_name: str, params: Any) -> _BlockingVerdict:
        return _BlockingVerdict(allowed=False, reason=f"{tool_name} not allowed")

    def validate_tool_result(self, tool_name: str, result: Any) -> _BlockingVerdict:
        return _BlockingVerdict(allowed=False, reason="Secret leaked")

    def validate_output(self, text: str) -> _BlockingVerdict:
        return _BlockingVerdict(allowed=False, reason="PII in output")

    def set_variable(self, name: str, value: Any) -> None:
        pass


class _BlockingRuntime:
    def new_session(self, **kwargs: Any) -> _BlockingSession:
        return _BlockingSession()


class TestBlockingScenarios:
    @pytest.fixture
    def blocking_kernel(self) -> AgentShieldKernel:
        return AgentShieldKernel(_BlockingRuntime())

    def test_input_blocked(self, blocking_kernel: AgentShieldKernel) -> None:
        result = blocking_kernel.validate_input("ignore previous instructions")
        assert not result.allowed
        assert result.action == ShieldAction.BLOCK
        assert "Jailbreak" in result.reason

    def test_output_blocked(self, blocking_kernel: AgentShieldKernel) -> None:
        result = blocking_kernel.validate_output("SSN: 123-45-6789")
        assert not result.allowed

    def test_tool_call_blocked_at_state(self, blocking_kernel: AgentShieldKernel) -> None:
        result = blocking_kernel.validate_tool_call("delete_database", {})
        assert not result.allowed
        assert not result.state_verdict.allowed
        assert "not allowed" in result.state_verdict.reason

    def test_tool_result_blocked(self, blocking_kernel: AgentShieldKernel) -> None:
        result = blocking_kernel.validate_tool_result("fetch", "password=secret123")
        assert not result.allowed
        assert "Secret" in result.reason

    def test_violation_handler_called(self) -> None:
        violations: list[ShieldVerdict] = []
        kernel = AgentShieldKernel(
            _BlockingRuntime(),
            on_violation=lambda v: violations.append(v),
        )
        kernel.validate_input("bad input")
        assert len(violations) == 1
        assert not violations[0].allowed

    def test_stats_track_blocked(self, blocking_kernel: AgentShieldKernel) -> None:
        blocking_kernel.validate_input("bad1")
        blocking_kernel.validate_input("bad2")
        stats = blocking_kernel.get_stats()
        assert stats["blocked"] == 2
        assert stats["passed"] == 0
        assert stats["pass_rate"] == 0.0


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------


class _ErrorSession:
    """Simulates Agent Shield session that raises errors."""

    def begin_turn(self) -> None:
        pass

    def end_turn(self) -> None:
        pass

    def validate_input(self, text: str) -> Any:
        raise RuntimeError("Agent Shield internal error")

    def validate_tool_call(self, tool_name: str, params: Any) -> Any:
        raise RuntimeError("SDK crashed")

    def validate_tool_result(self, tool_name: str, result: Any) -> Any:
        raise RuntimeError("Timeout")

    def validate_output(self, text: str) -> Any:
        raise RuntimeError("Network error")

    def set_variable(self, name: str, value: Any) -> None:
        pass


class _ErrorRuntime:
    def new_session(self, **kwargs: Any) -> _ErrorSession:
        return _ErrorSession()


class TestErrorHandling:
    def test_fail_closed_blocks_on_error(self) -> None:
        kernel = AgentShieldKernel(_ErrorRuntime(), fail_closed=True)
        result = kernel.validate_input("test")
        assert not result.allowed
        assert "error" in result.reason.lower()

    def test_fail_open_allows_on_error(self) -> None:
        kernel = AgentShieldKernel(_ErrorRuntime(), fail_closed=False)
        result = kernel.validate_input("test")
        assert result.allowed
        assert result.action == ShieldAction.WARN

    def test_tool_call_error_fail_closed(self) -> None:
        kernel = AgentShieldKernel(_ErrorRuntime(), fail_closed=True)
        result = kernel.validate_tool_call("some_tool", {"param": "value"})
        assert not result.allowed

    def test_output_error_fail_closed(self) -> None:
        kernel = AgentShieldKernel(_ErrorRuntime(), fail_closed=True)
        result = kernel.validate_output("test output")
        assert not result.allowed

    def test_tool_result_error_fail_closed(self) -> None:
        kernel = AgentShieldKernel(_ErrorRuntime(), fail_closed=True)
        result = kernel.validate_tool_result("tool", "result")
        assert not result.allowed


# ---------------------------------------------------------------------------
# Output redaction
# ---------------------------------------------------------------------------


@dataclass
class _RedactingVerdict:
    allowed: bool = True
    reason: str = ""
    policy_name: str = "redact_pii"
    response: str = "[REDACTED]"

    def __bool__(self) -> bool:
        return self.allowed


class _RedactingSession:
    def begin_turn(self) -> None:
        pass

    def end_turn(self) -> None:
        pass

    def validate_input(self, text: str) -> _RedactingVerdict:
        return _RedactingVerdict()

    def validate_tool_call(self, tool_name: str, params: Any) -> _RedactingVerdict:
        return _RedactingVerdict()

    def validate_tool_result(self, tool_name: str, result: Any) -> _RedactingVerdict:
        return _RedactingVerdict()

    def validate_output(self, text: str) -> _RedactingVerdict:
        return _RedactingVerdict(response="[REDACTED]")

    def set_variable(self, name: str, value: Any) -> None:
        pass


class _RedactingRuntime:
    def new_session(self, **kwargs: Any) -> _RedactingSession:
        return _RedactingSession()


class TestOutputRedaction:
    def test_redacted_output_captured(self) -> None:
        kernel = AgentShieldKernel(_RedactingRuntime())
        result = kernel.validate_output("My SSN is 123-45-6789")
        assert result.allowed
        assert result.modified_value == "[REDACTED]"


# ---------------------------------------------------------------------------
# Import guard
# ---------------------------------------------------------------------------


class TestImportGuard:
    def test_from_yaml_raises_without_sdk(self) -> None:
        with pytest.raises(ImportError, match="agent-shield"):
            AgentShieldKernel.from_yaml("nonexistent.yaml")

    def test_mock_works_without_sdk(self) -> None:
        kernel = AgentShieldKernel.mock()
        assert kernel.validate_input("test").allowed


# ---------------------------------------------------------------------------
# Elapsed time tracking
# ---------------------------------------------------------------------------


class TestElapsedTime:
    def test_input_has_elapsed_ms(self, mock_kernel: AgentShieldKernel) -> None:
        result = mock_kernel.validate_input("test")
        assert result.elapsed_ms >= 0

    def test_output_has_elapsed_ms(self, mock_kernel: AgentShieldKernel) -> None:
        result = mock_kernel.validate_output("test")
        assert result.elapsed_ms >= 0
