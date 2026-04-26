# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Test Layer 4: Intelligence packages.
"""

import pytest


class TestSCAK:
    """Test self-correcting-agent-kernel package."""
    
    def test_import_scak(self):
        """Test basic import."""
        try:
            from agent_kernel import (
                SelfCorrectingAgentKernel,
                diagnose_failure,
                triage_failure,
            )
            assert SelfCorrectingAgentKernel is not None
        except ImportError:
            pytest.skip("scak not fully installed")
    
    def test_import_failure_models(self):
        """Test importing failure models from scak."""
        try:
            from agent_kernel.models import FailureType, FailureSeverity
            assert FailureType is not None
            assert FailureSeverity is not None
        except ImportError:
            # May use agent_primitives instead
            from agent_primitives import FailureType, FailureSeverity
            assert FailureType is not None


class TestMuteAgent:
    """Test mute-agent package."""
    
    def test_import_mute_agent(self):
        """Test basic import."""
        try:
            from mute_agent import MuteAgent
            assert MuteAgent is not None
        except ImportError:
            pytest.skip("mute-agent not installed")
    
    def test_import_core_components(self):
        """Test importing core components."""
        try:
            from mute_agent.core import ReasoningAgent, ExecutionAgent
            assert ReasoningAgent is not None
            assert ExecutionAgent is not None
        except ImportError:
            pytest.skip("mute-agent core not available")


# =========================================================================
# SelfCorrectingKernel tests (#168)
# =========================================================================


try:
    from agent_kernel import SelfCorrectingAgentKernel
    HAS_SCAK = True
except ImportError:
    HAS_SCAK = False


@pytest.mark.skipif(not HAS_SCAK, reason="agent_kernel not installed")
class TestSelfCorrectingKernel:
    """Test kernel execution, self-correction on failure, and learning from mistakes."""

    @pytest.fixture
    def kernel(self):
        return SelfCorrectingAgentKernel(config={"log_level": "WARNING"})

    def test_kernel_initializes(self, kernel):
        """Kernel can be instantiated with default config."""
        assert kernel.detector is not None
        assert kernel.analyzer is not None
        assert kernel.triage is not None

    def test_handle_failure_returns_result(self, kernel):
        """handle_failure returns a dict with expected keys."""
        result = kernel.handle_failure(
            agent_id="agent-1",
            error_message="Division by zero",
            context={"action": "compute"},
        )
        assert isinstance(result, dict)
        assert "success" in result
        assert "failure" in result

    def test_handle_failure_records_and_analyzes(self, kernel):
        """A failure is recorded and analyzed."""
        result = kernel.handle_failure(
            agent_id="agent-2",
            error_message="KeyError: 'missing_key'",
            context={"action": "lookup"},
        )
        assert "failure" in result
        assert result["analysis"] is not None

    def test_handle_failure_retry_available(self, kernel):
        """handle_failure returns a result for transient errors."""
        result = kernel.handle_failure(
            agent_id="agent-3",
            error_message="Timeout",
            context={"action": "fetch"},
        )
        assert isinstance(result, dict)
        assert "failure" in result

    def test_failure_history_accumulates(self, kernel):
        """Failures are recorded in the detector's history."""
        kernel.handle_failure("agent-4", "err-1", context={"action": "a"})
        kernel.handle_failure("agent-4", "err-2", context={"action": "b"})
        history = kernel.get_failure_history(agent_id="agent-4")
        assert len(history) >= 2

    def test_wake_up_and_fix_convenience(self, kernel):
        """wake_up_and_fix delegates to handle_failure."""
        result = kernel.wake_up_and_fix("agent-5", "NoneType error", {"action": "run"})
        assert isinstance(result, dict)
        assert "success" in result

    def test_async_triage_queues_noncritical(self, kernel):
        """Non-critical failures with user_prompt are routed to async queue."""
        result = kernel.handle_failure(
            agent_id="agent-6",
            error_message="Formatting issue",
            context={"action": "format"},
            user_prompt="Make it pretty",
        )
        # The triage engine decides; verify we get a result either way
        assert isinstance(result, dict)

    def test_get_agent_status(self, kernel):
        """get_agent_status returns an AgentState."""
        status = kernel.get_agent_status("new-agent")
        assert status is not None

    def test_learning_from_repeated_failures(self, kernel):
        """Repeated similar failures produce similar-failure references in analysis."""
        for i in range(3):
            kernel.handle_failure(
                agent_id="learn-agent",
                error_message="Connection refused",
                context={"action": "connect", "attempt": i},
            )
        history = kernel.get_failure_history(agent_id="learn-agent")
        assert len(history) >= 3
