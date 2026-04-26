# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Tests for LangChain SRE callback handler.

No real LangChain dependency — simulates callback events directly.

Run with: python -m pytest tests/test_langchain_callback.py -v --tb=short
"""

from unittest.mock import MagicMock

from agent_sre.integrations.langchain.callback import (
    AgentSRECallback,
)

# =============================================================================
# Helpers: simulate LangChain callback events
# =============================================================================


def _simulate_llm_call(
    cb: AgentSRECallback,
    run_id: str = "llm-1",
    model: str = "gpt-4",
    prompt_tokens: int = 100,
    completion_tokens: int = 50,
    duration_ms: float = 200,
    error: str | None = None,
) -> None:
    """Simulate on_llm_start → on_llm_end (or on_llm_error)."""
    serialized = {"name": model, "id": ["langchain", "llms", model]}
    cb.on_llm_start(serialized, ["test prompt"], run_id=run_id)

    if error:
        cb.on_llm_error(RuntimeError(error), run_id=run_id)
    else:
        # Simulate response with token usage
        response = MagicMock()
        response.llm_output = {
            "token_usage": {
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
            }
        }
        cb.on_llm_end(response, run_id=run_id)


def _simulate_tool_call(
    cb: AgentSRECallback,
    run_id: str = "tool-1",
    tool_name: str = "search",
    error: str | None = None,
) -> None:
    """Simulate on_tool_start → on_tool_end (or on_tool_error)."""
    serialized = {"name": tool_name}
    cb.on_tool_start(serialized, "input text", run_id=run_id)

    if error:
        cb.on_tool_error(RuntimeError(error), run_id=run_id)
    else:
        cb.on_tool_end("tool output", run_id=run_id)


def _simulate_chain(
    cb: AgentSRECallback,
    run_id: str = "chain-1",
    chain_type: str = "RetrievalQA",
    error: str | None = None,
) -> None:
    """Simulate on_chain_start → on_chain_end (or on_chain_error)."""
    serialized = {"name": chain_type}
    cb.on_chain_start(serialized, {"query": "test"}, run_id=run_id)

    if error:
        cb.on_chain_error(RuntimeError(error), run_id=run_id)
    else:
        cb.on_chain_end({"result": "answer"}, run_id=run_id)


# =============================================================================
# LLM Callback Tests
# =============================================================================


class TestLLMCallbacks:
    def test_llm_call_recorded(self):
        cb = AgentSRECallback()
        _simulate_llm_call(cb)
        assert len(cb.llm_calls) == 1
        assert cb.llm_calls[0].model == "gpt-4"

    def test_llm_token_counts(self):
        cb = AgentSRECallback()
        _simulate_llm_call(cb, prompt_tokens=200, completion_tokens=100)
        assert cb.total_input_tokens == 200
        assert cb.total_output_tokens == 100

    def test_llm_cost_estimation(self):
        cb = AgentSRECallback(cost_per_1k_input=0.01, cost_per_1k_output=0.03)
        _simulate_llm_call(cb, prompt_tokens=1000, completion_tokens=500)
        expected = 1.0 * 0.01 + 0.5 * 0.03  # $0.01 + $0.015 = $0.025
        assert abs(cb.total_cost_usd - expected) < 0.0001

    def test_llm_error(self):
        cb = AgentSRECallback()
        _simulate_llm_call(cb, run_id="err-1", error="timeout")
        assert len(cb.llm_calls) == 1
        assert cb.llm_calls[0].error == "timeout"

    def test_llm_latency(self):
        cb = AgentSRECallback()
        _simulate_llm_call(cb)
        record = cb.llm_calls[0]
        assert record.latency_ms >= 0

    def test_multiple_llm_calls(self):
        cb = AgentSRECallback()
        _simulate_llm_call(cb, run_id="llm-1", prompt_tokens=100, completion_tokens=50)
        _simulate_llm_call(cb, run_id="llm-2", prompt_tokens=200, completion_tokens=100)
        assert len(cb.llm_calls) == 2
        assert cb.total_input_tokens == 300
        assert cb.total_output_tokens == 150

    def test_llm_end_without_start(self):
        """Should not crash if on_llm_end is called without on_llm_start."""
        cb = AgentSRECallback()
        response = MagicMock()
        response.llm_output = None
        cb.on_llm_end(response, run_id="orphan")
        assert len(cb.llm_calls) == 0

    def test_llm_no_token_usage(self):
        cb = AgentSRECallback()
        cb.on_llm_start({"name": "model"}, ["prompt"], run_id="no-usage")
        response = MagicMock()
        response.llm_output = {}
        cb.on_llm_end(response, run_id="no-usage")
        assert cb.llm_calls[0].input_tokens == 0
        assert cb.llm_calls[0].cost_usd == 0.0


# =============================================================================
# Tool Callback Tests
# =============================================================================


class TestToolCallbacks:
    def test_tool_call_recorded(self):
        cb = AgentSRECallback()
        _simulate_tool_call(cb, tool_name="calculator")
        assert len(cb.tool_calls) == 1
        assert cb.tool_calls[0].tool_name == "calculator"
        assert cb.tool_calls[0].success

    def test_tool_error(self):
        cb = AgentSRECallback()
        _simulate_tool_call(cb, run_id="t-err", error="not found")
        assert len(cb.tool_calls) == 1
        assert not cb.tool_calls[0].success
        assert cb.tool_calls[0].error == "not found"

    def test_tool_accuracy_all_success(self):
        cb = AgentSRECallback()
        _simulate_tool_call(cb, run_id="t1")
        _simulate_tool_call(cb, run_id="t2")
        assert cb.tool_accuracy == 1.0

    def test_tool_accuracy_mixed(self):
        cb = AgentSRECallback()
        _simulate_tool_call(cb, run_id="t1")
        _simulate_tool_call(cb, run_id="t2", error="fail")
        assert cb.tool_accuracy == 0.5

    def test_tool_accuracy_no_calls(self):
        cb = AgentSRECallback()
        assert cb.tool_accuracy == 1.0  # default


# =============================================================================
# Chain Callback Tests
# =============================================================================


class TestChainCallbacks:
    def test_chain_recorded(self):
        cb = AgentSRECallback()
        _simulate_chain(cb)
        assert len(cb.chains) == 1
        assert cb.chains[0].success

    def test_chain_error(self):
        cb = AgentSRECallback()
        _simulate_chain(cb, run_id="c-err", error="boom")
        assert len(cb.chains) == 1
        assert not cb.chains[0].success
        assert cb.chains[0].error == "boom"

    def test_task_success_rate(self):
        cb = AgentSRECallback()
        _simulate_chain(cb, run_id="c1")
        _simulate_chain(cb, run_id="c2")
        _simulate_chain(cb, run_id="c3", error="fail")
        assert abs(cb.task_success_rate - 2 / 3) < 0.01

    def test_task_success_rate_no_chains(self):
        cb = AgentSRECallback()
        assert cb.task_success_rate == 1.0

    def test_chain_latency(self):
        cb = AgentSRECallback()
        _simulate_chain(cb)
        assert cb.avg_latency_ms >= 0

    def test_p95_latency(self):
        cb = AgentSRECallback()
        for i in range(20):
            _simulate_chain(cb, run_id=f"c-{i}")
        assert cb.p95_latency_ms >= 0

    def test_p95_latency_no_chains(self):
        cb = AgentSRECallback()
        assert cb.p95_latency_ms == 0.0


# =============================================================================
# SLI Snapshot
# =============================================================================


class TestSLISnapshot:
    def test_snapshot_keys(self):
        cb = AgentSRECallback()
        _simulate_chain(cb, run_id="c1")
        _simulate_llm_call(cb, run_id="l1")
        _simulate_tool_call(cb, run_id="t1")
        snap = cb.get_sli_snapshot()

        assert "task_success_rate" in snap
        assert "tool_accuracy" in snap
        assert "total_cost_usd" in snap
        assert "avg_cost_usd" in snap
        assert "avg_latency_ms" in snap
        assert "p95_latency_ms" in snap
        assert "total_input_tokens" in snap
        assert "total_output_tokens" in snap
        assert "chain_count" in snap
        assert "llm_call_count" in snap
        assert "tool_call_count" in snap

    def test_snapshot_counts(self):
        cb = AgentSRECallback()
        _simulate_chain(cb, run_id="c1")
        _simulate_chain(cb, run_id="c2")
        _simulate_llm_call(cb, run_id="l1")
        _simulate_tool_call(cb, run_id="t1")
        _simulate_tool_call(cb, run_id="t2")
        _simulate_tool_call(cb, run_id="t3")

        snap = cb.get_sli_snapshot()
        assert snap["chain_count"] == 2
        assert snap["llm_call_count"] == 1
        assert snap["tool_call_count"] == 3


# =============================================================================
# Reset
# =============================================================================


class TestReset:
    def test_reset_clears_all(self):
        cb = AgentSRECallback()
        _simulate_chain(cb, run_id="c1")
        _simulate_llm_call(cb, run_id="l1")
        _simulate_tool_call(cb, run_id="t1")

        cb.reset()
        assert len(cb.llm_calls) == 0
        assert len(cb.tool_calls) == 0
        assert len(cb.chains) == 0
        assert cb.total_cost_usd == 0.0
        assert cb.task_success_rate == 1.0


# =============================================================================
# No-op handlers
# =============================================================================


class TestNoOpHandlers:
    def test_no_ops_dont_crash(self):
        cb = AgentSRECallback()
        cb.on_text("hello")
        cb.on_llm_new_token("tok")
        cb.on_agent_action(MagicMock())
        cb.on_agent_finish(MagicMock())
        cb.on_retry(MagicMock())


# =============================================================================
# Integration
# =============================================================================


class TestIntegration:
    def test_full_agent_execution(self):
        """Simulate a full agent execution with multiple LLM calls and tools."""
        cb = AgentSRECallback(cost_per_1k_input=0.01, cost_per_1k_output=0.03)

        # Chain starts
        cb.on_chain_start({"name": "AgentExecutor"}, {"input": "Search for Python tutorials"}, run_id="chain-main")

        # LLM call 1: decide action
        _simulate_llm_call(cb, run_id="llm-1", prompt_tokens=500, completion_tokens=50)

        # Tool call: search
        _simulate_tool_call(cb, run_id="tool-1", tool_name="web_search")

        # LLM call 2: synthesize answer
        _simulate_llm_call(cb, run_id="llm-2", prompt_tokens=800, completion_tokens=200)

        # Chain ends
        cb.on_chain_end({"output": "Here are the tutorials..."}, run_id="chain-main")

        # Verify SLIs
        assert cb.task_success_rate == 1.0
        assert cb.tool_accuracy == 1.0
        assert cb.total_input_tokens == 1300
        assert cb.total_output_tokens == 250
        assert cb.total_cost_usd > 0
        assert len(cb.chains) == 1
        assert len(cb.llm_calls) == 2
        assert len(cb.tool_calls) == 1

        # Check cost math
        expected_cost = (500 / 1000 * 0.01 + 50 / 1000 * 0.03) + (800 / 1000 * 0.01 + 200 / 1000 * 0.03)
        assert abs(cb.total_cost_usd - expected_cost) < 0.0001

    def test_failed_agent_execution(self):
        """Simulate an agent execution that fails mid-way."""
        cb = AgentSRECallback()

        _simulate_chain(cb, run_id="c1")  # success
        _simulate_chain(cb, run_id="c2", error="LLM rate limit")  # failure

        assert cb.task_success_rate == 0.5
        snap = cb.get_sli_snapshot()
        assert snap["chain_count"] == 2

    def test_imports_from_package(self):
        """Verify package exports."""
        from agent_sre.integrations.langchain import AgentSRECallback as Imported
        assert Imported is AgentSRECallback
