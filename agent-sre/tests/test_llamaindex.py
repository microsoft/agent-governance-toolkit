# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Tests for LlamaIndex SRE callback handler.

No real LlamaIndex dependency — simulates callback events directly.

Run with: python -m pytest tests/test_llamaindex.py -v --tb=short
"""



from agent_sre.integrations.llamaindex.handler import (
    AgentSRELlamaIndexHandler,
)

# =============================================================================
# Helpers: simulate LlamaIndex callback events
# =============================================================================


def _simulate_query(
    handler: AgentSRELlamaIndexHandler,
    query_str: str = "test query",
    error: str | None = None,
) -> None:
    """Simulate on_query_start → on_query_end (or on_query_error)."""
    handler.on_query_start(query_str)
    if error:
        handler.on_query_error(RuntimeError(error))
    else:
        handler.on_query_end(response="test response")


def _simulate_llm_call(
    handler: AgentSRELlamaIndexHandler,
    prompt: str = "test prompt",
    input_tokens: int = 100,
    output_tokens: int = 50,
    error: str | None = None,
) -> None:
    """Simulate on_llm_start → on_llm_end (or on_llm_error)."""
    handler.on_llm_start(prompt)
    if error:
        handler.on_llm_error(RuntimeError(error))
    else:
        handler.on_llm_end(
            response="test response",
            input_tokens=input_tokens,
            output_tokens=output_tokens,
        )


def _simulate_retriever_call(
    handler: AgentSRELlamaIndexHandler,
    query: str = "test query",
    num_nodes: int = 3,
    error: str | None = None,
) -> None:
    """Simulate on_retriever_start → on_retriever_end (or on_retriever_error)."""
    handler.on_retriever_start(query)
    if error:
        handler.on_retriever_error(RuntimeError(error))
    else:
        nodes = [f"node_{i}" for i in range(num_nodes)]
        handler.on_retriever_end(nodes)


# =============================================================================
# Query Callback Tests
# =============================================================================


class TestQueryCallbacks:
    def test_query_recorded(self):
        handler = AgentSRELlamaIndexHandler()
        _simulate_query(handler)
        assert len(handler.queries) == 1
        assert handler.queries[0].success

    def test_query_error(self):
        handler = AgentSRELlamaIndexHandler()
        _simulate_query(handler, error="timeout")
        assert len(handler.queries) == 1
        assert not handler.queries[0].success
        assert handler.queries[0].error == "timeout"

    def test_task_success_rate(self):
        handler = AgentSRELlamaIndexHandler()
        _simulate_query(handler)
        _simulate_query(handler)
        _simulate_query(handler, error="fail")
        assert abs(handler.task_success_rate - 2 / 3) < 0.01

    def test_task_success_rate_no_queries(self):
        handler = AgentSRELlamaIndexHandler()
        assert handler.task_success_rate == 1.0


# =============================================================================
# LLM Callback Tests
# =============================================================================


class TestLLMCallbacks:
    def test_llm_call_recorded(self):
        handler = AgentSRELlamaIndexHandler()
        _simulate_llm_call(handler)
        assert len(handler.llm_calls) == 1

    def test_llm_token_counts(self):
        handler = AgentSRELlamaIndexHandler()
        _simulate_llm_call(handler, input_tokens=200, output_tokens=100)
        assert handler.total_input_tokens == 200
        assert handler.total_output_tokens == 100

    def test_llm_cost_estimation(self):
        handler = AgentSRELlamaIndexHandler(cost_per_1k_input=0.01, cost_per_1k_output=0.03)
        _simulate_llm_call(handler, input_tokens=1000, output_tokens=500)
        expected = 1.0 * 0.01 + 0.5 * 0.03  # $0.01 + $0.015 = $0.025
        assert abs(handler.total_cost_usd - expected) < 0.0001

    def test_llm_error(self):
        handler = AgentSRELlamaIndexHandler()
        _simulate_llm_call(handler, error="timeout")
        assert len(handler.llm_calls) == 1
        assert handler.llm_calls[0].error == "timeout"


# =============================================================================
# Retriever Callback Tests
# =============================================================================


class TestRetrieverCallbacks:
    def test_retriever_recorded(self):
        handler = AgentSRELlamaIndexHandler()
        _simulate_retriever_call(handler)
        assert len(handler.retrievers) == 1
        assert handler.retrievers[0].success
        assert handler.retrievers[0].num_nodes == 3

    def test_retriever_error(self):
        handler = AgentSRELlamaIndexHandler()
        _simulate_retriever_call(handler, error="index not found")
        assert len(handler.retrievers) == 1
        assert not handler.retrievers[0].success
        assert handler.retrievers[0].error == "index not found"

    def test_tool_accuracy_all_success(self):
        handler = AgentSRELlamaIndexHandler()
        _simulate_retriever_call(handler)
        _simulate_retriever_call(handler)
        assert handler.tool_accuracy == 1.0

    def test_tool_accuracy_mixed(self):
        handler = AgentSRELlamaIndexHandler()
        _simulate_retriever_call(handler)
        _simulate_retriever_call(handler, error="fail")
        assert handler.tool_accuracy == 0.5


# =============================================================================
# Sub-Question Tests
# =============================================================================


class TestSubQuestions:
    def test_sub_questions_tracked(self):
        handler = AgentSRELlamaIndexHandler()
        handler.on_sub_question("What is X?")
        handler.on_sub_question("What is Y?")
        handler.on_sub_question_end("What is X?", "X is ...")
        handler.on_sub_question_end("What is Y?", "Y is ...")
        assert len(handler.sub_questions) == 2
        assert handler.sub_questions[0]["answer"] == "X is ..."
        assert handler.sub_questions[1]["answer"] == "Y is ..."


# =============================================================================
# SLI Snapshot
# =============================================================================


class TestSLISnapshot:
    def test_snapshot_keys(self):
        handler = AgentSRELlamaIndexHandler()
        _simulate_query(handler)
        _simulate_llm_call(handler)
        _simulate_retriever_call(handler)
        snap = handler.get_sli_snapshot()

        assert "task_success_rate" in snap
        assert "tool_accuracy" in snap
        assert "total_cost_usd" in snap
        assert "avg_cost_usd" in snap
        assert "avg_latency_ms" in snap
        assert "p95_latency_ms" in snap
        assert "total_input_tokens" in snap
        assert "total_output_tokens" in snap
        assert "query_count" in snap
        assert "llm_call_count" in snap
        assert "retriever_count" in snap

    def test_snapshot_counts(self):
        handler = AgentSRELlamaIndexHandler()
        _simulate_query(handler)
        _simulate_query(handler)
        _simulate_llm_call(handler)
        _simulate_retriever_call(handler)
        _simulate_retriever_call(handler)
        _simulate_retriever_call(handler)

        snap = handler.get_sli_snapshot()
        assert snap["query_count"] == 2
        assert snap["llm_call_count"] == 1
        assert snap["retriever_count"] == 3


# =============================================================================
# Reset
# =============================================================================


class TestReset:
    def test_reset_clears_all(self):
        handler = AgentSRELlamaIndexHandler()
        _simulate_query(handler)
        _simulate_llm_call(handler)
        _simulate_retriever_call(handler)

        handler.reset()
        assert len(handler.queries) == 0
        assert len(handler.llm_calls) == 0
        assert len(handler.retrievers) == 0
        assert handler.total_cost_usd == 0.0
        assert handler.task_success_rate == 1.0


# =============================================================================
# Integration
# =============================================================================


class TestIntegration:
    def test_full_rag_execution(self):
        """Simulate a full RAG pipeline: query → retriever → LLM → query end."""
        handler = AgentSRELlamaIndexHandler(
            cost_per_1k_input=0.01, cost_per_1k_output=0.03,
        )

        # Query starts
        handler.on_query_start("What is Python?")

        # Retriever fetches nodes
        handler.on_retriever_start("What is Python?")
        handler.on_retriever_end(["node1", "node2", "node3"])

        # LLM synthesizes answer
        handler.on_llm_start("Synthesize answer from context")
        handler.on_llm_end(
            response="Python is a programming language.",
            input_tokens=500,
            output_tokens=100,
        )

        # Query ends
        handler.on_query_end(response="Python is a programming language.")

        # Verify SLIs
        assert handler.task_success_rate == 1.0
        assert handler.tool_accuracy == 1.0
        assert handler.total_input_tokens == 500
        assert handler.total_output_tokens == 100
        assert handler.total_cost_usd > 0
        assert len(handler.queries) == 1
        assert len(handler.llm_calls) == 1
        assert len(handler.retrievers) == 1

        # Check cost math
        expected_cost = 500 / 1000 * 0.01 + 100 / 1000 * 0.03
        assert abs(handler.total_cost_usd - expected_cost) < 0.0001

    def test_imports_from_package(self):
        """Verify package exports."""
        from agent_sre.integrations.llamaindex import AgentSRELlamaIndexHandler as Imported
        assert Imported is AgentSRELlamaIndexHandler
