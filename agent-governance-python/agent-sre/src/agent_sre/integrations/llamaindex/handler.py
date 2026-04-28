# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
LlamaIndex Callback Handler for Agent-SRE
==========================================

Automatically records SLIs (Service Level Indicators) from LlamaIndex
query engine execution:

- **TaskSuccessRate**: Tracks query success/failure ratio
- **ResponseLatency**: Measures per-query and per-LLM-call latency
- **CostPerTask**: Estimates cost from token usage (configurable rates)
- **ToolCallAccuracy**: Tracks retriever call success/failure ratio

Works without importing llama-index — uses duck typing so it plugs into
any LlamaIndex callback manager.

Example:
    >>> from agent_sre.integrations.llamaindex import AgentSRELlamaIndexHandler
    >>>
    >>> handler = AgentSRELlamaIndexHandler(cost_per_1k_input=0.003, cost_per_1k_output=0.015)
    >>> # Attach to LlamaIndex callback manager
    >>>
    >>> print(handler.task_success_rate)   # 1.0
    >>> print(handler.total_cost_usd)     # 0.0042
    >>> print(handler.avg_latency_ms)     # 182.5
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class LLMCallRecord:
    """Record of a single LLM invocation."""

    run_id: str
    started_at: float
    ended_at: float = 0.0
    input_tokens: int = 0
    output_tokens: int = 0
    cost_usd: float = 0.0
    error: str = ""

    @property
    def latency_ms(self) -> float:
        if self.ended_at <= 0:
            return 0.0
        return (self.ended_at - self.started_at) * 1000


@dataclass
class QueryRecord:
    """Record of a query execution."""

    run_id: str
    query_str: str
    started_at: float
    ended_at: float = 0.0
    success: bool = True
    error: str = ""

    @property
    def latency_ms(self) -> float:
        if self.ended_at <= 0:
            return 0.0
        return (self.ended_at - self.started_at) * 1000


@dataclass
class RetrieverRecord:
    """Record of a retriever invocation."""

    run_id: str
    query: str
    started_at: float
    ended_at: float = 0.0
    num_nodes: int = 0
    success: bool = True
    error: str = ""

    @property
    def latency_ms(self) -> float:
        if self.ended_at <= 0:
            return 0.0
        return (self.ended_at - self.started_at) * 1000


class AgentSRELlamaIndexHandler:
    """
    LlamaIndex callback handler that auto-records Agent-SRE SLIs.

    Implements the LlamaIndex callback interface via duck typing
    (no llama-index import required).

    Tracks:
    - Query success/failure → TaskSuccessRate SLI
    - LLM call latency & tokens → CostPerTask SLI
    - Retriever success/failure → ToolCallAccuracy SLI
    - Sub-questions as steps
    """

    def __init__(
        self,
        *,
        cost_per_1k_input: float = 0.003,
        cost_per_1k_output: float = 0.015,
    ):
        self.cost_per_1k_input = cost_per_1k_input
        self.cost_per_1k_output = cost_per_1k_output

        # Records
        self._queries: list[QueryRecord] = []
        self._llm_calls: list[LLMCallRecord] = []
        self._retrievers: list[RetrieverRecord] = []
        self._sub_questions: list[dict[str, Any]] = []

        # Active runs
        self._active_queries: dict[str, QueryRecord] = {}
        self._active_llm: dict[str, LLMCallRecord] = {}
        self._active_retrievers: dict[str, RetrieverRecord] = {}

        # ID counters
        self._query_counter = 0
        self._llm_counter = 0
        self._retriever_counter = 0

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _estimate_cost(self, input_tokens: int, output_tokens: int) -> float:
        return (
            input_tokens / 1000 * self.cost_per_1k_input
            + output_tokens / 1000 * self.cost_per_1k_output
        )

    # ------------------------------------------------------------------
    # Query callbacks
    # ------------------------------------------------------------------

    def on_query_start(self, query_str: str, **kwargs: Any) -> None:
        """Called when a query starts executing."""
        self._query_counter += 1
        rid = f"query-{self._query_counter}"
        record = QueryRecord(run_id=rid, query_str=query_str, started_at=time.time())
        self._active_queries[rid] = record

    def on_query_end(self, response: Any = None, **kwargs: Any) -> None:
        """Called when a query finishes executing."""
        if not self._active_queries:
            return
        rid = next(reversed(self._active_queries))
        record = self._active_queries.pop(rid)
        record.ended_at = time.time()
        record.success = True
        self._queries.append(record)

    def on_query_error(self, error: Any, **kwargs: Any) -> None:
        """Called when a query errors out."""
        if not self._active_queries:
            return
        rid = next(reversed(self._active_queries))
        record = self._active_queries.pop(rid)
        record.ended_at = time.time()
        record.success = False
        record.error = str(error)
        self._queries.append(record)

    # ------------------------------------------------------------------
    # LLM callbacks
    # ------------------------------------------------------------------

    def on_llm_start(self, prompt: str = "", **kwargs: Any) -> None:
        """Called when LLM starts generating."""
        self._llm_counter += 1
        rid = f"llm-{self._llm_counter}"
        record = LLMCallRecord(run_id=rid, started_at=time.time())
        self._active_llm[rid] = record

    def on_llm_end(
        self,
        response: Any = None,
        input_tokens: int = 0,
        output_tokens: int = 0,
        **kwargs: Any,
    ) -> None:
        """Called when LLM finishes generating."""
        if not self._active_llm:
            return
        rid = next(reversed(self._active_llm))
        record = self._active_llm.pop(rid)
        record.ended_at = time.time()
        record.input_tokens = input_tokens
        record.output_tokens = output_tokens
        record.cost_usd = self._estimate_cost(input_tokens, output_tokens)
        self._llm_calls.append(record)

    def on_llm_error(self, error: Any, **kwargs: Any) -> None:
        """Called when LLM errors out."""
        if not self._active_llm:
            return
        rid = next(reversed(self._active_llm))
        record = self._active_llm.pop(rid)
        record.ended_at = time.time()
        record.error = str(error)
        self._llm_calls.append(record)

    # ------------------------------------------------------------------
    # Retriever callbacks
    # ------------------------------------------------------------------

    def on_retriever_start(self, query: str = "", **kwargs: Any) -> None:
        """Called when a retriever starts."""
        self._retriever_counter += 1
        rid = f"retriever-{self._retriever_counter}"
        record = RetrieverRecord(run_id=rid, query=query, started_at=time.time())
        self._active_retrievers[rid] = record

    def on_retriever_end(self, nodes: Any = None, **kwargs: Any) -> None:
        """Called when a retriever finishes."""
        if not self._active_retrievers:
            return
        rid = next(reversed(self._active_retrievers))
        record = self._active_retrievers.pop(rid)
        record.ended_at = time.time()
        record.success = True
        if nodes is not None:
            record.num_nodes = len(nodes) if hasattr(nodes, "__len__") else 0
        self._retrievers.append(record)

    def on_retriever_error(self, error: Any, **kwargs: Any) -> None:
        """Called when a retriever errors out."""
        if not self._active_retrievers:
            return
        rid = next(reversed(self._active_retrievers))
        record = self._active_retrievers.pop(rid)
        record.ended_at = time.time()
        record.success = False
        record.error = str(error)
        self._retrievers.append(record)

    # ------------------------------------------------------------------
    # Sub-question callbacks
    # ------------------------------------------------------------------

    def on_sub_question(self, question: str, **kwargs: Any) -> None:
        """Called when a sub-question is generated."""
        self._sub_questions.append({"question": question, "answer": None})

    def on_sub_question_end(self, question: str, answer: str, **kwargs: Any) -> None:
        """Called when a sub-question is answered."""
        for sq in reversed(self._sub_questions):
            if sq["question"] == question and sq["answer"] is None:
                sq["answer"] = answer
                break

    # ------------------------------------------------------------------
    # Synthesize callbacks (no-op tracking, but complete interface)
    # ------------------------------------------------------------------

    def on_synthesize_start(self, query: str = "", **kwargs: Any) -> None:
        """Called when synthesis starts."""
        pass

    def on_synthesize_end(self, response: Any = None, **kwargs: Any) -> None:
        """Called when synthesis ends."""
        pass

    # ------------------------------------------------------------------
    # SLI Properties
    # ------------------------------------------------------------------

    @property
    def task_success_rate(self) -> float:
        """Fraction of queries that completed without error."""
        if not self._queries:
            return 1.0
        return sum(1 for q in self._queries if q.success) / len(self._queries)

    @property
    def tool_accuracy(self) -> float:
        """Fraction of retriever calls that completed without error."""
        if not self._retrievers:
            return 1.0
        return sum(1 for r in self._retrievers if r.success) / len(self._retrievers)

    @property
    def total_cost_usd(self) -> float:
        """Total estimated LLM cost in USD."""
        return sum(r.cost_usd for r in self._llm_calls)

    @property
    def avg_cost_usd(self) -> float:
        """Average cost per query execution."""
        if not self._queries:
            return 0.0
        return self.total_cost_usd / len(self._queries)

    @property
    def total_input_tokens(self) -> int:
        return sum(r.input_tokens for r in self._llm_calls)

    @property
    def total_output_tokens(self) -> int:
        return sum(r.output_tokens for r in self._llm_calls)

    @property
    def avg_latency_ms(self) -> float:
        """Average query latency in milliseconds."""
        latencies = [q.latency_ms for q in self._queries if q.latency_ms > 0]
        if not latencies:
            return 0.0
        return sum(latencies) / len(latencies)

    @property
    def p95_latency_ms(self) -> float:
        """95th percentile query latency in milliseconds."""
        latencies = sorted(q.latency_ms for q in self._queries if q.latency_ms > 0)
        if not latencies:
            return 0.0
        idx = int(len(latencies) * 0.95)
        return latencies[min(idx, len(latencies) - 1)]

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    @property
    def queries(self) -> list[QueryRecord]:
        return list(self._queries)

    @property
    def llm_calls(self) -> list[LLMCallRecord]:
        return list(self._llm_calls)

    @property
    def retrievers(self) -> list[RetrieverRecord]:
        return list(self._retrievers)

    @property
    def sub_questions(self) -> list[dict[str, Any]]:
        return list(self._sub_questions)

    def get_sli_snapshot(self) -> dict[str, Any]:
        """Return all SLI values as a dict (for recording into Agent-SRE SLO)."""
        return {
            "task_success_rate": self.task_success_rate,
            "tool_accuracy": self.tool_accuracy,
            "total_cost_usd": self.total_cost_usd,
            "avg_cost_usd": self.avg_cost_usd,
            "avg_latency_ms": self.avg_latency_ms,
            "p95_latency_ms": self.p95_latency_ms,
            "total_input_tokens": self.total_input_tokens,
            "total_output_tokens": self.total_output_tokens,
            "query_count": len(self._queries),
            "llm_call_count": len(self._llm_calls),
            "retriever_count": len(self._retrievers),
            "sub_question_count": len(self._sub_questions),
        }

    def reset(self) -> None:
        """Clear all records."""
        self._queries.clear()
        self._llm_calls.clear()
        self._retrievers.clear()
        self._sub_questions.clear()
        self._active_queries.clear()
        self._active_llm.clear()
        self._active_retrievers.clear()
