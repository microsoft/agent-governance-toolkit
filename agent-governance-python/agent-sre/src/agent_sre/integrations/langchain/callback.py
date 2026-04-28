# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
LangChain Callback Handler for Agent-SRE
==========================================

Automatically records SLIs (Service Level Indicators) from LangChain
chain/agent execution:

- **TaskSuccessRate**: Tracks chain success/failure ratio
- **ResponseLatency**: Measures per-chain and per-LLM-call latency
- **CostPerTask**: Estimates cost from token usage (configurable rates)
- **ToolCallAccuracy**: Tracks tool call success/failure ratio

Works without importing langchain — uses duck typing so it plugs into
any LangChain ``callbacks=[...]`` list.

Example:
    >>> from agent_sre.integrations.langchain import AgentSRECallback
    >>>
    >>> cb = AgentSRECallback(cost_per_1k_input=0.003, cost_per_1k_output=0.015)
    >>> chain.invoke("query", config={"callbacks": [cb]})
    >>>
    >>> print(cb.task_success_rate)   # 1.0
    >>> print(cb.total_cost_usd)     # 0.0042
    >>> print(cb.avg_latency_ms)     # 182.5
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
    model: str
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
class ToolCallRecord:
    """Record of a single tool invocation."""

    run_id: str
    tool_name: str
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
class ChainRecord:
    """Record of a chain/agent execution."""

    run_id: str
    chain_type: str
    started_at: float
    ended_at: float = 0.0
    success: bool = True
    error: str = ""

    @property
    def latency_ms(self) -> float:
        if self.ended_at <= 0:
            return 0.0
        return (self.ended_at - self.started_at) * 1000


class AgentSRECallback:
    """
    LangChain callback handler that auto-records Agent-SRE SLIs.

    Implements the LangChain BaseCallbackHandler interface via duck typing
    (no langchain import required).

    Tracks:
    - Chain success/failure → TaskSuccessRate SLI
    - LLM call latency → ResponseLatency SLI
    - Token usage → CostPerTask SLI
    - Tool call success/failure → ToolCallAccuracy SLI
    """

    def __init__(
        self,
        *,
        cost_per_1k_input: float = 0.003,
        cost_per_1k_output: float = 0.015,
        name: str = "agent-sre",
    ):
        self.cost_per_1k_input = cost_per_1k_input
        self.cost_per_1k_output = cost_per_1k_output
        self.name = name

        # Records
        self._llm_calls: list[LLMCallRecord] = []
        self._tool_calls: list[ToolCallRecord] = []
        self._chains: list[ChainRecord] = []

        # Active runs (keyed by run_id string)
        self._active_llm: dict[str, LLMCallRecord] = {}
        self._active_tools: dict[str, ToolCallRecord] = {}
        self._active_chains: dict[str, ChainRecord] = {}

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _run_id_str(run_id: Any) -> str:
        """Convert run_id (UUID or str) to string."""
        return str(run_id) if run_id else ""

    def _estimate_cost(self, input_tokens: int, output_tokens: int) -> float:
        return (
            input_tokens / 1000 * self.cost_per_1k_input
            + output_tokens / 1000 * self.cost_per_1k_output
        )

    # ------------------------------------------------------------------
    # LLM callbacks
    # ------------------------------------------------------------------

    def on_llm_start(
        self,
        serialized: dict[str, Any],
        prompts: list[str],
        *,
        run_id: Any | None = None,
        **kwargs: Any,
    ) -> None:
        """Called when LLM starts generating."""
        rid = self._run_id_str(run_id)
        model = ""
        if serialized:
            model = serialized.get("name", serialized.get("id", [""])[-1] if serialized.get("id") else "")
        record = LLMCallRecord(run_id=rid, model=model, started_at=time.time())
        self._active_llm[rid] = record

    def on_llm_end(
        self,
        response: Any,
        *,
        run_id: Any | None = None,
        **kwargs: Any,
    ) -> None:
        """Called when LLM finishes generating."""
        rid = self._run_id_str(run_id)
        record = self._active_llm.pop(rid, None)
        if record is None:
            return
        record.ended_at = time.time()

        # Extract token usage from response
        if response and hasattr(response, "llm_output"):
            llm_output = response.llm_output or {}
            usage = llm_output.get("token_usage", {})
            record.input_tokens = usage.get("prompt_tokens", 0)
            record.output_tokens = usage.get("completion_tokens", 0)
            record.cost_usd = self._estimate_cost(record.input_tokens, record.output_tokens)

        self._llm_calls.append(record)

    def on_llm_error(
        self,
        error: BaseException,
        *,
        run_id: Any | None = None,
        **kwargs: Any,
    ) -> None:
        """Called when LLM errors out."""
        rid = self._run_id_str(run_id)
        record = self._active_llm.pop(rid, None)
        if record is None:
            return
        record.ended_at = time.time()
        record.error = str(error)
        self._llm_calls.append(record)

    # ------------------------------------------------------------------
    # Tool callbacks
    # ------------------------------------------------------------------

    def on_tool_start(
        self,
        serialized: dict[str, Any],
        input_str: str,
        *,
        run_id: Any | None = None,
        **kwargs: Any,
    ) -> None:
        """Called when a tool starts executing."""
        rid = self._run_id_str(run_id)
        tool_name = serialized.get("name", "") if serialized else ""
        record = ToolCallRecord(run_id=rid, tool_name=tool_name, started_at=time.time())
        self._active_tools[rid] = record

    def on_tool_end(
        self,
        output: str,
        *,
        run_id: Any | None = None,
        **kwargs: Any,
    ) -> None:
        """Called when a tool finishes executing."""
        rid = self._run_id_str(run_id)
        record = self._active_tools.pop(rid, None)
        if record is None:
            return
        record.ended_at = time.time()
        record.success = True
        self._tool_calls.append(record)

    def on_tool_error(
        self,
        error: BaseException,
        *,
        run_id: Any | None = None,
        **kwargs: Any,
    ) -> None:
        """Called when a tool errors out."""
        rid = self._run_id_str(run_id)
        record = self._active_tools.pop(rid, None)
        if record is None:
            return
        record.ended_at = time.time()
        record.success = False
        record.error = str(error)
        self._tool_calls.append(record)

    # ------------------------------------------------------------------
    # Chain callbacks
    # ------------------------------------------------------------------

    def on_chain_start(
        self,
        serialized: dict[str, Any],
        inputs: dict[str, Any],
        *,
        run_id: Any | None = None,
        **kwargs: Any,
    ) -> None:
        """Called when a chain starts executing."""
        rid = self._run_id_str(run_id)
        chain_type = ""
        if serialized:
            chain_type = serialized.get("name", serialized.get("id", [""])[-1] if serialized.get("id") else "")
        record = ChainRecord(run_id=rid, chain_type=chain_type, started_at=time.time())
        self._active_chains[rid] = record

    def on_chain_end(
        self,
        outputs: dict[str, Any],
        *,
        run_id: Any | None = None,
        **kwargs: Any,
    ) -> None:
        """Called when a chain finishes executing."""
        rid = self._run_id_str(run_id)
        record = self._active_chains.pop(rid, None)
        if record is None:
            return
        record.ended_at = time.time()
        record.success = True
        self._chains.append(record)

    def on_chain_error(
        self,
        error: BaseException,
        *,
        run_id: Any | None = None,
        **kwargs: Any,
    ) -> None:
        """Called when a chain errors out."""
        rid = self._run_id_str(run_id)
        record = self._active_chains.pop(rid, None)
        if record is None:
            return
        record.ended_at = time.time()
        record.success = False
        record.error = str(error)
        self._chains.append(record)

    # ------------------------------------------------------------------
    # No-op handlers (required by LangChain interface)
    # ------------------------------------------------------------------
    # Stubs required by BaseCallbackHandler — not yet wired to SLIs.
    # ------------------------------------------------------------------

    def on_text(self, text: str, **kwargs: Any) -> None:  # noqa: D102
        pass

    def on_llm_new_token(self, token: str, **kwargs: Any) -> None:  # noqa: D102
        pass

    def on_agent_action(self, action: Any, **kwargs: Any) -> None:  # noqa: D102
        pass

    def on_agent_finish(self, finish: Any, **kwargs: Any) -> None:  # noqa: D102
        pass

    def on_retry(self, retry_state: Any, **kwargs: Any) -> None:  # noqa: D102
        pass

    # ------------------------------------------------------------------
    # SLI Properties (computed from records)
    # ------------------------------------------------------------------

    @property
    def task_success_rate(self) -> float:
        """Fraction of chains that completed without error."""
        if not self._chains:
            return 1.0
        return sum(1 for c in self._chains if c.success) / len(self._chains)

    @property
    def tool_accuracy(self) -> float:
        """Fraction of tool calls that completed without error."""
        if not self._tool_calls:
            return 1.0
        return sum(1 for t in self._tool_calls if t.success) / len(self._tool_calls)

    @property
    def total_cost_usd(self) -> float:
        """Total estimated LLM cost in USD."""
        return sum(r.cost_usd for r in self._llm_calls)

    @property
    def avg_cost_usd(self) -> float:
        """Average cost per chain execution."""
        if not self._chains:
            return 0.0
        return self.total_cost_usd / len(self._chains)

    @property
    def total_input_tokens(self) -> int:
        return sum(r.input_tokens for r in self._llm_calls)

    @property
    def total_output_tokens(self) -> int:
        return sum(r.output_tokens for r in self._llm_calls)

    @property
    def avg_latency_ms(self) -> float:
        """Average chain latency in milliseconds."""
        latencies = [c.latency_ms for c in self._chains if c.latency_ms > 0]
        if not latencies:
            return 0.0
        return sum(latencies) / len(latencies)

    @property
    def p95_latency_ms(self) -> float:
        """95th percentile chain latency in milliseconds."""
        latencies = sorted(c.latency_ms for c in self._chains if c.latency_ms > 0)
        if not latencies:
            return 0.0
        idx = int(len(latencies) * 0.95)
        return latencies[min(idx, len(latencies) - 1)]

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    @property
    def llm_calls(self) -> list[LLMCallRecord]:
        return list(self._llm_calls)

    @property
    def tool_calls(self) -> list[ToolCallRecord]:
        return list(self._tool_calls)

    @property
    def chains(self) -> list[ChainRecord]:
        return list(self._chains)

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
            "chain_count": len(self._chains),
            "llm_call_count": len(self._llm_calls),
            "tool_call_count": len(self._tool_calls),
        }

    def reset(self) -> None:
        """Clear all records."""
        self._llm_calls.clear()
        self._tool_calls.clear()
        self._chains.clear()
        self._active_llm.clear()
        self._active_tools.clear()
        self._active_chains.clear()
