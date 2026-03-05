# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Performance benchmarks for Agent OS kernel, policies, and adapters.

Run with: pytest tests/test_benchmarks.py -v -m benchmark
"""

from __future__ import annotations

import asyncio
import time
from typing import Any, Dict, List, Optional

import pytest

from agent_os.base_agent import AgentConfig, AuditEntry, BaseAgent
from agent_os.integrations.base import (
    ExecutionContext as GovExecutionContext,
    GovernancePolicy,
    PatternType,
    PolicyInterceptor,
    ToolCallRequest,
)
from agent_os.stateless import (
    ExecutionContext,
    ExecutionResult,
    MemoryBackend,
    StatelessKernel,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

ITERATIONS_KERNEL = 1000
ITERATIONS_POLICY = 1000
ITERATIONS_ADAPTER = 1000
CONCURRENT_TASKS = 100

# Max latency thresholds (nanoseconds)
KERNEL_EXECUTE_MAX_NS = 1_000_000  # 1 ms
MEMORY_BACKEND_OP_MAX_NS = 500_000  # 0.5 ms
POLICY_EVAL_SIMPLE_MAX_NS = 500_000  # 0.5 ms
POLICY_EVAL_COMPLEX_MAX_NS = 2_000_000  # 2 ms
POLICY_CREATION_MAX_NS = 1_000_000  # 1 ms
INTERCEPTOR_MAX_NS = 500_000  # 0.5 ms
ADAPTER_CONTEXT_MAX_NS = 1_000_000  # 1 ms
AUDIT_APPEND_MAX_NS = 500_000  # 0.5 ms
CONCURRENT_MAX_NS = 5_000_000  # 5 ms per op under contention


def _ns_to_us(ns: float) -> float:
    return ns / 1_000


def _ns_to_ms(ns: float) -> float:
    return ns / 1_000_000


def _print_table(rows: List[tuple]) -> None:
    """Print a formatted results table."""
    header = ("Benchmark", "Iterations", "Avg (µs)", "Min (µs)", "Max (µs)", "P99 (µs)")
    widths = [max(len(str(r[i])) for r in [header] + rows) for i in range(len(header))]
    fmt = "  ".join(f"{{:<{w}}}" for w in widths)
    sep = "  ".join("-" * w for w in widths)
    print()
    print(fmt.format(*header))
    print(sep)
    for row in rows:
        print(fmt.format(*row))
    print()


def _stats(timings_ns: List[int]) -> Dict[str, float]:
    """Compute stats from a list of nanosecond timings."""
    timings_ns.sort()
    n = len(timings_ns)
    return {
        "avg": sum(timings_ns) / n,
        "min": timings_ns[0],
        "max": timings_ns[-1],
        "p99": timings_ns[min(int(n * 0.99), n - 1)],
    }


def _row(name: str, iterations: int, stats: Dict[str, float]) -> tuple:
    return (
        name,
        iterations,
        f"{_ns_to_us(stats['avg']):.1f}",
        f"{_ns_to_us(stats['min']):.1f}",
        f"{_ns_to_us(stats['max']):.1f}",
        f"{_ns_to_us(stats['p99']):.1f}",
    )


# ---------------------------------------------------------------------------
# Stub adapter for benchmarking BaseIntegration wrap/unwrap
# ---------------------------------------------------------------------------

class _StubIntegration:
    """Minimal integration stub for benchmarking wrap/unwrap overhead."""

    def __init__(self, policy: Optional[GovernancePolicy] = None) -> None:
        self.policy = policy or GovernancePolicy()
        self.contexts: Dict[str, GovExecutionContext] = {}

    def wrap(self, agent: Any) -> Any:
        return {"governed": True, "agent": agent}

    def unwrap(self, governed_agent: Any) -> Any:
        return governed_agent.get("agent", governed_agent)

    def create_context(self, agent_id: str) -> GovExecutionContext:
        from uuid import uuid4

        ctx = GovExecutionContext(
            agent_id=agent_id,
            session_id=str(uuid4())[:8],
            policy=self.policy,
        )
        self.contexts[agent_id] = ctx
        return ctx


# ---------------------------------------------------------------------------
# Stub agent for audit log benchmarking
# ---------------------------------------------------------------------------

class _BenchAgent(BaseAgent):
    async def run(self, *args: Any, **kwargs: Any) -> ExecutionResult:
        return await self._execute("bench_action", {"key": "value"})


# ===========================================================================
# 1. Kernel Benchmarks
# ===========================================================================


@pytest.mark.benchmark
class TestKernelBenchmarks:
    """Measure StatelessKernel execute() latency and MemoryBackend throughput."""

    async def test_kernel_execute_latency(self) -> None:
        """Measure StatelessKernel.execute() latency over 1000 iterations."""
        kernel = StatelessKernel()
        ctx = ExecutionContext(agent_id="bench-agent", policies=[])
        timings: List[int] = []

        for _ in range(ITERATIONS_KERNEL):
            start = time.perf_counter_ns()
            await kernel.execute("noop", {}, ctx)
            timings.append(time.perf_counter_ns() - start)

        s = _stats(timings)
        _print_table([_row("kernel.execute()", ITERATIONS_KERNEL, s)])
        assert s["avg"] < KERNEL_EXECUTE_MAX_NS, (
            f"Kernel execute avg {_ns_to_ms(s['avg']):.3f}ms exceeds 1ms threshold"
        )

    async def test_memory_backend_get_set_throughput(self) -> None:
        """Measure MemoryBackend get/set throughput."""
        backend = MemoryBackend()
        set_timings: List[int] = []
        get_timings: List[int] = []

        for i in range(ITERATIONS_KERNEL):
            key = f"key-{i}"
            value = {"data": i, "payload": "x" * 100}

            start = time.perf_counter_ns()
            await backend.set(key, value)
            set_timings.append(time.perf_counter_ns() - start)

            start = time.perf_counter_ns()
            await backend.get(key)
            get_timings.append(time.perf_counter_ns() - start)

        s_set = _stats(set_timings)
        s_get = _stats(get_timings)
        _print_table([
            _row("MemoryBackend.set()", ITERATIONS_KERNEL, s_set),
            _row("MemoryBackend.get()", ITERATIONS_KERNEL, s_get),
        ])
        assert s_set["avg"] < MEMORY_BACKEND_OP_MAX_NS, (
            f"MemoryBackend.set avg {_ns_to_us(s_set['avg']):.1f}µs exceeds threshold"
        )
        assert s_get["avg"] < MEMORY_BACKEND_OP_MAX_NS, (
            f"MemoryBackend.get avg {_ns_to_us(s_get['avg']):.1f}µs exceeds threshold"
        )

    async def test_kernel_execute_under_1ms(self) -> None:
        """Assert kernel execute overhead stays under 1ms."""
        kernel = StatelessKernel()
        ctx = ExecutionContext(agent_id="bench-agent", policies=["read_only"])
        timings: List[int] = []

        for _ in range(ITERATIONS_KERNEL):
            start = time.perf_counter_ns()
            await kernel.execute("database_query", {"query": "SELECT 1"}, ctx)
            timings.append(time.perf_counter_ns() - start)

        s = _stats(timings)
        assert s["avg"] < KERNEL_EXECUTE_MAX_NS, (
            f"Kernel execute avg {_ns_to_ms(s['avg']):.3f}ms exceeds 1ms overhead budget"
        )


# ===========================================================================
# 2. Policy Enforcement Benchmarks
# ===========================================================================


@pytest.mark.benchmark
class TestPolicyBenchmarks:
    """Measure policy evaluation, creation, and interceptor overhead."""

    def test_simple_policy_evaluation(self) -> None:
        """Measure policy evaluation time for a simple policy."""
        policy = GovernancePolicy()
        timings: List[int] = []

        for _ in range(ITERATIONS_POLICY):
            start = time.perf_counter_ns()
            policy.matches_pattern("some harmless input text")
            timings.append(time.perf_counter_ns() - start)

        s = _stats(timings)
        _print_table([_row("policy.matches_pattern(simple)", ITERATIONS_POLICY, s)])
        assert s["avg"] < POLICY_EVAL_SIMPLE_MAX_NS, (
            f"Simple policy eval avg {_ns_to_us(s['avg']):.1f}µs exceeds threshold"
        )

    def test_complex_policy_evaluation(self) -> None:
        """Measure policy evaluation time for a complex policy with many patterns."""
        policy = GovernancePolicy(
            blocked_patterns=[
                "password",
                "secret",
                "api_key",
                ("rm\\s+-rf", PatternType.REGEX),
                ("sudo\\s+.*", PatternType.REGEX),
                ("\\d{3}-\\d{2}-\\d{4}", PatternType.REGEX),
                ("*.exe", PatternType.GLOB),
                ("*.sh", PatternType.GLOB),
                "credit_card",
                "ssn",
            ],
        )
        timings: List[int] = []

        for _ in range(ITERATIONS_POLICY):
            start = time.perf_counter_ns()
            policy.matches_pattern(
                "This is a long input string with various content that needs to "
                "be checked against multiple patterns including regex and glob types."
            )
            timings.append(time.perf_counter_ns() - start)

        s = _stats(timings)
        _print_table([_row("policy.matches_pattern(complex)", ITERATIONS_POLICY, s)])
        assert s["avg"] < POLICY_EVAL_COMPLEX_MAX_NS, (
            f"Complex policy eval avg {_ns_to_us(s['avg']):.1f}µs exceeds threshold"
        )

    def test_governance_policy_creation(self) -> None:
        """Measure GovernancePolicy creation time."""
        timings: List[int] = []

        for _ in range(ITERATIONS_POLICY):
            start = time.perf_counter_ns()
            GovernancePolicy(
                name="bench-policy",
                max_tokens=2048,
                max_tool_calls=5,
                allowed_tools=["read_file", "search"],
                blocked_patterns=["password", ("rm\\s+-rf", PatternType.REGEX)],
                confidence_threshold=0.9,
            )
            timings.append(time.perf_counter_ns() - start)

        s = _stats(timings)
        _print_table([_row("GovernancePolicy()", ITERATIONS_POLICY, s)])
        assert s["avg"] < POLICY_CREATION_MAX_NS, (
            f"Policy creation avg {_ns_to_us(s['avg']):.1f}µs exceeds threshold"
        )

    def test_policy_interceptor_overhead(self) -> None:
        """Benchmark PolicyInterceptor overhead per call."""
        policy = GovernancePolicy(
            allowed_tools=["read_file", "search", "query"],
            blocked_patterns=["password", "secret"],
        )
        interceptor = PolicyInterceptor(policy)
        request = ToolCallRequest(
            tool_name="read_file",
            arguments={"path": "/tmp/data.txt"},
            call_id="bench-001",
            agent_id="bench-agent",
        )
        timings: List[int] = []

        for _ in range(ITERATIONS_POLICY):
            start = time.perf_counter_ns()
            interceptor.intercept(request)
            timings.append(time.perf_counter_ns() - start)

        s = _stats(timings)
        _print_table([_row("PolicyInterceptor.intercept()", ITERATIONS_POLICY, s)])
        assert s["avg"] < INTERCEPTOR_MAX_NS, (
            f"Interceptor avg {_ns_to_us(s['avg']):.1f}µs exceeds threshold"
        )


# ===========================================================================
# 3. Adapter Benchmarks
# ===========================================================================


@pytest.mark.benchmark
class TestAdapterBenchmarks:
    """Measure adapter wrap/unwrap, audit log, and context creation overhead."""

    def test_adapter_wrap_unwrap(self) -> None:
        """Measure adapter wrap/unwrap overhead with a mocked backend."""
        integration = _StubIntegration()
        agent = {"name": "test-agent", "type": "analyzer"}
        timings_wrap: List[int] = []
        timings_unwrap: List[int] = []

        for _ in range(ITERATIONS_ADAPTER):
            start = time.perf_counter_ns()
            governed = integration.wrap(agent)
            timings_wrap.append(time.perf_counter_ns() - start)

            start = time.perf_counter_ns()
            integration.unwrap(governed)
            timings_unwrap.append(time.perf_counter_ns() - start)

        s_wrap = _stats(timings_wrap)
        s_unwrap = _stats(timings_unwrap)
        _print_table([
            _row("adapter.wrap()", ITERATIONS_ADAPTER, s_wrap),
            _row("adapter.unwrap()", ITERATIONS_ADAPTER, s_unwrap),
        ])
        assert s_wrap["avg"] < ADAPTER_CONTEXT_MAX_NS
        assert s_unwrap["avg"] < ADAPTER_CONTEXT_MAX_NS

    async def test_audit_log_append_and_rotation(self) -> None:
        """Benchmark audit log append + rotation performance."""
        config = AgentConfig(agent_id="bench-agent", max_audit_log_size=500)
        agent = _BenchAgent(config)
        timings: List[int] = []

        for _ in range(ITERATIONS_ADAPTER):
            start = time.perf_counter_ns()
            await agent._execute("bench_action", {"key": "value"})
            timings.append(time.perf_counter_ns() - start)

        s = _stats(timings)
        _print_table([_row("audit_log.append+rotate", ITERATIONS_ADAPTER, s)])
        assert s["avg"] < AUDIT_APPEND_MAX_NS, (
            f"Audit append avg {_ns_to_us(s['avg']):.1f}µs exceeds threshold"
        )
        # Verify rotation happened: log should be at most max_audit_log_size
        assert len(agent._audit_log) <= config.max_audit_log_size

    def test_context_creation_overhead(self) -> None:
        """Measure context creation overhead."""
        integration = _StubIntegration()
        timings: List[int] = []

        for i in range(ITERATIONS_ADAPTER):
            start = time.perf_counter_ns()
            integration.create_context(f"agent-{i}")
            timings.append(time.perf_counter_ns() - start)

        s = _stats(timings)
        _print_table([_row("create_context()", ITERATIONS_ADAPTER, s)])
        assert s["avg"] < ADAPTER_CONTEXT_MAX_NS, (
            f"Context creation avg {_ns_to_us(s['avg']):.1f}µs exceeds threshold"
        )


# ===========================================================================
# 4. Concurrency Benchmarks
# ===========================================================================


@pytest.mark.benchmark
class TestConcurrencyBenchmarks:
    """Measure concurrent kernel operations and verify no degradation."""

    async def test_concurrent_kernel_operations(self) -> None:
        """Measure concurrent kernel operations with 100 async tasks."""
        kernel = StatelessKernel()
        timings: List[int] = []
        lock = asyncio.Lock()

        async def _task(task_id: int) -> None:
            ctx = ExecutionContext(agent_id=f"agent-{task_id}", policies=[])
            start = time.perf_counter_ns()
            await kernel.execute("query", {"id": task_id}, ctx)
            elapsed = time.perf_counter_ns() - start
            async with lock:
                timings.append(elapsed)

        await asyncio.gather(*[_task(i) for i in range(CONCURRENT_TASKS)])

        s = _stats(timings)
        _print_table([_row("concurrent.execute(100)", CONCURRENT_TASKS, s)])
        assert len(timings) == CONCURRENT_TASKS
        assert s["avg"] < CONCURRENT_MAX_NS, (
            f"Concurrent avg {_ns_to_us(s['avg']):.1f}µs exceeds threshold"
        )

    async def test_no_degradation_under_contention(self) -> None:
        """Verify no performance degradation under contention vs sequential."""
        kernel = StatelessKernel()
        ctx = ExecutionContext(agent_id="bench-agent", policies=[])

        # Sequential baseline
        seq_timings: List[int] = []
        for _ in range(CONCURRENT_TASKS):
            start = time.perf_counter_ns()
            await kernel.execute("query", {}, ctx)
            seq_timings.append(time.perf_counter_ns() - start)

        seq_avg = sum(seq_timings) / len(seq_timings)

        # Concurrent run
        conc_timings: List[int] = []
        lock = asyncio.Lock()

        async def _task(task_id: int) -> None:
            task_ctx = ExecutionContext(agent_id=f"agent-{task_id}", policies=[])
            start = time.perf_counter_ns()
            await kernel.execute("query", {}, task_ctx)
            elapsed = time.perf_counter_ns() - start
            async with lock:
                conc_timings.append(elapsed)

        await asyncio.gather(*[_task(i) for i in range(CONCURRENT_TASKS)])

        conc_avg = sum(conc_timings) / len(conc_timings)

        s_seq = _stats(seq_timings)
        s_conc = _stats(conc_timings)
        _print_table([
            _row("sequential.execute()", CONCURRENT_TASKS, s_seq),
            _row("concurrent.execute()", CONCURRENT_TASKS, s_conc),
        ])

        # Allow up to 10x degradation under contention (generous for CI)
        degradation_factor = conc_avg / seq_avg if seq_avg > 0 else 1.0
        assert degradation_factor < 10.0, (
            f"Concurrent degradation {degradation_factor:.1f}x exceeds 10x limit"
        )
