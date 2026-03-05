# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Benchmarks for integration adapters — GovernancePolicy overhead."""

from __future__ import annotations

import time
from typing import Any, Dict, List

from agent_os.integrations.base import GovernancePolicy, PatternType


def _sync_timer(func, iterations: int = 10_000) -> Dict[str, Any]:
    """Run a synchronous function *iterations* times and return latency stats."""
    latencies: List[float] = []
    for _ in range(iterations):
        start = time.perf_counter()
        func()
        latencies.append((time.perf_counter() - start) * 1_000)
    latencies.sort()
    total_seconds = sum(latencies) / 1_000
    return {
        "iterations": iterations,
        "total_seconds": round(total_seconds, 4),
        "ops_per_sec": round(iterations / total_seconds) if total_seconds > 0 else 0,
        "p50_ms": round(latencies[len(latencies) // 2], 4),
        "p95_ms": round(latencies[int(len(latencies) * 0.95)], 4),
        "p99_ms": round(latencies[int(len(latencies) * 0.99)], 4),
    }


def _make_adapter_policy(name: str) -> GovernancePolicy:
    """Create a representative GovernancePolicy for adapter benchmarks."""
    return GovernancePolicy(
        name=name,
        max_tokens=4096,
        max_tool_calls=10,
        allowed_tools=["read_file", "web_search", "database_query"],
        blocked_patterns=[
            "password",
            ("rm\\s+-rf", PatternType.REGEX),
            ("*.exe", PatternType.GLOB),
        ],
        confidence_threshold=0.85,
    )


def bench_policy_init(iterations: int = 5_000) -> Dict[str, Any]:
    """Benchmark GovernancePolicy initialization (adapter startup cost)."""

    def init() -> None:
        GovernancePolicy(
            name="bench",
            max_tokens=4096,
            max_tool_calls=10,
            allowed_tools=["read_file", "web_search"],
            blocked_patterns=[
                "password",
                ("rm\\s+-rf", PatternType.REGEX),
            ],
        )

    return {"name": "Adapter Init (GovernancePolicy)", **_sync_timer(init, iterations)}


def bench_policy_check_tool_allowed(iterations: int = 10_000) -> Dict[str, Any]:
    """Benchmark checking if a tool is in the allowed list."""
    policy = _make_adapter_policy("openai")

    def check() -> None:
        tool = "web_search"
        _ = not policy.allowed_tools or tool in policy.allowed_tools

    return {"name": "Tool Allowed Check", **_sync_timer(check, iterations)}


def bench_policy_pattern_match(iterations: int = 10_000) -> Dict[str, Any]:
    """Benchmark blocked pattern matching against tool arguments."""
    policy = _make_adapter_policy("langchain")
    test_input = "Please search for user data in the production database"

    def check() -> None:
        for pat_str, pat_type, compiled in policy._compiled_patterns:
            if pat_type == PatternType.SUBSTRING:
                _ = pat_str.lower() in test_input.lower()
            elif compiled:
                _ = compiled.search(test_input)

    return {"name": "Pattern Match (per call)", **_sync_timer(check, iterations)}


def bench_governance_overhead_per_adapter(iterations: int = 5_000) -> List[Dict[str, Any]]:
    """Benchmark full governance overhead for each adapter type."""
    adapter_names = [
        "OpenAI",
        "LangChain",
        "Anthropic",
        "LlamaIndex",
        "CrewAI",
        "AutoGen",
        "Gemini",
        "Mistral",
        "SemanticKernel",
    ]
    results = []
    for name in adapter_names:
        policy = _make_adapter_policy(name.lower())
        tool_name = "web_search"
        tool_args = "Search for recent news about governance frameworks"

        def full_check() -> None:
            # Simulate the governance check path adapters use
            _ = not policy.allowed_tools or tool_name in policy.allowed_tools
            for pat_str, pat_type, compiled in policy._compiled_patterns:
                if pat_type == PatternType.SUBSTRING:
                    _ = pat_str.lower() in tool_args.lower()
                elif compiled:
                    _ = compiled.search(tool_args)

        stats = _sync_timer(full_check, iterations)
        results.append({"name": f"Adapter Overhead ({name})", **stats})
    return results


def run_all() -> List[Dict[str, Any]]:
    """Run all adapter benchmarks and return results."""
    results = [
        bench_policy_init(),
        bench_policy_check_tool_allowed(),
        bench_policy_pattern_match(),
    ]
    results.extend(bench_governance_overhead_per_adapter())
    return results


if __name__ == "__main__":
    import json

    for result in run_all():
        print(json.dumps(result, indent=2))
