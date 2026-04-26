#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Agent-SRE + LangChain Monitoring Demo
======================================

Demonstrates Agent-SRE's LangChain callback handler for monitoring
agent reliability with SLI collection and SLO compliance — no API
keys required.

Run:
    pip install agent-sre
    python demo.py
"""

from __future__ import annotations

import random
import time

from agent_sre import SLO, ErrorBudget
from agent_sre.slo.indicators import (
    CostPerTask,
    HallucinationRate,
    ResponseLatency,
    TaskSuccessRate,
    ToolCallAccuracy,
)
from agent_sre.slo.dashboard import SLODashboard
from agent_sre.integrations.langchain.callback import AgentSRECallback
from agent_sre.evals import EvalInput, EvaluationEngine, EvalSuite, RulesJudge

# ── 1. Configure Agent-SRE monitoring ──────────────────────────────────

# SLI indicators
success_rate = TaskSuccessRate(target=0.90, window="24h")
latency_sli = ResponseLatency(target_ms=10_000.0, window="1h")
cost_sli = CostPerTask(target_usd=1.00, window="24h")
tool_accuracy = ToolCallAccuracy(target=0.95, window="24h")
hallucination = HallucinationRate(target=0.05, window="24h")

# SLO with error budget
slo = SLO(
    name="langchain-rag-agent",
    description="Production RAG agent reliability targets",
    indicators=[success_rate, latency_sli, cost_sli, tool_accuracy, hallucination],
    error_budget=ErrorBudget(total=0.10, burn_rate_critical=10.0),
)

# Dashboard
dashboard = SLODashboard()
dashboard.register_slo(slo)

# LangChain callback handler
sre_callback = AgentSRECallback(
    cost_per_1k_input=0.003,
    cost_per_1k_output=0.015,
)

# LLM-as-Judge evaluator (rules-based — no LLM needed)
judge = RulesJudge()
evaluator = EvaluationEngine(judge)
eval_suite = EvalSuite.rag()


# ── 2. Mock LangChain agent ───────────────────────────────────────────

TASKS = [
    {
        "query": "What are the key features of Python 3.12?",
        "context": "Python 3.12 features include improved error messages, "
        "faster CPython, and new typing features.",
        "reference": "Python 3.12 has improved error messages, faster CPython, "
        "and typing enhancements.",
    },
    {
        "query": "How does vector search work in RAG systems?",
        "context": "RAG uses vector embeddings to find relevant documents, "
        "then feeds them to an LLM.",
        "reference": "Vector search converts text to embeddings and finds "
        "nearest neighbors for retrieval.",
    },
    {
        "query": "Explain Kubernetes pod autoscaling",
        "context": "HPA adjusts replicas based on CPU/memory. VPA adjusts "
        "resource requests.",
        "reference": "Kubernetes HPA scales pod count, VPA scales resource "
        "requests based on metrics.",
    },
    {
        "query": "What is the CAP theorem?",
        "context": "CAP states distributed systems can have at most 2 of: "
        "Consistency, Availability, Partition tolerance.",
        "reference": "CAP theorem: choose 2 of consistency, availability, "
        "and partition tolerance.",
    },
    {
        "query": "How do transformers work in NLP?",
        "context": "Transformers use self-attention to process sequences in "
        "parallel, unlike RNNs.",
        "reference": "Transformers use self-attention mechanisms for parallel "
        "sequence processing.",
    },
]


class _FakeGeneration:
    """Mimics a LangChain Generation object."""

    def __init__(self, text: str) -> None:
        self.text = text
        self.generation_info = {
            "token_usage": {
                "prompt_tokens": random.randint(100, 500),
                "completion_tokens": random.randint(50, 300),
            }
        }


class _FakeLLMResponse:
    """Mimics a LangChain LLMResult object."""

    def __init__(self, text: str) -> None:
        self.generations = [[_FakeGeneration(text)]]


def simulate_langchain_task(task: dict) -> dict:
    """Simulate a LangChain RAG agent processing a single task.

    Drives the AgentSRECallback through the same lifecycle events that
    a real LangChain agent would trigger: on_llm_start → on_llm_end,
    on_tool_start → on_tool_end, on_chain_start → on_chain_end.
    """

    # --- LLM call ---
    sre_callback.on_llm_start(
        serialized={"name": "gpt-4"},
        prompts=[f"Context: {task['context']}\n\nQuestion: {task['query']}"],
    )

    latency_ms = random.uniform(200, 3_000)
    time.sleep(0.01)  # brief pause for realism

    # ~8 % failure rate
    succeeded = random.random() < 0.92
    if not succeeded:
        sre_callback.on_llm_error(error=Exception("Rate limit exceeded"))
        return {"success": False, "response": "", "latency_ms": latency_ms}

    response_text = task["reference"] + " Additionally, this is a well-established concept."
    sre_callback.on_llm_end(response=_FakeLLMResponse(response_text))

    # --- Tool call ---
    tool_correct = random.random() < 0.96
    sre_callback.on_tool_start(
        serialized={"name": "vector_search"},
        input_str=task["query"],
    )
    if tool_correct:
        sre_callback.on_tool_end(output="Found 5 relevant documents")
    else:
        sre_callback.on_tool_error(error=Exception("Index timeout"))

    # --- Chain completion ---
    sre_callback.on_chain_start(
        serialized={"name": "rag_chain"},
        inputs={"query": task["query"]},
    )
    sre_callback.on_chain_end(outputs={"result": response_text})

    return {
        "success": True,
        "response": response_text,
        "latency_ms": latency_ms,
        "tool_correct": tool_correct,
    }


# ── 3. Run 50 simulated calls ─────────────────────────────────────────

def main() -> None:
    print("Agent-SRE + LangChain Monitoring Demo")
    print("=" * 60)
    print()

    num_tasks = 50
    for i in range(num_tasks):
        task = random.choice(TASKS)
        result = simulate_langchain_task(task)

        # Record into SLIs
        success_rate.record_task(success=result["success"])
        latency_sli.record_latency(result["latency_ms"])
        cost_sli.record_cost(random.uniform(0.01, 0.15))
        slo.record_event(good=result["success"])

        if result.get("tool_correct") is not None:
            tool_accuracy.record_call(correct=result["tool_correct"])

        # Run LLM-as-Judge evaluation on successful responses
        if result["success"] and result["response"]:
            eval_result = evaluator.run(
                EvalInput(
                    query=task["query"],
                    response=result["response"],
                    reference=task["reference"],
                    context=task["context"],
                ),
                suite=eval_suite,
            )
            hallu_results = [
                r for r in eval_result.results if r.criterion.value == "hallucination"
            ]
            if hallu_results:
                hallucination.record_evaluation(hallucinated=(hallu_results[0].score < 0.7))

        # Real-time progress with per-task summary
        status_icon = "\u2713" if result["success"] else "\u2717"
        cost_usd = random.uniform(0.01, 0.15)
        print(
            f"  [{i + 1:>2}/{num_tasks}] {status_icon} "
            f"\"{task['query'][:50]}\" "
            f" {result['latency_ms']:>7.0f}ms"
            f"  ${cost_usd:.2f}"
            + ("" if result["success"] else "  FAILED")
        )

    # ── 4. SLO compliance report ───────────────────────────────────────

    print()
    print("SLO Compliance Report")
    print("\u2500" * 60)

    status = slo.evaluate()
    print(f"  SLO Status:         {status.value.upper()}")
    print(f"  Error Budget:       {slo.error_budget.remaining_percent:.1f}% remaining")
    print()

    print("  SLI Values:")
    for ind in slo.indicators:
        val = ind.current_value()
        comp = ind.compliance()
        if val is not None:
            label = "\u2705" if comp and comp >= 0.5 else "\u274c"
            print(f"    {label} {ind.name}: {val:.3f} (target: {ind.target})")
    print()

    # LangChain callback snapshot
    snapshot = sre_callback.get_sli_snapshot()
    print("  LangChain Callback Metrics:")
    print(f"    Task Success Rate: {snapshot.get('task_success_rate', 0):.1%}")
    print(f"    Tool Accuracy:     {snapshot.get('tool_accuracy', 0):.1%}")
    print(f"    Avg Latency:       {snapshot.get('avg_latency_ms', 0):.0f} ms")
    print(f"    Total Cost:        ${snapshot.get('total_cost_usd', 0):.4f}")
    print(f"    LLM Calls:         {snapshot.get('llm_call_count', 0)}")
    print(f"    Tool Calls:        {snapshot.get('tool_call_count', 0)}")
    print(f"    Chain Runs:        {snapshot.get('chain_count', 0)}")
    print()

    # Evaluation stats
    eval_stats = evaluator.get_stats()
    print("  LLM-as-Judge Evaluation:")
    print(f"    Evaluations Run:   {eval_stats['total_evaluations']}")
    print(f"    Pass Rate:         {eval_stats['pass_rate']:.1%}")
    print(f"    Avg Score:         {eval_stats['avg_score']:.3f}")
    for criterion, score in eval_stats.get("by_criterion", {}).items():
        print(f"      {criterion}: {score:.3f}")
    print()

    # Dashboard health
    dashboard.take_snapshot()
    health = dashboard.health_summary()
    print("  Dashboard Health:")
    print(f"    Total SLOs: {health['total_slos']}")
    for name, status_val in health.get("slos", {}).items():
        print(f"      {name}: {status_val}")

    print()
    print("\u2500" * 60)
    print("Demo complete. In production, pass AgentSRECallback to any")
    print("LangChain chain or agent via callbacks=[sre_callback].")


if __name__ == "__main__":
    main()
