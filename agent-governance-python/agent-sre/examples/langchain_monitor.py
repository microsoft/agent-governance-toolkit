# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Agent-SRE + LangChain — Monitor a LangChain agent with SLOs.

Demonstrates how Agent-SRE's LangChain callback handler instruments
a LangChain agent with automatic SLI collection, cost tracking,
and SLO evaluation — zero configuration required.

Run:
    pip install agent-sre
    python examples/langchain_monitor.py

Note: This example uses mocked LangChain components so it runs
without any LangChain or LLM API dependency.
"""

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


# ── 1. Set up Agent-SRE monitoring ──────────────────────────────────────

# SLI indicators
success_rate = TaskSuccessRate(target=0.90, window="24h")
latency = ResponseLatency(target_ms=10000.0, window="1h")
cost = CostPerTask(target_usd=1.00, window="24h")
tool_accuracy = ToolCallAccuracy(target=0.95, window="24h")
hallucination = HallucinationRate(target=0.05, window="24h")

# SLO definition
slo = SLO(
    name="langchain-rag-agent",
    description="Production RAG agent reliability targets",
    indicators=[success_rate, latency, cost, tool_accuracy, hallucination],
    error_budget=ErrorBudget(total=0.10, burn_rate_critical=10.0),
)

# Dashboard
dashboard = SLODashboard()
dashboard.register_slo(slo)

# LangChain callback handler (would be passed to LangChain as: callbacks=[sre_callback])
sre_callback = AgentSRECallback()

# LLM-as-Judge evaluator (rules-based for this demo)
judge = RulesJudge()
evaluator = EvaluationEngine(judge)
eval_suite = EvalSuite.rag()

# ── 2. Simulate LangChain agent tasks ──────────────────────────────────

TASKS = [
    {
        "query": "What are the key features of Python 3.12?",
        "context": "Python 3.12 features include improved error messages, faster CPython, and new typing features.",
        "reference": "Python 3.12 has improved error messages, faster CPython, and typing enhancements.",
    },
    {
        "query": "How does vector search work in RAG systems?",
        "context": "RAG uses vector embeddings to find relevant documents, then feeds them to an LLM.",
        "reference": "Vector search converts text to embeddings and finds nearest neighbors for retrieval.",
    },
    {
        "query": "Explain Kubernetes pod autoscaling",
        "context": "HPA adjusts replicas based on CPU/memory. VPA adjusts resource requests.",
        "reference": "Kubernetes HPA scales pod count, VPA scales resource requests based on metrics.",
    },
    {
        "query": "What is the CAP theorem?",
        "context": "CAP states distributed systems can have at most 2 of: Consistency, Availability, Partition tolerance.",
        "reference": "CAP theorem: choose 2 of consistency, availability, and partition tolerance.",
    },
    {
        "query": "How do transformers work in NLP?",
        "context": "Transformers use self-attention to process sequences in parallel, unlike RNNs.",
        "reference": "Transformers use self-attention mechanisms for parallel sequence processing.",
    },
]


def simulate_langchain_task(task: dict) -> dict:
    """Simulate a LangChain RAG agent processing a task."""

    # --- LLM call (simulated) ---
    sre_callback.on_llm_start(
        serialized={"name": "gpt-4"},
        prompts=[f"Context: {task['context']}\n\nQuestion: {task['query']}"],
    )

    latency_ms = random.uniform(200, 3000)
    time.sleep(0.01)  # Brief pause for realism

    # Simulate token usage
    class FakeGeneration:
        def __init__(self, text):
            self.text = text
            self.generation_info = {
                "token_usage": {
                    "prompt_tokens": random.randint(100, 500),
                    "completion_tokens": random.randint(50, 300),
                }
            }

    class FakeResponse:
        def __init__(self, text):
            self.generations = [[FakeGeneration(text)]]

    # Simulate occasional failures
    succeeded = random.random() < 0.92
    if not succeeded:
        sre_callback.on_llm_error(error=Exception("Rate limit exceeded"))
        return {"success": False, "response": "", "latency_ms": latency_ms}

    response_text = task["reference"] + " Additionally, this is a well-established concept."
    sre_callback.on_llm_end(response=FakeResponse(response_text))

    # --- Tool call (simulated) ---
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


# ── 3. Run the simulation ──────────────────────────────────────────────

print("Agent-SRE + LangChain Monitoring Demo")
print("=" * 60)
print()

num_tasks = 50
for i in range(num_tasks):
    task = random.choice(TASKS)
    result = simulate_langchain_task(task)

    # Record into SLIs
    success_rate.record_task(success=result["success"])
    latency.record_latency(result["latency_ms"])
    cost.record_cost(random.uniform(0.01, 0.15))
    slo.record_event(good=result["success"])

    if result.get("tool_correct") is not None:
        tool_accuracy.record_call(correct=result["tool_correct"])

    # Run LLM-as-Judge evaluation
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
        # Feed hallucination eval into SLI
        hallu_results = [r for r in eval_result.results if r.criterion.value == "hallucination"]
        if hallu_results:
            hallucination.record_evaluation(
                hallucinated=(hallu_results[0].score < 0.7)
            )

    if (i + 1) % 10 == 0:
        print(f"  Processed {i + 1}/{num_tasks} tasks...")

# ── 4. Report results ──────────────────────────────────────────────────

print()
print("SLO Report")
print("─" * 60)

status = slo.evaluate()
print(f"  Status:           {status.value.upper()}")
print(f"  Error Budget:     {slo.error_budget.remaining_percent:.1f}% remaining")
print()

print("SLI Values:")
for ind in slo.indicators:
    val = ind.current_value()
    comp = ind.compliance()
    if val is not None:
        label = "✅" if comp and comp >= 0.5 else "❌"
        print(f"  {label} {ind.name}: {val:.3f} (target: {ind.target})")

print()

# LangChain callback stats
snapshot = sre_callback.get_sli_snapshot()
print("LangChain Callback Metrics:")
print(f"  Task Success Rate: {snapshot.get('task_success_rate', 0):.1%}")
print(f"  Tool Accuracy:     {snapshot.get('tool_accuracy', 0):.1%}")
print(f"  Avg Latency:       {snapshot.get('avg_latency_ms', 0):.0f} ms")
print(f"  Total Cost:        ${snapshot.get('total_cost_usd', 0):.4f}")

print()

# Evaluation stats
eval_stats = evaluator.get_stats()
print("LLM-as-Judge Evaluation:")
print(f"  Evaluations Run:   {eval_stats['total_evaluations']}")
print(f"  Pass Rate:         {eval_stats['pass_rate']:.1%}")
print(f"  Avg Score:         {eval_stats['avg_score']:.3f}")
for criterion, score in eval_stats.get("by_criterion", {}).items():
    print(f"    {criterion}: {score:.3f}")

print()

# Dashboard snapshot
dashboard.take_snapshot()
health = dashboard.health_summary()
print("Dashboard Health:")
print(f"  Total SLOs: {health['total_slos']}")
for name, status_val in health.get("slos", {}).items():
    print(f"    {name}: {status_val}")

print()
print("─" * 60)
print("This demo shows Agent-SRE monitoring a LangChain RAG agent")
print("with SLOs, cost tracking, and LLM-as-Judge evaluation.")
