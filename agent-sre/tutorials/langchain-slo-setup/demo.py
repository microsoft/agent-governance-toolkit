# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Tutorial: Set up SLOs for a LangChain Agent
============================================

Runnable demo — no API keys required.

This script simulates a LangChain RAG agent monitored by Agent SRE.
It defines SLOs for latency, success rate, tool accuracy, cost, and
hallucination rate, runs 100 simulated calls, and prints an SLO
compliance report with error-budget status and per-call violations.

Run:
    pip install agent-sre
    python demo.py
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
from agent_sre.slo.objectives import ExhaustionAction, SLOStatus
from agent_sre.slo.dashboard import SLODashboard
from agent_sre.integrations.langchain.callback import AgentSRECallback

# ── Step 1: Mock LangChain agent ───────────────────────────────────────
# In production you would import from langchain and create a real agent.
# Here we simulate the callback lifecycle so the demo runs without keys.


class MockLangChainAgent:
    """Simulates a LangChain RAG agent with realistic response patterns."""

    QUERIES = [
        "What are Python 3.12's key features?",
        "How does vector search work in RAG?",
        "Explain Kubernetes pod autoscaling.",
        "What is the CAP theorem?",
        "How do transformers work in NLP?",
    ]

    def __init__(self, callback: AgentSRECallback) -> None:
        self.callback = callback

    def run(self, query: str) -> dict:
        """Execute one agent task and return metrics."""
        # Notify callback of LLM start
        self.callback.on_llm_start(
            serialized={"name": "gpt-4o-mini"},
            prompts=[f"Answer: {query}"],
        )

        latency_ms = random.gauss(2000, 800)
        latency_ms = max(200, latency_ms)
        time.sleep(0.005)  # brief pause for realism

        succeeded = random.random() < 0.93
        if not succeeded:
            self.callback.on_llm_error(error=Exception("Rate limit exceeded"))
            return {
                "success": False,
                "response": "",
                "latency_ms": latency_ms,
                "cost_usd": random.uniform(0.01, 0.05),
                "tool_correct": None,
                "hallucinated": False,
            }

        # Simulate LLM response
        class _Gen:
            def __init__(self):
                self.text = f"Answer to: {query}"
                self.generation_info = {
                    "token_usage": {
                        "prompt_tokens": random.randint(100, 400),
                        "completion_tokens": random.randint(50, 250),
                    }
                }

        class _Resp:
            def __init__(self):
                self.generations = [[_Gen()]]

        self.callback.on_llm_end(response=_Resp())

        # Simulate tool call
        tool_correct = random.random() < 0.96
        self.callback.on_tool_start(
            serialized={"name": "vector_search"},
            input_str=query,
        )
        if tool_correct:
            self.callback.on_tool_end(output="Found 5 relevant documents")
        else:
            self.callback.on_tool_error(error=Exception("Index timeout"))

        return {
            "success": True,
            "response": f"Answer to: {query}",
            "latency_ms": latency_ms,
            "cost_usd": random.uniform(0.02, 0.12),
            "tool_correct": tool_correct,
            "hallucinated": random.random() < 0.07,
        }


# ── Step 2: Define SLOs ───────────────────────────────────────────────

success_rate = TaskSuccessRate(target=0.95, window="24h")
latency_sli = ResponseLatency(target_ms=5000.0, percentile=0.95, window="1h")
tool_accuracy = ToolCallAccuracy(target=0.98, window="24h")
cost_sli = CostPerTask(target_usd=0.50, window="24h")
hallucination = HallucinationRate(target=0.05, window="24h")

budget = ErrorBudget(
    total=0.05,
    burn_rate_alert=2.0,
    burn_rate_critical=10.0,
    exhaustion_action=ExhaustionAction.FREEZE_DEPLOYMENTS,
)

slo = SLO(
    name="langchain-rag-agent",
    description="Production RAG agent reliability targets",
    indicators=[success_rate, latency_sli, tool_accuracy, cost_sli, hallucination],
    error_budget=budget,
)

# ── Step 3: Attach Agent SRE monitoring ────────────────────────────────

dashboard = SLODashboard()
dashboard.register_slo(slo)

sre_callback = AgentSRECallback()
agent = MockLangChainAgent(callback=sre_callback)

# ── Step 4: Run 100 simulated calls ───────────────────────────────────

NUM_CALLS = 100
violations: list[dict] = []

print("=" * 62)
print("  Tutorial: Set up SLOs for a LangChain Agent")
print("=" * 62)
print()

random.seed(42)  # reproducible results

for i in range(NUM_CALLS):
    query = random.choice(MockLangChainAgent.QUERIES)
    result = agent.run(query)

    # Record SLIs
    success_rate.record_task(success=result["success"])
    latency_sli.record_latency(result["latency_ms"])
    cost_sli.record_cost(cost_usd=result["cost_usd"])
    hallucination.record_evaluation(hallucinated=result["hallucinated"])
    if result["tool_correct"] is not None:
        tool_accuracy.record_call(correct=result["tool_correct"])

    slo.record_event(
        good=result["success"]
        and not result["hallucinated"]
        and result.get("tool_correct", True)
    )

    # Track per-call violations
    call_violations = []
    if not result["success"]:
        call_violations.append("task_failure")
    if result["latency_ms"] > 5000:
        call_violations.append(f"latency={result['latency_ms']:.0f}ms")
    if result["cost_usd"] > 0.50:
        call_violations.append(f"cost=${result['cost_usd']:.2f}")
    if result["hallucinated"]:
        call_violations.append("hallucination")
    if result["tool_correct"] is False:
        call_violations.append("tool_error")

    if call_violations:
        violations.append({"call": i + 1, "query": query, "issues": call_violations})

    if (i + 1) % 25 == 0:
        print(f"  ▸ Processed {i + 1}/{NUM_CALLS} calls...")

# ── Step 5: SLO compliance report ─────────────────────────────────────

print()
print("─" * 62)
print("  SLO Compliance Report")
print("─" * 62)
print()

status = slo.evaluate()
print(f"  SLO:    {slo.name}")
print(f"  Status: {status.value.upper()}")
print()

print("  Indicator Results:")
for ind in slo.indicators:
    val = ind.current_value()
    comp = ind.compliance()
    if val is not None and comp is not None:
        ok = "✅" if comp >= ind.target else "❌"
        print(f"    {ok} {ind.name:<22} value={val:.3f}  target={ind.target}  compliance={comp:.1%}")
print()

# ── Step 6: Error budget status ───────────────────────────────────────

print("─" * 62)
print("  Error Budget Status")
print("─" * 62)
print()
print(f"  Total Budget:     {budget.total:.0%}")
print(f"  Remaining:        {slo.error_budget.remaining_percent:.1f}%")
print(f"  Exhausted:        {slo.error_budget.is_exhausted}")
print(f"  Burn Rate (1h):   {slo.error_budget.burn_rate(3600):.1f}×")
print()

# Alerts
firing = slo.error_budget.firing_alerts()
if firing:
    print("  Firing Alerts:")
    for alert in firing:
        print(f"    🔔 {alert.severity.upper()}: {alert.name} (burn rate {alert.rate:.1f}×)")
else:
    print("  ✅ No alerts firing")

if status == SLOStatus.EXHAUSTED:
    print(f"\n  🚨 Error budget exhausted — action: {budget.exhaustion_action.value}")
elif status in (SLOStatus.CRITICAL, SLOStatus.WARNING):
    print(f"\n  ⚠️  SLO at risk — consider throttling traffic or rolling back")
print()

# ── Calls that violated SLOs ──────────────────────────────────────────

print("─" * 62)
print(f"  Calls with SLO Violations ({len(violations)}/{NUM_CALLS})")
print("─" * 62)
print()
for v in violations[:15]:
    issues = ", ".join(v["issues"])
    print(f"  Call #{v['call']:>3}: [{issues}]  query={v['query'][:40]}")
if len(violations) > 15:
    print(f"  ... and {len(violations) - 15} more")

# Dashboard snapshot
dashboard.take_snapshot()
health = dashboard.health_summary()
print()
print("─" * 62)
print("  Dashboard Summary")
print("─" * 62)
print(f"  Total SLOs tracked: {health['total_slos']}")
for name, s in health.get("slos", {}).items():
    print(f"    {name}: {s}")

print()
print("─" * 62)
print("  Done! See README.md for the full tutorial.")
print("─" * 62)
