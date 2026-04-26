# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Chaos Engineering Demo for a Chatbot Agent
===========================================

Simulates a chatbot agent, defines SLOs, injects chaos (latency spikes,
outages, token exhaustion, context overflow), and shows how error budgets,
burn-rate alerts, and circuit breakers respond — **no API keys required**.

Run:
    cd examples/chaos-chatbot
    python demo.py
"""

from __future__ import annotations

import random
import time

from agent_sre import SLO, ErrorBudget
from agent_sre.chaos.engine import ChaosExperiment, Fault, ResilienceScore
from agent_sre.slo.indicators import (
    CostPerTask,
    HallucinationRate,
    ResponseLatency,
    TaskSuccessRate,
)

# ── Helpers ────────────────────────────────────────────────────────────

HEADER = "\033[1;36m"  # bold cyan
OK = "\033[32m"  # green
WARN = "\033[33m"  # yellow
ERR = "\033[31m"  # red
RESET = "\033[0m"

STATUS_COLOR = {
    "healthy": OK,
    "warning": WARN,
    "critical": ERR,
    "exhausted": ERR,
    "unknown": RESET,
}


def banner(text: str) -> None:
    print(f"\n{HEADER}{'=' * 64}")
    print(f"  {text}")
    print(f"{'=' * 64}{RESET}\n")


def status_line(slo: SLO) -> None:
    status = slo.evaluate()
    color = STATUS_COLOR.get(status.value, RESET)
    budget = slo.error_budget.remaining_percent
    burn = slo.error_budget.burn_rate(3600)
    alerts = slo.error_budget.firing_alerts()
    alert_str = ", ".join(a.name for a in alerts) if alerts else "none"
    print(
        f"  SLO {color}{status.value:>10}{RESET}  "
        f"budget {budget:5.1f}%  "
        f"burn {burn:5.1f}x  "
        f"alerts: {alert_str}"
    )


def indicator_table(slo: SLO) -> None:
    for ind in slo.indicators:
        val = ind.current_value()
        comp = ind.compliance()
        if val is None:
            continue
        label = f"{OK}✅{RESET}" if (comp is not None and comp >= 0.9) else f"{ERR}❌{RESET}"
        print(f"    {label} {ind.name}: {val:.4f}  (target {ind.target:.4f})")


# ── Mock chatbot ───────────────────────────────────────────────────────


class MockChatbot:
    """Simulates an LLM-backed chatbot with injectable faults."""

    def __init__(self) -> None:
        self.base_latency_ms: float = 400.0
        self.base_error_rate: float = 0.02
        self.base_hallucination_rate: float = 0.03
        self.base_cost: float = 0.04

        # Chaos overrides
        self.extra_latency_ms: float = 0.0
        self.extra_error_rate: float = 0.0
        self.extra_hallucination_rate: float = 0.0
        self.context_overflow: bool = False

        # Circuit breaker
        self.circuit_open: bool = False
        self._consecutive_errors: int = 0
        self._cb_threshold: int = 5

    def respond(self, message: str) -> dict:
        """Process a chat message and return a result dict."""
        if self.circuit_open:
            return {
                "success": False,
                "latency_ms": 0.0,
                "cost": 0.0,
                "hallucinated": False,
                "error": "circuit_breaker_open",
            }

        # Latency
        latency = self.base_latency_ms + random.uniform(0, 200)
        latency += self.extra_latency_ms * random.uniform(0.5, 1.0)

        # Context overflow → always fails
        if self.context_overflow and random.random() < 0.6:
            self._record_error()
            return {
                "success": False,
                "latency_ms": latency,
                "cost": 0.0,
                "hallucinated": False,
                "error": "context_window_overflow",
            }

        # Error injection
        error_rate = min(1.0, self.base_error_rate + self.extra_error_rate)
        if random.random() < error_rate:
            self._record_error()
            return {
                "success": False,
                "latency_ms": latency,
                "cost": 0.0,
                "hallucinated": False,
                "error": "llm_error",
            }

        # Success path
        self._consecutive_errors = 0
        hallucinated = random.random() < (
            self.base_hallucination_rate + self.extra_hallucination_rate
        )
        cost = self.base_cost + random.uniform(0, 0.03)

        return {
            "success": True,
            "latency_ms": latency,
            "cost": cost,
            "hallucinated": hallucinated,
            "error": None,
        }

    def _record_error(self) -> None:
        self._consecutive_errors += 1
        if self._consecutive_errors >= self._cb_threshold:
            self.circuit_open = True

    def reset_chaos(self) -> None:
        self.extra_latency_ms = 0.0
        self.extra_error_rate = 0.0
        self.extra_hallucination_rate = 0.0
        self.context_overflow = False

    def reset_circuit_breaker(self) -> None:
        self.circuit_open = False
        self._consecutive_errors = 0


# ── SLO setup ──────────────────────────────────────────────────────────


def build_slo() -> tuple[SLO, TaskSuccessRate, ResponseLatency, CostPerTask, HallucinationRate]:
    success = TaskSuccessRate(target=0.95, window="1h")
    latency = ResponseLatency(target_ms=2000.0, percentile=0.95, window="1h")
    cost = CostPerTask(target_usd=0.10, window="1h")
    hallucination = HallucinationRate(target=0.05, window="1h")

    slo = SLO(
        name="chatbot-agent",
        description="Chatbot reliability targets: latency <2 s, accuracy >95%, cost <$0.10",
        indicators=[success, latency, cost, hallucination],
        error_budget=ErrorBudget(total=0.05, burn_rate_alert=2.0, burn_rate_critical=5.0),
    )
    return slo, success, latency, cost, hallucination


# ── Traffic simulation ─────────────────────────────────────────────────


def run_traffic(
    bot: MockChatbot,
    slo: SLO,
    success_sli: TaskSuccessRate,
    latency_sli: ResponseLatency,
    cost_sli: CostPerTask,
    hallucination_sli: HallucinationRate,
    n: int,
    label: str,
) -> dict:
    """Send *n* requests and record against SLIs. Returns summary stats."""
    ok = 0
    total = 0
    for i in range(n):
        result = bot.respond(f"test message {i}")
        total += 1

        succeeded = result["success"] and not result["hallucinated"]
        if result["success"]:
            ok += 1

        success_sli.record_task(success=result["success"])
        latency_sli.record_latency(result["latency_ms"])
        cost_sli.record_cost(result["cost"])
        hallucination_sli.record_evaluation(hallucinated=result["hallucinated"])
        slo.record_event(good=succeeded)

    rate = ok / total if total else 0.0
    print(f"  [{label}] {total} requests — {ok} OK ({rate:.0%})")
    status_line(slo)
    return {"total": total, "ok": ok, "rate": rate}


# ── Chaos scenarios ────────────────────────────────────────────────────


def run_chaos_scenario(
    name: str,
    bot: MockChatbot,
    slo: SLO,
    success_sli: TaskSuccessRate,
    latency_sli: ResponseLatency,
    cost_sli: CostPerTask,
    hallucination_sli: HallucinationRate,
    experiment: ChaosExperiment,
    n: int = 20,
) -> dict:
    """Inject a fault, run traffic, then reset."""
    print(f"\n  {WARN}⚡ Scenario: {name}{RESET}")
    print(f"     {experiment.description}")
    experiment.start()
    for fault in experiment.faults:
        experiment.inject_fault(fault)

    stats = run_traffic(bot, slo, success_sli, latency_sli, cost_sli, hallucination_sli, n, name)
    experiment.complete(
        ResilienceScore(overall=round(stats["rate"] * 100, 1), passed=stats["rate"] >= 0.85)
    )
    bot.reset_chaos()
    return stats


# ── Main ───────────────────────────────────────────────────────────────


def main() -> None:
    random.seed(42)
    bot = MockChatbot()
    slo, success_sli, latency_sli, cost_sli, hallucination_sli = build_slo()

    banner("Chaos Engineering Demo — Chatbot Agent")

    print("  Agent:   MockChatbot (simulated, no API keys)")
    print("  SLOs:    latency < 2 s · accuracy > 95% · cost < $0.10/call")
    print("  Budget:  5% error budget over a 30-day window")

    # ── Phase 1: Baseline ──────────────────────────────────────────────
    banner("Phase 1 · Baseline (normal traffic)")
    baseline = run_traffic(
        bot, slo, success_sli, latency_sli, cost_sli, hallucination_sli, 50, "baseline"
    )
    print()
    indicator_table(slo)

    # ── Phase 2: Chaos injection ───────────────────────────────────────
    banner("Phase 2 · Chaos Injection")

    # Scenario 1 — LLM API latency spike
    bot.extra_latency_ms = 5000.0
    exp1 = ChaosExperiment(
        name="LLM API Latency Spike",
        target_agent="chatbot-agent",
        faults=[Fault.latency_injection("llm_provider", delay_ms=5000, rate=0.7)],
        duration_seconds=300,
        description="70% of LLM calls take 3-8 s instead of ~0.5 s",
    )
    run_chaos_scenario(
        "LLM API latency spike",
        bot, slo, success_sli, latency_sli, cost_sli, hallucination_sli, exp1,
    )

    # Scenario 2 — Partial outage (50% errors)
    bot.extra_error_rate = 0.50
    exp2 = ChaosExperiment(
        name="Partial Outage",
        target_agent="chatbot-agent",
        faults=[Fault.error_injection("llm_provider", error="service_unavailable", rate=0.5)],
        duration_seconds=300,
        description="50% of LLM calls return HTTP 503 errors",
    )
    run_chaos_scenario(
        "Partial outage (50% errors)",
        bot, slo, success_sli, latency_sli, cost_sli, hallucination_sli, exp2,
    )

    # Scenario 3 — Token limit exhaustion
    bot.extra_error_rate = 0.80
    exp3 = ChaosExperiment(
        name="Token Exhaustion",
        target_agent="chatbot-agent",
        faults=[Fault.error_injection("llm_provider", error="rate_limit_exceeded", rate=0.8)],
        duration_seconds=300,
        description="80% of calls hit token-per-minute rate limits",
    )
    run_chaos_scenario(
        "Token limit exhaustion",
        bot, slo, success_sli, latency_sli, cost_sli, hallucination_sli, exp3,
    )

    # Scenario 4 — Context window overflow
    bot.context_overflow = True
    exp4 = ChaosExperiment(
        name="Context Window Overflow",
        target_agent="chatbot-agent",
        faults=[Fault.error_injection("llm_provider", error="context_overflow", rate=0.6)],
        duration_seconds=300,
        description="Oversize prompts exceed the model's context window",
    )
    run_chaos_scenario(
        "Context window overflow",
        bot, slo, success_sli, latency_sli, cost_sli, hallucination_sli, exp4,
    )

    print()
    indicator_table(slo)

    # ── Phase 3: Circuit breaker ───────────────────────────────────────
    banner("Phase 3 · Circuit Breaker")

    if slo.error_budget.is_exhausted or slo.error_budget.remaining_percent < 20:
        bot.circuit_open = True
        print(f"  {ERR}🔴 Circuit breaker OPEN — blocking further calls{RESET}")
        print(f"     Error budget remaining: {slo.error_budget.remaining_percent:.1f}%")
        # Show that calls are blocked
        result = bot.respond("blocked message")
        print(f"     Sample call → error: {result['error']}")
    else:
        print(f"  {OK}🟢 Circuit breaker stays closed — budget still OK{RESET}")

    # ── Phase 4: Recovery ──────────────────────────────────────────────
    banner("Phase 4 · Recovery")

    bot.reset_chaos()
    bot.reset_circuit_breaker()
    print("  Chaos cleared, circuit breaker reset.\n")

    recovery = run_traffic(
        bot, slo, success_sli, latency_sli, cost_sli, hallucination_sli, 50, "recovery"
    )
    print()
    indicator_table(slo)

    # ── Summary ────────────────────────────────────────────────────────
    banner("Summary")

    final_status = slo.evaluate()
    color = STATUS_COLOR.get(final_status.value, RESET)
    print(f"  Final SLO status:       {color}{final_status.value}{RESET}")
    print(f"  Error budget remaining: {slo.error_budget.remaining_percent:.1f}%")
    print(f"  Burn rate (1 h):        {slo.error_budget.burn_rate(3600):.1f}x")
    print(f"  Baseline success:       {baseline['rate']:.0%}")
    print(f"  Recovery success:       {recovery['rate']:.0%}")
    print()

    experiments = [exp1, exp2, exp3, exp4]
    print("  Experiment Results:")
    for exp in experiments:
        passed = f"{OK}PASS{RESET}" if exp.resilience.passed else f"{ERR}FAIL{RESET}"
        print(f"    {passed}  {exp.name:<28} score {exp.resilience.overall:5.1f}")

    overall = sum(e.resilience.overall for e in experiments) / len(experiments)
    all_passed = all(e.resilience.passed for e in experiments)
    verdict = f"{OK}RESILIENT{RESET}" if all_passed else f"{ERR}NEEDS IMPROVEMENT{RESET}"
    print(f"\n  Overall resilience: {overall:.1f}/100 — {verdict}")

    print(f"\n{'─' * 64}")
    print("  This demo used agent-sre to inject chaos into a chatbot agent")
    print("  and measure the impact on SLOs, error budgets, and circuit")
    print("  breakers — with zero API keys.")
    print(f"{'─' * 64}\n")


if __name__ == "__main__":
    main()
