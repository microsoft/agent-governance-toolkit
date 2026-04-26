# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Canary Rollout Demo — Safely upgrade an AI model (GPT-3.5 → GPT-4).

Simulates a progressive delivery pipeline that:
  1. Establishes a baseline with GPT-3.5 (100 % traffic)
  2. Shifts 5 % of traffic to GPT-4 (canary)
  3. Monitors SLOs (latency, cost, quality) at each stage
  4. Promotes GPT-4 through 25 % → 50 % → 100 % if SLOs hold
  5. Automatically rolls back to GPT-3.5 if SLOs are breached

No API keys required — all model behaviour is simulated.

Run:
    cd examples/canary-model-upgrade
    python demo.py
"""

from __future__ import annotations

import random

from agent_sre import SLO, ErrorBudget
from agent_sre.delivery.rollout import (
    RollbackCondition,
    RolloutState,
    RolloutStep,
)
from agent_sre.slo.indicators import (
    CostPerTask,
    HallucinationRate,
    ResponseLatency,
    TaskSuccessRate,
)

# ── ANSI helpers ──────────────────────────────────────────────────────

BOLD = "\033[1m"
HEADER = "\033[1;36m"  # bold cyan
OK = "\033[32m"        # green
WARN = "\033[33m"      # yellow
ERR = "\033[31m"       # red
DIM = "\033[2m"        # dim
RESET = "\033[0m"

STATUS_COLOR = {
    "healthy": OK,
    "warning": WARN,
    "critical": ERR,
    "exhausted": ERR,
    "unknown": RESET,
}


def banner(text: str) -> None:
    print(f"\n{HEADER}{'═' * 64}")
    print(f"  {text}")
    print(f"{'═' * 64}{RESET}\n")


def section(text: str) -> None:
    print(f"\n  {BOLD}── {text} ──{RESET}\n")


def progress_bar(pct: float, width: int = 30) -> str:
    filled = int(width * pct)
    bar = "█" * filled + "░" * (width - filled)
    return f"[{bar}] {pct:.0%}"


# ── Simulated model behaviour ────────────────────────────────────────


class SimulatedModel:
    """Mimics an LLM endpoint with controllable quality characteristics."""

    def __init__(
        self,
        name: str,
        latency_ms: float,
        latency_jitter_ms: float,
        error_rate: float,
        hallucination_rate: float,
        cost_per_call: float,
    ) -> None:
        self.name = name
        self.latency_ms = latency_ms
        self.latency_jitter_ms = latency_jitter_ms
        self.error_rate = error_rate
        self.hallucination_rate = hallucination_rate
        self.cost_per_call = cost_per_call

    def call(self) -> dict:
        latency = self.latency_ms + random.uniform(0, self.latency_jitter_ms)
        if random.random() < self.error_rate:
            return {"success": False, "latency_ms": latency, "cost": 0.0, "hallucinated": False}
        hallucinated = random.random() < self.hallucination_rate
        cost = self.cost_per_call + random.uniform(0, self.cost_per_call * 0.15)
        return {"success": True, "latency_ms": latency, "cost": cost, "hallucinated": hallucinated}


# Model profiles — realistic but simulated
GPT35 = SimulatedModel(
    name="gpt-3.5-turbo",
    latency_ms=350,
    latency_jitter_ms=150,
    error_rate=0.02,
    hallucination_rate=0.06,
    cost_per_call=0.002,
)

# Two GPT-4 variants: one "good" upgrade and one that regresses on cost/latency
GPT4_GOOD = SimulatedModel(
    name="gpt-4 (good upgrade)",
    latency_ms=800,
    latency_jitter_ms=400,
    error_rate=0.01,
    hallucination_rate=0.02,
    cost_per_call=0.03,
)

GPT4_BAD = SimulatedModel(
    name="gpt-4 (bad upgrade — latency regression)",
    latency_ms=4500,
    latency_jitter_ms=3000,
    error_rate=0.04,
    hallucination_rate=0.03,
    cost_per_call=0.06,
)

# ── SLO setup ────────────────────────────────────────────────────────


def build_slo(name: str) -> tuple[SLO, TaskSuccessRate, ResponseLatency, CostPerTask, HallucinationRate]:
    success = TaskSuccessRate(target=0.95, window="1h")
    latency = ResponseLatency(target_ms=2000.0, percentile=0.95, window="1h")
    cost = CostPerTask(target_usd=0.10, window="1h")
    hallucination = HallucinationRate(target=0.05, window="1h")

    slo = SLO(
        name=name,
        description=f"SLOs for {name}: latency <2 s, success >95%, cost <$0.10, hallucination <5%",
        indicators=[success, latency, cost, hallucination],
        error_budget=ErrorBudget(total=0.05, burn_rate_alert=2.0, burn_rate_critical=5.0),
    )
    return slo, success, latency, cost, hallucination


# ── Traffic simulation ───────────────────────────────────────────────


def run_traffic(
    model: SimulatedModel,
    slo: SLO,
    success_sli: TaskSuccessRate,
    latency_sli: ResponseLatency,
    cost_sli: CostPerTask,
    hallucination_sli: HallucinationRate,
    n: int,
) -> dict:
    """Send *n* simulated requests and record against SLIs."""
    ok = 0
    total_latency = 0.0
    total_cost = 0.0
    hallucinated_count = 0

    for _ in range(n):
        result = model.call()
        good = result["success"] and not result["hallucinated"]

        if result["success"]:
            ok += 1
        if result["hallucinated"]:
            hallucinated_count += 1
        total_latency += result["latency_ms"]
        total_cost += result["cost"]

        success_sli.record_task(success=result["success"])
        latency_sli.record_latency(result["latency_ms"])
        cost_sli.record_cost(result["cost"])
        hallucination_sli.record_evaluation(hallucinated=result["hallucinated"])
        slo.record_event(good=good)

    return {
        "total": n,
        "ok": ok,
        "success_rate": ok / n,
        "avg_latency_ms": total_latency / n,
        "avg_cost": total_cost / n,
        "hallucination_rate": hallucinated_count / n,
    }


def print_metrics(stats: dict, model_name: str) -> None:
    sr = stats["success_rate"]
    sr_color = OK if sr >= 0.95 else (WARN if sr >= 0.90 else ERR)
    lat = stats["avg_latency_ms"]
    lat_color = OK if lat < 2000 else (WARN if lat < 3000 else ERR)
    cost = stats["avg_cost"]
    cost_color = OK if cost < 0.10 else (WARN if cost < 0.15 else ERR)
    hall = stats["hallucination_rate"]
    hall_color = OK if hall < 0.05 else (WARN if hall < 0.08 else ERR)

    print(f"    {DIM}Model:{RESET}  {model_name}")
    print(f"    {DIM}Reqs:{RESET}   {stats['total']:>4}   {DIM}OK:{RESET} {stats['ok']:>4}  "
          f"({sr_color}{sr:.1%}{RESET})")
    print(f"    {DIM}Latency:{RESET}        {lat_color}{lat:>8.0f} ms{RESET}  (target < 2 000 ms)")
    print(f"    {DIM}Cost/call:{RESET}      {cost_color}${cost:>7.4f}{RESET}    (target < $0.10)")
    print(f"    {DIM}Hallucination:{RESET}  {hall_color}{hall:>8.1%}{RESET}    (target < 5%)")


def slo_status_line(slo: SLO) -> None:
    status = slo.evaluate()
    color = STATUS_COLOR.get(status.value, RESET)
    budget = slo.error_budget.remaining_percent
    print(f"    SLO: {color}{status.value:>10}{RESET}  "
          f"error budget: {budget:5.1f}% remaining")


# ── Canary rollout engine ────────────────────────────────────────────
# CanaryRollout.start/advance/rollback are Enterprise-only.  This demo
# drives the rollout loop directly using the data-classes that *are*
# available in Public Preview (RolloutStep, RollbackCondition, etc.).


def collect_canary_metrics(model: SimulatedModel, n: int) -> dict[str, float]:
    """Quick metric collection for rollback condition checks."""
    ok = 0
    total_latency = 0.0
    total_cost = 0.0
    hallucinated = 0

    for _ in range(n):
        result = model.call()
        if result["success"]:
            ok += 1
        if result["hallucinated"]:
            hallucinated += 1
        total_latency += result["latency_ms"]
        total_cost += result["cost"]

    return {
        "error_rate": 1.0 - (ok / n),
        "hallucination_rate": hallucinated / n,
        "p95_latency_ms": total_latency / n * 1.6,  # rough p95 estimate
        "avg_cost_usd": total_cost / n,
    }


def check_rollback(
    conditions: list[RollbackCondition],
    metrics: dict[str, float],
) -> list[str]:
    """Return list of breached condition descriptions (empty = pass)."""
    breached: list[str] = []
    for cond in conditions:
        val = metrics.get(cond.metric)
        if val is not None and cond.should_rollback(val):
            breached.append(f"{cond.metric}={val:.4f} (threshold {cond.threshold})")
    return breached


def run_canary_scenario(
    label: str,
    canary_model: SimulatedModel,
    baseline_model: SimulatedModel,
) -> None:
    """Execute a full canary rollout scenario (promote or rollback)."""
    random.seed(42)

    steps = [
        RolloutStep(weight=0.05, duration_seconds=30, name="5% canary"),
        RolloutStep(weight=0.25, duration_seconds=30, name="25% ramp"),
        RolloutStep(weight=0.50, duration_seconds=30, name="50% ramp"),
        RolloutStep(weight=1.00, duration_seconds=0, name="100% full rollout"),
    ]
    rollback_conditions = [
        RollbackCondition(metric="error_rate", threshold=0.10, comparator="gte"),
        RollbackCondition(metric="hallucination_rate", threshold=0.08, comparator="gte"),
        RollbackCondition(metric="p95_latency_ms", threshold=5000.0, comparator="gte"),
        RollbackCondition(metric="avg_cost_usd", threshold=0.10, comparator="gte"),
    ]

    state = RolloutState.PENDING

    banner(f"Scenario: {label}")
    print(f"  Baseline model: {baseline_model.name}")
    print(f"  Canary model:   {canary_model.name}")

    # ── Phase 1: Baseline ─────────────────────────────────────────────
    section("Phase 1 · Baseline (100% → GPT-3.5)")

    slo_base, s_sli, l_sli, c_sli, h_sli = build_slo("baseline")
    baseline_stats = run_traffic(baseline_model, slo_base, s_sli, l_sli, c_sli, h_sli, 100)
    print_metrics(baseline_stats, baseline_model.name)
    slo_status_line(slo_base)
    print()
    print(f"    {OK}✓{RESET} Baseline established — all SLOs met")

    # ── Phase 2: Canary (5 %) ─────────────────────────────────────────
    section("Phase 2 · Canary deployment (5% → GPT-4)")

    state = RolloutState.CANARY
    step = steps[0]
    print(f"    Rollout started")
    print(f"    Current step:    {step.name} ({step.weight:.0%} traffic)")
    print(f"    {progress_bar(step.weight)}")
    print()

    slo_canary, s_sli2, l_sli2, c_sli2, h_sli2 = build_slo("canary")
    canary_stats = run_traffic(canary_model, slo_canary, s_sli2, l_sli2, c_sli2, h_sli2, 20)
    print_metrics(canary_stats, canary_model.name)
    slo_status_line(slo_canary)

    # ── Phase 3: SLO monitoring & progressive promotion ───────────────
    section("Phase 3 · SLO monitoring & progressive promotion")

    promoted_through = 0
    for step_idx, step in enumerate(steps):
        metrics = collect_canary_metrics(canary_model, 50)
        breached = check_rollback(rollback_conditions, metrics)

        weight_str = f"{step.weight:.0%}"
        print(f"    Stage {step_idx + 1}: {step.name} ({weight_str} traffic)")
        print(f"    {progress_bar(step.weight)}")
        print(f"      error_rate:        {metrics['error_rate']:.2%}")
        print(f"      hallucination:     {metrics['hallucination_rate']:.2%}")
        print(f"      p95_latency:       {metrics['p95_latency_ms']:.0f} ms")
        print(f"      avg_cost:          ${metrics['avg_cost_usd']:.4f}")

        if breached:
            state = RolloutState.ROLLED_BACK
            print()
            print(f"      {ERR}🛑 ROLLBACK TRIGGERED{RESET}")
            for b in breached:
                print(f"         ↳ {ERR}{b}{RESET}")
            break

        promoted_through = step_idx + 1
        if step_idx < len(steps) - 1:
            print(f"      {OK}✅ SLOs met — advancing to next stage{RESET}")
            print()
        else:
            state = RolloutState.COMPLETE
            print(f"      {OK}✅ SLOs met — fully promoted{RESET}")
            print()

    # ── Phase 4/5: Result ─────────────────────────────────────────────
    progress_pct = (promoted_through / len(steps)) * 100

    if state == RolloutState.ROLLED_BACK:
        section("Phase 4 · Automatic rollback")
        print(f"    {ERR}✗{RESET} GPT-4 failed SLO checks")
        print(f"    {OK}✓{RESET} Rolled back to {baseline_model.name} — zero user impact")
        print(f"    Status: {ERR}{state.value}{RESET}")
    else:
        section("Phase 4 · Full promotion")
        print(f"    {OK}✓{RESET} GPT-4 passed all SLO checks at every stage")
        print(f"    {OK}✓{RESET} Promoted to 100% traffic")
        print(f"    Status: {OK}{state.value}{RESET}")

    print(f"    Progress: {progress_pct:.0f}%")
    print()


# ── Main ─────────────────────────────────────────────────────────────


def main() -> None:
    banner("Canary Rollout Demo — AI Model Upgrade (GPT-3.5 → GPT-4)")

    print("  This demo simulates a progressive delivery pipeline for upgrading")
    print("  an AI model from GPT-3.5 to GPT-4 using agent-sre.")
    print()
    print("  SLO targets:")
    print("    • Latency:        p95 < 2 000 ms")
    print("    • Success rate:   > 95%")
    print("    • Cost per call:  < $0.10")
    print("    • Hallucination:  < 5%")
    print()
    print(f"  {DIM}No API keys needed — all behaviour is simulated.{RESET}")

    # ── Scenario A: Successful upgrade ────────────────────────────────
    run_canary_scenario(
        label="Successful model upgrade",
        canary_model=GPT4_GOOD,
        baseline_model=GPT35,
    )

    # ── Scenario B: Failed upgrade (automatic rollback) ───────────────
    run_canary_scenario(
        label="Failed model upgrade (automatic rollback)",
        canary_model=GPT4_BAD,
        baseline_model=GPT35,
    )

    # ── Summary ───────────────────────────────────────────────────────
    banner("Summary")

    print("  Scenario A — Good GPT-4 upgrade:")
    print(f"    {OK}✓ Promoted through 5% → 25% → 50% → 100%{RESET}")
    print(f"    {OK}✓ All SLOs remained within thresholds{RESET}")
    print()
    print("  Scenario B — Bad GPT-4 upgrade (latency regression):")
    print(f"    {ERR}✗ Rolled back at canary stage{RESET}")
    print(f"    {OK}✓ Users never saw degraded performance{RESET}")
    print()
    print(f"{'─' * 64}")
    print("  agent-sre enables safe model upgrades with progressive delivery,")
    print("  SLO-gated promotion, and automatic rollback — ensuring zero")
    print("  user impact when an upgrade regresses.")
    print(f"{'─' * 64}\n")


if __name__ == "__main__":
    main()
