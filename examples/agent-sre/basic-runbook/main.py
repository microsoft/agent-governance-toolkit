#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Agent-SRE Basic Runbook — Health check, incident, and remediation.

Run:
    pip install -r requirements.txt
    python main.py

Demonstrates the three pillars of the agent_sre workflow:

1. Define an SLO and watch its health transition UNKNOWN -> HEALTHY -> EXHAUSTED.
2. Detect an SLO breach signal and create an Incident automatically.
3. Execute a multi-step Runbook with an approval gate against the incident.

No API keys are required. After installation the example runs locally and
does not call external services. Task outcomes are deterministic so the
printed output is stable across runs.
"""

from agent_sre import ErrorBudget, SLO
from agent_sre.incidents.detector import IncidentDetector, Signal, SignalType
from agent_sre.incidents.runbook import Runbook, RunbookStep
from agent_sre.incidents.runbook_executor import RunbookExecutor
from agent_sre.slo.dashboard import SLODashboard
from agent_sre.slo.indicators import TaskSuccessRate


def print_health(label: str, dashboard: SLODashboard, slo_name: str) -> None:
    summary = dashboard.health_summary()
    print(f"{label}: {summary['slos'][slo_name]}")


def main() -> None:
    print("Agent-SRE Basic Runbook")
    print("=" * 60)

    # ── 1. Define the SLO ──────────────────────────────────────────────
    success_rate = TaskSuccessRate(target=0.95, window="24h")
    slo = SLO(
        name="demo-agent",
        description="Demo agent reliability target",
        indicators=[success_rate],
        error_budget=ErrorBudget(total=0.05, burn_rate_critical=10.0),
    )
    dashboard = SLODashboard()
    dashboard.register_slo(slo)

    # ── 2. Initial health check (no data yet -> unknown) ───────────────
    print_health("Initial health  ", dashboard, slo.name)

    # ── 3. Warm up with successful tasks (-> healthy) ──────────────────
    for _ in range(20):
        success_rate.record_task(success=True)
        slo.record_event(good=True)
    print_health("After warmup    ", dashboard, slo.name)

    # ── 4. Trigger a breach with one bad event (-> exhausted) ──────────
    success_rate.record_task(success=False)
    slo.record_event(good=False)
    print_health("After failure   ", dashboard, slo.name)

    # ── 5. Detect & create an incident ─────────────────────────────────
    detector = IncidentDetector(correlation_window_seconds=60)
    signal = Signal(
        signal_type=SignalType.ERROR_BUDGET_EXHAUSTED,
        source=slo.name,
        message="Error budget exhausted after task failure",
    )
    incident = detector.ingest_signal(signal)
    if incident is None:
        raise RuntimeError(
            "Expected ERROR_BUDGET_EXHAUSTED to create an incident"
        )

    print()
    print(f"[!] Incident created: {incident.title}")
    print(f"    Severity:    {incident.severity.value}")
    print(f"    Incident ID: {incident.incident_id}")

    # ── 6. Execute a runbook ───────────────────────────────────────────
    def check_health(_incident) -> str:
        summary = dashboard.health_summary()
        return f"health summary refreshed (status={summary['slos'][slo.name]})"

    def restart_agent(_incident) -> str:
        return "agent restarted"

    def verify_recovery(_incident) -> str:
        for _ in range(5):
            success_rate.record_task(success=True)
            slo.record_event(good=True)
        return "recovery checks passed"

    runbook = Runbook(
        name="demo-agent recovery",
        description="Check health, restart the agent (with approval), verify recovery.",
        steps=[
            RunbookStep(name="Check health", action=check_health),
            RunbookStep(
                name="Restart agent",
                action=restart_agent,
                requires_approval=True,
            ),
            RunbookStep(name="Verify recovery", action=verify_recovery),
        ],
    )

    executor = RunbookExecutor()
    execution = executor.execute(
        runbook=runbook,
        incident=incident,
        approve_callback=lambda step, inc: True,
    )

    print()
    print(f"Runbook execution: {execution.status.value}")
    for result in execution.step_results:
        duration = result.duration_seconds or 0.0
        print(
            f"  [ok] {result.step_name:<18} "
            f"({duration:.3f}s)  -> {result.output}"
        )


if __name__ == "__main__":
    main()
