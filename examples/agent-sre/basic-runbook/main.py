# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Minimal Agent SRE runbook example."""

from __future__ import annotations

from agent_sre.incidents.detector import Incident, IncidentSeverity, Signal, SignalType
from agent_sre.incidents.runbook import Runbook, RunbookStep
from agent_sre.incidents.runbook_executor import RunbookExecutor


def check_health(incident: Incident) -> str:
    return f"checked health for {incident.agent_id}"


def restart_worker(incident: Incident) -> str:
    incident.add_action("restart_worker", "worker restarted")
    return "worker restarted"


def main() -> None:
    signal = Signal(
        signal_type=SignalType.SLO_BREACH,
        source="support-agent",
        value=0.92,
        threshold=0.95,
        message="Task success SLO is below target",
    )
    incident = Incident(
        title="Support agent SLO breach",
        severity=IncidentSeverity.P2,
        signals=[signal],
        agent_id="support-agent",
    )

    runbook = Runbook(
        id="basic-slo-runbook",
        name="Basic SLO Runbook",
        description="Check health and restart a worker for a simple SLO breach.",
        steps=[
            RunbookStep(name="Health check", action=check_health),
            RunbookStep(name="Restart worker", action=restart_worker),
            RunbookStep(name="Notify on-call", action="notify sre-oncall"),
        ],
    )

    execution = RunbookExecutor().execute(runbook, incident)
    print(f"incident: {incident.title} ({incident.severity.value})")
    print(f"runbook status: {execution.status.value}")
    for result in execution.step_results:
        print(f"- {result.step_name}: {result.status.value} {result.output}")


if __name__ == "__main__":
    main()
