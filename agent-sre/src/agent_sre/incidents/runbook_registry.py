# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# Public Preview — basic implementation
"""Runbook registry — registration, matching, and YAML loading."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any

import yaml

from agent_sre.incidents.runbook import Runbook, RunbookStep

if TYPE_CHECKING:
    from agent_sre.incidents.detector import Incident


class RunbookRegistry:
    """Registry for managing runbooks and matching them to incidents."""

    def __init__(self) -> None:
        self._runbooks: dict[str, Runbook] = {}

    def register(self, runbook: Runbook) -> None:
        """Register a runbook."""
        self._runbooks[runbook.id] = runbook

    def get(self, runbook_id: str) -> Runbook | None:
        """Get a runbook by ID."""
        return self._runbooks.get(runbook_id)

    def list_all(self) -> list[Runbook]:
        """List all registered runbooks."""
        return list(self._runbooks.values())

    def match(self, incident: Incident) -> list[Runbook]:
        """Find runbooks matching an incident's type/severity.

        A runbook matches if any of its trigger_conditions match the incident.
        A condition matches when all specified fields (type, severity) match
        the incident's signals and severity.
        """
        matched: list[Runbook] = []
        incident_signal_types = {s.signal_type.value for s in incident.signals}
        incident_severity = incident.severity.value

        for runbook in self._runbooks.values():
            for condition in runbook.trigger_conditions:
                cond_type = condition.get("type")
                cond_severity = condition.get("severity")

                type_match = cond_type is None or cond_type in incident_signal_types
                severity_match = cond_severity is None or cond_severity == incident_severity
                if type_match and severity_match:
                    matched.append(runbook)
                    break

        return matched


def load_runbooks_from_yaml(path: str | Path) -> list[Runbook]:
    """Load runbook definitions from a YAML file.

    YAML format:
        runbooks:
          - id: my-runbook
            name: My Runbook
            description: Does something
            trigger_conditions:
              - type: slo_breach
                severity: p1
            labels:
              team: sre
            steps:
              - name: Step 1
                action: "echo hello"
                timeout_seconds: 60
                requires_approval: false
                rollback_action: "echo rollback"
    """
    path = Path(path)
    with open(path) as f:
        data: dict[str, Any] = yaml.safe_load(f)

    runbooks: list[Runbook] = []
    for entry in data.get("runbooks", []):
        steps: list[RunbookStep] = []
        for step_data in entry.get("steps", []):
            steps.append(RunbookStep(
                name=step_data["name"],
                action=step_data.get("action", ""),
                timeout_seconds=step_data.get("timeout_seconds", 300),
                requires_approval=step_data.get("requires_approval", False),
                rollback_action=step_data.get("rollback_action"),
            ))

        runbooks.append(Runbook(
            id=entry.get("id", ""),
            name=entry.get("name", ""),
            description=entry.get("description", ""),
            trigger_conditions=entry.get("trigger_conditions", []),
            steps=steps,
            labels=entry.get("labels", {}),
        ))

    return runbooks
