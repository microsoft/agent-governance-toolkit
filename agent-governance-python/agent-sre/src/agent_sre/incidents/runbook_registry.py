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


# Bounds on YAML-loaded runbooks to guard against memory exhaustion
# from a malicious or accidental dump (e.g. a misconfigured generator
# producing a million entries). Operators wanting more than this should
# split the catalog across files.
_MAX_RUNBOOKS_PER_FILE = 1_000
_MAX_STEPS_PER_RUNBOOK = 500


def load_runbooks_from_yaml(path: str | Path) -> list[Runbook]:
    """Load runbook definitions from a YAML file.

    Validates the document structure and rejects entries that would
    silently corrupt the registry — empty ``id``, duplicate ``id``,
    non-list ``runbooks`` or ``trigger_conditions``, or step entries
    missing required fields. Raises :class:`ValueError` with a
    file-and-entry reference on any violation.

    YAML format::

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
        data: Any = yaml.safe_load(f)

    if data is None:
        return []

    if not isinstance(data, dict):
        raise ValueError(
            f"{path}: top-level YAML must be a mapping, got {type(data).__name__}"
        )

    entries = data.get("runbooks", [])
    if entries is None:
        return []
    if not isinstance(entries, list):
        raise ValueError(
            f"{path}: 'runbooks' must be a list, got {type(entries).__name__}"
        )
    if len(entries) > _MAX_RUNBOOKS_PER_FILE:
        raise ValueError(
            f"{path}: {len(entries)} runbooks exceeds limit "
            f"({_MAX_RUNBOOKS_PER_FILE}); split the catalog across files"
        )

    runbooks: list[Runbook] = []
    seen_ids: set[str] = set()
    for idx, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise ValueError(
                f"{path}: runbook[{idx}] must be a mapping, got "
                f"{type(entry).__name__}"
            )

        rb_id = entry.get("id")
        if not isinstance(rb_id, str) or not rb_id.strip():
            raise ValueError(
                f"{path}: runbook[{idx}] is missing a non-empty 'id'"
            )
        if rb_id in seen_ids:
            raise ValueError(
                f"{path}: runbook[{idx}] duplicates id '{rb_id}'"
            )
        seen_ids.add(rb_id)

        trigger_conditions = entry.get("trigger_conditions", [])
        if not isinstance(trigger_conditions, list):
            raise ValueError(
                f"{path}: runbook '{rb_id}': trigger_conditions must be a list"
            )

        labels = entry.get("labels", {}) or {}
        if not isinstance(labels, dict):
            raise ValueError(
                f"{path}: runbook '{rb_id}': labels must be a mapping"
            )

        raw_steps = entry.get("steps", []) or []
        if not isinstance(raw_steps, list):
            raise ValueError(
                f"{path}: runbook '{rb_id}': steps must be a list"
            )
        if len(raw_steps) > _MAX_STEPS_PER_RUNBOOK:
            raise ValueError(
                f"{path}: runbook '{rb_id}': {len(raw_steps)} steps "
                f"exceeds limit ({_MAX_STEPS_PER_RUNBOOK})"
            )

        steps: list[RunbookStep] = []
        for step_idx, step_data in enumerate(raw_steps):
            if not isinstance(step_data, dict):
                raise ValueError(
                    f"{path}: runbook '{rb_id}' step[{step_idx}] must be a mapping"
                )
            name = step_data.get("name")
            if not isinstance(name, str) or not name.strip():
                raise ValueError(
                    f"{path}: runbook '{rb_id}' step[{step_idx}] is missing 'name'"
                )
            steps.append(RunbookStep(
                name=name,
                action=step_data.get("action", ""),
                timeout_seconds=step_data.get("timeout_seconds", 300),
                requires_approval=step_data.get("requires_approval", False),
                rollback_action=step_data.get("rollback_action"),
            ))

        runbooks.append(Runbook(
            id=rb_id,
            name=entry.get("name", ""),
            description=entry.get("description", ""),
            trigger_conditions=trigger_conditions,
            steps=steps,
            labels=labels,
        ))

    return runbooks
