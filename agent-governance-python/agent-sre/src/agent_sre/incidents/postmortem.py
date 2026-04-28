# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# Community Edition — basic implementation
"""Postmortem data models — basic incident summary.

Postmortem template generation is not available in Community Edition.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from agent_sre.incidents.detector import Incident, IncidentSeverity, IncidentState


class PostmortemStatus(Enum):
    """Status of a postmortem document."""
    DRAFT = "draft"
    IN_REVIEW = "in_review"
    PUBLISHED = "published"


@dataclass
class TimelineEntry:
    """A single entry in the incident timeline."""
    timestamp: float
    event: str
    actor: str = ""  # agent, human, system
    details: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "event": self.event,
            "actor": self.actor,
            "details": self.details,
        }


@dataclass
class ActionItem:
    """A follow-up action from the postmortem."""
    action_id: str = field(default_factory=lambda: uuid.uuid4().hex[:8])
    title: str = ""
    description: str = ""
    priority: str = "medium"  # low, medium, high, critical
    owner: str = ""
    status: str = "open"  # open, in_progress, done
    due_date: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_id": self.action_id,
            "title": self.title,
            "description": self.description,
            "priority": self.priority,
            "owner": self.owner,
            "status": self.status,
            "due_date": self.due_date,
        }


@dataclass
class Postmortem:
    """A postmortem template document."""
    postmortem_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    incident_id: str = ""
    title: str = ""
    status: PostmortemStatus = PostmortemStatus.DRAFT
    severity: IncidentSeverity = IncidentSeverity.P3
    summary: str = ""
    impact: str = ""
    root_cause: str = ""
    detection: str = ""
    response: str = ""
    lessons_learned: list[str] = field(default_factory=list)
    timeline: list[TimelineEntry] = field(default_factory=list)
    action_items: list[ActionItem] = field(default_factory=list)
    contributing_factors: list[str] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    author: str = "agent-sre"

    def add_timeline_entry(self, event: str, actor: str = "system", details: str = "", ts: float | None = None) -> None:
        self.timeline.append(TimelineEntry(
            timestamp=ts or time.time(),
            event=event,
            actor=actor,
            details=details,
        ))

    def add_action_item(self, title: str, description: str = "", priority: str = "medium", owner: str = "") -> ActionItem:
        item = ActionItem(title=title, description=description, priority=priority, owner=owner)
        self.action_items.append(item)
        return item

    def publish(self) -> None:
        self.status = PostmortemStatus.PUBLISHED
        self.updated_at = time.time()

    def to_dict(self) -> dict[str, Any]:
        return {
            "postmortem_id": self.postmortem_id,
            "incident_id": self.incident_id,
            "title": self.title,
            "status": self.status.value,
            "severity": self.severity.value,
            "summary": self.summary,
            "impact": self.impact,
            "root_cause": self.root_cause,
            "detection": self.detection,
            "response": self.response,
            "lessons_learned": self.lessons_learned,
            "contributing_factors": self.contributing_factors,
            "timeline": [t.to_dict() for t in self.timeline],
            "action_items": [a.to_dict() for a in self.action_items],
            "created_at": self.created_at,
            "author": self.author,
        }

    def to_markdown(self) -> str:
        """Render postmortem as Markdown."""
        lines = [
            f"# Postmortem: {self.title}",
            "",
            f"**Incident ID:** {self.incident_id}",
            f"**Severity:** {self.severity.value.upper()}",
            f"**Status:** {self.status.value}",
            f"**Author:** {self.author}",
            "",
            "## Summary",
            self.summary or "_No summary provided._",
            "",
            "## Impact",
            self.impact or "_No impact assessment._",
            "",
            "## Root Cause",
            self.root_cause or "_Under investigation._",
            "",
        ]

        if self.contributing_factors:
            lines.append("## Contributing Factors")
            for factor in self.contributing_factors:
                lines.append(f"- {factor}")
            lines.append("")

        if self.timeline:
            lines.append("## Timeline")
            for entry in sorted(self.timeline, key=lambda e: e.timestamp):
                lines.append(f"- **{entry.event}** ({entry.actor}): {entry.details}")
            lines.append("")

        lines.extend([
            "## Detection",
            self.detection or "_Auto-detected by agent-sre._",
            "",
            "## Response",
            self.response or "_Automated response applied._",
            "",
        ])

        if self.lessons_learned:
            lines.append("## Lessons Learned")
            for lesson in self.lessons_learned:
                lines.append(f"- {lesson}")
            lines.append("")

        if self.action_items:
            lines.append("## Action Items")
            for item in self.action_items:
                status_mark = "x" if item.status == "done" else " "
                lines.append(f"- [{status_mark}] **[{item.priority.upper()}]** {item.title}: {item.description}")
            lines.append("")

        return "\n".join(lines)


class PostmortemGenerator:
    """Generates postmortems automatically from incident data."""

    def __init__(self) -> None:
        self._postmortems: list[Postmortem] = []

    def generate(self, incident: Incident) -> Postmortem:
        """Generate a postmortem document from incident data.

        Assembles summary, impact, root cause analysis, detection details,
        response actions, timeline, contributing factors, lessons learned,
        and suggested action items into a structured Postmortem.

        Args:
            incident: The incident to generate a postmortem for.

        Returns:
            A populated Postmortem in DRAFT status.
        """
        postmortem = Postmortem(
            incident_id=incident.incident_id,
            title=incident.title,
            severity=incident.severity,
            summary=self._build_summary(incident),
            impact=self._build_impact(incident),
            root_cause=self._analyze_root_cause(incident),
            detection=self._build_detection(incident),
            response=self._build_response(incident),
            lessons_learned=self._suggest_lessons(incident),
            action_items=self._suggest_actions(incident),
            contributing_factors=self._identify_factors(incident),
        )

        # Build timeline from signals and actions
        for signal in incident.signals:
            postmortem.add_timeline_entry(
                event=f"Signal: {signal.signal_type.value}",
                actor="system",
                details=signal.message or signal.source,
                ts=signal.timestamp,
            )
        for action in incident.actions:
            postmortem.add_timeline_entry(
                event=f"Response: {action.action_type}",
                actor="agent-sre",
                details=action.result,
                ts=action.timestamp,
            )

        self._postmortems.append(postmortem)
        return postmortem

    def _build_summary(self, incident: Incident) -> str:
        signal_types = {s.signal_type.value for s in incident.signals}
        duration = round(incident.duration_seconds, 0)
        return (
            f"A {incident.severity.value.upper()} incident affecting agent '{incident.agent_id}' "
            f"was detected via {', '.join(signal_types)}. "
            f"Duration: {duration}s. "
            f"{'Resolved.' if incident.state == IncidentState.RESOLVED else 'Ongoing.'}"
        )

    def _build_impact(self, incident: Incident) -> str:
        action_count = len(incident.actions)
        signal_count = len(incident.signals)
        return (
            f"Agent '{incident.agent_id}' was affected. "
            f"{signal_count} reliability signal(s) triggered, "
            f"{action_count} response action(s) taken."
        )

    def _build_detection(self, incident: Incident) -> str:
        if not incident.signals:
            return "No signals recorded."
        first = incident.signals[0]
        return f"First detected via {first.signal_type.value} from '{first.source}': {first.message}"

    def _build_response(self, incident: Incident) -> str:
        if not incident.actions:
            return "No automated responses were triggered."
        actions = [a.action_type for a in incident.actions]
        return f"Automated responses: {', '.join(actions)}"

    def _analyze_root_cause(self, incident: Incident) -> str:
        if not incident.signals:
            return "Root cause unknown — no signals recorded."
        primary = incident.signals[0]
        return f"Primary signal: {primary.signal_type.value} from '{primary.source}' (value: {primary.value}, threshold: {primary.threshold})"

    def _suggest_actions(self, incident: Incident) -> list[ActionItem]:
        actions: list[ActionItem] = []
        signal_types = {s.signal_type.value for s in incident.signals}

        if "slo_breach" in signal_types:
            actions.append(ActionItem(
                title="Review SLO targets",
                description="Evaluate if current SLO targets are realistic given observed performance.",
                priority="medium",
            ))
        if "error_budget_exhausted" in signal_types:
            actions.append(ActionItem(
                title="Freeze deployments",
                description="Halt agent deployments until error budget recovers.",
                priority="high",
            ))
        if "cost_anomaly" in signal_types:
            actions.append(ActionItem(
                title="Investigate cost spike",
                description="Analyze task-level costs to identify the root cause of the anomaly.",
                priority="high",
            ))
        if "policy_violation" in signal_types:
            actions.append(ActionItem(
                title="Audit policy configuration",
                description="Review agent-os policy rules and agent behavior for compliance gaps.",
                priority="critical",
            ))

        # Always add a review action
        actions.append(ActionItem(
            title="Review monitoring coverage",
            description="Ensure SLIs and alerts cover the failure mode seen in this incident.",
            priority="medium",
        ))
        return actions

    def _suggest_lessons(self, incident: Incident) -> list[str]:
        lessons = []
        if incident.severity in (IncidentSeverity.P1, IncidentSeverity.P2):
            lessons.append("High-severity incidents should trigger circuit breaker protection.")
        if len(incident.signals) > 2:
            lessons.append("Multiple correlated signals suggest systemic issue — consider chaos testing.")
        if not incident.actions:
            lessons.append("No automated responses were triggered — evaluate adding auto-remediation.")
        if incident.duration_seconds > 300:
            lessons.append("Time-to-resolution exceeded 5 minutes — consider faster detection or manual rollback.")
        return lessons

    def _identify_factors(self, incident: Incident) -> list[str]:
        factors = []
        for signal in incident.signals:
            factors.append(f"{signal.signal_type.value}: {signal.message or signal.source}")
        return factors

    @property
    def all_postmortems(self) -> list[Postmortem]:
        return self._postmortems

    def summary(self) -> dict[str, Any]:
        return {
            "total": len(self._postmortems),
            "by_severity": {
                sev.value: sum(1 for p in self._postmortems if p.severity == sev)
                for sev in IncidentSeverity
            },
            "total_action_items": sum(len(p.action_items) for p in self._postmortems),
        }
