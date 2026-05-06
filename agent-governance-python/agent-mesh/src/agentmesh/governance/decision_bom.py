# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Decision Bill of Materials (Decision BOM) - Reconstructible View.

Provides an on-demand, non-invasive reconstructible view of every factor that
contributed to a governance decision. Rather than storing a pre-built BOM at
decision time (which would couple tightly to the action pipeline), this module
queries existing observability signals (audit logs, trust scores, policy
evaluations, OTel traces) and reconstructs the full decision context after
the fact.

Design principles (from architecture review):
  - Reconstructible view: slow but complete, built on demand
  - Infer from observability signals: non-invasive, no agent reporting required
  - Python-first implementation
  - Less complete but non-invasive > complete but invasive
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional, Protocol, runtime_checkable


# ---------------------------------------------------------------------------
# Protocols for signal sources (observability layer)
# ---------------------------------------------------------------------------


@runtime_checkable
class AuditSource(Protocol):
    """Protocol for querying audit log entries."""

    def query_by_trace(self, trace_id: str) -> list[dict[str, Any]]:
        """Return audit entries matching a trace ID."""
        ...

    def query_by_agent(
        self, agent_id: str, start: datetime, end: datetime
    ) -> list[dict[str, Any]]:
        """Return audit entries for an agent within a time range."""
        ...


@runtime_checkable
class TrustSource(Protocol):
    """Protocol for querying trust score history."""

    def get_score_at(self, agent_id: str, timestamp: datetime) -> Optional[float]:
        """Return the trust score for an agent at a point in time."""
        ...

    def get_score_history(
        self, agent_id: str, start: datetime, end: datetime
    ) -> list[dict[str, Any]]:
        """Return trust score changes within a time range."""
        ...


@runtime_checkable
class PolicySource(Protocol):
    """Protocol for querying policy evaluation results."""

    def get_evaluations(self, trace_id: str) -> list[dict[str, Any]]:
        """Return policy evaluation results for a trace ID."""
        ...

    def get_active_policies_at(self, timestamp: datetime) -> list[dict[str, Any]]:
        """Return policies that were active at a given timestamp."""
        ...


@runtime_checkable
class TraceSource(Protocol):
    """Protocol for querying OTel trace spans."""

    def get_spans(self, trace_id: str) -> list[dict[str, Any]]:
        """Return all spans for a given trace ID."""
        ...


# ---------------------------------------------------------------------------
# BOM Data Models
# ---------------------------------------------------------------------------


class BOMFieldCategory(str, Enum):
    """Categories for BOM fields, aligned with governance concerns."""

    IDENTITY = "identity"
    TRUST = "trust"
    POLICY = "policy"
    ACTION = "action"
    CONTEXT = "context"
    OUTCOME = "outcome"
    LINEAGE = "lineage"


@dataclass
class BOMField:
    """A single field in the Decision BOM."""

    name: str
    category: BOMFieldCategory
    value: Any
    source: str  # Which signal source provided this
    confidence: float = 1.0  # 0.0-1.0, how certain we are of this value
    inferred: bool = False  # True if reconstructed rather than directly observed


@dataclass
class DecisionBOM:
    """Complete Bill of Materials for a single governance decision.

    Reconstructed on-demand from observability signals. Contains every factor
    that contributed to the decision outcome.
    """

    # Required identifiers
    decision_id: str
    timestamp: datetime
    agent_id: str

    # The decision itself
    action_requested: str
    outcome: str  # allow, deny, alert

    # Reconstructed fields organized by category
    fields: list[BOMField] = field(default_factory=list)

    # Reconstruction metadata
    reconstructed_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    sources_queried: list[str] = field(default_factory=list)
    completeness_score: float = 0.0  # 0.0-1.0

    def get_fields_by_category(self, category: BOMFieldCategory) -> list[BOMField]:
        """Return all fields in a given category."""
        return [f for f in self.fields if f.category == category]

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary for API responses or storage."""
        return {
            "decision_id": self.decision_id,
            "timestamp": self.timestamp.isoformat(),
            "agent_id": self.agent_id,
            "action_requested": self.action_requested,
            "outcome": self.outcome,
            "reconstructed_at": self.reconstructed_at.isoformat(),
            "sources_queried": self.sources_queried,
            "completeness_score": self.completeness_score,
            "fields": [
                {
                    "name": f.name,
                    "category": f.category.value,
                    "value": f.value,
                    "source": f.source,
                    "confidence": f.confidence,
                    "inferred": f.inferred,
                }
                for f in self.fields
            ],
        }


# ---------------------------------------------------------------------------
# BOM Reconstructor
# ---------------------------------------------------------------------------

# Required fields every BOM should have if sources provide them
REQUIRED_FIELDS = [
    "agent_identity",
    "trust_score_at_decision",
    "policy_rules_evaluated",
    "action_type",
    "decision_outcome",
]

# Nice-to-have fields that enrich the BOM but are not critical
OPTIONAL_FIELDS = [
    "delegation_chain",
    "trust_score_trend",
    "similar_past_decisions",
    "resource_target",
    "session_context",
    "cost_incurred",
    "latency_ms",
    "otel_trace_id",
    "parent_intent_id",
]


class DecisionBOMReconstructor:
    """Reconstructs Decision BOMs from observability signals.

    Non-invasive: queries existing audit, trust, policy, and trace data
    without requiring agents to report anything extra.

    Usage::

        reconstructor = DecisionBOMReconstructor(
            audit_source=my_audit_backend,
            trust_source=my_trust_store,
            policy_source=my_policy_log,
        )
        bom = reconstructor.reconstruct(trace_id="abc123")
    """

    def __init__(
        self,
        audit_source: Optional[AuditSource] = None,
        trust_source: Optional[TrustSource] = None,
        policy_source: Optional[PolicySource] = None,
        trace_source: Optional[TraceSource] = None,
    ):
        self._audit = audit_source
        self._trust = trust_source
        self._policy = policy_source
        self._trace = trace_source

    @property
    def available_sources(self) -> list[str]:
        """List which signal sources are configured."""
        sources = []
        if self._audit:
            sources.append("audit")
        if self._trust:
            sources.append("trust")
        if self._policy:
            sources.append("policy")
        if self._trace:
            sources.append("trace")
        return sources

    def reconstruct(
        self,
        trace_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        timestamp: Optional[datetime] = None,
        window_seconds: float = 5.0,
    ) -> DecisionBOM:
        """Reconstruct a Decision BOM from observability signals.

        Provide either a trace_id (preferred, most precise) or an agent_id +
        timestamp combination (fuzzy match within window_seconds).

        Args:
            trace_id: OTel trace ID for precise correlation.
            agent_id: Agent identifier for time-based lookup.
            timestamp: Approximate time of the decision.
            window_seconds: How wide a window to search around timestamp.

        Returns:
            Reconstructed DecisionBOM with all available fields populated.

        Raises:
            ValueError: If neither trace_id nor (agent_id + timestamp) provided.
        """
        if not trace_id and not (agent_id and timestamp):
            raise ValueError(
                "Provide either trace_id or both agent_id and timestamp"
            )

        fields: list[BOMField] = []
        sources_queried: list[str] = []

        # Phase 1: Gather audit entries
        audit_entries = self._gather_audit(
            trace_id, agent_id, timestamp, window_seconds
        )
        if audit_entries:
            sources_queried.append("audit")
            fields.extend(self._extract_from_audit(audit_entries))

        # Phase 2: Gather trust scores
        resolved_agent = agent_id or self._agent_from_audit(audit_entries)
        resolved_time = timestamp or self._time_from_audit(audit_entries)

        if resolved_agent and resolved_time:
            trust_fields = self._gather_trust(resolved_agent, resolved_time)
            if trust_fields:
                sources_queried.append("trust")
                fields.extend(trust_fields)

        # Phase 3: Gather policy evaluations
        policy_fields = self._gather_policy(trace_id, resolved_time)
        if policy_fields:
            sources_queried.append("policy")
            fields.extend(policy_fields)

        # Phase 4: Gather trace spans
        if trace_id:
            trace_fields = self._gather_trace(trace_id)
            if trace_fields:
                sources_queried.append("trace")
                fields.extend(trace_fields)

        # Build the BOM
        bom = DecisionBOM(
            decision_id=trace_id or f"{resolved_agent}@{resolved_time.isoformat()}" if resolved_time else "unknown",
            timestamp=resolved_time or datetime.now(timezone.utc),
            agent_id=resolved_agent or "unknown",
            action_requested=self._find_field_value(fields, "action_type", "unknown"),
            outcome=self._find_field_value(fields, "decision_outcome", "unknown"),
            fields=fields,
            sources_queried=sources_queried,
            completeness_score=self._compute_completeness(fields),
        )

        return bom

    def reconstruct_batch(
        self,
        agent_id: str,
        start: datetime,
        end: datetime,
    ) -> list[DecisionBOM]:
        """Reconstruct BOMs for all decisions by an agent in a time range.

        Args:
            agent_id: The agent to query decisions for.
            start: Start of the time range.
            end: End of the time range.

        Returns:
            List of reconstructed DecisionBOMs, ordered by timestamp.
        """
        if not self._audit:
            return []

        entries = self._audit.query_by_agent(agent_id, start, end)

        # Group entries by trace_id where available
        trace_groups: dict[str, list[dict]] = {}
        ungrouped: list[dict] = []

        for entry in entries:
            tid = entry.get("trace_id")
            if tid:
                trace_groups.setdefault(tid, []).append(entry)
            else:
                ungrouped.append(entry)

        boms = []
        for tid, group in trace_groups.items():
            bom = self.reconstruct(trace_id=tid, agent_id=agent_id)
            boms.append(bom)

        # For ungrouped entries, reconstruct individually by timestamp
        for entry in ungrouped:
            ts = entry.get("timestamp")
            if isinstance(ts, str):
                ts = datetime.fromisoformat(ts)
            if ts:
                bom = self.reconstruct(agent_id=agent_id, timestamp=ts)
                boms.append(bom)

        boms.sort(key=lambda b: b.timestamp)
        return boms

    # ------------------------------------------------------------------
    # Private: Source gathering
    # ------------------------------------------------------------------

    def _gather_audit(
        self,
        trace_id: Optional[str],
        agent_id: Optional[str],
        timestamp: Optional[datetime],
        window: float,
    ) -> list[dict[str, Any]]:
        if not self._audit:
            return []

        if trace_id:
            return self._audit.query_by_trace(trace_id)

        if agent_id and timestamp:
            from datetime import timedelta

            start = timestamp - timedelta(seconds=window)
            end = timestamp + timedelta(seconds=window)
            return self._audit.query_by_agent(agent_id, start, end)

        return []

    def _gather_trust(
        self, agent_id: str, timestamp: datetime
    ) -> list[BOMField]:
        if not self._trust:
            return []

        fields = []
        score = self._trust.get_score_at(agent_id, timestamp)
        if score is not None:
            fields.append(BOMField(
                name="trust_score_at_decision",
                category=BOMFieldCategory.TRUST,
                value=score,
                source="trust",
            ))

        # Get recent trend (last 60 seconds)
        from datetime import timedelta

        history = self._trust.get_score_history(
            agent_id, timestamp - timedelta(seconds=60), timestamp
        )
        if len(history) >= 2:
            trend = history[-1].get("score", 0) - history[0].get("score", 0)
            fields.append(BOMField(
                name="trust_score_trend",
                category=BOMFieldCategory.TRUST,
                value=trend,
                source="trust",
                inferred=True,
            ))

        return fields

    def _gather_policy(
        self, trace_id: Optional[str], timestamp: Optional[datetime]
    ) -> list[BOMField]:
        if not self._policy:
            return []

        fields = []

        if trace_id:
            evals = self._policy.get_evaluations(trace_id)
            if evals:
                fields.append(BOMField(
                    name="policy_rules_evaluated",
                    category=BOMFieldCategory.POLICY,
                    value=[e.get("rule_name", "unknown") for e in evals],
                    source="policy",
                ))
                # Extract the decision outcome
                decisions = [e.get("decision") for e in evals if e.get("decision")]
                if decisions:
                    # If any deny, outcome is deny
                    if "deny" in decisions:
                        outcome = "deny"
                    elif "alert" in decisions:
                        outcome = "alert"
                    else:
                        outcome = "allow"
                    fields.append(BOMField(
                        name="decision_outcome",
                        category=BOMFieldCategory.OUTCOME,
                        value=outcome,
                        source="policy",
                    ))

        if timestamp:
            active = self._policy.get_active_policies_at(timestamp)
            if active:
                fields.append(BOMField(
                    name="active_policies",
                    category=BOMFieldCategory.POLICY,
                    value=[p.get("name", "unknown") for p in active],
                    source="policy",
                ))

        return fields

    def _gather_trace(self, trace_id: str) -> list[BOMField]:
        if not self._trace:
            return []

        fields = []
        spans = self._trace.get_spans(trace_id)
        if spans:
            fields.append(BOMField(
                name="otel_trace_id",
                category=BOMFieldCategory.LINEAGE,
                value=trace_id,
                source="trace",
            ))
            # Compute total latency from first to last span
            start_times = [s.get("start_time") for s in spans if s.get("start_time")]
            end_times = [s.get("end_time") for s in spans if s.get("end_time")]
            if start_times and end_times:
                latency = max(end_times) - min(start_times)
                fields.append(BOMField(
                    name="latency_ms",
                    category=BOMFieldCategory.CONTEXT,
                    value=latency,
                    source="trace",
                    inferred=True,
                ))

        return fields

    # ------------------------------------------------------------------
    # Private: Extraction helpers
    # ------------------------------------------------------------------

    def _extract_from_audit(self, entries: list[dict]) -> list[BOMField]:
        """Extract BOM fields from audit log entries."""
        fields = []
        if not entries:
            return fields

        # Use the primary entry (first one, typically the decision event)
        primary = entries[0]

        if primary.get("agent_did"):
            fields.append(BOMField(
                name="agent_identity",
                category=BOMFieldCategory.IDENTITY,
                value=primary["agent_did"],
                source="audit",
            ))

        if primary.get("action"):
            fields.append(BOMField(
                name="action_type",
                category=BOMFieldCategory.ACTION,
                value=primary["action"],
                source="audit",
            ))

        if primary.get("resource"):
            fields.append(BOMField(
                name="resource_target",
                category=BOMFieldCategory.ACTION,
                value=primary["resource"],
                source="audit",
            ))

        if primary.get("outcome"):
            fields.append(BOMField(
                name="decision_outcome",
                category=BOMFieldCategory.OUTCOME,
                value=primary["outcome"],
                source="audit",
            ))

        if primary.get("policy_decision"):
            fields.append(BOMField(
                name="policy_decision",
                category=BOMFieldCategory.POLICY,
                value=primary["policy_decision"],
                source="audit",
            ))

        if primary.get("session_id"):
            fields.append(BOMField(
                name="session_context",
                category=BOMFieldCategory.CONTEXT,
                value=primary["session_id"],
                source="audit",
            ))

        # If multiple entries, capture delegation chain
        if len(entries) > 1:
            chain = [e.get("agent_did") for e in entries if e.get("agent_did")]
            if len(set(chain)) > 1:
                fields.append(BOMField(
                    name="delegation_chain",
                    category=BOMFieldCategory.LINEAGE,
                    value=list(dict.fromkeys(chain)),  # dedupe preserving order
                    source="audit",
                    inferred=True,
                ))

        return fields

    def _agent_from_audit(self, entries: list[dict]) -> Optional[str]:
        """Extract agent ID from audit entries."""
        for e in entries:
            if e.get("agent_did"):
                return e["agent_did"]
        return None

    def _time_from_audit(self, entries: list[dict]) -> Optional[datetime]:
        """Extract timestamp from audit entries."""
        for e in entries:
            ts = e.get("timestamp")
            if isinstance(ts, datetime):
                return ts
            if isinstance(ts, str):
                return datetime.fromisoformat(ts)
        return None

    def _find_field_value(
        self, fields: list[BOMField], name: str, default: Any
    ) -> Any:
        """Find a field by name and return its value."""
        for f in fields:
            if f.name == name:
                return f.value
        return default

    def _compute_completeness(self, fields: list[BOMField]) -> float:
        """Compute how complete the BOM is (0.0-1.0).

        Based on how many required fields are present.
        """
        if not REQUIRED_FIELDS:
            return 1.0

        found = sum(
            1 for req in REQUIRED_FIELDS
            if any(f.name == req for f in fields)
        )
        return found / len(REQUIRED_FIELDS)
