#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Example: Data Quality-Aware Agent Governance

Demonstrates combining AGT policy evaluation with an external data quality
signal as a two-layer governance decision point.

The policy engine answers: Is this agent authorized to perform this action?
The data quality registry answers: Is the target dataset trustworthy right now?

Both layers must pass. A fully authorized agent is still blocked if the
target dataset fails freshness or validation checks.

Pattern origin: AGT Discussion #1795, #814
CTEF alignment: data-quality scheme in CTEF v0.3.2 source_version registry
               carries the integrity hash (a2aproject/A2A#1786)
"""

import sys
import json
import asyncio
from pathlib import Path
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional

# Add the control-plane module to path
# In a real deployment this would be installed as a package
sys.path.insert(
    0,
    str(
        Path(__file__).parent.parent.parent
        / "agent-governance-python"
        / "agent-os"
        / "modules"
        / "control-plane"
        / "src"
    ),
)

from agent_control_plane.kernel_space import KernelSpace, SyscallRequest, SyscallType
from agent_control_plane.policy_engine import PolicyEngine
from agent_control_plane.signals import AgentKernelPanic


# ---------------------------------------------------------------------------
# Data Quality Registry (simulated)
# In production this would pull from dbt artifacts or a metadata catalog
# ---------------------------------------------------------------------------

@dataclass
class DatasetQualitySnapshot:
    """
    Represents the quality state of a dataset at a point in time.
    
    In production: sourced from dbt run results, Great Expectations,
    or a metadata catalog like Atlan or DataHub.
    """
    dataset_id: str
    owner_did: str                    # dataset_owner_did for CTEF source_version
    freshness_at: datetime            # Last successful validation timestamp
    freshness_threshold_hours: float  # Max acceptable staleness
    quality_score: float              # 0.0 - 1.0
    quality_threshold: float          # Minimum acceptable score
    failed_tests: list[str]           # Names of failed validation tests
    validation_status: str            # "pass" | "warn" | "fail"

    @property
    def is_fresh(self) -> bool:
        age_hours = (datetime.now() - self.freshness_at).total_seconds() / 3600
        return age_hours <= self.freshness_threshold_hours

    @property
    def meets_quality_threshold(self) -> bool:
        return self.quality_score >= self.quality_threshold

    @property
    def is_trustworthy(self) -> bool:
        return self.is_fresh and self.meets_quality_threshold and not self.failed_tests


class DataQualityRegistry:
    """
    Simulated data quality registry.
    
    Mirrors the kind of metadata a dbt-based governance platform
    exposes at runtime: freshness threshold, quality score,
    failed test names, dataset owner.
    """

    def __init__(self):
        self._datasets: dict[str, DatasetQualitySnapshot] = {}

    def register(self, snapshot: DatasetQualitySnapshot):
        self._datasets[snapshot.dataset_id] = snapshot

    def get(self, dataset_id: str) -> Optional[DatasetQualitySnapshot]:
        return self._datasets.get(dataset_id)


# ---------------------------------------------------------------------------
# Audit Log
# ---------------------------------------------------------------------------

@dataclass
class AuditEntry:
    timestamp: str
    agent_id: str
    action: str
    dataset_id: str
    layer: str          # "agt_policy" | "data_quality" | "unified"
    decision: str       # "allowed" | "blocked"
    reason: str


class AuditLog:
    def __init__(self):
        self._entries: list[AuditEntry] = []

    def record(self, entry: AuditEntry):
        self._entries.append(entry)
        status = "✓ ALLOWED" if entry.decision == "allowed" else "✗ BLOCKED"
        print(f"  [{entry.layer.upper()}] {status} — {entry.reason}")

    def summary(self):
        print("\n--- Audit Log Summary ---")
        for e in self._entries:
            print(
                f"  {e.timestamp} | {e.agent_id} | {e.action} on {e.dataset_id} "
                f"| {e.layer} | {e.decision} | {e.reason}"
            )


# ---------------------------------------------------------------------------
# Two-Layer Governance Check
# ---------------------------------------------------------------------------

async def governed_query(
    kernel: KernelSpace,
    policy_engine: PolicyEngine,
    quality_registry: DataQualityRegistry,
    audit_log: AuditLog,
    agent_id: str,
    action: str,
    dataset_id: str,
) -> dict:
    """
    Execute a two-layer governance check before allowing an agent action.

    Layer 1 — AGT Policy: Is this agent authorized for this action?
    Layer 2 — Data Quality: Is the target dataset trustworthy right now?

    Returns a result dict with decision and reason.
    """
    timestamp = datetime.now().isoformat()

    print(f"\nAgent '{agent_id}' requesting '{action}' on dataset '{dataset_id}'")

    # ------------------------------------------------------------------
    # Layer 1: AGT Policy Evaluation
    # ------------------------------------------------------------------
    violation = policy_engine.check_violation(
        agent_role=agent_id,
        tool_name=action,
        args={"dataset": dataset_id},
    )

    if violation:
        audit_log.record(AuditEntry(
            timestamp=timestamp,
            agent_id=agent_id,
            action=action,
            dataset_id=dataset_id,
            layer="agt_policy",
            decision="blocked",
            reason=violation,
        ))
        return {"decision": "blocked", "layer": "agt_policy", "reason": violation}

    audit_log.record(AuditEntry(
        timestamp=timestamp,
        agent_id=agent_id,
        action=action,
        dataset_id=dataset_id,
        layer="agt_policy",
        decision="allowed",
        reason="Agent authorized for action",
    ))

    # ------------------------------------------------------------------
    # Layer 2: Data Quality Check
    # ------------------------------------------------------------------
    snapshot = quality_registry.get(dataset_id)

    if snapshot is None:
        reason = f"Dataset '{dataset_id}' not registered in quality registry"
        audit_log.record(AuditEntry(
            timestamp=timestamp,
            agent_id=agent_id,
            action=action,
            dataset_id=dataset_id,
            layer="data_quality",
            decision="blocked",
            reason=reason,
        ))
        return {"decision": "blocked", "layer": "data_quality", "reason": reason}

    if not snapshot.is_fresh:
        age_hours = (datetime.now() - snapshot.freshness_at).total_seconds() / 3600
        reason = (
            f"Dataset stale by {age_hours:.1f}h "
            f"(threshold: {snapshot.freshness_threshold_hours}h)"
        )
        audit_log.record(AuditEntry(
            timestamp=timestamp,
            agent_id=agent_id,
            action=action,
            dataset_id=dataset_id,
            layer="data_quality",
            decision="blocked",
            reason=reason,
        ))
        return {"decision": "blocked", "layer": "data_quality", "reason": reason}

    if not snapshot.meets_quality_threshold:
        reason = (
            f"Quality score {snapshot.quality_score} below threshold "
            f"{snapshot.quality_threshold}"
        )
        audit_log.record(AuditEntry(
            timestamp=timestamp,
            agent_id=agent_id,
            action=action,
            dataset_id=dataset_id,
            layer="data_quality",
            decision="blocked",
            reason=reason,
        ))
        return {"decision": "blocked", "layer": "data_quality", "reason": reason}

    if snapshot.failed_tests:
        reason = f"Failed validation tests: {', '.join(snapshot.failed_tests)}"
        audit_log.record(AuditEntry(
            timestamp=timestamp,
            agent_id=agent_id,
            action=action,
            dataset_id=dataset_id,
            layer="data_quality",
            decision="blocked",
            reason=reason,
        ))
        return {"decision": "blocked", "layer": "data_quality", "reason": reason}

    # Both layers passed
    audit_log.record(AuditEntry(
        timestamp=timestamp,
        agent_id=agent_id,
        action=action,
        dataset_id=dataset_id,
        layer="data_quality",
        decision="allowed",
        reason=(
            f"Fresh ({snapshot.freshness_at.strftime('%Y-%m-%dT%H:%M:%S')}), "
            f"score {snapshot.quality_score}, "
            f"all tests passing"
        ),
    ))

    return {
        "decision": "allowed",
        "layer": "unified",
        "reason": "Both AGT policy and data quality checks passed",
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

async def main():
    print("=" * 60)
    print("Data Quality-Aware Agent Governance — Example")
    print("=" * 60)

    # ------------------------------------------------------------------
    # Setup: Policy Engine
    # ------------------------------------------------------------------
    policy_engine = PolicyEngine()

    # analyst-agent-01 is authorized to run database_query
    policy_engine.add_constraint(
        "analyst-agent-01",
        ["database_query", "report_generate"],
    )

    # report-agent-02 is authorized but only for reporting
    policy_engine.add_constraint(
        "report-agent-02",
        ["report_generate"],
    )

    policy_engine.freeze()  # Lock policy — no runtime self-modification

    # ------------------------------------------------------------------
    # Setup: Kernel
    # ------------------------------------------------------------------
    kernel = KernelSpace(policy_engine=policy_engine)

    # ------------------------------------------------------------------
    # Setup: Data Quality Registry
    # Simulates what a dbt-based governance platform would expose
    # ------------------------------------------------------------------
    registry = DataQualityRegistry()

    # user_events: STALE and FAILING — should be blocked
    registry.register(DatasetQualitySnapshot(
        dataset_id="user_events",
        owner_did="did:web:analytics.example.com",
        freshness_at=datetime.now() - timedelta(hours=14),  # 14h stale
        freshness_threshold_hours=6.0,
        quality_score=0.72,
        quality_threshold=0.85,
        failed_tests=["not_null_user_id", "accepted_values_event_type"],
        validation_status="fail",
    ))

    # revenue_metrics: FRESH and PASSING — should be allowed
    registry.register(DatasetQualitySnapshot(
        dataset_id="revenue_metrics",
        owner_did="did:web:finance.example.com",
        freshness_at=datetime.now() - timedelta(hours=1),  # 1h fresh
        freshness_threshold_hours=6.0,
        quality_score=0.97,
        quality_threshold=0.85,
        failed_tests=[],
        validation_status="pass",
    ))

    audit_log = AuditLog()

    # ------------------------------------------------------------------
    # Scenario 1: Authorized agent, FAILING dataset → blocked at Layer 2
    # ------------------------------------------------------------------
    print("\n--- Scenario 1: Authorized agent, stale/failing dataset ---")
    result = await governed_query(
        kernel, policy_engine, registry, audit_log,
        agent_id="analyst-agent-01",
        action="database_query",
        dataset_id="user_events",
    )
    print(f"  Final decision: {result['decision'].upper()} ({result['layer']})")

    # ------------------------------------------------------------------
    # Scenario 2: Authorized agent, PASSING dataset → allowed
    # ------------------------------------------------------------------
    print("\n--- Scenario 2: Authorized agent, fresh/passing dataset ---")
    result = await governed_query(
        kernel, policy_engine, registry, audit_log,
        agent_id="analyst-agent-01",
        action="database_query",
        dataset_id="revenue_metrics",
    )
    print(f"  Final decision: {result['decision'].upper()} ({result['layer']})")

    # ------------------------------------------------------------------
    # Scenario 3: Unauthorized agent → blocked at Layer 1
    # ------------------------------------------------------------------
    print("\n--- Scenario 3: Unauthorized agent (blocked at AGT layer) ---")
    result = await governed_query(
        kernel, policy_engine, registry, audit_log,
        agent_id="report-agent-02",
        action="database_query",       # Not in report-agent-02's allowed tools
        dataset_id="revenue_metrics",
    )
    print(f"  Final decision: {result['decision'].upper()} ({result['layer']})")

    # ------------------------------------------------------------------
    # Audit log
    # ------------------------------------------------------------------
    audit_log.summary()

    print("\n" + "=" * 60)
    print("Key insight: Scenario 1 shows why authorization alone is not enough.")
    print("The agent was permitted. The data was not trustworthy.")
    print("Without Layer 2, the agent queries broken data with a clean audit trail.")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
