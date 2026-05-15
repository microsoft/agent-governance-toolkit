"""Decision Bill of Materials (BOM) Demo.

Reconstructs the full decision context from existing observability signals:
audit logs, trust scores, policy evaluations, and OTel traces. Non-invasive
approach that requires no changes to agents.

Usage:
    pip install agentmesh-platform
    python examples/decision-bom/decision_bom_demo.py
"""

import json
from datetime import datetime, timedelta, timezone

from agentmesh.governance.decision_bom import (
    BOMFieldCategory,
    DecisionBOMReconstructor,
)


# ---------------------------------------------------------------------------
# In-Memory Signal Sources (replace with your real backends)
# ---------------------------------------------------------------------------


class InMemoryAuditSource:
    def __init__(self):
        self.entries: list[dict] = []

    def query_by_trace(self, trace_id: str) -> list[dict]:
        return [e for e in self.entries if e.get("trace_id") == trace_id]

    def query_by_agent(self, agent_id: str, start: datetime, end: datetime) -> list[dict]:
        return [
            e for e in self.entries
            if e.get("agent_did") == agent_id
            and start <= e.get("timestamp", start) <= end
        ]


class InMemoryTrustSource:
    def __init__(self):
        self.scores: dict[str, float] = {}
        self.history: list[dict] = []

    def get_score_at(self, agent_id: str, timestamp: datetime) -> float | None:
        return self.scores.get(agent_id)

    def get_score_history(self, agent_id: str, start: datetime, end: datetime) -> list[dict]:
        return [h for h in self.history if h.get("agent_id") == agent_id]


class InMemoryPolicySource:
    def __init__(self):
        self.evaluations: list[dict] = []
        self.active_policies: list[dict] = []

    def get_evaluations(self, trace_id: str) -> list[dict]:
        return [e for e in self.evaluations if e.get("trace_id") == trace_id]

    def get_active_policies_at(self, timestamp: datetime) -> list[dict]:
        return self.active_policies


class InMemoryTraceSource:
    def __init__(self):
        self.spans: list[dict] = []

    def get_spans(self, trace_id: str) -> list[dict]:
        return [s for s in self.spans if s.get("trace_id") == trace_id]


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------


def main():
    now = datetime.now(timezone.utc)

    print("=" * 60)
    print("  Decision BOM Reconstructor Demo")
    print("=" * 60)

    # --- Set up signal sources ---
    audit = InMemoryAuditSource()
    audit.entries = [
        {
            "trace_id": "trace-abc-123",
            "agent_did": "did:mesh:payment-agent",
            "action": "transfer_funds",
            "resource": "account:checking",
            "outcome": "allow",
            "policy_decision": "allow",
            "session_id": "session-42",
            "timestamp": now,
        },
        {
            "trace_id": "trace-def-456",
            "agent_did": "did:mesh:payment-agent",
            "action": "read_balance",
            "outcome": "allow",
            "timestamp": now - timedelta(seconds=10),
        },
    ]

    trust = InMemoryTrustSource()
    trust.scores = {"did:mesh:payment-agent": 0.85}
    trust.history = [
        {"agent_id": "did:mesh:payment-agent", "score": 0.80},
        {"agent_id": "did:mesh:payment-agent", "score": 0.85},
    ]

    policy = InMemoryPolicySource()
    policy.evaluations = [
        {"trace_id": "trace-abc-123", "rule_name": "max-transfer", "decision": "allow"},
        {"trace_id": "trace-abc-123", "rule_name": "rate-limit", "decision": "allow"},
    ]
    policy.active_policies = [{"name": "max-transfer"}, {"name": "rate-limit"}]

    trace = InMemoryTraceSource()
    trace.spans = [
        {"trace_id": "trace-abc-123", "start_time": 100, "end_time": 150},
        {"trace_id": "trace-abc-123", "start_time": 110, "end_time": 200},
    ]

    # ---------------------------------------------------------------
    # 1. Partial BOM (audit only)
    # ---------------------------------------------------------------
    print("\n--- Partial BOM (audit only) ---")
    partial = DecisionBOMReconstructor(audit_source=audit)
    bom = partial.reconstruct(trace_id="trace-abc-123")
    print(f"  Agent:        {bom.agent_id}")
    print(f"  Action:       {bom.action_requested}")
    print(f"  Outcome:      {bom.outcome}")
    print(f"  Completeness: {bom.completeness_score:.0%}")
    print(f"  Sources:      {bom.sources_queried}")

    # ---------------------------------------------------------------
    # 2. Full BOM (all sources)
    # ---------------------------------------------------------------
    print("\n--- Full BOM (all 4 sources) ---")
    full = DecisionBOMReconstructor(
        audit_source=audit,
        trust_source=trust,
        policy_source=policy,
        trace_source=trace,
    )
    bom = full.reconstruct(trace_id="trace-abc-123")
    print(f"  Agent:        {bom.agent_id}")
    print(f"  Action:       {bom.action_requested}")
    print(f"  Outcome:      {bom.outcome}")
    print(f"  Completeness: {bom.completeness_score:.0%}")
    print(f"  Sources:      {bom.sources_queried}")

    print("\n  Fields by category:")
    for category in BOMFieldCategory:
        fields = bom.get_fields_by_category(category)
        if fields:
            print(f"    [{category.value}]")
            for f in fields:
                inferred = " (inferred)" if f.inferred else ""
                print(f"      {f.name}: {f.value}{inferred}")

    # ---------------------------------------------------------------
    # 3. Batch reconstruction
    # ---------------------------------------------------------------
    print("\n--- Batch Reconstruction ---")
    boms = full.reconstruct_batch(
        agent_id="did:mesh:payment-agent",
        start=now - timedelta(minutes=5),
        end=now + timedelta(seconds=1),
    )
    print(f"  Reconstructed {len(boms)} decisions:")
    for b in boms:
        print(f"    {b.action_requested}: {b.outcome} "
              f"(completeness: {b.completeness_score:.0%})")

    # ---------------------------------------------------------------
    # 4. Export to JSON
    # ---------------------------------------------------------------
    print("\n--- JSON Export (truncated) ---")
    export = bom.to_dict()
    # Show just the structure, not full content
    print(f"  Keys: {list(export.keys())}")
    print(f"  Fields count: {len(export['fields'])}")
    print(f"  Sample field: {json.dumps(export['fields'][0], default=str)}")

    print(f"\n{'=' * 60}")
    print("  Demo complete!")
    print(f"{'=' * 60}")


if __name__ == "__main__":
    main()
