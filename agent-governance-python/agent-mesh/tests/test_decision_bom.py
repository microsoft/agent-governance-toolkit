# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for Decision BOM Reconstructor."""

from datetime import datetime, timedelta, timezone

import pytest

from agentmesh.governance.decision_bom import (
    BOMField,
    BOMFieldCategory,
    DecisionBOM,
    DecisionBOMReconstructor,
    REQUIRED_FIELDS,
    OPTIONAL_FIELDS,
)


# ---------------------------------------------------------------------------
# Mock Sources
# ---------------------------------------------------------------------------


class MockAuditSource:
    """Mock audit source for testing."""

    def __init__(self, entries: list[dict] | None = None):
        self._entries = entries or []

    def query_by_trace(self, trace_id: str) -> list[dict]:
        return [e for e in self._entries if e.get("trace_id") == trace_id]

    def query_by_agent(self, agent_id: str, start: datetime, end: datetime) -> list[dict]:
        results = []
        for e in self._entries:
            if e.get("agent_did") != agent_id:
                continue
            ts = e.get("timestamp")
            if isinstance(ts, str):
                ts = datetime.fromisoformat(ts)
            if ts and start <= ts <= end:
                results.append(e)
        return results


class MockTrustSource:
    """Mock trust source for testing."""

    def __init__(self, scores: dict[str, float] | None = None, history: list[dict] | None = None):
        self._scores = scores or {}
        self._history = history or []

    def get_score_at(self, agent_id: str, timestamp: datetime) -> float | None:
        return self._scores.get(agent_id)

    def get_score_history(self, agent_id: str, start: datetime, end: datetime) -> list[dict]:
        return [h for h in self._history if h.get("agent_id") == agent_id]


class MockPolicySource:
    """Mock policy source for testing."""

    def __init__(self, evaluations: list[dict] | None = None, active_policies: list[dict] | None = None):
        self._evaluations = evaluations or []
        self._active = active_policies or []

    def get_evaluations(self, trace_id: str) -> list[dict]:
        return [e for e in self._evaluations if e.get("trace_id") == trace_id]

    def get_active_policies_at(self, timestamp: datetime) -> list[dict]:
        return self._active


class MockTraceSource:
    """Mock trace source for testing."""

    def __init__(self, spans: list[dict] | None = None):
        self._spans = spans or []

    def get_spans(self, trace_id: str) -> list[dict]:
        return [s for s in self._spans if s.get("trace_id") == trace_id]


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def now():
    return datetime.now(timezone.utc)


@pytest.fixture
def audit_entries(now):
    return [
        {
            "trace_id": "trace-001",
            "agent_did": "did:mesh:agent-alpha",
            "action": "transfer_funds",
            "resource": "account:checking",
            "outcome": "allow",
            "policy_decision": "allow",
            "session_id": "session-xyz",
            "timestamp": now,
        }
    ]


@pytest.fixture
def full_reconstructor(audit_entries, now):
    return DecisionBOMReconstructor(
        audit_source=MockAuditSource(audit_entries),
        trust_source=MockTrustSource(
            scores={"did:mesh:agent-alpha": 0.85},
            history=[
                {"agent_id": "did:mesh:agent-alpha", "score": 0.80, "timestamp": now - timedelta(seconds=30)},
                {"agent_id": "did:mesh:agent-alpha", "score": 0.85, "timestamp": now},
            ],
        ),
        policy_source=MockPolicySource(
            evaluations=[
                {"trace_id": "trace-001", "rule_name": "max-transfer", "decision": "allow"},
                {"trace_id": "trace-001", "rule_name": "rate-limit", "decision": "allow"},
            ],
            active_policies=[{"name": "max-transfer"}, {"name": "rate-limit"}],
        ),
        trace_source=MockTraceSource(
            spans=[
                {"trace_id": "trace-001", "start_time": 100, "end_time": 150},
                {"trace_id": "trace-001", "start_time": 110, "end_time": 200},
            ]
        ),
    )


# ---------------------------------------------------------------------------
# DecisionBOM Model Tests
# ---------------------------------------------------------------------------


class TestDecisionBOM:
    def test_to_dict(self, now):
        bom = DecisionBOM(
            decision_id="d-1",
            timestamp=now,
            agent_id="agent-1",
            action_requested="read",
            outcome="allow",
            fields=[
                BOMField(name="trust_score_at_decision", category=BOMFieldCategory.TRUST, value=0.9, source="trust"),
            ],
            sources_queried=["audit", "trust"],
            completeness_score=0.6,
        )
        d = bom.to_dict()
        assert d["decision_id"] == "d-1"
        assert d["agent_id"] == "agent-1"
        assert d["outcome"] == "allow"
        assert len(d["fields"]) == 1
        assert d["fields"][0]["category"] == "trust"
        assert d["completeness_score"] == 0.6

    def test_get_fields_by_category(self, now):
        bom = DecisionBOM(
            decision_id="d-2",
            timestamp=now,
            agent_id="a",
            action_requested="x",
            outcome="deny",
            fields=[
                BOMField(name="f1", category=BOMFieldCategory.TRUST, value=1, source="s"),
                BOMField(name="f2", category=BOMFieldCategory.POLICY, value=2, source="s"),
                BOMField(name="f3", category=BOMFieldCategory.TRUST, value=3, source="s"),
            ],
        )
        trust_fields = bom.get_fields_by_category(BOMFieldCategory.TRUST)
        assert len(trust_fields) == 2


# ---------------------------------------------------------------------------
# Reconstructor Tests
# ---------------------------------------------------------------------------


class TestReconstructor:
    def test_requires_trace_or_agent_plus_time(self):
        r = DecisionBOMReconstructor()
        with pytest.raises(ValueError, match="Provide either trace_id"):
            r.reconstruct()

    def test_available_sources_empty(self):
        r = DecisionBOMReconstructor()
        assert r.available_sources == []

    def test_available_sources_all(self, full_reconstructor):
        assert set(full_reconstructor.available_sources) == {"audit", "trust", "policy", "trace"}

    def test_reconstruct_by_trace_id(self, full_reconstructor):
        bom = full_reconstructor.reconstruct(trace_id="trace-001")
        assert bom.agent_id == "did:mesh:agent-alpha"
        assert bom.action_requested == "transfer_funds"
        assert bom.outcome == "allow"
        assert "audit" in bom.sources_queried
        assert "trust" in bom.sources_queried
        assert "policy" in bom.sources_queried
        assert "trace" in bom.sources_queried

    def test_reconstruct_by_agent_and_time(self, audit_entries, now):
        r = DecisionBOMReconstructor(
            audit_source=MockAuditSource(audit_entries),
        )
        bom = r.reconstruct(agent_id="did:mesh:agent-alpha", timestamp=now)
        assert bom.agent_id == "did:mesh:agent-alpha"
        assert bom.action_requested == "transfer_funds"

    def test_trust_score_included(self, full_reconstructor):
        bom = full_reconstructor.reconstruct(trace_id="trace-001")
        trust_fields = bom.get_fields_by_category(BOMFieldCategory.TRUST)
        scores = [f for f in trust_fields if f.name == "trust_score_at_decision"]
        assert len(scores) == 1
        assert scores[0].value == 0.85

    def test_trust_trend_inferred(self, full_reconstructor):
        bom = full_reconstructor.reconstruct(trace_id="trace-001")
        trust_fields = bom.get_fields_by_category(BOMFieldCategory.TRUST)
        trends = [f for f in trust_fields if f.name == "trust_score_trend"]
        assert len(trends) == 1
        assert trends[0].inferred is True
        assert trends[0].value == pytest.approx(0.05)

    def test_policy_rules_evaluated(self, full_reconstructor):
        bom = full_reconstructor.reconstruct(trace_id="trace-001")
        policy_fields = bom.get_fields_by_category(BOMFieldCategory.POLICY)
        rules = [f for f in policy_fields if f.name == "policy_rules_evaluated"]
        assert len(rules) == 1
        assert "max-transfer" in rules[0].value
        assert "rate-limit" in rules[0].value

    def test_trace_latency(self, full_reconstructor):
        bom = full_reconstructor.reconstruct(trace_id="trace-001")
        context_fields = bom.get_fields_by_category(BOMFieldCategory.CONTEXT)
        latency = [f for f in context_fields if f.name == "latency_ms"]
        assert len(latency) == 1
        assert latency[0].value == 100  # max(200) - min(100)

    def test_completeness_score(self, full_reconstructor):
        bom = full_reconstructor.reconstruct(trace_id="trace-001")
        # Should have: agent_identity, trust_score_at_decision, policy_rules_evaluated,
        # action_type, decision_outcome = 5/5
        assert bom.completeness_score == 1.0

    def test_partial_completeness(self, now):
        # Only audit, no trust/policy
        r = DecisionBOMReconstructor(
            audit_source=MockAuditSource([{
                "trace_id": "t-1",
                "agent_did": "a-1",
                "action": "read",
                "outcome": "allow",
                "timestamp": now,
            }]),
        )
        bom = r.reconstruct(trace_id="t-1")
        # Has agent_identity, action_type, decision_outcome = 3/5
        assert bom.completeness_score == pytest.approx(0.6)

    def test_no_sources_returns_empty_bom(self):
        r = DecisionBOMReconstructor()
        bom = r.reconstruct(trace_id="nonexistent")
        assert bom.completeness_score == 0.0
        assert bom.fields == []

    def test_delegation_chain_inferred(self, now):
        entries = [
            {"trace_id": "t-2", "agent_did": "agent-a", "action": "delegate", "timestamp": now},
            {"trace_id": "t-2", "agent_did": "agent-b", "action": "execute", "timestamp": now},
        ]
        r = DecisionBOMReconstructor(audit_source=MockAuditSource(entries))
        bom = r.reconstruct(trace_id="t-2")
        lineage = bom.get_fields_by_category(BOMFieldCategory.LINEAGE)
        chains = [f for f in lineage if f.name == "delegation_chain"]
        assert len(chains) == 1
        assert chains[0].value == ["agent-a", "agent-b"]
        assert chains[0].inferred is True


# ---------------------------------------------------------------------------
# Batch Reconstruction Tests
# ---------------------------------------------------------------------------


class TestBatchReconstruction:
    def test_reconstruct_batch(self, now):
        entries = [
            {"trace_id": "t-1", "agent_did": "agent-x", "action": "read", "outcome": "allow", "timestamp": now - timedelta(seconds=10)},
            {"trace_id": "t-2", "agent_did": "agent-x", "action": "write", "outcome": "deny", "timestamp": now},
        ]
        r = DecisionBOMReconstructor(audit_source=MockAuditSource(entries))
        boms = r.reconstruct_batch("agent-x", now - timedelta(seconds=30), now + timedelta(seconds=1))
        assert len(boms) == 2
        assert boms[0].timestamp <= boms[1].timestamp

    def test_batch_empty_when_no_audit(self):
        r = DecisionBOMReconstructor()
        boms = r.reconstruct_batch("agent-x", datetime.now(timezone.utc) - timedelta(hours=1), datetime.now(timezone.utc))
        assert boms == []


# ---------------------------------------------------------------------------
# Field Definitions Tests
# ---------------------------------------------------------------------------


class TestFieldDefinitions:
    def test_required_fields_defined(self):
        assert len(REQUIRED_FIELDS) == 5
        assert "agent_identity" in REQUIRED_FIELDS
        assert "trust_score_at_decision" in REQUIRED_FIELDS

    def test_optional_fields_defined(self):
        assert len(OPTIONAL_FIELDS) >= 5
        assert "delegation_chain" in OPTIONAL_FIELDS
        assert "cost_incurred" in OPTIONAL_FIELDS

    def test_no_overlap(self):
        assert not set(REQUIRED_FIELDS) & set(OPTIONAL_FIELDS)
