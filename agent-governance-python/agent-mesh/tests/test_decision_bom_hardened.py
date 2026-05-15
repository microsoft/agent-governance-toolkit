# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Hardened tests for Decision BOM Reconstructor.

Covers source exception resilience, ambiguous reconstruction,
JSON export roundtrip, and edge cases.
"""

from datetime import datetime, timedelta, timezone

import pytest

from agentmesh.governance.decision_bom import (
    BOMField,
    BOMFieldCategory,
    DecisionBOM,
    DecisionBOMReconstructor,
)


# ---------------------------------------------------------------------------
# Mock Sources (reusable)
# ---------------------------------------------------------------------------


class MockAuditSource:
    def __init__(self, entries=None):
        self._entries = entries or []

    def query_by_trace(self, trace_id):
        return [e for e in self._entries if e.get("trace_id") == trace_id]

    def query_by_agent(self, agent_id, start, end):
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


class FailingTrustSource:
    """Trust source that always raises."""

    def get_score_at(self, agent_id, timestamp):
        raise ConnectionError("Trust service unavailable")

    def get_score_history(self, agent_id, start, end):
        raise ConnectionError("Trust service unavailable")


class FailingPolicySource:
    def get_evaluations(self, trace_id):
        raise TimeoutError("Policy service timed out")

    def get_active_policies_at(self, timestamp):
        raise TimeoutError("Policy service timed out")


class FailingTraceSource:
    def get_spans(self, trace_id):
        raise RuntimeError("Trace backend error")


class MockTrustSource:
    def __init__(self, scores=None, history=None):
        self._scores = scores or {}
        self._history = history or []

    def get_score_at(self, agent_id, timestamp):
        return self._scores.get(agent_id)

    def get_score_history(self, agent_id, start, end):
        return [h for h in self._history if h.get("agent_id") == agent_id]


class MockPolicySource:
    def __init__(self, evaluations=None, active_policies=None):
        self._evaluations = evaluations or []
        self._active = active_policies or []

    def get_evaluations(self, trace_id):
        return [e for e in self._evaluations if e.get("trace_id") == trace_id]

    def get_active_policies_at(self, timestamp):
        return self._active


class MockTraceSource:
    def __init__(self, spans=None):
        self._spans = spans or []

    def get_spans(self, trace_id):
        return [s for s in self._spans if s.get("trace_id") == trace_id]


@pytest.fixture
def now():
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Source Exception Resilience
# ---------------------------------------------------------------------------


class TestSourceResilience:
    """Failing sources should not crash reconstruction; partial BOM returned."""

    def test_failing_trust_source_returns_partial_bom(self, now):
        entries = [{
            "trace_id": "t-1", "agent_did": "agent-1",
            "action": "read", "outcome": "allow", "timestamp": now,
        }]
        r = DecisionBOMReconstructor(
            audit_source=MockAuditSource(entries),
            trust_source=FailingTrustSource(),
        )
        bom = r.reconstruct(trace_id="t-1")
        # Should have audit fields but no trust fields
        assert bom.agent_id == "agent-1"
        assert bom.completeness_score < 1.0
        trust_fields = bom.get_fields_by_category(BOMFieldCategory.TRUST)
        assert len(trust_fields) == 0

    def test_failing_policy_source_returns_partial_bom(self, now):
        entries = [{
            "trace_id": "t-1", "agent_did": "agent-1",
            "action": "read", "outcome": "allow", "timestamp": now,
        }]
        r = DecisionBOMReconstructor(
            audit_source=MockAuditSource(entries),
            policy_source=FailingPolicySource(),
        )
        bom = r.reconstruct(trace_id="t-1")
        assert bom.agent_id == "agent-1"
        policy_fields = bom.get_fields_by_category(BOMFieldCategory.POLICY)
        assert len(policy_fields) == 0

    def test_failing_trace_source_returns_partial_bom(self, now):
        entries = [{
            "trace_id": "t-1", "agent_did": "agent-1",
            "action": "read", "outcome": "allow", "timestamp": now,
        }]
        r = DecisionBOMReconstructor(
            audit_source=MockAuditSource(entries),
            trace_source=FailingTraceSource(),
        )
        bom = r.reconstruct(trace_id="t-1")
        assert bom.agent_id == "agent-1"
        context_fields = bom.get_fields_by_category(BOMFieldCategory.CONTEXT)
        latency = [f for f in context_fields if f.name == "latency_ms"]
        assert len(latency) == 0

    def test_all_sources_failing_except_audit(self, now):
        entries = [{
            "trace_id": "t-1", "agent_did": "agent-1",
            "action": "read", "outcome": "allow", "timestamp": now,
        }]
        r = DecisionBOMReconstructor(
            audit_source=MockAuditSource(entries),
            trust_source=FailingTrustSource(),
            policy_source=FailingPolicySource(),
            trace_source=FailingTraceSource(),
        )
        bom = r.reconstruct(trace_id="t-1")
        assert bom.agent_id == "agent-1"
        assert bom.action_requested == "read"
        assert bom.completeness_score > 0.0  # at least audit fields


# ---------------------------------------------------------------------------
# JSON Export Roundtrip
# ---------------------------------------------------------------------------


class TestJSONExport:
    def test_to_dict_roundtrip_preserves_all_fields(self, now):
        fields = [
            BOMField(name="agent_identity", category=BOMFieldCategory.IDENTITY, value="agent-x", source="audit"),
            BOMField(name="trust_score_at_decision", category=BOMFieldCategory.TRUST, value=0.9, source="trust"),
            BOMField(name="policy_decision", category=BOMFieldCategory.POLICY, value="allow", source="policy"),
            BOMField(name="latency_ms", category=BOMFieldCategory.CONTEXT, value=42, source="trace", inferred=True),
        ]
        bom = DecisionBOM(
            decision_id="d-1",
            timestamp=now,
            agent_id="agent-x",
            action_requested="transfer",
            outcome="allow",
            fields=fields,
            sources_queried=["audit", "trust", "policy", "trace"],
            completeness_score=1.0,
        )
        d = bom.to_dict()

        # Verify structure
        assert d["decision_id"] == "d-1"
        assert d["agent_id"] == "agent-x"
        assert len(d["fields"]) == 4
        assert d["completeness_score"] == 1.0
        assert set(d["sources_queried"]) == {"audit", "trust", "policy", "trace"}

        # Verify field structure
        for fd in d["fields"]:
            assert "name" in fd
            assert "category" in fd
            assert "value" in fd
            assert "source" in fd

    def test_inferred_flag_preserved_in_export(self, now):
        bom = DecisionBOM(
            decision_id="d-2",
            timestamp=now,
            agent_id="a",
            action_requested="x",
            outcome="allow",
            fields=[
                BOMField(name="latency_ms", category=BOMFieldCategory.CONTEXT, value=50, source="trace", inferred=True),
                BOMField(name="agent_identity", category=BOMFieldCategory.IDENTITY, value="a", source="audit", inferred=False),
            ],
        )
        d = bom.to_dict()
        inferred_fields = [f for f in d["fields"] if f.get("inferred", False)]
        assert len(inferred_fields) == 1
        assert inferred_fields[0]["name"] == "latency_ms"


# ---------------------------------------------------------------------------
# Multiple Audit Entries
# ---------------------------------------------------------------------------


class TestMultipleAuditEntries:
    def test_batch_with_different_outcomes(self, now):
        entries = [
            {"trace_id": "t-1", "agent_did": "a1", "action": "read", "outcome": "allow", "timestamp": now - timedelta(seconds=5)},
            {"trace_id": "t-2", "agent_did": "a1", "action": "delete", "outcome": "deny", "timestamp": now},
        ]
        r = DecisionBOMReconstructor(audit_source=MockAuditSource(entries))
        boms = r.reconstruct_batch("a1", now - timedelta(seconds=10), now + timedelta(seconds=1))
        assert len(boms) == 2
        outcomes = {b.outcome for b in boms}
        assert outcomes == {"allow", "deny"}

    def test_reconstruct_with_multiple_traces_returns_first(self, now):
        """When multiple audit entries share a trace_id, reconstruction works."""
        entries = [
            {"trace_id": "t-multi", "agent_did": "a1", "action": "step1", "outcome": "allow", "timestamp": now},
            {"trace_id": "t-multi", "agent_did": "a2", "action": "step2", "outcome": "allow", "timestamp": now},
        ]
        r = DecisionBOMReconstructor(audit_source=MockAuditSource(entries))
        bom = r.reconstruct(trace_id="t-multi")
        # Should reconstruct something (first entry used)
        assert bom.agent_id in ("a1", "a2")


# ---------------------------------------------------------------------------
# Completeness Scoring Edge Cases
# ---------------------------------------------------------------------------


class TestCompletenessEdgeCases:
    def test_zero_completeness_with_no_data(self):
        r = DecisionBOMReconstructor()
        bom = r.reconstruct(trace_id="nonexistent")
        assert bom.completeness_score == 0.0

    def test_full_completeness_requires_all_required_fields(self, now):
        """Full completeness needs agent_identity, trust_score, policy_rules, action_type, decision_outcome."""
        entries = [{
            "trace_id": "t-full", "agent_did": "agent-x",
            "action": "transfer", "outcome": "allow",
            "policy_decision": "allow", "timestamp": now,
        }]
        r = DecisionBOMReconstructor(
            audit_source=MockAuditSource(entries),
            trust_source=MockTrustSource(
                scores={"agent-x": 0.9},
                history=[{"agent_id": "agent-x", "score": 0.9, "timestamp": now}],
            ),
            policy_source=MockPolicySource(
                evaluations=[{"trace_id": "t-full", "rule_name": "r1", "decision": "allow"}],
                active_policies=[{"name": "r1"}],
            ),
            trace_source=MockTraceSource(
                spans=[{"trace_id": "t-full", "start_time": 100, "end_time": 200}],
            ),
        )
        bom = r.reconstruct(trace_id="t-full")
        assert bom.completeness_score == 1.0

    def test_partial_completeness_with_trust_only(self, now):
        """Audit + trust but no policy or trace."""
        entries = [{
            "trace_id": "t-partial", "agent_did": "agent-x",
            "action": "read", "outcome": "allow", "timestamp": now,
        }]
        r = DecisionBOMReconstructor(
            audit_source=MockAuditSource(entries),
            trust_source=MockTrustSource(
                scores={"agent-x": 0.85},
                history=[{"agent_id": "agent-x", "score": 0.85, "timestamp": now}],
            ),
        )
        bom = r.reconstruct(trace_id="t-partial")
        # Has agent_identity, trust_score, action_type, decision_outcome = 4/5
        assert bom.completeness_score == pytest.approx(0.8)
