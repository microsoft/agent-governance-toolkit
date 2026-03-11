"""Tests for core modules that don't require openai-agents SDK."""

import time
import threading
from openai_agents_trust.identity import AgentIdentity
from openai_agents_trust.trust import TrustScorer, TrustScore
from openai_agents_trust.policy import GovernancePolicy
from openai_agents_trust.audit import AuditLog


# === Identity Tests ===

class TestAgentIdentity:
    def test_create_identity(self):
        identity = AgentIdentity(agent_id="agent-1", name="Researcher", secret_key="secret123")
        assert identity.agent_id == "agent-1"
        assert identity.name == "Researcher"

    def test_did_generation(self):
        identity = AgentIdentity(agent_id="agent-1", name="Test", secret_key="key")
        assert identity.did.startswith("did:agentmesh:")
        assert len(identity.did) > 14

    def test_did_deterministic(self):
        id1 = AgentIdentity(agent_id="same-id", name="A", secret_key="k1")
        id2 = AgentIdentity(agent_id="same-id", name="B", secret_key="k2")
        assert id1.did == id2.did

    def test_sign_and_verify(self):
        identity = AgentIdentity(agent_id="agent-1", name="Test", secret_key="secret")
        sig = identity.sign("hello world")
        assert identity.verify("hello world", sig)
        assert not identity.verify("different message", sig)

    def test_to_dict(self):
        identity = AgentIdentity(agent_id="a1", name="Test", secret_key="s")
        d = identity.to_dict()
        assert d["agent_id"] == "a1"
        assert d["did"].startswith("did:agentmesh:")
        assert "secret_key" not in d  # should not expose secret


# === Trust Tests ===

class TestTrustScore:
    def test_default_scores(self):
        score = TrustScore(agent_id="a1")
        assert score.overall == 1.0
        assert score.reliability == 1.0

    def test_compute_overall(self):
        score = TrustScore(agent_id="a1", reliability=0.8, capability=0.6)
        overall = score.compute_overall()
        assert 0.0 <= overall <= 1.0
        assert score.overall == overall

    def test_validation(self):
        try:
            TrustScore(agent_id="a1", overall=1.5)
            assert False, "Should have raised ValueError"
        except ValueError:
            pass

    def test_to_dict(self):
        score = TrustScore(agent_id="a1")
        d = score.to_dict()
        assert d["agent_id"] == "a1"
        assert all(k in d for k in ("overall", "reliability", "capability", "security"))


class TestTrustScorer:
    def test_get_score_creates_default(self):
        scorer = TrustScorer()
        score = scorer.get_score("agent-1")
        assert score.agent_id == "agent-1"
        assert score.overall == 1.0

    def test_record_success(self):
        scorer = TrustScorer(default_score=0.5)
        scorer.record_success("a1", boost=0.1)
        assert scorer.get_score("a1").reliability == 0.6

    def test_record_failure(self):
        scorer = TrustScorer()
        scorer.record_failure("a1", penalty=0.3)
        assert scorer.get_score("a1").reliability == 0.7

    def test_check_trust(self):
        scorer = TrustScorer()
        assert scorer.check_trust("a1", min_score=0.5)
        scorer.record_failure("a1", penalty=0.9)
        scorer.record_failure("a1", "capability", penalty=0.9)
        scorer.record_failure("a1", "security", penalty=0.9)
        assert not scorer.check_trust("a1", min_score=0.5)

    def test_score_capped(self):
        scorer = TrustScorer()
        for _ in range(100):
            scorer.record_success("a1", boost=0.1)
        assert scorer.get_score("a1").reliability == 1.0

    def test_score_floored(self):
        scorer = TrustScorer()
        for _ in range(100):
            scorer.record_failure("a1", penalty=0.1)
        assert scorer.get_score("a1").reliability == 0.0


# === Policy Tests ===

class TestGovernancePolicy:
    def test_default_policy(self):
        policy = GovernancePolicy()
        assert policy.max_tokens == 10000
        assert policy.max_tool_calls == 50

    def test_check_content_passes(self):
        policy = GovernancePolicy(blocked_patterns=[r"DROP TABLE"])
        assert policy.check_content("SELECT * FROM users") is None

    def test_check_content_blocks(self):
        policy = GovernancePolicy(blocked_patterns=[r"DROP TABLE", r"rm -rf"])
        result = policy.check_content("DROP TABLE users")
        assert result is not None
        assert "blocked pattern" in result

    def test_check_tool_allowed(self):
        policy = GovernancePolicy(allowed_tools=["search", "calculate"])
        assert policy.check_tool("search") is None

    def test_check_tool_blocked(self):
        policy = GovernancePolicy(allowed_tools=["search"])
        result = policy.check_tool("execute_code")
        assert result is not None
        assert "not in allowed" in result

    def test_check_tool_no_allowlist(self):
        policy = GovernancePolicy()
        assert policy.check_tool("anything") is None

    def test_to_dict(self):
        policy = GovernancePolicy(name="test", max_tokens=5000)
        d = policy.to_dict()
        assert d["name"] == "test"
        assert d["max_tokens"] == 5000


# === Audit Tests ===

class TestAuditLog:
    def test_record_entry(self):
        log = AuditLog()
        entry = log.record("a1", "tool_call", "allow")
        assert entry.agent_id == "a1"
        assert entry.decision == "allow"
        assert len(log) == 1

    def test_hash_chain(self):
        log = AuditLog()
        e1 = log.record("a1", "start", "allow")
        e2 = log.record("a1", "tool", "allow")
        assert e2.previous_hash == e1.entry_hash
        assert e1.previous_hash == ""

    def test_verify_chain(self):
        log = AuditLog()
        for i in range(10):
            log.record(f"agent-{i}", "action", "allow")
        assert log.verify_chain()

    def test_empty_chain_valid(self):
        log = AuditLog()
        assert log.verify_chain()

    def test_filter_by_agent(self):
        log = AuditLog()
        log.record("a1", "action1", "allow")
        log.record("a2", "action2", "deny")
        log.record("a1", "action3", "allow")
        entries = log.get_entries(agent_id="a1")
        assert len(entries) == 2

    def test_filter_by_decision(self):
        log = AuditLog()
        log.record("a1", "action1", "allow")
        log.record("a1", "action2", "deny")
        entries = log.get_entries(decision="deny")
        assert len(entries) == 1

    def test_limit(self):
        log = AuditLog()
        for i in range(20):
            log.record("a1", f"action-{i}", "allow")
        entries = log.get_entries(limit=5)
        assert len(entries) == 5

    def test_thread_safety(self):
        log = AuditLog()
        def writer(n):
            for i in range(50):
                log.record(f"agent-{n}", f"action-{i}", "allow")

        threads = [threading.Thread(target=writer, args=(i,)) for i in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(log) == 200
        assert log.verify_chain()

    def test_entry_to_dict(self):
        log = AuditLog()
        entry = log.record("a1", "test", "allow", {"key": "value"})
        d = entry.to_dict()
        assert d["agent_id"] == "a1"
        assert d["details"]["key"] == "value"
        assert d["entry_hash"] != ""
