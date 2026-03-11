"""
Tests for A2A AgentMesh integration.

Covers: AgentCard, AgentSkill, TaskEnvelope, TaskState, TrustGate, TrustPolicy
No external dependencies — pure unit tests.

Run with: python -m pytest tests/ -v --tb=short
"""

import json
import time

import pytest

from a2a_agentmesh.agent_card import AgentCard, AgentSkill
from a2a_agentmesh.task import TaskEnvelope, TaskMessage, TaskState
from a2a_agentmesh.trust_gate import TrustGate, TrustPolicy, TrustResult


# =============================================================================
# AgentSkill
# =============================================================================


class TestAgentSkill:
    def test_basic(self):
        s = AgentSkill(id="search", name="Web Search")
        assert s.id == "search"
        assert s.name == "Web Search"

    def test_to_dict(self):
        s = AgentSkill(
            id="extract",
            name="Extract Data",
            description="Extracts data from documents",
            tags=["nlp", "extraction"],
            input_modes=["application/pdf"],
            output_modes=["application/json"],
            examples=["Extract invoice totals"],
        )
        d = s.to_dict()
        assert d["id"] == "extract"
        assert d["name"] == "Extract Data"
        assert d["description"] == "Extracts data from documents"
        assert d["tags"] == ["nlp", "extraction"]
        assert d["inputModes"] == ["application/pdf"]
        assert d["outputModes"] == ["application/json"]
        assert d["examples"] == ["Extract invoice totals"]

    def test_minimal_to_dict(self):
        s = AgentSkill(id="x", name="X")
        d = s.to_dict()
        assert "id" in d
        assert "name" in d
        # defaults present
        assert "inputModes" in d


# =============================================================================
# AgentCard
# =============================================================================


class TestAgentCard:
    def test_basic_creation(self):
        card = AgentCard(name="TestBot")
        assert card.name == "TestBot"
        assert card.version == "1.0.0"

    def test_from_identity(self):
        card = AgentCard.from_identity(
            did="did:mesh:abc123",
            name="PaymentAgent",
            description="Handles payments",
            capabilities=["process_payment", "refund"],
            public_key="base64pubkey",
            trust_score=800,
            organization="FinCorp",
            url="https://pay.example.com",
        )
        assert card.name == "PaymentAgent"
        assert card.agent_did == "did:mesh:abc123"
        assert card.trust_score == 800
        assert card.organization == "FinCorp"
        assert len(card.skills) == 2
        assert card.skills[0].id == "process_payment"
        assert card.public_key_fingerprint  # should be non-empty
        assert "a2a/1.0" in card.supported_protocols
        assert "iatp/1.0" in card.supported_protocols

    def test_to_dict_core_fields(self):
        card = AgentCard(
            name="Bot",
            description="A bot",
            url="https://bot.test",
            version="2.0.0",
        )
        d = card.to_dict()
        assert d["name"] == "Bot"
        assert d["description"] == "A bot"
        assert d["url"] == "https://bot.test"
        assert d["version"] == "2.0.0"

    def test_to_dict_extensions(self):
        card = AgentCard.from_identity(
            did="did:mesh:xyz",
            name="Bot",
            trust_score=500,
        )
        d = card.to_dict()
        assert d["x-agentmesh-did"] == "did:mesh:xyz"
        assert d["x-agentmesh-trust-score"] == 500
        assert "x-agentmesh-protocols" in d

    def test_to_json(self):
        card = AgentCard(name="JsonBot")
        j = card.to_json()
        parsed = json.loads(j)
        assert parsed["name"] == "JsonBot"

    def test_from_dict(self):
        original = AgentCard.from_identity(
            did="did:mesh:roundtrip",
            name="RoundTrip",
            capabilities=["search"],
            trust_score=700,
        )
        d = original.to_dict()
        restored = AgentCard.from_dict(d)
        assert restored.name == "RoundTrip"
        assert restored.agent_did == "did:mesh:roundtrip"
        assert restored.trust_score == 700
        assert len(restored.skills) == 1
        assert restored.skills[0].id == "search"

    def test_has_skill(self):
        card = AgentCard.from_identity(
            did="did:mesh:1",
            name="Bot",
            capabilities=["search", "translate"],
        )
        assert card.has_skill("search")
        assert card.has_skill("translate")
        assert not card.has_skill("compute")

    def test_skill_ids(self):
        card = AgentCard.from_identity(
            did="did:mesh:1",
            name="Bot",
            capabilities=["a", "b", "c"],
        )
        assert card.skill_ids() == ["a", "b", "c"]


# =============================================================================
# TaskMessage
# =============================================================================


class TestTaskMessage:
    def test_basic(self):
        m = TaskMessage(role="user", content="Hello")
        assert m.role == "user"
        assert m.content == "Hello"
        assert m.content_type == "text/plain"

    def test_to_dict(self):
        m = TaskMessage(role="agent", content="Done")
        d = m.to_dict()
        assert d["role"] == "agent"
        assert d["parts"][0]["text"] == "Done"

    def test_metadata(self):
        m = TaskMessage(role="user", content="Hi", metadata={"trace_id": "t1"})
        d = m.to_dict()
        assert d["metadata"]["trace_id"] == "t1"


# =============================================================================
# TaskEnvelope
# =============================================================================


class TestTaskEnvelope:
    def test_create_factory(self):
        t = TaskEnvelope.create(
            skill_id="search",
            source_did="did:mesh:src",
            target_did="did:mesh:tgt",
            source_trust_score=600,
            input_text="Find weather in NYC",
        )
        assert t.skill_id == "search"
        assert t.source_did == "did:mesh:src"
        assert t.target_did == "did:mesh:tgt"
        assert t.source_trust_score == 600
        assert t.state == TaskState.SUBMITTED
        assert len(t.messages) == 1
        assert t.messages[0].content == "Find weather in NYC"

    def test_state_machine_happy_path(self):
        t = TaskEnvelope.create(skill_id="x", source_did="did:mesh:a")
        assert t.state == TaskState.SUBMITTED
        t.start()
        assert t.state == TaskState.WORKING
        t.complete("result")
        assert t.state == TaskState.COMPLETE
        assert t.is_terminal

    def test_state_machine_fail(self):
        t = TaskEnvelope.create(skill_id="x", source_did="did:mesh:a")
        t.start()
        t.fail("timeout")
        assert t.state == TaskState.FAILED
        assert t.error == "timeout"
        assert t.is_terminal

    def test_state_machine_cancel(self):
        t = TaskEnvelope.create(skill_id="x", source_did="did:mesh:a")
        t.cancel()
        assert t.state == TaskState.CANCELED
        assert t.is_terminal

    def test_invalid_transition_from_complete(self):
        t = TaskEnvelope.create(skill_id="x", source_did="did:mesh:a")
        t.start()
        t.complete()
        with pytest.raises(ValueError, match="Invalid transition"):
            t.start()

    def test_invalid_transition_from_failed(self):
        t = TaskEnvelope.create(skill_id="x", source_did="did:mesh:a")
        t.fail("err")
        with pytest.raises(ValueError):
            t.complete()

    def test_add_message(self):
        t = TaskEnvelope.create(skill_id="x", source_did="did:mesh:a")
        t.add_message("agent", "thinking...")
        t.add_message("agent", "done!")
        assert len(t.messages) == 2

    def test_to_dict(self):
        t = TaskEnvelope.create(
            skill_id="search",
            source_did="did:mesh:src",
            target_did="did:mesh:tgt",
            source_trust_score=700,
            input_text="query",
        )
        d = t.to_dict()
        assert d["id"] == t.task_id
        assert d["status"]["state"] == "submitted"
        assert d["skill_id"] == "search"
        assert d["x-agentmesh-trust"]["source_did"] == "did:mesh:src"
        assert d["x-agentmesh-trust"]["source_trust_score"] == 700
        assert len(d["messages"]) == 1

    def test_to_dict_with_error(self):
        t = TaskEnvelope.create(skill_id="x", source_did="did:mesh:a")
        t.fail("boom")
        d = t.to_dict()
        assert d["status"]["error"] == "boom"

    def test_roundtrip_serialisation(self):
        original = TaskEnvelope.create(
            skill_id="translate",
            source_did="did:mesh:a",
            target_did="did:mesh:b",
            source_trust_score=900,
            input_text="Translate this",
        )
        d = original.to_dict()
        restored = TaskEnvelope.from_dict(d)
        assert restored.task_id == original.task_id
        assert restored.skill_id == "translate"
        assert restored.source_did == "did:mesh:a"
        assert restored.source_trust_score == 900
        assert len(restored.messages) == 1

    def test_is_terminal_for_non_terminal(self):
        t = TaskEnvelope.create(skill_id="x", source_did="did:mesh:a")
        assert not t.is_terminal
        t.start()
        assert not t.is_terminal


# =============================================================================
# TrustPolicy
# =============================================================================


class TestTrustPolicy:
    def test_defaults(self):
        p = TrustPolicy()
        assert p.min_trust_score == 100
        assert p.max_requests_per_minute == 60
        assert p.require_did is True

    def test_custom(self):
        p = TrustPolicy(
            min_trust_score=500,
            blocked_dids=["did:mesh:bad"],
            skill_trust_overrides={"admin": 900},
        )
        assert p.min_trust_score == 500
        assert "did:mesh:bad" in p.blocked_dids
        assert p.skill_trust_overrides["admin"] == 900


# =============================================================================
# TrustResult
# =============================================================================


class TestTrustResult:
    def test_allowed(self):
        r = TrustResult(allowed=True, reason="ok", trust_score=500)
        assert r.allowed
        d = r.to_dict()
        assert d["allowed"] is True

    def test_denied(self):
        r = TrustResult(allowed=False, reason="blocked", trust_score=0)
        assert not r.allowed


# =============================================================================
# TrustGate
# =============================================================================


class TestTrustGate:
    def _make_envelope(self, did="did:mesh:agent1", score=500, skill="search"):
        return TaskEnvelope.create(
            skill_id=skill,
            source_did=did,
            source_trust_score=score,
        )

    def test_allow_valid_request(self):
        gate = TrustGate()
        result = gate.evaluate(self._make_envelope())
        assert result.allowed

    def test_deny_missing_did(self):
        gate = TrustGate(TrustPolicy(require_did=True))
        envelope = TaskEnvelope.create(skill_id="x", source_did="")
        result = gate.evaluate(envelope)
        assert not result.allowed
        assert "DID is required" in result.reason

    def test_deny_blocked_did(self):
        gate = TrustGate(TrustPolicy(blocked_dids=["did:mesh:evil"]))
        result = gate.evaluate(self._make_envelope(did="did:mesh:evil"))
        assert not result.allowed
        assert "blocked" in result.reason

    def test_deny_not_in_allow_list(self):
        gate = TrustGate(TrustPolicy(allowed_dids=["did:mesh:friend"]))
        result = gate.evaluate(self._make_envelope(did="did:mesh:stranger"))
        assert not result.allowed
        assert "allow list" in result.reason

    def test_allow_in_allow_list(self):
        gate = TrustGate(TrustPolicy(allowed_dids=["did:mesh:friend"]))
        result = gate.evaluate(self._make_envelope(did="did:mesh:friend"))
        assert result.allowed

    def test_deny_low_trust_score(self):
        gate = TrustGate(TrustPolicy(min_trust_score=600))
        result = gate.evaluate(self._make_envelope(score=400))
        assert not result.allowed
        assert "Trust score" in result.reason

    def test_allow_sufficient_trust(self):
        gate = TrustGate(TrustPolicy(min_trust_score=300))
        result = gate.evaluate(self._make_envelope(score=500))
        assert result.allowed

    def test_skill_trust_override(self):
        gate = TrustGate(
            TrustPolicy(
                min_trust_score=100,
                skill_trust_overrides={"admin": 900},
            )
        )
        # Normal skill: allowed at 500
        assert gate.evaluate(self._make_envelope(skill="search", score=500)).allowed
        # Admin skill: denied at 500
        result = gate.evaluate(self._make_envelope(skill="admin", score=500))
        assert not result.allowed
        # Admin skill: allowed at 950
        assert gate.evaluate(self._make_envelope(skill="admin", score=950)).allowed

    def test_rate_limit(self):
        gate = TrustGate(TrustPolicy(max_requests_per_minute=3))
        for _ in range(3):
            assert gate.evaluate(self._make_envelope()).allowed
        result = gate.evaluate(self._make_envelope())
        assert not result.allowed
        assert "Rate limit" in result.reason

    def test_rate_limit_per_agent(self):
        gate = TrustGate(TrustPolicy(max_requests_per_minute=2))
        # Agent 1: 2 allowed
        assert gate.evaluate(self._make_envelope(did="did:mesh:a1")).allowed
        assert gate.evaluate(self._make_envelope(did="did:mesh:a1")).allowed
        # Agent 1: rate limited
        assert not gate.evaluate(self._make_envelope(did="did:mesh:a1")).allowed
        # Agent 2: still allowed (different DID)
        assert gate.evaluate(self._make_envelope(did="did:mesh:a2")).allowed

    def test_evaluate_and_gate_auto_fail(self):
        gate = TrustGate(TrustPolicy(min_trust_score=999))
        envelope = self._make_envelope(score=100)
        result = gate.evaluate_and_gate(envelope)
        assert not result.allowed
        assert envelope.state == TaskState.FAILED
        assert envelope.error != ""

    def test_evaluate_and_gate_allow(self):
        gate = TrustGate(TrustPolicy(min_trust_score=100))
        envelope = self._make_envelope(score=500)
        result = gate.evaluate_and_gate(envelope)
        assert result.allowed
        assert envelope.state == TaskState.SUBMITTED  # not changed

    def test_evaluation_log(self):
        gate = TrustGate()
        gate.evaluate(self._make_envelope())
        gate.evaluate(self._make_envelope(score=0))
        log = gate.get_evaluation_log()
        assert len(log) == 2

    def test_stats(self):
        gate = TrustGate(TrustPolicy(min_trust_score=300))
        gate.evaluate(self._make_envelope(score=500))  # allowed
        gate.evaluate(self._make_envelope(score=100))  # denied
        gate.evaluate(self._make_envelope(score=400))  # allowed
        stats = gate.get_stats()
        assert stats["total_evaluations"] == 3
        assert stats["allowed"] == 2
        assert stats["denied"] == 1

    def test_clear_rate_limits(self):
        gate = TrustGate(TrustPolicy(max_requests_per_minute=1))
        assert gate.evaluate(self._make_envelope()).allowed
        assert not gate.evaluate(self._make_envelope()).allowed
        gate.clear_rate_limits()
        assert gate.evaluate(self._make_envelope()).allowed

    def test_no_did_required(self):
        gate = TrustGate(TrustPolicy(require_did=False, min_trust_score=0))
        envelope = TaskEnvelope.create(skill_id="x", source_did="")
        result = gate.evaluate(envelope)
        assert result.allowed


# =============================================================================
# Integration: full lifecycle
# =============================================================================


class TestIntegration:
    def test_full_lifecycle(self):
        """Agent A discovers Agent B via card, sends trusted task, gate evaluates."""
        # 1. Agent B publishes card
        card_b = AgentCard.from_identity(
            did="did:mesh:agent-b",
            name="TranslationAgent",
            capabilities=["translate", "summarize"],
            trust_score=800,
            organization="LangCorp",
        )
        assert card_b.has_skill("translate")

        # 2. Agent A creates task targeting a skill
        task = TaskEnvelope.create(
            skill_id="translate",
            source_did="did:mesh:agent-a",
            target_did=card_b.agent_did,
            source_trust_score=600,
            input_text="Translate 'hello' to Spanish",
        )

        # 3. Trust gate evaluates
        gate = TrustGate(TrustPolicy(min_trust_score=500))
        result = gate.evaluate(task)
        assert result.allowed

        # 4. Task executes
        task.start()
        assert task.state == TaskState.WORKING
        task.complete("'hola'")
        assert task.state == TaskState.COMPLETE

        # 5. Verify serialisation roundtrip
        d = task.to_dict()
        restored = TaskEnvelope.from_dict(d)
        assert restored.skill_id == "translate"
        assert restored.state == TaskState.COMPLETE

    def test_denied_lifecycle(self):
        """Low-trust agent is denied and task auto-fails."""
        task = TaskEnvelope.create(
            skill_id="admin",
            source_did="did:mesh:untrusted",
            source_trust_score=50,
        )
        gate = TrustGate(TrustPolicy(min_trust_score=500))
        result = gate.evaluate_and_gate(task)
        assert not result.allowed
        assert task.state == TaskState.FAILED
        assert task.is_terminal

    def test_card_to_json_roundtrip(self):
        """AgentCard survives JSON serialisation."""
        card = AgentCard.from_identity(
            did="did:mesh:rt",
            name="RoundTrip",
            capabilities=["search"],
            trust_score=777,
            public_key="pk123",
        )
        j = card.to_json()
        d = json.loads(j)
        restored = AgentCard.from_dict(d)
        assert restored.agent_did == "did:mesh:rt"
        assert restored.trust_score == 777
        assert restored.has_skill("search")
