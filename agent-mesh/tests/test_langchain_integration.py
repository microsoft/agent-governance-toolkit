# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# Copyright (c) Agent-Mesh Contributors. All rights reserved.
# Licensed under the MIT License.
"""Tests for LangChain trust callback handler and tool wrappers."""

import pytest

from agentmesh.exceptions import TrustVerificationError
from agentmesh.integrations.langchain import (
    AgentMeshTrustCallback,
    InMemoryTrustStore,
    TrustVerifiedTool,
    trust_verified_tool,
)


# ── Helpers ─────────────────────────────────────────────────────────


class _FakeTool:
    """Minimal tool mock with a ``run`` method."""

    name = "fake_tool"
    description = "A fake tool for testing"

    def run(self, query: str) -> str:
        return f"result:{query}"


# ── InMemoryTrustStore ──────────────────────────────────────────────


class TestInMemoryTrustStore:
    def test_default_score(self):
        store = InMemoryTrustStore(default_score=600)
        assert store.get_trust_score("did:mesh:new") == 600

    def test_set_and_get(self):
        store = InMemoryTrustStore()
        store.set_trust_score("did:mesh:a", 800)
        assert store.get_trust_score("did:mesh:a") == 800

    def test_record_interaction_success_increases(self):
        store = InMemoryTrustStore(default_score=500)
        store.record_interaction("did:mesh:a", success=True)
        assert store.get_trust_score("did:mesh:a") > 500

    def test_record_interaction_failure_decreases(self):
        store = InMemoryTrustStore(default_score=500)
        store.record_interaction("did:mesh:a", success=False)
        assert store.get_trust_score("did:mesh:a") < 500

    def test_score_clamped(self):
        store = InMemoryTrustStore()
        store.set_trust_score("did:mesh:a", 1500)
        assert store.get_trust_score("did:mesh:a") == 1000
        store.set_trust_score("did:mesh:a", -100)
        assert store.get_trust_score("did:mesh:a") == 0


# ── AgentMeshTrustCallback ─────────────────────────────────────────


class TestAgentMeshTrustCallback:
    def _make_callback(self, score: int = 600, min_score: int = 500):
        store = InMemoryTrustStore(default_score=score)
        return AgentMeshTrustCallback(
            agent_did="did:mesh:test",
            min_trust_score=min_score,
            trust_store=store,
        )

    def test_tool_start_verifies_trust(self):
        cb = self._make_callback(score=700, min_score=500)
        cb.on_tool_start({"name": "search"}, "query")
        # No exception means trust was verified

    def test_tool_start_blocks_low_trust(self):
        cb = self._make_callback(score=300, min_score=500)
        with pytest.raises(TrustVerificationError, match="below required"):
            cb.on_tool_start({"name": "search"}, "query")

    def test_tool_end_records_interaction(self):
        cb = self._make_callback(score=700)
        cb.on_tool_end("some output")
        interactions = cb.get_interactions()
        assert len(interactions) == 1
        assert interactions[0].event == "tool_end"
        assert interactions[0].success is True

    def test_tool_error_records_failure(self):
        cb = self._make_callback(score=700)
        cb.on_tool_error(RuntimeError("fail"))
        interactions = cb.get_interactions()
        assert len(interactions) == 1
        assert interactions[0].success is False

    def test_chain_start_logs_without_error(self):
        cb = self._make_callback(score=700)
        cb.on_chain_start({"name": "test_chain"}, {"input": "hello"})
        # Should not raise

    def test_chain_end_records_success(self):
        cb = self._make_callback(score=700)
        cb.on_chain_end({"output": "world"})
        interactions = cb.get_interactions()
        assert len(interactions) == 1
        assert interactions[0].event == "chain_end"
        assert interactions[0].success is True

    def test_chain_error_records_failure_and_updates_trust(self):
        cb = self._make_callback(score=700, min_score=500)
        initial_score = cb.trust_store.get_trust_score("did:mesh:test")
        cb.on_chain_error(ValueError("something broke"))
        interactions = cb.get_interactions()
        assert len(interactions) == 1
        assert interactions[0].success is False
        new_score = cb.trust_store.get_trust_score("did:mesh:test")
        assert new_score < initial_score

    def test_llm_start_verifies_trust(self):
        cb = self._make_callback(score=700, min_score=500)
        cb.on_llm_start({"name": "gpt-4"}, ["Hello"])
        # No exception means trust was verified

    def test_llm_start_blocks_low_trust(self):
        cb = self._make_callback(score=300, min_score=500)
        with pytest.raises(TrustVerificationError, match="below required"):
            cb.on_llm_start({"name": "gpt-4"}, ["Hello"])

    def test_get_stats(self):
        cb = self._make_callback(score=700)
        cb.on_chain_end({"output": "ok"})
        cb.on_tool_error(RuntimeError("fail"))
        stats = cb.get_stats()
        assert stats["agent_did"] == "did:mesh:test"
        assert stats["total_interactions"] == 2
        assert stats["successes"] == 1
        assert stats["failures"] == 1

    def test_multiple_tool_calls_track_correctly(self):
        cb = self._make_callback(score=700)
        cb.on_tool_start({"name": "tool_a"}, "input1")
        cb.on_tool_end("output1")
        cb.on_tool_start({"name": "tool_b"}, "input2")
        cb.on_tool_end("output2")
        assert len(cb.get_interactions()) == 2
        assert all(r.success for r in cb.get_interactions())


# ── trust_verified_tool wrapper ─────────────────────────────────────


class TestTrustVerifiedToolWrapper:
    def test_wrapper_passes_with_sufficient_trust(self):
        store = InMemoryTrustStore(default_score=700)
        tool = _FakeTool()
        wrapped = trust_verified_tool(tool, "did:mesh:a", min_score=500, trust_store=store)
        result = wrapped("hello")
        assert result == "result:hello"

    def test_wrapper_blocks_low_trust(self):
        store = InMemoryTrustStore(default_score=300)
        tool = _FakeTool()
        wrapped = trust_verified_tool(tool, "did:mesh:a", min_score=500, trust_store=store)
        with pytest.raises(TrustVerificationError, match="below required"):
            wrapped("hello")

    def test_wrapper_uses_default_store(self):
        tool = _FakeTool()
        wrapped = trust_verified_tool(tool, "did:mesh:a", min_score=400)
        # Default InMemoryTrustStore has score 500, so 400 threshold passes
        result = wrapped("test")
        assert result == "result:test"


# ── TrustVerifiedTool subclass ──────────────────────────────────────


class TestTrustVerifiedTool:
    def test_run_with_sufficient_trust(self):
        store = InMemoryTrustStore(default_score=700)
        tool = TrustVerifiedTool(
            name="calc",
            description="Calculator",
            agent_did="did:mesh:a",
            min_trust_score=500,
            trust_store=store,
            inner_fn=lambda q, **kw: f"answer:{q}",
        )
        result = tool._run("2+2")
        assert result == "answer:2+2"

    def test_run_blocks_low_trust(self):
        store = InMemoryTrustStore(default_score=300)
        tool = TrustVerifiedTool(
            name="calc",
            description="Calculator",
            agent_did="did:mesh:a",
            min_trust_score=500,
            trust_store=store,
            inner_fn=lambda q, **kw: q,
        )
        with pytest.raises(TrustVerificationError, match="below required"):
            tool._run("2+2")

    def test_run_without_inner_fn_raises(self):
        store = InMemoryTrustStore(default_score=700)
        tool = TrustVerifiedTool(
            name="empty",
            description="No function",
            agent_did="did:mesh:a",
            min_trust_score=500,
            trust_store=store,
        )
        with pytest.raises(NotImplementedError):
            tool._run("query")

    def test_tool_attributes(self):
        tool = TrustVerifiedTool(
            name="my_tool",
            description="My description",
            agent_did="did:mesh:a",
        )
        assert tool.name == "my_tool"
        assert tool.description == "My description"
