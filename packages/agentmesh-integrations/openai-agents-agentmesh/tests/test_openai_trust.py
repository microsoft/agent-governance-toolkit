"""Tests for OpenAI Agents AgentMesh trust integration."""

import pytest

from openai_agents_agentmesh import (
    AgentTrustContext,
    FunctionCallResult,
    HandoffResult,
    HandoffVerifier,
    TrustedFunctionGuard,
)


# =============================================================================
# FunctionCallResult / HandoffResult
# =============================================================================


class TestResults:
    def test_function_call_to_dict(self):
        r = FunctionCallResult(allowed=True, function_name="search", agent_did="d1")
        d = r.to_dict()
        assert d["allowed"] is True
        assert d["function"] == "search"

    def test_handoff_to_dict(self):
        r = HandoffResult(allowed=False, source_did="d1", target_did="d2", reason="low trust")
        d = r.to_dict()
        assert not d["allowed"]
        assert d["reason"] == "low trust"


# =============================================================================
# AgentTrustContext
# =============================================================================


class TestAgentTrustContext:
    def test_basic(self):
        ctx = AgentTrustContext(user_id="user-1", originating_did="did:mesh:root")
        assert ctx.delegation_depth == 0
        assert ctx.current_agent == "did:mesh:root"

    def test_add_delegation(self):
        ctx = AgentTrustContext(originating_did="did:mesh:root", max_delegation_depth=3)
        assert ctx.add_delegation("did:mesh:a1")
        assert ctx.add_delegation("did:mesh:a2")
        assert ctx.delegation_depth == 2
        assert ctx.current_agent == "did:mesh:a2"

    def test_max_depth(self):
        ctx = AgentTrustContext(max_delegation_depth=2)
        assert ctx.add_delegation("a1")
        assert ctx.add_delegation("a2")
        assert not ctx.add_delegation("a3")  # exceeds max
        assert ctx.delegation_depth == 2

    def test_to_dict(self):
        ctx = AgentTrustContext(user_id="u1", originating_did="d0")
        ctx.add_delegation("d1")
        d = ctx.to_dict()
        assert d["user_id"] == "u1"
        assert d["scope_chain"] == ["d1"]
        assert d["delegation_depth"] == 1


# =============================================================================
# TrustedFunctionGuard
# =============================================================================


class TestTrustedFunctionGuard:
    def test_allow_default(self):
        g = TrustedFunctionGuard(min_trust_score=100)
        r = g.check_call("did:mesh:a1", 500, "search")
        assert r.allowed

    def test_deny_low_trust(self):
        g = TrustedFunctionGuard(min_trust_score=500)
        r = g.check_call("did:mesh:a1", 200, "search")
        assert not r.allowed
        assert "Trust score" in r.reason

    def test_sensitive_function(self):
        g = TrustedFunctionGuard(
            min_trust_score=100,
            sensitive_functions={"delete_file": 800, "send_email": 700},
        )
        # Normal function: allowed at 500
        assert g.check_call("d1", 500, "search").allowed
        # Sensitive: denied at 500
        assert not g.check_call("d1", 500, "delete_file").allowed
        # Sensitive: allowed at 900
        assert g.check_call("d1", 900, "delete_file").allowed

    def test_blocked_function(self):
        g = TrustedFunctionGuard(blocked_functions=["exec_code"])
        r = g.check_call("d1", 1000, "exec_code")
        assert not r.allowed
        assert "blocked" in r.reason

    def test_block_unblock(self):
        g = TrustedFunctionGuard()
        g.block_function("danger")
        assert not g.check_call("d1", 1000, "danger").allowed
        g.unblock_function("danger")
        assert g.check_call("d1", 1000, "danger").allowed

    def test_set_threshold(self):
        g = TrustedFunctionGuard(min_trust_score=100)
        g.set_threshold("admin", 900)
        assert not g.check_call("d1", 500, "admin").allowed
        assert g.check_call("d1", 950, "admin").allowed

    def test_log(self):
        g = TrustedFunctionGuard()
        g.check_call("d1", 500, "search")
        g.check_call("d1", 500, "calc")
        assert len(g.get_log()) == 2

    def test_stats(self):
        g = TrustedFunctionGuard(
            min_trust_score=500,
            sensitive_functions={"admin": 900},
            blocked_functions=["exec"],
        )
        g.check_call("d1", 600, "search")  # allowed
        g.check_call("d1", 200, "search")  # denied
        g.check_call("d1", 600, "exec")  # denied (blocked)
        stats = g.get_stats()
        assert stats["total_checks"] == 3
        assert stats["allowed"] == 1
        assert stats["denied"] == 2
        assert stats["sensitive_functions"] == 1
        assert stats["blocked_functions"] == 1


# =============================================================================
# HandoffVerifier
# =============================================================================


class TestHandoffVerifier:
    def test_allow_handoff(self):
        v = HandoffVerifier(min_trust_score=300)
        r = v.verify_handoff("d1", 500, "d2", 600)
        assert r.allowed

    def test_deny_low_source_trust(self):
        v = HandoffVerifier(min_trust_score=500)
        r = v.verify_handoff("d1", 200, "d2", 800)
        assert not r.allowed
        assert "Source trust" in r.reason

    def test_deny_low_target_trust(self):
        v = HandoffVerifier(min_trust_score=500)
        r = v.verify_handoff("d1", 800, "d2", 200)
        assert not r.allowed
        assert "Target trust" in r.reason

    def test_deny_self_delegation(self):
        v = HandoffVerifier()
        r = v.verify_handoff("d1", 1000, "d1", 1000)
        assert not r.allowed
        assert "self" in r.reason.lower()

    def test_delegation_depth(self):
        v = HandoffVerifier(max_delegation_depth=2)
        ctx = AgentTrustContext()
        # First handoff: ok
        r = v.verify_handoff("d1", 500, "d2", 500, context=ctx)
        assert r.allowed
        assert ctx.delegation_depth == 1
        # Second: ok
        r = v.verify_handoff("d2", 500, "d3", 500, context=ctx)
        assert r.allowed
        assert ctx.delegation_depth == 2
        # Third: denied (depth exceeded)
        r = v.verify_handoff("d3", 500, "d4", 500, context=ctx)
        assert not r.allowed
        assert "depth" in r.reason.lower()

    def test_mutual_trust_not_required(self):
        v = HandoffVerifier(min_trust_score=300, require_mutual_trust=False)
        assert v.verify_handoff("d1", 500, "d2", 400).allowed

    def test_log_and_stats(self):
        v = HandoffVerifier(min_trust_score=500)
        v.verify_handoff("d1", 600, "d2", 700)  # allowed
        v.verify_handoff("d1", 200, "d2", 700)  # denied
        stats = v.get_stats()
        assert stats["total_handoffs"] == 2
        assert stats["allowed"] == 1
        assert stats["denied"] == 1
        assert len(v.get_log()) == 2


# =============================================================================
# Integration
# =============================================================================


class TestIntegration:
    def test_full_agent_workflow(self):
        """Simulate: Triage → Research → Specialist with trust verification."""
        guard = TrustedFunctionGuard(
            min_trust_score=300,
            sensitive_functions={"file_write": 700},
        )
        verifier = HandoffVerifier(min_trust_score=400, max_delegation_depth=3)
        ctx = AgentTrustContext(user_id="user-42", originating_did="did:mesh:triage")

        # Triage agent calls a function
        assert guard.check_call("did:mesh:triage", 800, "search").allowed

        # Triage hands off to Research
        r = verifier.verify_handoff(
            "did:mesh:triage", 800, "did:mesh:research", 600, context=ctx
        )
        assert r.allowed
        assert ctx.delegation_depth == 1

        # Research calls sensitive function
        r = guard.check_call("did:mesh:research", 600, "file_write")
        assert not r.allowed  # 600 < 700

        # Research calls normal function
        assert guard.check_call("did:mesh:research", 600, "web_search").allowed

        # Research hands off to Specialist
        r = verifier.verify_handoff(
            "did:mesh:research", 600, "did:mesh:specialist", 900, context=ctx
        )
        assert r.allowed
        assert ctx.delegation_depth == 2

        # Specialist calls sensitive function (high trust)
        assert guard.check_call("did:mesh:specialist", 900, "file_write").allowed

        # Context preserves chain
        assert ctx.current_agent == "did:mesh:specialist"
        assert ctx.user_id == "user-42"
        d = ctx.to_dict()
        assert len(d["scope_chain"]) == 2

    def test_imports(self):
        from openai_agents_agentmesh import (
            AgentTrustContext,
            HandoffResult,
            HandoffVerifier,
            FunctionCallResult,
            TrustedFunctionGuard,
        )
        assert all(c is not None for c in [
            AgentTrustContext, HandoffResult, HandoffVerifier,
            FunctionCallResult, TrustedFunctionGuard,
        ])
