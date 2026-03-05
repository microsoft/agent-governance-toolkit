# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for deterministic trust root and supervisor hierarchy."""

from __future__ import annotations

import pytest

from agent_os.integrations.base import GovernancePolicy
from agent_os.supervisor import SupervisorHierarchy
from agent_os.trust_root import TrustDecision, TrustRoot


# ============================================================================
# TrustRoot tests
# ============================================================================


class TestTrustRoot:
    """Trust root deterministic guarantees."""

    def test_is_always_deterministic(self) -> None:
        root = TrustRoot(policies=[GovernancePolicy()])
        assert root.is_deterministic() is True

    def test_validates_allowed_action(self) -> None:
        policy = GovernancePolicy(allowed_tools=["read_file", "list_files"])
        root = TrustRoot(policies=[policy])
        decision = root.validate_action({"tool": "read_file", "arguments": {}})
        assert decision.allowed is True
        assert decision.deterministic is True

    def test_rejects_disallowed_tool(self) -> None:
        policy = GovernancePolicy(allowed_tools=["read_file"])
        root = TrustRoot(policies=[policy])
        decision = root.validate_action({"tool": "delete_file", "arguments": {}})
        assert decision.allowed is False
        assert "delete_file" in decision.reason

    def test_rejects_blocked_pattern(self) -> None:
        policy = GovernancePolicy(blocked_patterns=["DROP TABLE"])
        root = TrustRoot(policies=[policy])
        decision = root.validate_action(
            {"tool": "sql_query", "arguments": {"query": "DROP TABLE users"}}
        )
        assert decision.allowed is False
        assert "Blocked pattern" in decision.reason

    def test_requires_at_least_one_policy(self) -> None:
        with pytest.raises(ValueError, match="at least one policy"):
            TrustRoot(policies=[])

    def test_decision_cannot_be_overridden(self) -> None:
        """TrustDecision is a dataclass — but the trust root is the final authority."""
        policy = GovernancePolicy(allowed_tools=["read_file"])
        root = TrustRoot(policies=[policy])
        decision = root.validate_action({"tool": "delete_file", "arguments": {}})
        assert decision.allowed is False
        # Even if someone mutates the decision object, a fresh call still denies
        decision.allowed = True
        fresh = root.validate_action({"tool": "delete_file", "arguments": {}})
        assert fresh.allowed is False

    def test_validate_supervisor_rejects_agent_at_level_0(self) -> None:
        root = TrustRoot(policies=[GovernancePolicy()])
        assert root.validate_supervisor({"name": "llm-sup", "level": 0, "is_agent": True}) is False

    def test_validate_supervisor_accepts_deterministic_at_level_0(self) -> None:
        root = TrustRoot(policies=[GovernancePolicy()])
        assert root.validate_supervisor({"name": "root", "level": 0, "is_agent": False}) is True

    def test_validate_supervisor_accepts_agent_at_middle_level(self) -> None:
        root = TrustRoot(policies=[GovernancePolicy()])
        assert root.validate_supervisor({"name": "mid", "level": 1, "is_agent": True}) is True


# ============================================================================
# SupervisorHierarchy tests
# ============================================================================


class TestSupervisorHierarchy:
    """Hierarchy enforcement rules."""

    def _make_hierarchy(self) -> SupervisorHierarchy:
        root = TrustRoot(policies=[GovernancePolicy(allowed_tools=["read_file"])])
        h = SupervisorHierarchy(trust_root=root)
        h.register_supervisor("trust-root", level=0, is_agent=False)
        h.register_supervisor("safety-agent", level=1, is_agent=True)
        h.register_supervisor("worker-supervisor", level=2, is_agent=True)
        return h

    def test_valid_hierarchy_no_violations(self) -> None:
        h = self._make_hierarchy()
        assert h.validate_hierarchy() == []

    def test_rejects_llm_agent_at_level_0(self) -> None:
        root = TrustRoot(policies=[GovernancePolicy()])
        h = SupervisorHierarchy(trust_root=root)
        h.register_supervisor("bad-root", level=0, is_agent=True)
        violations = h.validate_hierarchy()
        assert any("deterministic" in v for v in violations)

    def test_allows_llm_agent_at_middle_levels(self) -> None:
        root = TrustRoot(policies=[GovernancePolicy()])
        h = SupervisorHierarchy(trust_root=root)
        h.register_supervisor("root", level=0, is_agent=False)
        h.register_supervisor("mid-agent", level=1, is_agent=True)
        assert h.validate_hierarchy() == []

    def test_escalation_reaches_trust_root(self) -> None:
        h = self._make_hierarchy()
        decision = h.escalate({"tool": "read_file", "arguments": {}}, from_level=2)
        assert decision.allowed is True
        assert decision.deterministic is True

    def test_escalation_denied_by_trust_root(self) -> None:
        h = self._make_hierarchy()
        decision = h.escalate({"tool": "delete_file", "arguments": {}}, from_level=2)
        assert decision.allowed is False

    def test_authority_chain_order(self) -> None:
        h = self._make_hierarchy()
        chain = h.get_authority_chain({"tool": "read_file", "arguments": {}})
        assert chain[-1] == "trust-root"
        assert chain[0] == "worker-supervisor"

    def test_missing_level_0_violation(self) -> None:
        root = TrustRoot(policies=[GovernancePolicy()])
        h = SupervisorHierarchy(trust_root=root)
        h.register_supervisor("mid", level=1, is_agent=True)
        violations = h.validate_hierarchy()
        assert any("Level 0" in v for v in violations)
