# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for SupervisorHierarchy.escalate depth limiting."""

from __future__ import annotations

import pytest

from agent_os.supervisor import SupervisorHierarchy
from agent_os.trust_root import TrustDecision, TrustRoot


def _hierarchy(max_escalation_depth: int) -> SupervisorHierarchy:
    # The runtime is only consulted by validate_action, which the max-depth
    # branch never reaches, so a non-None sentinel is sufficient here.
    trust_root = TrustRoot(runtime=object(), max_escalation_depth=max_escalation_depth)
    hierarchy = SupervisorHierarchy(trust_root)
    hierarchy.register_supervisor("root", level=0)
    hierarchy.register_supervisor("mid", level=1)
    hierarchy.register_supervisor("near", level=2)
    return hierarchy


@pytest.mark.parametrize("max_depth", [0, 1, 2])
def test_escalate_past_max_depth_returns_well_formed_deny(max_depth: int) -> None:
    """Regression for #3539: escalating past max_escalation_depth must return a
    limiting TrustDecision, not raise TypeError.

    The hierarchy has three levels (0, 1, 2) below ``from_level=3``, so every
    ``max_depth`` here is exceeded and the depth guard trips. Before the fix the
    guard constructed ``TrustDecision(..., policy_name=...)``, which raised
    ``TypeError`` because the dataclass has no ``policy_name`` field (and no
    ``authority`` was supplied)."""
    hierarchy = _hierarchy(max_escalation_depth=max_depth)

    decision = hierarchy.escalate({"tool": "x", "arguments": {}}, from_level=3)

    assert isinstance(decision, TrustDecision)
    assert decision.allowed is False
    assert "max escalation depth" in decision.reason.lower()
    assert decision.authority == "trust_root"
    assert decision.deterministic is True
