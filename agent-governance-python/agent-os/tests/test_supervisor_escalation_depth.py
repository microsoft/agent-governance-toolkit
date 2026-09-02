# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Regression test for the escalation-depth cap in ``SupervisorHierarchy``.

When an escalation chain exceeded ``max_escalation_depth`` the cap branch built a
``TrustDecision`` with a ``policy_name`` keyword the dataclass never defined and
without the required ``authority`` field, so the guard raised ``TypeError``
instead of returning a deny decision (issue #3539).
"""
from __future__ import annotations

from agent_os.supervisor import SupervisorHierarchy
from agent_os.trust_root import TrustDecision


class _StubTrustRoot:
    """Minimal trust root: only the escalation-depth guard is exercised here."""

    def __init__(self, max_escalation_depth: int) -> None:
        self.max_escalation_depth = max_escalation_depth

    def validate_action(self, action: dict) -> TrustDecision:
        # Reached only when the depth cap is NOT hit.
        return TrustDecision(
            allowed=True, reason="stub allow", authority="native-runtime"
        )


def _hierarchy_exceeding_depth() -> SupervisorHierarchy:
    """A chain whose distinct levels below ``from_level`` exceed the cap."""
    hierarchy = SupervisorHierarchy(trust_root=_StubTrustRoot(max_escalation_depth=2))
    # Levels 0, 1, 2, 3 -> four distinct levels above from_level=4.
    for level in range(4):
        hierarchy.register_supervisor(
            f"sup-{level}", level=level, is_agent=level != 0
        )
    return hierarchy


def test_escalation_depth_cap_returns_well_formed_decision() -> None:
    """Past the cap the guard must deny, not raise ``TypeError``."""
    decision = _hierarchy_exceeding_depth().escalate(
        {"tool": "x", "arguments": {}}, from_level=4
    )
    assert isinstance(decision, TrustDecision)
    assert not decision.allowed
    assert "Max escalation depth" in decision.reason
    assert decision.authority == "supervisor"
    assert decision.deterministic


def test_escalation_below_the_cap_still_reaches_the_trust_root() -> None:
    """Under the cap the decision still flows through to the trust root."""
    hierarchy = SupervisorHierarchy(trust_root=_StubTrustRoot(max_escalation_depth=5))
    hierarchy.register_supervisor("root", level=0, is_agent=False)
    hierarchy.register_supervisor("worker", level=1, is_agent=True)
    decision = hierarchy.escalate({"tool": "x", "arguments": {}}, from_level=1)
    assert decision.allowed
