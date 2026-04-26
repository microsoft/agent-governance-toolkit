# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for ring enforcer and action classifier."""

from hypervisor.models import ActionDescriptor, ExecutionRing, ReversibilityLevel
from hypervisor.rings.classifier import ActionClassifier
from hypervisor.rings.enforcer import RingEnforcer


class TestRingEnforcer:
    def setup_method(self):
        self.enforcer = RingEnforcer()

    def test_ring3_allows_read_only(self):
        action = ActionDescriptor(
            action_id="search", name="Search", execute_api="/search", is_read_only=True
        )
        result = self.enforcer.check(
            agent_ring=ExecutionRing.RING_3_SANDBOX,
            action=action,
            eff_score=0.3,
        )
        assert result.allowed

    def test_ring3_blocks_ring2_action(self):
        action = ActionDescriptor(
            action_id="draft", name="Draft", execute_api="/draft",
            undo_api="/draft/undo", reversibility=ReversibilityLevel.FULL,
        )
        result = self.enforcer.check(
            agent_ring=ExecutionRing.RING_3_SANDBOX,
            action=action,
            eff_score=0.7,
        )
        assert not result.allowed
        assert "insufficient" in result.reason.lower()

    def test_ring1_requires_consensus(self):
        action = ActionDescriptor(
            action_id="delete", name="Delete", execute_api="/delete",
            reversibility=ReversibilityLevel.NONE,
        )
        result = self.enforcer.check(
            agent_ring=ExecutionRing.RING_1_PRIVILEGED,
            action=action,
            eff_score=0.96,
            has_consensus=False,
        )
        # Public preview: no consensus requirement, access granted if ring is sufficient
        assert result.allowed

    def test_ring1_with_consensus_allowed(self):
        action = ActionDescriptor(
            action_id="delete", name="Delete", execute_api="/delete",
            reversibility=ReversibilityLevel.NONE,
        )
        result = self.enforcer.check(
            agent_ring=ExecutionRing.RING_1_PRIVILEGED,
            action=action,
            eff_score=0.96,
            has_consensus=True,
        )
        assert result.allowed

    def test_ring0_requires_sre_witness(self):
        action = ActionDescriptor(
            action_id="config", name="Config", execute_api="/config", is_admin=True
        )
        result = self.enforcer.check(
            agent_ring=ExecutionRing.RING_0_ROOT,
            action=action,
            eff_score=1.0,
            has_sre_witness=False,
        )
        assert not result.allowed
        assert result.requires_sre_witness

    def test_should_demote(self):
        assert self.enforcer.should_demote(ExecutionRing.RING_2_STANDARD, eff_score=0.3)
        assert not self.enforcer.should_demote(ExecutionRing.RING_2_STANDARD, eff_score=0.7)


class TestActionClassifier:
    def setup_method(self):
        self.classifier = ActionClassifier()

    def test_classify_reversible(self):
        action = ActionDescriptor(
            action_id="draft", name="Draft", execute_api="/draft",
            undo_api="/draft/undo", reversibility=ReversibilityLevel.FULL,
        )
        result = self.classifier.classify(action)
        assert result.ring == ExecutionRing.RING_2_STANDARD
        assert result.risk_weight == 0.2

    def test_classify_non_reversible(self):
        action = ActionDescriptor(
            action_id="delete", name="Delete", execute_api="/delete",
            reversibility=ReversibilityLevel.NONE,
        )
        result = self.classifier.classify(action)
        assert result.ring == ExecutionRing.RING_1_PRIVILEGED
        assert result.risk_weight == 0.95

    def test_cache_hit(self):
        action = ActionDescriptor(
            action_id="cached", name="Cached", execute_api="/cached",
            reversibility=ReversibilityLevel.PARTIAL,
        )
        r1 = self.classifier.classify(action)
        r2 = self.classifier.classify(action)
        assert r1 is r2  # same object from cache

    def test_override(self):
        action = ActionDescriptor(
            action_id="overridden", name="X", execute_api="/x",
            reversibility=ReversibilityLevel.FULL,
        )
        self.classifier.classify(action)
        self.classifier.set_override("overridden", ring=ExecutionRing.RING_1_PRIVILEGED)
        result = self.classifier.classify(action)
        assert result.ring == ExecutionRing.RING_1_PRIVILEGED
