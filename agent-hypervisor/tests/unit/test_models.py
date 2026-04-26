# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for core models."""

from hypervisor.models import (
    ActionDescriptor,
    ExecutionRing,
    ReversibilityLevel,
)


class TestExecutionRing:
    def test_from_eff_score_sandbox(self):
        assert ExecutionRing.from_eff_score(0.3) == ExecutionRing.RING_3_SANDBOX

    def test_from_eff_score_standard(self):
        assert ExecutionRing.from_eff_score(0.7) == ExecutionRing.RING_2_STANDARD

    def test_from_eff_score_privileged_with_consensus(self):
        assert ExecutionRing.from_eff_score(0.96, has_consensus=True) == ExecutionRing.RING_1_PRIVILEGED

    def test_from_eff_score_privileged_without_consensus_gets_standard(self):
        assert ExecutionRing.from_eff_score(0.96, has_consensus=False) == ExecutionRing.RING_2_STANDARD

    def test_from_eff_score_boundary_060(self):
        # Exactly 0.60 is NOT > 0.60, so sandbox
        assert ExecutionRing.from_eff_score(0.60) == ExecutionRing.RING_3_SANDBOX

    def test_from_eff_score_just_above_060(self):
        assert ExecutionRing.from_eff_score(0.601) == ExecutionRing.RING_2_STANDARD


class TestReversibilityLevel:
    def test_full_risk_weight(self):
        assert ReversibilityLevel.FULL.default_risk_weight == 0.2

    def test_partial_risk_weight(self):
        assert ReversibilityLevel.PARTIAL.default_risk_weight == 0.65

    def test_none_risk_weight(self):
        assert ReversibilityLevel.NONE.default_risk_weight == 0.95

    def test_risk_weight_ranges(self):
        assert ReversibilityLevel.FULL.risk_weight_range == (0.1, 0.3)
        assert ReversibilityLevel.PARTIAL.risk_weight_range == (0.5, 0.8)
        assert ReversibilityLevel.NONE.risk_weight_range == (0.9, 1.0)


class TestActionDescriptor:
    def test_read_only_requires_ring3(self):
        action = ActionDescriptor(
            action_id="search",
            name="Search",
            execute_api="/api/search",
            is_read_only=True,
        )
        assert action.required_ring == ExecutionRing.RING_3_SANDBOX

    def test_admin_requires_ring0(self):
        action = ActionDescriptor(
            action_id="config",
            name="Configure",
            execute_api="/api/config",
            is_admin=True,
        )
        assert action.required_ring == ExecutionRing.RING_0_ROOT

    def test_non_reversible_requires_ring1(self):
        action = ActionDescriptor(
            action_id="delete",
            name="Delete Data",
            execute_api="/api/delete",
            reversibility=ReversibilityLevel.NONE,
        )
        assert action.required_ring == ExecutionRing.RING_1_PRIVILEGED

    def test_reversible_requires_ring2(self):
        action = ActionDescriptor(
            action_id="draft",
            name="Draft Email",
            execute_api="/api/draft",
            undo_api="/api/draft/undo",
            reversibility=ReversibilityLevel.FULL,
        )
        assert action.required_ring == ExecutionRing.RING_2_STANDARD

    def test_risk_weight_from_reversibility(self):
        action = ActionDescriptor(
            action_id="transfer",
            name="Wire Transfer",
            execute_api="/api/transfer",
            reversibility=ReversibilityLevel.NONE,
        )
        assert action.risk_weight == 0.95
