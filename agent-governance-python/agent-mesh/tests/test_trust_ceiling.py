# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for trust ceiling propagation in TrustScore and DelegationScope."""

from __future__ import annotations

import os
from unittest.mock import patch

import pytest

from agentmesh.reward.scoring import TrustScore, RewardDimension


# ── TrustScore ceiling ────────────────────────────────────────


class TestTrustScoreCeiling:
    """Tests for trust ceiling enforcement on TrustScore."""

    def test_no_ceiling_by_default(self):
        score = TrustScore(agent_did="did:mesh:abc")
        assert score.trust_ceiling is None
        assert score.total_score == 500  # default

    def test_ceiling_clamps_initial_score(self):
        score = TrustScore(agent_did="did:mesh:abc", trust_ceiling=300)
        # Default score is 500, ceiling is 300 -> clamped to 300
        assert score.total_score == 300

    def test_ceiling_allows_lower_initial_score(self):
        score = TrustScore(
            agent_did="did:mesh:abc", total_score=200, trust_ceiling=300
        )
        assert score.total_score == 200

    def test_update_respects_ceiling(self):
        score = TrustScore(
            agent_did="did:mesh:abc", total_score=200, trust_ceiling=700
        )
        score.update(900, {})
        assert score.total_score == 700  # clamped to ceiling

    def test_update_allows_below_ceiling(self):
        score = TrustScore(
            agent_did="did:mesh:abc", total_score=200, trust_ceiling=700
        )
        score.update(500, {})
        assert score.total_score == 500

    def test_update_without_ceiling_uses_max(self):
        score = TrustScore(agent_did="did:mesh:abc", total_score=200)
        score.update(999, {})
        assert score.total_score == 999

    def test_ceiling_from_env_var(self):
        with patch.dict(os.environ, {"AGT_TRUST_CEILING": "600"}, clear=False):
            score = TrustScore(agent_did="did:mesh:abc")
            assert score.trust_ceiling == 600
            assert score.total_score == 500  # default, below ceiling

    def test_ceiling_from_env_clamps_default_score(self):
        with patch.dict(os.environ, {"AGT_TRUST_CEILING": "200"}, clear=False):
            score = TrustScore(agent_did="did:mesh:abc")
            assert score.trust_ceiling == 200
            assert score.total_score == 200  # clamped from 500

    def test_explicit_ceiling_overrides_env(self):
        with patch.dict(os.environ, {"AGT_TRUST_CEILING": "600"}, clear=False):
            score = TrustScore(
                agent_did="did:mesh:abc", trust_ceiling=300
            )
            assert score.trust_ceiling == 300

    def test_invalid_env_ceiling_ignored(self):
        with patch.dict(os.environ, {"AGT_TRUST_CEILING": "not_a_number"}, clear=False):
            score = TrustScore(agent_did="did:mesh:abc")
            assert score.trust_ceiling is None

    def test_env_ceiling_clamped_to_valid_range(self):
        with patch.dict(os.environ, {"AGT_TRUST_CEILING": "5000"}, clear=False):
            score = TrustScore(agent_did="did:mesh:abc")
            assert score.trust_ceiling == 1000

    def test_negative_env_ceiling_clamped_to_zero(self):
        with patch.dict(os.environ, {"AGT_TRUST_CEILING": "-100"}, clear=False):
            score = TrustScore(agent_did="did:mesh:abc")
            assert score.trust_ceiling == 0

    def test_tier_reflects_clamped_score(self):
        score = TrustScore(
            agent_did="did:mesh:abc", total_score=900, trust_ceiling=400
        )
        # Score clamped to 400, which is in "probationary" tier (300-499)
        assert score.total_score == 400
        assert score.tier == "probationary"

    def test_ceiling_preserved_in_dict(self):
        score = TrustScore(
            agent_did="did:mesh:abc", total_score=200, trust_ceiling=700
        )
        d = score.to_dict()
        assert "trust_ceiling" in TrustScore.model_fields


# ── DelegationScope ceiling propagation ───────────────────────

try:
    from adk_agentmesh.governance import DelegationScope
    _has_adk = True
except ImportError:
    _has_adk = False


@pytest.mark.skipif(not _has_adk, reason="adk_agentmesh not installed")
class TestDelegationScopeCeiling:
    """Tests for trust ceiling propagation through DelegationScope.narrow()."""

    def test_narrow_propagates_parent_ceiling(self):
        parent = DelegationScope(trust_ceiling=700)
        child = parent.narrow()
        assert child.trust_ceiling == 700

    def test_narrow_clamps_requested_ceiling_to_parent(self):
        parent = DelegationScope(trust_ceiling=700)
        child = parent.narrow(trust_ceiling=900)
        assert child.trust_ceiling == 700  # can't exceed parent

    def test_narrow_allows_lower_ceiling(self):
        parent = DelegationScope(trust_ceiling=700)
        child = parent.narrow(trust_ceiling=400)
        assert child.trust_ceiling == 400

    def test_narrow_without_parent_ceiling_passes_through(self):
        parent = DelegationScope()
        child = parent.narrow(trust_ceiling=500)
        assert child.trust_ceiling == 500

    def test_narrow_no_ceiling_stays_none(self):
        parent = DelegationScope()
        child = parent.narrow()
        assert child.trust_ceiling is None

    def test_narrow_chain_monotonically_narrows(self):
        root = DelegationScope(trust_ceiling=800, max_depth=5)
        level1 = root.narrow(trust_ceiling=600)
        level2 = level1.narrow(trust_ceiling=700)  # clamped to 600
        level3 = level2.narrow(trust_ceiling=300)

        assert level1.trust_ceiling == 600
        assert level2.trust_ceiling == 600  # can't exceed parent
        assert level3.trust_ceiling == 300


# ── Integration: TrustScore + DelegationScope ─────────────────


@pytest.mark.skipif(not _has_adk, reason="adk_agentmesh not installed")
class TestTrustCeilingIntegration:
    """End-to-end: parent trust flows through delegation to child score."""

    def test_parent_trust_becomes_child_ceiling(self):
        parent_score = TrustScore(agent_did="did:mesh:parent", total_score=700)

        scope = DelegationScope(trust_ceiling=parent_score.total_score)
        child_scope = scope.narrow()

        child_score = TrustScore(
            agent_did="did:mesh:child",
            trust_ceiling=child_scope.trust_ceiling,
        )

        # Child starts at default 500, below ceiling 700
        assert child_score.total_score == 500
        # Child cannot exceed parent's score at delegation time
        child_score.update(900, {})
        assert child_score.total_score == 700

    def test_low_trust_parent_constrains_child(self):
        parent_score = TrustScore(agent_did="did:mesh:parent", total_score=250)

        scope = DelegationScope(trust_ceiling=parent_score.total_score)
        child_scope = scope.narrow()

        child_score = TrustScore(
            agent_did="did:mesh:child",
            trust_ceiling=child_scope.trust_ceiling,
        )

        # Default 500 clamped to ceiling 250
        assert child_score.total_score == 250
        # Even perfect behavior can't push past ceiling
        child_score.update(1000, {})
        assert child_score.total_score == 250
