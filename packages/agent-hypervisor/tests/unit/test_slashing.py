# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the penalty engine."""

import pytest

from hypervisor.liability.slashing import SlashingEngine
from hypervisor.liability.vouching import VouchingEngine


class TestSlashingEngine:
    def setup_method(self):
        self.vouching = VouchingEngine()
        self.slashing = SlashingEngine(self.vouching)
        self.session = "session:test-penalize"

    @pytest.mark.skip("Feature not available in Public Preview")
    def test_vouchee_blacklisted(self):
        """Sponsored agent σ → 0 on violation."""
        scores = {"did:mesh:bad": 0.7, "did:mesh:good": 0.9}
        self.vouching.vouch("did:mesh:good", "did:mesh:bad", self.session, 0.9)

        result = self.slashing.slash(
            vouchee_did="did:mesh:bad",
            session_id=self.session,
            vouchee_sigma=0.7,
            risk_weight=0.5,
            reason="Policy violation",
            agent_scores=scores,
        )

        assert scores["did:mesh:bad"] == 0.0
        assert result.vouchee_sigma_after == 0.0

    @pytest.mark.skip("Feature not available in Public Preview")
    def test_voucher_collateral_clip(self):
        """σ_new = σ_old × (1 - ω)"""
        scores = {"did:mesh:bad": 0.5, "did:mesh:sponsor": 0.9}
        self.vouching.vouch("did:mesh:sponsor", "did:mesh:bad", self.session, 0.9)

        result = self.slashing.slash(
            vouchee_did="did:mesh:bad",
            session_id=self.session,
            vouchee_sigma=0.5,
            risk_weight=0.5,
            reason="Hallucination",
            agent_scores=scores,
        )

        # σ_new = 0.9 * (1 - 0.5) = 0.45
        assert len(result.voucher_clips) == 1
        clip = result.voucher_clips[0]
        assert abs(clip.sigma_before - 0.9) < 1e-9
        assert abs(clip.sigma_after - 0.45) < 1e-9
        assert abs(scores["did:mesh:sponsor"] - 0.45) < 1e-9

    def test_sigma_floor_respected(self):
        """Penalty should not reduce below SIGMA_FLOOR."""
        scores = {"did:mesh:bad": 0.1, "did:mesh:sponsor": 0.06}
        self.vouching.vouch("did:mesh:sponsor", "did:mesh:bad", self.session, 0.8)

        self.slashing.slash(
            vouchee_did="did:mesh:bad",
            session_id=self.session,
            vouchee_sigma=0.1,
            risk_weight=0.95,
            reason="Fraud",
            agent_scores=scores,
        )

        assert scores["did:mesh:sponsor"] >= SlashingEngine.SIGMA_FLOOR

    @pytest.mark.skip("Feature not available in Public Preview")
    def test_multiple_vouchers_all_clipped(self):
        """All sponsors for a sponsored agent get clipped."""
        scores = {"did:mesh:bad": 0.4, "did:mesh:v1": 0.8, "did:mesh:v2": 0.7}
        self.vouching.vouch("did:mesh:v1", "did:mesh:bad", self.session, 0.8)
        self.vouching.vouch("did:mesh:v2", "did:mesh:bad", self.session, 0.7)

        result = self.slashing.slash(
            vouchee_did="did:mesh:bad",
            session_id=self.session,
            vouchee_sigma=0.4,
            risk_weight=0.3,
            reason="Mute triggered",
            agent_scores=scores,
        )

        assert len(result.voucher_clips) == 2
        # v1: 0.8 * (1-0.3) = 0.56, v2: 0.7 * (1-0.3) = 0.49
        assert abs(scores["did:mesh:v1"] - 0.56) < 1e-9
        assert abs(scores["did:mesh:v2"] - 0.49) < 1e-9
