#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for established-account dampening in contributor_check.py."""

from __future__ import annotations

import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import patch

import pytest

# Add scripts/ to path so we can import contributor_check
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from contributor_check import (
    ReputationReport,
    Signal,
    _dampen_for_established_accounts,
    _is_established,
)


def _make_user(age_days: int = 2000, followers: int = 200, public_repos: int = 50) -> dict:
    """Create a mock GitHub user dict."""
    created = datetime.now(timezone.utc) - timedelta(days=age_days)
    return {
        "created_at": created.isoformat(),
        "followers": followers,
        "following": 30,
        "public_repos": public_repos,
    }


# ---------------------------------------------------------------------------
# _is_established
# ---------------------------------------------------------------------------

class TestIsEstablished:
    def test_established_account(self):
        user = _make_user(age_days=2000, followers=200, public_repos=50)
        assert _is_established(user) is True

    def test_new_account_not_established(self):
        user = _make_user(age_days=100, followers=200, public_repos=50)
        assert _is_established(user) is False

    def test_low_followers_not_established(self):
        user = _make_user(age_days=2000, followers=10, public_repos=50)
        assert _is_established(user) is False

    def test_low_repos_not_established(self):
        user = _make_user(age_days=2000, followers=200, public_repos=5)
        assert _is_established(user) is False

    def test_boundary_365_not_established(self):
        user = _make_user(age_days=365, followers=50, public_repos=20)
        assert _is_established(user) is False

    def test_boundary_366_is_established(self):
        user = _make_user(age_days=366, followers=50, public_repos=20)
        assert _is_established(user) is True


# ---------------------------------------------------------------------------
# _dampen_for_established_accounts
# ---------------------------------------------------------------------------

class TestDampening:
    def test_dampens_recent_repo_burst(self):
        """Established account with moderate repo burst gets dampened."""
        report = ReputationReport(username="testuser")
        report.add(Signal(name="recent_repo_burst", severity="HIGH",
                          detail="20 repos in last 90 days", value=20))
        user = _make_user(age_days=5000, followers=1400, public_repos=300)
        _dampen_for_established_accounts(report, user)
        assert report.signals[0].severity == "LOW"
        assert "dampened" in report.signals[0].detail

    def test_dampens_cross_repo_spray(self):
        """Established account with moderate spray gets dampened to MEDIUM."""
        report = ReputationReport(username="testuser")
        report.add(Signal(name="cross_repo_spray", severity="HIGH",
                          detail="6 repos in 7 days", value=6))
        user = _make_user(age_days=5000, followers=1400, public_repos=300)
        _dampen_for_established_accounts(report, user)
        assert report.signals[0].severity == "MEDIUM"
        assert "dampened" in report.signals[0].detail

    def test_dampens_cross_repo_spread(self):
        """Established account spread signal gets dampened."""
        report = ReputationReport(username="testuser")
        report.add(Signal(name="cross_repo_spread", severity="MEDIUM",
                          detail="Issues in 10 repos", value=10))
        user = _make_user(age_days=5000, followers=1400, public_repos=300)
        _dampen_for_established_accounts(report, user)
        assert report.signals[0].severity == "LOW"

    def test_extreme_repo_burst_not_dampened(self):
        """Even established accounts keep HIGH for extreme bursts (>30)."""
        report = ReputationReport(username="testuser")
        report.add(Signal(name="recent_repo_burst", severity="HIGH",
                          detail="40 repos in last 90 days", value=40))
        user = _make_user(age_days=5000, followers=1400, public_repos=300)
        _dampen_for_established_accounts(report, user)
        assert report.signals[0].severity == "HIGH"
        assert "dampened" not in report.signals[0].detail

    def test_extreme_spray_not_dampened(self):
        """Even established accounts keep HIGH for extreme spray (>8)."""
        report = ReputationReport(username="testuser")
        report.add(Signal(name="cross_repo_spray", severity="HIGH",
                          detail="12 repos in 7 days", value=12))
        user = _make_user(age_days=5000, followers=1400, public_repos=300)
        _dampen_for_established_accounts(report, user)
        assert report.signals[0].severity == "HIGH"

    def test_no_dampening_for_new_account(self):
        """New accounts don't get any dampening."""
        report = ReputationReport(username="testuser")
        report.add(Signal(name="recent_repo_burst", severity="HIGH",
                          detail="20 repos in last 90 days", value=20))
        user = _make_user(age_days=30, followers=5, public_repos=20)
        _dampen_for_established_accounts(report, user)
        assert report.signals[0].severity == "HIGH"

    def test_no_dampening_with_abuse_signals(self):
        """Established accounts with abuse signals don't get dampened."""
        report = ReputationReport(username="testuser")
        report.add(Signal(name="recent_repo_burst", severity="HIGH",
                          detail="20 repos in last 90 days", value=20))
        report.add(Signal(name="credential_laundering", severity="HIGH",
                          detail="Suspicious credential pattern"))
        user = _make_user(age_days=5000, followers=1400, public_repos=300)
        _dampen_for_established_accounts(report, user)
        assert report.signals[0].severity == "HIGH"  # NOT dampened

    def test_no_dampening_with_thin_credibility(self):
        """Thin credibility blocks dampening."""
        report = ReputationReport(username="testuser")
        report.add(Signal(name="cross_repo_spray", severity="HIGH",
                          detail="6 repos in 7 days", value=6))
        report.add(Signal(name="thin_credibility", severity="MEDIUM",
                          detail="No substantive contributions"))
        user = _make_user(age_days=5000, followers=1400, public_repos=300)
        _dampen_for_established_accounts(report, user)
        assert report.signals[0].severity == "HIGH"  # NOT dampened

    def test_no_dampening_with_self_promotion(self):
        """Self-promotion spray blocks dampening."""
        report = ReputationReport(username="testuser")
        report.add(Signal(name="recent_repo_burst", severity="HIGH",
                          detail="20 repos in last 90 days", value=20))
        report.add(Signal(name="self_promotion_spray", severity="HIGH",
                          detail="Promoting own repos"))
        user = _make_user(age_days=5000, followers=1400, public_repos=300)
        _dampen_for_established_accounts(report, user)
        assert report.signals[0].severity == "HIGH"  # NOT dampened

    def test_unrelated_signals_not_touched(self):
        """Signals not in the dampen rules are left alone."""
        report = ReputationReport(username="testuser")
        report.add(Signal(name="governance_theme_concentration", severity="MEDIUM",
                          detail="8/10 repos are governance themed", value=8))
        user = _make_user(age_days=5000, followers=1400, public_repos=300)
        _dampen_for_established_accounts(report, user)
        assert report.signals[0].severity == "MEDIUM"

    def test_aaronpowell_scenario(self):
        """Reproduce the Aaron Powell false positive: established account,
        moderate repo burst + moderate spray -> should NOT be HIGH overall."""
        report = ReputationReport(username="aaronpowell")
        report.add(Signal(name="recent_repo_burst", severity="HIGH",
                          detail="20 repos created in last 90 days", value=20))
        report.add(Signal(name="cross_repo_spray", severity="HIGH",
                          detail="Issues filed in 6 repos within 7 days", value=6))
        user = _make_user(age_days=5685, followers=1407, public_repos=316)
        _dampen_for_established_accounts(report, user)
        report.compute_risk()
        # After dampening: repo_burst=LOW, spray=MEDIUM
        assert report.signals[0].severity == "LOW"
        assert report.signals[1].severity == "MEDIUM"
        assert report.risk != "HIGH"
        assert report.risk == "LOW"  # 0 HIGH, 1 MEDIUM -> LOW
