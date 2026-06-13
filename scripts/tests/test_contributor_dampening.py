#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for established-account dampening in contributor_check.py."""

# Synthetic GitHub usernames/org logins used only as test fixtures below.
# cspell:ignore someoneelse freshorg freerider bigorg realauthor sockpuppet orgbacked splitcloner maint

from __future__ import annotations

import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Add scripts/ to path so we can import contributor_check
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from contributor_check import (
    ReputationReport,
    Signal,
    _dampen_for_established_accounts,
    _established_credibility,
    _has_prior_target_contribution,
    _is_established,
    _org_owned_established,
)


@pytest.fixture(autouse=True)
def _no_api_pacing(monkeypatch):
    """Zero the maintainer-lookup API pacing so unit tests do not sleep."""
    monkeypatch.setattr(
        "contributor_check._MAINTAINER_LOOKUP_PACE_SECONDS", 0, raising=False
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


# ---------------------------------------------------------------------------
# Org-aware + prior-interaction established credibility (Phase 1)
# ---------------------------------------------------------------------------

def _recent_iso(days: int = 10) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _aged_iso(days: int = 800) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")


class TestOrgOwnedEstablished:
    def test_true_when_aged_repo_and_user_contributed(self):
        def fake_api(path, params=None):
            if path == "/users/consolidator/orgs":
                return [{"login": "myorg"}]
            if path == "/orgs/myorg/repos":
                return [{"name": "flagship", "stargazers_count": 40,
                         "fork": False, "created_at": _aged_iso(800)}]
            if path == "/repos/myorg/flagship/contributors":
                return [{"login": "someoneelse"}, {"login": "Consolidator"}]
            return []
        with patch("contributor_check._api", side_effect=fake_api):
            ok, evidence = _org_owned_established("consolidator")
        assert ok is True
        assert "myorg/flagship" in evidence

    def test_false_when_repo_not_aged(self):
        """60 stars but created this week: fails the age branch (star-buying guard)."""
        def fake_api(path, params=None):
            if path == "/users/promo/orgs":
                return [{"login": "freshorg"}]
            if path == "/orgs/freshorg/repos":
                return [{"name": "bought", "stargazers_count": 60,
                         "fork": False, "created_at": _recent_iso(5)}]
            return []
        with patch("contributor_check._api", side_effect=fake_api):
            ok, _ = _org_owned_established("promo")
        assert ok is False

    def test_false_when_user_not_contributor(self):
        """Aged, well-starred org repo but the user is NOT a contributor
        (mirror-a-famous-repo guard)."""
        def fake_api(path, params=None):
            if path == "/users/freerider/orgs":
                return [{"login": "bigorg"}]
            if path == "/orgs/bigorg/repos":
                return [{"name": "famous", "stargazers_count": 5000,
                         "fork": False, "created_at": _aged_iso(1500)}]
            if path == "/repos/bigorg/famous/contributors":
                return [{"login": "realauthor"}]
            return []
        with patch("contributor_check._api", side_effect=fake_api):
            ok, _ = _org_owned_established("freerider")
        assert ok is False

    def test_false_when_no_orgs(self):
        with patch("contributor_check._api", return_value=[]):
            ok, _ = _org_owned_established("loner")
        assert ok is False


class TestPriorTargetContribution:
    TARGET = "microsoft/agent-governance-toolkit"

    def _prs(self, n):
        return [{"number": i, "author_association": "CONTRIBUTOR"} for i in range(1, n + 1)]

    def test_true_two_distinct_maintainer_merges(self):
        prs = self._prs(2)

        def fake_api(path, params=None):
            if path == f"/repos/{self.TARGET}/pulls/1":
                return {"merged_by": {"login": "maintA"}}
            if path == f"/repos/{self.TARGET}/pulls/2":
                return {"merged_by": {"login": "maintB"}}
            return None

        with patch("contributor_check._search_issues", return_value=prs), \
             patch("contributor_check._api", side_effect=fake_api), \
             patch("contributor_check._is_public_org_member", return_value=True):
            assert _has_prior_target_contribution("dev", self.TARGET) is True

    def test_false_single_maintainer_merge(self):
        prs = self._prs(1)
        with patch("contributor_check._search_issues", return_value=prs), \
             patch("contributor_check._api", return_value={"merged_by": {"login": "maintA"}}), \
             patch("contributor_check._is_public_org_member", return_value=True):
            assert _has_prior_target_contribution("dev", self.TARGET) is False

    def test_false_merger_not_org_member(self):
        """Sock-puppet-ring defense: non-member mergers do not count."""
        prs = self._prs(2)

        def fake_api(path, params=None):
            return {"merged_by": {"login": "sockpuppet"}}

        with patch("contributor_check._search_issues", return_value=prs), \
             patch("contributor_check._api", side_effect=fake_api), \
             patch("contributor_check._is_public_org_member", return_value=False):
            assert _has_prior_target_contribution("dev", self.TARGET) is False

    def test_false_same_maintainer_twice(self):
        """Distinct-maintainer requirement: same merger on both PRs counts once."""
        prs = self._prs(2)
        with patch("contributor_check._search_issues", return_value=prs), \
             patch("contributor_check._api", return_value={"merged_by": {"login": "maintA"}}), \
             patch("contributor_check._is_public_org_member", return_value=True):
            assert _has_prior_target_contribution("dev", self.TARGET) is False

    def test_false_self_merged(self):
        prs = self._prs(2)
        with patch("contributor_check._search_issues", return_value=prs), \
             patch("contributor_check._api", return_value={"merged_by": {"login": "dev"}}), \
             patch("contributor_check._is_public_org_member", return_value=True):
            assert _has_prior_target_contribution("dev", self.TARGET) is False

    def test_false_when_none(self):
        with patch("contributor_check._search_issues", return_value=[]):
            assert _has_prior_target_contribution("dev", self.TARGET) is False

    def test_false_without_target(self):
        assert _has_prior_target_contribution("dev", None) is False

    def test_paces_between_pr_detail_calls(self):
        """Per-PR detail calls are paced (sleep BETWEEN calls), but never before
        the first call. Non-member mergers force the no-early-exit path so all
        three PRs are looked up -> exactly two pacing sleeps."""
        prs = self._prs(3)
        sleep_mock = MagicMock()
        with patch("contributor_check._search_issues", return_value=prs), \
             patch("contributor_check._api", return_value={"merged_by": {"login": "x"}}), \
             patch("contributor_check._is_public_org_member", return_value=False), \
             patch("contributor_check._MAINTAINER_LOOKUP_PACE_SECONDS", 0.5), \
             patch("contributor_check.time.sleep", sleep_mock):
            assert _has_prior_target_contribution("dev", self.TARGET) is False
        assert sleep_mock.call_count == 2
        sleep_mock.assert_called_with(0.5)

    def test_no_pacing_for_single_pr(self):
        """A single PR lookup makes one API call and never paces."""
        prs = self._prs(1)
        sleep_mock = MagicMock()
        with patch("contributor_check._search_issues", return_value=prs), \
             patch("contributor_check._api", return_value={"merged_by": {"login": "x"}}), \
             patch("contributor_check._is_public_org_member", return_value=False), \
             patch("contributor_check._MAINTAINER_LOOKUP_PACE_SECONDS", 0.5), \
             patch("contributor_check.time.sleep", sleep_mock):
            assert _has_prior_target_contribution("dev", self.TARGET) is False
        assert sleep_mock.call_count == 0


class TestEstablishedCredibility:
    def test_personal_established_full_tier(self):
        user = _make_user(age_days=2000, followers=200, public_repos=50)
        assert _established_credibility(user) == (True, True)

    def test_org_backed_is_partial_tier(self):
        user = _make_user(age_days=2000, followers=11, public_repos=3)
        assert _established_credibility(user, org_backed=True) == (True, False)

    def test_prior_interaction_is_partial_tier(self):
        user = _make_user(age_days=2000, followers=11, public_repos=3)
        assert _established_credibility(user, prior_interaction=True) == (True, False)

    def test_none_not_credible(self):
        user = _make_user(age_days=2000, followers=11, public_repos=3)
        assert _established_credibility(user) == (False, False)


class TestDampenFullTier:
    def test_explicit_established_dampens_thin_personal_account(self):
        report = ReputationReport(username="consolidator")
        report.add(Signal(name="recent_repo_burst", severity="HIGH",
                          detail="20 repos in 90 days", value=20))
        user = _make_user(age_days=2000, followers=11, public_repos=3)
        assert _is_established(user) is False
        _dampen_for_established_accounts(report, user, established=True, full=True)
        assert report.signals[0].severity == "LOW"

    def test_backward_compatible_default(self):
        report = ReputationReport(username="established")
        report.add(Signal(name="recent_repo_burst", severity="HIGH",
                          detail="20 repos in 90 days", value=20))
        user = _make_user(age_days=2000, followers=200, public_repos=50)
        _dampen_for_established_accounts(report, user)  # no established=/full=
        assert report.signals[0].severity == "LOW"

    def test_explicit_false_blocks_dampening(self):
        report = ReputationReport(username="x")
        report.add(Signal(name="recent_repo_burst", severity="HIGH",
                          detail="20 repos", value=20))
        user = _make_user(age_days=2000, followers=200, public_repos=50)
        _dampen_for_established_accounts(report, user, established=False)
        assert report.signals[0].severity == "HIGH"


class TestPartialTier:
    def test_partial_does_not_dampen_volume_burst(self):
        """Org/prior credibility does NOT vouch for a sudden volume burst."""
        report = ReputationReport(username="orgbacked")
        report.add(Signal(name="recent_repo_burst", severity="HIGH", detail="20", value=20))
        user = _make_user(age_days=2000, followers=11, public_repos=3)
        _dampen_for_established_accounts(report, user, established=True, full=False)
        assert report.signals[0].severity == "HIGH"

    def test_partial_dampens_single_feature_overlap(self):
        report = ReputationReport(username="specialist")
        report.add(Signal(name="feature_overlap", severity="HIGH", detail="4/6", value=4))
        user = _make_user(age_days=2000, followers=11, public_repos=3)
        _dampen_for_established_accounts(report, user, established=True, full=False)
        assert report.signals[0].severity == "MEDIUM"


class TestFeatureOverlapDampening:
    def test_single_overlap_dampened_full_tier(self):
        report = ReputationReport(username="specialist")
        report.add(Signal(name="feature_overlap", severity="HIGH", detail="4/6", value=4))
        user = _make_user(age_days=2000, followers=200, public_repos=50)
        _dampen_for_established_accounts(report, user, established=True, full=True)
        assert report.signals[0].severity == "MEDIUM"

    def test_multi_overlap_stays_high(self):
        """Two-plus feature_overlap HIGH = split multi-repo clone -> non-dampenable."""
        report = ReputationReport(username="splitcloner")
        report.add(Signal(name="feature_overlap", severity="HIGH", detail="repoA 4/6", value=4))
        report.add(Signal(name="feature_overlap", severity="HIGH", detail="repoB 5/6", value=5))
        user = _make_user(age_days=2000, followers=200, public_repos=50)
        _dampen_for_established_accounts(report, user, established=True, full=True)
        assert all(s.severity == "HIGH" for s in report.signals)

    def test_single_overlap_no_longer_blocks_burst(self):
        report = ReputationReport(username="specialist")
        report.add(Signal(name="recent_repo_burst", severity="HIGH", detail="20", value=20))
        report.add(Signal(name="feature_overlap", severity="HIGH", detail="4/6", value=4))
        user = _make_user(age_days=2000, followers=200, public_repos=50)
        _dampen_for_established_accounts(report, user, established=True, full=True)
        burst = next(s for s in report.signals if s.name == "recent_repo_burst")
        assert burst.severity == "LOW"

    def test_six_bucket_overlap_stays_high(self):
        report = ReputationReport(username="cloner")
        report.add(Signal(name="feature_overlap", severity="HIGH", detail="6/6", value=6))
        user = _make_user(age_days=2000, followers=200, public_repos=50)
        _dampen_for_established_accounts(report, user, established=True, full=True)
        assert report.signals[0].severity == "HIGH"

    def test_real_abuse_still_blocks_dampening(self):
        report = ReputationReport(username="abuser")
        report.add(Signal(name="recent_repo_burst", severity="HIGH", detail="20", value=20))
        report.add(Signal(name="credential_laundering", severity="HIGH", detail="x"))
        user = _make_user(age_days=2000, followers=200, public_repos=50)
        _dampen_for_established_accounts(report, user, established=True, full=True)
        burst = next(s for s in report.signals if s.name == "recent_repo_burst")
        assert burst.severity == "HIGH"


class TestDomainSpecialistIntegration:
    def test_single_overlap_partial_credibility_not_high(self):
        """Domain specialist: ONE overlapping repo + partial credibility -> not HIGH."""
        report = ReputationReport(username="specialist")
        report.add(Signal(name="feature_overlap", severity="HIGH", detail="repoA 4/6", value=4))
        user = _make_user(age_days=2000, followers=11, public_repos=3)
        _dampen_for_established_accounts(report, user, established=True, full=False)
        report.compute_risk()
        assert report.risk != "HIGH"

    def test_multi_overlap_stays_high_even_credible(self):
        """Split multi-repo clone stays HIGH even for a credible account."""
        report = ReputationReport(username="splitcloner")
        report.add(Signal(name="feature_overlap", severity="HIGH", detail="repoA 4/6", value=4))
        report.add(Signal(name="feature_overlap", severity="HIGH", detail="repoB 5/6", value=5))
        user = _make_user(age_days=2000, followers=11, public_repos=3)
        _dampen_for_established_accounts(report, user, established=True, full=False)
        report.compute_risk()
        assert report.risk == "HIGH"

    def test_throwaway_promoter_still_high(self):
        report = ReputationReport(username="throwaway")
        report.add(Signal(name="feature_overlap", severity="HIGH", detail="repoA 4/6", value=4))
        report.add(Signal(name="feature_overlap", severity="HIGH", detail="repoB 5/6", value=5))
        user = _make_user(age_days=20, followers=0, public_repos=3)
        _dampen_for_established_accounts(report, user, established=False)
        report.compute_risk()
        assert report.risk == "HIGH"
