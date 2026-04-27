#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for contributor_check.py."""

from __future__ import annotations

import json
import sys
import os
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from contributor_check import (
    Signal,
    ReputationReport,
    check_account_shape,
    check_contributor,
    check_feature_overlap,
    check_thin_credibility,
    format_report,
    _check_fork_burst,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_user(
    created_days_ago: int = 365,
    public_repos: int = 10,
    followers: int = 50,
    following: int = 20,
    **kwargs,
) -> dict:
    """Create a mock GitHub user profile."""
    created = datetime.now(timezone.utc) - timedelta(days=created_days_ago)
    return {
        "login": kwargs.get("login", "test-user"),
        "name": kwargs.get("name", "Test User"),
        "bio": kwargs.get("bio", "A developer"),
        "company": kwargs.get("company"),
        "created_at": created.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "public_repos": public_repos,
        "followers": followers,
        "following": following,
    }


# ---------------------------------------------------------------------------
# Account shape tests
# ---------------------------------------------------------------------------

class TestAccountShape:
    def test_normal_account_no_signals(self):
        user = _make_user(created_days_ago=730, public_repos=15, followers=50, following=30)
        signals = check_account_shape(user)
        assert len(signals) == 0

    def test_high_repo_velocity(self):
        user = _make_user(created_days_ago=30, public_repos=20)
        signals = check_account_shape(user)
        names = [s.name for s in signals]
        assert "repo_velocity" in names or "new_account_burst" in names

    def test_following_farming_high(self):
        user = _make_user(followers=10, following=500)
        signals = check_account_shape(user)
        names = [s.name for s in signals]
        assert "following_farming" in names

    def test_following_farming_extreme(self):
        user = _make_user(followers=94, following=2092)
        signals = check_account_shape(user)
        farm_signals = [s for s in signals if s.name == "following_farming"]
        assert len(farm_signals) == 1
        assert farm_signals[0].severity == "HIGH"

    def test_new_account_burst(self):
        user = _make_user(created_days_ago=60, public_repos=54)
        signals = check_account_shape(user)
        burst = [s for s in signals if s.name == "new_account_burst"]
        assert len(burst) == 1
        assert burst[0].severity == "HIGH"

    def test_zero_followers_with_repos(self):
        user = _make_user(followers=0, following=0, public_repos=20)
        signals = check_account_shape(user)
        names = [s.name for s in signals]
        assert "zero_followers" in names

    def test_established_account_no_flags(self):
        user = _make_user(created_days_ago=1000, public_repos=30, followers=200, following=50)
        signals = check_account_shape(user)
        assert all(s.severity != "HIGH" for s in signals)


# ---------------------------------------------------------------------------
# Report tests
# ---------------------------------------------------------------------------

class TestReputationReport:
    def test_low_risk_no_signals(self):
        report = ReputationReport(username="clean-user")
        assert report.compute_risk() == "LOW"

    def test_medium_risk_one_high(self):
        report = ReputationReport(username="sus-user")
        report.add(Signal("test", "HIGH", "test detail"))
        assert report.compute_risk() == "MEDIUM"

    def test_high_risk_two_high(self):
        report = ReputationReport(username="claw-user")
        report.add(Signal("test1", "HIGH", "detail 1"))
        report.add(Signal("test2", "HIGH", "detail 2"))
        assert report.compute_risk() == "HIGH"

    def test_medium_risk_three_medium(self):
        report = ReputationReport(username="borderline-user")
        report.add(Signal("t1", "MEDIUM", "d1"))
        report.add(Signal("t2", "MEDIUM", "d2"))
        report.add(Signal("t3", "MEDIUM", "d3"))
        assert report.compute_risk() == "MEDIUM"


# ---------------------------------------------------------------------------
# Format tests
# ---------------------------------------------------------------------------

class TestFormat:
    def test_text_output_contains_username(self):
        report = ReputationReport(username="example-user")
        report.risk = "LOW"
        output = format_report(report)
        assert "example-user" in output
        assert "LOW" in output

    def test_json_output_valid(self):
        report = ReputationReport(username="json-user")
        report.risk = "HIGH"
        report.add(Signal("test_sig", "HIGH", "some detail"))
        output = format_report(report, as_json=True)
        data = json.loads(output)
        assert data["username"] == "json-user"
        assert data["risk"] == "HIGH"
        assert len(data["signals"]) == 1
        assert data["signals"][0]["name"] == "test_sig"

    def test_text_output_signals_displayed(self):
        report = ReputationReport(username="sig-user")
        report.add(Signal("spray", "HIGH", "5 repos in 7 days"))
        output = format_report(report)
        assert "spray" in output
        assert "5 repos in 7 days" in output


# ---------------------------------------------------------------------------
# Integration test (mocked API)
# ---------------------------------------------------------------------------

class TestCheckContributor:
    @patch("contributor_check._api")
    def test_user_not_found(self, mock_api):
        mock_api.return_value = None
        report = check_contributor("ghost-user")
        assert report.risk == "UNKNOWN"
        assert any(s.name == "user_not_found" for s in report.signals)

    @patch("contributor_check._search_issues")
    @patch("contributor_check._api")
    def test_clean_user(self, mock_api, mock_search):
        def api_side_effect(path, params=None):
            if "/users/" in path and "/repos" not in path:
                return _make_user(created_days_ago=500, public_repos=8, followers=100, following=30)
            if "/repos" in path:
                return []
            return []

        mock_api.side_effect = api_side_effect
        mock_search.return_value = []
        report = check_contributor("clean-dev")
        assert report.risk == "LOW"
        assert len(report.signals) == 0

    @patch("contributor_check._search_issues")
    @patch("contributor_check._api")
    def test_suspicious_user(self, mock_api, mock_search):
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        def api_side_effect(path, params=None):
            if "/users/" in path and "/repos" not in path:
                return _make_user(
                    login="claw-bot",
                    created_days_ago=57,
                    public_repos=54,
                    followers=2,
                    following=0,
                )
            if "/repos" in path:
                return [
                    {
                        "name": f"agent-governance-{i}",
                        "description": "governance toolkit",
                        "topics": ["agent-governance"],
                        "created_at": now_str,
                    }
                    for i in range(20)
                ]
            return []

        mock_api.side_effect = api_side_effect
        mock_search.return_value = []

        report = check_contributor("claw-bot")
        assert report.risk in ("MEDIUM", "HIGH")
        signal_names = [s.name for s in report.signals]
        assert "new_account_burst" in signal_names or "repo_velocity" in signal_names


# ---------------------------------------------------------------------------
# Fork burst tests
# ---------------------------------------------------------------------------

class TestForkBurst:
    def test_no_forks_no_signal(self):
        repos = [
            {"name": "my-project", "fork": False, "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")},
        ]
        signals = _check_fork_burst(repos)
        assert len(signals) == 0

    def test_awesome_fork_burst_detected(self):
        now = datetime.now(timezone.utc)
        repos = [
            {"name": f"awesome-list-{i}", "fork": True, "description": "curated list", "created_at": (now - timedelta(hours=i)).strftime("%Y-%m-%dT%H:%M:%SZ")}
            for i in range(5)
        ]
        signals = _check_fork_burst(repos)
        names = [s.name for s in signals]
        assert "awesome_fork_burst" in names
        burst = [s for s in signals if s.name == "awesome_fork_burst"]
        assert burst[0].severity == "HIGH"

    def test_general_fork_burst_medium(self):
        now = datetime.now(timezone.utc)
        repos = [
            {"name": f"project-{i}", "fork": True, "created_at": (now - timedelta(hours=i * 2)).strftime("%Y-%m-%dT%H:%M:%SZ")}
            for i in range(6)
        ]
        signals = _check_fork_burst(repos)
        names = [s.name for s in signals]
        assert "fork_burst" in names

    def test_old_forks_ignored(self):
        old = datetime.now(timezone.utc) - timedelta(days=120)
        repos = [
            {"name": f"awesome-old-{i}", "fork": True, "description": "awesome list", "created_at": (old + timedelta(hours=i)).strftime("%Y-%m-%dT%H:%M:%SZ")}
            for i in range(5)
        ]
        signals = _check_fork_burst(repos)
        assert len(signals) == 0


# ---------------------------------------------------------------------------
# Feature overlap tests
# ---------------------------------------------------------------------------

class TestFeatureOverlap:
    @patch("contributor_check._api")
    def test_clone_repo_detected(self, mock_api):
        def api_side_effect(path, params=None):
            if "/repos" in path and "readme" not in path:
                return [{
                    "name": "my-agent-guard",
                    "fork": False,
                    "description": "policy engine with mcp scanner, ed25519 agent identity, execution sandbox, audit trail, circuit breaker, owasp agentic compliance",
                    "topics": ["kill-switch", "trust-scoring"],
                    "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "stargazers_count": 1,
                    "full_name": "clone-user/my-agent-guard",
                }]
            if "readme" in path:
                return None
            return []

        mock_api.side_effect = api_side_effect
        signals = check_feature_overlap("clone-user", "microsoft/agent-governance-toolkit")
        assert any(s.name == "feature_overlap" and s.severity == "HIGH" for s in signals)

    @patch("contributor_check._api")
    def test_unrelated_repo_no_signal(self, mock_api):
        def api_side_effect(path, params=None):
            if "/repos" in path:
                return [{
                    "name": "my-website",
                    "fork": False,
                    "description": "personal blog built with Next.js",
                    "topics": ["react", "nextjs"],
                    "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "stargazers_count": 5,
                }]
            return []

        mock_api.side_effect = api_side_effect
        signals = check_feature_overlap("normal-user", "microsoft/agent-governance-toolkit")
        assert len(signals) == 0

    def test_no_target_repo_skips(self):
        signals = check_feature_overlap("anyone", None)
        assert len(signals) == 0


# ---------------------------------------------------------------------------
# Thin credibility tests
# ---------------------------------------------------------------------------

class TestThinCredibility:
    @patch("contributor_check._search_issues")
    @patch("contributor_check._api")
    def test_thin_repo_promoted_across_orgs(self, mock_api, mock_search):
        now = datetime.now(timezone.utc)

        def api_side_effect(path, params=None):
            if "/repos" in path:
                return [{
                    "name": "my-framework",
                    "fork": False,
                    "full_name": "promo-user/my-framework",
                    "description": "my governance framework",
                    "created_at": (now - timedelta(days=10)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "stargazers_count": 0,
                }]
            return []

        mock_api.side_effect = api_side_effect
        mock_search.return_value = [
            {
                "title": "Add my-framework support",
                "body": "my-framework provides governance...",
                "repository_url": "https://api.github.com/repos/aaif/project-proposals",
                "created_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            },
            {
                "title": "Integrate my-framework",
                "body": "my-framework would be great for...",
                "repository_url": "https://api.github.com/repos/openssf/some-project",
                "created_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            },
        ]
        signals = check_thin_credibility("promo-user", "microsoft/agent-governance-toolkit")
        assert any(s.name == "thin_credibility" and s.severity == "HIGH" for s in signals)

    @patch("contributor_check._search_issues")
    @patch("contributor_check._api")
    def test_established_repo_no_signal(self, mock_api, mock_search):
        now = datetime.now(timezone.utc)

        def api_side_effect(path, params=None):
            if "/repos" in path:
                return [{
                    "name": "mature-project",
                    "fork": False,
                    "full_name": "good-user/mature-project",
                    "description": "well established project",
                    "created_at": (now - timedelta(days=365)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "stargazers_count": 500,
                }]
            return []

        mock_api.side_effect = api_side_effect
        mock_search.return_value = []
        signals = check_thin_credibility("good-user", "microsoft/agent-governance-toolkit")
        assert len(signals) == 0
