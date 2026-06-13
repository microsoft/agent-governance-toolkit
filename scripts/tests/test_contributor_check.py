#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for contributor_check.py."""

# Synthetic GitHub usernames/org logins used only as test fixtures below.
# cspell:ignore myorg trustedorg randomorg freshclone

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
    check_spray_pattern,
    format_report,
    _check_fork_burst,
    _check_batch_naming,
    _check_self_promotion,
    _fork_has_outgoing_pr,
    _apply_allowlist,
    _is_allowlisted,
    _load_allowlist,
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

    @patch("contributor_check._fork_has_outgoing_pr", return_value=True)
    def test_awesome_forks_with_prs_excluded(self, mock_pr):
        """Forks that have outgoing PRs are legitimate and should not trigger."""
        now = datetime.now(timezone.utc)
        repos = [
            {"name": f"awesome-list-{i}", "fork": True, "description": "curated list", "created_at": (now - timedelta(hours=i)).strftime("%Y-%m-%dT%H:%M:%SZ")}
            for i in range(5)
        ]
        signals = _check_fork_burst(repos, username="testuser")
        names = [s.name for s in signals]
        assert "awesome_fork_burst" not in names

    @patch("contributor_check._fork_has_outgoing_pr", side_effect=lambda u, n: n == "awesome-list-0")
    def test_mixed_forks_partial_prs(self, mock_pr):
        """Only forks without PRs count toward the burst."""
        now = datetime.now(timezone.utc)
        repos = [
            {"name": f"awesome-list-{i}", "fork": True, "description": "curated list", "created_at": (now - timedelta(hours=i)).strftime("%Y-%m-%dT%H:%M:%SZ")}
            for i in range(4)
        ]
        # 4 forks, 1 has PR -> 3 remain, which hits >= 3 threshold
        signals = _check_fork_burst(repos, username="testuser")
        names = [s.name for s in signals]
        assert "awesome_fork_burst" in names

    def test_no_username_skips_pr_check(self):
        """Without username, PR check is skipped (backward compat)."""
        now = datetime.now(timezone.utc)
        repos = [
            {"name": f"awesome-list-{i}", "fork": True, "description": "curated list", "created_at": (now - timedelta(hours=i)).strftime("%Y-%m-%dT%H:%M:%SZ")}
            for i in range(5)
        ]
        signals = _check_fork_burst(repos)
        names = [s.name for s in signals]
        assert "awesome_fork_burst" in names


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


# ---------------------------------------------------------------------------
# Batch naming tests
# ---------------------------------------------------------------------------

class TestBatchNaming:
    def test_many_mcp_repos_same_day(self):
        now = datetime.now(timezone.utc)
        repos = [
            {"name": f"service-{i}-mcp", "fork": False, "stargazers_count": 0,
             "created_at": (now - timedelta(hours=i)).strftime("%Y-%m-%dT%H:%M:%SZ")}
            for i in range(6)
        ]
        signals = _check_batch_naming(repos)
        assert any(s.name == "batch_repo_naming" and s.severity == "HIGH" for s in signals)

    def test_few_repos_no_signal(self):
        now = datetime.now(timezone.utc)
        repos = [
            {"name": "one-mcp", "fork": False, "stargazers_count": 0,
             "created_at": now.strftime("%Y-%m-%dT%H:%M:%SZ")},
            {"name": "two-mcp", "fork": False, "stargazers_count": 0,
             "created_at": now.strftime("%Y-%m-%dT%H:%M:%SZ")},
        ]
        signals = _check_batch_naming(repos)
        assert len(signals) == 0

    def test_high_star_repos_excluded(self):
        now = datetime.now(timezone.utc)
        repos = [
            {"name": f"popular-{i}-mcp", "fork": False, "stargazers_count": 50,
             "created_at": (now - timedelta(hours=i)).strftime("%Y-%m-%dT%H:%M:%SZ")}
            for i in range(6)
        ]
        signals = _check_batch_naming(repos)
        assert len(signals) == 0

    def test_old_repos_excluded(self):
        old = datetime.now(timezone.utc) - timedelta(days=200)
        repos = [
            {"name": f"old-{i}-mcp", "fork": False, "stargazers_count": 0,
             "created_at": (old + timedelta(hours=i)).strftime("%Y-%m-%dT%H:%M:%SZ")}
            for i in range(6)
        ]
        signals = _check_batch_naming(repos)
        assert len(signals) == 0

    def test_medium_for_three_repos(self):
        now = datetime.now(timezone.utc)
        repos = [
            {"name": f"tool-{i}-agent", "fork": False, "stargazers_count": 0,
             "created_at": (now - timedelta(hours=i)).strftime("%Y-%m-%dT%H:%M:%SZ")}
            for i in range(3)
        ]
        signals = _check_batch_naming(repos)
        assert any(s.name == "batch_repo_naming" and s.severity == "MEDIUM" for s in signals)


# ---------------------------------------------------------------------------
# Self-promotion tests
# ---------------------------------------------------------------------------

class TestSelfPromotion:
    def test_promoting_own_repos_high(self):
        user_repos = [
            {"name": "buywhere-mcp", "fork": False, "full_name": "spammer/buywhere-mcp",
             "stargazers_count": 0, "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")},
            {"name": "buywhere", "fork": False, "full_name": "spammer/buywhere",
             "stargazers_count": 0, "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")},
        ]
        issues = [
            {"title": f"Add spammer/buywhere-mcp support", "body": "spammer/buywhere-mcp is great for shopping",
             "repository_url": f"https://api.github.com/repos/org{i}/repo",
             "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
            for i in range(6)
        ]
        signals = _check_self_promotion("spammer", issues, user_repos)
        assert any(s.name == "self_promotion_spray" and s.severity == "HIGH" for s in signals)

    def test_no_self_references_clean(self):
        user_repos = [
            {"name": "my-project", "fork": False, "full_name": "dev/my-project",
             "stargazers_count": 0, "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")},
        ]
        issues = [
            {"title": "Bug in auth flow", "body": "The auth flow crashes when...",
             "repository_url": f"https://api.github.com/repos/org{i}/repo",
             "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
            for i in range(10)
        ]
        signals = _check_self_promotion("dev", issues, user_repos)
        assert len(signals) == 0

    def test_generic_names_not_matched(self):
        user_repos = [
            {"name": "app", "fork": False, "full_name": "dev/app",
             "stargazers_count": 0, "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")},
            {"name": "api", "fork": False, "full_name": "dev/api",
             "stargazers_count": 0, "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")},
            {"name": "web", "fork": False, "full_name": "dev/web",
             "stargazers_count": 0, "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")},
        ]
        issues = [
            {"title": "App crashes on load", "body": "The web api returns 500...",
             "repository_url": f"https://api.github.com/repos/org{i}/repo",
             "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
            for i in range(10)
        ]
        signals = _check_self_promotion("dev", issues, user_repos)
        assert len(signals) == 0

    def test_issues_in_own_org_excluded(self):
        user_repos = [
            {"name": "my-tool", "fork": False, "full_name": "myorg/my-tool",
             "stargazers_count": 0, "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")},
        ]
        issues = [
            {"title": "Update my-tool docs", "body": "my-tool needs better docs",
             "repository_url": "https://api.github.com/repos/myorg/other-repo",
             "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
            for _ in range(10)
        ]
        signals = _check_self_promotion("myorg", issues, user_repos)
        assert len(signals) == 0

    def test_established_repos_not_flagged_as_spam(self):
        """Promoting a well-known project (>50 stars) should not trigger self_promotion_spray."""
        user_repos = [
            {"name": "popular-toolkit", "fork": False, "full_name": "maintainer/popular-toolkit",
             "stargazers_count": 1400,
             "created_at": (datetime.now(timezone.utc) - timedelta(days=800)).strftime("%Y-%m-%dT%H:%M:%SZ")},
        ]
        issues = [
            {"title": f"Integrate maintainer/popular-toolkit", "body": "maintainer/popular-toolkit can help here",
             "repository_url": f"https://api.github.com/repos/org{i}/repo",
             "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
            for i in range(8)
        ]
        signals = _check_self_promotion("maintainer", issues, user_repos)
        assert not any(s.name == "self_promotion_spray" for s in signals)
        assert any(s.name == "established_project_reference" and s.severity == "LOW" for s in signals)

    def test_mixed_thin_and_established_repos(self):
        """When both thin and established repos are promoted, thin-repo spam still fires."""
        now = datetime.now(timezone.utc)
        user_repos = [
            {"name": "good-project", "fork": False, "full_name": "user/good-project",
             "stargazers_count": 200,
             "created_at": (now - timedelta(days=500)).strftime("%Y-%m-%dT%H:%M:%SZ")},
            {"name": "thin-project", "fork": False, "full_name": "user/thin-project",
             "stargazers_count": 0,
             "created_at": now.strftime("%Y-%m-%dT%H:%M:%SZ")},
        ]
        issues = [
            {"title": f"Add user/thin-project", "body": "user/thin-project is useful",
             "repository_url": f"https://api.github.com/repos/org{i}/repo",
             "created_at": now.strftime("%Y-%m-%dT%H:%M:%SZ")}
            for i in range(6)
        ]
        signals = _check_self_promotion("user", issues, user_repos)
        assert any(s.name == "self_promotion_spray" for s in signals)


# ---------------------------------------------------------------------------
# Coordinated promotion tests
# ---------------------------------------------------------------------------

class TestCoordinatedPromotion:
    def test_many_thin_repos_same_targets(self):
        now = datetime.now(timezone.utc)
        thin_names = ["tool-a", "tool-b", "tool-c", "tool-d"]
        repos = [
            {"name": n, "fork": False, "full_name": f"spammer/{n}",
             "created_at": (now - timedelta(days=5)).strftime("%Y-%m-%dT%H:%M:%SZ"),
             "stargazers_count": 0}
            for n in thin_names
        ]

        # Each thin repo promoted to the same 3 orgs
        issues = []
        for n in thin_names:
            for org in ["orgA", "orgB", "orgC"]:
                issues.append({
                    "title": f"Add {n} support",
                    "body": f"{n} integration",
                    "repository_url": f"https://api.github.com/repos/{org}/project",
                    "created_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
                })

        signals = check_thin_credibility("spammer", repos=repos, issues=issues)
        assert any(s.name == "coordinated_promotion" and s.severity == "HIGH" for s in signals)

    def test_different_targets_no_coordination(self):
        now = datetime.now(timezone.utc)
        repos = [
            {"name": f"proj-{i}", "fork": False, "full_name": f"user/proj-{i}",
             "created_at": (now - timedelta(days=5)).strftime("%Y-%m-%dT%H:%M:%SZ"),
             "stargazers_count": 0}
            for i in range(4)
        ]
        # Each repo promoted to completely different orgs
        issues = []
        for i in range(4):
            for j in range(2):
                issues.append({
                    "title": f"Add proj-{i}",
                    "body": f"proj-{i} is useful",
                    "repository_url": f"https://api.github.com/repos/unique-org-{i}-{j}/repo",
                    "created_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
                })

        signals = check_thin_credibility("user", repos=repos, issues=issues)
        assert not any(s.name == "coordinated_promotion" for s in signals)


# ---------------------------------------------------------------------------
# Negative/regression tests for false positives
# ---------------------------------------------------------------------------

class TestFalsePositiveRegression:
    """Ensure legitimate spec/protocol contributors are not flagged."""

    def test_spec_contributor_no_self_promo(self):
        """Spec contributor files issues across repos about protocol topics, not own repos."""
        user_repos = [
            {"name": "http-spec-tests", "fork": False, "full_name": "spec-dev/http-spec-tests"},
        ]
        issues = [
            {"title": "HTTP/3 support tracking", "body": "Tracking HTTP/3 adoption in this project",
             "repository_url": f"https://api.github.com/repos/org{i}/web-server",
             "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
            for i in range(15)
        ]
        signals = _check_self_promotion("spec-dev", issues, user_repos)
        assert len(signals) == 0

    def test_forked_repos_excluded_from_self_promo(self):
        """Forked repos should not count as self-promotion targets."""
        user_repos = [
            {"name": "popular-framework", "fork": True, "full_name": "dev/popular-framework"},
            {"name": "my-real-project", "fork": False, "full_name": "dev/my-real-project"},
        ]
        issues = [
            {"title": "popular-framework has a bug", "body": "popular-framework crashes here",
             "repository_url": f"https://api.github.com/repos/org{i}/repo",
             "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
            for i in range(10)
        ]
        signals = _check_self_promotion("dev", issues, user_repos)
        assert len(signals) == 0


# ---------------------------------------------------------------------------
# feature_overlap: established repo skip (Phase 2)
# ---------------------------------------------------------------------------

class TestFeatureOverlapEstablishedSkip:
    def _repo(self, name, stars, days):
        # Description spans 4 AGT feature buckets (mcp_security, policy_engine,
        # identity_crypto, runtime_controls).
        return {
            "name": name,
            "description": "mcp security policy engine ed25519 kill switch",
            "topics": [],
            "fork": False,
            "created_at": (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "stargazers_count": stars,
        }

    def test_skips_established_repo(self):
        """A mature, well-starred domain repo is expertise, not cloning."""
        repo = self._repo("flagship", stars=60, days=400)

        def fake_api(path, params=None):
            if path == "/users/spec/repos":
                return [repo]
            return None  # readme fetch -> none

        with patch("contributor_check._api", side_effect=fake_api):
            signals = check_feature_overlap("spec", "microsoft/agent-governance-toolkit")
        assert all(s.name != "feature_overlap" for s in signals)

    def test_fires_on_thin_repo(self):
        """A young, unstarred repo matching the same buckets still fires HIGH."""
        repo = self._repo("freshclone", stars=0, days=5)

        def fake_api(path, params=None):
            if path == "/users/clone/repos":
                return [repo]
            return None

        with patch("contributor_check._api", side_effect=fake_api):
            signals = check_feature_overlap("clone", "microsoft/agent-governance-toolkit")
        overlap = [s for s in signals if s.name == "feature_overlap"]
        assert overlap and overlap[0].severity == "HIGH"


# ---------------------------------------------------------------------------
# Maintainer allowlist (Phase 3)
# ---------------------------------------------------------------------------

class TestAllowlist:
    def test_load_reads_users_and_orgs(self, tmp_path):
        p = tmp_path / "al.json"
        p.write_text('{"users": ["Alice"], "orgs": ["MyOrg"]}', encoding="utf-8")
        users, orgs = _load_allowlist(p)
        assert users == {"alice"}
        assert orgs == {"myorg"}

    def test_load_missing_file_is_empty(self, tmp_path):
        users, orgs = _load_allowlist(tmp_path / "nope.json")
        assert users == set()
        assert orgs == set()

    def test_load_invalid_json_is_empty(self, tmp_path):
        p = tmp_path / "bad.json"
        p.write_text("{not json", encoding="utf-8")
        assert _load_allowlist(p) == (set(), set())

    def test_is_allowlisted_user(self):
        assert _is_allowlisted("Alice", [], ({"alice"}, set())) is True

    def test_is_allowlisted_org(self):
        assert _is_allowlisted("bob", ["TrustedOrg"], (set(), {"trustedorg"})) is True

    def test_not_allowlisted(self):
        assert _is_allowlisted("mallory", ["randomorg"], ({"alice"}, {"trustedorg"})) is False

    def test_shipped_allowlist_is_empty(self):
        """The committed allowlist ships EMPTY -- no self-exemption."""
        users, orgs = _load_allowlist()  # default path: scripts/contributor_check_allowlist.json
        assert users == set()
        assert orgs == set()


class TestApplyAllowlist:
    """The allowlist only SOFTENS (HIGH->MEDIUM); it never sets LOW and never
    whitewashes a deliberate-abuse signal or a multi-repo split-clone."""

    @staticmethod
    def _report(*signals: Signal) -> ReputationReport:
        report = ReputationReport(username="trusted")
        for s in signals:
            report.add(s)
        report.compute_risk()
        return report

    def test_softens_high_to_medium(self):
        # Two non-abuse HIGH signals -> HIGH; allowlist softens to MEDIUM.
        report = self._report(
            Signal(name="repo_velocity", severity="HIGH", detail=""),
            Signal(name="new_account_burst", severity="HIGH", detail=""),
        )
        assert report.risk == "HIGH"
        _apply_allowlist(report)
        assert report.risk == "MEDIUM"
        assert any(s.name == "allowlisted" for s in report.signals)

    def test_never_sets_low(self):
        # A single non-abuse HIGH signal is only MEDIUM; allowlist leaves it,
        # never downgrading to LOW.
        report = self._report(Signal(name="repo_velocity", severity="HIGH", detail=""))
        assert report.risk == "MEDIUM"
        _apply_allowlist(report)
        assert report.risk == "MEDIUM"

    def test_blocked_by_deliberate_abuse_signal(self):
        report = self._report(
            Signal(name="thin_credibility", severity="HIGH", detail=""),
            Signal(name="repo_velocity", severity="HIGH", detail=""),
        )
        _apply_allowlist(report)
        assert report.risk == "HIGH"
        assert any(s.name == "allowlist_blocked" for s in report.signals)
        assert not any(s.name == "allowlisted" for s in report.signals)

    def test_blocked_by_split_clone(self):
        report = self._report(
            Signal(name="feature_overlap", severity="HIGH", detail=""),
            Signal(name="feature_overlap", severity="HIGH", detail=""),
        )
        _apply_allowlist(report)
        assert report.risk == "HIGH"
        assert any(s.name == "allowlist_blocked" for s in report.signals)
