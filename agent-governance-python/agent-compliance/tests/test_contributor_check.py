# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for contributor check account shape analysis."""

from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from agent_compliance.cli import contributor_check
from agent_compliance.cli.contributor_check import (
    check_account_shape,
    check_credential_spray,
)


def _make_user(**kwargs) -> dict:
    defaults = {
        "login": "sample-user",
        "created_at": (
            datetime.now(timezone.utc) - timedelta(days=365)
        ).isoformat(),
        "public_repos": 10,
        "followers": 5,
        "following": 5,
    }
    defaults.update(kwargs)
    return defaults


class TestCheckAccountShape:
    def test_normal_account_no_signals(self):
        user = _make_user()
        signals = check_account_shape(user)
        assert not any(s.name == "future_account_timestamp" for s in signals)

    def test_future_created_at_emits_signal(self):
        """Regression: a future created_at made age_days negative, so
        the new_account_burst check (age_days < 90) always fired and
        repos_per_day could be negative/infinite. Future timestamps
        must be clamped and flagged as suspicious.
        """
        future_ts = (
            datetime.now(timezone.utc) + timedelta(days=30)
        ).isoformat()
        user = _make_user(created_at=future_ts, public_repos=50)
        signals = check_account_shape(user)
        assert any(s.name == "future_account_timestamp" for s in signals)
        # age_days should be clamped to 0, so repos_per_day division
        # should not raise and new_account_burst should NOT fire with
        # a negative age
        assert not any(
            s.name == "new_account_burst" and "-" in s.detail
            for s in signals
        )

    def test_new_account_burst_still_works(self):
        """The clamp should not break legitimate new-account detection."""
        recent_ts = (
            datetime.now(timezone.utc) - timedelta(days=30)
        ).isoformat()
        user = _make_user(created_at=recent_ts, public_repos=25)
        signals = check_account_shape(user)
        assert any(s.name == "new_account_burst" for s in signals)


# ---------------------------------------------------------------------------
# check_credential_spray two-query pinning
# ---------------------------------------------------------------------------
# cspell:ignore spray

class TestCheckCredentialSprayTwoQuery:
    """Pin the two-query (is:issue + is:pr) behavior of check_credential_spray."""

    def test_two_queries_issued_and_pr_citation_detected(self):
        """check_credential_spray must issue two searches and detect a PR citation."""
        pr_item = {
            "html_url": "https://github.com/other-org/other-repo/pull/7",
            "repository_url": "https://api.github.com/repos/other-org/other-repo",
            "body": "We integrated microsoft/agent-governance-toolkit via pr #42 merged last week",
            "pull_request": {"url": "https://api.github.com/repos/other-org/other-repo/pulls/7"},
        }

        with patch(
            "agent_compliance.cli.contributor_check._search_issues",
            side_effect=[[], [pr_item]],
        ) as mock_search:
            signals = check_credential_spray(
                "spray-user", "microsoft/agent-governance-toolkit",
            )

        # Must have called _search_issues exactly twice
        assert mock_search.call_count == 2

        # Verify the two query strings
        calls = [c.args[0] for c in mock_search.call_args_list]
        assert calls[0] == "author:spray-user is:issue"
        assert calls[1] == "author:spray-user is:pr"

        # Should detect credential_citation from the PR item
        assert len(signals) == 1
        assert signals[0].name == "credential_citation"


# ---------------------------------------------------------------------------
# _search_issues pagination
# ---------------------------------------------------------------------------

class TestSearchIssuesPagination:
    """Mirrors credential_audit.py's identical fix: _search_issues must page
    through GitHub's full search result window, not just the first page."""

    def test_paginates_across_multiple_pages(self):
        pages = {
            "1": {"items": [{"number": i} for i in range(100)]},
            "2": {"items": [{"number": i} for i in range(100, 150)]},
        }

        def fake_api(path, params=None):
            return pages.get(params["page"])

        with patch.object(contributor_check, "_api", side_effect=fake_api) as mock_api:
            items = contributor_check._search_issues("author:x is:issue", per_page=100)

        assert len(items) == 150
        assert mock_api.call_count == 2

    def test_stops_when_a_short_page_is_returned(self):
        pages = {"1": {"items": [{"number": 1}, {"number": 2}]}}

        def fake_api(path, params=None):
            return pages.get(params["page"])

        with patch.object(contributor_check, "_api", side_effect=fake_api) as mock_api:
            items = contributor_check._search_issues("author:x is:issue", per_page=100)

        assert len(items) == 2
        assert mock_api.call_count == 1

    def test_stops_at_github_search_result_window(self):
        def fake_api(path, params=None):
            return {"items": [{"number": i} for i in range(int(params["per_page"]))]}

        with patch.object(contributor_check, "_api", side_effect=fake_api) as mock_api:
            items = contributor_check._search_issues("author:x is:issue", per_page=100)

        assert len(items) == 1000
        assert mock_api.call_count == 10

    def test_empty_first_page_returns_no_items(self):
        with patch.object(contributor_check, "_api", return_value=None) as mock_api:
            items = contributor_check._search_issues("author:x is:issue", per_page=100)

        assert items == []
        assert mock_api.call_count == 1


# ---------------------------------------------------------------------------
# Repo pagination and the spray window
# ---------------------------------------------------------------------------

def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


class TestRepoListingPagination:
    def test_recent_repo_burst_counts_past_first_page(self):
        now = datetime.now(timezone.utc)
        all_repos = [
            {"name": f"repo-{i}", "fork": False, "description": "",
             "created_at": _iso(now - timedelta(hours=i))}
            for i in range(130)
        ]

        def fake_api(path, params=None):
            if path == "/users/busy/repos":
                page = int(params["page"])
                size = int(params["per_page"])
                return all_repos[(page - 1) * size: page * size]
            return None

        with patch.object(contributor_check, "_api", side_effect=fake_api):
            signals = contributor_check.check_repo_themes("busy")
        burst = [s for s in signals if s.name == "recent_repo_burst"]
        assert burst and burst[0].value == 130

    def test_old_repos_on_later_pages_affect_theme_denominator(self):
        old = _iso(datetime.now(timezone.utc) - timedelta(days=120))
        repos = [
            {"name": f"governance-{i}" if i < 60 else f"repo-{i}",
             "fork": False, "description": "", "created_at": old}
            for i in range(200)
        ]

        def fake_api(path, params=None):
            return repos[(int(params["page"]) - 1) * 100:int(params["page"]) * 100]

        with patch.object(contributor_check, "_api", side_effect=fake_api) as mock_api:
            signals = contributor_check.check_repo_themes("busy")

        assert all(s.name != "governance_theme_concentration" for s in signals)
        assert mock_api.call_count == 3



class TestSprayWindow:
    @staticmethod
    def _issues(days: list[float]) -> list[dict]:
        base = datetime.now(timezone.utc) - timedelta(days=20)
        return [
            {"created_at": _iso(base + timedelta(days=d)),
             "repository_url": f"https://api.github.com/repos/org{i}/repo{i}",
             "title": "", "body": ""}
            for i, d in enumerate(days)
        ]

    def test_five_repos_over_thirteen_days_is_not_spray(self):
        signals = contributor_check.check_spray_pattern(
            "u", issues=self._issues([0, 3, 6, 10, 13]), user_repos=[])
        assert all(s.name != "cross_repo_spray" for s in signals)

    def test_five_repos_within_seven_days_is_spray(self):
        signals = contributor_check.check_spray_pattern(
            "u", issues=self._issues([0, 1.5, 3, 5, 7]), user_repos=[])
        spray = [s for s in signals if s.name == "cross_repo_spray"]
        assert spray and spray[0].value == 5

    def test_window_is_seven_days_not_eight(self):
        signals = contributor_check.check_spray_pattern(
            "u", issues=self._issues([0, 1, 2, 3, 7 + 20 / 24]), user_repos=[])
        assert all(s.name != "cross_repo_spray" for s in signals)
