# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for contributor check account shape analysis."""

from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from agent_compliance.cli.contributor_check import (
    check_account_shape,
    check_credential_spray,
)


def _make_user(**kwargs) -> dict:
    defaults = {
        "login": "testuser",
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
