"""Tests for contributor check account shape analysis."""

from datetime import datetime, timedelta, timezone

from agent_compliance.cli.contributor_check import check_account_shape


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
