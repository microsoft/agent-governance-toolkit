# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for Helicone integration — headers and event logging.

Uses offline mode (no Helicone connection required) to verify that
headers and events are correctly generated.
"""

from __future__ import annotations

from agent_sre.integrations.helicone import HeliconeHeaders, HeliconeLogger

# ========== HeliconeHeaders Tests ==========


class TestHeliconeHeaders:
    def test_basic_headers(self):
        """Basic headers with API key and agent ID."""
        h = HeliconeHeaders(api_key="sk-test", agent_id="bot-1")
        headers = h.get_headers()

        assert headers["Helicone-Auth"] == "Bearer sk-test"
        assert headers["Helicone-User-Id"] == "bot-1"
        assert headers["Helicone-Property-AgentId"] == "bot-1"

    def test_custom_properties(self):
        """Custom properties are added as Helicone-Property headers."""
        h = HeliconeHeaders(api_key="sk-test", agent_id="bot-1")
        headers = h.get_headers(custom_properties={"env": "prod", "version": "1.0"})

        assert headers["Helicone-Property-env"] == "prod"
        assert headers["Helicone-Property-version"] == "1.0"

    def test_disabled(self):
        """Disabled headers return empty dict."""
        h = HeliconeHeaders(api_key="sk-test", agent_id="bot-1", enabled=False)
        headers = h.get_headers()

        assert headers == {}

    def test_session_headers(self):
        """Session name is added as Helicone-Session-Id."""
        h = HeliconeHeaders(api_key="sk-test", agent_id="bot-1")
        headers = h.get_headers(session_name="task-42")

        assert headers["Helicone-Session-Id"] == "task-42"

    def test_user_id_override(self):
        """User ID overrides agent ID in Helicone-User-Id."""
        h = HeliconeHeaders(api_key="sk-test", agent_id="bot-1")
        headers = h.get_headers(user_id="user-99")

        assert headers["Helicone-User-Id"] == "user-99"
        assert headers["Helicone-Property-AgentId"] == "bot-1"

    def test_no_api_key(self):
        """No API key means no Helicone-Auth header."""
        h = HeliconeHeaders(agent_id="bot-1")
        headers = h.get_headers()

        assert "Helicone-Auth" not in headers
        assert headers["Helicone-User-Id"] == "bot-1"

    def test_empty_headers(self):
        """No api_key, no agent_id — still returns a dict (empty)."""
        h = HeliconeHeaders()
        headers = h.get_headers()

        assert isinstance(headers, dict)


# ========== HeliconeLogger Tests ==========


class TestHeliconeLogger:
    def test_offline_mode(self):
        """Logger without API key is offline."""
        logger = HeliconeLogger()
        assert logger.is_offline is True

    def test_log_feedback(self):
        """Log feedback event."""
        logger = HeliconeLogger()
        event = logger.log_feedback("req-001", rating=True, comment="Great response")

        assert event.helicone_id == "req-001"
        assert event.event_type == "feedback"
        assert event.data["rating"] is True
        assert event.data["comment"] == "Great response"
        assert len(logger.logged_events) == 1

    def test_log_slo_score(self):
        """Log SLO score event."""
        logger = HeliconeLogger()
        event = logger.log_slo_score(
            helicone_id="req-002",
            slo_name="latency-slo",
            status="healthy",
            budget_remaining=0.85,
        )

        assert event.helicone_id == "req-002"
        assert event.event_type == "slo_score"
        assert event.data["slo_name"] == "latency-slo"
        assert event.data["status"] == "healthy"
        assert event.data["budget_remaining"] == 0.85
        assert len(logger.logged_events) == 1

    def test_clear(self):
        """Clear removes all events."""
        logger = HeliconeLogger()
        logger.log_feedback("req-1", rating=True)
        logger.log_slo_score("req-2", "slo", "healthy", 0.9)

        assert len(logger.logged_events) == 2

        logger.clear()
        assert len(logger.logged_events) == 0

    def test_stats(self):
        """Get stats returns correct counts."""
        logger = HeliconeLogger()
        logger.log_feedback("req-1", rating=True)
        logger.log_feedback("req-2", rating=False)
        logger.log_slo_score("req-3", "slo", "warning", 0.3)

        stats = logger.get_stats()
        assert stats["total_events"] == 3
        assert stats["feedback_events"] == 2
        assert stats["slo_score_events"] == 1

    def test_imports_from_package(self):
        """Public API is importable."""
        from agent_sre.integrations.helicone import HeliconeHeaders, HeliconeLogger

        headers = HeliconeHeaders()
        assert headers.enabled is True

        logger = HeliconeLogger()
        assert logger.is_offline is True
