# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for webhook notification system."""

import json
import threading
import time
import urllib.error
from http.client import HTTPResponse
from io import BytesIO
from unittest.mock import MagicMock, patch

import pytest

from agent_os.integrations.webhooks import (
    DeliveryRecord,
    WebhookConfig,
    WebhookEvent,
    WebhookNotifier,
)


class TestWebhookConfig:
    def test_defaults(self):
        cfg = WebhookConfig(url="https://example.com/hook")
        assert cfg.url == "https://example.com/hook"
        assert cfg.headers == {}
        assert cfg.timeout == 5.0
        assert cfg.retry_count == 3
        assert cfg.retry_delay == 1.0
        assert cfg.events == []

    def test_custom_values(self):
        cfg = WebhookConfig(
            url="https://example.com/hook",
            headers={"Authorization": "Bearer tok"},
            timeout=10.0,
            retry_count=5,
            retry_delay=2.0,
            events=["policy_violation"],
        )
        assert cfg.headers == {"Authorization": "Bearer tok"}
        assert cfg.timeout == 10.0
        assert cfg.retry_count == 5
        assert cfg.events == ["policy_violation"]


class TestWebhookEvent:
    def test_defaults(self):
        ev = WebhookEvent(event_type="test", agent_id="a1", action="run")
        assert ev.event_type == "test"
        assert ev.agent_id == "a1"
        assert ev.severity == "info"
        assert ev.timestamp  # auto-populated

    def test_invalid_severity(self):
        with pytest.raises(ValueError, match="severity must be"):
            WebhookEvent(
                event_type="test", agent_id="a1", action="run", severity="bad"
            )

    def test_valid_severities(self):
        for sev in ("info", "warning", "critical"):
            ev = WebhookEvent(
                event_type="test", agent_id="a1", action="run", severity=sev
            )
            assert ev.severity == sev


def _mock_response(status=200):
    """Create a mock urllib response."""
    resp = MagicMock()
    resp.status = status
    resp.__enter__ = MagicMock(return_value=resp)
    resp.__exit__ = MagicMock(return_value=False)
    return resp


class TestWebhookNotifier:
    def test_notify_sends_to_all_matching(self):
        c1 = WebhookConfig(url="https://a.com/hook")
        c2 = WebhookConfig(url="https://b.com/hook")
        notifier = WebhookNotifier([c1, c2])
        event = WebhookEvent(event_type="test", agent_id="a1", action="run")

        with patch("urllib.request.urlopen", return_value=_mock_response(200)):
            records = notifier.notify(event)

        assert len(records) == 2
        assert all(r.success for r in records)
        assert records[0].url == "https://a.com/hook"
        assert records[1].url == "https://b.com/hook"

    def test_event_filtering(self):
        c1 = WebhookConfig(url="https://a.com/hook", events=["policy_violation"])
        c2 = WebhookConfig(url="https://b.com/hook", events=["budget_warning"])
        notifier = WebhookNotifier([c1, c2])
        event = WebhookEvent(event_type="policy_violation", agent_id="a1", action="run")

        with patch("urllib.request.urlopen", return_value=_mock_response(200)):
            records = notifier.notify(event)

        assert len(records) == 1
        assert records[0].url == "https://a.com/hook"

    def test_empty_events_matches_all(self):
        cfg = WebhookConfig(url="https://a.com/hook", events=[])
        notifier = WebhookNotifier([cfg])
        event = WebhookEvent(event_type="anything", agent_id="a1", action="run")

        with patch("urllib.request.urlopen", return_value=_mock_response(200)):
            records = notifier.notify(event)

        assert len(records) == 1
        assert records[0].success

    def test_retry_on_failure(self):
        cfg = WebhookConfig(url="https://a.com/hook", retry_count=3, retry_delay=0.0)
        notifier = WebhookNotifier([cfg])
        event = WebhookEvent(event_type="test", agent_id="a1", action="run")

        with patch(
            "urllib.request.urlopen",
            side_effect=urllib.error.URLError("connection refused"),
        ):
            records = notifier.notify(event)

        assert len(records) == 1
        assert not records[0].success
        assert records[0].error is not None

    def test_retry_succeeds_on_second_attempt(self):
        cfg = WebhookConfig(url="https://a.com/hook", retry_count=3, retry_delay=0.0)
        notifier = WebhookNotifier([cfg])
        event = WebhookEvent(event_type="test", agent_id="a1", action="run")

        with patch(
            "urllib.request.urlopen",
            side_effect=[
                urllib.error.URLError("fail"),
                _mock_response(200),
            ],
        ):
            records = notifier.notify(event)

        assert len(records) == 1
        assert records[0].success
        assert records[0].status_code == 200

    def test_http_error_records_status_code(self):
        cfg = WebhookConfig(url="https://a.com/hook", retry_count=1, retry_delay=0.0)
        notifier = WebhookNotifier([cfg])
        event = WebhookEvent(event_type="test", agent_id="a1", action="run")

        with patch(
            "urllib.request.urlopen",
            side_effect=urllib.error.HTTPError(
                "https://a.com/hook", 500, "Server Error", {}, BytesIO(b"")
            ),
        ):
            records = notifier.notify(event)

        assert len(records) == 1
        assert not records[0].success
        assert records[0].status_code == 500

    def test_payload_format(self):
        cfg = WebhookConfig(
            url="https://a.com/hook",
            headers={"X-Custom": "val"},
        )
        notifier = WebhookNotifier([cfg])
        event = WebhookEvent(
            event_type="test", agent_id="a1", action="run",
            details={"key": "value"}, severity="warning",
        )

        with patch("urllib.request.urlopen", return_value=_mock_response(200)) as mock_open:
            notifier.notify(event)

        req = mock_open.call_args[0][0]
        body = json.loads(req.data.decode("utf-8"))
        assert body["event_type"] == "test"
        assert body["agent_id"] == "a1"
        assert body["details"] == {"key": "value"}
        assert body["severity"] == "warning"
        assert req.get_header("Content-type") == "application/json"
        assert req.get_header("X-custom") == "val"

    def test_notify_async_runs_in_background(self):
        cfg = WebhookConfig(url="https://a.com/hook")
        notifier = WebhookNotifier([cfg])
        event = WebhookEvent(event_type="test", agent_id="a1", action="run")

        with patch("urllib.request.urlopen", return_value=_mock_response(200)):
            thread = notifier.notify_async(event)
            thread.join(timeout=5.0)

        assert not thread.is_alive()
        assert len(notifier.get_history()) == 1
        assert notifier.get_history()[0].success

    def test_notify_violation(self):
        cfg = WebhookConfig(url="https://a.com/hook")
        notifier = WebhookNotifier([cfg])

        with patch("urllib.request.urlopen", return_value=_mock_response(200)) as mock_open:
            records = notifier.notify_violation(
                agent_id="agent-1",
                action="delete_file",
                policy_name="no_delete",
                reason="Deletion not allowed",
            )

        assert len(records) == 1
        assert records[0].success
        req = mock_open.call_args[0][0]
        body = json.loads(req.data.decode("utf-8"))
        assert body["event_type"] == "policy_violation"
        assert body["severity"] == "critical"
        assert body["details"]["policy_name"] == "no_delete"
        assert body["details"]["reason"] == "Deletion not allowed"

    def test_notify_budget_warning(self):
        cfg = WebhookConfig(url="https://a.com/hook")
        notifier = WebhookNotifier([cfg])

        with patch("urllib.request.urlopen", return_value=_mock_response(200)) as mock_open:
            records = notifier.notify_budget_warning(agent_id="agent-1", usage_pct=85.0)

        body = json.loads(mock_open.call_args[0][0].data.decode("utf-8"))
        assert body["event_type"] == "budget_warning"
        assert body["severity"] == "warning"
        assert body["details"]["usage_percent"] == 85.0

    def test_notify_budget_warning_critical_at_100(self):
        cfg = WebhookConfig(url="https://a.com/hook")
        notifier = WebhookNotifier([cfg])

        with patch("urllib.request.urlopen", return_value=_mock_response(200)) as mock_open:
            notifier.notify_budget_warning(agent_id="agent-1", usage_pct=100.0)

        body = json.loads(mock_open.call_args[0][0].data.decode("utf-8"))
        assert body["severity"] == "critical"

    def test_get_history(self):
        cfg = WebhookConfig(url="https://a.com/hook")
        notifier = WebhookNotifier([cfg])

        assert notifier.get_history() == []

        with patch("urllib.request.urlopen", return_value=_mock_response(200)):
            notifier.notify(WebhookEvent(event_type="e1", agent_id="a1", action="x"))
            notifier.notify(WebhookEvent(event_type="e2", agent_id="a1", action="y"))

        history = notifier.get_history()
        assert len(history) == 2
        assert history[0].event_type == "e1"
        assert history[1].event_type == "e2"

    def test_history_is_copy(self):
        cfg = WebhookConfig(url="https://a.com/hook")
        notifier = WebhookNotifier([cfg])

        with patch("urllib.request.urlopen", return_value=_mock_response(200)):
            notifier.notify(WebhookEvent(event_type="e1", agent_id="a1", action="x"))

        h1 = notifier.get_history()
        h1.clear()
        assert len(notifier.get_history()) == 1  # original unmodified

    def test_thread_safety(self):
        cfg = WebhookConfig(url="https://a.com/hook")
        notifier = WebhookNotifier([cfg])

        with patch("urllib.request.urlopen", return_value=_mock_response(200)):
            threads = []
            for i in range(10):
                t = threading.Thread(
                    target=notifier.notify,
                    args=(WebhookEvent(event_type=f"e{i}", agent_id="a1", action="x"),),
                )
                threads.append(t)
                t.start()
            for t in threads:
                t.join(timeout=5.0)

        assert len(notifier.get_history()) == 10

    def test_no_configs(self):
        notifier = WebhookNotifier([])
        event = WebhookEvent(event_type="test", agent_id="a1", action="run")
        records = notifier.notify(event)
        assert records == []
