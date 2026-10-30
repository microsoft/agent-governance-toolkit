# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Regression tests for the webhook SSRF guard in agent-os (#3516).

No network is used: DNS answers are injected through the guard's
``resolver``, and sockets go either to a local HTTP server on the loopback
interface or to a patched ``socket.create_connection`` that records the
pinned target and refuses the connection. The guard module itself is a
copy of the agent-mesh one; the last test keeps the two identical.
"""

from __future__ import annotations

import http.server
import json
import pathlib
import threading
import urllib.error
import urllib.request

import pytest

from agent_os.integrations import webhook_guard
from agent_os.integrations.escalation import EscalationRequest, WebhookApprovalBackend
from agent_os.integrations.webhook_guard import (
    DEFAULT_GUARD,
    WebhookEndpointBlockedError,
    WebhookEndpointGuard,
)
from agent_os.integrations.webhooks import WebhookConfig, WebhookEvent, WebhookNotifier

PUBLIC_V4 = "93.184.216.34"

BLOCKED_URLS = [
    # literal loopback, private, link-local, unspecified, shared, ULA
    "http://127.0.0.1/",
    "http://10.0.0.5/",
    "http://172.16.0.1/",
    "http://192.168.1.1/",
    "http://0.0.0.0/",
    "http://100.64.0.1/",
    "http://169.254.169.254/",
    "http://[::1]/",
    "http://[fe80::1]/",
    "http://[fd00:ec2::254]/",
    # IPv4-mapped and IPv4-compatible IPv6
    "http://[::ffff:127.0.0.1]/",
    "http://[::ffff:a9fe:a9fe]/",
    "http://[::7f00:1]/",
    # decimal, hex, octal, short IPv4
    "http://2130706433/",
    "http://0x7f000001/",
    "http://017700000001/",
    "http://127.1/",
    "http://0/",
    # host-name tricks
    "http://localhost/",
    "http://api.localhost/",
    "http://metadata.google.internal./",
    "http://METADATA.GOOGLE.INTERNAL/",
    "http://169.254.169.254./",
]
PUBLIC_URLS = [
    "https://example.com/hook",
    f"http://{PUBLIC_V4}/",
    "http://127.0.0.1.nip.io/",  # a DNS name; blocked at connect time instead
]


def _resolver(*answers: list[str]):
    calls: list[str] = []

    def resolve(host: str) -> list[str]:
        calls.append(host)
        index = min(len(calls), len(answers)) - 1
        return list(answers[index])

    resolve.calls = calls  # type: ignore[attr-defined]
    return resolve


class TestGuard:
    @pytest.mark.parametrize("url", BLOCKED_URLS)
    def test_internal_destination_rejected(self, url):
        with pytest.raises(WebhookEndpointBlockedError, match="blocked"):
            DEFAULT_GUARD.validate_url(url)

    @pytest.mark.parametrize("url", PUBLIC_URLS)
    def test_public_destination_accepted(self, url):
        DEFAULT_GUARD.validate_url(url)

    def test_non_http_scheme_rejected(self):
        with pytest.raises(ValueError, match="only http and https"):
            DEFAULT_GUARD.validate_url("ftp://example.com/x")

    @pytest.mark.parametrize(
        "answer", [["127.0.0.1"], ["169.254.169.254"], ["::1"], [PUBLIC_V4, "10.0.0.5"]]
    )
    def test_name_resolving_to_internal_blocked(self, answer):
        guard = WebhookEndpointGuard(resolver=_resolver(answer))
        with pytest.raises(WebhookEndpointBlockedError, match="resolves to blocked"):
            guard.resolve_allowed_addresses("127.0.0.1.nip.io")

    def test_allow_list_admits_internal_network(self):
        guard = WebhookEndpointGuard.allowing(["10.0.0.0/8"], resolver=_resolver(["10.1.2.3"]))
        guard.validate_url("http://10.9.9.9/hook")
        assert guard.resolve_allowed_addresses("hooks.corp.internal") == ["10.1.2.3"]

    def test_opener_has_no_redirect_or_proxy_handler(self):
        handlers = {type(h) for h in DEFAULT_GUARD.build_opener().handlers}
        assert urllib.request.HTTPRedirectHandler not in handlers
        assert urllib.request.ProxyHandler not in handlers


class _Server:
    def __init__(self):
        self.requests: list[tuple[str, str, bytes]] = []
        self.redirect_to: str | None = None
        server = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length)
                server.requests.append((self.headers.get("Host", ""), self.path, body))
                if server.redirect_to:
                    self.send_response(302)
                    self.send_header("Location", server.redirect_to)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                self.send_response(200)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"{}")

            def log_message(self, *args):
                pass

        self.httpd = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()

    def guard(self):
        return WebhookEndpointGuard.allowing(["hook.example"], resolver=_resolver(["127.0.0.1"]))

    def url(self, path="/hook"):
        return f"http://hook.example:{self.port}{path}"


@pytest.fixture
def server():
    srv = _Server()
    try:
        yield srv
    finally:
        srv.close()


@pytest.fixture
def connect_log(monkeypatch):
    attempts: list[tuple[str, int]] = []

    def fake_create_connection(address, *args, **kwargs):
        attempts.append((address[0], address[1]))
        raise ConnectionRefusedError("refused by test")

    monkeypatch.setattr(webhook_guard.socket, "create_connection", fake_create_connection)
    return attempts


def _event():
    return WebhookEvent(event_type="policy_violation", agent_id="a1", action="run")


class TestWebhookNotifierGuard:
    @pytest.mark.parametrize("url", BLOCKED_URLS[::4])
    def test_internal_url_rejected_at_construction(self, url):
        with pytest.raises(ValueError, match="blocked"):
            WebhookNotifier([WebhookConfig(url=url)])

    def test_rebinding_name_fails_delivery_without_connecting(self, connect_log):
        guard = WebhookEndpointGuard(resolver=_resolver(["169.254.169.254"]))
        notifier = WebhookNotifier(
            [WebhookConfig(url="http://127.0.0.1.nip.io/hook", retry_count=2, retry_delay=0.0)],
            endpoint_guard=guard,
        )
        records = notifier.notify(_event())
        assert len(records) == 1
        assert not records[0].success
        assert "blocked" in records[0].error
        assert connect_log == []

    def test_dns_rebinding_between_deliveries_is_blocked(self, connect_log):
        resolve = _resolver([PUBLIC_V4], ["127.0.0.1"])
        guard = WebhookEndpointGuard(resolver=resolve)
        notifier = WebhookNotifier(
            [WebhookConfig(url="https://hooks.example/hook", retry_count=1, retry_delay=0.0)],
            endpoint_guard=guard,
        )
        notifier.notify(_event())
        assert connect_log == [(PUBLIC_V4, 443)]
        record = notifier.notify(_event())[0]
        assert not record.success and "blocked" in record.error
        assert connect_log == [(PUBLIC_V4, 443)]
        assert resolve.calls == ["hooks.example", "hooks.example"]

    def test_delivery_pinned_to_resolved_address(self, server):
        notifier = WebhookNotifier([WebhookConfig(url=server.url())], endpoint_guard=server.guard())
        record = notifier.notify(_event())[0]
        assert record.success and record.status_code == 200
        host, path, body = server.requests[0]
        assert (host, path) == (f"hook.example:{server.port}", "/hook")
        assert json.loads(body)["event_type"] == "policy_violation"

    def test_redirect_is_not_followed(self, server):
        server.redirect_to = f"http://127.0.0.1:{server.port}/internal"
        notifier = WebhookNotifier(
            [WebhookConfig(url=server.url(), retry_count=1)], endpoint_guard=server.guard()
        )
        record = notifier.notify(_event())[0]
        assert not record.success and record.status_code == 302
        assert [path for _, path, _ in server.requests] == ["/hook"]


def _escalation():
    return EscalationRequest(request_id="r1", agent_id="a1", action="deploy", reason="risky")


class TestWebhookApprovalBackendGuard:
    @pytest.mark.parametrize("url", BLOCKED_URLS[::4])
    def test_internal_url_rejected_at_construction(self, url):
        with pytest.raises(ValueError, match="blocked"):
            WebhookApprovalBackend(url)

    def test_rebinding_name_is_logged_not_connected(self, connect_log, caplog):
        guard = WebhookEndpointGuard(resolver=_resolver(["10.0.0.5"]))
        backend = WebhookApprovalBackend("https://hooks.attacker.example/esc", endpoint_guard=guard)
        with caplog.at_level("WARNING"):
            backend.submit(_escalation())
        assert connect_log == []
        assert "Failed to send escalation webhook" in caplog.text
        assert backend.get_decision("r1") is not None  # the request is still queued

    def test_notification_pinned_to_resolved_address(self, server):
        backend = WebhookApprovalBackend(server.url("/esc"), endpoint_guard=server.guard())
        backend.submit(_escalation())
        host, path, body = server.requests[0]
        assert (host, path) == (f"hook.example:{server.port}", "/esc")
        assert json.loads(body)["request_id"] == "r1"

    def test_redirect_is_not_followed(self, server, caplog):
        server.redirect_to = f"http://127.0.0.1:{server.port}/internal"
        backend = WebhookApprovalBackend(server.url("/esc"), endpoint_guard=server.guard())
        with caplog.at_level("WARNING"):
            backend.submit(_escalation())
        assert [path for _, path, _ in server.requests] == ["/esc"]
        assert "Failed to send escalation webhook" in caplog.text


class TestTwinModuleInSync:
    def test_agent_mesh_copy_is_identical(self):
        here = pathlib.Path(webhook_guard.__file__)
        twin = (
            here.parents[4] / "agent-mesh" / "src" / "agentmesh" / "governance" / "webhook_guard.py"
        )
        if not twin.exists():
            pytest.skip("agent-mesh checkout not present beside agent-os")
        assert twin.read_text() == here.read_text()
