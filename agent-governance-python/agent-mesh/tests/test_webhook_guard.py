# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Regression tests for the webhook SSRF guard (#3516).

No network is used: DNS answers are injected through the guard's
``resolver``, and sockets go either to a local HTTP server on the loopback
interface or to a patched ``socket.create_connection`` that records the
pinned target and refuses the connection.
"""

from __future__ import annotations

import http.server
import json
import pathlib
import socket
import threading
import urllib.error
import urllib.request
import warnings
from datetime import timedelta

import pytest

from agentmesh.governance import webhook_guard
from agentmesh.governance.advisory import HttpAdvisory
from agentmesh.governance.approval import ApprovalRequest as LegacyApprovalRequest
from agentmesh.governance.approval import WebhookApproval
from agentmesh.governance.approval_protocol import ApprovalRequest, utcnow
from agentmesh.governance.approval_webhook import VersionedWebhookApproval
from agentmesh.governance.webhook_guard import (
    DEFAULT_GUARD,
    WebhookEndpointBlockedError,
    WebhookEndpointGuard,
)

PUBLIC_V4 = "93.184.216.34"
PUBLIC_V6 = "2606:2800:21f:cb07:6820:80da:af6b:8b2c"

# Case 2 and 3: literal loopback, private, link-local, unspecified, ULA.
LITERAL_BLOCKED = [
    "http://127.0.0.1/",
    "http://127.255.255.254/",
    "http://10.0.0.5/",
    "http://172.16.0.1/",
    "http://172.31.255.255/",
    "http://192.168.1.1/",
    "http://0.0.0.0/",
    "http://100.64.0.1/",
    "http://169.254.169.254/",
    "http://169.254.1.2/",
    "http://192.0.0.9/",
    "http://198.18.0.1/",
    "http://224.0.0.1/",
    "http://[::1]/",
    "http://[::]/",
    "http://[fe80::1]/",
    "http://[fe80::1%25eth0]/",
    "http://[fec0::1]/",
    "http://[fd00:ec2::254]/",
    "http://[fc00::1]/",
    "http://[ff02::1]/",
    "http://[2001:db8::1]/",
]
# Case 4: IPv4-mapped and IPv4-compatible IPv6.
MAPPED_BLOCKED = [
    "http://[::ffff:127.0.0.1]/",
    "http://[::ffff:7f00:1]/",
    "http://[::ffff:a9fe:a9fe]/",
    "http://[::ffff:10.0.0.1]/",
    "http://[::7f00:1]/",
    "http://[::a9fe:a9fe]/",
]
# Case 5: decimal, hex, octal and short IPv4 spellings.
NUMERIC_BLOCKED = [
    "http://2130706433/",
    "http://0x7f000001/",
    "http://017700000001/",
    "http://127.1/",
    "http://0/",
    "http://0xa9fea9fe/",
]
# Case 6: host-name tricks.
HOSTNAME_BLOCKED = [
    "http://localhost/",
    "http://LOCALHOST:8080/",
    "http://api.localhost/",
    "http://localhost./",
    "http://metadata.google.internal/",
    "http://METADATA.GOOGLE.INTERNAL/",
    "http://metadata.google.internal./",
    "http://metadata.google/",
    "http://v1.metadata.google.internal/",
    "http://169.254.169.254./",
    "http://user:pass@169.254.169.254/",
]
PUBLIC_URLS = [
    "https://example.com/hook",
    "https://hooks.example.com:8443/path?x=1",
    f"http://{PUBLIC_V4}/",
    f"http://[{PUBLIC_V6}]/",
    "http://127.0.0.1.nip.io/",  # a DNS name; blocked at connect time instead
]


def _resolver(*answers: list[str]):
    """A resolver that returns ``answers`` in turn and counts its calls."""
    calls: list[str] = []

    def resolve(host: str) -> list[str]:
        calls.append(host)
        index = min(len(calls), len(answers)) - 1
        return list(answers[index])

    resolve.calls = calls  # type: ignore[attr-defined]
    return resolve


# --------------------------------------------------------------------------- #
# Construction-time validation
# --------------------------------------------------------------------------- #


class TestValidateUrl:
    @pytest.mark.parametrize(
        "url", LITERAL_BLOCKED + MAPPED_BLOCKED + NUMERIC_BLOCKED + HOSTNAME_BLOCKED
    )
    def test_internal_destination_rejected(self, url):
        with pytest.raises(WebhookEndpointBlockedError, match="blocked"):
            DEFAULT_GUARD.validate_url(url)

    @pytest.mark.parametrize("url", PUBLIC_URLS)
    def test_public_destination_accepted(self, url):
        DEFAULT_GUARD.validate_url(url)

    def test_blocked_error_is_a_value_error(self):
        with pytest.raises(ValueError):
            DEFAULT_GUARD.validate_url("http://127.0.0.1/")

    @pytest.mark.parametrize("url", ["ftp://example.com/x", "file:///etc/passwd", "gopher://x/"])
    def test_non_http_scheme_rejected(self, url):
        with pytest.raises(ValueError, match="only http and https"):
            DEFAULT_GUARD.validate_url(url)

    def test_missing_host_rejected(self):
        with pytest.raises(ValueError, match="no host"):
            DEFAULT_GUARD.validate_url("http:///path")

    def test_malformed_port_rejected(self):
        with pytest.raises(ValueError, match="Malformed"):
            DEFAULT_GUARD.validate_url("http://example.com:abc/")

    def test_allow_list_network_admits_literal(self):
        guard = WebhookEndpointGuard.allowing(["10.20.0.0/16"])
        guard.validate_url("http://10.20.3.4/hook")
        with pytest.raises(WebhookEndpointBlockedError):
            guard.validate_url("http://10.21.0.1/hook")

    def test_allow_list_single_address_admits_mapped_form(self):
        guard = WebhookEndpointGuard.allowing(["127.0.0.1"])
        guard.validate_url("http://127.0.0.1:1/x")
        guard.validate_url("http://[::ffff:127.0.0.1]:1/x")
        with pytest.raises(WebhookEndpointBlockedError):
            guard.validate_url("http://127.0.0.2/x")

    def test_allow_list_hostname_is_normalised(self):
        guard = WebhookEndpointGuard.allowing(["Hooks.Corp.Internal."])
        guard.validate_url("http://hooks.corp.internal/x")
        guard.validate_url("http://HOOKS.CORP.INTERNAL./x")

    def test_allow_list_rejects_empty_entry(self):
        with pytest.raises(ValueError):
            WebhookEndpointGuard.allowing([" "])

    def test_default_guard_allows_nothing_internal(self):
        assert DEFAULT_GUARD.allowed_hosts == frozenset()
        assert DEFAULT_GUARD.allowed_networks == ()


# --------------------------------------------------------------------------- #
# Connect-time resolution
# --------------------------------------------------------------------------- #


class TestResolveAllowedAddresses:
    @pytest.mark.parametrize(
        "host,answer",
        [
            ("127.0.0.1.nip.io", "127.0.0.1"),  # case 1, the issue's PoC
            ("metadata.attacker.example", "169.254.169.254"),
            ("intranet.attacker.example", "10.0.0.5"),
            ("v6.attacker.example", "::1"),
            ("mapped.attacker.example", "::ffff:169.254.169.254"),
            ("ula.attacker.example", "fd00:ec2::254"),
        ],
    )
    def test_name_resolving_to_internal_address_blocked(self, host, answer):
        guard = WebhookEndpointGuard(resolver=_resolver([answer]))
        with pytest.raises(WebhookEndpointBlockedError, match="resolves to blocked"):
            guard.resolve_allowed_addresses(host)

    def test_any_internal_record_blocks_the_whole_answer(self):
        # Case 9: public A record plus internal AAAA record.
        guard = WebhookEndpointGuard(resolver=_resolver([PUBLIC_V4, "::1"]))
        with pytest.raises(WebhookEndpointBlockedError):
            guard.resolve_allowed_addresses("dual.example")

    def test_public_answer_returned_for_pinning(self):
        guard = WebhookEndpointGuard(resolver=_resolver([PUBLIC_V4, PUBLIC_V6]))
        assert guard.resolve_allowed_addresses("hooks.example") == [PUBLIC_V4, PUBLIC_V6]

    def test_literal_address_does_not_consult_resolver(self):
        resolve = _resolver([PUBLIC_V4])
        guard = WebhookEndpointGuard(resolver=resolve)
        assert guard.resolve_allowed_addresses(PUBLIC_V4) == [PUBLIC_V4]
        with pytest.raises(WebhookEndpointBlockedError):
            guard.resolve_allowed_addresses("2130706433")
        assert resolve.calls == []

    def test_blocked_hostname_does_not_consult_resolver(self):
        resolve = _resolver([PUBLIC_V4])
        guard = WebhookEndpointGuard(resolver=resolve)
        with pytest.raises(WebhookEndpointBlockedError):
            guard.resolve_allowed_addresses("metadata.google.internal.")
        assert resolve.calls == []

    def test_resolution_failure_propagates_as_os_error(self):
        def failing(host):
            raise socket.gaierror("no such host")

        guard = WebhookEndpointGuard(resolver=failing)
        with pytest.raises(OSError):
            guard.resolve_allowed_addresses("missing.example")

    def test_empty_answer_is_an_error(self):
        guard = WebhookEndpointGuard(resolver=_resolver([]))
        with pytest.raises(OSError, match="did not resolve"):
            guard.resolve_allowed_addresses("empty.example")

    def test_allow_listed_network_admits_resolved_address(self):
        guard = WebhookEndpointGuard.allowing(["10.0.0.0/8"], resolver=_resolver(["10.1.2.3"]))
        assert guard.resolve_allowed_addresses("hooks.corp.internal") == ["10.1.2.3"]

    def test_allow_listed_host_admits_its_addresses(self):
        guard = WebhookEndpointGuard.allowing(
            ["hooks.corp.internal"], resolver=_resolver(["192.168.5.5"])
        )
        assert guard.resolve_allowed_addresses("hooks.corp.internal") == ["192.168.5.5"]
        with pytest.raises(WebhookEndpointBlockedError):
            guard.resolve_allowed_addresses("other.corp.internal")


# --------------------------------------------------------------------------- #
# Transport: pinning, redirects, proxies, rebinding
# --------------------------------------------------------------------------- #


class _Server:
    """Loopback HTTP server that records requests and serves a scripted reply."""

    def __init__(self):
        self.requests: list[tuple[str, str, bytes]] = []
        self.reply = (200, {"action": "allow"})
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
                status, payload = server.reply
                data = json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            do_GET = do_POST

            def log_message(self, *args):
                pass

        self.httpd = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()

    def guard(self, host="hook.example"):
        """A guard that answers ``host`` with the loopback server and
        allow-lists the name, so the loopback address is accepted."""
        return WebhookEndpointGuard.allowing([host], resolver=_resolver(["127.0.0.1"]))

    def url(self, path="/hook", host="hook.example"):
        return f"http://{host}:{self.port}{path}"


@pytest.fixture
def server():
    srv = _Server()
    try:
        yield srv
    finally:
        srv.close()


@pytest.fixture
def connect_log(monkeypatch):
    """Replace the socket connect with one that records the pinned target
    and refuses, so no packet leaves the host."""
    attempts: list[tuple[str, int]] = []

    def fake_create_connection(address, *args, **kwargs):
        attempts.append((address[0], address[1]))
        raise ConnectionRefusedError("refused by test")

    monkeypatch.setattr(webhook_guard.socket, "create_connection", fake_create_connection)
    return attempts


def _post(url, body=b"{}"):
    return urllib.request.Request(
        url, data=body, headers={"Content-Type": "application/json"}, method="POST"
    )


class TestGuardedTransport:
    def test_connection_pinned_to_resolved_address(self, server):
        # ``hook.example`` has no DNS entry anywhere; the request can only
        # succeed if the guard connects to the address its resolver returned
        # and keeps the original name in the Host header.
        with server.guard().open(_post(server.url()), timeout=5) as resp:
            assert resp.status == 200
            assert json.loads(resp.read()) == {"action": "allow"}
        assert server.requests == [(f"hook.example:{server.port}", "/hook", b"{}")]

    def test_redirect_is_refused_not_followed(self, server):
        # Case 7: a public endpoint answering 3xx towards an internal target.
        server.redirect_to = f"http://127.0.0.1:{server.port}/secret"
        with pytest.raises(urllib.error.HTTPError) as excinfo:
            server.guard().open(_post(server.url()), timeout=5)
        assert excinfo.value.code == 302
        assert [path for _, path, _ in server.requests] == ["/hook"]

    def test_proxy_environment_is_ignored(self, server, monkeypatch):
        # Case 10: HTTP_PROXY pointing at an internal host.
        monkeypatch.setenv("http_proxy", "http://127.0.0.1:9/")
        monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:9/")
        assert urllib.request.getproxies().get("http")  # the default opener would use it
        with server.guard().open(_post(server.url()), timeout=5) as resp:
            assert resp.status == 200
        assert len(server.requests) == 1

    def test_dns_rebinding_between_requests_is_blocked(self, connect_log):
        # Case 8: first answer public, second answer loopback. The second
        # request must be refused before any socket is opened.
        resolve = _resolver([PUBLIC_V4], ["127.0.0.1"])
        guard = WebhookEndpointGuard(resolver=resolve)
        with pytest.raises(urllib.error.URLError):
            guard.open(_post("http://hooks.example/approve"), timeout=5)
        assert connect_log == [(PUBLIC_V4, 80)]
        with pytest.raises(WebhookEndpointBlockedError):
            guard.open(_post("http://hooks.example/approve"), timeout=5)
        assert connect_log == [(PUBLIC_V4, 80)]
        assert resolve.calls == ["hooks.example", "hooks.example"]

    def test_connect_resolves_every_request(self, connect_log):
        resolve = _resolver([PUBLIC_V4])
        guard = WebhookEndpointGuard(resolver=resolve)
        for _ in range(3):
            with pytest.raises(urllib.error.URLError):
                guard.open(_post("https://hooks.example:8443/approve"), timeout=5)
        assert connect_log == [(PUBLIC_V4, 8443)] * 3
        assert len(resolve.calls) == 3

    def test_name_resolving_to_internal_never_connects(self, connect_log):
        guard = WebhookEndpointGuard(resolver=_resolver(["127.0.0.1"]))
        with pytest.raises(WebhookEndpointBlockedError):
            guard.open(_post("http://127.0.0.1.nip.io/hook"), timeout=5)
        assert connect_log == []

    def test_literal_internal_url_never_connects(self, connect_log):
        # The URL is validated again on every send, so a URL swapped in after
        # construction cannot bypass the guard.
        with pytest.raises(WebhookEndpointBlockedError):
            DEFAULT_GUARD.open(_post("http://169.254.169.254/latest/meta-data/"), timeout=5)
        assert connect_log == []

    def test_opener_has_no_redirect_or_proxy_handler(self):
        handlers = {type(h) for h in DEFAULT_GUARD.build_opener().handlers}
        assert urllib.request.HTTPRedirectHandler not in handlers
        assert urllib.request.ProxyHandler not in handlers
        assert urllib.request.FileHandler not in handlers


# --------------------------------------------------------------------------- #
# The senders use the guard
# --------------------------------------------------------------------------- #


def _protocol_request():
    return ApprovalRequest(
        policy_decision_id="pd_1",
        action_digest="sha256:abc123",
        agent_id="agent-1",
        operation="tool.invoke",
        policy_version="2026.06.17",
        approval_chain_id="high-risk",
        approval_chain_version="3",
        expires_at=utcnow() + timedelta(seconds=300),
        subject_id="user-1",
        target_resource="prod-db",
    )


def _legacy_request():
    return LegacyApprovalRequest(action="transfer", rule_name="r", policy_name="p", agent_id="a")


def _legacy_webhook(url, **kwargs):
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", FutureWarning)
        return WebhookApproval(url, **kwargs)


SENDER_BLOCKED_URLS = [
    "http://127.0.0.1/",
    "http://localhost/",
    "http://169.254.169.254./",
    "http://[fd00:ec2::254]/",
    "http://[::ffff:a9fe:a9fe]/",
    "http://2130706433/",
]


class TestHttpAdvisoryGuard:
    @pytest.mark.parametrize("url", SENDER_BLOCKED_URLS)
    def test_internal_url_rejected_at_construction(self, url):
        with pytest.raises(ValueError, match="blocked"):
            HttpAdvisory(url)

    def test_rebinding_name_fails_to_configured_action(self, connect_log):
        guard = WebhookEndpointGuard(resolver=_resolver(["169.254.169.254"]))
        advisory = HttpAdvisory("http://127.0.0.1.nip.io/classify", on_error="block", endpoint_guard=guard)
        decision = advisory.check({"x": 1})
        assert decision.action == "block"
        assert "blocked" in decision.reason
        assert connect_log == []

    def test_public_endpoint_served_through_pinned_connection(self, server):
        server.reply = (200, {"action": "flag_for_review", "reason": "odd", "confidence": 0.4})
        advisory = HttpAdvisory(server.url("/classify"), endpoint_guard=server.guard())
        decision = advisory.check({"tool": "rm"})
        assert decision.action == "flag_for_review"
        assert decision.reason == "odd"
        host, path, body = server.requests[0]
        assert (host, path) == (f"hook.example:{server.port}", "/classify")
        assert json.loads(body) == {"tool": "rm"}

    def test_redirecting_endpoint_fails_to_configured_action(self, server):
        server.redirect_to = f"http://127.0.0.1:{server.port}/internal"
        advisory = HttpAdvisory(server.url("/classify"), on_error="block", endpoint_guard=server.guard())
        assert advisory.check({}).action == "block"
        assert [path for _, path, _ in server.requests] == ["/classify"]


class TestVersionedWebhookApprovalGuard:
    @pytest.mark.parametrize("url", SENDER_BLOCKED_URLS)
    def test_internal_url_rejected_at_construction(self, url):
        with pytest.raises(ValueError, match="blocked"):
            VersionedWebhookApproval(url)

    def test_rebinding_name_denies_closed(self, connect_log):
        guard = WebhookEndpointGuard(resolver=_resolver(["10.0.0.5"]))
        approver = VersionedWebhookApproval("https://hooks.attacker.example/approve", endpoint_guard=guard)
        decision = approver.request_decision(_protocol_request())
        assert not decision.approved
        assert decision.approver == "system:webhook-error"
        assert "blocked" in decision.reason
        assert connect_log == []

    def test_request_reaches_pinned_endpoint(self, server):
        server.reply = (200, {})
        approver = VersionedWebhookApproval(server.url("/approve"), endpoint_guard=server.guard())
        decision = approver.request_decision(_protocol_request())
        assert not decision.approved  # empty body fails the binding check, as before
        host, path, body = server.requests[0]
        assert (host, path) == (f"hook.example:{server.port}", "/approve")
        assert json.loads(body)["action_digest"] == "sha256:abc123"

    def test_redirect_denies_closed(self, server):
        server.redirect_to = f"http://127.0.0.1:{server.port}/internal"
        approver = VersionedWebhookApproval(server.url("/approve"), endpoint_guard=server.guard())
        decision = approver.request_decision(_protocol_request())
        assert not decision.approved
        assert "302" in decision.reason
        assert [path for _, path, _ in server.requests] == ["/approve"]


class TestLegacyWebhookApprovalGuard:
    @pytest.mark.parametrize("url", SENDER_BLOCKED_URLS)
    def test_internal_url_rejected_at_construction(self, url):
        with pytest.raises(ValueError, match="blocked"):
            _legacy_webhook(url)

    def test_rebinding_name_denies_closed(self, connect_log):
        guard = WebhookEndpointGuard(resolver=_resolver([PUBLIC_V4, "::1"]))
        approver = _legacy_webhook("https://hooks.attacker.example/approve", endpoint_guard=guard)
        decision = approver.request_approval(_legacy_request())
        assert not decision.approved
        assert decision.approver == "system:webhook-error"
        assert "blocked" in decision.reason
        assert connect_log == []

    def test_request_reaches_pinned_endpoint(self, server):
        server.reply = (200, {"approved": True, "approver": "alice"})
        approver = _legacy_webhook(server.url("/approve"), endpoint_guard=server.guard())
        decision = approver.request_approval(_legacy_request())
        assert decision.approved
        assert server.requests[0][0] == f"hook.example:{server.port}"


class TestTwinModuleInSync:
    def test_agent_os_copy_is_identical(self):
        here = pathlib.Path(webhook_guard.__file__)
        twin = (
            here.parents[4] / "agent-os" / "src" / "agent_os" / "integrations" / "webhook_guard.py"
        )
        if not twin.exists():
            pytest.skip("agent-os checkout not present beside agent-mesh")
        assert twin.read_text() == here.read_text()
