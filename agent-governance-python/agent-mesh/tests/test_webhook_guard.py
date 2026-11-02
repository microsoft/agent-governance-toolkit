# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Regression tests for the webhook SSRF guard (#3516).

No network is used: DNS answers are injected through the guard's
``resolver``, and sockets go either to a local HTTP server on the loopback
interface or to a patched ``socket.create_connection`` that records the
pinned target and refuses the connection.
"""

from __future__ import annotations

import contextlib
import http.server
import json
import pathlib
import socket
import ssl
import threading
import urllib.error
import urllib.request
import warnings
from datetime import datetime, timedelta, timezone

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
    default_resolver,
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
        self.thread = threading.Thread(
            target=self.httpd.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True
        )
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
# Transport: TLS over the pinned connection
# --------------------------------------------------------------------------- #

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
except ImportError:  # pragma: no cover - exercised only without the dev extra
    x509 = None

needs_cryptography = pytest.mark.skipif(
    x509 is None, reason="the cryptography package is needed to mint test certificates"
)

TLS_HOST = "webhook.test"


def _name(common_name):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def _issue(subject, issuer_name, issuer_key, *, ca=False, san=None):
    """Mint a certificate for ``subject``; ``issuer_key`` is ``None`` for a
    self-signed one. Short-lived EC keys keep the tests fast."""
    key = ec.generate_private_key(ec.SECP256R1())
    signer = issuer_key or key
    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(subject))
        .issuer_name(issuer_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    if san:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(san)]), critical=False
        )
    return key, builder.sign(signer, hashes.SHA256())


def _write_pem(directory, stem, key, cert):
    cert_path = directory / f"{stem}.crt"
    key_path = directory / f"{stem}.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return cert_path, key_path


class _TLSCerts:
    """A throwaway test CA plus three leaf certificates: one for
    ``webhook.test``, one for another name, and one self-signed."""

    def __init__(self, directory):
        ca_key, ca_cert = _issue("Webhook Test CA", _name("Webhook Test CA"), None, ca=True)
        self.ca_file, _ = _write_pem(directory, "ca", ca_key, ca_cert)
        self.good = _write_pem(
            directory, "good", *_issue(TLS_HOST, ca_cert.subject, ca_key, san=TLS_HOST)
        )
        self.wrong_host = _write_pem(
            directory,
            "wrong-host",
            *_issue("other.test", ca_cert.subject, ca_key, san="other.test"),
        )
        self.self_signed = _write_pem(
            directory, "self-signed", *_issue(TLS_HOST, _name(TLS_HOST), None, san=TLS_HOST)
        )


class _TLSServer(_Server):
    """The loopback server from above, wrapped in TLS with the given leaf
    certificate. Records the SNI name each client handshake presented."""

    def __init__(self, cert_path, key_path):
        super().__init__()
        self.sni_names: list[str | None] = []
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(cert_path), str(key_path))

        def record_sni(sock, server_name, ctx):
            self.sni_names.append(server_name)

        context.sni_callback = record_sni
        self.httpd.socket = context.wrap_socket(self.httpd.socket, server_side=True)

    def guard(self, host=TLS_HOST, ca_file=None):
        """Pin ``host`` to the loopback server and trust only ``ca_file``
        (nothing at all when it is ``None``; the system store is never
        consulted)."""
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = True
        if ca_file is not None:
            context.load_verify_locations(str(ca_file))
        return WebhookEndpointGuard.allowing(
            [host], resolver=_resolver(["127.0.0.1"]), ssl_context=context
        )

    def url(self, path="/hook", host=TLS_HOST):
        return f"https://{host}:{self.port}{path}"


@pytest.fixture(scope="module")
def tls_certs(tmp_path_factory):
    if x509 is None:
        pytest.skip("the cryptography package is needed to mint test certificates")
    return _TLSCerts(tmp_path_factory.mktemp("webhook-tls"))


@pytest.fixture
def connect_trace(monkeypatch):
    """Record every address the guard connects to, then connect for real."""
    real = socket.create_connection
    attempts: list[tuple[str, int]] = []

    def tracing_create_connection(address, *args, **kwargs):
        attempts.append((address[0], address[1]))
        return real(address, *args, **kwargs)

    monkeypatch.setattr(webhook_guard.socket, "create_connection", tracing_create_connection)
    return attempts


@contextlib.contextmanager
def _tls_server(certs, which):
    cert_path, key_path = getattr(certs, which)
    srv = _TLSServer(cert_path, key_path)
    try:
        yield srv
    finally:
        srv.close()


@needs_cryptography
class TestGuardedTLSTransport:
    def test_pinned_connection_verifies_and_presents_original_hostname(
        self, tls_certs, connect_trace
    ):
        # The socket goes to the pinned loopback address, yet TLS must verify
        # the leaf against the URL's name and send that name as SNI.
        with _tls_server(tls_certs, "good") as server:
            guard = server.guard(ca_file=tls_certs.ca_file)
            with guard.open(_post(server.url()), timeout=5) as resp:
                assert resp.status == 200
                assert json.loads(resp.read()) == {"action": "allow"}
            assert connect_trace == [("127.0.0.1", server.port)]
            assert server.sni_names == [TLS_HOST]
            assert server.requests == [(f"{TLS_HOST}:{server.port}", "/hook", b"{}")]

    def test_certificate_for_another_host_is_rejected(self, tls_certs, connect_trace):
        # Trusted CA, wrong name: the pinned address must not relax the
        # host name check.
        with _tls_server(tls_certs, "wrong_host") as server:
            guard = server.guard(ca_file=tls_certs.ca_file)
            with pytest.raises(urllib.error.URLError) as excinfo:
                guard.open(_post(server.url()), timeout=5)
            assert isinstance(excinfo.value.reason, ssl.SSLCertVerificationError)
            assert connect_trace == [("127.0.0.1", server.port)]
            assert server.requests == []

    def test_self_signed_certificate_is_rejected(self, tls_certs, connect_trace):
        # Right name, issuer outside the trust store.
        with _tls_server(tls_certs, "self_signed") as server:
            guard = server.guard(ca_file=tls_certs.ca_file)
            with pytest.raises(urllib.error.URLError) as excinfo:
                guard.open(_post(server.url()), timeout=5)
            assert isinstance(excinfo.value.reason, ssl.SSLCertVerificationError)
            assert connect_trace == [("127.0.0.1", server.port)]
            assert server.requests == []

    def test_good_certificate_needs_the_test_ca_to_be_trusted(self, tls_certs):
        # The same leaf fails with an empty trust store, so the passing test
        # above proves the CA file, not a disabled check, is what admits it.
        with _tls_server(tls_certs, "good") as server:
            with pytest.raises(urllib.error.URLError) as excinfo:
                server.guard(ca_file=None).open(_post(server.url()), timeout=5)
            assert isinstance(excinfo.value.reason, ssl.SSLCertVerificationError)

    def test_default_guard_verifies_against_the_system_store(self):
        # No context configured: the handler falls back to a verifying
        # default context, never to an unverified one.
        assert DEFAULT_GUARD.ssl_context is None
        handler = next(
            h for h in DEFAULT_GUARD.build_opener().handlers
            if isinstance(h, webhook_guard._GuardedHTTPSHandler)
        )
        assert handler._context.verify_mode == ssl.CERT_REQUIRED
        assert handler._context.check_hostname is True

    def test_with_ssl_context_keeps_policy(self):
        context = ssl.create_default_context()
        base = WebhookEndpointGuard.allowing(["10.0.0.0/8", "hooks.corp.internal"])
        guard = base.with_ssl_context(context)
        assert guard.ssl_context is context
        assert guard.allowed_hosts == base.allowed_hosts
        assert guard.allowed_networks == base.allowed_networks
        assert guard.with_resolver(default_resolver).ssl_context is context


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
