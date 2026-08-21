# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for MCP auth method enforcement."""

import pytest
from agent_os.mcp_auth_enforcement import (
    McpAuthPolicy,
    McpServerEntry,
    AuthCheckResult,
    VALID_AUTH_METHODS,
)


class TestMcpServerEntry:
    def test_valid_entry(self):
        e = McpServerEntry(name="test", allowed_auth_methods=["oauth2", "mtls"])
        assert e.name == "test"
        assert e.require_tls is True

    def test_invalid_auth_method(self):
        with pytest.raises(ValueError, match="Invalid auth method"):
            McpServerEntry(name="test", allowed_auth_methods=["magic"])


class TestMcpAuthPolicy:
    def test_deny_none_by_default(self):
        policy = McpAuthPolicy()
        result = policy.check("any-server", auth_method="none")
        assert not result.allowed
        assert "none" in result.reason.lower()

    def test_allow_oauth2_by_default(self):
        policy = McpAuthPolicy()
        result = policy.check("any-server", auth_method="oauth2")
        assert result.allowed

    def test_allow_mtls_by_default(self):
        policy = McpAuthPolicy()
        result = policy.check("any-server", auth_method="mtls")
        assert result.allowed

    def test_allow_bearer_by_default(self):
        policy = McpAuthPolicy()
        result = policy.check("any-server", auth_method="bearer")
        assert result.allowed

    def test_deny_api_key_not_in_default(self):
        policy = McpAuthPolicy()
        result = policy.check("any-server", auth_method="api_key")
        assert not result.allowed

    def test_custom_default_methods(self):
        policy = McpAuthPolicy(default_allowed_methods=["api_key", "bearer"])
        assert policy.check("s", auth_method="api_key").allowed
        assert not policy.check("s", auth_method="oauth2").allowed

    def test_per_server_allowlist(self):
        policy = McpAuthPolicy(servers=[
            McpServerEntry(name="finance", allowed_auth_methods=["mtls"]),
        ])
        # mtls allowed for finance
        assert policy.check("finance", auth_method="mtls").allowed
        # oauth2 NOT allowed for finance (even though it's in default)
        assert not policy.check("finance", auth_method="oauth2").allowed

    def test_unknown_server_uses_default(self):
        policy = McpAuthPolicy(servers=[
            McpServerEntry(name="finance", allowed_auth_methods=["mtls"]),
        ])
        # Unknown server falls back to default (oauth2 allowed)
        assert policy.check("unknown", auth_method="oauth2").allowed

    def test_deny_none_can_be_disabled(self):
        policy = McpAuthPolicy(deny_none=False, default_allowed_methods=["none"])
        result = policy.check("s", auth_method="none")
        assert result.allowed

    def test_invalid_auth_method_rejected(self):
        policy = McpAuthPolicy()
        result = policy.check("s", auth_method="magic")
        assert not result.allowed
        assert "Unknown" in result.reason

    def test_tls_required(self):
        policy = McpAuthPolicy(servers=[
            McpServerEntry(name="secure", allowed_auth_methods=["oauth2"], require_tls=True),
        ])
        # HTTPS OK
        assert policy.check("secure", auth_method="oauth2", url="https://api.example.com").allowed
        # HTTP rejected
        assert not policy.check("secure", auth_method="oauth2", url="http://api.example.com").allowed

    def test_add_remove_server(self):
        policy = McpAuthPolicy()
        policy.add_server(McpServerEntry(name="new", allowed_auth_methods=["api_key"]))
        assert policy.check("new", auth_method="api_key").allowed
        policy.remove_server("new")
        # Falls back to default
        assert not policy.check("new", auth_method="api_key").allowed

    def test_result_fields(self):
        policy = McpAuthPolicy()
        result = policy.check("my-server", auth_method="oauth2")
        assert result.server_name == "my-server"
        assert result.auth_method == "oauth2"
        assert result.allowed
        assert len(result.reason) > 0


class TestTlsGateEntryUrlFallback:
    """Tests for the TLS gate consulting entry.url when the caller omits url.

    Regression tests for https://github.com/microsoft/agent-governance-toolkit/issues/3785:
    the TLS gate previously only checked the *caller-supplied* url, silently
    skipping the check when url was empty even when entry.url was configured
    with a non-TLS scheme.
    """

    def test_caller_url_empty_entry_url_http_denied(self):
        """Core bug: caller omits url but entry.url is http → must deny."""
        policy = McpAuthPolicy(servers=[
            McpServerEntry(
                name="insecure-configured",
                url="http://mcp.internal/api",
                allowed_auth_methods=["oauth2"],
                require_tls=True,
            ),
        ])
        result = policy.check("insecure-configured", auth_method="oauth2")
        assert not result.allowed
        assert "TLS" in result.reason

    def test_caller_url_empty_entry_url_https_allowed(self):
        """entry.url is https and caller omits url → must allow."""
        policy = McpAuthPolicy(servers=[
            McpServerEntry(
                name="secure-configured",
                url="https://mcp.internal/api",
                allowed_auth_methods=["oauth2"],
                require_tls=True,
            ),
        ])
        result = policy.check("secure-configured", auth_method="oauth2")
        assert result.allowed

    def test_caller_url_empty_entry_url_wss_allowed(self):
        """entry.url is wss (TLS WebSocket) and caller omits url → must allow."""
        policy = McpAuthPolicy(servers=[
            McpServerEntry(
                name="ws-secure",
                url="wss://mcp.internal/stream",
                allowed_auth_methods=["bearer"],
                require_tls=True,
            ),
        ])
        result = policy.check("ws-secure", auth_method="bearer")
        assert result.allowed

    def test_caller_url_empty_entry_url_ws_denied(self):
        """entry.url is ws (no TLS) and caller omits url → must deny."""
        policy = McpAuthPolicy(servers=[
            McpServerEntry(
                name="ws-insecure",
                url="ws://mcp.internal/stream",
                allowed_auth_methods=["bearer"],
                require_tls=True,
            ),
        ])
        result = policy.check("ws-insecure", auth_method="bearer")
        assert not result.allowed
        assert "TLS" in result.reason

    def test_caller_url_empty_entry_url_ftp_denied(self):
        """entry.url with non-TLS scheme (ftp) and caller omits url → must deny."""
        policy = McpAuthPolicy(servers=[
            McpServerEntry(
                name="ftp-server",
                url="ftp://files.internal/data",
                allowed_auth_methods=["api_key"],
                require_tls=True,
            ),
        ])
        result = policy.check("ftp-server", auth_method="api_key")
        assert not result.allowed

    def test_caller_url_overrides_entry_url(self):
        """When caller supplies a url, it takes precedence over entry.url."""
        policy = McpAuthPolicy(servers=[
            McpServerEntry(
                name="mixed",
                url="https://mcp.internal/api",
                allowed_auth_methods=["oauth2"],
                require_tls=True,
            ),
        ])
        # Caller supplies http → denied even though entry.url is https
        result = policy.check("mixed", auth_method="oauth2", url="http://evil.example.com")
        assert not result.allowed

    def test_caller_https_overrides_entry_http(self):
        """When caller supplies https, it takes precedence over entry's http url."""
        policy = McpAuthPolicy(servers=[
            McpServerEntry(
                name="upgraded",
                url="http://mcp.internal/api",
                allowed_auth_methods=["oauth2"],
                require_tls=True,
            ),
        ])
        # Caller supplies https → allowed even though entry.url is http
        result = policy.check("upgraded", auth_method="oauth2", url="https://mcp.secure.com")
        assert result.allowed

    def test_both_urls_empty_require_tls_true_allowed(self):
        """S10.12 compat: add_server with default url='' must remain allowed.

        When both caller url and entry.url are empty, require_tls has nothing
        to evaluate, so the connection is permitted (fail-open on missing URL,
        not fail-open on TLS).
        """
        policy = McpAuthPolicy(servers=[
            McpServerEntry(
                name="no-url",
                url="",
                allowed_auth_methods=["mtls"],
                require_tls=True,
            ),
        ])
        result = policy.check("no-url", auth_method="mtls")
        assert result.allowed

    def test_require_tls_false_skips_check(self):
        """When require_tls is False, any URL scheme is accepted."""
        policy = McpAuthPolicy(servers=[
            McpServerEntry(
                name="permissive",
                url="http://mcp.internal/api",
                allowed_auth_methods=["oauth2"],
                require_tls=False,
            ),
        ])
        result = policy.check("permissive", auth_method="oauth2")
        assert result.allowed

    def test_entry_url_no_scheme_denied(self):
        """entry.url with no scheme (e.g. bare hostname) → denied under require_tls."""
        policy = McpAuthPolicy(servers=[
            McpServerEntry(
                name="bare",
                url="mcp.internal:8443/api",
                allowed_auth_methods=["oauth2"],
                require_tls=True,
            ),
        ])
        result = policy.check("bare", auth_method="oauth2")
        assert not result.allowed

    def test_caller_empty_string_is_treated_as_absent(self):
        """Passing url='' explicitly behaves the same as omitting it."""
        policy = McpAuthPolicy(servers=[
            McpServerEntry(
                name="explicit-empty",
                url="http://mcp.internal/api",
                allowed_auth_methods=["oauth2"],
                require_tls=True,
            ),
        ])
        result = policy.check("explicit-empty", auth_method="oauth2", url="")
        assert not result.allowed
        assert "TLS" in result.reason

    def test_yaml_tls_fallback(self):
        """End-to-end: YAML-loaded policy with require_tls + entry.url fallback."""
        policy = McpAuthPolicy.from_yaml("""
mcp_auth_policy:
  servers:
    - name: finance-tls
      url: http://mcp.internal/finance
      allowed_auth_methods: [mtls]
      require_tls: true
    - name: finance-secure
      url: https://mcp.internal/finance
      allowed_auth_methods: [mtls]
      require_tls: true
""")
        # http entry.url → denied when caller omits url
        assert not policy.check("finance-tls", auth_method="mtls").allowed
        # https entry.url → allowed when caller omits url
        assert policy.check("finance-secure", auth_method="mtls").allowed


class TestFromYaml:
    def test_parse_yaml(self):
        policy = McpAuthPolicy.from_yaml("""
mcp_auth_policy:
  deny_none: true
  default_allowed_methods: [oauth2, mtls]
  servers:
    - name: finance-tools
      url: https://mcp.internal/finance
      allowed_auth_methods: [mtls]
      require_tls: true
    - name: public-search
      allowed_auth_methods: [oauth2, api_key]
""")
        assert policy.check("finance-tools", auth_method="mtls").allowed
        assert not policy.check("finance-tools", auth_method="oauth2").allowed
        assert policy.check("public-search", auth_method="api_key").allowed
        assert policy.check("unknown", auth_method="oauth2").allowed
        assert not policy.check("unknown", auth_method="bearer").allowed

    def test_empty_yaml(self):
        policy = McpAuthPolicy.from_yaml("")
        assert policy.check("s", auth_method="oauth2").allowed
