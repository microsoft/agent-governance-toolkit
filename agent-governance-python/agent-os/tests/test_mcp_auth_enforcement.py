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


class TestTlsGateUsesTheConfiguredUrl:
    """``require_tls`` must hold for the URL the server is registered with.

    The gate only ran when the *caller* passed a ``url``, which defaults to
    ``""``. So a server configured with a plaintext URL and ``require_tls=True``
    was allowed by any caller that did not repeat that URL -- including every
    caller on the ``from_yaml`` path, where the URL lives in config and the call
    site has no reason to pass it again.
    """

    @staticmethod
    def _policy(url: str, **kwargs: object) -> McpAuthPolicy:
        return McpAuthPolicy(
            servers=[
                McpServerEntry(name="finance", url=url, allowed_auth_methods=["mtls"], **kwargs),
            ]
        )

    @pytest.mark.parametrize(
        "url",
        [
            "http://mcp.internal/finance",
            "ws://mcp.internal/finance",
            "ftp://mcp.internal/finance",
            "gopher://mcp.internal",
            # No scheme: the shape a bare host or a glob pattern takes. Nothing
            # here says the transport is encrypted, so TLS is not satisfied.
            "mcp.internal/finance",
            "*.internal/finance",
        ],
    )
    def test_plaintext_configured_url_is_denied_without_a_caller_url(self, url: str) -> None:
        result = self._policy(url).check("finance", auth_method="mtls")
        assert result.allowed is False
        assert "requires TLS" in result.reason

    @pytest.mark.parametrize("url", ["https://mcp.internal/finance", "wss://mcp.internal/ws"])
    def test_tls_configured_url_is_allowed(self, url: str) -> None:
        assert self._policy(url).check("finance", auth_method="mtls").allowed is True

    def test_scheme_case_is_ignored(self) -> None:
        assert self._policy("HTTPS://MCP.INTERNAL").check("finance", auth_method="mtls").allowed

    def test_caller_url_still_wins_over_the_configured_one(self) -> None:
        # The caller knows the URL actually being dialed; a plaintext dial
        # against an https-registered server must still be blocked.
        policy = self._policy("https://mcp.internal/finance")
        assert policy.check("finance", auth_method="mtls").allowed is True
        assert (
            policy.check("finance", auth_method="mtls", url="http://mcp.internal/finance").allowed
            is False
        )

    def test_no_url_anywhere_leaves_the_gate_skipped(self) -> None:
        # Unchanged behaviour: with no URL from either source there is nothing
        # to evaluate. Denying this would be a separate policy decision about
        # every server registered without a URL.
        assert self._policy("").check("finance", auth_method="mtls").allowed is True

    def test_require_tls_false_allows_plaintext(self) -> None:
        policy = self._policy("http://mcp.internal/finance", require_tls=False)
        assert policy.check("finance", auth_method="mtls").allowed is True

    def test_auth_method_denial_is_not_masked_by_the_tls_gate(self) -> None:
        # A method outside the allowlist must still be reported as such, not as
        # a TLS problem — the allowlist check comes first.
        result = self._policy("http://mcp.internal/finance").check("finance", auth_method="oauth2")
        assert result.allowed is False
        assert "not allowed for server" in result.reason

    def test_yaml_configured_plaintext_server_is_denied(self) -> None:
        policy = McpAuthPolicy.from_yaml("""
mcp_auth_policy:
  servers:
    - name: finance-tools
      url: http://mcp.internal/finance
      allowed_auth_methods: [mtls]
      require_tls: true
""")
        assert policy.check("finance-tools", auth_method="mtls").allowed is False


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
