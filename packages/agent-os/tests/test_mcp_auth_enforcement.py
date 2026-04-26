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
