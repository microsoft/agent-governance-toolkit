# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Configuration diagnostics for MCP authentication policy loading."""

import logging

from agent_os.mcp_auth_enforcement import McpAuthPolicy, McpServerEntry


def test_yaml_warns_when_tls_is_required_without_a_url(caplog) -> None:
    with caplog.at_level(logging.WARNING, logger="agent_os.mcp_auth_enforcement"):
        McpAuthPolicy.from_yaml("""
mcp_auth_policy:
  servers:
    - name: finance-tools
      allowed_auth_methods: [mtls]
      require_tls: true
""")

    assert "finance-tools" in caplog.text
    assert "requires TLS but has no URL configured" in caplog.text


def test_yaml_with_tls_url_does_not_emit_missing_url_warning(caplog) -> None:
    with caplog.at_level(logging.WARNING, logger="agent_os.mcp_auth_enforcement"):
        McpAuthPolicy.from_yaml("""
mcp_auth_policy:
  servers:
    - name: finance-tools
      url: https://mcp.internal/finance
      allowed_auth_methods: [mtls]
      require_tls: true
""")

    assert "requires TLS but has no URL configured" not in caplog.text


def test_programmatic_entry_without_url_remains_allowed(caplog) -> None:
    """The config warning must not change the S10.12 programmatic path."""
    with caplog.at_level(logging.WARNING, logger="agent_os.mcp_auth_enforcement"):
        policy = McpAuthPolicy(
            servers=[McpServerEntry(name="dynamic", allowed_auth_methods=["mtls"])]
        )

    assert "requires TLS but has no URL configured" not in caplog.text
    assert policy.check("dynamic", auth_method="mtls").allowed
