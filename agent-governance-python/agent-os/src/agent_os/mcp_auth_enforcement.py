# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
MCP auth method enforcement — validates that MCP server connections
use approved authentication methods per the allowlist.

Supports: oauth2, mtls, api_key, bearer, none.
Default policy: deny connections with auth_method=none.

Usage::

    from agent_os.mcp_auth_enforcement import McpAuthPolicy, McpServerEntry

    policy = McpAuthPolicy(
        default_allowed_methods=["oauth2", "mtls", "bearer"],
        servers=[
            McpServerEntry(
                name="finance-tools",
                url="https://mcp.internal/finance",
                allowed_auth_methods=["mtls"],
            ),
            McpServerEntry(
                name="public-search",
                url="https://mcp.external/search",
                allowed_auth_methods=["oauth2", "api_key"],
            ),
        ],
    )

    # Check before connecting to MCP server
    result = policy.check("finance-tools", auth_method="api_key")
    assert not result.allowed  # api_key not in finance-tools allowlist
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Supported auth methods (aligns with 2026 MCP roadmap)
VALID_AUTH_METHODS = {"oauth2", "mtls", "api_key", "bearer", "none"}

# Only these URL schemes represent an actual TLS-secured transport.
TLS_SCHEMES = frozenset({"https", "wss"})


@dataclass
class McpServerEntry:
    """MCP server entry in the auth enforcement allowlist.

    Attributes:
        name: Server name (matches MCP server registration).
        url: Server URL pattern (exact match or glob).
        allowed_auth_methods: Auth methods permitted for this server.
        require_tls: Whether TLS is required. Default True.
        min_tls_version: Minimum TLS version. Default "1.2".
    """

    name: str
    url: str = ""
    allowed_auth_methods: list[str] = field(default_factory=lambda: ["oauth2", "mtls", "bearer"])
    require_tls: bool = True
    min_tls_version: str = "1.2"

    def __post_init__(self):
        for method in self.allowed_auth_methods:
            if method not in VALID_AUTH_METHODS:
                raise ValueError(
                    f"Invalid auth method '{method}' for server '{self.name}'. "
                    f"Valid methods: {sorted(VALID_AUTH_METHODS)}"
                )


@dataclass
class AuthCheckResult:
    """Result of an MCP auth method enforcement check."""

    allowed: bool
    server_name: str
    auth_method: str
    reason: str


class McpAuthPolicy:
    """Enforce authentication method requirements for MCP server connections.

    Args:
        default_allowed_methods: Default allowed auth methods for servers
            not in the explicit allowlist. Default: ["oauth2", "mtls", "bearer"].
        deny_none: Whether to deny connections with auth_method="none".
            Default True (fail-closed).
        servers: Explicit per-server auth method allowlist.
    """

    def __init__(
        self,
        default_allowed_methods: list[str] | None = None,
        deny_none: bool = True,
        servers: list[McpServerEntry] | None = None,
    ):
        self._default_methods = set(default_allowed_methods or ["oauth2", "mtls", "bearer"])
        self._deny_none = deny_none
        self._servers: dict[str, McpServerEntry] = {}
        for s in (servers or []):
            self._servers[s.name] = s

    def add_server(self, entry: McpServerEntry) -> None:
        """Add or update a server in the allowlist."""
        self._servers[entry.name] = entry

    def remove_server(self, name: str) -> bool:
        """Remove a server from the allowlist."""
        return self._servers.pop(name, None) is not None

    @staticmethod
    def _tls_violation(url: str) -> str | None:
        """Return why *url* is not TLS-secured, or ``None`` if it is.

        Scheme-based rather than prefix-based: ``ftp://``, ``ws://`` and a URL
        with no scheme at all are all non-TLS, and only ``https``/``wss`` are
        actual TLS transports.

        A non-empty URL with **no scheme** is a violation rather than a pass. It
        is the shape a bare host or a glob pattern takes (``mcp.internal``,
        ``*.internal/finance``), and there is no way to tell from it whether the
        connection will be encrypted -- so a TLS requirement cannot be
        considered satisfied. Callers decide whether to invoke this at all for
        an empty URL.

        The returned string never embeds the URL itself. It reaches
        ``AuthCheckResult.reason``, which audit backends promote to attributes
        (``otel_audit_backend`` maps it to ``agt.audit.reason``), and a server
        URL can carry a token in its userinfo or query string. The scheme is
        the only part needed to explain the decision, and it is not secret.
        """
        try:
            scheme = urlparse(url).scheme.lower()
        except (ValueError, AttributeError):
            scheme = ""
        if scheme in TLS_SCHEMES:
            return None
        allowlist = ", ".join(sorted(TLS_SCHEMES))
        if not scheme:
            return f"the URL has no scheme, so TLS cannot be verified (need {allowlist})"
        return f"URL scheme {scheme!r} is not in the TLS allowlist ({allowlist})"

    def check(self, server_name: str, auth_method: str, url: str = "") -> AuthCheckResult:
        """Check if an auth method is allowed for the given MCP server.

        Args:
            server_name: Name of the MCP server.
            auth_method: Authentication method being used.
            url: Server URL for the connection being checked. When omitted, the
                URL registered on the matching :class:`McpServerEntry` is used
                instead, so a server configured with a plaintext URL is blocked
                whether or not the caller repeats that URL here.

        Returns:
            AuthCheckResult indicating whether the connection is allowed.
        """
        auth_method = auth_method.lower().strip()

        if auth_method not in VALID_AUTH_METHODS:
            return AuthCheckResult(
                allowed=False,
                server_name=server_name,
                auth_method=auth_method,
                reason=f"Unknown auth method '{auth_method}'. Valid: {sorted(VALID_AUTH_METHODS)}",
            )

        # Deny none by default
        if auth_method == "none" and self._deny_none:
            return AuthCheckResult(
                allowed=False,
                server_name=server_name,
                auth_method=auth_method,
                reason="Unauthenticated MCP connections (auth_method=none) are denied by policy",
            )

        # Check per-server allowlist
        entry = self._servers.get(server_name)
        if entry:
            if auth_method in entry.allowed_auth_methods:
                # TLS check: the scheme is parsed and matched against the
                # allowlist below, so only `https://` and `wss://` count as
                # TLS-secured transports.
                #
                # The URL to check falls back to the one registered on the
                # entry. `url` defaults to "" and the gate used to be skipped
                # entirely when it was falsy, so a server configured with a
                # plaintext URL and require_tls=True was allowed by any caller
                # that did not repeat the URL -- including every caller on the
                # from_yaml path, where the URL lives in config and the call
                # site has no reason to pass it again.
                #
                # When neither the caller nor the entry supplies a URL there is
                # nothing to evaluate, and the gate stays skipped as before.
                # Denying that case would be a separate policy decision about
                # every server registered without a URL, not this fix.
                effective_url = url or entry.url
                if entry.require_tls and effective_url:
                    violation = self._tls_violation(effective_url)
                    if violation is not None:
                        return AuthCheckResult(
                            allowed=False,
                            server_name=server_name,
                            auth_method=auth_method,
                            reason=f"Server '{server_name}' requires TLS but {violation}",
                        )
                return AuthCheckResult(
                    allowed=True,
                    server_name=server_name,
                    auth_method=auth_method,
                    reason=f"Auth method '{auth_method}' is in server '{server_name}' allowlist",
                )
            else:
                return AuthCheckResult(
                    allowed=False,
                    server_name=server_name,
                    auth_method=auth_method,
                    reason=(
                        f"Auth method '{auth_method}' not allowed for server '{server_name}'. "
                        f"Allowed: {entry.allowed_auth_methods}"
                    ),
                )

        # Fall back to default policy
        if auth_method in self._default_methods:
            return AuthCheckResult(
                allowed=True,
                server_name=server_name,
                auth_method=auth_method,
                reason=f"Auth method '{auth_method}' is in default allowlist",
            )

        return AuthCheckResult(
            allowed=False,
            server_name=server_name,
            auth_method=auth_method,
            reason=(
                f"Auth method '{auth_method}' not in default allowlist. "
                f"Allowed: {sorted(self._default_methods)}"
            ),
        )

    @classmethod
    def from_yaml(cls, yaml_content: str) -> "McpAuthPolicy":
        """Load auth policy from YAML.

        Example::

            mcp_auth_policy:
              deny_none: true
              default_allowed_methods: [oauth2, mtls, bearer]
              servers:
                - name: finance-tools
                  url: https://mcp.internal/finance
                  allowed_auth_methods: [mtls]
                  require_tls: true
        """
        import yaml

        data = yaml.safe_load(yaml_content) or {}
        policy_data = data.get("mcp_auth_policy", data)

        servers = []
        for s in policy_data.get("servers", []):
            servers.append(McpServerEntry(
                name=s["name"],
                url=s.get("url", ""),
                allowed_auth_methods=s.get("allowed_auth_methods", ["oauth2", "mtls", "bearer"]),
                require_tls=s.get("require_tls", True),
                min_tls_version=s.get("min_tls_version", "1.2"),
            ))

        return cls(
            default_allowed_methods=policy_data.get("default_allowed_methods"),
            deny_none=policy_data.get("deny_none", True),
            servers=servers,
        )
