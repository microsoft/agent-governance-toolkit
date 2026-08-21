# MCP Auth Enforcement — TLS Gate

`McpAuthPolicy` enforces per-server authentication method allowlists for MCP
connections. When a server entry has `require_tls: true` (the default), the
policy gate validates that the connection URL uses a TLS-secured transport
(`https` or `wss`) before allowing the connection.

## URL resolution order

The TLS gate resolves the URL to check using the following priority:

1. **Caller-supplied URL** — the `url` argument passed to `check()`.
2. **Configured entry URL** — the `url` field on the `McpServerEntry`.
3. **No URL available** — both sources are empty.

When the caller does not supply a URL (or passes `""`), the gate falls back to
the configured `entry.url`. This prevents a caller from bypassing the TLS
requirement by simply omitting the URL argument.

When neither source provides a URL, the gate permits the connection. This
preserves spec S10.12 compatibility: `add_server()` with default `url=""` must
remain allowed for registrations where the URL is determined at connection time.

## Configuration

```python
from agent_os.mcp_auth_enforcement import McpAuthPolicy, McpServerEntry

policy = McpAuthPolicy(
    servers=[
        McpServerEntry(
            name="finance-tools",
            url="https://mcp.internal/finance",
            allowed_auth_methods=["mtls"],
            require_tls=True,  # default
        ),
    ],
)

# Caller supplies url → checked directly
result = policy.check("finance-tools", auth_method="mtls",
                       url="https://mcp.internal/finance")
assert result.allowed

# Caller omits url → entry.url is checked
result = policy.check("finance-tools", auth_method="mtls")
assert result.allowed  # entry.url is https

# Non-TLS entry.url is caught even without caller url
policy_http = McpAuthPolicy(
    servers=[
        McpServerEntry(
            name="insecure",
            url="http://mcp.internal/api",
            allowed_auth_methods=["oauth2"],
            require_tls=True,
        ),
    ],
)
result = policy_http.check("insecure", auth_method="oauth2")
assert not result.allowed  # http scheme denied
```

## YAML configuration

```yaml
mcp_auth_policy:
  deny_none: true
  default_allowed_methods: [oauth2, mtls, bearer]
  servers:
    - name: finance-tools
      url: https://mcp.internal/finance
      allowed_auth_methods: [mtls]
      require_tls: true
    - name: dev-local
      url: ""                          # S10.12: empty URL allowed
      allowed_auth_methods: [oauth2]
      require_tls: true
```

## Allowed TLS schemes

Only `https` and `wss` are treated as TLS-secured transports. All other
schemes — `http`, `ws`, `ftp`, `gopher`, bare hostnames without a scheme —
are rejected when `require_tls` is `true`.

## Security considerations

Prior to the fix for
[#3785](https://github.com/microsoft/agent-governance-toolkit/issues/3785),
the TLS gate only checked the caller-supplied `url` and never consulted
`entry.url`. A caller that omitted `url` (or passed `""`) bypassed the TLS
check entirely, even when the server entry had `require_tls: true` and a
configured non-TLS URL. In multi-tenant setups where the caller is
untrusted, this allowed connections to proceed over plaintext transports.

The fix ensures the configured URL is always evaluated when no caller URL is
provided, closing the bypass while preserving backward compatibility for
entries that legitimately have no URL configured.
