<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# agent-mcp-governance

`agent-mcp-governance` is a standalone **Public Preview** package that exposes
the MCP governance primitives used in this repository:

- `MCPGateway` for policy enforcement and audit logging
- `MCPSlidingRateLimiter` for per-agent call budgets
- `MCPSessionAuthenticator` for short-lived MCP sessions
- `MCPMessageSigner`, `MCPSecurityScanner`, and `MCPResponseScanner` for
  message integrity and security scanning

This package is intentionally thin. It exists as a focused MCP governance
surface for enterprise packaging and reuse scenarios without pulling in the
full Agent Governance Toolkit as an install-time dependency.

## Installation

```bash
pip install agent-mcp-governance
```

## Quick usage

```python
from agent_mcp_governance import (
    MCPGateway,
    MCPSessionAuthenticator,
    MCPSlidingRateLimiter,
)


class DemoPolicy:
    name = "demo"
    allowed_tools = ["read_file", "web_search"]
    max_tool_calls = 10
    log_all_calls = True
    require_human_approval = False

    def matches_pattern(self, _text: str) -> list[str]:
        return []


policy = DemoPolicy()
gateway = MCPGateway(policy)
rate_limiter = MCPSlidingRateLimiter(max_calls_per_window=5, window_size=60.0)
session_auth = MCPSessionAuthenticator()

token = session_auth.create_session("agent-123", user_id="alice@example.com")
session = session_auth.validate_session("agent-123", token)

if session and rate_limiter.try_acquire(session.rate_limit_key):
    allowed, reason = gateway.intercept_tool_call(
        session.agent_id,
        "read_file",
        {"path": "docs/architecture.md"},
    )
    print(allowed, reason)
```

## Zero AGT dependency note

The package metadata declares **zero Agent Governance Toolkit dependencies**
(`dependencies = []` in `pyproject.toml`). That makes this package suitable for
monorepo, vendored, and enterprise repackaging workflows where MCP governance
components are distributed independently from the broader toolkit.

## Security guidance

For deployment guidance and hardening recommendations, see the
[OWASP MCP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html).
