"""
mcp-trust-proxy: MCP tool access control via AgentMesh trust verification.

Components:
- TrustProxy: Intercepts MCP tool calls, verifies agent identity/trust
- ToolPolicy: Per-tool trust and capability requirements
- AuthResult: Authorization decision with audit trail
"""

from mcp_trust_proxy.proxy import TrustProxy, ToolPolicy, AuthResult

__all__ = ["TrustProxy", "ToolPolicy", "AuthResult"]
