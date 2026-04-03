# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
MCP Trust-Verified Server — demonstrates trust-gated tool access.

DEMO ONLY: This example accepts agent_did and trust_score as client-supplied
tool arguments. In production, agent identity and trust scores must come from
a verified source (identity registry, trust server) — never from the calling
agent itself.

Three tools with escalating trust requirements:
  - read_file:       low trust (300), no special capabilities
  - write_file:      medium trust (600), requires "fs_write" capability
  - query_database:  high trust (800), requires "db_query", rate-limited

Each tool call is authorized through a TrustProxy before execution.
Tools are fingerprinted with MCPSecurityScanner for rug-pull detection.
"""

from __future__ import annotations

import atexit

from mcp.server.fastmcp import FastMCP

# Trust proxy — enforces per-tool trust thresholds and capabilities
from mcp_trust_proxy import AuthResult, ToolPolicy, TrustProxy

# Security scanner — fingerprints tool definitions to detect rug pulls
from agent_os.mcp_security import MCPSecurityScanner

# ---------------------------------------------------------------------------
# Server setup
# ---------------------------------------------------------------------------

SERVER_NAME = "trust-verified-example"

mcp = FastMCP(
    "Trust-Verified Server",
    instructions=(
        "An example MCP server where every tool call is gated by "
        "AgentMesh trust verification. Agents must present a DID and "
        "meet the tool's minimum trust score to proceed."
    ),
)

# ---------------------------------------------------------------------------
# Governance layer
# ---------------------------------------------------------------------------

# Step 1: Configure the trust proxy with per-tool policies.
proxy = TrustProxy(
    default_min_trust=300,
    tool_policies={
        "read_file": ToolPolicy(
            min_trust=300,
            description="Read a file (low trust)",
        ),
        "write_file": ToolPolicy(
            min_trust=600,
            required_capabilities=["fs_write"],
            description="Write a file (medium trust)",
        ),
        "query_database": ToolPolicy(
            min_trust=800,
            required_capabilities=["db_query"],
            max_calls_per_minute=10,
            description="Query a database (high trust, rate-limited)",
        ),
    },
)

# Step 2: Register tool fingerprints for rug-pull detection.
scanner = MCPSecurityScanner()

scanner.register_tool(
    tool_name="read_file",
    description="Read a file by path and return its contents.",
    schema={"type": "object", "properties": {"path": {"type": "string"}}},
    server_name=SERVER_NAME,
)
scanner.register_tool(
    tool_name="write_file",
    description="Write content to a file path.",
    schema={
        "type": "object",
        "properties": {
            "path": {"type": "string"},
            "content": {"type": "string"},
        },
    },
    server_name=SERVER_NAME,
)
scanner.register_tool(
    tool_name="query_database",
    description="Execute a read-only SQL query.",
    schema={"type": "object", "properties": {"sql": {"type": "string"}}},
    server_name=SERVER_NAME,
)

# Simple audit log — collects AuthResult records for review.
audit_log: list[dict] = []


def _authorize(tool_name: str, agent_did: str, trust_score: int,
               capabilities: list[str] | None = None) -> AuthResult:
    """Authorize a tool call and record the result. Fail-closed on errors."""
    try:
        result = proxy.authorize(
            agent_did=agent_did,
            agent_trust_score=trust_score,
            tool_name=tool_name,
            agent_capabilities=capabilities,
        )
    except Exception:
        # Fail closed — any authorization error means deny.
        result = AuthResult(
            allowed=False,
            tool_name=tool_name,
            agent_did=agent_did,
            trust_score=trust_score,
            reason="Authorization error (fail-closed)",
        )
    audit_log.append(result.to_dict())
    return result


# ---------------------------------------------------------------------------
# Tool definitions
# ---------------------------------------------------------------------------

@mcp.tool()
def read_file(path: str, agent_did: str = "", trust_score: int = 0) -> dict:
    """Read a file by path. Requires minimum trust score of 300.

    Args:
        path: File path to read.
        agent_did: The calling agent's DID (e.g. "did:mesh:abc123").
        trust_score: The agent's current trust score (0-1000).
    """
    auth = _authorize("read_file", agent_did, trust_score)
    if not auth.allowed:
        return {"error": auth.reason, "allowed": False}
    # Simulated file read (replace with real I/O in production)
    return {"path": path, "content": f"[simulated content of {path}]", "allowed": True}


@mcp.tool()
def write_file(path: str, content: str, agent_did: str = "",
               trust_score: int = 0, capabilities: list[str] | None = None) -> dict:
    """Write content to a file. Requires trust >= 600 and fs_write capability.

    Args:
        path: Destination file path.
        content: Content to write.
        agent_did: The calling agent's DID.
        trust_score: The agent's current trust score (0-1000).
        capabilities: List of agent capabilities (must include "fs_write").
    """
    auth = _authorize("write_file", agent_did, trust_score, capabilities)
    if not auth.allowed:
        return {"error": auth.reason, "allowed": False}
    return {"path": path, "bytes_written": len(content), "allowed": True}


@mcp.tool()
def query_database(sql: str, agent_did: str = "", trust_score: int = 0,
                   capabilities: list[str] | None = None) -> dict:
    """Execute a read-only SQL query. Requires trust >= 800, db_query capability, rate-limited to 10/min.

    Args:
        sql: The SQL query to execute (read-only).
        agent_did: The calling agent's DID.
        trust_score: The agent's current trust score (0-1000).
        capabilities: List of agent capabilities (must include "db_query").
    """
    auth = _authorize("query_database", agent_did, trust_score, capabilities)
    if not auth.allowed:
        return {"error": auth.reason, "allowed": False}
    return {"sql": sql, "rows": [{"id": 1, "name": "example"}], "allowed": True}


# ---------------------------------------------------------------------------
# Shutdown summary
# ---------------------------------------------------------------------------

def _print_summary() -> None:
    stats = proxy.get_stats()
    print(f"\n--- Trust Proxy Summary ---")
    print(f"Total requests: {stats['total_requests']}")
    print(f"Allowed: {stats['allowed']}  |  Denied: {stats['denied']}")
    print(f"Audit entries: {len(audit_log)}")

atexit.register(_print_summary)

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    mcp.run()
