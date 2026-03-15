# MCP Ecosystem — Governance Server & Registry

**Submissions:**
- [modelcontextprotocol/servers#3352](https://github.com/modelcontextprotocol/servers/issues/3352) — Community governance server (Open Issue)
- [modelcontextprotocol/registry#978](https://github.com/modelcontextprotocol/registry/issues/978) — Governance category + server entry (Open Issue)
**Date Submitted:** March 2, 2026

---

## Overview

Two complementary proposals to add governance capabilities to the MCP ecosystem: a governance MCP server that any client can use, and a new security/governance category in the MCP Registry.

---

## 1. Governance MCP Server (servers#3352)

**Status:** Open issue — awaiting approval for PR

### Why

Governance needs to work across **all** MCP clients (Claude, Copilot, ADK, Cursor, etc.) without each client implementing their own governance logic. A centralized MCP governance server provides universal policy enforcement.

### Proposed Tools

| Tool | Description |
|------|-------------|
| `governance_check_policy` | Validate a tool call against loaded governance policies |
| `governance_detect_threats` | Scan content for known threat patterns (5 categories) |
| `governance_score_trust` | Calculate trust score for agent delegation |
| `governance_audit_log` | Log a governance event to the audit trail |
| `governance_audit_query` | Query audit trail for compliance reporting |

### Proposed Resources

| URI | Description |
|-----|-------------|
| `governance://policies/active` | Active governance policies (JSON) |
| `governance://audit/recent` | Recent audit events (JSON) |

### Implementation Plan
- Python using MCP Python SDK
- YAML-based policy configuration (matching Agent-OS policy format)
- SQLite for audit trail storage
- Configurable governance levels: permissive / moderate / strict / paranoid

---

## 2. Registry Category (registry#978)

**Status:** Open issue — awaiting approval

### Proposal
Add a "security" or "governance" category to the MCP Registry for:
- Policy enforcement servers
- Security scanning servers
- Audit/compliance servers
- Trust scoring servers

### Proposed Entry
```json
{
  "name": "agent-governance",
  "description": "Policy enforcement, threat detection, trust scoring, and audit trails for MCP tool calls",
  "repository": "https://github.com/microsoft/agent-governance-toolkit",
  "category": "security",
  "tools": [
    "governance_check_policy",
    "governance_detect_threats",
    "governance_score_trust",
    "governance_audit_log",
    "governance_audit_query"
  ]
}
```

## Existing MCP Server

The toolkit already includes a working MCP server:
- Published on npm: `@agentos/mcp-server`
- Listed on [Glama](https://glama.ai/mcp/servers/@microsoft/agentos-mcp-server)
- Supports both stdio and HTTP transports

## Links

- [MCP Servers Repository](https://github.com/modelcontextprotocol/servers)
- [MCP Registry](https://github.com/modelcontextprotocol/registry)
- [Agent Governance Toolkit](https://github.com/microsoft/agent-governance-toolkit)
- [Glama Listing](https://glama.ai/mcp/servers/@microsoft/agentos-mcp-server)
