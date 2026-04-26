# MCP Tools Reference

Agent OS exposes its kernel primitives through the [Model Context Protocol (MCP)](https://modelcontextprotocol.io/).
The MCP Kernel Server (`modules/mcp-kernel-server/`) provides **8 tools**, **2 resources**, and **3 prompts** that any MCP-compatible client (Claude Desktop, GitHub Copilot, Cursor) can use.

> **Server info:** `agent-os-kernel` v1.2.0 · Protocol `2024-11-05`

---

## Tools

### `verify_code_safety`

Check if code is safe to execute before running it. This is the primary integration point for AI assistants to verify generated code against the Agent OS policy engine.

**Input Schema:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `code` | `string` | ✅ | The code to verify |
| `language` | `string` | ✅ | Programming language (e.g. `python`, `javascript`, `sql`) |
| `context` | `object` | | Additional context (file path, project type, etc.) |

**Output:**

```json
{
  "safe": true,
  "violations": [],
  "warnings": [],
  "language": "python",
  "code_length": 42,
  "rules_checked": 20
}
```

When violations are found (`safe: false`):

```json
{
  "safe": false,
  "violations": [
    {
      "rule": "drop_table",
      "severity": "critical",
      "message": "Destructive SQL: DROP operation detected",
      "alternative": "Consider using soft delete or archiving instead of DROP"
    }
  ],
  "blocked_reason": "Destructive SQL: DROP operation detected",
  "alternative": "Consider using soft delete or archiving instead of DROP"
}
```

**Example usage:**

```
Use verify_code_safety with:
  code: "DROP TABLE users;"
  language: "sql"
```

---

### `cmvk_verify`

Verify a claim across multiple AI models to detect hallucinations using drift-based consensus. Calculates pairwise drift between model responses and flags disagreements above the threshold.

**Input Schema:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `claim` | `string` | ✅ | The claim or statement to verify |
| `context` | `string` | | Optional context for the claim |
| `models` | `array[string]` | | Models to use (default: all configured) |
| `threshold` | `number` | | Agreement threshold 0–1 (default: 0.85) |

**Output:**

```json
{
  "verified": true,
  "confidence": 0.912,
  "drift_score": 0.088,
  "avg_drift": 0.065,
  "models_checked": ["gpt-4", "claude-sonnet-4", "gemini-pro"],
  "disagreement_detected": false,
  "consensus_method": "drift_threshold",
  "interpretation": "Strong consensus across all models. High confidence in claim validity."
}
```

---

### `cmvk_review`

Multi-model code review for security, bugs, and best practices. Optimised for code analysis rather than general claim verification.

**Input Schema:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `code` | `string` | ✅ | The code to review |
| `language` | `string` | | Programming language |
| `models` | `array[string]` | | Models to use (default: `["gpt-4", "claude-sonnet-4", "gemini-pro"]`) |
| `focus` | `array[string]` | | Areas to focus on: `security`, `bugs`, `performance`, `style` |

**Output:**

```json
{
  "consensus": 0.67,
  "reviews": [
    {"model": "gpt-4", "passed": true, "issues": [], "summary": "No issues found"},
    {"model": "claude-sonnet-4", "passed": false, "issues": [...], "summary": "Found 1 issue(s)"}
  ],
  "issues": [
    {
      "category": "security",
      "severity": "high",
      "issue": "eval() usage is dangerous",
      "fix": "Use JSON.parse() or ast.literal_eval() for data parsing"
    }
  ],
  "recommendation": "Based on multi-model review:\n1. eval() usage is dangerous: Use JSON.parse()..."
}
```

---

### `kernel_execute`

Execute an action through the Agent OS kernel with policy enforcement, signal handling, and audit logging. All context is passed in the request (stateless).

**Input Schema:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `action` | `string` | ✅ | Action to execute (e.g. `database_query`, `file_write`) |
| `params` | `object` | | Parameters for the action |
| `agent_id` | `string` | ✅ | ID of the requesting agent |
| `policies` | `array[string]` | | Policy names to enforce (e.g. `["read_only", "no_pii"]`) |
| `context` | `object` | | Execution context (history, state, etc.) |

**Output (allowed):**

```json
{
  "status": "executed",
  "action": "database_query",
  "result": "Action 'database_query' executed successfully",
  "params_received": ["query"]
}
```

**Output (blocked — SIGKILL):**

```json
{
  "error": "SIGKILL: Policy violation - Write query blocked by read_only policy"
}
```

---

### `iatp_sign`

Sign content with cryptographic trust attestation for inter-agent communication using the Inter-Agent Trust Protocol.

**Input Schema:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `content` | `string` | ✅ | Content to sign |
| `agent_id` | `string` | ✅ | ID of the signing agent |
| `capabilities` | `array[string]` | | Capabilities being attested (e.g. `["reversible", "idempotent"]`) |
| `metadata` | `object` | | Additional metadata to include |

**Output:**

```json
{
  "signature": "a1b2c3d4...",
  "agent_id": "agent-001",
  "capabilities": ["reversible"],
  "content_hash": "e5f6a7b8...",
  "timestamp": "2025-01-01T00:00:00",
  "protocol_version": "iatp-1.0"
}
```

---

### `iatp_verify`

Verify trust relationship with another agent before communication. Checks capability manifest, attestation signature, trust level, and policy compatibility.

**Input Schema:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `remote_agent_id` | `string` | ✅ | ID of the agent to verify |
| `required_trust_level` | `string` | | One of `verified_partner`, `trusted`, `standard`, `any` (default: `standard`) |
| `required_scopes` | `array[string]` | | Required capability scopes (e.g. `["repo:read"]`) |
| `data_classification` | `string` | | One of `public`, `internal`, `confidential`, `pii` |

**Output (verified):**

```json
{
  "verified": true,
  "remote_agent_id": "agent-002",
  "trust_score": 8,
  "trust_level": "standard",
  "scopes": ["data:read", "data:write"],
  "attestation_valid": true,
  "policy_compatible": true
}
```

**Output (rejected):**

```json
{
  "verified": false,
  "trust_score": 3,
  "required_score": 5,
  "error": "Trust score 3 below required 5"
}
```

---

### `iatp_reputation`

Query or slash (penalise) agent reputation in the IATP network.

**Input Schema:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `action` | `string` | ✅ | `query` or `slash` |
| `agent_id` | `string` | ✅ | Agent ID to query or slash |
| `slash_reason` | `string` | | Reason for slashing (required if `action=slash`) |
| `slash_severity` | `string` | | `critical` (-2.0), `high` (-1.0), `medium` (-0.5), `low` (-0.25) |
| `evidence` | `object` | | Evidence for the slash (e.g. CMVK drift score) |

**Output (query):**

```json
{
  "agent_id": "agent-002",
  "reputation_score": 5.0,
  "trust_level": "standard",
  "history_count": 0
}
```

**Output (slash):**

```json
{
  "agent_id": "agent-002",
  "previous_score": 5.0,
  "new_score": 4.0,
  "penalty_applied": 1.0,
  "reason": "Hallucination detected",
  "severity": "high"
}
```

---

### `get_audit_log`

Retrieve the Agent OS audit trail for compliance and debugging.

**Input Schema:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `limit` | `number` | | Maximum entries to return (default: 20) |
| `filter` | `object` | | Filter criteria (see below) |
| `filter.agent_id` | `string` | | Filter by agent ID |
| `filter.type` | `string` | | One of `blocked`, `allowed`, `cmvk_review`, `all` |
| `filter.since` | `string` | | ISO 8601 timestamp |

**Output:**

```json
{
  "logs": [...],
  "returned": 5,
  "total": 42,
  "stats": {
    "blocked_total": 3,
    "allowed_total": 39
  }
}
```

---

## Resources

| URI | Name | Description | MIME Type |
|-----|------|-------------|-----------|
| `vfs://` | Agent VFS Root | Virtual File System for agent memory | `application/json` |
| `audit://` | Audit Log | Immutable audit trail of agent actions | `application/json` |

### Resource Templates

| URI Template | Description |
|-------------|-------------|
| `vfs://{agent_id}/mem/{path}` | Agent working memory |
| `vfs://{agent_id}/policy/{path}` | Agent policy files |
| `audit://{agent_id}/log` | Read-only audit trail for a specific agent |

---

## Prompts

### `governed_agent`

Standard instructions for operating as a governed agent under Agent OS.

| Argument | Required | Description |
|----------|----------|-------------|
| `agent_id` | ✅ | Unique identifier for this agent |
| `policies` | | Comma-separated list of policies to enforce |

### `verify_claim`

Instructions for verifying a claim using CMVK verification.

| Argument | Required | Description |
|----------|----------|-------------|
| `claim` | ✅ | The claim to verify |

### `safe_execution`

Template for executing actions safely through the kernel.

| Argument | Required | Description |
|----------|----------|-------------|
| `action` | ✅ | The action to execute |
| `params` | ✅ | JSON parameters for the action |

---

## Running the Server

```bash
# Stdio mode (for Claude Desktop / Copilot)
mcp-kernel-server --stdio

# HTTP mode (for development)
mcp-kernel-server --http --port 8080
```

### Claude Desktop Configuration

```json
{
  "mcpServers": {
    "agent-os-kernel": {
      "command": "mcp-kernel-server",
      "args": ["--stdio"]
    }
  }
}
```
