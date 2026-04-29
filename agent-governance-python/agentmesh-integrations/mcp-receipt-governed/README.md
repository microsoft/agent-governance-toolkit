# MCP Receipt Governed

MCP tool-call receipt signing integration for Agent Governance Toolkit.

Every MCP tool invocation optionally produces a **signed governance receipt** linking the Cedar policy decision to the tool call, providing a cryptographically verifiable audit trail for agent operations.

## Quick Start

```python
from mcp_receipt_governed import McpReceiptAdapter

adapter = McpReceiptAdapter(
    cedar_policy="""
        permit(principal, action == Action::"ReadData", resource);
        forbid(principal, action == Action::"DeleteFile", resource);
    """,
    cedar_policy_id="policy:mcp-tools:v1",
    signing_key_hex="a" * 64,  # Replace with real Ed25519 seed
)

# Govern a tool call — produces a signed receipt
receipt = adapter.govern_tool_call(
    agent_did="did:mesh:agent-1",
    tool_name="ReadData",
    tool_args={"path": "/data/report.csv"},
)

print(f"Decision: {receipt.cedar_decision}")
print(f"Receipt ID: {receipt.receipt_id}")
print(f"Signed: {receipt.signature is not None}")
```

## Features

- **Cedar policy binding**: Receipt payload includes the Cedar policy ID and allow/deny decision
- **Ed25519 signatures**: Non-repudiable receipt signing with HMAC-SHA256 fallback
- **Canonical JSON hashing**: JCS-style deterministic serialization for verifiable receipts
- **Receipt store**: In-memory audit trail with filtering by agent, tool, or decision
- **Zero required dependencies**: Works with stdlib only; Ed25519 signing available via `pip install agentmesh-mcp-receipts[crypto]`

## Installation

```bash
# From the repository root
pip install -e agent-governance-python/agentmesh-integrations/mcp-receipt-governed

# With Ed25519 signing support
pip install -e "agent-governance-python/agentmesh-integrations/mcp-receipt-governed[crypto]"
```

## Testing

```bash
cd agent-governance-python/agentmesh-integrations/mcp-receipt-governed
pip install -e ".[dev]"
pytest tests/ -v
```

## Architecture

```
MCP Tool Call
     │
     ▼
┌────────────────────┐
│  McpReceiptAdapter │
│  ┌──────────────┐  │
│  │ Cedar Policy │──┼──▶ allow / deny
│  │  Evaluator   │  │
│  └──────────────┘  │
│  ┌──────────────┐  │
│  │  Receipt     │──┼──▶ GovernanceReceipt
│  │  Generator   │  │    (tool, agent, policy, decision)
│  └──────────────┘  │
│  ┌──────────────┐  │
│  │  Ed25519     │──┼──▶ Signed receipt
│  │  Signer      │  │
│  └──────────────┘  │
│  ┌──────────────┐  │
│  │ ReceiptStore │──┼──▶ Audit trail
│  └──────────────┘  │
└────────────────────┘
```

## License

MIT — see [LICENSE](LICENSE).
