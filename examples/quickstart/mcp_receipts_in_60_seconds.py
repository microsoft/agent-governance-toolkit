#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""MCP tool-call receipt signing in 60 seconds.

Every MCP tool call produces a signed governance receipt linking the
Cedar policy decision to the invocation — a verifiable audit trail.

Usage:
    pip install -e "agent-governance-python/agentmesh-integrations/mcp-receipt-governed[crypto]"
    python examples/quickstart/mcp_receipts_in_60_seconds.py
"""

from mcp_receipt_governed import McpReceiptAdapter, verify_receipt

# 1. Define a Cedar policy — permit reads, deny deletes
adapter = McpReceiptAdapter(
    cedar_policy="""
        permit(principal, action == Action::"ReadData", resource);
        permit(principal, action == Action::"ListFiles", resource);
        forbid(principal, action == Action::"DeleteFile", resource);
    """,
    cedar_policy_id="policy:mcp-tools:v1",
)

# 2. Govern tool calls — each produces a receipt
print("\n🛡️  MCP Receipt Signing in 60 Seconds\n")
print("Governing tool calls against Cedar policy:\n")

tools = [
    ("ReadData", {"path": "/data/report.csv"}),
    ("ListFiles", {"dir": "/data/"}),
    ("DeleteFile", {"path": "/data/secrets.key"}),
]

for tool_name, args in tools:
    receipt = adapter.govern_tool_call(
        agent_did="did:mesh:my-agent",
        tool_name=tool_name,
        tool_args=args,
    )
    icon = "✅" if receipt.cedar_decision == "allow" else "🚫"
    print(f"  {icon} {tool_name}: {receipt.cedar_decision} (receipt: {receipt.receipt_id[:8]}...)")

# 3. Check the audit trail
stats = adapter.get_stats()
print(f"\n📊 Receipts: {stats['total']} total, {stats['allowed']} allowed, {stats['denied']} denied")

print("\n✨ Done! Every tool call has a governance receipt.")
print("\nNext steps:")
print("  🔐 Add Ed25519 signing:  pip install mcp_receipt_governed[crypto]")
print("  📜 Full demo:            python examples/mcp-receipt-governed/demo.py")
print("  📚 Cedar policies:       docs/tutorials/01-policy-engine.md")
