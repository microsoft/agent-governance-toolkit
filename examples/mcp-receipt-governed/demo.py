#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
MCP Receipt Governed — Demo

Demonstrates MCP tool calls producing signed governance receipts with Cedar
policy decisions. Each tool invocation is policy-checked and recorded in a
verifiable audit trail.

Usage:
    pip install -e "agent-governance-python/agentmesh-integrations/mcp-receipt-governed[crypto]"
    python examples/mcp-receipt-governed/demo.py
"""

from pathlib import Path

from mcp_receipt_governed import McpReceiptAdapter, verify_receipt


def main() -> None:
    # Load Cedar policy
    policy_path = Path(__file__).parent / "policies" / "mcp-tools.cedar"
    cedar_policy = policy_path.read_text()

    # Generate a signing key (in production, use a persistent key from a vault)
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        key = Ed25519PrivateKey.generate()
        signing_key = key.private_bytes_raw().hex()
        has_crypto = True
    except ImportError:
        signing_key = None
        has_crypto = False
        print("⚠️  cryptography not installed — receipts will be unsigned")
        print("   Install with: pip install cryptography\n")

    # Create the adapter
    adapter = McpReceiptAdapter(
        cedar_policy=cedar_policy,
        cedar_policy_id="policy:mcp-tools:v1",
        signing_key_hex=signing_key,
    )

    print("🛡️  MCP Receipt Governed — Demo\n")
    print("Cedar policy loaded from: policies/mcp-tools.cedar")
    print(f"Signing: {'Ed25519' if has_crypto else 'disabled'}\n")
    print("─" * 60)

    # Simulate MCP tool calls from two agents
    tool_calls = [
        ("did:mesh:researcher", "ReadData", {"path": "/data/report.csv"}),
        ("did:mesh:researcher", "ListFiles", {"directory": "/data/"}),
        ("did:mesh:researcher", "SearchData", {"query": "revenue Q4"}),
        ("did:mesh:analyst", "ReadData", {"path": "/data/metrics.json"}),
        ("did:mesh:analyst", "DeleteFile", {"path": "/data/secrets.key"}),
        ("did:mesh:analyst", "DropTable", {"table": "user_accounts"}),
        ("did:mesh:researcher", "SendEmail", {"to": "external@corp.com"}),
    ]

    print(f"\n{'Agent':<24} {'Tool':<16} {'Decision':<10} {'Signed':<8} {'Verified'}")
    print("─" * 60)

    for agent_did, tool_name, tool_args in tool_calls:
        receipt = adapter.govern_tool_call(
            agent_did=agent_did,
            tool_name=tool_name,
            tool_args=tool_args,
        )

        icon = "✅" if receipt.cedar_decision == "allow" else "🚫"
        signed = "yes" if receipt.signature else "no"
        verified = verify_receipt(receipt) if receipt.signature else "n/a"

        agent_short = agent_did.split(":")[-1]
        print(
            f"  {icon} {agent_short:<20} {tool_name:<16} "
            f"{receipt.cedar_decision:<10} {signed:<8} {verified}"
        )

    # Print statistics
    stats = adapter.get_stats()
    print("\n" + "─" * 60)
    print(f"\n📊 Audit Summary:")
    print(f"   Total receipts:  {stats['total']}")
    print(f"   Allowed:         {stats['allowed']}")
    print(f"   Denied:          {stats['denied']}")
    print(f"   Unique agents:   {stats['unique_agents']}")
    print(f"   Unique tools:    {stats['unique_tools']}")

    # Show one receipt in full
    receipts = adapter.get_receipts()
    if receipts:
        print(f"\n📜 Sample Receipt (first allowed):")
        for r in receipts:
            if r.cedar_decision == "allow":
                d = r.to_dict()
                for k, v in d.items():
                    if v is not None:
                        val = f"{v[:32]}..." if isinstance(v, str) and len(v) > 32 else v
                        print(f"   {k}: {val}")
                break

    print("\n✨ Done! Every tool call has a signed governance receipt.")
    print("\nNext steps:")
    print("  📚 Cedar policies:     docs/tutorials/01-policy-engine.md")
    print("  🔐 Agent identity:     docs/tutorials/02-trust-and-identity.md")
    print("  🌐 MCP trust proxy:    agent-governance-python/agentmesh-integrations/mcp-trust-proxy/")


if __name__ == "__main__":
    main()
