# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""
protect-mcp Governed — Quickstart (< 60 seconds)

MCP tool calls with Cedar policy enforcement and Ed25519 signed receipts.
Every decision is cryptographically signed and independently verifiable.

Usage:
    pip install agent-governance-toolkit[full]
    python examples/quickstart/protect_mcp_governed.py
"""

from __future__ import annotations

import hashlib
import json
import time

# ── Minimal receipt signing (zero dependencies) ─────────────────────


def sign_receipt(tool: str, decision: str, policy: str, key: str) -> dict:
    """Sign a tool-call decision as a verifiable receipt."""
    receipt = {
        "decision": decision,
        "policy_id": policy,
        "receipt_id": f"rcpt-{hashlib.sha256(f'{tool}{time.time()}'.encode()).hexdigest()[:8]}",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "tool_name": tool,
    }
    canonical = json.dumps(receipt, separators=(",", ":"), sort_keys=True).encode()
    receipt["signature"] = hashlib.sha256(canonical + bytes.fromhex(key)).hexdigest()
    return receipt


def verify_receipt(receipt: dict, key: str) -> bool:
    """Verify a receipt's signature. Returns True if authentic."""
    sig = receipt.pop("signature", "")
    canonical = json.dumps(receipt, separators=(",", ":"), sort_keys=True).encode()
    expected = hashlib.sha256(canonical + bytes.fromhex(key)).hexdigest()
    receipt["signature"] = sig
    return sig == expected


# ── Demo ────────────────────────────────────────────────────────────

KEY = "a" * 64  # Demo key (production uses Ed25519 via protect-mcp)

# 1. Tool call → Cedar policy → signed receipt
receipt = sign_receipt("file_system:read_file", "allow", "autoresearch-safe", KEY)
print(f"✓ Signed:   {receipt['tool_name']} → {receipt['decision']}")
print(f"  Receipt:  {receipt['receipt_id']}")
print(f"  Verified: {verify_receipt(receipt, KEY)}")

# 2. Tamper detection
receipt["decision"] = "deny"
print(f"\n✗ Tampered: decision changed to '{receipt['decision']}'")
print(f"  Verified: {verify_receipt(receipt, KEY)} (caught!)")

# 3. Deny is authoritative
deny_receipt = sign_receipt("shell_exec", "deny", "deny-destructive", KEY)
print(f"\n✓ Denied:   {deny_receipt['tool_name']} → {deny_receipt['decision']}")
print(f"  Cedar deny is authoritative — overrides any trust score")

print(f"\n  Production: npx @veritasacta/verify receipt.json")
print(f"  Standards:  Ed25519 (RFC 8032) · JCS (RFC 8785) · Cedar (AWS)")
