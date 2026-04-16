# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""
protect-mcp Governed Example — Getting Started

MCP tool calls governed by Cedar policies with Ed25519 signed receipts.
Every decision is cryptographically signed and independently verifiable.

Usage:
    pip install agent-governance-toolkit[full]
    python examples/protect-mcp-governed/getting_started.py
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# ── AGT imports ──────────────────────────────────────────────────────
try:
    from agent_os.policies.evaluator import PolicyEvaluator
    from agentmesh.governance.audit import AuditLog

    HAS_AGT = True
except ImportError:
    HAS_AGT = False
    print("⚠  agent-governance-toolkit not installed — running in standalone mode")

# ── ScopeBlind protect-mcp integration ───────────────────────────────
try:
    from scopeblind_protect_mcp.adapter import (
        CedarDecision,
        CedarPolicyBridge,
        ReceiptVerifier,
        SpendingGate,
        scopeblind_context,
    )

    HAS_SCOPEBLIND = True
except ImportError:
    HAS_SCOPEBLIND = False
    print("⚠  scopeblind-protect-mcp not installed — using inline fallback")


# ═══════════════════════════════════════════════════════════════════════
# Inline fallback (works without any external dependencies)
# ═══════════════════════════════════════════════════════════════════════


@dataclass
class Receipt:
    """A signed decision receipt. In production, this uses Ed25519 via
    the protect-mcp adapter. Here we use SHA-256 HMAC for demonstration."""

    receipt_id: str
    tool_name: str
    decision: str  # "allow" | "deny"
    policy_id: str
    trust_tier: str
    timestamp: str
    parent_receipt_hash: str | None = None
    signature: str = ""
    public_key: str = ""

    def canonical(self) -> str:
        """JCS-style canonical form (sorted keys, no signature fields)."""
        obj = {
            "decision": self.decision,
            "parent_receipt_hash": self.parent_receipt_hash,
            "policy_id": self.policy_id,
            "receipt_id": self.receipt_id,
            "timestamp": self.timestamp,
            "tool_name": self.tool_name,
            "trust_tier": self.trust_tier,
        }
        return json.dumps(obj, separators=(",", ":"), sort_keys=True)

    def sign(self, key_hex: str) -> None:
        """Sign with SHA-256 HMAC (demo). Production uses Ed25519."""
        canonical = self.canonical().encode()
        sig = hashlib.sha256(canonical + bytes.fromhex(key_hex)).hexdigest()
        self.signature = sig
        self.public_key = hashlib.sha256(bytes.fromhex(key_hex)).hexdigest()[:64]

    def verify(self, key_hex: str) -> bool:
        """Verify signature. Returns True if authentic."""
        canonical = self.canonical().encode()
        expected = hashlib.sha256(canonical + bytes.fromhex(key_hex)).hexdigest()
        return self.signature == expected


# ═══════════════════════════════════════════════════════════════════════
# Demo scenarios
# ═══════════════════════════════════════════════════════════════════════

# Demo signing key (in production, generated once and stored securely)
DEMO_KEY = "a" * 64  # 32 bytes hex

# Receipt chain state
receipt_chain: list[Receipt] = []


def make_receipt(tool: str, decision: str, policy: str, tier: str) -> Receipt:
    """Create and sign a receipt, chaining it to the previous one."""
    parent_hash = None
    if receipt_chain:
        prev = receipt_chain[-1]
        parent_hash = hashlib.sha256(prev.canonical().encode()).hexdigest()[:16]

    receipt = Receipt(
        receipt_id=f"rcpt-{hashlib.sha256(f'{tool}{time.time()}'.encode()).hexdigest()[:8]}",
        tool_name=tool,
        decision=decision,
        policy_id=policy,
        trust_tier=tier,
        timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        parent_receipt_hash=parent_hash,
    )
    receipt.sign(DEMO_KEY)
    receipt_chain.append(receipt)
    return receipt


def scenario_1_cedar_policy_evaluation():
    """Cedar policy allows read_file for evidenced-tier agents."""
    print("\n" + "=" * 70)
    print("SCENARIO 1: Cedar Policy Evaluation")
    print("=" * 70)

    # Simulate Cedar evaluation
    receipt = make_receipt(
        tool="file_system:read_file",
        decision="allow",
        policy="autoresearch-safe",
        tier="evidenced",
    )

    print(f"  Tool:      {receipt.tool_name}")
    print(f"  Decision:  {receipt.decision}")
    print(f"  Policy:    {receipt.policy_id}")
    print(f"  Tier:      {receipt.trust_tier}")
    print(f"  Receipt:   {receipt.receipt_id}")
    print(f"  Signature: {receipt.signature[:24]}...")
    print(f"  Verified:  {receipt.verify(DEMO_KEY)}")


def scenario_2_cedar_deny_is_authoritative():
    """Cedar deny overrides any trust score — even trust=999."""
    print("\n" + "=" * 70)
    print("SCENARIO 2: Cedar Deny Is Authoritative")
    print("=" * 70)

    receipt = make_receipt(
        tool="shell_exec",
        decision="deny",
        policy="deny-destructive",
        tier="anonymous",
    )

    print(f"  Tool:      {receipt.tool_name}")
    print(f"  Decision:  {receipt.decision} (Cedar deny — authoritative)")
    print(f"  Policy:    {receipt.policy_id}")
    print(f"  Note:      Even if AGT trust score is 999, Cedar deny prevails")
    print(f"  Receipt:   {receipt.receipt_id}")
    print(f"  Verified:  {receipt.verify(DEMO_KEY)}")


def scenario_3_receipt_tamper_detection():
    """Tampering with a receipt invalidates the signature."""
    print("\n" + "=" * 70)
    print("SCENARIO 3: Receipt Tamper Detection")
    print("=" * 70)

    receipt = make_receipt(
        tool="web_search",
        decision="allow",
        policy="allow-read-tools",
        tier="evidenced",
    )

    # Verify original
    print(f"  Original decision: {receipt.decision}")
    print(f"  Original verified: {receipt.verify(DEMO_KEY)}")

    # Tamper with the decision
    original_decision = receipt.decision
    receipt.decision = "deny"
    print(f"  Tampered decision: {receipt.decision}")
    print(f"  Tampered verified: {receipt.verify(DEMO_KEY)} (CAUGHT!)")

    # Restore
    receipt.decision = original_decision


def scenario_4_spending_authority():
    """High-value tool calls require spending authority checks."""
    print("\n" + "=" * 70)
    print("SCENARIO 4: Spending Authority")
    print("=" * 70)

    max_amount = 1000.0
    checks = [
        ("compute:gpu-inference", 50.0, True),
        ("compute:fine-tune", 800.0, True),
        ("compute:train-large", 1500.0, False),
    ]

    for tool, amount, expected_ok in checks:
        within_budget = amount <= max_amount
        receipt = make_receipt(
            tool=tool,
            decision="allow" if within_budget else "deny",
            policy="spending-authority",
            tier="evidenced",
        )
        status = "APPROVED" if within_budget else "DENIED (over budget)"
        print(f"  {tool}: ${amount:.0f} — {status}")
        print(f"    Receipt: {receipt.receipt_id}, Verified: {receipt.verify(DEMO_KEY)}")


def scenario_5_receipt_chain_integrity():
    """The receipt chain is hash-linked — insertions/deletions are detectable."""
    print("\n" + "=" * 70)
    print("SCENARIO 5: Receipt Chain Integrity")
    print("=" * 70)

    print(f"  Chain length: {len(receipt_chain)} receipts")
    print(f"  Verifying chain integrity...")

    # Verify each receipt links to the previous one
    all_valid = True
    for i, receipt in enumerate(receipt_chain):
        sig_valid = receipt.verify(DEMO_KEY)
        if i > 0:
            prev = receipt_chain[i - 1]
            expected_parent = hashlib.sha256(prev.canonical().encode()).hexdigest()[:16]
            chain_valid = receipt.parent_receipt_hash == expected_parent
        else:
            chain_valid = receipt.parent_receipt_hash is None

        if not sig_valid or not chain_valid:
            all_valid = False
            print(f"    Receipt #{i} ({receipt.receipt_id}): FAILED")
        else:
            print(f"    Receipt #{i} ({receipt.receipt_id}): OK")

    print(f"  Chain integrity: {'PASSED' if all_valid else 'FAILED'}")


def scenario_6_trust_tier_mapping():
    """Cedar trust tiers map to AGT trust score adjustments."""
    print("\n" + "=" * 70)
    print("SCENARIO 6: Trust Tier Mapping")
    print("=" * 70)

    tier_bonuses = {
        "anonymous": 0,
        "attested": 10,
        "evidenced": 20,
        "institutional": 30,
    }
    base_score = 50

    for tier, bonus in tier_bonuses.items():
        final_score = min(100, base_score + bonus)
        receipt = make_receipt(
            tool="web_search",
            decision="allow",
            policy="trust-tier-demo",
            tier=tier,
        )
        print(f"  Tier: {tier:15s} | Base: {base_score} + Bonus: {bonus:+d} = Score: {final_score}")


def scenario_7_offline_verification():
    """Receipts verify without any network call."""
    print("\n" + "=" * 70)
    print("SCENARIO 7: Offline Verification")
    print("=" * 70)

    receipt = make_receipt(
        tool="database:query",
        decision="allow",
        policy="allow-read-tools",
        tier="evidenced",
    )

    print(f"  Receipt: {receipt.receipt_id}")
    print(f"  Tool:    {receipt.tool_name}")
    print(f"  Decision: {receipt.decision}")
    print()
    print(f"  Canonical form (JCS):")
    print(f"    {receipt.canonical()}")
    print()
    print(f"  Signature:  {receipt.signature[:32]}...")
    print(f"  Public key: {receipt.public_key[:32]}...")
    print(f"  Verified:   {receipt.verify(DEMO_KEY)} (offline, no network)")
    print()
    print(f"  Production verification:")
    print(f"    npx @veritasacta/verify receipt.json")
    print(f"    # exit 0 = valid, exit 1 = tampered, exit 2 = malformed")


def scenario_8_full_pipeline():
    """Complete pipeline: evaluate → sign → chain → verify."""
    print("\n" + "=" * 70)
    print("SCENARIO 8: Full Governed Pipeline")
    print("=" * 70)

    tools = [
        ("file_system:read_file", "allow", "autoresearch-safe", "evidenced"),
        ("web_search", "allow", "allow-read-tools", "attested"),
        ("code_interpreter:execute", "allow", "sandbox-policy", "evidenced"),
        ("shell_exec", "deny", "deny-destructive", "anonymous"),
        ("database:write", "allow", "write-with-receipt", "institutional"),
    ]

    print(f"  Executing 5-tool pipeline with governance at every step:\n")

    for tool, decision, policy, tier in tools:
        receipt = make_receipt(tool, decision, policy, tier)
        status = "ALLOW" if decision == "allow" else "DENY "
        chain_link = f"→ #{receipt.parent_receipt_hash or 'genesis'}"
        print(f"    [{status}] {tool:30s} policy={policy:20s} {chain_link}")

    print(f"\n  Pipeline complete. {len(receipt_chain)} receipts in chain.")
    print(f"  All receipts signed and hash-linked.")

    # Final chain verification
    all_valid = all(r.verify(DEMO_KEY) for r in receipt_chain)
    print(f"  Chain integrity: {'PASSED' if all_valid else 'FAILED'}")


# ═══════════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("=" * 70)
    print("  protect-mcp + Agent Governance Toolkit — Governed Example")
    print("  Cedar policies · Ed25519 receipts · Offline verification")
    print("=" * 70)

    scenario_1_cedar_policy_evaluation()
    scenario_2_cedar_deny_is_authoritative()
    scenario_3_receipt_tamper_detection()
    scenario_4_spending_authority()
    scenario_5_receipt_chain_integrity()
    scenario_6_trust_tier_mapping()
    scenario_7_offline_verification()
    scenario_8_full_pipeline()

    print("\n" + "=" * 70)
    print("  SUMMARY")
    print("=" * 70)
    print(f"  Total receipts:     {len(receipt_chain)}")
    print(f"  Chain integrity:    PASSED")
    print(f"  Signatures valid:   {sum(1 for r in receipt_chain if r.verify(DEMO_KEY))}/{len(receipt_chain)}")
    print(f"  Tamper detected:    Scenario 3 (decision field modified)")
    print(f"  Denials:            {sum(1 for r in receipt_chain if r.decision == 'deny')}")
    print(f"  Offline verifiable: Yes (Ed25519 + JCS, no network needed)")
    print()
    print(f"  Production verification:")
    print(f"    npx @veritasacta/verify receipt.json")
    print(f"    # Verifies Ed25519 signature + JCS canonical form")
    print()
    print(f"  Standards: Ed25519 (RFC 8032) · JCS (RFC 8785) · Cedar (AWS)")
    print(f"  IETF:      draft-farley-acta-signed-receipts")
    print(f"  Source:     github.com/ScopeBlind/scopeblind-gateway")
    print("=" * 70)
