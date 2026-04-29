#!/usr/bin/env python3
# Copyright (c) lawcontinue. Licensed under the MIT License.
"""
Pipeline Governance — Demo

Demonstrates governance of multi-node distributed LLM inference with signed
receipts, Cedar policy evaluation, and cross-shard trust propagation.

Each pipeline step (shard loading, inference, cross-shard transfer) is:
1. **Policy-checked** against a Cedar policy (permit/forbid rules)
2. **Receipted** with a governance receipt linking decision to the action
3. **Signed** with Ed25519 for non-repudiation
4. **Hash-chained** so verifiers can detect insertion or deletion of steps

This is a runnable example for learning and prototyping. The inference itself
is mocked (no GPU required), but the governance flow follows real patterns from
distributed inference on Apple Silicon (Hippo Pipeline).

Usage:
    pip install -r requirements.txt
    python demo.py
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional

_logger = logging.getLogger(__name__)

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    from cryptography.exceptions import InvalidSignature

    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False
    print("⚠️  cryptography not installed — receipts will be unsigned")
    print("   Install with: pip install -r requirements.txt\n")


# ── Receipt Core ──────────────────────────────────────────────────────────


@dataclass
class GovernanceReceipt:
    """Signed proof of a governance decision for a pipeline step."""

    receipt_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    action: str = ""
    principal: str = ""
    cedar_decision: Literal["allow", "deny"] = "deny"
    args_hash: str = ""
    timestamp: float = field(default_factory=time.time)
    session_id: Optional[str] = None
    step_index: int = 0
    nonce: str = field(default_factory=lambda: uuid.uuid4().hex[:16])
    parent_receipt_hash: Optional[str] = None
    signature: Optional[str] = None
    signer_public_key: Optional[str] = None
    context: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None

    def canonical_payload(self) -> str:
        """RFC 8785 JCS canonical JSON (signature fields excluded).

        Includes a per-receipt nonce to prevent replay attacks: even if two
        receipts have identical action/principal/context, the nonce ensures
        a different payload hash.
        """
        data: Dict[str, Any] = {
            "action": self.action,
            "args_hash": self.args_hash,
            "cedar_decision": self.cedar_decision,
            "nonce": self.nonce,
            "principal": self.principal,
            "receipt_id": self.receipt_id,
            "session_id": self.session_id,
            "step_index": self.step_index,
            "timestamp": self.timestamp,
        }
        if self.parent_receipt_hash is not None:
            data["parent_receipt_hash"] = self.parent_receipt_hash
        return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

    def payload_hash(self) -> str:
        return hashlib.sha256(self.canonical_payload().encode()).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "action": self.action,
            "principal": self.principal,
            "cedar_decision": self.cedar_decision,
            "args_hash": self.args_hash,
            "step_index": self.step_index,
            "payload_hash": self.payload_hash(),
            "signature": self.signature,
        }


def sign_receipt(receipt: GovernanceReceipt, private_key: Ed25519PrivateKey) -> None:
    """Sign receipt payload with Ed25519 (fail-closed)."""
    payload_bytes = receipt.canonical_payload().encode()
    sig = private_key.sign(payload_bytes)
    receipt.signature = sig.hex()
    pub = private_key.public_key()
    receipt.signer_public_key = pub.public_bytes(
        encoding=Encoding.Raw,
        format=PublicFormat.Raw,
    ).hex()


def verify_receipt(receipt: GovernanceReceipt) -> bool:
    """Verify receipt signature offline.

    Only catches InvalidSignature — other errors (malformed key, hex decode
    failure) propagate so they can be diagnosed rather than silently returning False.
    """
    if not receipt.signature or not receipt.signer_public_key:
        return False
    try:
        pub_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(receipt.signer_public_key))
        pub_key.verify(bytes.fromhex(receipt.signature), receipt.canonical_payload().encode())
        return True
    except InvalidSignature:
        return False


# ── Cedar Policy Evaluator (inline, no external dependency) ───────────────


class CedarPolicyEvaluator:
    """Minimal Cedar policy evaluator with inline permit/forbid parsing."""

    def __init__(self, policy_content: str):
        self.policy_content = policy_content

    def evaluate(self, action: str, principal: str, context: Dict[str, Any]) -> bool:
        normalized = f'Action::"{action}"'

        # Check forbid rules first (highest priority)
        if self._matches_forbid(normalized, principal, context):
            return False

        # Check permit rules
        if self._matches_permit(normalized, principal, context):
            return True

        # Default deny
        return False

    def _matches_forbid(self, action: str, principal: str, context: Dict[str, Any]) -> bool:
        # Pattern: forbid(principal, action == Action::"X", resource) when { condition };
        pattern = r'forbid\s*\(.*?action\s*==\s*Action::"([^"]+)".*?\)\s*when\s*\{(.*?)\}\s*;'
        for m in re.finditer(pattern, self.policy_content, re.DOTALL):
            if f'Action::"{m.group(1)}"' == action:
                if self._eval_condition(m.group(2), principal, context):
                    return True

        # Pattern without when clause
        pattern_bare = r'forbid\s*\(.*?action\s*==\s*Action::"([^"]+)".*?\)\s*;'
        for m in re.finditer(pattern_bare, self.policy_content, re.DOTALL):
            if f'Action::"{m.group(1)}"' == action:
                # Check if this is a bare forbid (no when clause)
                block = m.group(0)
                if "when" not in block:
                    return True
        return False

    def _matches_permit(self, action: str, principal: str, context: Dict[str, Any]) -> bool:
        # Pattern with principal constraint + optional when clause
        pat_princ = r'permit\s*\(\s*principal\s*==\s*Rank::"([^"]+)"\s*,\s*action\s*==\s*Action::"([^"]+)"\s*,\s*resource\s*\)\s*(?:when\s*\{(.*?)\}\s*)?;'
        for m in re.finditer(pat_princ, self.policy_content, re.DOTALL):
            if f'Action::"{m.group(2)}"' == action:
                if principal != f'Rank::"{m.group(1)}"':
                    continue
                if m.group(3):
                    if not self._eval_condition(m.group(3), principal, context):
                        continue
                return True

        # Pattern without principal constraint (bare principal)
        pattern_bare = r'permit\s*\(\s*principal\s*,\s*action\s*==\s*Action::"([^"]+)"\s*,\s*resource\s*\)\s*(?:when\s*\{(.*?)\}\s*)?;'
        for m in re.finditer(pattern_bare, self.policy_content, re.DOTALL):
            if f'Action::"{m.group(1)}"' == action:
                if m.group(2):
                    if not self._eval_condition(m.group(2), principal, context):
                        continue
                return True
        return False

    def _eval_condition(self, cond: str, principal: str, context: Dict[str, Any]) -> bool:
        """Evaluate simple Cedar conditions: comparisons and 'in' operator."""
        cond = cond.strip()

        # Handle 'in' operator: context.model in ["a", "b"]
        m_in = re.search(r'context\.(\w+)\s+in\s+\[(.*?)\]', cond)
        if m_in:
            key = m_in.group(1)
            vals = [v.strip().strip('"') for v in m_in.group(2).split(",")]
            return str(context.get(key, "")) in vals

        # Handle comparison: context.x op context.y [/ N]
        m_ctx = re.search(r'context\.(\w+)\s*(==|!=|>=|<=|>|<)\s*context\.(\w+)(?:\s*/\s*(\d+))?', cond)
        if m_ctx:
            left_key = m_ctx.group(1)
            op = m_ctx.group(2)
            right_key = m_ctx.group(3)
            divisor = int(m_ctx.group(4)) if m_ctx.group(4) else 1
            left_val = context.get(left_key, 0)
            right_val = context.get(right_key, 0) / divisor
            if op == "==": return left_val == right_val
            elif op == "!=": return left_val != right_val
            elif op == ">=": return left_val >= right_val
            elif op == "<=": return left_val <= right_val
            elif op == ">": return left_val > right_val
            elif op == "<": return left_val < right_val

        # Handle comparison: context.x op literal_value
        m_eq = re.search(r'context\.(\w+)\s*(==|!=|>=|<=|>|<)\s*(true|false|\d+|"[^"]*")', cond)
        if m_eq:
            key = m_eq.group(1)
            op = m_eq.group(2)
            val_str = m_eq.group(3).strip('"')
            ctx_val = context.get(key)

            if val_str == "true":
                val = True
            elif val_str == "false":
                val = False
            else:
                try:
                    val = int(val_str)
                except ValueError:
                    val = val_str

            if op == "==": return ctx_val == val
            elif op == "!=": return ctx_val != val
            elif op == ">=": return ctx_val >= val
            elif op == "<=": return ctx_val <= val
            elif op == ">": return ctx_val > val
            elif op == "<": return ctx_val < val

        # Handle negation: !(context.x in [...])
        m_notin = re.search(r'!\s*\(?\s*context\.(\w+)\s+in\s+\[(.*?)\]', cond)
        if m_notin:
            key = m_notin.group(1)
            vals = [v.strip().strip('"') for v in m_notin.group(2).split(",")]
            return str(context.get(key, "")) not in vals

        # Handle principal check
        m_princ = re.search(r'principal\s*==\s*Rank::"([^"]+)"', cond)
        if m_princ:
            return principal == f'Rank::"{m_princ.group(1)}"'

        # Handle logical OR in principal checks
        m_or = re.search(r'principal\s*==\s*Rank::"([^"]+)".*\|\|.*principal\s*==\s*Rank::"([^"]+)"', cond)
        if m_or:
            return principal in [f'Rank::"{m_or.group(1)}"', f'Rank::"{m_or.group(2)}"']

        return True  # if no condition matched, default allow


# ── Pipeline Governance Adapter ───────────────────────────────────────────


class PipelineGovernanceAdapter:
    """Wraps distributed pipeline steps with Cedar policy and signed receipts."""

    def __init__(
        self,
        cedar_policy: str,
        signing_key: Optional[Ed25519PrivateKey] = None,
        session_id: Optional[str] = None,
    ):
        self._evaluator = CedarPolicyEvaluator(cedar_policy)
        self._signing_key = signing_key
        self._session_id = session_id or str(uuid.uuid4())
        self._step_index = 0
        self._last_receipt_hash: Optional[str] = None
        self.receipts: List[GovernanceReceipt] = []

    def govern_step(
        self,
        action: str,
        principal: str,
        args: Dict[str, Any],
        context: Dict[str, Any],
    ) -> GovernanceReceipt:
        """Evaluate Cedar policy for a pipeline step and produce a signed receipt.

        Args:
            action: The pipeline action (e.g. LoadShard, RunInference, CrossShardTransfer).
            principal: The agent identity (e.g. 'Rank::"r0"').
            args: Action arguments, hashed into the receipt for integrity.
            context: Cedar evaluation context (model, memory_budget, etc.).

        Returns:
            A GovernanceReceipt with the policy decision. If allowed and a signing
            key is configured, the receipt is Ed25519-signed and hash-chained to
            the previous receipt in the session.
        """
        args_hash = hashlib.sha256(json.dumps(args, sort_keys=True).encode()).hexdigest()
        decision = self._evaluator.evaluate(action, principal, context)
        cedar_decision = "allow" if decision else "deny"

        receipt = GovernanceReceipt(
            action=action,
            principal=principal,
            cedar_decision=cedar_decision,
            args_hash=args_hash,
            session_id=self._session_id,
            step_index=self._step_index,
            parent_receipt_hash=self._last_receipt_hash,
            context=context,
        )

        if self._signing_key and cedar_decision == "allow":
            sign_receipt(receipt, self._signing_key)

        self._last_receipt_hash = receipt.payload_hash()
        self._step_index += 1
        self.receipts.append(receipt)
        return receipt

    def verify_chain(self) -> bool:
        """Verify the entire receipt hash chain + signatures."""
        for i, receipt in enumerate(self.receipts):
            # Verify parent hash linkage
            if i > 0:
                expected_parent = self.receipts[i - 1].payload_hash()
                if receipt.parent_receipt_hash != expected_parent:
                    return False
            # Verify signature
            if receipt.signature and not verify_receipt(receipt):
                return False
        return True

    def get_stats(self) -> Dict[str, Any]:
        allowed = sum(1 for r in self.receipts if r.cedar_decision == "allow")
        denied = len(self.receipts) - allowed
        return {
            "total": len(self.receipts),
            "allowed": allowed,
            "denied": denied,
            "chain_valid": self.verify_chain(),
            "session_id": self._session_id,
        }


# ── Mock Pipeline ─────────────────────────────────────────────────────────


@dataclass
class PipelineShard:
    """Mock inference shard (represents one node in a multi-node pipeline)."""

    rank: int
    model: str
    shard_size_mb: int
    total_shards: int


def mock_inference_step(shard: PipelineShard, prompt_tokens: int) -> Dict[str, Any]:
    """Simulate a single inference step on a shard."""
    return {
        "rank": shard.rank,
        "model": shard.model,
        "tokens_processed": prompt_tokens,
        "latency_ms": 120 + (shard.rank * 15),  # mock latency
        "output_sample": "The governance of distributed systems requires...",
    }


# ── Main Demo ─────────────────────────────────────────────────────────────


def main() -> None:
    policy_path = Path(__file__).parent / "policies" / "pipeline-governance.cedar"
    cedar_policy = policy_path.read_text()

    # Generate signing key
    signing_key = None
    if HAS_CRYPTO:
        signing_key = Ed25519PrivateKey.generate()

    adapter = PipelineGovernanceAdapter(
        cedar_policy=cedar_policy,
        signing_key=signing_key,
        session_id=f"pipeline-session-{uuid.uuid4().hex[:8]}",
    )

    print("Pipeline Governance — Demo\n")
    print(f"Cedar policy: policies/pipeline-governance.cedar")
    print(f"Signing: {'Ed25519' if HAS_CRYPTO else 'disabled'}")
    print(f"Session: {adapter._session_id}\n")
    print("─" * 80)

    # ── Scenario 1: Legitimate distributed inference ──
    print("\n--- normal pipeline run ---\n")

    shard_r0 = PipelineShard(rank=0, model="gemma-3-12b-qat4", shard_size_mb=3460, total_shards=2)
    shard_r1 = PipelineShard(rank=0, model="gemma-3-12b-qat4", shard_size_mb=3460, total_shards=2)

    steps = [
        # R0 loads its shard
        ("LoadShard", 'Rank::"r0"', {"shard_index": 0}, {
            "shard_index": 0, "total_shards": 2,
            "shard_size_mb": 3460, "memory_budget_mb": 7400,
            "model": "gemma-3-12b-qat4",
        }),
        # R1 loads its shard
        ("LoadShard", 'Rank::"r1"', {"shard_index": 1}, {
            "shard_index": 1, "total_shards": 2,
            "shard_size_mb": 3460, "memory_budget_mb": 7400,
            "model": "gemma-3-12b-qat4",
        }),
        # R0 runs inference on approved model
        ("RunInference", 'Rank::"r0"', {"prompt": "Explain governance"}, {
            "model": "gemma-3-12b-qat4",
        }),
        # Cross-shard transfer with valid receipt
        ("CrossShardTransfer", 'Rank::"r0"', {"hidden_states": "..."}, {
            "has_valid_receipt": True,
        }),
        # R1 runs inference
        ("RunInference", 'Rank::"r1"', {"hidden_states": "..."}, {
            "model": "gemma-3-12b-qat4",
        }),
        # Write audit log
        ("WriteAudit", 'Rank::"r0"', {"audit_event": "pipeline_complete"}, {}),
    ]

    print(f"{'Step':<6} {'Action':<24} {'Principal':<14} {'Decision':<10} {'Signed':<8} {'Chain OK'}")
    print("─" * 80)

    for action, principal, args, context in steps:
        receipt = adapter.govern_step(action, principal, args, context)
        icon = "✅" if receipt.cedar_decision == "allow" else "🚫"
        signed = "yes" if receipt.signature else "no"
        chain_ok = adapter.verify_chain() if receipt.cedar_decision == "allow" else "—"
        principal_short = principal.split('"')[1] if '"' in principal else principal
        print(f"  {icon} {receipt.step_index:<4} {action:<24} {principal_short:<14} "
              f"{receipt.cedar_decision:<10} {signed:<8} {chain_ok}")

    # ── Scenario 2: Policy violations ──
    print("\n\n--- policy violations ---\n")

    violations = [
        # R0 tries to load a shard that exceeds memory budget
        ("LoadShard", 'Rank::"r0"', {"shard_index": 0}, {
            "shard_index": 0, "total_shards": 2,
            "shard_size_mb": 8000, "memory_budget_mb": 7400,  # exceeds budget
            "model": "gemma-3-12b-qat4",
        }),
        # Unauthorized rank tries to load (no matching permit rule)
        ("LoadShard", 'Rank::"r2"', {"shard_index": 0}, {
            "shard_index": 0, "total_shards": 2,
            "shard_size_mb": 2000, "memory_budget_mb": 7400,
            "model": "gemma-3-12b-qat4",
        }),
        # Run inference on unapproved model
        ("RunInference", 'Rank::"r0"', {"prompt": "Hello"}, {
            "model": "llama-4-maverick",  # not in approved list
        }),
        # Cross-shard transfer without receipt
        ("CrossShardTransfer", 'Rank::"r0"', {"hidden_states": "..."}, {
            "has_valid_receipt": False,  # missing receipt
        }),
        # R0 tries to load shard exceeding memory (different threshold)
        ("LoadShard", 'Rank::"r1"', {"shard_index": 0}, {
            "shard_index": 0, "total_shards": 2,
            "shard_size_mb": 9500, "memory_budget_mb": 7400,  # way over budget
            "model": "gemma-3-12b-qat4",
        }),
    ]

    print(f"{'Step':<6} {'Action':<24} {'Principal':<14} {'Decision':<10} {'Reason'}")
    print("─" * 80)

    for action, principal, args, context in violations:
        receipt = adapter.govern_step(action, principal, args, context)
        icon = "🚫" if receipt.cedar_decision == "deny" else "⚠️"
        principal_short = principal.split('"')[1] if '"' in principal else principal
        reason = _violation_reason(action, context)
        print(f"  {icon} {receipt.step_index:<4} {action:<24} {principal_short:<14} "
              f"{receipt.cedar_decision:<10} {reason}")

    # ── Summary ──
    stats = adapter.get_stats()
    print(f"\n{stats['allowed']} allowed, {stats['denied']} denied, chain_valid={stats['chain_valid']}")
    print(f"Session: {stats['session_id']}")

    # Show one receipt in full
    if adapter.receipts:
        print(f"\nSample receipt (first allowed):")
        for r in adapter.receipts:
            if r.cedar_decision == "allow":
                d = r.to_dict()
                for k, v in d.items():
                    if v is not None:
                        val = f"{v[:40]}..." if isinstance(v, str) and len(v) > 40 else v
                        print(f"   {k}: {val}")
                break

    print("\nDone. Each allowed step has a signed receipt linked to the previous one.")


def _violation_reason(action: str, context: Dict[str, Any]) -> str:
    """Generate human-readable reason for policy denial."""
    if action == "LoadShard" and context.get("shard_size_mb", 0) > context.get("memory_budget_mb", 0):
        return "shard_size exceeds memory_budget"
    if action == "RunInference" and context.get("model") not in ["gemma-3-12b-qat4", "qwen3-4b-bf16"]:
        return f"model '{context.get('model')}' not in approved list"
    if action == "CrossShardTransfer" and not context.get("has_valid_receipt"):
        return "missing valid receipt"
    return "no matching permit rule"


if __name__ == "__main__":
    main()
