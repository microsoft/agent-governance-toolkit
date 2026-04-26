# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
ScopeBlind protect-mcp adapter for AgentMesh.

protect-mcp operates at the MCP transport layer — it intercepts tool calls,
evaluates Cedar policies via WASM, and signs verifiable decision receipts
(Ed25519 + JCS canonicalization). This adapter bridges those runtime artifacts
into AGT's PolicyEngine interface.

Architecture:
  protect-mcp governs the **tool call boundary** (Cedar policy evaluation).
  AGT governs the **agent lifecycle** (trust scores, SLOs, circuit breakers).
  This adapter maps between the two so they compose rather than compete.

Key difference from mcp-trust-proxy:
  mcp-trust-proxy gates on trust scores (soft signals).
  protect-mcp gates on Cedar policies (formal, auditable, deterministic).
  Decision receipts provide cryptographic proof of what was decided and why.
"""

from __future__ import annotations

import hashlib
import json
import re
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set


# ---------------------------------------------------------------------------
# Cedar decision representation
# ---------------------------------------------------------------------------


@dataclass
class CedarDecision:
    """
    A Cedar policy evaluation result from protect-mcp.

    Cedar evaluates to allow or deny with an optional list of policy IDs
    that contributed to the decision. This is deterministic — the same
    policy set and context always produces the same decision.
    """

    effect: str  # "allow" or "deny"
    tool_name: str
    policy_ids: List[str] = field(default_factory=list)
    diagnostics: Dict[str, Any] = field(default_factory=dict)
    evaluated_at: float = field(default_factory=time.time)

    @property
    def allowed(self) -> bool:
        return self.effect == "allow"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "effect": self.effect,
            "tool": self.tool_name,
            "policy_ids": self.policy_ids,
            "diagnostics": self.diagnostics,
            "evaluated_at": self.evaluated_at,
        }

    @classmethod
    def from_receipt(cls, receipt: Dict[str, Any]) -> "CedarDecision":
        """Parse a CedarDecision from a protect-mcp receipt payload."""
        payload = receipt.get("payload", receipt)
        return cls(
            effect=payload.get("effect", payload.get("decision", "deny")),
            tool_name=payload.get("tool", payload.get("resource", "")),
            policy_ids=payload.get("policy_ids", []),
            diagnostics=payload.get("diagnostics", {}),
            evaluated_at=payload.get("timestamp", time.time()),
        )


# ---------------------------------------------------------------------------
# Cedar → AGT policy bridge
# ---------------------------------------------------------------------------


class CedarPolicyBridge:
    """
    Maps Cedar policy decisions into AGT's PolicyEngine evaluate() interface.

    Cedar is a formal policy language (open-sourced by AWS) that evaluates
    allow/deny decisions based on principal, action, resource, and context.
    protect-mcp uses Cedar WASM for sub-millisecond evaluation at the MCP
    transport layer.

    This bridge lets AGT consume Cedar decisions as hard constraints:
    - Cedar deny → AGT deny (non-negotiable)
    - Cedar allow → check AGT trust score (soft signal)

    This preserves Cedar's formal guarantees while layering AGT's
    behavioral trust on top.
    """

    MAX_HISTORY = 10000  # Prevent unbounded memory growth

    def __init__(
        self,
        trust_floor: int = 0,
        trust_bonus_per_allow: int = 50,
        deny_penalty: int = 200,
        require_receipt: bool = False,
        max_history: int = MAX_HISTORY,
    ):
        self.trust_floor = trust_floor
        self.trust_bonus = trust_bonus_per_allow
        self.deny_penalty = deny_penalty
        self.require_receipt = require_receipt
        self._max_history = max_history
        self._history: List[Dict[str, Any]] = []
        self._history_lock = threading.Lock()

    def evaluate(
        self,
        cedar_decision: CedarDecision,
        agent_trust_score: int = 0,
        agent_did: str = "",
        receipt: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Evaluate an MCP tool call through both Cedar and AGT lenses.

        Returns an AGT-compatible evaluation result with:
        - allowed: final decision (Cedar deny is always final)
        - cedar_effect: the Cedar decision
        - adjusted_trust: trust score after Cedar signal
        - reason: human-readable explanation
        """
        result: Dict[str, Any] = {
            "tool": cedar_decision.tool_name,
            "agent_did": agent_did,
            "cedar_effect": cedar_decision.effect,
            "policy_ids": cedar_decision.policy_ids,
            "timestamp": time.time(),
        }

        # Receipt required but not provided
        if self.require_receipt and receipt is None:
            result["allowed"] = False
            result["reason"] = "Decision receipt required but not provided"
            result["adjusted_trust"] = max(0, agent_trust_score - self.deny_penalty)
            self._record(result)
            return result

        # Cedar deny is authoritative — not overridable by trust score
        if not cedar_decision.allowed:
            result["allowed"] = False
            result["reason"] = (
                f"Cedar policy deny on '{cedar_decision.tool_name}' "
                f"(policies: {cedar_decision.policy_ids})"
            )
            result["adjusted_trust"] = max(0, agent_trust_score - self.deny_penalty)
            self._record(result)
            return result

        # Cedar allow — layer AGT trust check
        adjusted = min(1000, agent_trust_score + self.trust_bonus)
        if adjusted < self.trust_floor:
            result["allowed"] = False
            result["reason"] = (
                f"Cedar allowed but trust score {adjusted} below floor {self.trust_floor}"
            )
            result["adjusted_trust"] = adjusted
            self._record(result)
            return result

        result["allowed"] = True
        result["reason"] = "Cedar allow + trust check passed"
        result["adjusted_trust"] = adjusted

        if receipt:
            result["receipt_ref"] = hashlib.sha256(
                json.dumps(receipt, sort_keys=True).encode()
            ).hexdigest()

        with self._history_lock:
            self._history.append(result)
        return result

    def _record(self, entry: Dict[str, Any]) -> None:
        """Append to history with bounded size to prevent memory leaks."""
        with self._history_lock:
            self._history.append(entry)
            if len(self._history) > self._max_history:
                self._history = self._history[-self._max_history:]

    def get_history(self) -> List[Dict[str, Any]]:
        with self._history_lock:
            return list(self._history)

    def get_stats(self) -> Dict[str, Any]:
        with self._history_lock:
            total = len(self._history)
            allowed = sum(1 for r in self._history if r.get("allowed"))
            cedar_denies = sum(
                1 for r in self._history if r.get("cedar_effect") == "deny"
            )
        return {
            "total_evaluations": total,
            "allowed": allowed,
            "denied": total - allowed,
            "cedar_denies": cedar_denies,
            "trust_denies": total - allowed - cedar_denies,
        }


# ---------------------------------------------------------------------------
# Receipt verification
# ---------------------------------------------------------------------------


class ReceiptVerifier:
    """
    Validates protect-mcp decision receipts.

    Receipts are Ed25519-signed JSON envelopes following the Veritas Acta
    artifact format (JCS canonicalization). Each receipt proves:
    - What tool call was evaluated
    - What Cedar policies applied
    - What the decision was (allow/deny)
    - When it happened
    - Who signed it (tenant public key)

    Crucially, receipts are **issuer-blind** — the verifier can confirm
    validity without learning which organization issued the receipt.
    This prevents supply-chain surveillance.

    This class validates receipt structure and extracts AGT-compatible
    metadata. Cryptographic verification (Ed25519 signature check)
    is delegated to @veritasacta/verify or the protect-mcp runtime.
    """

    REQUIRED_FIELDS = {"type", "payload", "signature", "publicKey"}
    VALID_TYPES = {
        "scopeblind:decision",
        "scopeblind:spending_authority",
        "scopeblind:policy_evaluation",
        "acta:artifact",
    }

    MAX_LOG = 10000  # Prevent unbounded memory growth
    MAX_SEEN_RECEIPTS = 50000  # Replay protection window

    # Ed25519 public key: 64 hex chars (32 bytes)
    _ED25519_PK_PATTERN = re.compile(r"^[0-9a-fA-F]{64}$")
    # Also accept base64url-encoded keys (43-44 chars)
    _ED25519_PK_B64_PATTERN = re.compile(r"^[A-Za-z0-9_-]{43,44}=?$")

    def __init__(
        self,
        strict: bool = True,
        max_log: int = MAX_LOG,
        replay_protection: bool = True,
        max_seen_receipts: int = MAX_SEEN_RECEIPTS,
    ):
        self.strict = strict
        self.replay_protection = replay_protection
        self._max_log = max_log
        self._max_seen = max_seen_receipts
        self._verified: List[Dict[str, Any]] = []
        self._verified_lock = threading.Lock()
        # Replay protection: bounded ordered set of seen receipt hashes
        self._seen_receipts: OrderedDict[str, None] = OrderedDict()
        self._seen_lock = threading.Lock()

    def validate_structure_only(self, receipt: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate receipt structure only — no cryptographic verification.

        Cryptographic signature verification (Ed25519) is delegated to
        @veritasacta/verify or the protect-mcp runtime. This method only
        checks that required fields are present and the receipt type is
        recognized.

        Returns a result dict with:
        - valid: bool
        - receipt_type: str
        - tool: str (extracted from payload)
        - decision: str (allow/deny)
        - reason: str (if invalid)
        """
        # Check required fields
        missing = self.REQUIRED_FIELDS - set(receipt.keys())
        if missing:
            return {
                "valid": False,
                "reason": f"Missing required fields: {sorted(missing)}",
            }

        receipt_type = receipt.get("type", "")
        if self.strict and receipt_type not in self.VALID_TYPES:
            return {
                "valid": False,
                "reason": f"Unknown receipt type: {receipt_type}",
                "receipt_type": receipt_type,
            }

        payload = receipt.get("payload", {})
        if not isinstance(payload, dict):
            return {"valid": False, "reason": "Payload must be an object"}

        # Empty signature/publicKey should not pass as valid
        sig = receipt.get("signature", "")
        pk = receipt.get("publicKey", "")
        if not sig or not pk:
            return {
                "valid": False,
                "reason": "Empty signature or publicKey (cryptographic fields must be non-empty)",
                "receipt_type": receipt_type,
                "has_signature": bool(sig),
                "has_public_key": bool(pk),
            }

        # Validate Ed25519 public key format (32 bytes = 64 hex chars, or base64url)
        if not (self._ED25519_PK_PATTERN.match(pk) or self._ED25519_PK_B64_PATTERN.match(pk)):
            return {
                "valid": False,
                "reason": (
                    f"Invalid publicKey format: expected 64 hex chars (Ed25519) "
                    f"or base64url, got {len(pk)} chars"
                ),
                "receipt_type": receipt_type,
                "has_signature": True,
                "has_public_key": True,
            }

        # Replay protection: reject previously seen receipts
        if self.replay_protection:
            receipt_hash = hashlib.sha256(
                json.dumps(receipt, sort_keys=True).encode()
            ).hexdigest()
            with self._seen_lock:
                if receipt_hash in self._seen_receipts:
                    return {
                        "valid": False,
                        "reason": "Replay detected: this receipt has already been validated",
                        "receipt_type": receipt_type,
                        "replay": True,
                    }
                self._seen_receipts[receipt_hash] = None
                # Evict oldest entries when the window is full
                while len(self._seen_receipts) > self._max_seen:
                    self._seen_receipts.popitem(last=False)

        result = {
            "valid": True,
            "receipt_type": receipt_type,
            "tool": payload.get("tool", payload.get("resource", "")),
            "decision": payload.get("effect", payload.get("decision", "")),
            "timestamp": payload.get("timestamp"),
            "has_signature": True,
            "has_public_key": True,
        }

        # Spending authority specific fields
        if receipt_type == "scopeblind:spending_authority":
            result["amount"] = payload.get("amount")
            result["currency"] = payload.get("currency", "USD")
            result["utilization_band"] = payload.get("utilization_band")
            result["category"] = payload.get("category")

        with self._verified_lock:
            self._verified.append(result)
            if len(self._verified) > self._max_log:
                self._verified = self._verified[-self._max_log:]
        return result

    def to_agt_context(self, receipt: Dict[str, Any]) -> Dict[str, Any]:
        """Convert a validated receipt to AGT-compatible context."""
        validation = self.validate_structure_only(receipt)
        if not validation.get("valid"):
            return {"receipt_valid": False, "reason": validation.get("reason", "")}

        payload = receipt.get("payload", {})
        return {
            "receipt_valid": True,
            "receipt_type": validation["receipt_type"],
            "cedar_effect": validation.get("decision", ""),
            "tool": validation.get("tool", ""),
            "timestamp": validation.get("timestamp"),
            "receipt_ref": hashlib.sha256(
                json.dumps(receipt, sort_keys=True).encode()
            ).hexdigest(),
            "issuer_blind": True,  # protect-mcp receipts are always issuer-blind
            "payload_fields": sorted(payload.keys()),
        }

    def get_verification_log(self) -> List[Dict[str, Any]]:
        with self._verified_lock:
            return list(self._verified)


# ---------------------------------------------------------------------------
# Spending authority gate
# ---------------------------------------------------------------------------


class SpendingGate:
    """
    Enforces spending authority for agent financial operations.

    protect-mcp's spending authority system uses VOPRF (RFC 9497) to
    produce issuer-blind spending receipts. The receipt proves:
    - The spend is within authorized limits
    - The category is permitted
    - The utilization band (low/medium/high — not exact budget)

    What it does NOT reveal (by design):
    - Organization name or identity
    - Total budget ceiling
    - Exact remaining budget
    - Agent identity or delegation chain

    This gate integrates with AGT to add trust-score gating on top of
    the cryptographic spending proof.
    """

    UTILIZATION_BANDS = {"low", "medium", "high", "exceeded"}

    MAX_LOG = 10000  # Prevent unbounded memory growth

    def __init__(
        self,
        max_single_amount: float = 10000.0,
        high_util_trust_floor: int = 500,
        blocked_categories: Optional[List[str]] = None,
        max_log: int = MAX_LOG,
    ):
        self.max_single_amount = max_single_amount
        self.high_util_trust_floor = high_util_trust_floor
        self.blocked_categories = set(blocked_categories or [])
        self._max_log = max_log
        self._decisions: List[Dict[str, Any]] = []
        self._decisions_lock = threading.Lock()

    def evaluate_spend(
        self,
        amount: float,
        currency: str = "USD",
        category: str = "general",
        utilization_band: str = "low",
        agent_trust_score: int = 0,
        agent_did: str = "",
        receipt: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Evaluate a spending request through both spending authority and AGT trust.

        Checks (in order):
        1. Amount within single-transaction limit
        2. Category not blocked
        3. Utilization band + trust score check
        4. Receipt present (if high-value)
        """
        result: Dict[str, Any] = {
            "amount": amount,
            "currency": currency,
            "category": category,
            "utilization_band": utilization_band,
            "agent_did": agent_did,
            "agent_trust_score": agent_trust_score,
            "timestamp": time.time(),
        }

        # 1. Amount limit
        if amount > self.max_single_amount:
            result["allowed"] = False
            result["reason"] = (
                f"Amount {amount} {currency} exceeds single-transaction "
                f"limit of {self.max_single_amount} {currency}"
            )
            self._record(result)
            return result

        if amount <= 0:
            result["allowed"] = False
            result["reason"] = "Amount must be positive"
            self._record(result)
            return result

        # 2. Category check
        if category in self.blocked_categories:
            result["allowed"] = False
            result["reason"] = f"Category '{category}' is blocked"
            self._record(result)
            return result

        # 3. Utilization + trust
        if utilization_band not in self.UTILIZATION_BANDS:
            result["allowed"] = False
            result["reason"] = f"Invalid utilization band: {utilization_band}"
            self._record(result)
            return result

        if utilization_band == "exceeded":
            result["allowed"] = False
            result["reason"] = "Budget utilization exceeded"
            self._record(result)
            return result

        if utilization_band == "high" and agent_trust_score < self.high_util_trust_floor:
            result["allowed"] = False
            result["reason"] = (
                f"High utilization requires trust score >= {self.high_util_trust_floor} "
                f"(current: {agent_trust_score})"
            )
            self._record(result)
            return result

        # 4. Receipt check for high-value transactions
        if amount > 1000 and receipt is None:
            result["allowed"] = False
            result["reason"] = (
                f"Transactions above 1000 {currency} require a spending authority receipt"
            )
            self._record(result)
            return result

        result["allowed"] = True
        result["reason"] = "Spending authorized"
        if receipt:
            result["receipt_ref"] = hashlib.sha256(
                json.dumps(receipt, sort_keys=True).encode()
            ).hexdigest()

        with self._decisions_lock:
            self._decisions.append(result)
        return result

    def _record(self, entry: Dict[str, Any]) -> None:
        """Append to decisions with bounded size to prevent memory leaks."""
        with self._decisions_lock:
            self._decisions.append(entry)
            if len(self._decisions) > self._max_log:
                self._decisions = self._decisions[-self._max_log:]

    def get_decisions(self) -> List[Dict[str, Any]]:
        with self._decisions_lock:
            return list(self._decisions)

    def get_stats(self) -> Dict[str, Any]:
        with self._decisions_lock:
            total = len(self._decisions)
            allowed = sum(1 for d in self._decisions if d.get("allowed"))
            total_amount = sum(d.get("amount", 0) for d in self._decisions if d.get("allowed"))
        return {
            "total_requests": total,
            "allowed": allowed,
            "denied": total - allowed,
            "total_authorized_amount": total_amount,
            "blocked_categories": sorted(self.blocked_categories),
        }


# ---------------------------------------------------------------------------
# AGT context builder
# ---------------------------------------------------------------------------


def scopeblind_context(
    cedar_decision: Optional[CedarDecision] = None,
    receipt: Optional[Dict[str, Any]] = None,
    spend_amount: Optional[float] = None,
    spend_category: Optional[str] = None,
    utilization_band: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Build an AGT-compatible context dict from protect-mcp artifacts.

    This context can be passed to AGT's PolicyEngine.evaluate() to
    incorporate protect-mcp signals into governance decisions.

    Example:
        ctx = scopeblind_context(
            cedar_decision=decision,
            receipt=receipt,
            spend_amount=99.50,
        )
        agt_result = policy_engine.evaluate(action="purchase", context=ctx)
    """
    ctx: Dict[str, Any] = {
        "source": "scopeblind:protect-mcp",
        "version": "0.5.2",
    }

    if cedar_decision is not None:
        ctx["cedar"] = {
            "effect": cedar_decision.effect,
            "tool": cedar_decision.tool_name,
            "policy_ids": cedar_decision.policy_ids,
        }

    if receipt is not None:
        ctx["receipt"] = {
            "present": True,
            "type": receipt.get("type", ""),
            "has_signature": bool(receipt.get("signature")),
            "issuer_blind": True,
        }
        payload = receipt.get("payload", {})
        if payload:
            ctx["receipt"]["tool"] = payload.get("tool", payload.get("resource", ""))
            ctx["receipt"]["decision"] = payload.get("effect", payload.get("decision", ""))
    else:
        ctx["receipt"] = {"present": False}

    if spend_amount is not None:
        ctx["spending"] = {
            "amount": spend_amount,
            "category": spend_category or "general",
            "utilization_band": utilization_band or "unknown",
        }

    return ctx
