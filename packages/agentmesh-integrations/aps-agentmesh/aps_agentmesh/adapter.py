"""
APS-AgentMesh Adapter — Bridge between APS structural authorization and AGT policy evaluation.

APS PolicyDecision artifacts become hard constraints in AGT's PolicyEngine.
APS passport grades become trust signals in AGT's TrustManager.
APS delegation scope chains become capability proofs.

Usage with AGT PolicyEngine:
    gate = APSPolicyGate()
    context = gate.inject(aps_decision_json, delegation_chain_json)
    # Pass to AGT: policy_engine.evaluate(context)

Usage for trust bridging:
    bridge = APSTrustBridge()
    trust_score = bridge.grade_to_score(passport_grade=2)  # → 700
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


# ── APS Passport Grade → AGT Trust Score mapping ──
# Grade 0 (self-signed):     → 100 (low trust, unverified)
# Grade 1 (issuer countersigned): → 400 (moderate, AEOESS processed)
# Grade 2 (runtime-bound):   → 700 (high, infrastructure-attested)
# Grade 3 (principal-bound): → 900 (very high, verified human/org)
GRADE_TO_TRUST_SCORE: Dict[int, int] = {
    0: 100,   # self-signed keypair only
    1: 400,   # issuer countersigned
    2: 700,   # runtime-bound (challenge-response + infrastructure attestation)
    3: 900,   # principal-bound (runtime + verified human/org)
}

GRADE_LABELS: Dict[int, str] = {
    0: "self_signed",
    1: "issuer_countersigned",
    2: "runtime_bound",
    3: "principal_bound",
}


@dataclass
class APSDecision:
    """Parsed APS PolicyDecision artifact."""

    verdict: str          # "permit" | "deny"
    scope_used: str
    agent_id: str
    delegation_id: Optional[str] = None
    spend_amount: Optional[float] = None
    constraint_failures: List[str] = field(default_factory=list)
    signature: Optional[str] = None
    signed_at: Optional[str] = None

    @classmethod
    def from_json(cls, raw: str | dict) -> "APSDecision":
        d = json.loads(raw) if isinstance(raw, str) else raw
        return cls(
            verdict=d.get("verdict", "deny"),
            scope_used=d.get("scopeUsed", d.get("scope_used", "")),
            agent_id=d.get("agentId", d.get("agent_id", "")),
            delegation_id=d.get("delegationId", d.get("delegation_id")),
            spend_amount=d.get("spend", {}).get("amount") if isinstance(d.get("spend"), dict) else None,
            constraint_failures=d.get("constraintFailures", d.get("constraint_failures", [])),
            signature=d.get("signature"),
            signed_at=d.get("signedAt", d.get("signed_at")),
        )

    @property
    def is_permit(self) -> bool:
        return self.verdict == "permit"


@dataclass
class APSScopeChain:
    """Parsed APS delegation scope chain."""

    scopes: List[str]
    delegator: str       # public key of delegator
    delegatee: str       # public key of delegatee
    depth: int
    max_depth: int
    spend_limit: Optional[float] = None
    spend_used: Optional[float] = None

    @classmethod
    def from_json(cls, raw: str | dict) -> "APSScopeChain":
        d = json.loads(raw) if isinstance(raw, str) else raw
        return cls(
            scopes=d.get("scope", d.get("scopes", [])),
            delegator=d.get("delegatedBy", d.get("delegator", "")),
            delegatee=d.get("delegatedTo", d.get("delegatee", "")),
            depth=d.get("currentDepth", d.get("depth", 0)),
            max_depth=d.get("maxDepth", d.get("max_depth", 3)),
            spend_limit=d.get("spendLimit", d.get("spend_limit")),
            spend_used=d.get("spentAmount", d.get("spend_used")),
        )

    def covers_scope(self, required: str) -> bool:
        """Check if delegation covers a required scope (prefix match)."""
        for s in self.scopes:
            if s == "*" or required == s or required.startswith(s + ":"):
                return True
        return False

    @property
    def spend_remaining(self) -> Optional[float]:
        if self.spend_limit is None:
            return None
        return self.spend_limit - (self.spend_used or 0)


def verify_aps_signature(payload: str, signature: str, public_key: str) -> bool:
    """
    Verify an Ed25519 signature from APS.

    Returns True if signature is valid. Requires PyNaCl.
    Install with: pip install PyNaCl
    In production, use the agent-passport-system Python SDK for full verification.
    """
    try:
        from nacl.signing import VerifyKey
        from nacl.exceptions import BadSignatureError
        vk = VerifyKey(bytes.fromhex(public_key))
        vk.verify(payload.encode(), bytes.fromhex(signature))
        return True
    except ImportError:
        # Fail closed: cannot verify without nacl
        return False
    except (BadSignatureError, Exception):
        return False


def aps_context(
    decision: APSDecision | dict | str,
    scope_chain: APSScopeChain | dict | str | None = None,
    passport_grade: int = 0,
) -> Dict[str, Any]:
    """
    Build an AGT-compatible context dict from APS artifacts.

    This is the primary bridge function. The returned dict can be passed
    directly to AGT's PolicyEngine.evaluate(action, context).

    Example AGT policy rule that consumes this:
        - name: require-aps-authorization
          conditions:
            aps_decision.verdict: 'permit'
          allowed_actions:
            - 'deploy.*'
    """
    dec = decision if isinstance(decision, APSDecision) else APSDecision.from_json(decision)

    if not isinstance(passport_grade, int) or passport_grade not in GRADE_TO_TRUST_SCORE:
        raise ValueError(f"Invalid passport_grade: {passport_grade}. Must be 0, 1, 2, or 3.")

    ctx: Dict[str, Any] = {
        "aps_decision": {
            "verdict": dec.verdict,
            "scope_used": dec.scope_used,
            "agent_id": dec.agent_id,
            "delegation_id": dec.delegation_id,
            "is_permit": dec.is_permit,
            "constraint_failures": dec.constraint_failures,
            "signed": dec.signature is not None,
        },
        "aps_passport_grade": passport_grade,
        "aps_trust_score": GRADE_TO_TRUST_SCORE.get(passport_grade, 100),
        "aps_grade_label": GRADE_LABELS.get(passport_grade, "unknown"),
    }

    if scope_chain is not None:
        sc = scope_chain if isinstance(scope_chain, APSScopeChain) else APSScopeChain.from_json(scope_chain)
        ctx["aps_scope_chain"] = {
            "scopes": sc.scopes,
            "delegator": sc.delegator,
            "delegatee": sc.delegatee,
            "depth": sc.depth,
            "max_depth": sc.max_depth,
            "spend_remaining": sc.spend_remaining,
        }

    return ctx


class APSPolicyGate:
    """
    Injects APS PolicyDecision into AGT's PolicyEngine evaluation context.

    APS structural authorization becomes a hard constraint (gate).
    AGT behavioral trust scoring remains a soft signal.

    Usage:
        gate = APSPolicyGate()
        ctx = gate.build_context(aps_decision, scope_chain, passport_grade=2)
        # Pass to AGT: policy_engine.evaluate('deploy.production', ctx)
    """

    def build_context(
        self,
        decision: APSDecision | dict | str,
        scope_chain: APSScopeChain | dict | str | None = None,
        passport_grade: int = 0,
    ) -> Dict[str, Any]:
        """Build AGT-compatible context from APS artifacts."""
        return aps_context(decision, scope_chain, passport_grade)

    def is_permitted(self, decision: APSDecision | dict | str) -> bool:
        """Quick check: does APS permit this action?"""
        dec = decision if isinstance(decision, APSDecision) else APSDecision.from_json(decision)
        return dec.is_permit


class APSTrustBridge:
    """
    Maps APS passport grades to AGT trust scores.

    Default mapping:
      Grade 0 (self-signed) → 100
      Grade 1 (issuer countersigned) → 400
      Grade 2 (runtime-bound) → 700
      Grade 3 (principal-bound) → 900

    Custom mappings can be provided.
    """

    def __init__(self, mapping: Optional[Dict[int, int]] = None):
        self._mapping = mapping or dict(GRADE_TO_TRUST_SCORE)

    def grade_to_score(self, passport_grade: int) -> int:
        """Convert APS passport grade to AGT trust score."""
        return self._mapping.get(passport_grade, 100)

    def meets_threshold(self, passport_grade: int, min_score: int) -> bool:
        """Check if passport grade meets a minimum trust score threshold."""
        return self.grade_to_score(passport_grade) >= min_score

    def grade_label(self, passport_grade: int) -> str:
        """Human-readable label for a passport grade."""
        return GRADE_LABELS.get(passport_grade, "unknown")


class APSScopeVerifier:
    """
    Validates APS delegation scope chains for AGT task assignment.

    Checks:
    - Does the delegation cover the required scope?
    - Is the delegation within depth limits?
    - Is there remaining spend budget?
    """

    def verify(
        self,
        scope_chain: APSScopeChain | dict | str,
        required_scope: str,
        required_spend: Optional[float] = None,
    ) -> tuple[bool, str]:
        """
        Verify a scope chain covers a required scope and budget.

        Returns (allowed, reason).
        """
        sc = scope_chain if isinstance(scope_chain, APSScopeChain) else APSScopeChain.from_json(scope_chain)

        if sc.depth > sc.max_depth:
            return False, f"Delegation depth {sc.depth} exceeds max {sc.max_depth}"

        if not sc.covers_scope(required_scope):
            return False, f"Scope '{required_scope}' not covered by delegation scopes {sc.scopes}"

        if required_spend is not None and sc.spend_remaining is not None:
            if required_spend > sc.spend_remaining:
                return False, f"Required spend {required_spend} exceeds remaining {sc.spend_remaining}"

        return True, "Scope and budget verified"
