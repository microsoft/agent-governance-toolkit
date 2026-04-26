# Copyright (c) 2026 Tom Farley (ScopeBlind).
# Licensed under the MIT License.
"""Governance skill for sb-runtime: policy evaluation + Ed25519-signed receipts."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Optional

import yaml

from sb_runtime_agentmesh.receipts import Signer, receipt_hash, sign_receipt


class SandboxBackend(str, Enum):
    """Sandbox layer that wraps the process sb-runtime governs.

    ``none``
        No sandbox wrapping. Only appropriate for test harnesses.
    ``sb_runtime_builtin``
        sb-runtime's own Landlock + seccomp (Ring 3). Suitable for
        single-binary deployments where sb-runtime owns the entire
        security boundary.
    ``nono``
        A nono capability set wraps the agent process, and sb-runtime
        runs in Ring 2 (policy + receipts only). Recommended for Linux
        operators who treat the sandbox layer as separate from the
        receipts layer. See docs/integrations/sb-runtime.md section
        "Composing sb-runtime with nono".
    ``openshell``
        OpenShell container wraps the agent process; sb-runtime runs
        in Ring 2. Recommended for container-based deployments.
    """

    NONE = "none"
    SB_RUNTIME_BUILTIN = "sb_runtime_builtin"
    NONO = "nono"
    OPENSHELL = "openshell"


@dataclass
class PolicyDecision:
    allowed: bool
    action: str
    reason: str
    policy_name: Optional[str] = None
    policy_digest: Optional[str] = None
    trust_score: float = 0.0
    ring: int = 2
    sandbox_backend: SandboxBackend = SandboxBackend.NONE
    receipt: Optional[dict] = None


@dataclass
class _PolicyRule:
    name: str
    field: str
    operator: str
    value: Any
    action: str
    priority: int = 0
    message: str = ""


@dataclass
class _PolicyDigestBundle:
    digest: str = ""
    ruleset: list[dict] = field(default_factory=list)


class GovernanceSkill:
    """Policy + receipts skill that mirrors the OpenShell skill contract.

    Accepts the same policy YAML shape as ``openshell_agentmesh``.
    Adds:

    - Ed25519-signed decision receipts (Veritas Acta format) attached
      to each ``PolicyDecision``.
    - Chain linkage via ``previousReceiptHash`` across successive
      decisions.
    - Sandbox-backend field recording which layer wrapped the process
      (``sb_runtime_builtin`` | ``nono`` | ``openshell`` | ``none``).
    """

    def __init__(
        self,
        policy_dir: Optional[Path] = None,
        trust_threshold: float = 0.5,
        signer: Optional[Signer] = None,
        sandbox_backend: SandboxBackend = SandboxBackend.SB_RUNTIME_BUILTIN,
        ring: int = 3,
        issuer_id: Optional[str] = None,
    ) -> None:
        self._rules: list[_PolicyRule] = []
        self._trust_scores: dict[str, float] = {}
        self._audit_log: list[dict] = []
        self._trust_threshold = trust_threshold
        self._policy_bundle = _PolicyDigestBundle()
        self._signer = signer or Signer.generate()
        self._sandbox_backend = SandboxBackend(sandbox_backend)
        self._ring = int(ring)
        self._issuer_id = issuer_id or f"sb:issuer:{self._signer.kid[:12]}"
        self._previous_receipt_hash: Optional[str] = None
        if policy_dir:
            self.load_policies(policy_dir)

    # ------------------------------------------------------------------
    # Policy loading
    # ------------------------------------------------------------------

    def load_policies(self, policy_dir: Path) -> int:
        policy_dir = Path(policy_dir)
        if not policy_dir.is_dir():
            raise FileNotFoundError(f"Policy directory not found: {policy_dir}")
        self._rules.clear()
        ruleset = []
        for yaml_file in sorted(policy_dir.glob("*.yaml")):
            with open(yaml_file, encoding="utf-8") as f:
                doc = yaml.safe_load(f)
            if not doc:
                continue
            for rd in doc.get("rules", []):
                cond = rd.get("condition", {})
                rule = _PolicyRule(
                    name=rd.get("name", yaml_file.stem),
                    field=cond.get("field", "action"),
                    operator=cond.get("operator", "equals"),
                    value=cond.get("value", ""),
                    action=rd.get("action", "deny"),
                    priority=rd.get("priority", 0),
                    message=rd.get("message", ""),
                )
                self._rules.append(rule)
                ruleset.append(
                    {
                        "name": rule.name,
                        "field": rule.field,
                        "operator": rule.operator,
                        "value": rule.value,
                        "action": rule.action,
                        "priority": rule.priority,
                    }
                )
        self._rules.sort(key=lambda r: r.priority, reverse=True)
        # Policy digest binds the entire active ruleset into receipts
        canonical_ruleset = sorted(
            ruleset,
            key=lambda r: (-int(r["priority"]), str(r["name"])),
        )
        digest_material = repr(canonical_ruleset).encode("utf-8")
        self._policy_bundle = _PolicyDigestBundle(
            digest="sha256:" + hashlib.sha256(digest_material).hexdigest(),
            ruleset=canonical_ruleset,
        )
        return len(self._rules)

    # ------------------------------------------------------------------
    # Policy evaluation + receipt signing
    # ------------------------------------------------------------------

    def check_policy(
        self,
        action: str,
        context: Optional[dict] = None,
        *,
        sign: bool = True,
    ) -> PolicyDecision:
        context = context or {}
        agent_did = context.get("agent_did", "unknown")
        trust = self.get_trust_score(agent_did)

        matched: Optional[_PolicyRule] = None
        for rule in self._rules:
            target = action if rule.field == "action" else context.get(rule.field, "")
            if self._match(rule.operator, target, rule.value):
                matched = rule
                break

        if matched is not None:
            allowed = matched.action == "allow"
            reason = matched.message or (
                ("Allowed" if allowed else "Denied") + " by rule: " + matched.name
            )
            decision_outcome = "allow" if allowed else "deny"
            policy_name = matched.name
        else:
            allowed = False
            reason = "No matching rule - default deny"
            decision_outcome = "deny"
            policy_name = None

        decision = PolicyDecision(
            allowed=allowed,
            action=action,
            reason=reason,
            policy_name=policy_name,
            policy_digest=self._policy_bundle.digest or None,
            trust_score=trust,
            ring=self._ring,
            sandbox_backend=self._sandbox_backend,
        )

        if sign:
            decision.receipt = self._sign_decision(
                decision=decision,
                agent_did=agent_did,
                decision_outcome=decision_outcome,
            )

        self.log_action(action, decision_outcome, agent_did, context)
        return decision

    def _sign_decision(
        self,
        decision: PolicyDecision,
        agent_did: str,
        decision_outcome: str,
    ) -> dict:
        payload = {
            "type": "sb-runtime:decision",
            "agent_id": agent_did,
            "action": decision.action,
            "decision": decision_outcome,
            "ring": decision.ring,
            "sandbox_backend": decision.sandbox_backend.value,
            "policy_id": decision.policy_name or "default_deny",
            "policy_digest": decision.policy_digest or "",
            "trust_score": round(decision.trust_score, 6),
            "issuer_id": self._issuer_id,
        }
        envelope = sign_receipt(
            payload=payload,
            signer=self._signer,
            previous_receipt_hash=self._previous_receipt_hash,
        )
        self._previous_receipt_hash = receipt_hash(envelope)
        return envelope

    # ------------------------------------------------------------------
    # Trust + audit
    # ------------------------------------------------------------------

    def get_trust_score(self, agent_did: str) -> float:
        return self._trust_scores.get(agent_did, 1.0)

    def adjust_trust(self, agent_did: str, delta: float) -> float:
        current = self.get_trust_score(agent_did)
        new_score = max(0.0, min(1.0, current + delta))
        self._trust_scores[agent_did] = new_score
        return new_score

    def log_action(
        self,
        action: str,
        decision: str,
        agent_did: str = "unknown",
        context: Optional[dict] = None,
    ) -> dict:
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "decision": decision,
            "agent_did": agent_did,
            "trust_score": self.get_trust_score(agent_did),
            "context": context or {},
        }
        self._audit_log.append(entry)
        return entry

    def get_audit_log(self, limit: int = 50) -> list[dict]:
        return self._audit_log[-limit:]

    # ------------------------------------------------------------------
    # Public accessors
    # ------------------------------------------------------------------

    @property
    def signer(self) -> Signer:
        return self._signer

    @property
    def policy_digest(self) -> str:
        return self._policy_bundle.digest

    @property
    def sandbox_backend(self) -> SandboxBackend:
        return self._sandbox_backend

    @property
    def ring(self) -> int:
        return self._ring

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _match(operator: str, target: Any, value: Any) -> bool:
        if operator == "equals":
            return target == value
        if operator == "starts_with":
            return isinstance(target, str) and target.startswith(str(value))
        if operator == "contains":
            return str(value) in str(target)
        if operator == "matches":
            return isinstance(target, str) and bool(re.search(str(value), target))
        if operator == "in":
            return target in (value if isinstance(value, list) else [value])
        return False
