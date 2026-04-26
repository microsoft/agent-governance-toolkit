# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Unified AgentMesh Client

Orchestrates identity, policy, trust scoring, and audit logging into a
single governance pipeline.  Mirrors the unified client available in the
TypeScript, Go, Rust, and C# SDKs.
"""

from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, Field

from agentmesh.constants import TRUST_SCORE_DEFAULT, TRUST_SCORE_MAX
from agentmesh.governance.audit import AuditLog
from agentmesh.governance.policy import PolicyEngine
from agentmesh.identity.agent_id import AgentIdentity
from agentmesh.reward.scoring import TrustScore

# Default policy that allows all actions when no explicit policy is provided.
_DEFAULT_ALLOW_POLICY = """\
apiVersion: governance.toolkit/v1
name: __agentmesh_default_allow
agents:
  - "*"
rules: []
default_action: allow
"""


class GovernanceResult(BaseModel):
    """Result of executing an action through the governance pipeline."""

    decision: str = Field(
        ..., description="Policy decision: allow, deny, warn, or require_approval"
    )
    trust_score: float = Field(..., description="Current trust score (0-1000)")
    audit_entry: Any = Field(default=None, description="Associated audit entry")
    allowed: bool = Field(..., description="Whether the action was ultimately allowed")


class AgentMeshClient:
    """Unified governance client combining identity, policy, trust, and audit.

    Provides a single ``execute_with_governance`` method that runs every
    action through the full governance pipeline:

    1. Policy evaluation
    2. Audit logging
    3. Trust score update
    """

    def __init__(
        self,
        agent_id: str,
        *,
        capabilities: Optional[list[str]] = None,
        policy_yaml: Optional[str] = None,
        trust_config: Optional[dict] = None,
    ) -> None:
        # Create identity
        self._identity = AgentIdentity.create(
            name=agent_id,
            sponsor=f"{agent_id}@agentmesh.dev",
            capabilities=capabilities or [],
        )
        self._agent_did = str(self._identity.did)

        # Policy engine — load an explicit allow-all baseline so the
        # fail-closed engine doesn't deny everything when the caller
        # provides no policies.
        self._policy_engine = PolicyEngine()
        if policy_yaml:
            self._policy_engine.load_yaml(policy_yaml)
        else:
            self._policy_engine.load_yaml(_DEFAULT_ALLOW_POLICY)

        # Audit log
        self._audit_log = AuditLog()

        # Trust score
        initial_score = (
            trust_config.get("initial_score", TRUST_SCORE_DEFAULT)
            if trust_config
            else TRUST_SCORE_DEFAULT
        )
        self._trust_score = TrustScore(
            agent_did=self._agent_did,
            total_score=initial_score,
        )

        # Trust adjustment deltas
        self._success_delta = (
            trust_config.get("success_delta", 10) if trust_config else 10
        )
        self._failure_delta = (
            trust_config.get("failure_delta", -20) if trust_config else -20
        )

    # ── Public helpers ────────────────────────────────────────

    @property
    def identity(self) -> AgentIdentity:
        """The agent's identity."""
        return self._identity

    @property
    def agent_did(self) -> str:
        """The agent's decentralised identifier."""
        return self._agent_did

    @property
    def policy_engine(self) -> PolicyEngine:
        """The underlying policy engine."""
        return self._policy_engine

    @property
    def audit_log(self) -> AuditLog:
        """The underlying audit log."""
        return self._audit_log

    @property
    def trust_score(self) -> TrustScore:
        """Current trust score snapshot."""
        return self._trust_score

    # ── Core pipeline ─────────────────────────────────────────

    def execute_with_governance(
        self,
        action: str,
        context: Optional[dict] = None,
    ) -> GovernanceResult:
        """Run *action* through the full governance pipeline.

        Steps:
            1. Evaluate loaded policies.
            2. Log the event to the audit chain.
            3. Update the trust score (success on allow, failure on deny).
            4. Return a :class:`GovernanceResult`.
        """
        ctx = context or {}
        ctx.setdefault("action", {})
        if isinstance(ctx["action"], dict):
            ctx["action"].setdefault("type", action)

        # 1. Evaluate policy
        decision = self._policy_engine.evaluate(self._agent_did, ctx)

        # 2. Log to audit
        outcome = "success" if decision.allowed else "denied"
        audit_entry = self._audit_log.log(
            event_type="policy_evaluation",
            agent_did=self._agent_did,
            action=action,
            data=ctx,
            outcome=outcome,
            policy_decision=decision.action,
        )

        # 3. Update trust score
        if decision.allowed:
            new_score = min(
                TRUST_SCORE_MAX,
                self._trust_score.total_score + self._success_delta,
            )
        else:
            new_score = max(0, self._trust_score.total_score + self._failure_delta)

        self._trust_score.update(new_score, self._trust_score.dimensions)

        # 4. Build result
        return GovernanceResult(
            decision=decision.action,
            trust_score=float(self._trust_score.total_score),
            audit_entry=audit_entry,
            allowed=decision.allowed,
        )
