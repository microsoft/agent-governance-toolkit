# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
AuthorityResolver protocol for reputation-gated authority.

Defines the extension interface for composing trust scoring with
delegation chains. External implementations (e.g., agentmesh-reputation-gate)
implement this protocol; the governance pipeline calls it at the
enforcement boundary.

Design reference: docs/proposals/REPUTATION-GATED-AUTHORITY.md
Issue: #275

Usage:
    from agentmesh.governance.authority import AuthorityResolver, AuthorityDecision

    class MyResolver:
        def resolve(self, request: AuthorityRequest) -> AuthorityDecision:
            # Your authority composition logic
            ...

    # Register with PolicyEngine
    engine = PolicyEngine()
    engine.set_authority_resolver(MyResolver())
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal, Optional, Protocol, runtime_checkable


# ── Data types ────────────────────────────────────────────────


@dataclass
class DelegationInfo:
    """Delegation chain context for authority resolution.

    Maps to AgentMesh's ``ScopeChain`` / ``DelegationLink`` data.
    Implementations can populate this from the existing identity layer.
    """

    agent_did: str
    parent_did: Optional[str] = None
    delegation_depth: int = 0
    delegated_capabilities: list[str] = field(default_factory=list)
    chain_verified: bool = False
    chain_id: Optional[str] = None


@dataclass
class TrustInfo:
    """Trust score context for authority resolution.

    Maps to AgentMesh's ``RiskScore`` and handshake ``trust_score``.
    The 0–1000 scale matches AgentMesh defaults (500 = default new agent).
    """

    score: int = 500
    risk_level: str = "medium"
    identity_score: int = 50
    behavior_score: int = 50
    network_score: int = 50
    compliance_score: int = 50


@dataclass
class ActionRequest:
    """The action being requested, for authority evaluation.

    Maps to the ``context`` dict passed through the governance pipeline.
    """

    action_type: str
    tool_name: Optional[str] = None
    resource: Optional[str] = None
    parameters: dict[str, Any] = field(default_factory=dict)
    requested_spend: Optional[float] = None


@dataclass
class AuthorityDecision:
    """Result of authority resolution.

    Four decision states (per the ADR):
    - ``allow``: Action permitted with original scope
    - ``allow_narrowed``: Action permitted with reduced scope/limits
    - ``deny``: Action blocked
    - ``audit``: Action logged but not enforced (shadow mode)

    Attributes:
        decision: The authority verdict.
        effective_scope: Capabilities the agent may use for this action
            (may be narrower than delegated capabilities).
        effective_spend_limit: Maximum spend for this action (may be
            lower than the agent's delegation limit).
        narrowing_reason: Human-readable explanation when decision is
            ``allow_narrowed`` or ``deny``.
        trust_tier: The trust tier that was applied
            (e.g., ``"privileged"``, ``"trusted"``, ``"standard"``,
            ``"restricted"``, ``"untrusted"``).
        matched_invariants: Which of the 6 formal invariants were
            evaluated (for audit/debugging).
        timestamp: When the decision was made.
    """

    decision: Literal["allow", "allow_narrowed", "deny", "audit"]
    effective_scope: list[str] = field(default_factory=list)
    effective_spend_limit: Optional[float] = None
    narrowing_reason: Optional[str] = None
    trust_tier: str = "unknown"
    matched_invariants: list[str] = field(default_factory=list)
    timestamp: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )


@dataclass
class AuthorityRequest:
    """Complete context for an authority resolution request.

    Bundles identity, delegation, trust, and action into a single
    object so the resolver has everything it needs.
    """

    delegation: DelegationInfo
    trust: TrustInfo
    action: ActionRequest
    context: dict[str, Any] = field(default_factory=dict)


# ── Protocol ──────────────────────────────────────────────────


@runtime_checkable
class AuthorityResolver(Protocol):
    """Interface for authority resolution backends.

    Implementations compose trust scoring with delegation chains to
    produce an ``AuthorityDecision``. The governance pipeline calls
    ``resolve()`` between delegation verification and capability
    enforcement.

    The protocol is deliberately minimal — implementations own the
    composition logic (tier mapping, capability matching, cache
    strategy). The toolkit owns the enforcement boundary.

    Reference implementation: https://github.com/aeoess/agentmesh-reputation-gate
    """

    def resolve(self, request: AuthorityRequest) -> AuthorityDecision:
        """Resolve effective authority for an agent action.

        Args:
            request: Complete context including delegation chain,
                trust score, and the requested action.

        Returns:
            An ``AuthorityDecision`` with the verdict and any
            scope narrowing applied.
        """
        ...


# ── Default (passthrough) resolver ────────────────────────────


class DefaultAuthorityResolver:
    """No-op resolver that allows everything.

    Used when no external authority resolver is registered.
    Preserves pre-resolver behavior: delegation scope is the
    effective scope, no trust-based narrowing.
    """

    def resolve(self, request: AuthorityRequest) -> AuthorityDecision:
        return AuthorityDecision(
            decision="allow",
            effective_scope=request.delegation.delegated_capabilities,
            trust_tier="unresolved",
            narrowing_reason=None,
        )
