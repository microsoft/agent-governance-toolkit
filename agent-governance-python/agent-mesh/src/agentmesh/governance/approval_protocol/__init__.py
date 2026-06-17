# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Action-bound, fail-closed approval protocol (ADR-0030).

Reference schema and coordinator for the ``require_approval`` enforcement
outcome. This is step 1 of the ADR-0030 migration: the protocol foundation,
purely additive and not yet wired into the policy evaluator or the legacy
``agentmesh.governance.approval`` handlers.

Example::

    from agentmesh.governance.approval_protocol import (
        ActionBinding, ActionTarget, ApprovalChain, ApprovalStage,
        ApprovalCoordinator, InMemoryApprovalStore, ApproverKind, EntryDecision,
    )

    chain = ApprovalChain(
        chain_id="high-risk-tools",
        version="3",
        stages=(ApprovalStage(0, allowed_identities=frozenset({"did:web:example.com:users:alice"})),),
    )
    coordinator = ApprovalCoordinator(InMemoryApprovalStore(), {chain.chain_id: chain})

    binding = ActionBinding(
        operation="tool.invoke",
        agent_id="agent-123",
        target=ActionTarget("sql_execute", "2", resource="prod-db"),
        parameters={"statement": "UPDATE accounts SET status = ? WHERE id = ?", "values": ["closed", 42]},
    )
    decision, request = coordinator.open_request(
        binding, policy_rule_id="production-db-writes",
        policy_version="2026.06.11", chain_id=chain.chain_id, ttl_seconds=600,
    )
    coordinator.submit_entry(
        request.approval_request_id, stage_index=0,
        approver_kind=ApproverKind.HUMAN,
        approver_identity="did:web:example.com:users:alice",
        identity_assurance="oidc", decision=EntryDecision.ALLOW,
    )
    verdict = coordinator.validate_for_execution(
        request.approval_request_id,
        current_action_digest=binding.digest(),
        current_policy_version="2026.06.11",
        current_chain_version=chain.version,
    )
    assert verdict.allowed
"""

from .binding import SCHEMA_VERSION, ActionBinding, ActionTarget
from .coordinator import (
    ApprovalChain,
    ApprovalCoordinator,
    ApprovalProtocolError,
    ApprovalStage,
    ExecutionDecision,
    ReasonCode,
)
from .digest import DIGEST_PREFIX, canonicalize, sha256_jcs
from .models import (
    ApprovalChainEntry,
    ApprovalRequest,
    ApprovalResolution,
    ApprovalStatus,
    ApproverKind,
    EntryDecision,
    Outcome,
    PolicyDecisionRecord,
    Verdict,
    utcnow,
)
from .store import ApprovalStore, InMemoryApprovalStore

__all__ = [
    # digest
    "canonicalize",
    "sha256_jcs",
    "DIGEST_PREFIX",
    # binding
    "ActionBinding",
    "ActionTarget",
    "SCHEMA_VERSION",
    # models
    "Verdict",
    "ApprovalStatus",
    "ApproverKind",
    "EntryDecision",
    "Outcome",
    "PolicyDecisionRecord",
    "ApprovalRequest",
    "ApprovalChainEntry",
    "ApprovalResolution",
    "utcnow",
    # store
    "ApprovalStore",
    "InMemoryApprovalStore",
    # coordinator
    "ApprovalCoordinator",
    "ApprovalChain",
    "ApprovalStage",
    "ExecutionDecision",
    "ReasonCode",
    "ApprovalProtocolError",
]
