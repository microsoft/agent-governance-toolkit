# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
A2A Protocol Adapter for Agent-OS
==================================

Provides kernel-level governance for A2A (Agent-to-Agent) protocol tasks.

Backend (AGT 5.0): every content-policy decision is routed through
:class:`agt.policies.runtime.AgtRuntime` (the ACS-backed v5 engine).
The v4 :class:`A2APolicy` ``blocked_patterns`` are translated to a v4
:class:`~agent_os.integrations.base.GovernancePolicy` and from there
into an AGT manifest via
:func:`agt.policies.bridge.governance_to_acs_manifest` at adapter init
time. The runtime is memoised per policy and a
:class:`agt.policies.snapshot.SnapshotBuilder` mirrors the v4
``ExecutionContext`` budgets between intervention points. The legacy
``evaluate_task`` tuple-shaped API is preserved so v4 callers keep
working. ``transform`` verdicts (AGT-DELTA D1.1) rewrite the inbound
message text before the A2A task is forwarded; ``escalate`` verdicts
route through the configured approval resolver per AGT-DELTA D1.4.

Enforces Agent-OS policies on incoming A2A task negotiations:
- Skill-level access control (which skills are allowed/blocked)
- Content filtering on task messages
- Rate limiting per source agent
- Audit trail of all A2A interactions

Works with or without the ``a2a-agentmesh`` package — accepts plain dicts
from JSON-RPC endpoints as well as typed objects.

Example:
    >>> from agent_os.integrations.a2a_adapter import A2AGovernanceAdapter
    >>>
    >>> adapter = A2AGovernanceAdapter(
    ...     allowed_skills=["search", "translate"],
    ...     blocked_patterns=["DROP TABLE", "rm -rf"],
    ...     min_trust_score=300,
    ... )
    >>>
    >>> # Evaluate incoming A2A task request
    >>> result = adapter.evaluate_task({
    ...     "skill_id": "search",
    ...     "x-agentmesh-trust": {
    ...         "source_did": "did:mesh:agent-a",
    ...         "source_trust_score": 500,
    ...     },
    ...     "messages": [{"role": "user", "parts": [{"text": "Find weather"}]}],
    ... })
    >>> assert result["allowed"]
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from ._v5_runtime_bridge import (
    AdapterRuntimeBridge,
    BridgeResult,
    get_runtime_bridge,
)
from .base import ExecutionContext, GovernancePolicy

logger = logging.getLogger(__name__)


def _sanitize_did_for_agent_id(did: str) -> str:
    """Map an A2A DID to a string that satisfies the v4
    :class:`ExecutionContext.agent_id` regex (``^[a-zA-Z0-9_-]+$``).

    DIDs use colons (e.g. ``did:mesh:agent-a``) which are illegal in
    the agent_id field. We swap colons for underscores so the bridge
    can carry the DID end-to-end without losing identity.
    """
    safe = "".join(c if (c.isalnum() or c in "_-") else "_" for c in did)
    return safe or "anonymous"


@dataclass
class A2APolicy:
    """Policy for A2A task governance."""

    allowed_skills: list[str] = field(default_factory=list)
    blocked_skills: list[str] = field(default_factory=list)
    blocked_patterns: list[str] = field(default_factory=list)
    min_trust_score: int = 0
    max_requests_per_minute: int = 100
    require_trust_metadata: bool = False
    log_all: bool = True


@dataclass
class A2AEvaluation:
    """Result of evaluating an A2A task request.

    Attributes:
        allowed: Whether the inbound task is permitted.
        reason: Human-readable explanation.
        source_did: Source agent DID extracted from the trust metadata.
        skill_id: Skill the task is targeting.
        trust_score: Trust score of the source agent.
        conversation_alert: Optional ConversationGuardian alert.
        transform_value: Optional payload rewrite produced by an AGT
            transform verdict (AGT-DELTA D1.1). When set, the host
            should substitute it into the outbound task before
            forwarding to the A2A consumer.
        bridge_result: The full :class:`BridgeResult` from the AGT
            content-policy evaluation, when one fired. Carries the
            verdict, the v4 :class:`PolicyCheckResult`, and the
            ``audit_entry`` with the AGT bisected input/enforced
            identities per AGT-DELTA D1.4.
        timestamp: Wall-clock evaluation time.
    """

    allowed: bool
    reason: str = ""
    source_did: str = ""
    skill_id: str = ""
    trust_score: int = 0
    conversation_alert: Any | None = None
    transform_value: Any | None = None
    bridge_result: BridgeResult | None = None
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        d = {
            "allowed": self.allowed,
            "reason": self.reason,
            "source_did": self.source_did,
            "skill_id": self.skill_id,
            "trust_score": self.trust_score,
        }
        if self.conversation_alert is not None:
            d["conversation_alert"] = self.conversation_alert.to_dict()
        if self.transform_value is not None:
            d["transform_value"] = self.transform_value
        if self.bridge_result is not None:
            d["verdict"] = self.bridge_result.verdict
        return d


class A2AGovernanceAdapter:
    """
    Agent-OS governance adapter for A2A protocol tasks.

    Evaluates incoming A2A task requests (as dicts or typed objects)
    against Agent-OS policies. Optionally runs a ConversationGuardian
    to detect escalation, offensive intent, and feedback loops in
    inter-agent message content.

    Content-pattern enforcement is routed through the AGT 5.0 ACS
    runtime via :class:`AdapterRuntimeBridge`: ``blocked_patterns`` is
    translated to a v4 :class:`GovernancePolicy` and from there to an
    AGT manifest. ``transform`` verdicts (AGT-DELTA D1.1) rewrite the
    inbound message text on the returned :class:`A2AEvaluation`;
    ``escalate`` verdicts that the configured approval resolver
    refuses fail closed to a deny.
    """

    def __init__(
        self,
        policy: A2APolicy | None = None,
        *,
        allowed_skills: list[str] | None = None,
        blocked_skills: list[str] | None = None,
        blocked_patterns: list[str] | None = None,
        min_trust_score: int = 0,
        max_requests_per_minute: int = 100,
        conversation_guardian: Any | None = None,
        approval_resolver: Optional[Callable[..., Any]] = None,
        _runtime: Optional[Any] = None,
        _runtime_factory: Optional[Callable[..., Any]] = None,
    ):
        """Initialise the A2A governance adapter.

        Args:
            policy: An :class:`A2APolicy`. When ``None`` a policy is
                constructed from the convenience kwargs.
            allowed_skills, blocked_skills, blocked_patterns,
            min_trust_score, max_requests_per_minute,
            conversation_guardian: Convenience kwargs used to construct
                an ``A2APolicy`` when ``policy`` is ``None``.
            approval_resolver: Optional callable invoked when the AGT
                engine returns an ``escalate`` verdict. Signature matches
                :data:`agt.policies.runtime.ApprovalCallback`. When
                ``None`` an escalate verdict fails closed to ``deny``.
            _runtime: Test seam — inject a pre-built :class:`AgtRuntime`
                so scenario tests can wire a scripted policy dispatcher
                without OPA on PATH. Not part of the public surface.
            _runtime_factory: Test seam — override the runtime factory
                used by the bridge cache. Not part of the public surface.
        """
        if policy is not None:
            self.policy = policy
        else:
            self.policy = A2APolicy(
                allowed_skills=allowed_skills or [],
                blocked_skills=blocked_skills or [],
                blocked_patterns=blocked_patterns or [],
                min_trust_score=min_trust_score,
                max_requests_per_minute=max_requests_per_minute,
            )
        self._rate_tracker: dict[str, list[float]] = {}
        self._evaluations: list[A2AEvaluation] = []
        self._guardian = conversation_guardian

        # ── AGT 5.0 bridge ─────────────────────────────────────────
        # Translate ``blocked_patterns`` to a v4 GovernancePolicy so the
        # AGT manifest bridge generates an ``input`` intervention point
        # that pattern-scans the inbound message body. Skill / trust
        # / rate-limit fields remain host-side because the v4
        # GovernancePolicy schema does not encode them.
        self._governance_policy = GovernancePolicy(
            blocked_patterns=list(self.policy.blocked_patterns),
        )
        self._approval_resolver = approval_resolver
        self._bridge: AdapterRuntimeBridge = get_runtime_bridge(
            self._governance_policy,
            approval_resolver=approval_resolver,
            runtime=_runtime,
            runtime_factory=_runtime_factory,
        )
        self._contexts: dict[str, ExecutionContext] = {}

    @property
    def bridge(self) -> AdapterRuntimeBridge:
        """Return the v5 :class:`AdapterRuntimeBridge` for this adapter."""
        return self._bridge

    def _get_or_create_context(self, source_did: str) -> ExecutionContext:
        """Return (and lazily create) the :class:`ExecutionContext` for ``source_did``.

        The bridge requires a v4 :class:`ExecutionContext` to derive the
        per-session :class:`SnapshotBuilder`. A2A identifies inbound
        agents by DID, so we maintain one ``ExecutionContext`` per
        source DID (falling back to a shared ``anonymous`` context when
        the DID is empty). The DID is sanitised to satisfy the
        ``ExecutionContext.agent_id`` regex (``^[a-zA-Z0-9_-]+$``).
        """
        key = source_did or "anonymous"
        ctx = self._contexts.get(key)
        if ctx is None:
            safe_agent_id = _sanitize_did_for_agent_id(key)
            ctx = ExecutionContext(
                agent_id=safe_agent_id,
                session_id=f"a2a-{safe_agent_id}-{int(time.time())}",
                policy=self._governance_policy,
            )
            self._contexts[key] = ctx
        return ctx

    def _extract_fields(self, task: Any) -> dict[str, Any]:
        """Extract fields from a dict or typed object."""
        if isinstance(task, dict):
            trust = task.get("x-agentmesh-trust", {})
            messages_raw = task.get("messages", [])
            texts: list[str] = []
            for m in messages_raw:
                if isinstance(m, dict):
                    for part in m.get("parts", []):
                        if isinstance(part, dict) and "text" in part:
                            texts.append(part["text"])
            return {
                "skill_id": task.get("skill_id", ""),
                "source_did": trust.get("source_did", ""),
                "trust_score": trust.get("source_trust_score", 0),
                "texts": texts,
            }
        # Typed object (e.g. TaskEnvelope)
        texts = []
        for m in getattr(task, "messages", []):
            content = getattr(m, "content", "")
            if content:
                texts.append(content)
        return {
            "skill_id": getattr(task, "skill_id", ""),
            "source_did": getattr(task, "source_did", ""),
            "trust_score": getattr(task, "source_trust_score", 0),
            "texts": texts,
        }

    def _check_content(self, texts: list[str]) -> tuple[bool, str]:
        """Host-side fallback content scan (kept for callers that
        still invoke this method directly). The primary content gate
        runs through the AGT bridge in :meth:`evaluate_task`.
        """
        for text in texts:
            text_lower = text.lower()
            for pattern in self.policy.blocked_patterns:
                if pattern.lower() in text_lower:
                    return False, f"Content matches blocked pattern: '{pattern}'"
        return True, ""

    def evaluate_task(
        self,
        task: Any,
        *,
        conversation_id: str = "",
        sender: str = "",
        receiver: str = "",
    ) -> A2AEvaluation:
        """
        Evaluate an A2A task request against policies.

        Content-pattern checks route through the AGT 5.0 ACS runtime
        via :class:`AdapterRuntimeBridge` at the ``input`` intervention
        point. A ``deny`` verdict surfaces as
        :class:`A2AEvaluation` with ``allowed=False``; a ``transform``
        verdict (AGT-DELTA D1.1) is captured on
        :attr:`A2AEvaluation.transform_value` so the host can rewrite
        the inbound payload before forwarding; an ``escalate`` verdict
        that the configured approval resolver refuses fails closed to
        a deny.

        Args:
            task: Dict (from JSON-RPC) or typed TaskEnvelope object.
            conversation_id: Optional conversation ID for guardian analysis.
            sender: Optional sender agent ID for guardian analysis.
            receiver: Optional receiver agent ID for guardian analysis.

        Returns:
            A2AEvaluation with allowed/denied and reason.
        """
        fields = self._extract_fields(task)
        skill_id = fields["skill_id"]
        source_did = fields["source_did"]
        trust_score = fields["trust_score"]

        def deny(reason: str, bridge_result: BridgeResult | None = None) -> A2AEvaluation:
            e = A2AEvaluation(
                allowed=False,
                reason=reason,
                source_did=source_did,
                skill_id=skill_id,
                trust_score=trust_score,
                bridge_result=bridge_result,
            )
            self._evaluations.append(e)
            return e

        # 1. Trust metadata required
        if self.policy.require_trust_metadata and not source_did:
            return deny("Trust metadata (source DID) required")

        # 2. Skill blocked
        if skill_id in self.policy.blocked_skills:
            return deny(f"Skill '{skill_id}' is blocked")

        # 3. Skill not in allow list
        if self.policy.allowed_skills and skill_id not in self.policy.allowed_skills:
            return deny(f"Skill '{skill_id}' not in allowed list")

        # 4. Trust score
        if trust_score < self.policy.min_trust_score:
            return deny(
                f"Trust score {trust_score} below minimum {self.policy.min_trust_score}"
            )

        # 5. Content check via the AGT input intervention point.
        transform_value: Any | None = None
        bridge_result: BridgeResult | None = None
        if fields["texts"]:
            ctx = self._get_or_create_context(source_did)
            combined_text = " ".join(fields["texts"])
            bridge_result = self._bridge.evaluate_input(
                ctx, body=combined_text, source="a2a-peer"
            )
            if bridge_result.transform is not None and isinstance(
                bridge_result.transform.value, str
            ):
                # Capture the AGT-redacted payload so the host can
                # substitute it into the outbound task per AGT-DELTA D1.1.
                transform_value = bridge_result.transform.value
            elif not bridge_result.allowed:
                reason_text = (
                    bridge_result.reason
                    or "Content blocked by AGT input policy"
                )
                return deny(
                    f"Content matches blocked pattern: '{reason_text}'",
                    bridge_result,
                )
            else:
                # Host-side fallback content scan. The AGT manifest
                # bridge currently emits case-sensitive substring
                # patterns; the v4 A2A contract is case-insensitive, so
                # run the host-side ``_check_content`` to cover the
                # gap (mirrors the host-side guards documented for the
                # other v5-routed adapters).
                ok, reason = self._check_content(fields["texts"])
                if not ok:
                    return deny(reason, bridge_result)

        # 5.5 Conversation guardian analysis
        conversation_alert = None
        if self._guardian and fields["texts"]:
            from .conversation_guardian import AlertAction

            conv_id = conversation_id or task.get("id", "") if isinstance(task, dict) else getattr(task, "id", "")
            src = sender or source_did
            dst = receiver or skill_id
            combined_text = " ".join(fields["texts"])
            conversation_alert = self._guardian.analyze_message(
                conversation_id=conv_id or "unknown",
                sender=src or "unknown",
                receiver=dst or "unknown",
                content=combined_text,
            )
            if conversation_alert.action in (AlertAction.BREAK, AlertAction.QUARANTINE):
                return deny(
                    f"Conversation guardian: {conversation_alert.action.value} — "
                    + "; ".join(conversation_alert.reasons)
                )

        # 6. Rate limit
        if source_did:
            now = time.time()
            timestamps = self._rate_tracker.get(source_did, [])
            timestamps = [t for t in timestamps if t > now - 60]
            if len(timestamps) >= self.policy.max_requests_per_minute:
                return deny(f"Rate limit exceeded ({self.policy.max_requests_per_minute}/min)")
            timestamps.append(now)
            self._rate_tracker[source_did] = timestamps

        # Allowed
        e = A2AEvaluation(
            allowed=True,
            reason="Allowed",
            source_did=source_did,
            skill_id=skill_id,
            trust_score=trust_score,
            conversation_alert=conversation_alert,
            transform_value=transform_value,
            bridge_result=bridge_result,
        )
        self._evaluations.append(e)
        return e

    def get_evaluations(self) -> list[A2AEvaluation]:
        return list(self._evaluations)

    def get_stats(self) -> dict[str, Any]:
        total = len(self._evaluations)
        allowed = sum(1 for e in self._evaluations if e.allowed)
        return {
            "total": total,
            "allowed": allowed,
            "denied": total - allowed,
        }


__all__ = [
    "A2AGovernanceAdapter",
    "A2APolicy",
    "A2AEvaluation",
]
