# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""A2A protocol integration backed by a required native ACS runtime.

Task content is mediated through ACS. Skill access, trust thresholds, rate
limits, conversation monitoring, and audit remain host-owned controls.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any

from ._native_adapter_runtime import (
    AdapterResult,
    AdapterRuntime,
)
from .base import AdapterExecutionState, get_adapter_runtime

logger = logging.getLogger(__name__)


def _sanitize_did_for_agent_id(did: str) -> str:
    """Map an A2A DID to a valid :class:`AdapterExecutionState` agent ID.

    DIDs use colons (e.g. ``did:mesh:agent-a``) which are illegal in
    the agent ID field, so unsupported characters become underscores.
    """
    safe = "".join(c if (c.isalnum() or c in "_-") else "_" for c in did)
    return safe or "anonymous"


@dataclass
class A2APolicy:
    """Policy for A2A task governance."""

    allowed_skills: list[str] = field(default_factory=list)
    blocked_skills: list[str] = field(default_factory=list)
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
        bridge_result: The native :class:`AdapterResult` when content
            evaluation ran.
        timestamp: Wall-clock evaluation time.
    """

    allowed: bool
    reason: str = ""
    source_did: str = ""
    skill_id: str = ""
    trust_score: int = 0
    conversation_alert: Any | None = None
    transform_value: Any | None = None
    bridge_result: AdapterResult | None = None
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
    """Govern incoming A2A task requests with ACS and host controls."""

    def __init__(
        self,
        policy: A2APolicy | None = None,
        *,
        allowed_skills: list[str] | None = None,
        blocked_skills: list[str] | None = None,
        min_trust_score: int = 0,
        max_requests_per_minute: int = 100,
        conversation_guardian: Any | None = None,
        runtime: Any,
    ):
        """Initialise host controls and the required native runtime."""
        if policy is not None:
            self.policy = policy
        else:
            self.policy = A2APolicy(
                allowed_skills=allowed_skills or [],
                blocked_skills=blocked_skills or [],
                min_trust_score=min_trust_score,
                max_requests_per_minute=max_requests_per_minute,
            )
        self._rate_tracker: dict[str, list[float]] = {}
        self._evaluations: list[A2AEvaluation] = []
        self._guardian = conversation_guardian

        self._bridge: AdapterRuntime = get_adapter_runtime(runtime)
        self._contexts: dict[str, AdapterExecutionState] = {}

    @property
    def bridge(self) -> AdapterRuntime:
        """Return the v5 :class:`AdapterRuntime` for this adapter."""
        return self._bridge

    def _get_or_create_context(self, source_did: str) -> AdapterExecutionState:
        """Return (and lazily create) the :class:`AdapterExecutionState` for ``source_did``.

        A2A identifies inbound agents by DID, so each source gets a session
        context. Empty DIDs share an anonymous context.
        """
        key = source_did or "anonymous"
        ctx = self._contexts.get(key)
        if ctx is None:
            safe_agent_id = _sanitize_did_for_agent_id(key)
            ctx = AdapterExecutionState(
                agent_id=safe_agent_id,
                session_id=f"a2a-{safe_agent_id}-{int(time.time())}",
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
        via :class:`AdapterRuntime` at the ``input`` intervention
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

        def deny(reason: str, bridge_result: AdapterResult | None = None) -> A2AEvaluation:
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
        bridge_result: AdapterResult | None = None
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
