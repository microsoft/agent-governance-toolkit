# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
A2A Protocol Adapter for Agent-OS
==================================

Provides kernel-level governance for A2A (Agent-to-Agent) protocol tasks.

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
from typing import Any

logger = logging.getLogger(__name__)


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
    """Result of evaluating an A2A task request."""

    allowed: bool
    reason: str = ""
    source_did: str = ""
    skill_id: str = ""
    trust_score: int = 0
    conversation_alert: Any | None = None
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
        return d


class A2AGovernanceAdapter:
    """
    Agent-OS governance adapter for A2A protocol tasks.

    Evaluates incoming A2A task requests (as dicts or typed objects)
    against Agent-OS policies. Optionally runs a ConversationGuardian
    to detect escalation, offensive intent, and feedback loops in
    inter-agent message content.
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
    ):
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

        def deny(reason: str) -> A2AEvaluation:
            e = A2AEvaluation(
                allowed=False,
                reason=reason,
                source_did=source_did,
                skill_id=skill_id,
                trust_score=trust_score,
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

        # 5. Content check
        ok, reason = self._check_content(fields["texts"])
        if not ok:
            return deny(reason)

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
