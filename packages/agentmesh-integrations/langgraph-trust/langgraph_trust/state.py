"""Trust state types for LangGraph graphs."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class TrustVerdict(str, Enum):
    """Result of a trust verification."""

    PASS = "pass"
    FAIL = "fail"
    REVIEW = "review"


@dataclass
class TrustState:
    """Immutable record of a trust decision at a graph checkpoint."""

    verdict: TrustVerdict
    score: float
    threshold: float
    agent_did: str = ""
    reason: str = ""
    capabilities_checked: list[str] = field(default_factory=list)
    policy_violations: list[str] = field(default_factory=list)
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict.value,
            "score": self.score,
            "threshold": self.threshold,
            "agent_did": self.agent_did,
            "reason": self.reason,
            "capabilities_checked": self.capabilities_checked,
            "policy_violations": self.policy_violations,
            "timestamp": self.timestamp,
        }

    @property
    def passed(self) -> bool:
        return self.verdict == TrustVerdict.PASS
