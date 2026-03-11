"""TrustGate: Conditional checkpoint node that gates graph transitions on trust score."""

from __future__ import annotations

import threading
from datetime import datetime, timezone
from typing import Any

from langgraph_trust.identity import AgentID, AgentIdentityManager
from langgraph_trust.state import TrustState, TrustVerdict


class TrustScoreTracker:
    """In-memory dynamic trust scoring (0.0-1.0). Thread-safe.

    Agents start at ``default_score``. Successful interactions raise the
    score by ``success_delta``; failures drop it by the configured severity.
    """

    def __init__(self, default_score: float = 0.5) -> None:
        self.default_score = default_score
        self._scores: dict[str, float] = {}
        self._history: list[dict[str, Any]] = []
        self._lock = threading.Lock()

    def get_score(self, agent: str) -> float:
        with self._lock:
            return self._scores.get(agent, self.default_score)

    def record_success(self, agent: str, delta: float = 0.01) -> float:
        with self._lock:
            cur = self._scores.get(agent, self.default_score)
            new = min(1.0, cur + delta)
            self._scores[agent] = new
            self._history.append(
                {"agent": agent, "action": "success", "old": cur, "new": new,
                 "ts": datetime.now(timezone.utc).isoformat()}
            )
            return new

    def record_failure(self, agent: str, severity: float = 0.1) -> float:
        with self._lock:
            cur = self._scores.get(agent, self.default_score)
            new = max(0.0, cur - severity)
            self._scores[agent] = new
            self._history.append(
                {"agent": agent, "action": "failure", "old": cur, "new": new,
                 "severity": severity,
                 "ts": datetime.now(timezone.utc).isoformat()}
            )
            return new

    def set_score(self, agent: str, score: float) -> None:
        with self._lock:
            self._scores[agent] = max(0.0, min(1.0, score))

    @property
    def history(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._history)

    @property
    def scores(self) -> dict[str, float]:
        with self._lock:
            return dict(self._scores)


class TrustGate:
    """A LangGraph node that gates execution based on trust score.

    Use as a node function in ``StateGraph.add_node``.  The gate reads the
    ``trust_agent`` key from state (or falls back to the ``agent_name`` set at
    construction time), looks up the agent's current trust score, and writes
    a ``TrustState`` verdict back into the graph state under the
    ``trust_result`` key.

    Downstream conditional edges can branch on
    ``state["trust_result"]["verdict"]``.

    Example::

        gate = TrustGate(min_score=0.7, tracker=tracker)
        graph.add_node("trust_check", gate)
        graph.add_conditional_edges("trust_check", trust_edge(
            pass_node="execute",
            fail_node="human_review",
        ))
    """

    def __init__(
        self,
        min_score: float = 0.5,
        tracker: TrustScoreTracker | None = None,
        identity_manager: AgentIdentityManager | None = None,
        agent_name: str | None = None,
        required_capabilities: list[str] | None = None,
        review_threshold: float | None = None,
    ) -> None:
        self.min_score = min_score
        self.review_threshold = review_threshold
        self.tracker = tracker or TrustScoreTracker()
        self.identity_manager = identity_manager
        self.agent_name = agent_name
        self.required_capabilities = required_capabilities or []

    def __call__(self, state: dict[str, Any]) -> dict[str, Any]:
        """LangGraph node function: evaluate trust and return state update."""
        agent = state.get("trust_agent", self.agent_name or "unknown")
        score = self.tracker.get_score(agent)
        did = ""

        # Capability check via identity manager
        cap_violations: list[str] = []
        if self.identity_manager and self.required_capabilities:
            identity = self.identity_manager.get_identity(agent)
            if identity is None:
                return self._verdict(
                    TrustVerdict.FAIL, score, agent, "",
                    "No identity registered for agent",
                    cap_violations=["identity_missing"],
                )
            did = identity.did
            for cap in self.required_capabilities:
                if not identity.has_capability(cap):
                    cap_violations.append(cap)

        if cap_violations:
            return self._verdict(
                TrustVerdict.FAIL, score, agent, did,
                "Missing capabilities: %s" % cap_violations,
                cap_violations=cap_violations,
            )

        if score < self.min_score:
            return self._verdict(
                TrustVerdict.FAIL, score, agent, did,
                "Trust score %.3f below minimum %.3f" % (score, self.min_score),
            )

        if self.review_threshold is not None and score < self.review_threshold:
            return self._verdict(
                TrustVerdict.REVIEW, score, agent, did,
                "Trust score %.3f below review threshold %.3f"
                % (score, self.review_threshold),
            )

        return self._verdict(
            TrustVerdict.PASS, score, agent, did, "Trust gate passed",
        )

    def _verdict(
        self,
        verdict: TrustVerdict,
        score: float,
        agent: str,
        did: str,
        reason: str,
        cap_violations: list[str] | None = None,
    ) -> dict[str, Any]:
        ts = TrustState(
            verdict=verdict,
            score=score,
            threshold=self.min_score,
            agent_did=did,
            reason=reason,
            capabilities_checked=self.required_capabilities,
            policy_violations=cap_violations or [],
        )
        return {"trust_result": ts.to_dict()}
