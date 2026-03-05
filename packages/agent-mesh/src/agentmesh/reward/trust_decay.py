# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Trust Decay

Simple linear time decay: if no positive event in X hours, reduce
score by Y per hour.
"""

from __future__ import annotations

import logging
import time

from agentmesh.constants import TRUST_SCORE_DEFAULT, TRUST_SCORE_MAX

logger = logging.getLogger(__name__)
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class TrustEvent:
    """A trust-relevant event for an agent."""

    agent_did: str
    event_type: str            # e.g. "policy_violation", "handoff_failure"
    severity_weight: float     # 0.0 (minor) – 1.0 (critical)
    timestamp: float = field(default_factory=time.time)
    details: Optional[str] = None


# ---------------------------------------------------------------------------
# NetworkTrustEngine — basic linear decay implementation
# ---------------------------------------------------------------------------

class NetworkTrustEngine:
    """
    Basic trust engine with simple linear temporal decay.

    Parameters
    ----------
    decay_rate : float
        Per-hour decay applied when an agent has no positive signals.
    """

    def __init__(
        self,
        decay_rate: float = 2.0,
        propagation_factor: float = 0.3,
        propagation_depth: int = 2,
        regime_threshold: float = 0.5,
        history_window_hours: int = 1,
        baseline_days: int = 30,
    ) -> None:
        self.decay_rate = decay_rate
        # Accept but ignore advanced params for API compatibility
        self.propagation_factor = propagation_factor
        self.propagation_depth = propagation_depth
        self.regime_threshold = regime_threshold
        self.history_window_hours = history_window_hours
        self.baseline_days = baseline_days

        # Agent scores (0 – 1000)
        self._scores: Dict[str, float] = {}

        # Event log
        self._events: List[TrustEvent] = []

        # Last positive signal time per agent
        self._last_positive: Dict[str, float] = {}

        # Callbacks
        self._on_score_change: List[Callable] = []

    # -- Score management -----------------------------------------------------

    def get_score(self, agent_did: str) -> float:
        return self._scores.get(agent_did, float(TRUST_SCORE_DEFAULT))

    def set_score(self, agent_did: str, score: float) -> None:
        self._scores[agent_did] = max(0.0, min(float(TRUST_SCORE_MAX), score))

    # -- Interaction graph (no-op in basic edition) ---------------------------

    def record_interaction(self, from_did: str, to_did: str) -> None:
        """Record an interaction."""
        pass

    def get_neighbors(self, agent_did: str) -> List[Tuple[str, float]]:
        """Return empty list."""
        return []

    # -- Trust events ---------------------------------------------------------

    def record_action(self, agent_did: str, action_type: str) -> None:
        """Record an action."""
        pass

    def record_positive_signal(self, agent_did: str, bonus: float = 5.0) -> None:
        """Record a positive signal (prevents decay, small score bump)."""
        self._last_positive[agent_did] = time.time()
        current = self.get_score(agent_did)
        self.set_score(agent_did, current + bonus)

    def process_trust_event(self, event: TrustEvent) -> Dict[str, float]:
        """
        Process a trust event — direct impact only, no propagation.

        Returns a dict of {agent_did: score_delta}.
        """
        self._events.append(event)
        deltas: Dict[str, float] = {}

        # Direct impact only
        direct_impact = event.severity_weight * 100
        current = self.get_score(event.agent_did)
        new_score = current - direct_impact
        self.set_score(event.agent_did, new_score)
        deltas[event.agent_did] = -direct_impact

        # Notify callbacks
        for cb in self._on_score_change:
            try:
                cb(deltas)
            except Exception:
                logger.debug("Score change callback failed", exc_info=True)

        return deltas

    # -- Temporal decay -------------------------------------------------------

    def apply_temporal_decay(self, now: Optional[float] = None) -> Dict[str, float]:
        """
        Simple linear decay for agents without recent positive signals.

        Call this periodically (e.g. every minute).  Returns deltas.
        """
        now = now or time.time()
        deltas: Dict[str, float] = {}
        for agent_did, score in list(self._scores.items()):
            last = self._last_positive.get(agent_did, now)
            hours_since = (now - last) / 3600
            if hours_since > 0:
                decay = self.decay_rate * hours_since
                effective_decay = min(decay, max(0, score - 100))
                if effective_decay > 0:
                    self.set_score(agent_did, score - effective_decay)
                    deltas[agent_did] = -effective_decay
        return deltas

    # -- Regime detection (no-op in basic edition) ----------------------------

    def detect_regime_change(self, agent_did: str, now: Optional[float] = None) -> None:
        """Returns None."""
        return None

    # -- Callbacks ------------------------------------------------------------

    def on_regime_change(self, handler: Callable) -> None:
        """No-op."""
        pass

    def on_score_change(self, handler: Callable) -> None:
        self._on_score_change.append(handler)

    # -- Queries --------------------------------------------------------------

    @property
    def agent_count(self) -> int:
        return len(self._scores)

    @property
    def alerts(self) -> list:
        return []

    def get_health_report(self) -> Dict[str, Any]:
        return {
            "agent_count": self.agent_count,
            "edge_count": 0,
            "event_count": len(self._events),
            "alert_count": 0,
            "scores": dict(self._scores),
        }
