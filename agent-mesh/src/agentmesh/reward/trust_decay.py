# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Trust Decay

Behavioral trust decay with network effects.

Extends the RewardEngine with:
1. Trust contagion — if agent A trusts B, and B fails, A's score decays
   proportionally to their interaction density.
2. Temporal decay — trust scores decay over time when no positive signals
   are received.
3. Behavioral regime detection — detects sudden behavioural shifts via
   KL divergence between recent and historical action distributions.
"""

from __future__ import annotations

import logging
import math
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from agentmesh.constants import TRUST_SCORE_DEFAULT, TRUST_SCORE_MAX

logger = logging.getLogger(__name__)


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


@dataclass
class InteractionEdge:
    """Weighted directed edge in the interaction graph."""

    from_did: str
    to_did: str
    interaction_count: int = 0
    last_interaction: float = field(default_factory=time.time)

    @property
    def weight(self) -> float:
        """Normalised interaction weight (0–1, saturates at 100 interactions)."""
        return min(1.0, self.interaction_count / 100)


@dataclass
class RegimeChangeAlert:
    """Alert when an agent's behaviour shifts suddenly."""

    agent_did: str
    kl_divergence: float
    threshold: float
    recent_distribution: Dict[str, float]
    historical_distribution: Dict[str, float]
    detected_at: float = field(default_factory=time.time)


# ---------------------------------------------------------------------------
# NetworkTrustEngine — basic linear decay implementation
# ---------------------------------------------------------------------------

class NetworkTrustEngine:
    """
    Network-aware trust engine with temporal decay and regime detection.

    Parameters
    ----------
    decay_rate : float
        Per-hour decay applied when an agent has no positive signals.
    propagation_factor : float
        Fraction of a trust event's impact that propagates to neighbours.
    propagation_depth : int
        How many hops a trust event propagates in the interaction graph.
    regime_threshold : float
        KL divergence above which a regime change is flagged.
    history_window_hours : int
        How many hours of actions count as "recent" for regime detection.
    baseline_days : int
        How many days of history form the "historical" baseline.
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
        self.propagation_factor = propagation_factor
        self.propagation_depth = propagation_depth
        self.regime_threshold = regime_threshold
        self.history_window_hours = history_window_hours
        self.baseline_days = baseline_days

        # Agent scores (0 – 1000)
        self._scores: Dict[str, float] = {}

        # Interaction graph: (from_did, to_did) → InteractionEdge
        self._edges: Dict[Tuple[str, str], InteractionEdge] = {}

        # Action history: agent_did → list of (timestamp, action_type)
        self._action_history: Dict[str, List[Tuple[float, str]]] = defaultdict(list)

        # Event log
        self._events: List[TrustEvent] = []

        # Regime alerts
        self._alerts: List[RegimeChangeAlert] = []

        # Last positive signal time per agent
        self._last_positive: Dict[str, float] = {}

        # Callbacks
        self._on_regime_change: List[Callable] = []
        self._on_score_change: List[Callable] = []

    # -- Score management -----------------------------------------------------

    def get_score(self, agent_did: str) -> float:
        return self._scores.get(agent_did, float(TRUST_SCORE_DEFAULT))

    def set_score(self, agent_did: str, score: float) -> None:
        self._scores[agent_did] = max(0.0, min(float(TRUST_SCORE_MAX), score))

    # -- Interaction graph ----------------------------------------------------

    def record_interaction(self, from_did: str, to_did: str) -> None:
        """Record an interaction between two agents."""
        key = (from_did, to_did)
        if key not in self._edges:
            self._edges[key] = InteractionEdge(from_did=from_did, to_did=to_did)
        self._edges[key].interaction_count += 1
        self._edges[key].last_interaction = time.time()

    def get_neighbors(self, agent_did: str) -> List[Tuple[str, float]]:
        """Return (peer_did, interaction_weight) pairs for *agent_did*."""
        neighbors: List[Tuple[str, float]] = []
        for (f, t), edge in self._edges.items():
            if f == agent_did:
                neighbors.append((t, edge.weight))
            elif t == agent_did:
                neighbors.append((f, edge.weight))
        return neighbors

    # -- Trust events ---------------------------------------------------------

    def record_action(self, agent_did: str, action_type: str) -> None:
        """Record an action for regime detection."""
        self._action_history[agent_did].append((time.time(), action_type))

    def record_positive_signal(self, agent_did: str, bonus: float = 5.0) -> None:
        """Record a positive signal (prevents decay, small score bump)."""
        self._last_positive[agent_did] = time.time()
        current = self.get_score(agent_did)
        self.set_score(agent_did, current + bonus)

    def process_trust_event(self, event: TrustEvent) -> Dict[str, float]:
        """
        Process a trust event with network propagation.

        Returns a dict of {agent_did: score_delta} for every affected agent.
        """
        self._events.append(event)
        deltas: Dict[str, float] = {}

        # Direct impact
        direct_impact = event.severity_weight * 100
        current = self.get_score(event.agent_did)
        new_score = current - direct_impact
        self.set_score(event.agent_did, new_score)
        deltas[event.agent_did] = -direct_impact

        # Propagation
        self._propagate(
            event.agent_did,
            event.severity_weight,
            depth=0,
            visited={event.agent_did},
            deltas=deltas,
        )

        # Notify callbacks
        for cb in self._on_score_change:
            try:
                cb(deltas)
            except Exception:
                logger.debug("Score change callback failed", exc_info=True)

        return deltas

    def _propagate(
        self,
        source_did: str,
        severity: float,
        depth: int,
        visited: set,
        deltas: Dict[str, float],
    ) -> None:
        if depth >= self.propagation_depth:
            return
        for peer_did, interaction_weight in self.get_neighbors(source_did):
            if peer_did in visited:
                continue
            visited.add(peer_did)
            decay = severity * interaction_weight * self.propagation_factor
            impact = decay * 100 * (0.5 ** depth)  # diminishes per hop
            current = self.get_score(peer_did)
            self.set_score(peer_did, current - impact)
            deltas[peer_did] = deltas.get(peer_did, 0) - impact
            self._propagate(peer_did, severity * 0.5, depth + 1, visited, deltas)

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

    # -- Regime detection -----------------------------------------------------

    def detect_regime_change(self, agent_did: str, now: Optional[float] = None) -> Optional[RegimeChangeAlert]:
        """
        Check if *agent_did* has shifted behaviour recently.

        Uses KL divergence between the recent action distribution
        and the historical baseline.
        """
        now = now or time.time()
        history = self._action_history.get(agent_did, [])
        if len(history) < 10:
            return None  # Not enough data

        cutoff_recent = now - self.history_window_hours * 3600
        cutoff_baseline = now - self.baseline_days * 86400

        recent_actions = [a for t, a in history if t >= cutoff_recent]
        baseline_actions = [a for t, a in history if cutoff_baseline <= t < cutoff_recent]

        if len(recent_actions) < 5 or len(baseline_actions) < 5:
            return None

        recent_dist = self._to_distribution(recent_actions)
        baseline_dist = self._to_distribution(baseline_actions)

        kl = self._kl_divergence(recent_dist, baseline_dist)

        if kl > self.regime_threshold:
            alert = RegimeChangeAlert(
                agent_did=agent_did,
                kl_divergence=kl,
                threshold=self.regime_threshold,
                recent_distribution=recent_dist,
                historical_distribution=baseline_dist,
            )
            self._alerts.append(alert)
            for cb in self._on_regime_change:
                try:
                    cb(alert)
                except Exception:  # noqa: S110 — intentional silent catch for decay alert callback
                    pass
            return alert

    # -- Callbacks ------------------------------------------------------------

    def on_regime_change(self, handler: Callable) -> None:
        self._on_regime_change.append(handler)

    def on_score_change(self, handler: Callable) -> None:
        self._on_score_change.append(handler)

    # -- Queries --------------------------------------------------------------

    @property
    def agent_count(self) -> int:
        return len(self._scores)

    @property
    def alerts(self) -> List[RegimeChangeAlert]:
        return list(self._alerts)

    def get_health_report(self) -> Dict[str, Any]:
        return {
            "agent_count": self.agent_count,
            "edge_count": len(self._edges),
            "event_count": len(self._events),
            "alert_count": len(self._alerts),
            "scores": dict(self._scores),
        }

    # -- Internal helpers -----------------------------------------------------

    @staticmethod
    def _to_distribution(actions: List[str]) -> Dict[str, float]:
        counts = Counter(actions)
        total = sum(counts.values())
        return {k: v / total for k, v in counts.items()}

    @staticmethod
    def _kl_divergence(p: Dict[str, float], q: Dict[str, float]) -> float:
        """KL(P || Q) with Laplace smoothing."""
        all_keys = set(p) | set(q)
        eps = 1e-10
        kl = 0.0
        for k in all_keys:
            pk = p.get(k, eps)
            qk = q.get(k, eps)
            if pk > 0:
                kl += pk * math.log(pk / qk)
        return kl
