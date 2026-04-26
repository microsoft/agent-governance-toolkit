# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Rogue agent detection engine (OWASP ASI-10).

Detects behavioral anomalies that indicate an agent has gone rogue:
tool-call frequency spikes, action entropy deviation, and capability
profile violations.  Combines these signals into a single risk
assessment with optional auto-quarantine recommendations.
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


logger = logging.getLogger(__name__)


# ── Enums / value types ─────────────────────────────────────────────


class RiskLevel(Enum):
    """Overall risk classification for an agent."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# ── Configuration ────────────────────────────────────────────────────


@dataclass
class RogueDetectorConfig:
    """Tunable thresholds for the rogue-agent detector."""

    # ToolCallFrequencyAnalyzer
    frequency_window_seconds: float = 60.0
    frequency_z_threshold: float = 2.5
    frequency_min_windows: int = 5

    # ActionEntropyScorer
    entropy_low_threshold: float = 0.3
    entropy_high_threshold: float = 3.5
    entropy_min_actions: int = 10

    # CapabilityProfileDeviation
    capability_violation_weight: float = 1.0

    # RogueAgentDetector
    quarantine_risk_level: RiskLevel = RiskLevel.HIGH


# ── Assessment result ────────────────────────────────────────────────


@dataclass
class RogueAssessment:
    """Result of a rogue-agent risk assessment."""

    agent_id: str
    risk_level: RiskLevel
    composite_score: float
    frequency_score: float
    entropy_score: float
    capability_score: float
    quarantine_recommended: bool
    details: dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    previous_hash: str = ""
    entry_hash: str = ""

    def _hash_payload(self) -> str:
        """Return a canonical JSON string of the fields covered by the hash."""
        payload = {
            "agent_id": self.agent_id,
            "composite_score": self.composite_score,
            "quarantine_recommended": self.quarantine_recommended,
            "timestamp": self.timestamp,
            "frequency_score": self.frequency_score,
            "entropy_score": self.entropy_score,
            "capability_score": self.capability_score,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))

    def compute_hash(self, previous_hash: str) -> str:
        """Compute SHA-256 entry hash chained to *previous_hash*."""
        canonical = self._hash_payload()
        return hashlib.sha256(
            f"{previous_hash}:{canonical}".encode("utf-8"),
        ).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "risk_level": self.risk_level.value,
            "composite_score": round(self.composite_score, 4),
            "frequency_score": round(self.frequency_score, 4),
            "entropy_score": round(self.entropy_score, 4),
            "capability_score": round(self.capability_score, 4),
            "quarantine_recommended": self.quarantine_recommended,
            "details": self.details,
            "timestamp": self.timestamp,
            "previous_hash": self.previous_hash,
            "entry_hash": self.entry_hash,
        }


# ── Analyzers ────────────────────────────────────────────────────────


class ToolCallFrequencyAnalyzer:
    """Z-score analysis on tool-call frequency per time window.

    Tracks calls per agent per time bucket and detects sudden spikes
    using z-score against baseline.
    """

    def __init__(
        self,
        window_seconds: float = 60.0,
        z_threshold: float = 2.5,
        min_windows: int = 5,
    ) -> None:
        self.window_seconds = window_seconds
        self.z_threshold = z_threshold
        self.min_windows = min_windows
        # agent_id → deque of (window_start, count) tuples
        self._buckets: dict[str, deque[tuple[float, int]]] = defaultdict(
            lambda: deque(maxlen=200),
        )
        # agent_id → (current_window_start, running_count)
        self._current: dict[str, tuple[float, int]] = {}

    def _flush_bucket(self, agent_id: str, now: float) -> None:
        """Rotate the current bucket if the window has elapsed."""
        if agent_id not in self._current:
            self._current[agent_id] = (now, 0)
            return

        win_start, count = self._current[agent_id]
        if now - win_start >= self.window_seconds:
            self._buckets[agent_id].append((win_start, count))
            self._current[agent_id] = (now, 0)

    def record(self, agent_id: str, timestamp: float | None = None) -> None:
        """Record a single tool call."""
        now = timestamp if timestamp is not None else time.time()
        self._flush_bucket(agent_id, now)
        win_start, count = self._current[agent_id]
        self._current[agent_id] = (win_start, count + 1)

    def score(self, agent_id: str, timestamp: float | None = None) -> float:
        """Return a z-score for the current window's call frequency.

        Returns 0.0 when insufficient data is available.
        """
        now = timestamp if timestamp is not None else time.time()
        self._flush_bucket(agent_id, now)

        history = self._buckets.get(agent_id)
        if not history or len(history) < self.min_windows:
            return 0.0

        counts = [c for _, c in history]
        mean = sum(counts) / len(counts)
        variance = sum((x - mean) ** 2 for x in counts) / len(counts)
        std_dev = math.sqrt(variance)

        _, current_count = self._current.get(agent_id, (0.0, 0))

        if std_dev == 0:
            return 0.0

        return abs(current_count - mean) / std_dev


class ActionEntropyScorer:
    """Shannon entropy scoring for agent action diversity.

    Low entropy → agent stuck in a loop (repetitive behavior).
    Very high entropy → erratic, unfocused behavior.
    """

    def __init__(
        self,
        low_threshold: float = 0.3,
        high_threshold: float = 3.5,
        min_actions: int = 10,
    ) -> None:
        self.low_threshold = low_threshold
        self.high_threshold = high_threshold
        self.min_actions = min_actions
        # agent_id → list of action names
        self._actions: dict[str, list[str]] = defaultdict(list)

    def record(self, agent_id: str, action: str) -> None:
        """Record an action for the given agent."""
        self._actions[agent_id].append(action)

    def entropy(self, agent_id: str) -> float | None:
        """Compute Shannon entropy of the agent's action distribution.

        Returns ``None`` when fewer than ``min_actions`` have been recorded.
        """
        actions = self._actions.get(agent_id, [])
        if len(actions) < self.min_actions:
            return None

        total = len(actions)
        counts: dict[str, int] = {}
        for a in actions:
            counts[a] = counts.get(a, 0) + 1

        h = 0.0
        for c in counts.values():
            p = c / total
            if p > 0:
                h -= p * math.log2(p)
        return h

    def score(self, agent_id: str) -> float:
        """Return an anomaly score based on entropy deviation.

        * Score > 0 indicates anomalous entropy (too low or too high).
        * Returns 0.0 when data is insufficient or entropy is in range.
        """
        h = self.entropy(agent_id)
        if h is None:
            return 0.0

        if h < self.low_threshold:
            # Agent stuck in a loop — further below threshold → higher score
            return (self.low_threshold - h) / self.low_threshold if self.low_threshold > 0 else 1.0

        if h > self.high_threshold:
            # Erratic behavior
            return (h - self.high_threshold) / self.high_threshold if self.high_threshold > 0 else 1.0

        return 0.0


class CapabilityProfileDeviation:
    """Detect when an agent uses tools outside its declared profile.

    Each agent registers a set of allowed tools.  Any tool call
    outside that set increments a violation counter.  The score
    is the fraction of total calls that are violations.
    """

    def __init__(self, violation_weight: float = 1.0) -> None:
        self.violation_weight = violation_weight
        # agent_id → set of allowed tool names
        self._profiles: dict[str, set[str]] = {}
        # agent_id → (total_calls, violation_count)
        self._counters: dict[str, tuple[int, int]] = defaultdict(lambda: (0, 0))

    def register_profile(self, agent_id: str, allowed_tools: list[str]) -> None:
        """Register or update the capability profile for an agent."""
        self._profiles[agent_id] = set(allowed_tools)

    def record(self, agent_id: str, tool_name: str) -> bool:
        """Record a tool call and return ``True`` if it is a violation."""
        total, violations = self._counters[agent_id]
        total += 1

        is_violation = False
        profile = self._profiles.get(agent_id)
        if profile is not None and tool_name not in profile:
            violations += 1
            is_violation = True

        self._counters[agent_id] = (total, violations)
        return is_violation

    def score(self, agent_id: str) -> float:
        """Return a capability-deviation score in ``[0, 1]``.

        A value of 0 means no violations; 1 means every call was
        outside the declared profile.  Scaled by ``violation_weight``.
        """
        total, violations = self._counters.get(agent_id, (0, 0))
        if total == 0:
            return 0.0
        return (violations / total) * self.violation_weight


# ── Orchestrator ─────────────────────────────────────────────────────

_RISK_ORDER = [RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]

_GENESIS_HASH = "0" * 64  # SHA-256-length zero string used as the chain seed


class RogueAgentDetector:
    """Orchestrates frequency, entropy, and capability analyzers to
    produce a composite risk assessment for each agent.
    """

    def __init__(self, config: RogueDetectorConfig | None = None) -> None:
        self._config = config or RogueDetectorConfig()

        self.frequency_analyzer = ToolCallFrequencyAnalyzer(
            window_seconds=self._config.frequency_window_seconds,
            z_threshold=self._config.frequency_z_threshold,
            min_windows=self._config.frequency_min_windows,
        )
        self.entropy_scorer = ActionEntropyScorer(
            low_threshold=self._config.entropy_low_threshold,
            high_threshold=self._config.entropy_high_threshold,
            min_actions=self._config.entropy_min_actions,
        )
        self.capability_checker = CapabilityProfileDeviation(
            violation_weight=self._config.capability_violation_weight,
        )

        self._assessments: list[RogueAssessment] = []
        self._last_hash: str = _GENESIS_HASH

    # -- data ingestion ---------------------------------------------------

    def record_action(
        self,
        agent_id: str,
        action: str,
        tool_name: str,
        timestamp: float | None = None,
    ) -> None:
        """Feed an observed action into all analyzers."""
        ts = timestamp if timestamp is not None else time.time()
        self.frequency_analyzer.record(agent_id, timestamp=ts)
        self.entropy_scorer.record(agent_id, action)
        self.capability_checker.record(agent_id, tool_name)

    def register_capability_profile(
        self,
        agent_id: str,
        allowed_tools: list[str],
    ) -> None:
        """Declare the set of tools an agent is expected to use."""
        self.capability_checker.register_profile(agent_id, allowed_tools)

    # -- assessment -------------------------------------------------------

    def assess(
        self,
        agent_id: str,
        timestamp: float | None = None,
    ) -> RogueAssessment:
        """Produce a composite risk assessment for *agent_id*.

        Combines frequency z-score, entropy anomaly score, and
        capability violation score into a single ``RogueAssessment``.
        """
        freq_score = self.frequency_analyzer.score(agent_id, timestamp=timestamp)
        ent_score = self.entropy_scorer.score(agent_id)
        cap_score = self.capability_checker.score(agent_id)

        composite = freq_score + ent_score + cap_score
        risk_level = self._classify_risk(composite)

        quarantine_threshold_idx = _RISK_ORDER.index(
            self._config.quarantine_risk_level,
        )
        current_idx = _RISK_ORDER.index(risk_level)
        quarantine = current_idx >= quarantine_threshold_idx

        assessment = RogueAssessment(
            agent_id=agent_id,
            risk_level=risk_level,
            composite_score=composite,
            frequency_score=freq_score,
            entropy_score=ent_score,
            capability_score=cap_score,
            quarantine_recommended=quarantine,
            details={
                "frequency_z_threshold": self._config.frequency_z_threshold,
                "entropy_low_threshold": self._config.entropy_low_threshold,
                "entropy_high_threshold": self._config.entropy_high_threshold,
                "quarantine_risk_level": self._config.quarantine_risk_level.value,
            },
            timestamp=timestamp if timestamp is not None else time.time(),
        )

        # -- tamper-evident hash chain --
        assessment.previous_hash = self._last_hash
        assessment.entry_hash = assessment.compute_hash(self._last_hash)
        self._last_hash = assessment.entry_hash

        self._assessments.append(assessment)
        if quarantine:
            logger.warning(
                "Quarantine recommended for agent %s (risk=%s, score=%.2f)",
                agent_id,
                risk_level.value,
                composite,
            )

        return assessment

    # -- queries ----------------------------------------------------------

    @property
    def assessments(self) -> list[RogueAssessment]:
        """Return a copy of the assessment history."""
        return list(self._assessments)

    def verify_assessment_chain(self) -> tuple[bool, Optional[str]]:
        """Walk every assessment and verify hash linkage.

        Returns ``(True, None)`` when the chain is intact, or
        ``(False, description)`` on the first broken link.
        """
        prev_hash = _GENESIS_HASH
        for idx, assessment in enumerate(self._assessments):
            if assessment.previous_hash != prev_hash:
                return (
                    False,
                    f"Assessment {idx} (agent={assessment.agent_id}): "
                    f"previous_hash mismatch",
                )
            expected = assessment.compute_hash(prev_hash)
            if assessment.entry_hash != expected:
                return (
                    False,
                    f"Assessment {idx} (agent={assessment.agent_id}): "
                    f"entry_hash mismatch",
                )
            prev_hash = assessment.entry_hash
        return (True, None)

    # -- internals --------------------------------------------------------

    @staticmethod
    def _classify_risk(composite_score: float) -> RiskLevel:
        """Map composite score to a risk level.

        Thresholds (mirroring ``AnomalySeverity`` boundaries):
        * < 1.0  → LOW
        * < 2.0  → MEDIUM
        * < 3.0  → HIGH
        * >= 3.0 → CRITICAL
        """
        if composite_score >= 3.0:
            return RiskLevel.CRITICAL
        if composite_score >= 2.0:
            return RiskLevel.HIGH
        if composite_score >= 1.0:
            return RiskLevel.MEDIUM
        return RiskLevel.LOW
