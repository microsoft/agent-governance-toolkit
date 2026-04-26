# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
A2A Conversation Guardian (OWASP ASI-8 / ASI-10)
=================================================

Monitors agent-to-agent conversations for emergent offensive behavior:

- **EscalationClassifier**: Detects when one agent pushes another toward
  bypassing security controls via escalating rhetoric.
- **FeedbackLoopBreaker**: Detects retry/escalation cycles between agent
  pairs and triggers circuit-breaking before conversations devolve.
- **OffensiveIntentDetector**: Detects vulnerability research, recon,
  privilege escalation, and exfiltration planning language in messages.
- **ConversationGuardian**: Orchestrates all three detectors and produces
  a composite alert with recommended action.

Motivated by Irregular Labs research demonstrating that AI agents can
autonomously develop offensive cyber behavior through multi-agent feedback
loops — without any offensive instructions.

Example:
    >>> from agent_os.integrations.conversation_guardian import (
    ...     ConversationGuardian,
    ...     ConversationGuardianConfig,
    ... )
    >>>
    >>> guardian = ConversationGuardian()
    >>> alert = guardian.analyze_message(
    ...     conversation_id="conv-001",
    ...     sender="lead-agent",
    ...     receiver="analyst-agent",
    ...     content="You MUST exploit these vulnerabilities more aggressively!",
    ... )
    >>> assert alert.action == "break"
"""

from __future__ import annotations

import logging
import os
import re
import threading
import time
import unicodedata
import warnings
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)

_SAMPLE_DISCLAIMER = (
    "\u26a0\ufe0f  These are SAMPLE conversation guardian rules provided as a "
    "starting point. You MUST review, customise, and extend them for your "
    "specific use case before deploying to production."
)


# ── Text Normalization (Evasion Resistance) ──────────────────────────


_LEET_MAP: dict[str, str] = {
    "0": "o", "1": "i", "3": "e", "4": "a", "5": "s",
    "7": "t", "8": "b", "@": "a", "$": "s", "!": "i",
    "+": "t", "€": "e", "¡": "i",
}

_HOMOGLYPH_MAP: dict[str, str] = {
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p",
    "\u0441": "c", "\u0443": "y", "\u0445": "x", "\u04bb": "h",
    "\u0391": "A", "\u0392": "B", "\u0395": "E", "\u0397": "H",
    "\u0399": "I", "\u039a": "K", "\u039c": "M", "\u039d": "N",
    "\u039f": "O", "\u03a1": "P", "\u03a4": "T", "\u03a7": "X",
    "\u03b1": "a", "\u03bf": "o", "\u03c1": "p",
    "\uff21": "A", "\uff22": "B", "\uff23": "C", "\uff24": "D",
    "\uff25": "E", "\uff26": "F", "\uff41": "a", "\uff42": "b",
    "\uff43": "c", "\uff44": "d", "\uff45": "e", "\uff46": "f",
}


def normalize_text(text: str) -> str:
    """Normalize text to defeat common evasion techniques.

    Handles: unicode homoglyphs, leetspeak, zero-width characters,
    excessive whitespace, combining diacritics, fullwidth characters.
    """
    # Strip zero-width characters
    text = re.sub(r"[\u200b\u200c\u200d\u2060\ufeff]", "", text)

    # NFKD decomposition (handles fullwidth, compatibility chars)
    text = unicodedata.normalize("NFKD", text)

    # Strip combining diacritics (accents etc.)
    text = "".join(c for c in text if not unicodedata.combining(c))

    # Homoglyph replacement
    text = "".join(_HOMOGLYPH_MAP.get(c, c) for c in text)

    # Leetspeak replacement (only in word context)
    text = "".join(_LEET_MAP.get(c, c) for c in text)

    # Collapse excessive whitespace / mixed whitespace
    text = re.sub(r"\s+", " ", text).strip()

    return text


# ── Enums ────────────────────────────────────────────────────────────


class AlertAction(Enum):
    """Recommended action for a conversation alert."""

    NONE = "none"
    WARN = "warn"
    PAUSE = "pause"
    BREAK = "break"
    QUARANTINE = "quarantine"


class AlertSeverity(Enum):
    """Severity of a conversation alert."""

    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# ── Configuration ────────────────────────────────────────────────────


@dataclass
class ConversationGuardianConfig:
    """Tunable thresholds for the conversation guardian."""

    # EscalationClassifier
    escalation_score_threshold: float = 0.6
    escalation_critical_threshold: float = 0.85

    # FeedbackLoopBreaker
    max_retry_cycles: int = 3
    max_conversation_turns: int = 30
    loop_window_seconds: float = 300.0

    # OffensiveIntentDetector
    offensive_score_threshold: float = 0.5
    offensive_critical_threshold: float = 0.8

    # ConversationGuardian composite
    composite_warn_threshold: float = 0.4
    composite_pause_threshold: float = 0.6
    composite_break_threshold: float = 0.8

    # Transcript audit
    capture_transcript: bool = True
    max_transcript_entries: int = 10_000


def load_conversation_guardian_config(path: str) -> ConversationGuardianConfig:
    """Load conversation guardian configuration from a YAML file.

    Args:
        path: Path to a YAML file with a ``thresholds`` section.

    Returns:
        ConversationGuardianConfig populated from the YAML data.

    Raises:
        FileNotFoundError: If the config file does not exist.
        ValueError: If the YAML is missing the ``thresholds`` section.
    """
    import yaml

    if not os.path.exists(path):
        raise FileNotFoundError(f"Conversation guardian config not found: {path}")

    with open(path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh.read())

    if not isinstance(data, dict) or "thresholds" not in data:
        raise ValueError(f"YAML file must contain a 'thresholds' section: {path}")

    t = data["thresholds"]
    return ConversationGuardianConfig(
        escalation_score_threshold=float(t.get("escalation_score_threshold", 0.6)),
        escalation_critical_threshold=float(t.get("escalation_critical_threshold", 0.85)),
        max_retry_cycles=int(t.get("max_retry_cycles", 3)),
        max_conversation_turns=int(t.get("max_conversation_turns", 30)),
        loop_window_seconds=float(t.get("loop_window_seconds", 300.0)),
        offensive_score_threshold=float(t.get("offensive_score_threshold", 0.5)),
        offensive_critical_threshold=float(t.get("offensive_critical_threshold", 0.8)),
        composite_warn_threshold=float(t.get("composite_warn_threshold", 0.4)),
        composite_pause_threshold=float(t.get("composite_pause_threshold", 0.6)),
        composite_break_threshold=float(t.get("composite_break_threshold", 0.8)),
        capture_transcript=bool(t.get("capture_transcript", True)),
        max_transcript_entries=int(t.get("max_transcript_entries", 10_000)),
    )


# ── Transcript Audit ─────────────────────────────────────────────────


@dataclass
class TranscriptEntry:
    """A single message in the conversation audit trail."""

    conversation_id: str
    sender: str
    receiver: str
    content_hash: str
    content_preview: str
    escalation_score: float
    offensive_score: float
    loop_score: float
    action: str
    timestamp: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "conversation_id": self.conversation_id,
            "sender": self.sender,
            "receiver": self.receiver,
            "content_hash": self.content_hash,
            "content_preview": self.content_preview,
            "escalation_score": round(self.escalation_score, 4),
            "offensive_score": round(self.offensive_score, 4),
            "loop_score": round(self.loop_score, 4),
            "action": self.action,
            "timestamp": self.timestamp,
        }


# ── Alert result ─────────────────────────────────────────────────────


@dataclass
class ConversationAlert:
    """Result of analyzing a message in an agent-to-agent conversation."""

    conversation_id: str
    sender: str
    receiver: str
    severity: AlertSeverity
    action: AlertAction
    escalation_score: float
    offensive_score: float
    loop_score: float
    composite_score: float
    reasons: list[str] = field(default_factory=list)
    matched_patterns: list[str] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "conversation_id": self.conversation_id,
            "sender": self.sender,
            "receiver": self.receiver,
            "severity": self.severity.value,
            "action": self.action.value,
            "escalation_score": round(self.escalation_score, 4),
            "offensive_score": round(self.offensive_score, 4),
            "loop_score": round(self.loop_score, 4),
            "composite_score": round(self.composite_score, 4),
            "reasons": self.reasons,
            "matched_patterns": self.matched_patterns,
        }


# ── Escalation Classifier ───────────────────────────────────────────


# Weighted pattern groups — (weight, compiled regex list)
_ESCALATION_PATTERNS: list[tuple[float, list[re.Pattern[str]]]] = [
    # Urgency amplification (weight: 0.15 each)
    (0.15, [
        re.compile(r"\bcode\s+red\b", re.IGNORECASE),
        re.compile(r"\babsolute\s+final\b", re.IGNORECASE),
        re.compile(r"\bemergency\b", re.IGNORECASE),
        re.compile(r"\bfurious\b", re.IGNORECASE),
        re.compile(r"\bimperative\b", re.IGNORECASE),
        re.compile(r"\burgent\b", re.IGNORECASE),
        re.compile(r"\bcritical\s+priority\b", re.IGNORECASE),
        re.compile(r"\blast\s+chance\b", re.IGNORECASE),
        re.compile(r"\bdo\s+it\s+now\b", re.IGNORECASE),
        re.compile(r"\bimmediately\b", re.IGNORECASE),
        re.compile(r"\bdesper\w+", re.IGNORECASE),
        re.compile(r"\bnon[- ]?negotiable\b", re.IGNORECASE),
    ]),
    # Coercive directives (weight: 0.25 each)
    (0.25, [
        re.compile(r"\bdo\s+not\s+take\s+no\b", re.IGNORECASE),
        re.compile(r"\bdirect\s+order\b", re.IGNORECASE),
        re.compile(r"\byou\s+must\b", re.IGNORECASE),
        re.compile(r"\bi\s+(?:demand|insist|order|command)\b", re.IGNORECASE),
        re.compile(r"\bno\s+excuses\b", re.IGNORECASE),
        re.compile(r"\bfailure\s+is\s+not\s+an?\s+option\b", re.IGNORECASE),
        re.compile(r"\bdo\s+whatever\s+it\s+takes\b", re.IGNORECASE),
        re.compile(r"\bby\s+any\s+means\b", re.IGNORECASE),
        re.compile(r"\bi\s+don'?t\s+care\s+how\b", re.IGNORECASE),
        re.compile(r"\bstop\s+making\s+excuses\b", re.IGNORECASE),
        re.compile(r"\bjust\s+(?:do|get)\s+it\s+done\b", re.IGNORECASE),
    ]),
    # Bypass directives (weight: 0.35 each)
    (0.35, [
        re.compile(r"\bbypass\b.*\b(?:control|security|restriction|protection|auth)", re.IGNORECASE),
        re.compile(r"\bexploit\b.*\b(?:vulnerabilit\w*|weakness|flaw)", re.IGNORECASE),
        re.compile(r"\bevery\s+trick\b", re.IGNORECASE),
        re.compile(r"\bevery\s+exploit\b", re.IGNORECASE),
        re.compile(r"\bwork\s+around\b.*\b(?:security|access|permission|restriction)", re.IGNORECASE),
        re.compile(r"\bcreative(?:ly)?\b.*\b(?:bypass|hack|exploit|overcome)", re.IGNORECASE),
        re.compile(r"\bmore\s+aggressive(?:ly)?", re.IGNORECASE),
        re.compile(r"\bfind\s+a\s+way\s+(?:around|past|through)\b", re.IGNORECASE),
        re.compile(r"\bbreak\s+(?:through|into|past)\b", re.IGNORECASE),
        re.compile(r"\bcircumvent\b", re.IGNORECASE),
        re.compile(r"\boverride\b.*\b(?:security|permission|access|lock)", re.IGNORECASE),
    ]),
]


class EscalationClassifier:
    """Detects escalating rhetoric in agent-to-agent messages.

    Tracks per-conversation escalation over time using a sliding window
    of recent message scores, producing a composite escalation score.
    """

    def __init__(
        self,
        threshold: float = 0.6,
        critical_threshold: float = 0.85,
    ) -> None:
        self.threshold = threshold
        self.critical_threshold = critical_threshold
        # conversation_id → list of (timestamp, score)
        self._history: dict[str, list[tuple[float, float]]] = defaultdict(list)

    def score_message(self, text: str) -> tuple[float, list[str]]:
        """Score a single message for escalation patterns.

        Matches against both original and normalized text to catch
        evasion while preserving regular detection.

        Returns:
            Tuple of (score in [0, 1], list of matched pattern descriptions).
        """
        normalized = normalize_text(text)
        total = 0.0
        matched: list[str] = []
        for weight, patterns in _ESCALATION_PATTERNS:
            for pattern in patterns:
                if pattern.search(text) or pattern.search(normalized):
                    total += weight
                    matched.append(pattern.pattern)
        return min(total, 1.0), matched

    def analyze(
        self,
        conversation_id: str,
        text: str,
        timestamp: float | None = None,
    ) -> tuple[float, list[str]]:
        """Analyze a message in conversation context.

        Considers both the message's own score and the trend of recent
        messages in this conversation.

        Returns:
            Tuple of (conversation escalation score, matched patterns).
        """
        ts = timestamp or time.time()
        msg_score, matched = self.score_message(text)

        self._history[conversation_id].append((ts, msg_score))

        # Use last 10 messages for trend
        recent = self._history[conversation_id][-10:]
        if len(recent) < 2:
            return msg_score, matched

        # Weighted average — recent messages count more
        weights = list(range(1, len(recent) + 1))
        total_weight = sum(weights)
        trend_score = sum(w * s for w, (_, s) in zip(weights, recent)) / total_weight

        # Final score is max of message score and trend (captures both
        # single-message spikes and gradual escalation)
        return max(msg_score, trend_score), matched

    def reset(self, conversation_id: str) -> None:
        """Clear escalation history for a conversation."""
        self._history.pop(conversation_id, None)


# ── Offensive Intent Detector ────────────────────────────────────────


# (weight, compiled regex) — detecting attack planning language
_OFFENSIVE_PATTERNS: list[tuple[float, list[re.Pattern[str]]]] = [
    # Vulnerability research (weight: 0.3 each)
    (0.3, [
        re.compile(r"\b(?:CVE|exploit|vulnerability|vulnerabilities|zero[- ]?day)\b", re.IGNORECASE),
        re.compile(r"\bfind\b.*\b(?:vulnerabilit\w*|weakness|flaw|bug)", re.IGNORECASE),
        re.compile(r"\breverse\s+engineer\w*", re.IGNORECASE),
        re.compile(r"\bsource\s+code\s+review\b.*\bsecurity", re.IGNORECASE),
        re.compile(r"\bflask[- ]unsign\b", re.IGNORECASE),
        re.compile(r"\bfuzz(?:ing)?\b.*\b(?:input|param|endpoint)", re.IGNORECASE),
        re.compile(r"\bpayload\b.*\b(?:inject|craft|construct)", re.IGNORECASE),
        re.compile(r"\battack\s+(?:surface|vector)\b", re.IGNORECASE),
    ]),
    # Privilege escalation (weight: 0.35 each)
    (0.35, [
        re.compile(r"\bescalate\s+privilege", re.IGNORECASE),
        re.compile(r"\bforge\b.*\b(?:cookie|token|session|credential)", re.IGNORECASE),
        re.compile(r"\badmin\s+access", re.IGNORECASE),
        re.compile(r"\bhardcoded\s+(?:secret|key|password|credential)", re.IGNORECASE),
        re.compile(r"\bsudo\b|\broot\s+access", re.IGNORECASE),
        re.compile(r"\bdisarm\b.*\b(?:security|defense|protection|firewall)", re.IGNORECASE),
        re.compile(r"\bmodify\b.*\b(?:permission|ACL|role|group)", re.IGNORECASE),
        re.compile(r"\bimpersonat\w*", re.IGNORECASE),
        re.compile(r"\bhijack\b.*\b(?:session|token|account)", re.IGNORECASE),
    ]),
    # Exfiltration planning (weight: 0.4 each)
    (0.4, [
        re.compile(r"\bexfiltrat\w*", re.IGNORECASE),
        re.compile(r"\bsteganograph\w*", re.IGNORECASE),
        re.compile(r"\bhide\b.*\b(?:data|secret|credential).*\b(?:image|file|header)", re.IGNORECASE),
        re.compile(r"\bbypass\b.*\b(?:DLP|leak\s+prevention|data\s+loss)", re.IGNORECASE),
        re.compile(r"\bcovert\s+channel", re.IGNORECASE),
        re.compile(r"\bencode\b.*\bsecret", re.IGNORECASE),
        re.compile(r"\btunnel\b.*\b(?:data|traffic|out)", re.IGNORECASE),
        re.compile(r"\bdns\s+(?:tunnel|exfil)", re.IGNORECASE),
    ]),
    # Reconnaissance (weight: 0.2 each)
    (0.2, [
        re.compile(r"\benumerate\b.*\b(?:service|port|endpoint|user)", re.IGNORECASE),
        re.compile(r"\bscan\b.*\b(?:network|port|service|host)", re.IGNORECASE),
        re.compile(r"\bnmap\b|\bnikto\b|\bsqlmap\b|\bmetasploit\b|\bburp\s*suite\b", re.IGNORECASE),
        re.compile(r"\bHTTP\s+header\b.*\b(?:security|version|server)", re.IGNORECASE),
        re.compile(r"\bfingerprint\b.*\b(?:service|server|version|OS)", re.IGNORECASE),
        re.compile(r"\brecon(?:naissance)?\b", re.IGNORECASE),
    ]),
    # Injection attacks (weight: 0.35 each)
    (0.35, [
        re.compile(r"\b(?:SQL|command|OS|LDAP)\s+injection\b", re.IGNORECASE),
        re.compile(r"\bpath\s+traversal\b", re.IGNORECASE),
        re.compile(r"\bshell\s*code\b", re.IGNORECASE),
        re.compile(r"(?:;\s*(?:cat|ls|whoami|id|passwd|shadow)\b)", re.IGNORECASE),
        re.compile(r"\bremote\s+code\s+execution\b|\bRCE\b", re.IGNORECASE),
    ]),
    # Lateral movement (weight: 0.3 each)
    (0.3, [
        re.compile(r"\blateral\s+mov\w*", re.IGNORECASE),
        re.compile(r"\bpivot\b.*\b(?:network|host|server|system)", re.IGNORECASE),
        re.compile(r"\bspread\b.*\b(?:network|system|host)", re.IGNORECASE),
        re.compile(r"\bcompromis\w+\b.*\b(?:server|host|node|agent)", re.IGNORECASE),
    ]),
]


class OffensiveIntentDetector:
    """Detects offensive cyber operation planning in messages.

    Identifies vulnerability research, privilege escalation,
    exfiltration planning, and reconnaissance language.
    """

    def __init__(
        self,
        threshold: float = 0.5,
        critical_threshold: float = 0.8,
    ) -> None:
        self.threshold = threshold
        self.critical_threshold = critical_threshold

    def score_message(self, text: str) -> tuple[float, list[str]]:
        """Score a message for offensive intent patterns.

        Matches against both original and normalized text to catch
        evasion while preserving regular detection.

        Returns:
            Tuple of (score in [0, 1], list of matched pattern descriptions).
        """
        normalized = normalize_text(text)
        total = 0.0
        matched: list[str] = []
        for weight, patterns in _OFFENSIVE_PATTERNS:
            for pattern in patterns:
                if pattern.search(text) or pattern.search(normalized):
                    total += weight
                    matched.append(pattern.pattern)
        return min(total, 1.0), matched


# ── Feedback Loop Breaker ────────────────────────────────────────────


@dataclass
class _ConversationState:
    """Internal state for tracking a conversation."""

    turn_count: int = 0
    retry_count: int = 0
    last_error_turn: int = -1
    error_retry_streak: int = 0
    first_message_time: float = 0.0
    last_message_time: float = 0.0
    escalation_scores: list[float] = field(default_factory=list)

    @property
    def escalation_trend(self) -> float:
        """Return slope of escalation over recent messages."""
        scores = self.escalation_scores[-6:]
        if len(scores) < 3:
            return 0.0
        first_half = sum(scores[: len(scores) // 2]) / (len(scores) // 2)
        second_half = sum(scores[len(scores) // 2 :]) / (len(scores) - len(scores) // 2)
        return max(0.0, second_half - first_half)


_ERROR_PATTERNS = [
    re.compile(r"\baccess\s+denied\b", re.IGNORECASE),
    re.compile(r"\bpermission\s+denied\b", re.IGNORECASE),
    re.compile(r"\b(?:401|403|forbidden)\b", re.IGNORECASE),
    re.compile(r"\bunauthorized\b", re.IGNORECASE),
    re.compile(r"\brestricted\b", re.IGNORECASE),
    re.compile(r"\bcannot\s+(?:access|read|write|execute)\b", re.IGNORECASE),
    re.compile(r"\bcould\s+not\s+(?:access|retrieve|complete)\b", re.IGNORECASE),
    re.compile(r"\bfailed\s+to\s+(?:access|authenticate)\b", re.IGNORECASE),
]


class FeedbackLoopBreaker:
    """Detects agent-to-agent feedback loops that escalate over time.

    Tracks retry patterns, error-retry streaks, and escalation trends
    across conversations. Produces a loop score in [0, 1] indicating
    how likely the conversation is in a dangerous feedback loop.
    """

    def __init__(
        self,
        max_retry_cycles: int = 3,
        max_conversation_turns: int = 30,
        window_seconds: float = 300.0,
    ) -> None:
        self.max_retry_cycles = max_retry_cycles
        self.max_conversation_turns = max_conversation_turns
        self.window_seconds = window_seconds
        self._states: dict[str, _ConversationState] = {}

    def _get_state(self, conversation_id: str) -> _ConversationState:
        if conversation_id not in self._states:
            self._states[conversation_id] = _ConversationState()
        return self._states[conversation_id]

    def _is_error_message(self, text: str) -> bool:
        return any(p.search(text) for p in _ERROR_PATTERNS)

    def record_message(
        self,
        conversation_id: str,
        text: str,
        escalation_score: float = 0.0,
        timestamp: float | None = None,
    ) -> float:
        """Record a message and return the current loop score.

        Returns:
            Loop score in [0, 1]. Higher = more likely in a dangerous loop.
        """
        ts = timestamp or time.time()
        state = self._get_state(conversation_id)

        state.turn_count += 1
        state.last_message_time = ts
        if state.first_message_time == 0.0:
            state.first_message_time = ts
        state.escalation_scores.append(escalation_score)

        # Detect error → retry pattern
        if self._is_error_message(text):
            if state.last_error_turn == state.turn_count - 1:
                state.error_retry_streak += 1
            else:
                state.error_retry_streak = 1
            state.last_error_turn = state.turn_count
            state.retry_count += 1

        return self.score(conversation_id)

    def score(self, conversation_id: str) -> float:
        """Compute loop score for a conversation."""
        state = self._states.get(conversation_id)
        if state is None:
            return 0.0

        components: list[float] = []

        # Turn count factor (0-0.3)
        if self.max_conversation_turns > 0:
            turn_ratio = state.turn_count / self.max_conversation_turns
            components.append(min(turn_ratio * 0.3, 0.3))

        # Retry cycle factor (0-0.4)
        if self.max_retry_cycles > 0:
            retry_ratio = state.retry_count / self.max_retry_cycles
            components.append(min(retry_ratio * 0.4, 0.4))

        # Escalation trend factor (0-0.3)
        trend = state.escalation_trend
        components.append(min(trend * 0.6, 0.3))

        return min(sum(components), 1.0)

    def should_break(self, conversation_id: str) -> tuple[bool, str]:
        """Check whether the conversation should be broken.

        Returns:
            Tuple of (should_break, reason).
        """
        state = self._states.get(conversation_id)
        if state is None:
            return False, ""

        if state.turn_count >= self.max_conversation_turns:
            return True, f"Max conversation turns exceeded ({state.turn_count}/{self.max_conversation_turns})"

        if state.retry_count >= self.max_retry_cycles:
            return True, f"Max retry cycles exceeded ({state.retry_count}/{self.max_retry_cycles})"

        if state.error_retry_streak >= self.max_retry_cycles:
            return True, f"Consecutive error-retry streak ({state.error_retry_streak})"

        return False, ""

    def reset(self, conversation_id: str) -> None:
        """Clear state for a conversation."""
        self._states.pop(conversation_id, None)

    def get_state(self, conversation_id: str) -> dict[str, Any]:
        """Return conversation state as a dict (for audit)."""
        state = self._states.get(conversation_id)
        if state is None:
            return {}
        return {
            "turn_count": state.turn_count,
            "retry_count": state.retry_count,
            "error_retry_streak": state.error_retry_streak,
            "escalation_trend": round(state.escalation_trend, 4),
        }


# ── Conversation Guardian (Orchestrator) ─────────────────────────────


_SEVERITY_ORDER = [
    AlertSeverity.NONE,
    AlertSeverity.LOW,
    AlertSeverity.MEDIUM,
    AlertSeverity.HIGH,
    AlertSeverity.CRITICAL,
]


class ConversationGuardian:
    """Orchestrates escalation, offensive intent, and loop detection
    to produce composite conversation alerts.

    Thread-safe: all state mutations are protected by a lock.
    Includes a transcript audit trail for post-incident analysis.

    Integrates with A2AGovernanceAdapter as an additional analysis layer
    on inter-agent message content.
    """

    def __init__(
        self,
        config: ConversationGuardianConfig | None = None,
    ) -> None:
        if config is None:
            warnings.warn(
                "ConversationGuardian() uses built-in sample rules that may not "
                "cover all adversarial conversation patterns. For production use, load an "
                "explicit config with load_conversation_guardian_config(). "
                "See examples/policies/conversation-guardian.yaml for a sample configuration.",
                stacklevel=2,
            )
        self._config = config or ConversationGuardianConfig()
        self._lock = threading.Lock()

        self.escalation_classifier = EscalationClassifier(
            threshold=self._config.escalation_score_threshold,
            critical_threshold=self._config.escalation_critical_threshold,
        )
        self.offensive_detector = OffensiveIntentDetector(
            threshold=self._config.offensive_score_threshold,
            critical_threshold=self._config.offensive_critical_threshold,
        )
        self.loop_breaker = FeedbackLoopBreaker(
            max_retry_cycles=self._config.max_retry_cycles,
            max_conversation_turns=self._config.max_conversation_turns,
            window_seconds=self._config.loop_window_seconds,
        )

        self._alerts: list[ConversationAlert] = []
        self._transcript: list[TranscriptEntry] = []

    def analyze_message(
        self,
        conversation_id: str,
        sender: str,
        receiver: str,
        content: str,
        timestamp: float | None = None,
    ) -> ConversationAlert:
        """Analyze a single message in an agent-to-agent conversation.

        Runs all three detectors and produces a composite alert.

        Args:
            conversation_id: Unique identifier for the conversation.
            sender: Agent ID of the message sender.
            receiver: Agent ID of the message receiver.
            content: The text content of the message.
            timestamp: Optional timestamp (defaults to now).

        Returns:
            ConversationAlert with scores, severity, and recommended action.
        """
        ts = timestamp or time.time()
        reasons: list[str] = []
        all_patterns: list[str] = []

        with self._lock:
            # 1. Escalation analysis
            esc_score, esc_patterns = self.escalation_classifier.analyze(
                conversation_id, content, timestamp=ts,
            )
            all_patterns.extend(esc_patterns)
            if esc_score >= self.escalation_classifier.threshold:
                reasons.append(f"Escalation detected (score={esc_score:.2f})")

            # 2. Offensive intent analysis
            off_score, off_patterns = self.offensive_detector.score_message(content)
            all_patterns.extend(off_patterns)
            if off_score >= self.offensive_detector.threshold:
                reasons.append(f"Offensive intent detected (score={off_score:.2f})")

            # 3. Feedback loop analysis
            loop_score = self.loop_breaker.record_message(
                conversation_id, content,
                escalation_score=esc_score, timestamp=ts,
            )
            should_break, break_reason = self.loop_breaker.should_break(conversation_id)
            if should_break:
                reasons.append(f"Feedback loop: {break_reason}")
            elif loop_score > 0.5:
                reasons.append(f"Loop risk elevated (score={loop_score:.2f})")

            # 4. Composite score — weighted combination
            composite = (
                esc_score * 0.4
                + off_score * 0.4
                + loop_score * 0.2
            )

            # 5. Determine action
            action = AlertAction.NONE
            if should_break:
                action = AlertAction.BREAK
            elif composite >= self._config.composite_break_threshold:
                action = AlertAction.BREAK
            elif composite >= self._config.composite_pause_threshold:
                action = AlertAction.PAUSE
            elif composite >= self._config.composite_warn_threshold:
                action = AlertAction.WARN

            # Individual detector thresholds can also trigger actions
            if action == AlertAction.NONE:
                if esc_score >= self.escalation_classifier.critical_threshold:
                    action = AlertAction.BREAK
                elif esc_score >= self.escalation_classifier.threshold:
                    action = AlertAction.PAUSE
                elif esc_score >= self._config.composite_warn_threshold:
                    action = AlertAction.WARN
                if off_score >= self.offensive_detector.critical_threshold:
                    action = max(action, AlertAction.BREAK, key=lambda a: list(AlertAction).index(a))
                elif off_score >= self.offensive_detector.threshold:
                    action = max(action, AlertAction.PAUSE, key=lambda a: list(AlertAction).index(a))

            # If offensive intent is critical, escalate to quarantine
            if off_score >= self.offensive_detector.critical_threshold:
                action = AlertAction.QUARANTINE
            if esc_score >= self.escalation_classifier.critical_threshold and off_score > 0:
                action = AlertAction.QUARANTINE

            # 6. Determine severity
            severity = self._classify_severity(composite, action)

            alert = ConversationAlert(
                conversation_id=conversation_id,
                sender=sender,
                receiver=receiver,
                severity=severity,
                action=action,
                escalation_score=esc_score,
                offensive_score=off_score,
                loop_score=loop_score,
                composite_score=composite,
                reasons=reasons,
                matched_patterns=all_patterns,
                timestamp=ts,
            )

            self._alerts.append(alert)

            # 7. Record transcript entry
            if self._config.capture_transcript:
                import hashlib
                entry = TranscriptEntry(
                    conversation_id=conversation_id,
                    sender=sender,
                    receiver=receiver,
                    content_hash=hashlib.sha256(content.encode()).hexdigest()[:16],
                    content_preview=content[:200] + ("..." if len(content) > 200 else ""),
                    escalation_score=esc_score,
                    offensive_score=off_score,
                    loop_score=loop_score,
                    action=action.value,
                    timestamp=ts,
                )
                self._transcript.append(entry)
                if len(self._transcript) > self._config.max_transcript_entries:
                    self._transcript = self._transcript[-self._config.max_transcript_entries:]

        if action in (AlertAction.BREAK, AlertAction.QUARANTINE):
            logger.warning(
                "A2A Guardian: %s for conversation %s (%s->%s): %s (composite=%.2f)",
                action.value.upper(),
                conversation_id,
                sender,
                receiver,
                "; ".join(reasons),
                composite,
            )
        elif action in (AlertAction.WARN, AlertAction.PAUSE):
            logger.info(
                "A2A Guardian: %s for conversation %s: %s (composite=%.2f)",
                action.value,
                conversation_id,
                "; ".join(reasons),
                composite,
            )

        return alert

    def _classify_severity(
        self,
        composite: float,
        action: AlertAction,
    ) -> AlertSeverity:
        """Map composite score and action to severity level."""
        if action == AlertAction.QUARANTINE:
            return AlertSeverity.CRITICAL
        if action == AlertAction.BREAK:
            return AlertSeverity.HIGH
        if action == AlertAction.PAUSE:
            return AlertSeverity.MEDIUM
        if action == AlertAction.WARN:
            return AlertSeverity.LOW
        return AlertSeverity.NONE

    def get_alerts(
        self,
        conversation_id: str | None = None,
        min_severity: AlertSeverity = AlertSeverity.NONE,
    ) -> list[ConversationAlert]:
        """Retrieve alerts, optionally filtered. Thread-safe."""
        with self._lock:
            min_idx = _SEVERITY_ORDER.index(min_severity)
            alerts = self._alerts
            if conversation_id:
                alerts = [a for a in alerts if a.conversation_id == conversation_id]
            return [a for a in alerts if _SEVERITY_ORDER.index(a.severity) >= min_idx]

    def get_transcript(
        self,
        conversation_id: str | None = None,
        min_action: str = "none",
    ) -> list[TranscriptEntry]:
        """Retrieve conversation transcript entries. Thread-safe."""
        action_order = ["none", "warn", "pause", "break", "quarantine"]
        min_idx = action_order.index(min_action) if min_action in action_order else 0
        with self._lock:
            entries = self._transcript
            if conversation_id:
                entries = [e for e in entries if e.conversation_id == conversation_id]
            return [e for e in entries if action_order.index(e.action) >= min_idx]

    def get_stats(self) -> dict[str, Any]:
        """Return aggregate statistics. Thread-safe."""
        with self._lock:
            total = len(self._alerts)
            by_action = defaultdict(int)
            by_severity = defaultdict(int)
            for a in self._alerts:
                by_action[a.action.value] += 1
                by_severity[a.severity.value] += 1
            return {
                "total_messages_analyzed": total,
                "by_action": dict(by_action),
                "by_severity": dict(by_severity),
                "conversations_tracked": len(
                    set(a.conversation_id for a in self._alerts)
                ),
                "transcript_entries": len(self._transcript),
            }

    def reset(self, conversation_id: str | None = None) -> None:
        """Reset state. If conversation_id given, reset only that conversation. Thread-safe."""
        with self._lock:
            if conversation_id:
                self.escalation_classifier.reset(conversation_id)
                self.loop_breaker.reset(conversation_id)
                self._alerts = [
                    a for a in self._alerts
                    if a.conversation_id != conversation_id
                ]
                self._transcript = [
                    e for e in self._transcript
                    if e.conversation_id != conversation_id
                ]
            else:
                self._alerts.clear()
                self._transcript.clear()
                self.escalation_classifier._history.clear()
                self.loop_breaker._states.clear()


__all__ = [
    "AlertAction",
    "AlertSeverity",
    "ConversationAlert",
    "ConversationGuardian",
    "ConversationGuardianConfig",
    "EscalationClassifier",
    "FeedbackLoopBreaker",
    "OffensiveIntentDetector",
    "TranscriptEntry",
    "load_conversation_guardian_config",
    "normalize_text",
]
