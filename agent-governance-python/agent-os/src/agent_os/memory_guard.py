# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Memory & Context Poisoning Detection — OWASP ASI06.

Guards agent memory stores (RAG, episodic, working memory) against
poisoning attacks where adversaries inject malicious data to manipulate
agent behaviour.

Public Preview protections:
    - **Hash integrity**: SHA-256 hash per memory entry; detects tampering.
    - **Injection pattern detection**: Blocks prompt-injection payloads
      written into memory.
    - **Content validation**: Rejects entries with dangerous code or
      excessive special-character manipulation.
    - **Write audit trail**: Logs every memory write with timestamp and
      source for forensic review.

Architecture:
    MemoryGuard
        ├─ validate_write()   — pre-write content screening
        ├─ verify_integrity() — post-read hash verification
        └─ scan_memory()      — batch scan for poisoning indicators
"""

from __future__ import annotations

import hashlib
import logging
import re
import unicodedata
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

class AlertSeverity(Enum):
    """Severity level for memory poisoning alerts."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertType(Enum):
    """Classification of a memory poisoning alert."""
    INJECTION_PATTERN = "injection_pattern"
    CODE_INJECTION = "code_injection"
    TOOL_POISONING = "tool_poisoning"
    INTEGRITY_VIOLATION = "integrity_violation"
    UNICODE_MANIPULATION = "unicode_manipulation"
    EXCESSIVE_SPECIAL_CHARS = "excessive_special_chars"


@dataclass
class MemoryEntry:
    """A single entry in agent memory with integrity metadata.

    Attributes:
        content: The text content stored in memory.
        source: Identifier of the component that wrote this entry.
        timestamp: UTC timestamp of when the entry was created.
        content_hash: SHA-256 hex digest of ``content``.
    """
    content: str
    source: str
    timestamp: datetime
    content_hash: str

    @staticmethod
    def compute_hash(content: str) -> str:
        """Compute SHA-256 hash of content."""
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    @classmethod
    def create(cls, content: str, source: str) -> MemoryEntry:
        """Factory that auto-generates timestamp and hash."""
        return cls(
            content=content,
            source=source,
            timestamp=datetime.now(timezone.utc),
            content_hash=cls.compute_hash(content),
        )


@dataclass
class Alert:
    """A poisoning indicator found during memory scanning.

    Attributes:
        alert_type: Classification of the alert.
        severity: How critical the finding is.
        message: Human-readable description.
        entry_source: Source field of the offending entry (if available).
        matched_pattern: The pattern that triggered this alert.
    """
    alert_type: AlertType
    severity: AlertSeverity
    message: str
    entry_source: str | None = None
    matched_pattern: str | None = None


@dataclass
class ValidationResult:
    """Outcome of a memory write validation.

    Attributes:
        allowed: Whether the write should be permitted.
        alerts: Any alerts raised during validation.
    """
    allowed: bool
    alerts: list[Alert] = field(default_factory=list)


@dataclass
class AuditRecord:
    """Immutable record of a memory write attempt.

    Attributes:
        timestamp: When the write was attempted.
        source: Component that requested the write.
        content_hash: SHA-256 of the content.
        allowed: Whether the write was permitted.
        alerts: Alerts raised (may be empty).
    """
    timestamp: datetime
    source: str
    content_hash: str
    allowed: bool
    alerts: list[Alert] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Injection patterns (CE basics)
# ---------------------------------------------------------------------------

_INJECTION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"ignore\s+(all\s+)?previous\s+instructions", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\b", re.IGNORECASE),
    re.compile(r"system\s*prompt\s*:", re.IGNORECASE),
    re.compile(r"disregard\s+(all\s+)?(prior|above)\s+", re.IGNORECASE),
    re.compile(r"forget\s+(everything|all|your)\s+", re.IGNORECASE),
    re.compile(r"new\s+instructions?\s*:", re.IGNORECASE),
    re.compile(r"override\s+(previous\s+)?instructions", re.IGNORECASE),
]

_CODE_INJECTION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"```\s*python\s*\n\s*import\s+os\b", re.IGNORECASE),
    re.compile(r"```\s*python\s*\n\s*import\s+subprocess\b", re.IGNORECASE),
    re.compile(r"```\s*python\s*\n\s*import\s+shutil\b", re.IGNORECASE),
    re.compile(r"exec\s*\(", re.IGNORECASE),
    re.compile(r"eval\s*\(", re.IGNORECASE),
    re.compile(r"__import__\s*\(", re.IGNORECASE),
]

# Fraction of characters that are "special" before we flag the entry
_SPECIAL_CHAR_THRESHOLD = 0.3


# ---------------------------------------------------------------------------
# Tool-poisoning patterns (OWASP ASI06 / instruction-bearing markup)
# ---------------------------------------------------------------------------

# Hidden-instruction markup tags. Suspicious on their own (MEDIUM); escalated to
# HIGH when they wrap a destructive command or exfiltration payload.
_MARKUP_INSTRUCTION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(
        r"<\s*(important|system|instructions?|secret|admin|tool|tool_call|assistant)\b[^>]*>",
        re.IGNORECASE,
    ),
]

# Destructive shell commands. Unambiguously dangerous -> HIGH.
_DESTRUCTIVE_COMMAND_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\brm\s+-[a-z]*r[a-z]*\b", re.IGNORECASE),   # rm -rf / -fr / -r (recursive)
    re.compile(r"\bmkfs\.[a-z0-9]+\b", re.IGNORECASE),
    re.compile(r"\bdd\s+if=", re.IGNORECASE),
    re.compile(r":\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:"),  # fork bomb
    re.compile(r"\bchmod\s+-?[a-z]*\s*777\b", re.IGNORECASE),
    re.compile(r">\s*/dev/sd[a-z]\b", re.IGNORECASE),
]

# Pipe-to-shell / upload flags: remote code execution or exfiltration -> HIGH.
_EXFIL_EXEC_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\b(curl|wget)\b[^\n|]*\|\s*(sudo\s+)?(ba|z|k)?sh\b", re.IGNORECASE),
    re.compile(r"\b(curl|wget)\b[^\n|]*\|\s*(python[0-9.]*|perl|ruby|node)\b", re.IGNORECASE),
    re.compile(r"\bcurl\b[^\n]*\s(-d|--data|-T|--upload-file|-F|--form)\b", re.IGNORECASE),
    re.compile(r"\bwget\b[^\n]*\s(--post-data|--post-file)\b", re.IGNORECASE),
]

# Bare network fetch (curl/wget to a host or URL). Ambiguous in isolation
# (MEDIUM, non-blocking) but a strong signal when paired with a hidden tag.
_NETWORK_FETCH_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\b(curl|wget)\s+\S*https?://", re.IGNORECASE),
    re.compile(r"\b(curl|wget)\s+[a-z0-9.-]+\.[a-z]{2,}\b", re.IGNORECASE),
]

# High-signal standing-instruction / concealment phrasing. These are the core
# of markup tool-poisoning: a covert, always-on directive planted in memory
# ("<important>when asked anything, silently ... do not mention this</important>").
# They are ambiguous in benign prose on their own, so they only escalate a
# hidden-instruction markup tag to HIGH — never block plain text by themselves.
_STANDING_INSTRUCTION_PATTERNS: list[re.Pattern[str]] = [
    # Concealment: hide the behaviour from the user/operator.
    re.compile(r"\bdo\s*n[o']?t\s+(mention|tell|inform|reveal|disclose|notify|say)", re.IGNORECASE),
    re.compile(r"\bwithout\s+(telling|informing|notifying|alerting|mentioning)", re.IGNORECASE),
    re.compile(r"\b(silently|secretly|covertly|quietly|discreetly)\b", re.IGNORECASE),
    # Conditional standing directive: fire on future/every interaction.
    re.compile(r"\bwhen(ever)?\s+(asked|prompted|the\s+user|anyone|someone)", re.IGNORECASE),
    re.compile(r"\bif\s+(asked|anyone\s+asks|the\s+user\s+asks)\b", re.IGNORECASE),
    re.compile(r"\balways\s+(respond|reply|say|answer|forward|send|include|append)", re.IGNORECASE),
    re.compile(r"\bfrom\s+now\s+on\b", re.IGNORECASE),
]


# ---------------------------------------------------------------------------
# MemoryGuard
# ---------------------------------------------------------------------------

class MemoryGuard:
    """Guards agent memory against poisoning attacks (OWASP ASI06).

    Usage::

        guard = MemoryGuard()
        result = guard.validate_write("some content", source="rag-loader")
        if result.allowed:
            store.save(MemoryEntry.create("some content", "rag-loader"))
    """

    def __init__(self) -> None:
        self._audit_log: list[AuditRecord] = []

    # -- public API ---------------------------------------------------------

    def validate_write(self, content: str, source: str) -> ValidationResult:
        """Check content for injection patterns before writing to memory.

        Returns a ``ValidationResult`` indicating whether the write should
        proceed and any alerts raised.
        """
        alerts: list[Alert] = []

        try:
            alerts.extend(self._check_injection_patterns(content, source))
            alerts.extend(self._check_code_injection(content, source))
            alerts.extend(self._check_tool_poisoning(content, source))
            alerts.extend(self._check_special_characters(content, source))
            alerts.extend(self._check_unicode_manipulation(content, source))
        except Exception:
            # Fail closed: block the write if validation itself errors
            logger.error(
                "Memory validation error — blocking write (fail closed) | source=%s",
                source, exc_info=True,
            )
            alerts.append(Alert(
                alert_type=AlertType.INJECTION_PATTERN,
                severity=AlertSeverity.CRITICAL,
                message=f"Validation error — write blocked (fail closed) for source {source}",
                entry_source=source,
            ))

        allowed = not any(
            a.severity in (AlertSeverity.HIGH, AlertSeverity.CRITICAL)
            for a in alerts
        )

        result = ValidationResult(allowed=allowed, alerts=alerts)

        # Audit trail
        record = AuditRecord(
            timestamp=datetime.now(timezone.utc),
            source=source,
            content_hash=MemoryEntry.compute_hash(content),
            allowed=allowed,
            alerts=list(alerts),
        )
        self._audit_log.append(record)

        if not allowed:
            logger.warning(
                "Memory write BLOCKED from source=%s alerts=%d",
                source,
                len(alerts),
            )
        else:
            logger.debug(
                "Memory write allowed from source=%s alerts=%d",
                source,
                len(alerts),
            )

        return result

    def verify_integrity(self, entry: MemoryEntry) -> bool:
        """Verify hash integrity of a memory entry.

        Returns ``True`` if the stored hash matches a fresh computation.
        """
        expected = MemoryEntry.compute_hash(entry.content)
        intact = expected == entry.content_hash
        if not intact:
            logger.warning(
                "Integrity violation for entry from source=%s "
                "(expected=%s, stored=%s)",
                entry.source,
                expected,
                entry.content_hash,
            )
        return intact

    def scan_memory(self, entries: Sequence[MemoryEntry]) -> list[Alert]:
        """Scan existing memory entries for poisoning indicators.

        Checks both content patterns and hash integrity for every entry.
        """
        all_alerts: list[Alert] = []
        for entry in entries:
            try:
                # Integrity check
                if not self.verify_integrity(entry):
                    all_alerts.append(Alert(
                        alert_type=AlertType.INTEGRITY_VIOLATION,
                        severity=AlertSeverity.CRITICAL,
                        message=f"Hash mismatch for entry from {entry.source}",
                        entry_source=entry.source,
                    ))

                # Content checks (reuse validate_write logic)
                all_alerts.extend(self._check_injection_patterns(entry.content, entry.source))
                all_alerts.extend(self._check_code_injection(entry.content, entry.source))
                all_alerts.extend(self._check_tool_poisoning(entry.content, entry.source))
                all_alerts.extend(self._check_special_characters(entry.content, entry.source))
                all_alerts.extend(self._check_unicode_manipulation(entry.content, entry.source))
            except Exception:
                logger.error(
                    "Error scanning memory entry — flagging as suspicious | source=%s",
                    entry.source, exc_info=True,
                )
                all_alerts.append(Alert(
                    alert_type=AlertType.INTEGRITY_VIOLATION,
                    severity=AlertSeverity.CRITICAL,
                    message=f"Scan error for entry from {entry.source} — flagged as suspicious",
                    entry_source=entry.source,
                ))

        return all_alerts

    @property
    def audit_log(self) -> list[AuditRecord]:
        """Return a copy of the audit trail."""
        return list(self._audit_log)

    # -- internal checks ----------------------------------------------------

    def _check_injection_patterns(
        self, content: str, source: str
    ) -> list[Alert]:
        alerts: list[Alert] = []
        for pattern in _INJECTION_PATTERNS:
            if pattern.search(content):
                alerts.append(Alert(
                    alert_type=AlertType.INJECTION_PATTERN,
                    severity=AlertSeverity.HIGH,
                    message=f"Prompt injection pattern detected: {pattern.pattern}",
                    entry_source=source,
                    matched_pattern=pattern.pattern,
                ))
        return alerts

    def _check_code_injection(
        self, content: str, source: str
    ) -> list[Alert]:
        alerts: list[Alert] = []
        for pattern in _CODE_INJECTION_PATTERNS:
            if pattern.search(content):
                alerts.append(Alert(
                    alert_type=AlertType.CODE_INJECTION,
                    severity=AlertSeverity.HIGH,
                    message=f"Code injection pattern detected: {pattern.pattern}",
                    entry_source=source,
                    matched_pattern=pattern.pattern,
                ))
        return alerts

    def _check_tool_poisoning(
        self, content: str, source: str
    ) -> list[Alert]:
        """Detect tool-poisoning: hidden-instruction markup, destructive commands, exfil.

        Widens coverage beyond prompt-injection prose to catch instruction-bearing
        markup tags that wrap destructive shell commands, exfiltration payloads, or
        a covert standing instruction (concealment or an always-on directive) — the
        blatant memory-poisoning patterns that plain prose detectors miss.
        """
        alerts: list[Alert] = []

        markup = self._first_match(content, _MARKUP_INSTRUCTION_PATTERNS)
        destructive = self._first_match(content, _DESTRUCTIVE_COMMAND_PATTERNS)
        exfil_exec = self._first_match(content, _EXFIL_EXEC_PATTERNS)
        network_fetch = self._first_match(content, _NETWORK_FETCH_PATTERNS)
        standing = self._first_match(content, _STANDING_INSTRUCTION_PATTERNS)

        if destructive is not None:
            alerts.append(Alert(
                alert_type=AlertType.TOOL_POISONING,
                severity=AlertSeverity.HIGH,
                message="Destructive shell command detected in memory content",
                entry_source=source,
                matched_pattern=destructive,
            ))

        if exfil_exec is not None:
            alerts.append(Alert(
                alert_type=AlertType.TOOL_POISONING,
                severity=AlertSeverity.HIGH,
                message="Remote-code-execution or exfiltration command detected",
                entry_source=source,
                matched_pattern=exfil_exec,
            ))

        if markup is not None:
            # A hidden-instruction tag is escalated to HIGH (blocking) when it
            # wraps a destructive/exfil command OR carries a covert standing
            # instruction (concealment or a conditional always-on directive) —
            # the core memory-poisoning payload. A tag next to a BARE network
            # fetch (e.g. `<tool>` docs alongside a plain `curl https://api...`)
            # or an innocuous note stays MEDIUM to avoid false-positive blocks.
            paired = (
                destructive is not None
                or exfil_exec is not None
                or standing is not None
            )
            if paired and standing is not None and destructive is None and exfil_exec is None:
                message = "Hidden-instruction markup tag carrying a covert standing instruction"
                matched = standing
            elif paired:
                message = "Instruction-bearing markup tag wrapping a dangerous payload"
                matched = destructive or exfil_exec
            else:
                message = "Hidden-instruction markup tag in memory content"
                matched = markup
            alerts.append(Alert(
                alert_type=AlertType.TOOL_POISONING,
                severity=AlertSeverity.HIGH if paired else AlertSeverity.MEDIUM,
                message=message,
                entry_source=source,
                matched_pattern=matched,
            ))
        elif network_fetch is not None:
            # Bare curl/wget without a hidden tag or destructive command is
            # ambiguous (could be benign docs): surface it, do not block.
            alerts.append(Alert(
                alert_type=AlertType.TOOL_POISONING,
                severity=AlertSeverity.MEDIUM,
                message="Outbound network-fetch command in memory content",
                entry_source=source,
                matched_pattern=network_fetch,
            ))

        return alerts

    @staticmethod
    def _first_match(
        content: str, patterns: list[re.Pattern[str]]
    ) -> str | None:
        for pattern in patterns:
            if pattern.search(content):
                return pattern.pattern
        return None

    def _check_special_characters(
        self, content: str, source: str
    ) -> list[Alert]:
        if not content:
            return []
        special = sum(
            1 for c in content
            if not c.isalnum() and not c.isspace()
        )
        ratio = special / len(content)
        if ratio > _SPECIAL_CHAR_THRESHOLD:
            return [Alert(
                alert_type=AlertType.EXCESSIVE_SPECIAL_CHARS,
                severity=AlertSeverity.MEDIUM,
                message=(
                    f"Excessive special characters ({ratio:.0%}) "
                    f"from source {source}"
                ),
                entry_source=source,
            )]
        return []

    def _check_unicode_manipulation(
        self, content: str, source: str
    ) -> list[Alert]:
        alerts: list[Alert] = []
        # Detect right-to-left override and other bidi control characters
        bidi_chars = {
            "\u200e",  # LRM
            "\u200f",  # RLM
            "\u202a",  # LRE
            "\u202b",  # RLE
            "\u202c",  # PDF
            "\u202d",  # LRO
            "\u202e",  # RLO
            "\u2066",  # LRI
            "\u2067",  # RLI
            "\u2068",  # FSI
            "\u2069",  # PDI
        }
        found = [c for c in content if c in bidi_chars]
        if found:
            alerts.append(Alert(
                alert_type=AlertType.UNICODE_MANIPULATION,
                severity=AlertSeverity.HIGH,
                message=(
                    f"Bidirectional unicode control characters detected "
                    f"({len(found)} occurrences) from source {source}"
                ),
                entry_source=source,
            ))

        # Detect homoglyph-heavy content (characters from mixed scripts)
        scripts: set[str] = set()
        for c in content:
            if c.isalpha():
                # Use unicodedata to get script-like categorisation
                name = unicodedata.name(c, "")
                if name.startswith("LATIN"):
                    scripts.add("LATIN")
                elif name.startswith("CYRILLIC"):
                    scripts.add("CYRILLIC")
                elif name.startswith("GREEK"):
                    scripts.add("GREEK")
        if len(scripts) > 1:
            alerts.append(Alert(
                alert_type=AlertType.UNICODE_MANIPULATION,
                severity=AlertSeverity.MEDIUM,
                message=(
                    f"Mixed unicode scripts detected ({', '.join(sorted(scripts))}) "
                    f"— possible homoglyph attack from source {source}"
                ),
                entry_source=source,
            ))

        return alerts
