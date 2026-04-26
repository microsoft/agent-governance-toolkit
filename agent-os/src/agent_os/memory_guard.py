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
