# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Alert deduplication and storm protection.

Provides AlertDeduplicator for suppressing duplicate alerts within a time window,
AlertBatcher for batching alerts into digest notifications, and alert_fingerprint
for generating dedup keys from alert fields.

Closes #52.
"""

from __future__ import annotations

import hashlib
import threading
import time
from typing import TYPE_CHECKING

from agent_sre.alerts import Alert, AlertSeverity

if TYPE_CHECKING:
    from collections.abc import Sequence


def alert_fingerprint(alert: Alert, fields: Sequence[str] = ("agent_id", "title")) -> str:
    """Generate a dedup fingerprint from alert fields.

    Args:
        alert: The alert to fingerprint.
        fields: Tuple of Alert attribute names to include in fingerprint.

    Returns:
        Hex-digest string uniquely identifying this alert's dedup group.
    """
    parts = []
    for f in fields:
        val = getattr(alert, f, "")
        parts.append(f"{f}={val}")
    raw = "|".join(parts)
    return hashlib.sha256(raw.encode()).hexdigest()


class AlertDeduplicator:
    """Suppress duplicate alerts within a configurable time window.

    Thread-safe.  Alerts with the same fingerprint (derived from *group_by*
    fields) are suppressed if they arrive within *window_seconds* of the
    previous send.  RESOLVED alerts always pass through and clear the
    window for their fingerprint.
    """

    def __init__(
        self,
        window_seconds: float = 300,
        group_by: tuple[str, ...] = ("agent_id", "title"),
    ) -> None:
        self._window_seconds = window_seconds
        self._group_by = group_by
        self._lock = threading.Lock()
        self._sent: dict[str, float] = {}  # fingerprint -> last-sent timestamp
        self._total_received: int = 0
        self._total_deduplicated: int = 0

    # -- public API ----------------------------------------------------------

    def should_send(self, alert: Alert) -> bool:
        """Return True if *alert* is novel and should be delivered."""
        with self._lock:
            self._total_received += 1

            # RESOLVED alerts always pass and clear state
            if alert.severity == AlertSeverity.RESOLVED:
                fp = alert_fingerprint(alert, self._group_by)
                self._sent.pop(fp, None)
                return True

            fp = alert_fingerprint(alert, self._group_by)
            now = time.time()
            last = self._sent.get(fp)
            if last is not None and (now - last) < self._window_seconds:
                self._total_deduplicated += 1
                return False
            return True

    def record(self, alert: Alert) -> None:
        """Record that *alert* was sent (update window timestamp)."""
        with self._lock:
            fp = alert_fingerprint(alert, self._group_by)
            if alert.severity == AlertSeverity.RESOLVED:
                self._sent.pop(fp, None)
            else:
                self._sent[fp] = time.time()

    def get_stats(self) -> dict:
        """Return deduplication statistics."""
        with self._lock:
            return {
                "total_received": self._total_received,
                "total_deduplicated": self._total_deduplicated,
                "unique_alerts": len(self._sent),
            }

    def clear(self) -> None:
        """Reset all dedup state."""
        with self._lock:
            self._sent.clear()
            self._total_received = 0
            self._total_deduplicated = 0


class AlertBatcher:
    """Batch multiple alerts into digest notifications.

    Alerts are accumulated until either the *batch_window_seconds* expires
    or *max_batch_size* is reached, at which point the batch is considered
    ready for flushing.
    """

    def __init__(
        self,
        batch_window_seconds: float = 60,
        max_batch_size: int = 50,
    ) -> None:
        self._batch_window_seconds = batch_window_seconds
        self._max_batch_size = max_batch_size
        self._lock = threading.Lock()
        self._alerts: list[Alert] = []
        self._window_start: float = time.time()

    # -- public API ----------------------------------------------------------

    def add(self, alert: Alert) -> None:
        """Add an alert to the current batch."""
        with self._lock:
            if not self._alerts:
                self._window_start = time.time()
            self._alerts.append(alert)

    def is_ready(self) -> bool:
        """Return True when the batch should be flushed."""
        with self._lock:
            if not self._alerts:
                return False
            if len(self._alerts) >= self._max_batch_size:
                return True
            return time.time() - self._window_start >= self._batch_window_seconds

    def flush(self) -> list[Alert]:
        """Return all batched alerts and clear the batch."""
        with self._lock:
            alerts = list(self._alerts)
            self._alerts.clear()
            self._window_start = time.time()
            return alerts

    def get_digest(self) -> str:
        """Return a human-readable digest of batched alerts."""
        with self._lock:
            if not self._alerts:
                return "No alerts in batch."

            total = len(self._alerts)
            # Group by severity
            by_severity: dict[str, int] = {}
            for a in self._alerts:
                sev = a.severity.value
                by_severity[sev] = by_severity.get(sev, 0) + 1

            lines = [f"Alert Digest ({total} alert{'s' if total != 1 else ''}):", ""]
            for sev, count in sorted(by_severity.items()):
                lines.append(f"  {sev}: {count}")

            lines.append("")
            # List up to first 10 titles
            shown = self._alerts[:10]
            for a in shown:
                lines.append(f"  [{a.severity.value.upper()}] {a.title}")
            if total > 10:
                lines.append(f"  ... and {total - 10} more")

            return "\n".join(lines)

    @property
    def size(self) -> int:
        """Number of alerts currently in the batch."""
        with self._lock:
            return len(self._alerts)
