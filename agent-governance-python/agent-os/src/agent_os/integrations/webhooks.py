# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Webhook notifications for policy violations and governance events.

Sends POST requests to configured webhook endpoints when policy violations,
budget warnings, or other governance events are detected.
"""

import json
import logging
import threading
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

logger = logging.getLogger(__name__)


@dataclass
class WebhookConfig:
    """Configuration for a webhook endpoint."""
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    timeout: float = 5.0
    retry_count: int = 3
    retry_delay: float = 1.0
    events: list[str] = field(default_factory=list)


@dataclass
class WebhookEvent:
    """A governance event to send via webhook."""
    event_type: str
    agent_id: str
    action: str
    details: dict[str, Any] = field(default_factory=dict)
    timestamp: str = ""
    severity: str = "info"  # "info", "warning", "critical"

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()
        if self.severity not in ("info", "warning", "critical"):
            raise ValueError(
                f"severity must be 'info', 'warning', or 'critical', got '{self.severity}'"
            )


@dataclass
class DeliveryRecord:
    """Record of a webhook delivery attempt."""
    url: str
    event_type: str
    status_code: Optional[int]
    success: bool
    timestamp: str
    error: Optional[str] = None


class WebhookNotifier:
    """Sends webhook notifications for governance events.

    Thread-safe notifier that delivers events to configured webhook endpoints
    with retry logic and delivery history tracking.
    """

    def __init__(self, configs: list[WebhookConfig]):
        self._configs = list(configs)
        self._history: list[DeliveryRecord] = []
        self._lock = threading.Lock()

    def _matches(self, config: WebhookConfig, event: WebhookEvent) -> bool:
        """Check if a config subscribes to the given event type."""
        if not config.events:
            return True
        return event.event_type in config.events

    def _send(self, config: WebhookConfig, event: WebhookEvent) -> DeliveryRecord:
        """Send a single event to a single webhook endpoint with retries."""
        payload = json.dumps(asdict(event)).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        headers.update(config.headers)

        last_error: Optional[str] = None
        last_status: Optional[int] = None

        for attempt in range(config.retry_count):
            try:
                req = urllib.request.Request(  # noqa: S310 — webhook URL from configuration
                    config.url, data=payload, headers=headers, method="POST"
                )
                with urllib.request.urlopen(req, timeout=config.timeout) as resp:  # noqa: S310 — webhook URL from configuration
                    last_status = resp.status
                    record = DeliveryRecord(
                        url=config.url,
                        event_type=event.event_type,
                        status_code=last_status,
                        success=True,
                        timestamp=datetime.now(timezone.utc).isoformat(),
                    )
                    with self._lock:
                        self._history.append(record)
                    return record
            except urllib.error.HTTPError as exc:
                last_status = exc.code
                last_error = str(exc)
            except Exception as exc:
                last_error = str(exc)

            if attempt < config.retry_count - 1:
                time.sleep(config.retry_delay)

        record = DeliveryRecord(
            url=config.url,
            event_type=event.event_type,
            status_code=last_status,
            success=False,
            timestamp=datetime.now(timezone.utc).isoformat(),
            error=last_error,
        )
        with self._lock:
            self._history.append(record)
        logger.warning(
            "Webhook delivery failed for %s to %s: %s",
            event.event_type, config.url, last_error,
        )
        return record

    def notify(self, event: WebhookEvent) -> list[DeliveryRecord]:
        """Send event to all matching webhooks synchronously."""
        records: list[DeliveryRecord] = []
        for config in self._configs:
            if self._matches(config, event):
                records.append(self._send(config, event))
        return records

    def notify_async(self, event: WebhookEvent) -> threading.Thread:
        """Send event to all matching webhooks in a background thread."""
        thread = threading.Thread(target=self.notify, args=(event,), daemon=True)
        thread.start()
        return thread

    def notify_violation(
        self, agent_id: str, action: str, policy_name: str, reason: str
    ) -> list[DeliveryRecord]:
        """Convenience method to notify about a policy violation."""
        event = WebhookEvent(
            event_type="policy_violation",
            agent_id=agent_id,
            action=action,
            details={"policy_name": policy_name, "reason": reason},
            severity="critical",
        )
        return self.notify(event)

    def notify_budget_warning(
        self, agent_id: str, usage_pct: float
    ) -> list[DeliveryRecord]:
        """Convenience method to notify about a budget warning."""
        severity = "critical" if usage_pct >= 100.0 else "warning"
        event = WebhookEvent(
            event_type="budget_warning",
            agent_id=agent_id,
            action="budget_check",
            details={"usage_percent": usage_pct},
            severity=severity,
        )
        return self.notify(event)

    def get_history(self) -> list[DeliveryRecord]:
        """Return a copy of all delivery records."""
        with self._lock:
            return list(self._history)
