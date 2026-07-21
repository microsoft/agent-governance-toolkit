# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Relay inbox storage — protocols and in-memory default.

Spec: docs/specs/AGENTMESH-WIRE-1.0.md Section 12
"""

from __future__ import annotations

import threading
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Protocol


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


DEFAULT_TTL = timedelta(hours=72)


@dataclass
class StoredMessage:
    """A message held in the offline inbox."""

    message_id: str
    sender_did: str
    recipient_did: str
    payload: str  # opaque JSON string (ciphertext — relay cannot read)
    stored_at: datetime = field(default_factory=_utcnow)
    expires_at: datetime | None = None


class InboxStore(Protocol):
    """Protocol for relay inbox persistence."""

    def store(self, msg: StoredMessage) -> bool:
        """Store a message. Returns False if duplicate (by message_id)."""
        ...

    def fetch_pending(self, recipient_did: str) -> list[StoredMessage]:
        """Fetch all pending messages for a recipient, oldest first."""
        ...

    def acknowledge(
        self, message_id: str, recipient_did: str | None = None
    ) -> bool:
        """Delete a message by ID.

        When ``recipient_did`` is supplied, the message is deleted only if it
        is addressed to that recipient (spec 12.3: only the *recipient* may
        acknowledge). Returns True if a message was deleted; False if the id is
        unknown or the caller is not the message's recipient.
        """
        ...

    def cleanup_expired(self) -> int:
        """Remove expired messages. Returns count removed."""
        ...


class InMemoryInboxStore:
    """Thread-safe in-memory inbox store for development."""

    def __init__(self, ttl: timedelta = DEFAULT_TTL) -> None:
        self._ttl = ttl
        self._messages: dict[str, StoredMessage] = {}
        self._by_recipient: dict[str, list[str]] = defaultdict(list)
        self._lock = threading.Lock()

    def store(self, msg: StoredMessage) -> bool:
        with self._lock:
            if msg.message_id in self._messages:
                return False  # duplicate
            if msg.expires_at is None:
                msg.expires_at = msg.stored_at + self._ttl
            self._messages[msg.message_id] = msg
            self._by_recipient[msg.recipient_did].append(msg.message_id)
            return True

    def fetch_pending(self, recipient_did: str) -> list[StoredMessage]:
        with self._lock:
            now = _utcnow()
            ids = self._by_recipient.get(recipient_did, [])
            result = []
            for mid in ids:
                msg = self._messages.get(mid)
                if msg and (msg.expires_at is None or msg.expires_at > now):
                    result.append(msg)
            return sorted(result, key=lambda m: m.stored_at)

    def acknowledge(
        self, message_id: str, recipient_did: str | None = None
    ) -> bool:
        with self._lock:
            msg = self._messages.get(message_id)
            if msg is None:
                return False
            # Access control (spec 12.3): only the message's own recipient may
            # acknowledge/delete it. When a recipient DID is supplied and does
            # not match, refuse — this stops one agent's ack from deleting a
            # message queued for a different agent.
            if recipient_did is not None and msg.recipient_did != recipient_did:
                return False
            self._messages.pop(message_id, None)
            ids = self._by_recipient.get(msg.recipient_did, [])
            if message_id in ids:
                ids.remove(message_id)
            return True

    def cleanup_expired(self) -> int:
        with self._lock:
            now = _utcnow()
            expired = [
                mid for mid, msg in self._messages.items()
                if msg.expires_at and msg.expires_at <= now
            ]
            for mid in expired:
                msg = self._messages.pop(mid)
                ids = self._by_recipient.get(msg.recipient_did, [])
                if mid in ids:
                    ids.remove(mid)
            return len(expired)

    @property
    def message_count(self) -> int:
        with self._lock:
            return len(self._messages)
