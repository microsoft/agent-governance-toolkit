# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Identity Revocation List

Manual revocation list — a simple set of revoked DIDs.
"""

from datetime import datetime, timedelta, timezone
from typing import Optional

import json
from pathlib import Path
from pydantic import BaseModel, Field


class RevocationEntry(BaseModel):
    """A single revocation record for an agent identity.

    Attributes:
        agent_did: DID of the revoked agent.
        revoked_at: Timestamp when the revocation was created.
        reason: Human-readable reason for revocation.
        revoked_by: DID of the entity that performed the revocation.
        expires_at: Expiry time for temporary revocations, or None for permanent.
    """

    agent_did: str = Field(..., description="DID of the revoked agent")
    revoked_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    reason: str = Field(..., description="Reason for revocation")
    revoked_by: Optional[str] = Field(default=None, description="DID of the revoker")
    expires_at: Optional[datetime] = Field(
        default=None, description="Expiry time for temporary revocations"
    )


class RevocationList:
    """Manages revoked agent identities with optional file-backed persistence.

    Args:
        storage: "memory" for in-memory only, or a file path for file-backed storage.
    """

    def __init__(self, storage: str = "memory") -> None:
        self._entries: dict[str, RevocationEntry] = {}
        self._storage = storage
        if storage != "memory" and Path(storage).exists():
            self.load(storage)

    def revoke(
        self,
        agent_did: str,
        reason: str,
        revoked_by: str | None = None,
        ttl_seconds: int | None = None,
    ) -> RevocationEntry:
        """Add an agent to the revocation list.

        Args:
            agent_did: DID of the agent to revoke.
            reason: Human-readable reason for revocation.
            revoked_by: DID of the revoker (optional).
            ttl_seconds: If set, revocation expires after this many seconds.

        Returns:
            The created RevocationEntry.
        """
        expires_at = None
        if ttl_seconds is not None:
            expires_at = datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)

        entry = RevocationEntry(
            agent_did=agent_did,
            reason=reason,
            revoked_by=revoked_by,
            expires_at=expires_at,
        )
        self._entries[agent_did] = entry
        self._auto_persist()
        return entry

    def unrevoke(self, agent_did: str) -> bool:
        """Remove an agent from the revocation list.

        Returns:
            True if the agent was revoked and is now unrevoked, False if not found.
        """
        if agent_did in self._entries:
            del self._entries[agent_did]
            self._auto_persist()
            return True
        return False

    def is_revoked(self, agent_did: str) -> bool:
        """Check if an agent is currently revoked.

        Automatically handles expiry of temporary revocations.
        """
        entry = self._entries.get(agent_did)
        if entry is None:
            return False
        if entry.expires_at is not None and datetime.now(timezone.utc) >= entry.expires_at:
            del self._entries[agent_did]
            self._auto_persist()
            return False
        return True

    def get_entry(self, agent_did: str) -> RevocationEntry | None:
        """Get revocation details for an agent, or None if not revoked."""
        if self.is_revoked(agent_did):
            return self._entries.get(agent_did)
        return None

    def list_revoked(self) -> list[RevocationEntry]:
        """Return all currently revoked agents (excludes expired entries)."""
        self.cleanup_expired()
        return list(self._entries.values())

    def cleanup_expired(self) -> int:
        """Remove expired temporary revocations.

        Returns:
            Number of entries removed.
        """
        now = datetime.now(timezone.utc)
        expired = [
            did
            for did, entry in self._entries.items()
            if entry.expires_at is not None and now >= entry.expires_at
        ]
        for did in expired:
            del self._entries[did]
        if expired:
            self._auto_persist()
        return len(expired)

    def save(self, path: str) -> None:
        """Persist the revocation list to a JSON file.

        Args:
            path: File path to write the JSON data to.
        """
        data = [entry.model_dump(mode="json") for entry in self._entries.values()]
        Path(path).write_text(json.dumps(data, indent=2, default=str))

    def load(self, path: str) -> None:
        """Load the revocation list from a JSON file.

        Args:
            path: File path to read the JSON data from.
        """
        raw = json.loads(Path(path).read_text())
        self._entries = {}
        for item in raw:
            entry = RevocationEntry.model_validate(item)
            self._entries[entry.agent_did] = entry

    def _auto_persist(self) -> None:
        """Persist to file if file-backed storage is configured."""
        if self._storage != "memory":
            self.save(self._storage)

    def __len__(self) -> int:
        return len(self._entries)
