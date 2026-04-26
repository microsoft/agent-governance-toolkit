# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
File-backed Trust Score Store.

Persists trust scores to a JSON file on disk so that scores survive
agent restarts without requiring Redis or any external dependency.

Usage:
    from agentmesh.storage.file_trust_store import FileTrustStore

    store = FileTrustStore("./data/trust_scores.json")
    store.store_trust_score("did:mesh:agent-1", {"score": 850, "level": "high"})

    # After restart:
    store = FileTrustStore("./data/trust_scores.json")
    score = store.get_trust_score("did:mesh:agent-1")
    # score == {"score": 850, "level": "high"}
"""

from __future__ import annotations

import json
import logging
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)


class FileTrustStore:
    """File-backed trust score persistence.

    Stores trust scores in a JSON file on disk. Thread-safe via a
    reentrant lock. Writes are atomic (write-to-temp then rename)
    to prevent corruption on crash.

    Args:
        path: File path for the trust score JSON file.
        auto_save: If True, persist to disk on every write.
            If False, call ``save()`` explicitly.
    """

    def __init__(self, path: str = "./trust_scores.json", auto_save: bool = True) -> None:
        self._path = Path(path)
        self._auto_save = auto_save
        self._lock = threading.RLock()
        self._scores: dict[str, dict[str, Any]] = {}
        self._metadata: dict[str, dict[str, str]] = {}

        if self._path.exists():
            self._load()

    def store_trust_score(self, agent_did: str, score: dict[str, Any]) -> None:
        """Store or update a trust score for an agent.

        Args:
            agent_did: DID of the agent.
            score: Trust score data (arbitrary dict).
        """
        with self._lock:
            self._scores[agent_did] = score
            self._metadata[agent_did] = {
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }
            if self._auto_save:
                self._save()

    def get_trust_score(self, agent_did: str) -> Optional[dict[str, Any]]:
        """Retrieve the trust score for an agent.

        Args:
            agent_did: DID of the agent.

        Returns:
            Trust score dict, or None if not found.
        """
        with self._lock:
            return self._scores.get(agent_did)

    def delete_trust_score(self, agent_did: str) -> bool:
        """Remove a trust score.

        Args:
            agent_did: DID of the agent.

        Returns:
            True if the score existed and was removed.
        """
        with self._lock:
            if agent_did in self._scores:
                del self._scores[agent_did]
                self._metadata.pop(agent_did, None)
                if self._auto_save:
                    self._save()
                return True
            return False

    def list_agents(self) -> list[str]:
        """List all agent DIDs with stored trust scores."""
        with self._lock:
            return list(self._scores.keys())

    def get_all_scores(self) -> dict[str, dict[str, Any]]:
        """Return all stored trust scores."""
        with self._lock:
            return dict(self._scores)

    def save(self) -> None:
        """Explicitly persist to disk."""
        with self._lock:
            self._save()

    def _save(self) -> None:
        """Write scores to disk atomically."""
        data = {
            "version": "1.0",
            "saved_at": datetime.now(timezone.utc).isoformat(),
            "scores": self._scores,
            "metadata": self._metadata,
        }
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = self._path.with_suffix(".tmp")
        try:
            tmp_path.write_text(json.dumps(data, indent=2, default=str))
            tmp_path.replace(self._path)
        except Exception:
            logger.error("Failed to save trust scores to %s", self._path, exc_info=True)
            if tmp_path.exists():
                tmp_path.unlink()

    def _load(self) -> None:
        """Load scores from disk."""
        try:
            raw = json.loads(self._path.read_text())
            self._scores = raw.get("scores", {})
            self._metadata = raw.get("metadata", {})
            count = len(self._scores)
            logger.info(
                "Loaded %d trust scores from %s", count, self._path
            )
        except Exception:
            logger.warning(
                "Failed to load trust scores from %s, starting fresh",
                self._path,
                exc_info=True,
            )
            self._scores = {}
            self._metadata = {}

    def __len__(self) -> int:
        return len(self._scores)

    def __contains__(self, agent_did: str) -> bool:
        return agent_did in self._scores
