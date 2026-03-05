# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# Community Edition — basic context/memory management
"""
Store — Abstract interfaces and mutable file-based implementation for episodic memory.
"""

from abc import ABC, abstractmethod
from typing import List, Optional, Dict, Any
from pathlib import Path
import json
import numpy as np

from emk.schema import Episode


class VectorStoreAdapter(ABC):
    """Abstract interface for vector store implementations."""

    @abstractmethod
    def store(self, episode: Episode, embedding: Optional[np.ndarray] = None) -> str:
        """Store an episode. Returns the episode_id."""
        pass

    @abstractmethod
    def retrieve(
        self,
        query_embedding: Optional[np.ndarray] = None,
        filters: Optional[Dict[str, Any]] = None,
        limit: int = 10,
    ) -> List[Episode]:
        """Retrieve episodes, optionally filtered."""
        pass

    @abstractmethod
    def get_by_id(self, episode_id: str) -> Optional[Episode]:
        """Retrieve a specific episode by ID."""
        pass

    def update(self, episode_id: str, episode: Episode) -> bool:
        """Update an existing episode. Returns True if found and updated."""
        raise NotImplementedError

    def delete(self, episode_id: str) -> bool:
        """Delete an episode by ID. Returns True if found and deleted."""
        raise NotImplementedError

    def retrieve_failures(
        self,
        query_embedding: Optional[np.ndarray] = None,
        filters: Optional[Dict[str, Any]] = None,
        limit: int = 10,
    ) -> List[Episode]:
        """Retrieve episodes marked as failures."""
        failure_filters = filters.copy() if filters else {}
        failure_filters["is_failure"] = True
        return self.retrieve(query_embedding=query_embedding, filters=failure_filters, limit=limit)

    def retrieve_successes(
        self,
        query_embedding: Optional[np.ndarray] = None,
        filters: Optional[Dict[str, Any]] = None,
        limit: int = 10,
    ) -> List[Episode]:
        """Retrieve episodes that are NOT failures."""
        batch_size = min(limit * 3, 1000)
        all_episodes = self.retrieve(query_embedding=query_embedding, filters=filters, limit=batch_size)
        return [ep for ep in all_episodes if not ep.is_failure()][:limit]

    def retrieve_with_anti_patterns(
        self,
        query_embedding: Optional[np.ndarray] = None,
        filters: Optional[Dict[str, Any]] = None,
        limit: int = 10,
        include_failures: bool = True,
    ) -> Dict[str, List[Episode]]:
        """Retrieve both successes and failures."""
        result: Dict[str, List[Episode]] = {"successes": [], "failures": []}
        result["successes"] = self.retrieve_successes(query_embedding=query_embedding, filters=filters, limit=limit)
        if include_failures:
            result["failures"] = self.retrieve_failures(query_embedding=query_embedding, filters=filters, limit=limit)
        return result


class FileAdapter(VectorStoreAdapter):
    """
    Mutable JSONL-based file storage adapter.

    Supports store, retrieve, get_by_id, update and delete.
    """

    def __init__(self, filepath: str = "episodes.jsonl"):
        self.filepath = Path(filepath)
        self.filepath.parent.mkdir(parents=True, exist_ok=True)
        if not self.filepath.exists():
            self.filepath.touch()

    # -- helpers -----------------------------------------------------------

    def _read_all(self) -> List[Episode]:
        episodes: List[Episode] = []
        if not self.filepath.exists() or self.filepath.stat().st_size == 0:
            return episodes
        with open(self.filepath, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    episodes.append(Episode.from_json(line))
                except Exception:
                    continue
        return episodes

    def _write_all(self, episodes: List[Episode]) -> None:
        with open(self.filepath, "w") as f:
            for ep in episodes:
                f.write(ep.to_json() + "\n")

    # -- core API ----------------------------------------------------------

    def store(self, episode: Episode, embedding: Optional[np.ndarray] = None) -> str:
        with open(self.filepath, "a") as f:
            f.write(episode.to_json() + "\n")
        return episode.episode_id

    def retrieve(
        self,
        query_embedding: Optional[np.ndarray] = None,
        filters: Optional[Dict[str, Any]] = None,
        limit: int = 10,
    ) -> List[Episode]:
        episodes = self._read_all()
        if filters:
            episodes = [
                ep for ep in episodes
                if all(ep.metadata.get(k) == v for k, v in filters.items())
            ]
        episodes.reverse()
        return episodes[:limit]

    def get_by_id(self, episode_id: str) -> Optional[Episode]:
        for ep in self._read_all():
            if ep.episode_id == episode_id:
                return ep
        return None

    def update(self, episode_id: str, episode: Episode) -> bool:
        """Replace the episode with the given ID."""
        episodes = self._read_all()
        for i, ep in enumerate(episodes):
            if ep.episode_id == episode_id:
                episodes[i] = episode
                self._write_all(episodes)
                return True
        return False

    def delete(self, episode_id: str) -> bool:
        """Remove the episode with the given ID."""
        episodes = self._read_all()
        new_episodes = [ep for ep in episodes if ep.episode_id != episode_id]
        if len(new_episodes) == len(episodes):
            return False
        self._write_all(new_episodes)
        return True
