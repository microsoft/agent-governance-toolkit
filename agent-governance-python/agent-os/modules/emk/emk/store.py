# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Store — Abstract interfaces and mutable file-based implementation for episodic memory.
"""

from abc import ABC, abstractmethod
from typing import List, Optional, Dict, Any
from pathlib import Path
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


try:
    import chromadb
    from chromadb.config import Settings

    class ChromaDBAdapter(VectorStoreAdapter):
        """
        ChromaDB-based vector storage adapter.

        Uses ChromaDB for vector similarity search and efficient retrieval
        of episodes based on embeddings.
        """

        def __init__(
            self,
            collection_name: str = "episodes",
            persist_directory: str = "./chroma_data",
        ):
            self.client = chromadb.Client(Settings(
                persist_directory=persist_directory,
                anonymized_telemetry=False,
            ))
            self.collection = self.client.get_or_create_collection(
                name=collection_name,
                metadata={"description": "Episodic memory storage"},
            )

        # Metadata keys written by the adapter itself. They are stripped from the
        # metadata handed back as ``Episode.metadata``.
        _RESERVED_KEYS = ('episode_id', 'goal', 'action', 'result', 'reflection', 'timestamp')

        @staticmethod
        def _to_metadata(episode: Episode, episode_id: str) -> Dict[str, Any]:
            """Flatten an episode into a Chroma metadata dict.

            ``episode_id`` is persisted so a read rebuilds the episode with the
            id it was stored under instead of letting the model regenerate one
            from the normalized fields.
            """
            return {
                **episode.metadata,
                "episode_id": episode_id,
                "goal": episode.goal,
                "action": episode.action,
                "result": episode.result,
                "reflection": episode.reflection,
                "timestamp": episode.timestamp.isoformat(),
            }

        @classmethod
        def _from_metadata(cls, record_id: str, metadata: Dict[str, Any]) -> Episode:
            """Rebuild an episode from a Chroma record.

            Records written before ``episode_id`` was persisted carry no stored
            id, so the Chroma record id is used for them.
            """
            episode_metadata = {
                k: v for k, v in metadata.items() if k not in cls._RESERVED_KEYS
            }
            return Episode(
                episode_id=metadata.get("episode_id") or record_id,
                goal=metadata.get("goal", ""),
                action=metadata.get("action", ""),
                result=metadata.get("result", ""),
                reflection=metadata.get("reflection", ""),
                timestamp=metadata.get("timestamp", None),
                metadata=episode_metadata,
            )

        @staticmethod
        def _records(results: Dict[str, Any]) -> List[tuple]:
            """Return ``(record_id, metadata)`` pairs from a get or query result.

            ``collection.query`` nests ids and metadatas one level deeper than
            ``collection.get`` (one list per query embedding).
            """
            ids = results.get('ids') or []
            metadatas = results.get('metadatas') or []
            if ids and isinstance(ids[0], list):
                ids = ids[0]
            if metadatas and isinstance(metadatas[0], list):
                metadatas = metadatas[0]
            return list(zip(ids, metadatas))

        def store(self, episode: Episode, embedding: Optional[np.ndarray] = None) -> str:
            if embedding is None:
                text = f"{episode.goal} {episode.action} {episode.result} {episode.reflection}"
            else:
                text = None

            self.collection.add(
                ids=[episode.episode_id],
                documents=[text] if text else None,
                embeddings=[embedding.tolist()] if embedding is not None else None,
                metadatas=[self._to_metadata(episode, episode.episode_id)],
            )
            return episode.episode_id

        def retrieve(
            self,
            query_embedding: Optional[np.ndarray] = None,
            filters: Optional[Dict[str, Any]] = None,
            limit: int = 10,
        ) -> List[Episode]:
            if query_embedding is not None:
                results = self.collection.query(
                    query_embeddings=[query_embedding.tolist()],
                    n_results=limit,
                    where=filters,
                )
            else:
                results = self.collection.get(limit=limit, where=filters)

            episodes = []
            for record_id, metadata in self._records(results):
                try:
                    episodes.append(self._from_metadata(record_id, metadata or {}))
                except Exception:
                    # Skip a record whose stored fields do not form a valid
                    # episode; backend errors raised above are not caught here.
                    continue
            return episodes

        def get_by_id(self, episode_id: str) -> Optional[Episode]:
            """Return the episode stored under ``episode_id``.

            Returns ``None`` only when no record has that id. A backend error
            propagates to the caller instead of being reported as absence.
            """
            results = self.collection.get(ids=[episode_id])
            records = self._records(results)
            if not records:
                return None
            record_id, metadata = records[0]
            return self._from_metadata(record_id, metadata or {})

        def update(self, episode_id: str, episode: Episode) -> bool:
            """Replace the stored episode with the given ID. Returns True if found."""
            existing = self.collection.get(ids=[episode_id])
            if not existing or not existing.get("ids"):
                return False
            self.collection.update(
                ids=[episode_id],
                metadatas=[self._to_metadata(episode, episode_id)],
            )
            return True

        def delete(self, episode_id: str) -> bool:
            """Remove the episode with the given ID. Returns True if found."""
            existing = self.collection.get(ids=[episode_id])
            if not existing or not existing.get("ids"):
                return False
            self.collection.delete(ids=[episode_id])
            return True

except ImportError:
    # ChromaDB not installed — adapter will not be available
    pass
