# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Causal Episodic Memory — Episodes with causal links.

Extends EMK's Episode schema with causal indexing: each episode knows
what caused it and what effects it triggered.  This enables causal
chain retrieval for debugging, compliance auditing, and RL training.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CausalEpisode:
    """
    An episode enriched with causal links.

    Parameters
    ----------
    action : str
        What was done.
    params : dict
        Parameters of the action.
    result : dict
        Outcome of the action.
    caused_by : str | None
        Episode ID that triggered this one (backward link).
    caused_effects : tuple[str, ...]
        Episode IDs that this episode subsequently triggered (forward links).
    policy_context : dict
        Active policies when this episode executed.
    trust_context : dict
        Peer trust scores when this episode executed.
    agent_id : str
        DID / identifier of the acting agent.
    timestamp : float
        Unix epoch (auto-generated).
    episode_id : str
        SHA-256 content hash (auto-generated).
    """

    action: str
    params: Dict[str, Any] = field(default_factory=dict)
    result: Dict[str, Any] = field(default_factory=dict)
    caused_by: Optional[str] = None
    caused_effects: tuple = ()  # tuple[str, ...]
    policy_context: Dict[str, Any] = field(default_factory=dict)
    trust_context: Dict[str, Any] = field(default_factory=dict)
    agent_id: str = ""
    timestamp: float = field(default_factory=time.time)
    episode_id: str = ""

    def __post_init__(self) -> None:
        if not self.episode_id:
            content = json.dumps(
                {
                    "action": self.action,
                    "params": self.params,
                    "agent_id": self.agent_id,
                    "timestamp": self.timestamp,
                },
                sort_keys=True,
            )
            # frozen dataclass — use object.__setattr__
            object.__setattr__(
                self,
                "episode_id",
                hashlib.sha256(content.encode()).hexdigest(),
            )

    # -- Serialisation helpers ------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        return {
            "episode_id": self.episode_id,
            "action": self.action,
            "params": self.params,
            "result": self.result,
            "caused_by": self.caused_by,
            "caused_effects": list(self.caused_effects),
            "policy_context": self.policy_context,
            "trust_context": self.trust_context,
            "agent_id": self.agent_id,
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CausalEpisode":
        data = dict(data)
        data["caused_effects"] = tuple(data.get("caused_effects") or ())
        return cls(**data)


# ---------------------------------------------------------------------------
# Causal Memory Store  (SQLite-backed)
# ---------------------------------------------------------------------------

_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS episodes (
    episode_id   TEXT PRIMARY KEY,
    action       TEXT NOT NULL,
    params       TEXT NOT NULL DEFAULT '{}',
    result       TEXT NOT NULL DEFAULT '{}',
    caused_by    TEXT,
    policy_ctx   TEXT NOT NULL DEFAULT '{}',
    trust_ctx    TEXT NOT NULL DEFAULT '{}',
    agent_id     TEXT NOT NULL DEFAULT '',
    ts           REAL NOT NULL,
    FOREIGN KEY (caused_by) REFERENCES episodes(episode_id)
);

CREATE TABLE IF NOT EXISTS causal_edges (
    from_id  TEXT NOT NULL,
    to_id    TEXT NOT NULL,
    PRIMARY KEY (from_id, to_id),
    FOREIGN KEY (from_id) REFERENCES episodes(episode_id),
    FOREIGN KEY (to_id)   REFERENCES episodes(episode_id)
);

CREATE INDEX IF NOT EXISTS idx_episodes_agent  ON episodes(agent_id);
CREATE INDEX IF NOT EXISTS idx_episodes_action ON episodes(action);
CREATE INDEX IF NOT EXISTS idx_edges_from      ON causal_edges(from_id);
CREATE INDEX IF NOT EXISTS idx_edges_to        ON causal_edges(to_id);
"""


class CausalMemoryStore:
    """
    Persistent causal episodic memory backed by SQLite.

    Records episodes with causal links and supports graph traversal
    to retrieve full causal chains.
    """

    def __init__(self, db_path: str = ":memory:") -> None:
        self._db_path = db_path
        self._conn = sqlite3.connect(db_path)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.executescript(_SCHEMA_SQL)
        self._conn.commit()

    # -- Core API -------------------------------------------------------------

    def record(self, episode: CausalEpisode) -> str:
        """
        Record a causal episode.

        Inserts the episode row and any causal edges (caused_by → this,
        this → each effect).  Returns the episode_id.
        """
        cur = self._conn.cursor()
        cur.execute(
            """
            INSERT OR REPLACE INTO episodes
                (episode_id, action, params, result, caused_by,
                 policy_ctx, trust_ctx, agent_id, ts)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                episode.episode_id,
                episode.action,
                json.dumps(episode.params),
                json.dumps(episode.result),
                episode.caused_by,
                json.dumps(episode.policy_context),
                json.dumps(episode.trust_context),
                episode.agent_id,
                episode.timestamp,
            ),
        )

        # Backward edge: caused_by → this
        if episode.caused_by:
            cur.execute(
                "INSERT OR IGNORE INTO causal_edges (from_id, to_id) VALUES (?, ?)",
                (episode.caused_by, episode.episode_id),
            )

        # Forward edges: this → each effect
        for effect_id in episode.caused_effects:
            cur.execute(
                "INSERT OR IGNORE INTO causal_edges (from_id, to_id) VALUES (?, ?)",
                (episode.episode_id, effect_id),
            )

        self._conn.commit()
        return episode.episode_id

    def get(self, episode_id: str) -> Optional[CausalEpisode]:
        """Retrieve a single episode by ID."""
        row = self._conn.execute(
            "SELECT * FROM episodes WHERE episode_id = ?", (episode_id,)
        ).fetchone()
        if row is None:
            return None
        return self._row_to_episode(row)

    def get_effects(self, episode_id: str) -> List[CausalEpisode]:
        """Get all episodes directly caused by *episode_id*."""
        rows = self._conn.execute(
            """
            SELECT e.* FROM episodes e
            JOIN causal_edges ce ON ce.to_id = e.episode_id
            WHERE ce.from_id = ?
            ORDER BY e.ts
            """,
            (episode_id,),
        ).fetchall()
        return [self._row_to_episode(r) for r in rows]

    def get_causes(self, episode_id: str) -> List[CausalEpisode]:
        """Get all episodes that directly caused *episode_id*."""
        rows = self._conn.execute(
            """
            SELECT e.* FROM episodes e
            JOIN causal_edges ce ON ce.from_id = e.episode_id
            WHERE ce.to_id = ?
            ORDER BY e.ts
            """,
            (episode_id,),
        ).fetchall()
        return [self._row_to_episode(r) for r in rows]

    def get_causal_chain(
        self,
        episode_id: str,
        *,
        direction: str = "backward",
        max_depth: int = 20,
    ) -> List[CausalEpisode]:
        """
        Walk the causal graph from *episode_id*.

        Parameters
        ----------
        direction : "backward" | "forward" | "both"
            backward = follow caused_by links (why did this happen?)
            forward  = follow caused_effects (what did this cause?)
            both     = union of both directions
        max_depth : int
            Maximum traversal depth to prevent infinite loops.

        Returns
        -------
        List of CausalEpisode ordered by timestamp.
        """
        visited: set[str] = set()
        result: list[CausalEpisode] = []

        def _walk(eid: str, depth: int, fwd: bool) -> None:
            if depth > max_depth or eid in visited:
                return
            visited.add(eid)
            ep = self.get(eid)
            if ep is None:
                return
            result.append(ep)
            if fwd:
                for child in self.get_effects(eid):
                    _walk(child.episode_id, depth + 1, fwd=True)
            else:
                for parent in self.get_causes(eid):
                    _walk(parent.episode_id, depth + 1, fwd=False)

        if direction in ("backward", "both"):
            _walk(episode_id, 0, fwd=False)
        if direction in ("forward", "both"):
            # Allow re-visiting the root so the forward walk can start
            visited.discard(episode_id)
            _walk(episode_id, 0, fwd=True)

        # Deduplicate + sort by timestamp
        seen: set[str] = set()
        deduped: list[CausalEpisode] = []
        for ep in result:
            if ep.episode_id not in seen:
                seen.add(ep.episode_id)
                deduped.append(ep)
        deduped.sort(key=lambda e: e.timestamp)
        return deduped

    def query_by_agent(
        self, agent_id: str, *, limit: int = 100
    ) -> List[CausalEpisode]:
        """Get recent episodes for an agent."""
        rows = self._conn.execute(
            "SELECT * FROM episodes WHERE agent_id = ? ORDER BY ts DESC LIMIT ?",
            (agent_id, limit),
        ).fetchall()
        return [self._row_to_episode(r) for r in rows]

    def query_by_action(
        self, action: str, *, limit: int = 100
    ) -> List[CausalEpisode]:
        """Get recent episodes matching an action type."""
        rows = self._conn.execute(
            "SELECT * FROM episodes WHERE action = ? ORDER BY ts DESC LIMIT ?",
            (action, limit),
        ).fetchall()
        return [self._row_to_episode(r) for r in rows]

    @property
    def episode_count(self) -> int:
        row = self._conn.execute("SELECT COUNT(*) FROM episodes").fetchone()
        return row[0] if row else 0

    @property
    def edge_count(self) -> int:
        row = self._conn.execute("SELECT COUNT(*) FROM causal_edges").fetchone()
        return row[0] if row else 0

    def close(self) -> None:
        self._conn.close()

    # -- Internal helpers -----------------------------------------------------

    def _row_to_episode(self, row: tuple) -> CausalEpisode:
        (eid, action, params_json, result_json, caused_by,
         policy_json, trust_json, agent_id, ts) = row

        # Fetch forward edges
        effects = self._conn.execute(
            "SELECT to_id FROM causal_edges WHERE from_id = ?", (eid,)
        ).fetchall()

        return CausalEpisode(
            episode_id=eid,
            action=action,
            params=json.loads(params_json),
            result=json.loads(result_json),
            caused_by=caused_by,
            caused_effects=tuple(r[0] for r in effects),
            policy_context=json.loads(policy_json),
            trust_context=json.loads(trust_json),
            agent_id=agent_id,
            timestamp=ts,
        )
