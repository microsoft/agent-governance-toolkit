"""Agent inventory with deduplication and correlation.

The inventory stores one logical agent per unique fingerprint, merging
observations from multiple scanners. This prevents overcounting when
the same agent appears in GitHub, as a process, and in config files.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .models import AgentStatus, DiscoveredAgent, ScanResult


class AgentInventory:
    """Persistent, deduplicated inventory of discovered agents.

    Stores one logical agent per unique fingerprint. When the same agent
    is found by multiple scanners, observations are merged.
    """

    def __init__(self, storage_path: str | Path | None = None) -> None:
        self._agents: dict[str, DiscoveredAgent] = {}
        self._storage_path = Path(storage_path) if storage_path else None
        if self._storage_path and self._storage_path.exists():
            self._load()

    @property
    def agents(self) -> list[DiscoveredAgent]:
        """All agents in the inventory."""
        return list(self._agents.values())

    @property
    def count(self) -> int:
        return len(self._agents)

    def ingest(self, scan_result: ScanResult) -> dict[str, Any]:
        """Ingest a scan result, deduplicating against existing inventory.

        Returns summary: {"new": N, "updated": N, "total": N}
        """
        new_count = 0
        updated_count = 0

        for agent in scan_result.agents:
            existing = self._agents.get(agent.fingerprint)
            if existing:
                # Merge: add new evidence to existing agent
                for ev in agent.evidence:
                    existing.add_evidence(ev)
                # Merge tags
                existing.tags.update(agent.tags)
                # Update merge keys
                existing.merge_keys.update(agent.merge_keys)
                updated_count += 1
            else:
                self._agents[agent.fingerprint] = agent
                new_count += 1

        if self._storage_path:
            self._save()

        return {
            "new": new_count,
            "updated": updated_count,
            "total": self.count,
        }

    def get(self, fingerprint: str) -> DiscoveredAgent | None:
        """Get an agent by fingerprint."""
        return self._agents.get(fingerprint)

    def search(
        self,
        agent_type: str | None = None,
        status: AgentStatus | None = None,
        min_confidence: float = 0.0,
        tag_filter: dict[str, str] | None = None,
    ) -> list[DiscoveredAgent]:
        """Search inventory with filters."""
        results = []
        for agent in self._agents.values():
            if agent_type and agent.agent_type != agent_type:
                continue
            if status and agent.status != status:
                continue
            if agent.confidence < min_confidence:
                continue
            if tag_filter:
                if not all(agent.tags.get(k) == v for k, v in tag_filter.items()):
                    continue
            results.append(agent)
        return results

    def remove(self, fingerprint: str) -> bool:
        """Remove an agent from inventory."""
        if fingerprint in self._agents:
            del self._agents[fingerprint]
            if self._storage_path:
                self._save()
            return True
        return False

    def clear(self) -> None:
        """Clear all agents from inventory."""
        self._agents.clear()
        if self._storage_path:
            self._save()

    def export_json(self) -> str:
        """Export inventory as JSON."""
        return json.dumps(
            [a.model_dump(mode="json") for a in self._agents.values()],
            indent=2,
            default=str,
        )

    def _save(self) -> None:
        """Persist inventory to disk."""
        if not self._storage_path:
            return
        self._storage_path.parent.mkdir(parents=True, exist_ok=True)
        self._storage_path.write_text(self.export_json(), encoding="utf-8")

    def _load(self) -> None:
        """Load inventory from disk."""
        if not self._storage_path or not self._storage_path.exists():
            return
        try:
            data = json.loads(self._storage_path.read_text(encoding="utf-8"))
            for item in data:
                agent = DiscoveredAgent.model_validate(item)
                self._agents[agent.fingerprint] = agent
        except (json.JSONDecodeError, Exception):
            pass  # start fresh if corrupt

    def summary(self) -> dict[str, Any]:
        """Generate inventory summary statistics."""
        by_type: dict[str, int] = {}
        by_status: dict[str, int] = {}
        for agent in self._agents.values():
            by_type[agent.agent_type] = by_type.get(agent.agent_type, 0) + 1
            by_status[agent.status.value] = by_status.get(agent.status.value, 0) + 1

        return {
            "total_agents": self.count,
            "by_type": by_type,
            "by_status": by_status,
            "last_updated": datetime.now(timezone.utc).isoformat(),
        }
