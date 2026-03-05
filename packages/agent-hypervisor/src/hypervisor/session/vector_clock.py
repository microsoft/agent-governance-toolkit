# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# Community Edition — basic implementation
"""
Version Counters — stub implementation.

Community edition: no causal consistency enforcement.
VectorClock and VectorClockManager are retained for API compatibility.
"""

from __future__ import annotations

from dataclasses import dataclass, field


class CausalViolationError(Exception):
    """Raised when a write would violate causal ordering."""


@dataclass
class VectorClock:
    """A version counter (community edition: tracking only, no enforcement)."""

    clocks: dict[str, int] = field(default_factory=dict)

    def tick(self, agent_did: str) -> None:
        """Increment the clock for an agent."""
        self.clocks[agent_did] = self.clocks.get(agent_did, 0) + 1

    def get(self, agent_did: str) -> int:
        return self.clocks.get(agent_did, 0)

    def merge(self, other: VectorClock) -> VectorClock:
        """Merge two version counters (take component-wise max)."""
        merged = VectorClock(clocks=dict(self.clocks))
        for agent, clock in other.clocks.items():
            merged.clocks[agent] = max(merged.clocks.get(agent, 0), clock)
        return merged

    def happens_before(self, other: VectorClock) -> bool:
        return False

    def is_concurrent(self, other: VectorClock) -> bool:
        return False

    def copy(self) -> VectorClock:
        return VectorClock(clocks=dict(self.clocks))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, VectorClock):
            return False
        all_agents = set(self.clocks.keys()) | set(other.clocks.keys())
        return all(
            self.clocks.get(a, 0) == other.clocks.get(a, 0)
            for a in all_agents
        )


class VectorClockManager:
    """
    Version counter stub (community edition: no causal enforcement).
    Reads and writes always succeed.
    """

    def __init__(self) -> None:
        self._path_clocks: dict[str, VectorClock] = {}
        self._agent_clocks: dict[str, VectorClock] = {}
        self._conflict_count: int = 0

    def read(self, path: str, agent_did: str) -> VectorClock:
        """Record a read (no enforcement)."""
        return self._path_clocks.get(path, VectorClock()).copy()

    def write(
        self,
        path: str,
        agent_did: str,
        strict: bool = True,
    ) -> VectorClock:
        """Record a write (community edition: never rejects)."""
        agent_clock = self._agent_clocks.get(agent_did, VectorClock())
        agent_clock.tick(agent_did)
        self._path_clocks[path] = agent_clock.copy()
        self._agent_clocks[agent_did] = agent_clock
        return self._path_clocks[path]

    def get_path_clock(self, path: str) -> VectorClock:
        return self._path_clocks.get(path, VectorClock()).copy()

    def get_agent_clock(self, agent_did: str) -> VectorClock:
        return self._agent_clocks.get(agent_did, VectorClock()).copy()

    @property
    def conflict_count(self) -> int:
        return self._conflict_count

    @property
    def tracked_paths(self) -> int:
        return len(self._path_clocks)
