# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# Public Preview — basic implementation
"""
Vector Clocks -- causal ordering for multi-agent writes.

Implements standard component-wise vector clock comparison for
detecting causal ordering and concurrency between agent operations.
"""

from __future__ import annotations

import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field


class CausalViolationError(Exception):
    """Raised when a write would violate causal ordering."""


@contextmanager
def _locked_pair(a: VectorClock, b: VectorClock) -> Iterator[None]:
    """Hold the locks of both clocks, acquiring a shared lock only once.

    ``threading.Lock`` is not re-entrant, so comparing or merging a clock
    with itself must not try to take the same lock twice. Distinct clocks
    are locked in a deterministic order (by ``id()``) to prevent deadlocks.
    """
    if a is b:
        with a._lock:
            yield
        return
    first, second = sorted([a, b], key=id)
    with first._lock, second._lock:
        yield


@dataclass
class VectorClock:
    """A version counter (Public Preview: tracking only, no enforcement).

    Thread-safe: all reads and mutations are guarded by an internal lock
    to prevent data races when multiple agents tick/merge concurrently.
    """

    clocks: dict[str, int] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def tick(self, agent_did: str) -> None:
        """Increment the clock for an agent."""
        with self._lock:
            self.clocks[agent_did] = self.clocks.get(agent_did, 0) + 1

    def get(self, agent_did: str) -> int:
        with self._lock:
            return self.clocks.get(agent_did, 0)

    def merge(self, other: VectorClock) -> VectorClock:
        """Merge two version counters (take component-wise max).

        Acquires locks on both clocks to get consistent snapshots.
        """
        with _locked_pair(self, other):
            merged_clocks = dict(self.clocks)
            for agent, clock in other.clocks.items():
                merged_clocks[agent] = max(merged_clocks.get(agent, 0), clock)
        return VectorClock(clocks=merged_clocks)

    def happens_before(self, other: VectorClock) -> bool:
        """Return True if self causally precedes other.

        Clock A happens-before clock B iff every component of A is <=
        the corresponding component of B, and at least one is strictly <.
        """
        with _locked_pair(self, other):
            all_agents = set(self.clocks.keys()) | set(other.clocks.keys())
            at_least_one_less = False
            for agent in all_agents:
                self_val = self.clocks.get(agent, 0)
                other_val = other.clocks.get(agent, 0)
                if self_val > other_val:
                    return False
                if self_val < other_val:
                    at_least_one_less = True
            return at_least_one_less

    def is_concurrent(self, other: VectorClock) -> bool:
        """Return True if neither clock causally precedes the other."""
        return not self.happens_before(other) and not other.happens_before(self) and self != other

    def copy(self) -> VectorClock:
        with self._lock:
            return VectorClock(clocks=dict(self.clocks))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, VectorClock):
            return False
        with _locked_pair(self, other):
            all_agents = set(self.clocks.keys()) | set(other.clocks.keys())
            return all(self.clocks.get(a, 0) == other.clocks.get(a, 0) for a in all_agents)
