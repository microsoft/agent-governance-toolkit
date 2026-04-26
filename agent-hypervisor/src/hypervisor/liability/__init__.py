# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# Public Preview — basic implementation
"""
Liability Matrix — simple event log for sponsor→sponsored agent relationships.

Public Preview: graph operations are retained for API compatibility
but sponsorship/penalty/quarantine are stubs.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass
class LiabilityEdge:
    """An edge in the liability graph."""

    voucher_did: str
    vouchee_did: str
    bonded_amount: float
    vouch_id: str


class LiabilityMatrix:
    """
    Directed graph tracking sponsor→sponsored agent bonds within a session.

    Provides query APIs for exposure analysis and cascade detection.
    """

    def __init__(self, session_id: str) -> None:
        self.session_id = session_id
        self._edges: list[LiabilityEdge] = []

    def add_edge(
        self,
        voucher_did: str,
        vouchee_did: str,
        bonded_amount: float,
        vouch_id: str,
    ) -> LiabilityEdge:
        """Record a sponsorship relationship."""
        edge = LiabilityEdge(
            voucher_did=voucher_did,
            vouchee_did=vouchee_did,
            bonded_amount=bonded_amount,
            vouch_id=vouch_id,
        )
        self._edges.append(edge)
        return edge

    def remove_edge(self, vouch_id: str) -> None:
        """Remove a sponsorship relationship by sponsor ID."""
        self._edges = [e for e in self._edges if e.vouch_id != vouch_id]

    def who_vouches_for(self, agent_did: str) -> list[LiabilityEdge]:
        """Get all sponsors for a given agent."""
        return [e for e in self._edges if e.vouchee_did == agent_did]

    def who_is_vouched_by(self, agent_did: str) -> list[LiabilityEdge]:
        """Get all sponsored agents of a given sponsor."""
        return [e for e in self._edges if e.voucher_did == agent_did]

    def total_exposure(self, voucher_did: str) -> float:
        """Total σ bonded by a sponsor across all sponsored agents."""
        return sum(e.bonded_amount for e in self._edges if e.voucher_did == voucher_did)

    def cascade_path(self, agent_did: str, max_depth: int = 2) -> list[list[str]]:
        """
        Find cascade paths from an agent through the liability graph.

        Returns all paths where penalty agent_did would cascade to others.
        """
        paths: list[list[str]] = []
        self._dfs_cascade(agent_did, [agent_did], paths, max_depth)
        return paths

    def has_cycle(self) -> bool:
        """Check if the liability graph contains any cycles."""
        all_nodes = set()
        for e in self._edges:
            all_nodes.add(e.voucher_did)
            all_nodes.add(e.vouchee_did)

        visited: set[str] = set()
        in_stack: set[str] = set()

        for node in all_nodes:
            if node not in visited:
                if self._dfs_cycle(node, visited, in_stack):
                    return True
        return False

    def clear(self) -> None:
        """Release all bonds (session termination)."""
        self._edges.clear()

    @property
    def edges(self) -> list[LiabilityEdge]:
        return list(self._edges)

    def _dfs_cascade(
        self,
        current: str,
        path: list[str],
        paths: list[list[str]],
        max_depth: int,
    ) -> None:
        if len(path) > max_depth + 1:
            return
        vouchees = self.who_is_vouched_by(current)
        if not vouchees and len(path) > 1:
            paths.append(list(path))
            return
        for edge in vouchees:
            if edge.vouchee_did not in path:
                path.append(edge.vouchee_did)
                self._dfs_cascade(edge.vouchee_did, path, paths, max_depth)
                path.pop()
        if not vouchees:
            return
        if len(path) > 1:
            paths.append(list(path))

    def _dfs_cycle(
        self, node: str, visited: set[str], in_stack: set[str]
    ) -> bool:
        visited.add(node)
        in_stack.add(node)
        for edge in self._edges:
            if edge.voucher_did == node:
                neighbor = edge.vouchee_did
                if neighbor in in_stack:
                    return True
                if neighbor not in visited:
                    if self._dfs_cycle(neighbor, visited, in_stack):
                        return True
        in_stack.discard(node)
        return False
