# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Constraint Graph — DAG-based resource access control.

The constraint graph is the **only** path through which agents may access
resources (tools, APIs, data).  Every resource access request is resolved
by traversing a directed acyclic graph of constraint edges that encode
allow/deny rules with optional conditions.

Architecture:
    Agent ──▶ ConstraintGraph.resolve() ──▶ allow / deny
                     │
                     ├─ match agent_pattern against agent_id
                     ├─ match resource name
                     └─ evaluate conditions (time, role, etc.)

Integration:
    ``ConstraintGraphEnforcer`` implements the same ``intercept()`` protocol
    as ``PolicyInterceptor`` so it can be composed via ``CompositeInterceptor``.
"""

from __future__ import annotations

import fnmatch
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

class Permission(Enum):
    """Permission type for a constraint edge."""
    ALLOW = "allow"
    DENY = "deny"


class ResourceType(Enum):
    """Classification of a governed resource."""
    TOOL = "tool"
    API = "api"
    DATA = "data"


@dataclass(frozen=True)
class ResourceNode:
    """A resource (tool, API, data) in the constraint graph.

    Attributes:
        name: Unique resource identifier (e.g. ``"database_query"``).
        resource_type: Classification of the resource.
        metadata: Arbitrary key/value metadata for condition evaluation.
    """
    name: str
    resource_type: ResourceType = ResourceType.TOOL
    metadata: dict[str, Any] = field(default_factory=dict, hash=False)

    def __hash__(self) -> int:
        return hash((self.name, self.resource_type))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ResourceNode):
            return NotImplemented
        return self.name == other.name and self.resource_type == other.resource_type


@dataclass
class ConstraintEdge:
    """A constraint linking an agent pattern to a resource permission.

    Attributes:
        agent_pattern: Glob pattern matched against agent IDs.
        resource: The resource this constraint governs.
        permission: Whether to allow or deny access.
        conditions: Optional key/value conditions that must all be satisfied
            for this edge to apply (e.g. ``{"role": "admin"}``).
        priority: Higher-priority edges take precedence during resolution.
    """
    agent_pattern: str
    resource: str
    permission: Permission
    conditions: dict[str, Any] = field(default_factory=dict)
    priority: int = 0


# ---------------------------------------------------------------------------
# Constraint Graph
# ---------------------------------------------------------------------------

class ConstraintGraph:
    """DAG of resource constraints.

    Edges are evaluated in priority order (highest first).  The first matching
    edge determines the outcome.  If no edge matches, access is **denied** by
    default (deny-by-default posture).
    """

    def __init__(self) -> None:
        self._nodes: dict[str, ResourceNode] = {}
        self._edges: list[ConstraintEdge] = []

    # -- mutators -----------------------------------------------------------

    def add_resource(self, node: ResourceNode) -> None:
        """Register a resource node."""
        self._nodes[node.name] = node

    def add_constraint(self, edge: ConstraintEdge) -> None:
        """Add a constraint edge and re-sort by descending priority."""
        self._edges.append(edge)
        self._edges.sort(key=lambda e: e.priority, reverse=True)

    # -- query --------------------------------------------------------------

    @property
    def resources(self) -> dict[str, ResourceNode]:
        """Read-only view of registered resources."""
        return dict(self._nodes)

    @property
    def edges(self) -> list[ConstraintEdge]:
        """Read-only copy of constraint edges (sorted by priority)."""
        return list(self._edges)

    # -- resolution ---------------------------------------------------------

    def resolve(
        self,
        agent_id: str,
        resource: str,
        context: dict[str, Any] | None = None,
    ) -> bool:
        """Check whether *agent_id* may access *resource*.

        Args:
            agent_id: The requesting agent's identifier.
            resource: Name of the target resource.
            context: Runtime context used for condition evaluation.

        Returns:
            ``True`` if access is allowed, ``False`` otherwise.
        """
        context = context or {}

        for edge in self._edges:
            if not fnmatch.fnmatch(agent_id, edge.agent_pattern):
                continue
            if not fnmatch.fnmatch(resource, edge.resource):
                continue
            if not self._conditions_met(edge.conditions, context):
                continue

            allowed = edge.permission == Permission.ALLOW
            logger.debug(
                "constraint resolved: agent=%s resource=%s -> %s (priority=%d)",
                agent_id,
                resource,
                edge.permission.value,
                edge.priority,
            )
            return allowed

        # Deny by default
        logger.debug(
            "constraint resolved: agent=%s resource=%s -> deny (no matching edge)",
            agent_id,
            resource,
        )
        return False

    # -- internals ----------------------------------------------------------

    @staticmethod
    def _conditions_met(
        conditions: dict[str, Any],
        context: dict[str, Any],
    ) -> bool:
        """Return ``True`` if every condition key/value is present in *context*."""
        return all(context.get(k) == v for k, v in conditions.items())


# ---------------------------------------------------------------------------
# Enforcer (PolicyInterceptor-compatible)
# ---------------------------------------------------------------------------

class ConstraintGraphEnforcer:
    """Intercepts tool calls and enforces the constraint graph.

    Implements the same ``intercept(request) -> result`` protocol used by
    ``PolicyInterceptor`` and ``CompositeInterceptor`` so it can be plugged
    into the existing governance pipeline.
    """

    def __init__(
        self,
        graph: ConstraintGraph,
        context: dict[str, Any] | None = None,
    ) -> None:
        self.graph = graph
        self.context = context or {}

    def intercept(self, request: Any) -> Any:
        """Enforce constraint graph for a ``ToolCallRequest``.

        Imports are deferred to avoid circular dependency with
        ``integrations.base``.
        """
        from agent_os.integrations.base import ToolCallResult

        agent_id = getattr(request, "agent_id", "") or ""
        tool_name = getattr(request, "tool_name", "") or ""

        if not agent_id:
            return ToolCallResult(
                allowed=False,
                reason="Constraint graph requires agent_id on the request",
            )

        allowed = self.graph.resolve(agent_id, tool_name, self.context)
        if not allowed:
            return ToolCallResult(
                allowed=False,
                reason=(
                    f"Constraint graph denied agent '{agent_id}' "
                    f"access to resource '{tool_name}'"
                ),
            )

        return ToolCallResult(allowed=True)
