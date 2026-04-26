# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the constraint graph module."""

from __future__ import annotations

import pytest

from agent_os.constraint_graph import (
    ConstraintEdge,
    ConstraintGraph,
    ConstraintGraphEnforcer,
    Permission,
    ResourceNode,
    ResourceType,
)
from agent_os.integrations.base import ToolCallRequest


# ---------------------------------------------------------------------------
# ResourceNode
# ---------------------------------------------------------------------------

class TestResourceNode:
    def test_defaults(self):
        node = ResourceNode(name="db_query")
        assert node.name == "db_query"
        assert node.resource_type == ResourceType.TOOL
        assert node.metadata == {}

    def test_equality(self):
        a = ResourceNode(name="x", resource_type=ResourceType.API)
        b = ResourceNode(name="x", resource_type=ResourceType.API, metadata={"v": 1})
        assert a == b  # metadata is not part of equality


# ---------------------------------------------------------------------------
# ConstraintGraph — basic resolution
# ---------------------------------------------------------------------------

class TestConstraintGraphResolve:
    def _graph_with_edges(self, *edges: ConstraintEdge) -> ConstraintGraph:
        g = ConstraintGraph()
        for e in edges:
            g.add_constraint(e)
        return g

    def test_deny_by_default(self):
        g = ConstraintGraph()
        assert g.resolve("agent-1", "some_tool") is False

    def test_allow_exact_match(self):
        g = self._graph_with_edges(
            ConstraintEdge(
                agent_pattern="agent-1",
                resource="read_file",
                permission=Permission.ALLOW,
            )
        )
        assert g.resolve("agent-1", "read_file") is True

    def test_deny_explicit(self):
        g = self._graph_with_edges(
            ConstraintEdge(
                agent_pattern="agent-1",
                resource="delete_file",
                permission=Permission.DENY,
            )
        )
        assert g.resolve("agent-1", "delete_file") is False

    def test_glob_agent_pattern(self):
        g = self._graph_with_edges(
            ConstraintEdge(
                agent_pattern="reader-*",
                resource="read_file",
                permission=Permission.ALLOW,
            )
        )
        assert g.resolve("reader-01", "read_file") is True
        assert g.resolve("writer-01", "read_file") is False

    def test_glob_resource_pattern(self):
        g = self._graph_with_edges(
            ConstraintEdge(
                agent_pattern="agent-1",
                resource="read_*",
                permission=Permission.ALLOW,
            )
        )
        assert g.resolve("agent-1", "read_file") is True
        assert g.resolve("agent-1", "write_file") is False

    def test_priority_ordering(self):
        """Higher-priority deny overrides lower-priority allow."""
        g = self._graph_with_edges(
            ConstraintEdge(
                agent_pattern="*",
                resource="tool",
                permission=Permission.ALLOW,
                priority=0,
            ),
            ConstraintEdge(
                agent_pattern="bad-*",
                resource="tool",
                permission=Permission.DENY,
                priority=10,
            ),
        )
        assert g.resolve("good-agent", "tool") is True
        assert g.resolve("bad-agent", "tool") is False

    def test_conditions_must_match(self):
        g = self._graph_with_edges(
            ConstraintEdge(
                agent_pattern="agent-1",
                resource="admin_tool",
                permission=Permission.ALLOW,
                conditions={"role": "admin"},
            )
        )
        assert g.resolve("agent-1", "admin_tool") is False
        assert g.resolve("agent-1", "admin_tool", context={"role": "admin"}) is True
        assert g.resolve("agent-1", "admin_tool", context={"role": "user"}) is False

    def test_add_resource(self):
        g = ConstraintGraph()
        node = ResourceNode(name="api_v2", resource_type=ResourceType.API)
        g.add_resource(node)
        assert "api_v2" in g.resources

    def test_edges_property(self):
        g = ConstraintGraph()
        e = ConstraintEdge(agent_pattern="*", resource="*", permission=Permission.ALLOW)
        g.add_constraint(e)
        assert len(g.edges) == 1


# ---------------------------------------------------------------------------
# ConstraintGraphEnforcer
# ---------------------------------------------------------------------------

class TestConstraintGraphEnforcer:
    def test_allowed(self):
        g = ConstraintGraph()
        g.add_constraint(
            ConstraintEdge(agent_pattern="a1", resource="t1", permission=Permission.ALLOW)
        )
        enforcer = ConstraintGraphEnforcer(g)
        req = ToolCallRequest(tool_name="t1", arguments={}, agent_id="a1")
        result = enforcer.intercept(req)
        assert result.allowed is True

    def test_denied(self):
        g = ConstraintGraph()
        enforcer = ConstraintGraphEnforcer(g)
        req = ToolCallRequest(tool_name="t1", arguments={}, agent_id="a1")
        result = enforcer.intercept(req)
        assert result.allowed is False
        assert "denied" in result.reason.lower()

    def test_missing_agent_id(self):
        g = ConstraintGraph()
        enforcer = ConstraintGraphEnforcer(g)
        req = ToolCallRequest(tool_name="t1", arguments={})
        result = enforcer.intercept(req)
        assert result.allowed is False
        assert "agent_id" in result.reason.lower()
