"""
Unit tests for the Cross-Model Verification Kernel.
"""

import sys
from pathlib import Path

import pytest

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from cross_model_verification_kernel.core.graph_memory import GraphMemory
from cross_model_verification_kernel.core.types import (
    Node,
    NodeStatus,
    VerificationOutcome,
    VerificationResult,
)


class TestGraphMemory:
    """Tests for the GraphMemory class."""

    def test_create_node(self):
        """Test node creation."""
        graph = GraphMemory()
        node = graph.create_node("test content")

        assert node.id is not None
        assert node.content == "test content"
        assert node.status == NodeStatus.PENDING
        assert node.id in graph.nodes

    def test_update_node_status(self):
        """Test updating node status."""
        graph = GraphMemory()
        node = graph.create_node("test")

        graph.update_node_status(node.id, NodeStatus.VERIFIED)
        assert graph.nodes[node.id].status == NodeStatus.VERIFIED

    def test_verification_result_addition(self):
        """Test adding verification results to nodes."""
        graph = GraphMemory()
        node = graph.create_node("test")

        result = VerificationResult(outcome=VerificationOutcome.PASS, confidence=0.9)

        graph.add_verification_result(node.id, result)
        assert len(graph.nodes[node.id].verification_results) == 1
        assert graph.nodes[node.id].status == NodeStatus.VERIFIED

    def test_loop_detection(self):
        """Test state loop detection."""
        graph = GraphMemory()

        state_hash = GraphMemory.generate_state_hash("task", "solution", 1)
        assert not graph.has_visited_state(state_hash)

        graph.mark_state_visited(state_hash)
        assert graph.has_visited_state(state_hash)

    def test_solution_caching(self):
        """Test caching of verified solutions."""
        graph = GraphMemory()

        problem_hash = "test_problem"
        solution = "test_solution"

        assert graph.get_cached_solution(problem_hash) is None

        graph.cache_solution(problem_hash, solution)
        assert graph.get_cached_solution(problem_hash) == solution

    def test_get_verified_nodes(self):
        """Test retrieving verified nodes."""
        graph = GraphMemory()

        node1 = graph.create_node("verified")
        graph.update_node_status(node1.id, NodeStatus.VERIFIED)

        node2 = graph.create_node("pending")

        verified = graph.get_verified_nodes()
        assert len(verified) == 1
        assert verified[0].id == node1.id

    def test_clear(self):
        """Test clearing graph state."""
        graph = GraphMemory()
        graph.create_node("test")
        graph.mark_state_visited("state1")
        graph.cache_solution("prob1", "sol1")

        graph.clear()

        assert len(graph.nodes) == 0
        assert len(graph.visited_states) == 0
        assert len(graph.verified_cache) == 0


class TestTypes:
    """Tests for data types."""

    def test_verification_result_has_critical_issues(self):
        """Test detection of critical issues."""
        result1 = VerificationResult(
            outcome=VerificationOutcome.FAIL, confidence=0.8, critical_issues=["Bug found"]
        )
        assert result1.has_critical_issues()

        result2 = VerificationResult(outcome=VerificationOutcome.PASS, confidence=0.9)
        assert not result2.has_critical_issues()

    def test_node_is_verified(self):
        """Test node verification status check."""
        node = Node(id="test", content="test", status=NodeStatus.VERIFIED)
        assert node.is_verified()

        node.status = NodeStatus.PENDING
        assert not node.is_verified()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
