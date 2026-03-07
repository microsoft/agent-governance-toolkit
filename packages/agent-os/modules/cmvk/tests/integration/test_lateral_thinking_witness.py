"""
Unit tests for Lateral Thinking and Witness features.
"""

import json
import sys
import tempfile
from pathlib import Path

import pytest

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from cross_model_verification_kernel.core.graph_memory import GraphMemory


class TestLateralThinking:
    """Tests for Feature 2: Lateral Thinking (Graph Branching)."""

    def test_detect_approach_recursive(self):
        """Test detection of recursive approach."""
        graph = GraphMemory()

        recursive_code = """
def fibonacci(n):
    if n <= 1:
        return n
    return fibonacci(n-1) + fibonacci(n-2)
"""

        approach = graph.detect_approach(recursive_code)
        assert approach == "recursive"

    def test_detect_approach_iterative(self):
        """Test detection of iterative approach."""
        graph = GraphMemory()

        iterative_code = """
def fibonacci(n):
    a, b = 0, 1
    for i in range(n):
        a, b = b, a + b
    return a
"""

        approach = graph.detect_approach(iterative_code)
        assert approach == "iterative"

    def test_detect_approach_dynamic_programming(self):
        """Test detection of dynamic programming approach."""
        graph = GraphMemory()

        dp_code = """
def fibonacci(n):
    dp = [0] * (n + 1)
    dp[1] = 1
    for i in range(2, n + 1):
        dp[i] = dp[i-1] + dp[i-2]
    return dp[n]
"""

        approach = graph.detect_approach(dp_code)
        assert approach == "dynamic_programming"

    def test_record_approach_failure(self):
        """Test recording approach failures."""
        graph = GraphMemory()
        task = "Write a fibonacci function"

        recursive_solution = "def fib(n): return fib(n-1) + fib(n-2)"

        # First failure
        graph.record_approach_failure(recursive_solution, task)
        assert len(graph.approach_failures) == 1

        # Second failure - should mark as forbidden
        graph.record_approach_failure(recursive_solution, task)
        assert len(graph.forbidden_approaches) == 1

    def test_should_branch(self):
        """Test branching decision logic."""
        graph = GraphMemory()
        task = "Write a fibonacci function"

        recursive_solution = "def fib(n): return fib(n-1) + fib(n-2)"

        # Should not branch initially
        assert not graph.should_branch(recursive_solution, task)

        # Record two failures
        graph.record_approach_failure(recursive_solution, task)
        graph.record_approach_failure(recursive_solution, task)

        # Now should branch
        assert graph.should_branch(recursive_solution, task)

    def test_get_forbidden_approaches(self):
        """Test getting forbidden approaches for a task."""
        graph = GraphMemory()
        task = "Write a fibonacci function"

        recursive_solution = "def fib(n): return fib(n-1) + fib(n-2)"

        # Record two failures
        graph.record_approach_failure(recursive_solution, task)
        graph.record_approach_failure(recursive_solution, task)

        forbidden = graph.get_forbidden_approaches(task)
        assert "recursive" in forbidden


class TestWitness:
    """Tests for Feature 3: Witness (Traceability)."""

    def test_add_conversation_entry(self):
        """Test adding entries to conversation trace."""
        graph = GraphMemory()

        entry = {"type": "generation", "loop": 1, "solution": "test solution"}

        graph.add_conversation_entry(entry)

        assert len(graph.conversation_trace) == 1
        assert "timestamp" in graph.conversation_trace[0]
        assert graph.conversation_trace[0]["type"] == "generation"

    def test_get_conversation_trace(self):
        """Test retrieving conversation trace."""
        graph = GraphMemory()

        graph.add_conversation_entry({"type": "task_start"})
        graph.add_conversation_entry({"type": "generation"})
        graph.add_conversation_entry({"type": "verification"})

        trace = graph.get_conversation_trace()

        assert len(trace) == 3
        assert trace[0]["type"] == "task_start"
        assert trace[1]["type"] == "generation"
        assert trace[2]["type"] == "verification"

    def test_export_conversation_trace(self):
        """Test exporting conversation trace to JSON."""
        graph = GraphMemory()

        # Add some entries
        graph.add_conversation_entry({"type": "task_start", "task": "Write a function"})
        graph.add_conversation_entry({"type": "generation", "loop": 1})

        # Export to temporary file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            temp_path = f.name

        try:
            graph.export_conversation_trace(temp_path)

            # Verify file exists and contains valid JSON
            assert Path(temp_path).exists()

            with open(temp_path) as f:
                data = json.load(f)

            assert "trace" in data
            assert "stats" in data
            assert "nodes" in data
            assert len(data["trace"]) == 2
        finally:
            # Clean up
            Path(temp_path).unlink(missing_ok=True)

    def test_stats_include_new_metrics(self):
        """Test that stats include lateral thinking and witness metrics."""
        graph = GraphMemory()

        # Add some data
        graph.add_conversation_entry({"type": "test"})
        graph.record_approach_failure("def f(): return f()", "task")
        graph.record_approach_failure("def f(): return f()", "task")

        stats = graph.get_stats()

        assert "approach_failures" in stats
        assert "forbidden_approaches" in stats
        assert "conversation_entries" in stats
        assert stats["conversation_entries"] == 1
        assert stats["forbidden_approaches"] == 1

    def test_clear_resets_all_state(self):
        """Test that clear resets all new state."""
        graph = GraphMemory()

        # Add data to all new structures
        graph.add_conversation_entry({"type": "test"})
        graph.record_approach_failure("def f(): return f()", "task")
        graph.record_approach_failure("def f(): return f()", "task")

        # Clear
        graph.clear()

        # Verify all cleared
        assert len(graph.conversation_trace) == 0
        assert len(graph.approach_failures) == 0
        assert len(graph.forbidden_approaches) == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
