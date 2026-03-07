"""
Integration test for Feature 2: Lateral Thinking implementation.
Tests the new ExecutionTrace, NodeState classes and generator's forbidden strategies.
"""

import sys
from pathlib import Path

import pytest

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from cross_model_verification_kernel.agents.generator_openai import OpenAIGenerator
from cross_model_verification_kernel.core.types import ExecutionTrace, NodeState


class TestLateralThinkingIntegration:
    """Integration tests for Lateral Thinking feature components."""

    def test_execution_trace_creation(self):
        """Test ExecutionTrace dataclass."""
        trace = ExecutionTrace(
            step_id=1,
            code_generated="def factorial(n): return n * factorial(n-1)",
            verifier_feedback="RecursionError for large inputs",
            status="failed",
            strategy_used="recursive",
        )

        assert trace.step_id == 1
        assert trace.status == "failed"
        assert trace.strategy_used == "recursive"
        assert "factorial" in trace.code_generated

    def test_node_state_creation(self):
        """Test NodeState dataclass."""
        node = NodeState(
            input_query="Calculate factorial",
            current_code="def factorial(n): pass",
            status="pending",
        )

        assert node.input_query == "Calculate factorial"
        assert node.status == "pending"
        assert node.fail_count == 0
        assert len(node.forbidden_strategies) == 0

    def test_node_state_fail_count(self):
        """Test fail_count property of NodeState."""
        node = NodeState(input_query="Test")

        # Add successful trace
        node.history.append(
            ExecutionTrace(
                step_id=0, code_generated="code1", verifier_feedback="good", status="success"
            )
        )
        assert node.fail_count == 0

        # Add failed traces
        node.history.append(
            ExecutionTrace(
                step_id=1, code_generated="code2", verifier_feedback="error", status="failed"
            )
        )
        node.history.append(
            ExecutionTrace(
                step_id=2, code_generated="code3", verifier_feedback="error", status="failed"
            )
        )

        assert node.fail_count == 2

    def test_node_state_forbidden_strategies(self):
        """Test forbidden_strategies list in NodeState."""
        node = NodeState(input_query="Test")

        # Add forbidden strategies
        node.forbidden_strategies.append("recursive")
        node.forbidden_strategies.append("brute_force")

        assert len(node.forbidden_strategies) == 2
        assert "recursive" in node.forbidden_strategies
        assert "brute_force" in node.forbidden_strategies

    def test_generator_generate_solution_basic(self):
        """Test generate_solution method without forbidden strategies."""
        generator = OpenAIGenerator()

        result = generator.generate_solution(
            query="Write a simple function", context=None, forbidden_strategies=None
        )

        assert isinstance(result, str)
        assert len(result) > 0

    def test_generator_generate_solution_with_forbidden_strategies(self):
        """Test generate_solution method with forbidden strategies."""
        generator = OpenAIGenerator()

        result = generator.generate_solution(
            query="Write a factorial function",
            context="Previous attempt failed with RecursionError",
            forbidden_strategies=["recursive", "brute_force"],
        )

        assert isinstance(result, str)
        assert len(result) > 0

    def test_generator_generate_solution_with_context(self):
        """Test generate_solution method with context."""
        generator = OpenAIGenerator()

        context = "Previous attempt had off-by-one error"
        result = generator.generate_solution(
            query="Write a factorial function", context=context, forbidden_strategies=[]
        )

        assert isinstance(result, str)
        assert len(result) > 0

    def test_integration_node_state_with_traces(self):
        """Test NodeState with multiple ExecutionTrace entries."""
        node = NodeState(input_query="Calculate factorial of a number")

        # First attempt - recursive (failed)
        node.history.append(
            ExecutionTrace(
                step_id=0,
                code_generated="def factorial(n): return n * factorial(n-1)",
                verifier_feedback="RecursionError for large inputs",
                status="failed",
                strategy_used="recursive",
            )
        )
        node.forbidden_strategies.append("recursive")

        # Second attempt - iterative (success)
        node.history.append(
            ExecutionTrace(
                step_id=1,
                code_generated="def factorial(n):\n    result = 1\n    for i in range(1, n+1):\n        result *= i\n    return result",
                verifier_feedback="All tests passed",
                status="success",
                strategy_used="iterative",
            )
        )

        assert len(node.history) == 2
        assert node.fail_count == 1
        assert "recursive" in node.forbidden_strategies
        assert node.history[0].status == "failed"
        assert node.history[1].status == "success"

    def test_lateral_thinking_workflow(self):
        """Test complete lateral thinking workflow with NodeState."""
        # Create initial node state
        node = NodeState(
            input_query="Write a function to calculate fibonacci number", status="pending"
        )

        # Attempt 1: Recursive approach (fails)
        trace1 = ExecutionTrace(
            step_id=0,
            code_generated="def fib(n): return fib(n-1) + fib(n-2)",
            verifier_feedback="RecursionError for large inputs",
            status="failed",
            strategy_used="recursive",
        )
        node.history.append(trace1)
        node.status = "rejected"

        # After first failure, ban recursive approach
        node.forbidden_strategies.append("recursive")

        # Attempt 2: Iterative approach (succeeds)
        trace2 = ExecutionTrace(
            step_id=1,
            code_generated="def fib(n):\n    a, b = 0, 1\n    for _ in range(n):\n        a, b = b, a+b\n    return a",
            verifier_feedback="All tests passed",
            status="success",
            strategy_used="iterative",
        )
        node.history.append(trace2)
        node.current_code = trace2.code_generated
        node.status = "verified"

        # Verify the workflow
        assert len(node.history) == 2
        assert node.fail_count == 1
        assert len(node.forbidden_strategies) == 1
        assert "recursive" in node.forbidden_strategies
        assert node.status == "verified"
        assert "for" in node.current_code  # Iterative approach


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
