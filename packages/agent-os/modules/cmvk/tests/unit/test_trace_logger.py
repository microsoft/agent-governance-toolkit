"""
Test for Feature 3: Trace Logger

This test validates that the TraceLogger correctly serializes NodeState
to JSON for research purposes.
"""

import json
import os
import sys
import tempfile

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cross_model_verification_kernel.core.trace_logger import TraceLogger
from cross_model_verification_kernel.core.types import ExecutionTrace, NodeState


def test_trace_logger_basic():
    """Test basic trace logging functionality."""
    # Create a temporary directory for test traces
    with tempfile.TemporaryDirectory() as temp_dir:
        logger = TraceLogger(log_dir=temp_dir)

        # Create a test NodeState
        state = NodeState(
            input_query="Test query: Write a function to sort an array",
            current_code="def sort_array(arr): return sorted(arr)",
            status="verified",
        )

        # Add some history
        trace1 = ExecutionTrace(
            step_id=1,
            code_generated="def sort_array(arr): return arr.sort()",
            verifier_feedback="Failed: sort() modifies in place and returns None",
            status="failed",
            strategy_used="built_in_sort",
        )
        trace2 = ExecutionTrace(
            step_id=2,
            code_generated="def sort_array(arr): return sorted(arr)",
            verifier_feedback="Success: correctly returns sorted array",
            status="success",
            strategy_used="built_in_sort",
        )
        state.history.append(trace1)
        state.history.append(trace2)
        state.forbidden_strategies.append("bubble_sort")

        # Save trace
        filepath = logger.save_trace("test_run", state)

        # Verify file exists
        assert os.path.exists(filepath), f"Trace file not created at {filepath}"

        # Verify JSON is valid and contains expected data
        with open(filepath) as f:
            data = json.load(f)

        assert data["input_query"] == state.input_query
        assert data["current_code"] == state.current_code
        assert data["status"] == state.status
        assert len(data["history"]) == 2
        assert data["history"][0]["status"] == "failed"
        assert data["history"][1]["status"] == "success"
        assert data["forbidden_strategies"] == ["bubble_sort"]

        # Verify metadata
        assert "meta" in data
        assert data["meta"]["total_attempts"] == 2
        assert data["meta"]["final_status"] == "solved"

        print("✅ test_trace_logger_basic PASSED")


def test_trace_logger_failed_state():
    """Test trace logging for a failed state."""
    with tempfile.TemporaryDirectory() as temp_dir:
        logger = TraceLogger(log_dir=temp_dir)

        state = NodeState(input_query="Impossible query", status="rejected")

        # Add failed attempts
        for i in range(3):
            trace = ExecutionTrace(
                step_id=i + 1,
                code_generated=f"attempt_{i}",
                verifier_feedback="Failed",
                status="failed",
                strategy_used="recursive",
            )
            state.history.append(trace)

        state.forbidden_strategies.extend(["recursive", "iterative"])

        # Save trace
        filepath = logger.save_trace("failed_run", state)

        # Verify
        with open(filepath) as f:
            data = json.load(f)

        assert data["meta"]["total_attempts"] == 3
        assert data["meta"]["final_status"] == "failed"
        assert len(data["forbidden_strategies"]) == 2

        print("✅ test_trace_logger_failed_state PASSED")


if __name__ == "__main__":
    test_trace_logger_basic()
    test_trace_logger_failed_state()
    print("\n✅ All tests passed!")
