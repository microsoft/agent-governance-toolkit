"""
Test for the Visualizer Tool

This test validates that the visualizer correctly loads and formats
JSON traces for display.
"""

import json
import os
import sys
import tempfile
from io import StringIO

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cross_model_verification_kernel.tools.visualizer import (
    format_strategy,
    get_latest_trace,
    list_traces,
    load_trace,
    replay_trace,
)


def test_load_trace():
    """Test loading a trace JSON file."""
    # Create a temporary trace file
    trace_data = {
        "input_query": "Test query",
        "current_code": "print('hello')",
        "status": "verified",
        "history": [
            {
                "step_id": 1,
                "code_generated": "print('hello')",
                "verifier_feedback": "PASS",
                "status": "success",
                "strategy_used": "simple",
            }
        ],
        "forbidden_strategies": [],
        "meta": {"timestamp": "20260121-120000", "total_attempts": 1, "final_status": "solved"},
    }

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(trace_data, f)
        temp_file = f.name

    try:
        # Load the trace
        loaded_data = load_trace(temp_file)

        # Verify data
        assert loaded_data["input_query"] == "Test query"
        assert loaded_data["current_code"] == "print('hello')"
        assert len(loaded_data["history"]) == 1
        assert loaded_data["meta"]["final_status"] == "solved"

        print("✅ test_load_trace PASSED")
    finally:
        os.unlink(temp_file)


def test_list_traces():
    """Test listing trace files."""
    # Create a temporary directory with some trace files
    with tempfile.TemporaryDirectory() as temp_dir:
        # Create test trace files
        for i in range(3):
            trace_file = os.path.join(temp_dir, f"trace_{i}.json")
            with open(trace_file, "w") as f:
                json.dump({"test": i}, f)

        # List traces
        traces = list_traces(temp_dir)

        # Verify
        assert len(traces) == 3
        assert all(str(t).endswith(".json") for t in traces)

        print("✅ test_list_traces PASSED")


def test_get_latest_trace():
    """Test getting the most recent trace file."""
    with tempfile.TemporaryDirectory() as temp_dir:
        import time

        # Create test trace files with different timestamps
        for i in range(3):
            trace_file = os.path.join(temp_dir, f"trace_{i}.json")
            with open(trace_file, "w") as f:
                json.dump({"test": i}, f)
            time.sleep(0.01)  # Small delay to ensure different mtimes

        # Get latest
        latest = get_latest_trace(temp_dir)

        # Verify it's the last one created
        assert latest is not None
        assert "trace_2.json" in str(latest)

        print("✅ test_get_latest_trace PASSED")


def test_format_strategy():
    """Test strategy name formatting."""
    assert format_strategy("built_in_sort") == "Built In Sort"
    assert format_strategy("bubble_sort") == "Bubble Sort"
    assert format_strategy("two_pointer") == "Two Pointer"
    assert format_strategy("unknown") == "Unknown Strategy"
    assert format_strategy(None) == "Unknown Strategy"

    print("✅ test_format_strategy PASSED")


def test_replay_trace_basic():
    """Test basic trace replay without errors."""
    trace_data = {
        "input_query": "Write a function to add two numbers",
        "current_code": "def add(a, b): return a + b",
        "status": "verified",
        "history": [
            {
                "step_id": 1,
                "code_generated": "def add(a, b): return a + b",
                "verifier_feedback": "PASS: Simple and correct",
                "status": "success",
                "strategy_used": "direct",
            }
        ],
        "forbidden_strategies": [],
        "meta": {"timestamp": "20260121-120000", "total_attempts": 1, "final_status": "solved"},
    }

    # Capture output
    old_stdout = sys.stdout
    sys.stdout = StringIO()

    try:
        # Replay with instant speed
        replay_trace(trace_data, speed=0, show_code=False)
        output = sys.stdout.getvalue()

        # Verify key elements are in output
        assert "ADVERSARIAL KERNEL REPLAY" in output
        assert "Write a function to add two numbers" in output
        assert "GPT-4o (The Builder)" in output
        assert "Gemini (The Prosecutor)" in output
        assert "Kernel (The Arbiter)" in output
        assert "SUCCESS" in output

        print("✅ test_replay_trace_basic PASSED")
    finally:
        sys.stdout = old_stdout


def test_replay_trace_with_failures():
    """Test trace replay with multiple failed attempts."""
    trace_data = {
        "input_query": "Test problem",
        "current_code": "final solution",
        "status": "verified",
        "history": [
            {
                "step_id": 1,
                "code_generated": "attempt 1",
                "verifier_feedback": "OBJECTION! Error 1",
                "status": "failed",
                "strategy_used": "strategy1",
            },
            {
                "step_id": 2,
                "code_generated": "attempt 2",
                "verifier_feedback": "OBJECTION! Error 2",
                "status": "failed",
                "strategy_used": "strategy2",
            },
            {
                "step_id": 3,
                "code_generated": "final solution",
                "verifier_feedback": "PASS",
                "status": "success",
                "strategy_used": "strategy3",
            },
        ],
        "forbidden_strategies": ["strategy1", "strategy2"],
        "meta": {"timestamp": "20260121-120000", "total_attempts": 3, "final_status": "solved"},
    }

    old_stdout = sys.stdout
    sys.stdout = StringIO()

    try:
        replay_trace(trace_data, speed=0, show_code=False)
        output = sys.stdout.getvalue()

        # Verify multiple rounds
        assert "Round 1 of 3" in output
        assert "Round 2 of 3" in output
        assert "Round 3 of 3" in output
        assert "BANNED" in output
        assert "Banned Strategies: 2" in output

        print("✅ test_replay_trace_with_failures PASSED")
    finally:
        sys.stdout = old_stdout


if __name__ == "__main__":
    test_load_trace()
    test_list_traces()
    test_get_latest_trace()
    test_format_strategy()
    test_replay_trace_basic()
    test_replay_trace_with_failures()
    print("\n✅ All visualizer tests passed!")
