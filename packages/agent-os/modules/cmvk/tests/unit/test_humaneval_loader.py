"""
Tests for the HumanEval Dataset Loader

This test validates that the HumanEvalLoader correctly loads and formats
the HumanEval dataset for use with the Verification Kernel.
"""

import json
import os
import sys
import tempfile

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cross_model_verification_kernel.datasets.humaneval_loader import HumanEvalLoader


def test_loader_initialization():
    """Test basic loader initialization with sample dataset."""
    loader = HumanEvalLoader()

    assert loader is not None
    assert len(loader) > 0
    assert loader.dataset_path.exists()

    print("✅ test_loader_initialization PASSED")


def test_get_all_problems():
    """Test getting all problems from the dataset."""
    loader = HumanEvalLoader()
    problems = loader.get_all_problems()

    assert isinstance(problems, list)
    assert len(problems) > 0

    # Check structure of first problem
    problem = problems[0]
    assert "task_id" in problem
    assert "prompt" in problem
    assert "test" in problem
    assert "entry_point" in problem

    print("✅ test_get_all_problems PASSED")


def test_get_problem_by_id():
    """Test getting a specific problem by task ID."""
    loader = HumanEvalLoader()
    problem = loader.get_problem("HumanEval/0")

    assert problem is not None
    assert problem["task_id"] == "HumanEval/0"
    assert "has_close_elements" in problem["entry_point"]

    # Test non-existent ID
    problem = loader.get_problem("HumanEval/999")
    assert problem is None

    print("✅ test_get_problem_by_id PASSED")


def test_get_problem_by_index():
    """Test getting a problem by index."""
    loader = HumanEvalLoader()

    problem = loader.get_problem_by_index(0)
    assert problem is not None
    assert "task_id" in problem

    # Test out of range
    problem = loader.get_problem_by_index(999)
    assert problem is None

    print("✅ test_get_problem_by_index PASSED")


def test_format_for_kernel():
    """Test formatting a problem for the kernel."""
    loader = HumanEvalLoader()
    raw_problem = loader.get_problem_by_index(0)

    formatted = loader.format_for_kernel(raw_problem)

    # Check required fields
    assert "id" in formatted
    assert "query" in formatted
    assert "metadata" in formatted

    # Check ID is filesystem-safe
    assert "/" not in formatted["id"]
    assert formatted["id"] == "HumanEval_0"

    # Check query contains the prompt
    assert "Complete the following Python function" in formatted["query"]
    assert raw_problem["entry_point"] in formatted["query"]

    # Check metadata
    assert formatted["metadata"]["task_id"] == raw_problem["task_id"]
    assert formatted["metadata"]["entry_point"] == raw_problem["entry_point"]
    assert formatted["metadata"]["test_code"] == raw_problem["test"]

    print("✅ test_format_for_kernel PASSED")


def test_get_problem_subset():
    """Test getting a subset of problems."""
    loader = HumanEvalLoader()

    # Get first 3 problems
    subset = loader.get_problem_subset(start=0, count=3)
    assert len(subset) == 3

    # Get last 2 problems (if dataset has at least 5)
    if len(loader) >= 5:
        subset = loader.get_problem_subset(start=3, count=2)
        assert len(subset) == 2

    # Test boundary
    subset = loader.get_problem_subset(start=0, count=999)
    assert len(subset) == len(loader)

    print("✅ test_get_problem_subset PASSED")


def test_format_all_for_kernel():
    """Test formatting multiple problems for the kernel."""
    loader = HumanEvalLoader()

    # Format first 3 problems
    formatted_list = loader.format_all_for_kernel(start=0, count=3)
    assert len(formatted_list) == 3

    # Check all are properly formatted
    for formatted in formatted_list:
        assert "id" in formatted
        assert "query" in formatted
        assert "metadata" in formatted

    print("✅ test_format_all_for_kernel PASSED")


def test_loader_with_custom_path():
    """Test loader with a custom dataset path."""
    # Create a temporary test dataset
    test_data = [
        {
            "task_id": "Test/0",
            "prompt": "def test_func():\n    pass",
            "test": "assert test_func() is None",
            "entry_point": "test_func",
        }
    ]

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(test_data, f)
        temp_file = f.name

    try:
        loader = HumanEvalLoader(dataset_path=temp_file)
        assert len(loader) == 1

        problem = loader.get_problem("Test/0")
        assert problem is not None
        assert problem["entry_point"] == "test_func"

        print("✅ test_loader_with_custom_path PASSED")
    finally:
        os.unlink(temp_file)


def test_iterator():
    """Test that the loader is iterable."""
    loader = HumanEvalLoader()

    count = 0
    for problem in loader:
        assert "task_id" in problem
        count += 1

    assert count == len(loader)

    print("✅ test_iterator PASSED")


if __name__ == "__main__":
    test_loader_initialization()
    test_get_all_problems()
    test_get_problem_by_id()
    test_get_problem_by_index()
    test_format_for_kernel()
    test_get_problem_subset()
    test_format_all_for_kernel()
    test_loader_with_custom_path()
    test_iterator()
    print("\n✅ All HumanEval loader tests passed!")
