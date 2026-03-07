"""
Unit tests for Prosecutor Mode functionality.
"""

import sys
from pathlib import Path

import pytest

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from cross_model_verification_kernel.agents.verifier_gemini import GeminiVerifier
from cross_model_verification_kernel.core.types import VerificationOutcome, VerificationResult


class TestProsecutorMode:
    """Tests for the Prosecutor Mode functionality."""

    def test_verifier_initialization_with_prosecutor_mode(self):
        """Test that verifier initializes with prosecutor mode enabled."""
        verifier = GeminiVerifier(enable_prosecutor_mode=True)

        assert verifier.enable_prosecutor_mode is True
        assert verifier.sandbox is not None

    def test_verifier_initialization_without_prosecutor_mode(self):
        """Test that verifier can be initialized without prosecutor mode."""
        verifier = GeminiVerifier(enable_prosecutor_mode=False)

        assert verifier.enable_prosecutor_mode is False
        assert verifier.sandbox is None

    def test_extract_function_name(self):
        """Test function name extraction from solution code."""
        verifier = GeminiVerifier(enable_prosecutor_mode=False)

        # Test simple function
        code1 = "def fibonacci(n):\n    return n"
        assert verifier._extract_function_name(code1) == "fibonacci"

        # Test function with underscores
        code2 = "def calculate_sum(a, b):\n    return a + b"
        assert verifier._extract_function_name(code2) == "calculate_sum"

        # Test no function
        code3 = "x = 5\nprint(x)"
        assert verifier._extract_function_name(code3) is None

    def test_generate_hostile_tests_basic(self):
        """Test basic hostile test generation."""
        verifier = GeminiVerifier(enable_prosecutor_mode=False)

        context = {
            "task": "Write a fibonacci function",
            "solution": "def fibonacci(n):\n    if n <= 1:\n        return n\n    return fibonacci(n-1) + fibonacci(n-2)",
            "explanation": "Recursive implementation",
            "test_cases": "assert fibonacci(0) == 0",
        }

        verification_content = "Missing edge cases for negative numbers"

        hostile_tests = verifier._generate_hostile_tests(context, verification_content)

        # Should generate some template-based tests
        assert len(hostile_tests) > 0
        assert any("fibonacci" in test for test in hostile_tests)

    def test_parse_hostile_tests(self):
        """Test parsing hostile tests from LLM response."""
        verifier = GeminiVerifier(enable_prosecutor_mode=False)

        response = """Here are some hostile tests:

TEST:
```python
# Test negative input
assert fibonacci(-1) == 0
```

TEST:
```python
# Test large number
result = fibonacci(100)
assert result > 0
```
"""

        tests = verifier._parse_hostile_tests(response)

        assert len(tests) == 2
        assert "fibonacci(-1)" in tests[0]
        assert "fibonacci(100)" in tests[1]

    def test_execute_hostile_tests(self):
        """Test execution of hostile tests in sandbox."""
        verifier = GeminiVerifier(enable_prosecutor_mode=True)

        solution_code = """
def add(a, b):
    return a + b
"""

        hostile_tests = [
            "result = add(2, 3)\nprint('PASS' if result == 5 else 'FAIL')",
            "result = add(-1, 1)\nprint('PASS' if result == 0 else 'FAIL')",
        ]

        results = verifier._execute_hostile_tests(solution_code, hostile_tests)

        assert results["total"] == 2
        assert results["passed"] >= 0
        assert results["failures"] >= 0
        assert results["passed"] + results["failures"] == 2

    def test_verification_result_includes_hostile_tests(self):
        """Test that VerificationResult includes hostile test fields."""
        result = VerificationResult(
            outcome=VerificationOutcome.PASS,
            confidence=0.9,
            hostile_tests=["test1", "test2"],
            hostile_test_results={"total": 2, "passed": 2},
        )

        assert len(result.hostile_tests) == 2
        assert result.hostile_test_results["total"] == 2
        assert result.hostile_test_results["passed"] == 2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
