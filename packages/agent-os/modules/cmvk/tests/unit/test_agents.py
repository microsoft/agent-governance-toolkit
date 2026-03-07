"""
Unit tests for the agents module.
"""

import sys
from pathlib import Path

import pytest

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from cross_model_verification_kernel.agents.base_agent import BaseAgent
from cross_model_verification_kernel.core.types import GenerationResult, VerificationResult


class MockGenerator(BaseAgent):
    """Mock generator for testing."""

    def generate(self, task, context=None):
        return GenerationResult(
            solution="mock solution", explanation="mock explanation", test_cases="mock tests"
        )

    def verify(self, context):
        raise NotImplementedError()


class MockVerifier(BaseAgent):
    """Mock verifier for testing."""

    def generate(self, task, context=None):
        raise NotImplementedError()

    def verify(self, context):
        from cross_model_verification_kernel.core.types import VerificationOutcome

        return VerificationResult(
            outcome=VerificationOutcome.PASS, confidence=0.9, reasoning="mock verification"
        )


class TestBaseAgent:
    """Tests for BaseAgent interface."""

    def test_mock_generator(self):
        """Test mock generator implementation."""
        agent = MockGenerator("test-model", "test-key")
        result = agent.generate("test task")

        assert isinstance(result, GenerationResult)
        assert result.solution == "mock solution"

    def test_mock_verifier(self):
        """Test mock verifier implementation."""
        agent = MockVerifier("test-model", "test-key")
        result = agent.verify({"task": "test"})

        assert isinstance(result, VerificationResult)
        assert result.confidence == 0.9


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
