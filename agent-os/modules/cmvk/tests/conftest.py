"""
Shared pytest fixtures for CMVK tests.
"""

from unittest.mock import AsyncMock, MagicMock

import pytest


@pytest.fixture
def mock_generator():
    """Create a mock generator agent."""
    generator = MagicMock()
    generator.model_name = "gpt-4o"
    generator.generate = AsyncMock(
        return_value={
            "code": "def hello(): return 'Hello, World!'",
            "language": "python",
            "strategy": "simple",
        }
    )
    return generator


@pytest.fixture
def mock_verifier():
    """Create a mock verifier agent."""
    verifier = MagicMock()
    verifier.model_name = "gemini-1.5-pro"
    verifier.verify = AsyncMock(
        return_value={
            "passed": True,
            "issues": [],
            "confidence": 0.95,
        }
    )
    return verifier


@pytest.fixture
def sample_task():
    """Sample task for testing."""
    return "Write a function that returns the sum of two numbers."


@pytest.fixture
def sample_code():
    """Sample code for testing."""
    return """
def add(a, b):
    return a + b
"""


@pytest.fixture
def sample_buggy_code():
    """Sample buggy code for testing."""
    return """
def add(a, b):
    return a - b  # Bug: should be +
"""
