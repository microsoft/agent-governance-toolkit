# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for store adapter anti-pattern functionality."""

import pytest
import tempfile
import os

from emk.schema import Episode
from emk.store import FileAdapter


@pytest.fixture
def temp_file():
    """Create a temporary file for testing."""
    fd, path = tempfile.mkstemp(suffix=".jsonl")
    os.close(fd)
    yield path
    # Cleanup
    if os.path.exists(path):
        os.remove(path)


def test_retrieve_failures(temp_file):
    """Test retrieving only failure episodes."""
    adapter = FileAdapter(temp_file)
    
    # Store mix of success and failure episodes
    success_episode = Episode(
        goal="Success goal",
        action="Success action",
        result="Success",
        reflection="Worked well"
    )
    adapter.store(success_episode)
    
    failure_episode1 = Episode(
        goal="Failure goal 1",
        action="Failure action 1",
        result="Failed",
        reflection="Need to fix",
        metadata={"is_failure": True, "failure_reason": "Timeout"}
    )
    adapter.store(failure_episode1)
    
    failure_episode2 = Episode(
        goal="Failure goal 2",
        action="Failure action 2",
        result="Failed",
        reflection="Error occurred",
        metadata={"is_failure": True, "failure_reason": "Connection error"}
    )
    adapter.store(failure_episode2)
    
    # Retrieve only failures
    failures = adapter.retrieve_failures()
    
    assert len(failures) == 2
    assert all(ep.is_failure() for ep in failures)


def test_retrieve_successes(temp_file):
    """Test retrieving only successful episodes."""
    adapter = FileAdapter(temp_file)
    
    # Store mix of success and failure episodes
    for i in range(3):
        success_episode = Episode(
            goal=f"Success goal {i}",
            action=f"Success action {i}",
            result="Success",
            reflection="Worked well"
        )
        adapter.store(success_episode)
    
    failure_episode = Episode(
        goal="Failure goal",
        action="Failure action",
        result="Failed",
        reflection="Need to fix",
        metadata={"is_failure": True}
    )
    adapter.store(failure_episode)
    
    # Retrieve only successes
    successes = adapter.retrieve_successes()
    
    assert len(successes) == 3
    assert all(not ep.is_failure() for ep in successes)


def test_retrieve_with_anti_patterns(temp_file):
    """Test retrieving both successes and failures."""
    adapter = FileAdapter(temp_file)
    
    # Store multiple episodes
    for i in range(2):
        success = Episode(
            goal=f"API call {i}",
            action="GET /api/data",
            result="200 OK",
            reflection="Success"
        )
        adapter.store(success)
    
    for i in range(2):
        failure = Episode(
            goal=f"API call {i}",
            action="GET /api/data",
            result="500 Error",
            reflection="Failed",
            metadata={"is_failure": True}
        )
        adapter.store(failure)
    
    # Retrieve both
    result = adapter.retrieve_with_anti_patterns(limit=5)
    
    assert "successes" in result
    assert "failures" in result
    assert len(result["successes"]) == 2
    assert len(result["failures"]) == 2


def test_retrieve_with_anti_patterns_no_failures(temp_file):
    """Test retrieve with anti-patterns when no failures exist."""
    adapter = FileAdapter(temp_file)
    
    # Store only successes
    for i in range(3):
        episode = Episode(
            goal=f"Goal {i}",
            action=f"Action {i}",
            result="Success",
            reflection="Done"
        )
        adapter.store(episode)
    
    result = adapter.retrieve_with_anti_patterns()
    
    assert len(result["successes"]) == 3
    assert len(result["failures"]) == 0


def test_retrieve_with_anti_patterns_exclude_failures(temp_file):
    """Test retrieve with anti-patterns with failures excluded."""
    adapter = FileAdapter(temp_file)
    
    # Store both types
    success = Episode(goal="Success", action="A", result="OK", reflection="Good")
    adapter.store(success)
    
    failure = Episode(
        goal="Failure",
        action="B",
        result="Error",
        reflection="Bad",
        metadata={"is_failure": True}
    )
    adapter.store(failure)
    
    # Retrieve without failures
    result = adapter.retrieve_with_anti_patterns(include_failures=False)
    
    assert len(result["successes"]) == 1
    assert len(result["failures"]) == 0


def test_retrieve_failures_with_additional_filters(temp_file):
    """Test retrieving failures with additional metadata filters."""
    adapter = FileAdapter(temp_file)
    
    # Store failures with different metadata
    failure1 = Episode(
        goal="API failure",
        action="GET /api",
        result="Error",
        reflection="Failed",
        metadata={"is_failure": True, "user_id": "123"}
    )
    adapter.store(failure1)
    
    failure2 = Episode(
        goal="DB failure",
        action="Query DB",
        result="Error",
        reflection="Failed",
        metadata={"is_failure": True, "user_id": "456"}
    )
    adapter.store(failure2)
    
    # Retrieve failures for specific user
    user_failures = adapter.retrieve_failures(filters={"user_id": "123"})
    
    assert len(user_failures) == 1
    assert user_failures[0].metadata["user_id"] == "123"


def test_retrieve_successes_with_limit(temp_file):
    """Test retrieving successes with limit."""
    adapter = FileAdapter(temp_file)
    
    # Store many successes
    for i in range(10):
        episode = Episode(
            goal=f"Goal {i}",
            action=f"Action {i}",
            result="Success",
            reflection="Done"
        )
        adapter.store(episode)
    
    # Store one failure
    failure = Episode(
        goal="Failure",
        action="Action",
        result="Error",
        reflection="Failed",
        metadata={"is_failure": True}
    )
    adapter.store(failure)
    
    # Retrieve with limit
    successes = adapter.retrieve_successes(limit=5)
    
    assert len(successes) == 5
    assert all(not ep.is_failure() for ep in successes)


def test_retrieve_empty_store(temp_file):
    """Test retrieving from empty store."""
    adapter = FileAdapter(temp_file)
    
    failures = adapter.retrieve_failures()
    successes = adapter.retrieve_successes()
    result = adapter.retrieve_with_anti_patterns()
    
    assert len(failures) == 0
    assert len(successes) == 0
    assert len(result["successes"]) == 0
    assert len(result["failures"]) == 0
