# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the FileAdapter."""

import pytest
import tempfile
import os
from pathlib import Path

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


def test_file_adapter_creation(temp_file):
    """Test FileAdapter creation."""
    adapter = FileAdapter(temp_file)
    assert adapter.filepath == Path(temp_file)
    assert adapter.filepath.exists()


def test_store_episode(temp_file):
    """Test storing an episode."""
    adapter = FileAdapter(temp_file)
    
    episode = Episode(
        goal="Test goal",
        action="Test action",
        result="Test result",
        reflection="Test reflection"
    )
    
    episode_id = adapter.store(episode)
    
    assert episode_id == episode.episode_id
    assert adapter.filepath.stat().st_size > 0


def test_retrieve_episodes(temp_file):
    """Test retrieving episodes."""
    adapter = FileAdapter(temp_file)
    
    # Store multiple episodes
    episodes = []
    for i in range(5):
        episode = Episode(
            goal=f"Goal {i}",
            action=f"Action {i}",
            result=f"Result {i}",
            reflection=f"Reflection {i}"
        )
        adapter.store(episode)
        episodes.append(episode)
    
    # Retrieve all
    retrieved = adapter.retrieve(limit=10)
    
    assert len(retrieved) == 5
    # Should be in reverse order (most recent first)
    assert retrieved[0].goal == "Goal 4"
    assert retrieved[4].goal == "Goal 0"


def test_retrieve_with_limit(temp_file):
    """Test retrieving episodes with limit."""
    adapter = FileAdapter(temp_file)
    
    # Store multiple episodes
    for i in range(5):
        episode = Episode(
            goal=f"Goal {i}",
            action=f"Action {i}",
            result=f"Result {i}",
            reflection=f"Reflection {i}"
        )
        adapter.store(episode)
    
    # Retrieve with limit
    retrieved = adapter.retrieve(limit=3)
    
    assert len(retrieved) == 3


def test_retrieve_with_filters(temp_file):
    """Test retrieving episodes with metadata filters."""
    adapter = FileAdapter(temp_file)
    
    # Store episodes with different metadata
    episode1 = Episode(
        goal="Goal 1",
        action="Action 1",
        result="Result 1",
        reflection="Reflection 1",
        metadata={"user_id": "123"}
    )
    adapter.store(episode1)
    
    episode2 = Episode(
        goal="Goal 2",
        action="Action 2",
        result="Result 2",
        reflection="Reflection 2",
        metadata={"user_id": "456"}
    )
    adapter.store(episode2)
    
    episode3 = Episode(
        goal="Goal 3",
        action="Action 3",
        result="Result 3",
        reflection="Reflection 3",
        metadata={"user_id": "123"}
    )
    adapter.store(episode3)
    
    # Retrieve with filter
    retrieved = adapter.retrieve(filters={"user_id": "123"})
    
    assert len(retrieved) == 2
    assert all(e.metadata.get("user_id") == "123" for e in retrieved)


def test_get_by_id(temp_file):
    """Test retrieving a specific episode by ID."""
    adapter = FileAdapter(temp_file)
    
    episode = Episode(
        goal="Test goal",
        action="Test action",
        result="Test result",
        reflection="Test reflection"
    )
    
    episode_id = adapter.store(episode)
    
    # Retrieve by ID
    retrieved = adapter.get_by_id(episode_id)
    
    assert retrieved is not None
    assert retrieved.episode_id == episode_id
    assert retrieved.goal == episode.goal


def test_get_by_id_not_found(temp_file):
    """Test retrieving a non-existent episode."""
    adapter = FileAdapter(temp_file)
    
    retrieved = adapter.get_by_id("nonexistent")
    
    assert retrieved is None


def test_retrieve_empty_file(temp_file):
    """Test retrieving from an empty file."""
    adapter = FileAdapter(temp_file)
    
    retrieved = adapter.retrieve()
    
    assert retrieved == []


def test_multiple_stores_append(temp_file):
    """Test that multiple stores append to the file."""
    adapter = FileAdapter(temp_file)
    
    # Store first episode
    episode1 = Episode(
        goal="Goal 1",
        action="Action 1",
        result="Result 1",
        reflection="Reflection 1"
    )
    adapter.store(episode1)
    
    # Store second episode
    episode2 = Episode(
        goal="Goal 2",
        action="Action 2",
        result="Result 2",
        reflection="Reflection 2"
    )
    adapter.store(episode2)
    
    # Retrieve all
    retrieved = adapter.retrieve()
    
    assert len(retrieved) == 2
