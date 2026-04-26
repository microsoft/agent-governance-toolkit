# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the Episode schema."""

import pytest
from datetime import datetime
import json

from emk.schema import Episode


def test_episode_creation():
    """Test basic episode creation."""
    episode = Episode(
        goal="Test goal",
        action="Test action",
        result="Test result",
        reflection="Test reflection"
    )
    
    assert episode.goal == "Test goal"
    assert episode.action == "Test action"
    assert episode.result == "Test result"
    assert episode.reflection == "Test reflection"
    assert episode.episode_id is not None
    assert isinstance(episode.timestamp, datetime)
    assert episode.metadata == {}


def test_episode_with_metadata():
    """Test episode creation with metadata."""
    metadata = {"user_id": "123", "session": "abc"}
    episode = Episode(
        goal="Test goal",
        action="Test action",
        result="Test result",
        reflection="Test reflection",
        metadata=metadata
    )
    
    assert episode.metadata == metadata


def test_episode_id_generation():
    """Test that episode IDs are unique and deterministic."""
    episode1 = Episode(
        goal="Test goal",
        action="Test action",
        result="Test result",
        reflection="Test reflection"
    )
    
    episode2 = Episode(
        goal="Test goal",
        action="Test action",
        result="Test result",
        reflection="Test reflection"
    )
    
    # Same content should generate different IDs due to different timestamps
    assert episode1.episode_id != episode2.episode_id


def test_episode_to_dict():
    """Test episode conversion to dictionary."""
    episode = Episode(
        goal="Test goal",
        action="Test action",
        result="Test result",
        reflection="Test reflection"
    )
    
    data = episode.to_dict()
    
    assert isinstance(data, dict)
    assert data["goal"] == "Test goal"
    assert data["action"] == "Test action"
    assert data["result"] == "Test result"
    assert data["reflection"] == "Test reflection"
    assert "episode_id" in data
    assert "timestamp" in data


def test_episode_to_json():
    """Test episode conversion to JSON."""
    episode = Episode(
        goal="Test goal",
        action="Test action",
        result="Test result",
        reflection="Test reflection"
    )
    
    json_str = episode.to_json()
    
    assert isinstance(json_str, str)
    data = json.loads(json_str)
    assert data["goal"] == "Test goal"


def test_episode_from_dict():
    """Test episode creation from dictionary."""
    data = {
        "goal": "Test goal",
        "action": "Test action",
        "result": "Test result",
        "reflection": "Test reflection",
        "metadata": {"key": "value"}
    }
    
    episode = Episode.from_dict(data)
    
    assert episode.goal == "Test goal"
    assert episode.action == "Test action"
    assert episode.result == "Test result"
    assert episode.reflection == "Test reflection"
    assert episode.metadata == {"key": "value"}


def test_episode_from_json():
    """Test episode creation from JSON."""
    json_str = json.dumps({
        "goal": "Test goal",
        "action": "Test action",
        "result": "Test result",
        "reflection": "Test reflection"
    })
    
    episode = Episode.from_json(json_str)
    
    assert episode.goal == "Test goal"
    assert episode.action == "Test action"


def test_episode_roundtrip():
    """Test that episode can be serialized and deserialized."""
    original = Episode(
        goal="Test goal",
        action="Test action",
        result="Test result",
        reflection="Test reflection",
        metadata={"key": "value"}
    )
    
    # Convert to JSON and back
    json_str = original.to_json()
    restored = Episode.from_json(json_str)
    
    assert restored.goal == original.goal
    assert restored.action == original.action
    assert restored.result == original.result
    assert restored.reflection == original.reflection
    assert restored.metadata == original.metadata
