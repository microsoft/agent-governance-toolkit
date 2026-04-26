# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for negative memory (failure tracking) functionality."""

from emk.schema import Episode


def test_episode_is_failure_default():
    """Test that episodes are not failures by default."""
    episode = Episode(
        goal="Test goal",
        action="Test action",
        result="Test result",
        reflection="Test reflection"
    )
    
    assert not episode.is_failure()


def test_episode_mark_as_failure():
    """Test marking an episode as a failure."""
    episode = Episode(
        goal="Test goal",
        action="Test action",
        result="Test result",
        reflection="Test reflection"
    )
    
    failed_episode = episode.mark_as_failure(reason="Connection timeout")
    
    assert failed_episode.is_failure()
    assert failed_episode.metadata["is_failure"] is True
    assert failed_episode.metadata["failure_reason"] == "Connection timeout"
    
    # Original episode should remain unchanged (immutability)
    assert not episode.is_failure()


def test_episode_mark_as_failure_no_reason():
    """Test marking an episode as failure without a reason."""
    episode = Episode(
        goal="Test goal",
        action="Test action",
        result="Test result",
        reflection="Test reflection"
    )
    
    failed_episode = episode.mark_as_failure()
    
    assert failed_episode.is_failure()
    assert failed_episode.metadata["is_failure"] is True
    assert "failure_reason" not in failed_episode.metadata


def test_episode_with_failure_metadata():
    """Test creating an episode with failure metadata directly."""
    episode = Episode(
        goal="Test goal",
        action="Test action",
        result="Failed",
        reflection="Need to retry",
        metadata={"is_failure": True, "failure_reason": "Network error"}
    )
    
    assert episode.is_failure()
    assert episode.metadata["failure_reason"] == "Network error"


def test_episode_failure_serialization():
    """Test that failure metadata survives serialization."""
    episode = Episode(
        goal="Test goal",
        action="Test action",
        result="Failed",
        reflection="Test reflection"
    )
    
    failed_episode = episode.mark_as_failure(reason="Test failure")
    
    # Serialize and deserialize
    json_str = failed_episode.to_json()
    restored_episode = Episode.from_json(json_str)
    
    assert restored_episode.is_failure()
    assert restored_episode.metadata["failure_reason"] == "Test failure"
