# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for sleep cycle and memory compression."""

import pytest
import tempfile
import os
from datetime import datetime, timezone, timedelta
from pathlib import Path

from emk.schema import Episode
from emk.store import FileAdapter
from emk.sleep_cycle import MemoryCompressor


@pytest.fixture
def temp_store():
    """Create a temporary file adapter for testing."""
    fd, path = tempfile.mkstemp(suffix=".jsonl")
    os.close(fd)
    adapter = FileAdapter(path)
    yield adapter
    # Cleanup
    if os.path.exists(path):
        os.remove(path)


@pytest.fixture
def temp_rules_file():
    """Create a temporary rules file for testing."""
    fd, path = tempfile.mkstemp(suffix="_rules.jsonl")
    os.close(fd)
    yield path
    # Cleanup
    if os.path.exists(path):
        os.remove(path)


def test_memory_compressor_creation(temp_store, temp_rules_file):
    """Test creating a memory compressor."""
    compressor = MemoryCompressor(
        store=temp_store,
        age_threshold_days=30,
        rules_filepath=temp_rules_file
    )
    
    assert compressor.age_threshold_days == 30
    assert compressor.rules_filepath == Path(temp_rules_file)


def test_identify_old_episodes(temp_store, temp_rules_file):
    """Test identifying old episodes."""
    compressor = MemoryCompressor(
        store=temp_store,
        age_threshold_days=7,
        rules_filepath=temp_rules_file
    )
    
    # Create episodes with different ages
    now = datetime.now(timezone.utc)
    old_time = now - timedelta(days=10)
    recent_time = now - timedelta(days=3)
    
    old_episode = Episode(
        goal="Old goal",
        action="Old action",
        result="Old result",
        reflection="Old reflection",
        timestamp=old_time
    )
    
    recent_episode = Episode(
        goal="Recent goal",
        action="Recent action",
        result="Recent result",
        reflection="Recent reflection",
        timestamp=recent_time
    )
    
    episodes = [old_episode, recent_episode]
    old_episodes = compressor.identify_old_episodes(episodes)
    
    assert len(old_episodes) == 1
    assert old_episodes[0].goal == "Old goal"


def test_summarize_episodes(temp_store, temp_rules_file):
    """Test summarizing episodes into a semantic rule."""
    compressor = MemoryCompressor(
        store=temp_store,
        rules_filepath=temp_rules_file
    )
    
    # Create multiple episodes
    episodes = []
    for i in range(5):
        episode = Episode(
            goal=f"Query database for user {i}",
            action=f"SELECT * FROM users WHERE id={i}",
            result="Success",
            reflection="Query completed"
        )
        episodes.append(episode)
    
    # Summarize
    rule = compressor.summarize_episodes(episodes)
    
    assert rule.rule != ""
    assert len(rule.source_episode_ids) == 5
    assert 0.0 <= rule.confidence <= 1.0


def test_summarize_episodes_with_failures(temp_store, temp_rules_file):
    """Test summarizing episodes that include failures."""
    compressor = MemoryCompressor(
        store=temp_store,
        rules_filepath=temp_rules_file
    )
    
    # Create mix of success and failure episodes
    episodes = []
    for i in range(3):
        episode = Episode(
            goal="Connect to API",
            action="HTTP GET /api/data",
            result="Success",
            reflection="Data retrieved"
        )
        episodes.append(episode)
    
    # Add failures
    for i in range(2):
        episode = Episode(
            goal="Connect to API",
            action="HTTP GET /api/data",
            result="Timeout",
            reflection="Connection failed",
            metadata={"is_failure": True}
        )
        episodes.append(episode)
    
    rule = compressor.summarize_episodes(episodes)
    
    assert "failed" in rule.rule.lower() or "warning" in rule.rule.lower()
    assert rule.metadata["failure_count"] == 2
    assert rule.metadata["success_rate"] == 0.6


def test_store_and_retrieve_rules(temp_store, temp_rules_file):
    """Test storing and retrieving semantic rules."""
    compressor = MemoryCompressor(
        store=temp_store,
        rules_filepath=temp_rules_file
    )
    
    episodes = [
        Episode(
            goal="Test goal",
            action="Test action",
            result="Test result",
            reflection="Test reflection"
        )
    ]
    
    # Create and store a rule
    rule = compressor.summarize_episodes(episodes)
    rule_id = compressor.store_rule(rule)
    
    assert rule_id == rule.rule_id
    
    # Retrieve rules
    retrieved_rules = compressor.retrieve_rules()
    
    assert len(retrieved_rules) == 1
    assert retrieved_rules[0].rule_id == rule_id


def test_retrieve_rules_with_filters(temp_store, temp_rules_file):
    """Test retrieving rules with metadata filters."""
    compressor = MemoryCompressor(
        store=temp_store,
        rules_filepath=temp_rules_file
    )
    
    # Store multiple rules with different metadata
    episodes = [Episode(goal="Test", action="Test", result="Test", reflection="Test")]
    
    rule1 = compressor.summarize_episodes(episodes)
    rule1 = type(rule1)(
        **{**rule1.to_dict(), "metadata": {"category": "database"}}
    )
    compressor.store_rule(rule1)
    
    rule2 = compressor.summarize_episodes(episodes)
    rule2 = type(rule2)(
        **{**rule2.to_dict(), "metadata": {"category": "api"}}
    )
    compressor.store_rule(rule2)
    
    # Retrieve with filter
    db_rules = compressor.retrieve_rules(filters={"category": "database"})
    
    assert len(db_rules) == 1
    assert db_rules[0].metadata["category"] == "database"


def test_compress_old_episodes_dry_run(temp_store, temp_rules_file):
    """Test compression dry run."""
    compressor = MemoryCompressor(
        store=temp_store,
        age_threshold_days=7,
        compression_batch_size=3,
        rules_filepath=temp_rules_file
    )
    
    # Store old episodes
    old_time = datetime.now(timezone.utc) - timedelta(days=10)
    
    for i in range(5):
        episode = Episode(
            goal=f"Goal {i}",
            action=f"Action {i}",
            result="Success",
            reflection="Done",
            timestamp=old_time
        )
        temp_store.store(episode)
    
    # Run dry run compression
    result = compressor.compress_old_episodes(dry_run=True)
    
    assert result["compressed_count"] == 5
    assert result["rules_created"] == 2  # 5 episodes / 3 batch_size = 2 batches
    assert result["dry_run"] is True
    
    # Verify no rules were actually created
    rules = compressor.retrieve_rules()
    assert len(rules) == 0


def test_compress_old_episodes_actual(temp_store, temp_rules_file):
    """Test actual compression of old episodes."""
    compressor = MemoryCompressor(
        store=temp_store,
        age_threshold_days=7,
        compression_batch_size=2,
        rules_filepath=temp_rules_file
    )
    
    # Store old episodes
    old_time = datetime.now(timezone.utc) - timedelta(days=10)
    
    for i in range(4):
        episode = Episode(
            goal=f"Goal {i}",
            action=f"Action {i}",
            result="Success",
            reflection="Done",
            timestamp=old_time
        )
        temp_store.store(episode)
    
    # Run compression
    result = compressor.compress_old_episodes(dry_run=False)
    
    assert result["compressed_count"] == 4
    assert result["rules_created"] == 2  # 4 episodes / 2 batch_size = 2 batches
    assert result["dry_run"] is False
    
    # Verify rules were created
    rules = compressor.retrieve_rules()
    assert len(rules) == 2


def test_compress_no_old_episodes(temp_store, temp_rules_file):
    """Test compression when there are no old episodes."""
    compressor = MemoryCompressor(
        store=temp_store,
        age_threshold_days=7,
        rules_filepath=temp_rules_file
    )
    
    # Store only recent episodes
    recent_time = datetime.now(timezone.utc) - timedelta(days=3)
    
    for i in range(3):
        episode = Episode(
            goal=f"Goal {i}",
            action=f"Action {i}",
            result="Success",
            reflection="Done",
            timestamp=recent_time
        )
        temp_store.store(episode)
    
    # Run compression
    result = compressor.compress_old_episodes()
    
    assert result["compressed_count"] == 0
    assert result["rules_created"] == 0
    assert "No old episodes" in result["message"]


def test_custom_summarizer(temp_store, temp_rules_file):
    """Test using a custom summarization function."""
    compressor = MemoryCompressor(
        store=temp_store,
        rules_filepath=temp_rules_file
    )
    
    episodes = [
        Episode(
            goal="Test goal",
            action="Test action",
            result="Test result",
            reflection="Test reflection"
        )
    ]
    
    # Custom summarizer
    def custom_summarizer(eps):
        return f"Custom summary of {len(eps)} episodes"
    
    rule = compressor.summarize_episodes(episodes, summarizer=custom_summarizer)
    
    assert rule.rule == "Custom summary of 1 episodes"


def test_empty_episode_list_error(temp_store, temp_rules_file):
    """Test that summarizing empty episode list raises error."""
    compressor = MemoryCompressor(
        store=temp_store,
        rules_filepath=temp_rules_file
    )
    
    with pytest.raises(ValueError, match="Cannot summarize empty episode list"):
        compressor.summarize_episodes([])
