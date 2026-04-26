# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the Indexer."""

import pytest

from emk.schema import Episode
from emk.indexer import Indexer


def test_extract_tags_basic():
    """Test basic tag extraction."""
    text = "The user wants to retrieve data from the database"
    tags = Indexer.extract_tags(text)
    
    assert "user" in tags
    assert "wants" in tags
    assert "retrieve" in tags
    assert "data" in tags
    assert "database" in tags
    # Stop words should be filtered
    assert "the" not in tags
    assert "to" not in tags
    assert "from" not in tags


def test_extract_tags_min_length():
    """Test tag extraction with minimum length."""
    text = "I go to eat at a restaurant"
    tags = Indexer.extract_tags(text, min_length=4)
    
    assert "restaurant" in tags
    # Short words should be filtered
    assert "go" not in tags
    assert "eat" not in tags


def test_extract_tags_lowercased():
    """Test that tags are lowercased."""
    text = "Database Query System"
    tags = Indexer.extract_tags(text)
    
    assert "database" in tags
    assert "query" in tags
    assert "system" in tags
    assert "Database" not in tags


def test_generate_episode_tags():
    """Test generating tags from an episode."""
    episode = Episode(
        goal="Retrieve user preferences from database",
        action="Execute SQL query",
        result="Successfully retrieved data",
        reflection="Query was efficient",
        metadata={"user_id": "123", "query_type": "select"}
    )
    
    tags = Indexer.generate_episode_tags(episode)
    
    assert isinstance(tags, list)
    assert len(tags) > 0
    # Should include words from all fields
    assert "retrieve" in tags
    assert "preferences" in tags
    assert "database" in tags
    assert "query" in tags
    assert "efficient" in tags
    # Should include metadata keys
    assert "user_id" in tags
    assert "query_type" in tags


def test_compute_content_hash():
    """Test computing content hash."""
    episode = Episode(
        goal="Test goal",
        action="Test action",
        result="Test result",
        reflection="Test reflection"
    )
    
    content_hash = Indexer.compute_content_hash(episode)
    
    assert isinstance(content_hash, str)
    assert len(content_hash) == 64  # SHA-256 hash length
    assert content_hash == episode.episode_id


def test_enrich_metadata():
    """Test enriching episode metadata."""
    episode = Episode(
        goal="Test goal",
        action="Test action",
        result="Test result",
        reflection="Test reflection",
        metadata={"user_id": "123"}
    )
    
    enriched = Indexer.enrich_metadata(episode)
    
    assert "user_id" in enriched
    assert enriched["user_id"] == "123"
    assert "tags" in enriched
    assert isinstance(enriched["tags"], list)
    assert "goal_length" in enriched
    assert enriched["goal_length"] == len("Test goal")
    assert "action_length" in enriched
    assert "result_length" in enriched
    assert "reflection_length" in enriched


def test_enrich_metadata_no_auto_tags():
    """Test enriching metadata without auto tags."""
    episode = Episode(
        goal="Test goal",
        action="Test action",
        result="Test result",
        reflection="Test reflection"
    )
    
    enriched = Indexer.enrich_metadata(episode, auto_tags=False)
    
    assert "tags" not in enriched
    assert "goal_length" in enriched


def test_enrich_metadata_preserves_existing_tags():
    """Test that existing tags are preserved."""
    episode = Episode(
        goal="Test goal",
        action="Test action",
        result="Test result",
        reflection="Test reflection",
        metadata={"tags": ["custom", "tags"]}
    )
    
    enriched = Indexer.enrich_metadata(episode, auto_tags=True)
    
    assert enriched["tags"] == ["custom", "tags"]


def test_create_search_text():
    """Test creating search text from episode."""
    episode = Episode(
        goal="Retrieve user data",
        action="Query database",
        result="Success",
        reflection="Worked well",
        metadata={"user_id": "123"}
    )
    
    search_text = Indexer.create_search_text(episode)
    
    assert isinstance(search_text, str)
    assert "Goal: Retrieve user data" in search_text
    assert "Action: Query database" in search_text
    assert "Result: Success" in search_text
    assert "Reflection: Worked well" in search_text
    assert "Context:" in search_text
    assert "user_id: 123" in search_text


def test_create_search_text_no_metadata():
    """Test creating search text without metadata."""
    episode = Episode(
        goal="Test goal",
        action="Test action",
        result="Test result",
        reflection="Test reflection"
    )
    
    search_text = Indexer.create_search_text(episode)
    
    assert "Goal: Test goal" in search_text
    assert "Context:" not in search_text
