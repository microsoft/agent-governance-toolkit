# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for SemanticRule schema."""

import pytest
from datetime import datetime, timezone
from emk.schema import SemanticRule


def test_semantic_rule_creation():
    """Test creating a basic semantic rule."""
    rule = SemanticRule(
        rule="Use indexed user_id for database queries",
        source_episode_ids=["abc123", "def456"]
    )
    
    assert rule.rule == "Use indexed user_id for database queries"
    assert len(rule.source_episode_ids) == 2
    assert rule.confidence == 1.0
    assert rule.rule_id != ""


def test_semantic_rule_with_context():
    """Test creating a semantic rule with context."""
    rule = SemanticRule(
        rule="Cache frequently accessed user data",
        source_episode_ids=["xyz789"],
        context="Performance optimization",
        confidence=0.85
    )
    
    assert rule.context == "Performance optimization"
    assert rule.confidence == 0.85


def test_semantic_rule_with_metadata():
    """Test creating a semantic rule with metadata."""
    rule = SemanticRule(
        rule="Retry failed requests with exponential backoff",
        source_episode_ids=["aaa111", "bbb222", "ccc333"],
        metadata={"pattern_type": "error_handling", "frequency": 25}
    )
    
    assert rule.metadata["pattern_type"] == "error_handling"
    assert rule.metadata["frequency"] == 25


def test_semantic_rule_id_generation():
    """Test that rule_id is auto-generated."""
    rule = SemanticRule(
        rule="Test rule",
        source_episode_ids=["test123"]
    )
    
    assert rule.rule_id != ""
    assert len(rule.rule_id) == 64  # SHA-256 hash


def test_semantic_rule_immutability():
    """Test that semantic rules are immutable."""
    rule = SemanticRule(
        rule="Original rule",
        source_episode_ids=["test123"]
    )
    
    with pytest.raises(Exception):  # Pydantic will raise ValidationError or AttributeError
        rule.rule = "Modified rule"


def test_semantic_rule_serialization():
    """Test semantic rule JSON serialization."""
    rule = SemanticRule(
        rule="Test serialization",
        source_episode_ids=["abc", "def"],
        context="Testing",
        confidence=0.9,
        metadata={"test": True}
    )
    
    # Serialize to JSON
    json_str = rule.to_json()
    assert isinstance(json_str, str)
    
    # Deserialize
    restored_rule = SemanticRule.from_json(json_str)
    
    assert restored_rule.rule == rule.rule
    assert restored_rule.source_episode_ids == rule.source_episode_ids
    assert restored_rule.context == rule.context
    assert restored_rule.confidence == rule.confidence
    assert restored_rule.metadata == rule.metadata


def test_semantic_rule_to_dict():
    """Test semantic rule dictionary conversion."""
    rule = SemanticRule(
        rule="Test dict conversion",
        source_episode_ids=["test"]
    )
    
    rule_dict = rule.to_dict()
    
    assert isinstance(rule_dict, dict)
    assert rule_dict["rule"] == "Test dict conversion"
    assert rule_dict["source_episode_ids"] == ["test"]


def test_semantic_rule_from_dict():
    """Test creating semantic rule from dictionary."""
    data = {
        "rule": "Test from dict",
        "source_episode_ids": ["id1", "id2"],
        "context": "Test context",
        "confidence": 0.75
    }
    
    rule = SemanticRule.from_dict(data)
    
    assert rule.rule == data["rule"]
    assert rule.source_episode_ids == data["source_episode_ids"]
    assert rule.context == data["context"]
    assert rule.confidence == data["confidence"]


def test_semantic_rule_confidence_validation():
    """Test that confidence is validated between 0 and 1."""
    # Valid confidence
    rule = SemanticRule(
        rule="Valid confidence",
        source_episode_ids=["test"],
        confidence=0.5
    )
    assert rule.confidence == 0.5
    
    # Test edge cases
    rule_min = SemanticRule(
        rule="Min confidence",
        source_episode_ids=["test"],
        confidence=0.0
    )
    assert rule_min.confidence == 0.0
    
    rule_max = SemanticRule(
        rule="Max confidence",
        source_episode_ids=["test"],
        confidence=1.0
    )
    assert rule_max.confidence == 1.0
    
    # Invalid confidence should raise error
    with pytest.raises(Exception):  # Pydantic validation error
        SemanticRule(
            rule="Invalid confidence",
            source_episode_ids=["test"],
            confidence=1.5
        )


def test_semantic_rule_empty_source_ids():
    """Test semantic rule with empty source episode IDs."""
    rule = SemanticRule(
        rule="No source episodes",
        source_episode_ids=[]
    )
    
    assert len(rule.source_episode_ids) == 0


def test_semantic_rule_timestamp():
    """Test that created_at timestamp is auto-generated."""
    rule = SemanticRule(
        rule="Test timestamp",
        source_episode_ids=["test"]
    )
    
    assert isinstance(rule.created_at, datetime)
    assert rule.created_at.tzinfo == timezone.utc
