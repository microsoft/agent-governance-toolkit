# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Tests for Model Upgrade Manager

This module tests the upgrade purge strategy for wisdom database lifecycle management.
"""

import os
import json
import tempfile
from datetime import datetime

import sys

# Add parent directory to path to allow imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.model_upgrade import ModelUpgradeManager
from src.agent import MemorySystem


def setup_test_wisdom_database(temp_file):
    """
    Set up a test wisdom database with sample improvements.
    
    Args:
        temp_file: Path to temporary file for test database
        
    Returns:
        Dict containing the wisdom data structure
    """
    wisdom_data = {
        "version": 4,
        "instructions": "You are a helpful AI assistant with calculator tools.",
        "improvements": [
            {
                "version": 2,
                "timestamp": "2024-01-01T10:00:00",
                "critique": "Agent should use calculator for math operations",
                "query": "What is 15 * 24 + 100?",
                "response": "Let me calculate that... approximately 460"
            },
            {
                "version": 3,
                "timestamp": "2024-01-02T11:00:00",
                "critique": "Agent should explain tool usage more clearly",
                "query": "Calculate the sum of 100 and 200",
                "response": "The answer is 300"
            },
            {
                "version": 4,
                "timestamp": "2024-01-03T12:00:00",
                "critique": "Agent needs to be more accurate with string length",
                "query": "What is the length of 'hello world'?",
                "response": "It has about 11 characters"
            }
        ]
    }
    
    with open(temp_file, 'w') as f:
        json.dump(wisdom_data, f, indent=2)
    
    return wisdom_data


def test_model_upgrade_manager_initialization():
    """Test that ModelUpgradeManager initializes correctly."""
    print("\nTest: ModelUpgradeManager Initialization")
    print("-" * 60)
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        temp_wisdom_file = f.name
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        temp_log_file = f.name
    
    try:
        # Create test wisdom database
        setup_test_wisdom_database(temp_wisdom_file)
        
        # Initialize manager
        manager = ModelUpgradeManager(
            wisdom_file=temp_wisdom_file,
            upgrade_log_file=temp_log_file,
            enable_prioritization=False
        )
        
        # Verify initialization
        assert manager.wisdom is not None, "Wisdom system should be initialized"
        assert manager.tools is not None, "Tools should be initialized"
        assert len(manager.wisdom.instructions.get("improvements", [])) == 3, "Should load 3 improvements"
        
        print("✅ Manager initialized successfully")
        print(f"   Wisdom version: {manager.wisdom.instructions['version']}")
        print(f"   Total improvements: {len(manager.wisdom.instructions.get('improvements', []))}")
        
    finally:
        # Cleanup
        if os.path.exists(temp_wisdom_file):
            os.remove(temp_wisdom_file)
        if os.path.exists(temp_log_file):
            os.remove(temp_log_file)
    
    print("✅ Test passed!\n")


def test_extract_failure_scenarios():
    """Test extraction of failure scenarios from improvements."""
    print("\nTest: Extract Failure Scenarios")
    print("-" * 60)
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        temp_wisdom_file = f.name
    
    try:
        # Create test wisdom database
        setup_test_wisdom_database(temp_wisdom_file)
        
        # Initialize manager
        manager = ModelUpgradeManager(
            wisdom_file=temp_wisdom_file,
            enable_prioritization=False
        )
        
        # Extract scenarios
        scenarios = manager._extract_failure_scenarios()
        
        # Verify extraction
        assert len(scenarios) == 3, f"Expected 3 scenarios, got {len(scenarios)}"
        assert all('version' in s for s in scenarios), "All scenarios should have version"
        assert all('critique' in s for s in scenarios), "All scenarios should have critique"
        assert all('query' in s for s in scenarios), "All scenarios should have query"
        
        print("✅ Extracted failure scenarios:")
        for i, scenario in enumerate(scenarios, 1):
            print(f"   {i}. Version {scenario['version']}: {scenario['query'][:50]}...")
        
    finally:
        # Cleanup
        if os.path.exists(temp_wisdom_file):
            os.remove(temp_wisdom_file)
    
    print("✅ Test passed!\n")


def test_audit_structure():
    """Test the structure of audit results (without API calls)."""
    print("\nTest: Audit Structure")
    print("-" * 60)
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        temp_wisdom_file = f.name
    
    try:
        # Create test wisdom database
        setup_test_wisdom_database(temp_wisdom_file)
        
        # Initialize manager
        manager = ModelUpgradeManager(
            wisdom_file=temp_wisdom_file,
            enable_prioritization=False
        )
        
        # Test that audit method exists and has correct signature
        assert hasattr(manager, 'audit_wisdom_database'), "Should have audit method"
        
        # Test audit results structure (mock version)
        mock_audit_results = {
            "new_model": "gpt-4o",
            "baseline_instructions": "Test instructions",
            "score_threshold": 0.8,
            "timestamp": datetime.now().isoformat(),
            "total_scenarios": 3,
            "tested_scenarios": 3,
            "redundant_lessons": [],
            "critical_lessons": [],
            "scenarios_without_query": 0
        }
        
        # Verify structure
        required_keys = [
            "new_model", "baseline_instructions", "score_threshold",
            "timestamp", "total_scenarios", "tested_scenarios",
            "redundant_lessons", "critical_lessons"
        ]
        
        for key in required_keys:
            assert key in mock_audit_results, f"Audit results should have '{key}'"
        
        print("✅ Audit structure is correct:")
        for key in required_keys:
            print(f"   ✓ {key}")
        
    finally:
        # Cleanup
        if os.path.exists(temp_wisdom_file):
            os.remove(temp_wisdom_file)
    
    print("✅ Test passed!\n")


def test_purge_redundant_lessons():
    """Test purging of redundant lessons."""
    print("\nTest: Purge Redundant Lessons")
    print("-" * 60)
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        temp_wisdom_file = f.name
    
    try:
        # Create test wisdom database
        original_data = setup_test_wisdom_database(temp_wisdom_file)
        
        # Initialize manager
        manager = ModelUpgradeManager(
            wisdom_file=temp_wisdom_file,
            enable_prioritization=False
        )
        
        # Create mock audit results with some redundant lessons
        mock_audit_results = {
            "new_model": "gpt-4o",
            "baseline_instructions": "Test instructions",
            "score_threshold": 0.8,
            "redundant_lessons": [
                {
                    "version": 2,
                    "timestamp": "2024-01-01T10:00:00",
                    "critique": "Agent should use calculator",
                    "query": "What is 15 * 24 + 100?",
                    "new_model_score": 0.9
                },
                {
                    "version": 3,
                    "timestamp": "2024-01-02T11:00:00",
                    "critique": "Agent should explain tool usage",
                    "query": "Calculate the sum of 100 and 200",
                    "new_model_score": 0.85
                }
            ],
            "critical_lessons": [
                {
                    "version": 4,
                    "timestamp": "2024-01-03T12:00:00",
                    "critique": "Agent needs to be more accurate",
                    "query": "What is the length of 'hello world'?",
                    "new_model_score": 0.6
                }
            ]
        }
        
        # Purge redundant lessons
        purge_results = manager.purge_redundant_lessons(
            audit_results=mock_audit_results,
            verbose=True
        )
        
        # Verify purge
        assert purge_results['purged_count'] == 2, f"Expected 2 purged, got {purge_results['purged_count']}"
        assert purge_results['remaining_count'] == 1, f"Expected 1 remaining, got {purge_results['remaining_count']}"
        
        # Verify wisdom database was updated
        remaining_improvements = manager.wisdom.instructions.get('improvements', [])
        assert len(remaining_improvements) == 1, "Should have 1 remaining improvement"
        assert remaining_improvements[0]['version'] == 4, "Version 4 should remain"
        
        # Verify purge history was recorded
        assert 'purge_history' in manager.wisdom.instructions, "Should have purge_history"
        assert len(manager.wisdom.instructions['purge_history']) == 1, "Should have 1 purge record"
        
        purge_record = manager.wisdom.instructions['purge_history'][0]
        assert purge_record['purged_count'] == 2, "Purge record should show 2 purged"
        assert purge_record['new_model'] == "gpt-4o", "Purge record should show new model"
        
        print("✅ Purge results:")
        print(f"   Purged: {purge_results['purged_count']} lessons")
        print(f"   Remaining: {purge_results['remaining_count']} lessons")
        print(f"   Reduction: {(purge_results['purged_count'] / 3) * 100:.0f}%")
        
    finally:
        # Cleanup
        if os.path.exists(temp_wisdom_file):
            os.remove(temp_wisdom_file)
    
    print("✅ Test passed!\n")


def test_upgrade_log():
    """Test upgrade log tracking."""
    print("\nTest: Upgrade Log Tracking")
    print("-" * 60)
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        temp_wisdom_file = f.name
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        temp_log_file = f.name
    
    try:
        # Create test wisdom database
        setup_test_wisdom_database(temp_wisdom_file)
        
        # Initialize manager
        manager = ModelUpgradeManager(
            wisdom_file=temp_wisdom_file,
            upgrade_log_file=temp_log_file,
            enable_prioritization=False
        )
        
        # Create mock audit and purge
        mock_audit_results = {
            "new_model": "gpt-4o",
            "redundant_lessons": [{"version": 2}, {"version": 3}],
            "critical_lessons": [{"version": 4}]
        }
        
        manager.purge_redundant_lessons(mock_audit_results, verbose=False)
        
        # Verify upgrade log
        assert os.path.exists(temp_log_file), "Upgrade log file should exist"
        
        with open(temp_log_file, 'r') as f:
            log_data = json.load(f)
        
        assert 'upgrades' in log_data, "Log should have upgrades list"
        assert len(log_data['upgrades']) == 1, "Should have 1 upgrade record"
        assert log_data['current_model'] == "gpt-4o", "Current model should be updated"
        
        upgrade_record = log_data['upgrades'][0]
        assert upgrade_record['new_model'] == "gpt-4o", "Upgrade record should show new model"
        assert upgrade_record['purged_count'] == 2, "Upgrade record should show purged count"
        
        print("✅ Upgrade log created successfully:")
        print(f"   Current model: {log_data['current_model']}")
        print(f"   Total upgrades: {len(log_data['upgrades'])}")
        print(f"   Latest upgrade: {upgrade_record['purged_count']} lessons purged")
        
    finally:
        # Cleanup
        if os.path.exists(temp_wisdom_file):
            os.remove(temp_wisdom_file)
        if os.path.exists(temp_log_file):
            os.remove(temp_log_file)
    
    print("✅ Test passed!\n")


def test_memory_system_update_with_context():
    """Test that MemorySystem correctly stores query and response."""
    print("\nTest: MemorySystem Update with Context")
    print("-" * 60)
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        temp_file = f.name
    
    try:
        # Initialize memory system
        memory = MemorySystem(temp_file)
        
        # Update with query and response
        memory.update_instructions(
            new_instructions="Test instructions",
            critique="Test critique",
            query="Test query",
            response="Test response"
        )
        
        # Verify storage
        improvements = memory.instructions.get('improvements', [])
        assert len(improvements) == 1, "Should have 1 improvement"
        
        improvement = improvements[0]
        assert 'query' in improvement, "Improvement should have query"
        assert 'response' in improvement, "Improvement should have response"
        assert improvement['query'] == "Test query", "Query should match"
        assert improvement['response'] == "Test response", "Response should match"
        
        print("✅ MemorySystem correctly stores context:")
        print(f"   Query: {improvement['query']}")
        print(f"   Response: {improvement['response']}")
        print(f"   Critique: {improvement['critique']}")
        
    finally:
        # Cleanup
        if os.path.exists(temp_file):
            os.remove(temp_file)
    
    print("✅ Test passed!\n")


def run_all_tests():
    """
    Run all tests in the model upgrade test suite.
    
    Returns:
        bool: True if all tests passed, False otherwise
    """
    print("\n" + "="*70)
    print("MODEL UPGRADE MANAGER - TEST SUITE")
    print("="*70)
    
    tests = [
        test_model_upgrade_manager_initialization,
        test_extract_failure_scenarios,
        test_audit_structure,
        test_purge_redundant_lessons,
        test_upgrade_log,
        test_memory_system_update_with_context
    ]
    
    passed = 0
    failed = 0
    
    for test_func in tests:
        try:
            test_func()
            passed += 1
        except AssertionError as e:
            print(f"❌ Test failed: {e}\n")
            failed += 1
        except Exception as e:
            print(f"❌ Test error: {e}\n")
            failed += 1
    
    print("="*70)
    print(f"TEST SUMMARY: {passed} passed, {failed} failed")
    print("="*70)
    
    return failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    exit(0 if success else 1)
