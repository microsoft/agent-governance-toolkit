# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Test script to validate basic functionality without API calls.
Tests the core components and structure of the agent.
"""

import json
import os
import sys
import tempfile

# Add parent directory to path to allow imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.agent import MemorySystem, AgentTools


def test_memory_system():
    """Test the memory system."""
    print("Testing MemorySystem...")
    
    # Create a test memory file using tempfile for cross-platform compatibility
    test_file = os.path.join(tempfile.gettempdir(), 'test_instructions_temp.json')
    
    # Remove if exists from previous test
    if os.path.exists(test_file):
        os.remove(test_file)
    
    try:
        # Test initialization with new file (doesn't exist yet)
        memory = MemorySystem(test_file)
        assert memory.instructions is not None
        assert "instructions" in memory.instructions
        print("✓ Memory initialization works")
        
        # Test getting system prompt
        prompt = memory.get_system_prompt()
        assert isinstance(prompt, str)
        assert len(prompt) > 0
        print("✓ Get system prompt works")
        
        # Test updating instructions
        memory.update_instructions("New instructions", "Test critique")
        assert memory.instructions["version"] == 2
        assert len(memory.instructions["improvements"]) == 1
        print("✓ Update instructions works")
        
        # Test persistence
        memory2 = MemorySystem(test_file)
        assert memory2.instructions["version"] == 2
        assert memory2.instructions["instructions"] == "New instructions"
        print("✓ Instructions persistence works")
    finally:
        # Cleanup
        if os.path.exists(test_file):
            os.remove(test_file)
    
    print("MemorySystem: All tests passed!\n")


def test_agent_tools():
    """Test the agent tools."""
    print("Testing AgentTools...")
    
    tools = AgentTools()
    
    # Test calculator
    result = tools.calculate("2 + 2")
    assert "4" in result
    print("✓ Calculator tool works")
    
    # Test calculator with invalid input
    result = tools.calculate("import os")
    assert "Error" in result
    print("✓ Calculator validation works")
    
    # Test time tool
    result = tools.get_current_time()
    assert "Current time" in result
    print("✓ Time tool works")
    
    # Test string length
    result = tools.string_length("hello")
    assert "5" in result
    print("✓ String length tool works")
    
    # Test get available tools
    result = tools.get_available_tools()
    assert "calculate" in result
    assert "get_current_time" in result
    print("✓ Get available tools works")
    
    print("AgentTools: All tests passed!\n")


def test_json_format():
    """Test that the system_instructions.json is valid."""
    print("Testing system_instructions.json format...")
    
    # Get the root directory (parent of tests/)
    root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    json_file = os.path.join(root_dir, "system_instructions.json")
    
    with open(json_file, 'r') as f:
        data = json.load(f)
    
    assert "version" in data
    assert "instructions" in data
    assert "improvements" in data
    assert isinstance(data["version"], int)
    assert isinstance(data["instructions"], str)
    assert isinstance(data["improvements"], list)
    
    print("✓ JSON format is valid")
    print("system_instructions.json: All tests passed!\n")


def test_structure():
    """Test that all required files exist."""
    print("Testing project structure...")
    
    required_files = [
        "src/agent.py",
        "examples/example.py",
        "system_instructions.json",
        "requirements.txt",
        ".env.example",
        ".gitignore",
        "README.md"
    ]
    
    # Get the root directory (parent of tests/)
    root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    
    for file in required_files:
        file_path = os.path.join(root_dir, file)
        assert os.path.exists(file_path), f"Missing file: {file}"
        print(f"✓ {file} exists")
    
    print("Project structure: All tests passed!\n")


def main():
    """Run all tests."""
    print("="*60)
    print("Running Self-Evolving Agent Tests")
    print("="*60)
    print()
    
    try:
        test_structure()
        test_json_format()
        test_memory_system()
        test_agent_tools()
        
        print("="*60)
        print("All tests passed! ✓")
        print("="*60)
        print("\nNote: These tests validate structure and basic functionality.")
        print("To test the full agent with LLM calls, set up your .env file")
        print("and run: python example.py")
        
    except AssertionError as e:
        print(f"\n✗ Test failed: {e}")
        return 1
    except Exception as e:
        print(f"\n✗ Unexpected error: {e}")
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())
