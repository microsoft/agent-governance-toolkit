# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""
Test suite for the Context Triad (Hot, Warm, Cold) implementation.
"""

from caas.triad import ContextTriadManager
from caas.models import ContextLayer


def test_hot_context():
    """Test hot context management (The Situation)."""
    print("\n=== Testing Hot Context (The Situation) ===")
    
    manager = ContextTriadManager()
    
    # Add hot context items
    id1 = manager.add_hot_context(
        "User is debugging a NullPointerException in the authentication module",
        metadata={"source": "error_log", "type": "exception"},
        priority=2.0
    )
    print(f"✓ Added hot context item: {id1}")
    
    id2 = manager.add_hot_context(
        "Currently viewing auth_service.py lines 145-200",
        metadata={"source": "vscode", "type": "open_file"},
        priority=1.5
    )
    print(f"✓ Added hot context item: {id2}")
    
    id3 = manager.add_hot_context(
        "Current conversation: How to fix authentication issues?",
        metadata={"source": "conversation", "type": "user_message"},
        priority=3.0
    )
    print(f"✓ Added hot context item: {id3}")
    
    # Get hot context
    hot_context = manager.get_hot_context(max_tokens=500, include_metadata=True)
    print(f"\n--- Hot Context (prioritized) ---\n{hot_context}")
    
    # Verify hot context items are included
    assert "authentication" in hot_context.lower()
    assert "Hot Context" in hot_context
    print("✓ Hot context retrieved successfully")
    
    # Test clearing hot context
    manager.clear_hot_context()
    hot_context_after_clear = manager.get_hot_context()
    assert hot_context_after_clear == ""
    print("✓ Hot context cleared successfully")


def test_warm_context():
    """Test warm context management (The Persona)."""
    print("\n=== Testing Warm Context (The Persona) ===")
    
    manager = ContextTriadManager()
    
    # Add warm context items (user persona)
    id1 = manager.add_warm_context(
        "Senior Python developer with 8 years of experience",
        metadata={"category": "Experience", "source": "linkedin"},
        priority=1.5
    )
    print(f"✓ Added warm context item: {id1}")
    
    id2 = manager.add_warm_context(
        "Prefers type hints and comprehensive docstrings",
        metadata={"category": "Coding Style", "source": "preferences"},
        priority=2.0
    )
    print(f"✓ Added warm context item: {id2}")
    
    id3 = manager.add_warm_context(
        "Interested in AI/ML and distributed systems",
        metadata={"category": "Interests", "source": "github_bio"},
        priority=1.0
    )
    print(f"✓ Added warm context item: {id3}")
    
    id4 = manager.add_warm_context(
        "Prefers FastAPI over Flask, uses pytest for testing",
        metadata={"category": "Tech Stack", "source": "preferences"},
        priority=1.8
    )
    print(f"✓ Added warm context item: {id4}")
    
    # Get warm context
    warm_context = manager.get_warm_context(max_tokens=500, include_metadata=True)
    print(f"\n--- Warm Context (User Persona) ---\n{warm_context}")
    
    # Verify warm context items are included
    assert "Python" in warm_context or "python" in warm_context
    assert "Warm Context" in warm_context
    print("✓ Warm context retrieved successfully")


def test_cold_context():
    """Test cold context management (The Archive)."""
    print("\n=== Testing Cold Context (The Archive) ===")
    
    manager = ContextTriadManager()
    
    # Add cold context items (historical data)
    id1 = manager.add_cold_context(
        "Ticket #1234: Fixed authentication bug in v1.2.0 (closed 2023-06-15)",
        metadata={"date": "2023-06-15", "type": "ticket", "status": "closed"},
        priority=1.0
    )
    print(f"✓ Added cold context item: {id1}")
    
    id2 = manager.add_cold_context(
        "PR #567: Refactored authentication module (merged 2023-08-20)",
        metadata={"date": "2023-08-20", "type": "pr", "status": "merged"},
        priority=1.2
    )
    print(f"✓ Added cold context item: {id2}")
    
    id3 = manager.add_cold_context(
        "Design doc: Legacy authentication flow (2022-01-10)",
        metadata={"date": "2022-01-10", "type": "design_doc"},
        priority=0.8
    )
    print(f"✓ Added cold context item: {id3}")
    
    # Cold context without query should return empty
    cold_context_no_query = manager.get_cold_context()
    assert cold_context_no_query == ""
    print("✓ Cold context correctly returns empty without query")
    
    # Cold context with query
    cold_context = manager.get_cold_context(
        query="authentication",
        max_tokens=500,
        include_metadata=True
    )
    print(f"\n--- Cold Context (with query='authentication') ---\n{cold_context}")
    
    # Verify cold context items are included
    assert "authentication" in cold_context.lower()
    assert "Cold Context" in cold_context
    assert "Query: authentication" in cold_context
    print("✓ Cold context retrieved successfully with query")
    
    # Query that doesn't match should return minimal context
    cold_context_no_match = manager.get_cold_context(
        query="unrelated_topic",
        max_tokens=500
    )
    # Should still have header but no content
    assert cold_context_no_match == "" or "Cold Context" in cold_context_no_match
    print("✓ Cold context correctly handles non-matching query")


def test_full_context_triad():
    """Test the complete context triad."""
    print("\n=== Testing Full Context Triad ===")
    
    manager = ContextTriadManager()
    
    # Add hot context
    manager.add_hot_context(
        "Current error: AuthenticationError at line 145",
        metadata={"source": "error_log"},
        priority=2.0
    )
    
    # Add warm context
    manager.add_warm_context(
        "Senior developer, prefers detailed error messages",
        metadata={"category": "Profile"},
        priority=1.5
    )
    
    # Add cold context
    manager.add_cold_context(
        "Previous authentication bug fixed in 2023",
        metadata={"date": "2023-06-15"},
        priority=1.0
    )
    
    # Test 1: Hot + Warm only (default behavior)
    print("\n--- Test 1: Hot + Warm Context (Default) ---")
    result = manager.get_full_context(
        include_hot=True,
        include_warm=True,
        include_cold=False
    )
    
    assert "hot" in result["layers_included"]
    assert "warm" in result["layers_included"]
    assert "cold" not in result["layers_included"]
    assert "AuthenticationError" in result["hot_context"]
    assert "developer" in result["warm_context"].lower()
    assert result["cold_context"] == ""
    print("✓ Hot + Warm context retrieved (Cold excluded as expected)")
    
    # Test 2: Hot + Warm + Cold with query
    print("\n--- Test 2: Hot + Warm + Cold Context (with query) ---")
    result = manager.get_full_context(
        include_hot=True,
        include_warm=True,
        include_cold=True,
        cold_query="authentication"
    )
    
    assert "hot" in result["layers_included"]
    assert "warm" in result["layers_included"]
    assert "cold" in result["layers_included"]
    assert "AuthenticationError" in result["hot_context"]
    assert "authentication" in result["cold_context"].lower()
    print("✓ All three layers retrieved successfully")
    
    # Test 3: Cold without query (should not include cold)
    print("\n--- Test 3: Cold Context without query ---")
    result = manager.get_full_context(
        include_hot=False,
        include_warm=False,
        include_cold=True,
        cold_query=None
    )
    
    assert "cold" not in result["layers_included"]
    assert result["cold_context"] == ""
    print("✓ Cold context correctly excluded without query")
    
    # Test 4: Only Hot context
    print("\n--- Test 4: Only Hot Context ---")
    result = manager.get_full_context(
        include_hot=True,
        include_warm=False,
        include_cold=False
    )
    
    assert result["layers_included"] == ["hot"]
    assert "AuthenticationError" in result["hot_context"]
    print("✓ Only Hot context retrieved")


def test_context_policies():
    """Test that context triad follows its policies."""
    print("\n=== Testing Context Triad Policies ===")
    
    manager = ContextTriadManager()
    
    # Add items to all layers
    manager.add_hot_context("Hot: Current debugging session")
    manager.add_warm_context("Warm: User prefers Python")
    manager.add_cold_context("Cold: Old ticket from 2022")
    
    # Policy 1: Hot context ALWAYS included by default
    result = manager.get_full_context()
    assert "hot" in result["layers_included"]
    print("✓ Policy 1: Hot context included by default (Attention Head)")
    
    # Policy 2: Warm context ALWAYS ON by default
    assert "warm" in result["layers_included"]
    print("✓ Policy 2: Warm context included by default (Always On Filter)")
    
    # Policy 3: Cold context ON DEMAND ONLY (not included without query)
    assert "cold" not in result["layers_included"]
    print("✓ Policy 3: Cold context excluded by default (On Demand Only)")
    
    # Policy 4: Cold context only with explicit query
    result = manager.get_full_context(include_cold=True, cold_query="ticket")
    assert "cold" in result["layers_included"]
    print("✓ Policy 4: Cold context included when explicitly queried")


def test_priority_ordering():
    """Test that items are ordered by priority."""
    print("\n=== Testing Priority Ordering ===")
    
    manager = ContextTriadManager()
    
    # Add hot context with different priorities
    manager.add_hot_context("Low priority item", priority=1.0)
    manager.add_hot_context("High priority item", priority=3.0)
    manager.add_hot_context("Medium priority item", priority=2.0)
    
    hot_context = manager.get_hot_context()
    
    # High priority should appear first
    high_pos = hot_context.find("High priority")
    medium_pos = hot_context.find("Medium priority")
    low_pos = hot_context.find("Low priority")
    
    assert high_pos < medium_pos < low_pos
    print("✓ Items correctly ordered by priority (high to low)")


def test_token_limits():
    """Test that token limits are respected."""
    print("\n=== Testing Token Limits ===")
    
    manager = ContextTriadManager()
    
    # Add multiple hot context items
    for i in range(10):
        manager.add_hot_context(
            f"Item {i}: " + ("Long content " * 50),  # Make it long
            priority=1.0
        )
    
    # Get with small token limit
    hot_context = manager.get_hot_context(max_tokens=100)
    
    # Should be truncated
    assert len(hot_context) < 100 * 6  # Rough estimate (4-6 chars per token)
    print("✓ Token limits respected")


def test_item_removal():
    """Test removing items from context."""
    print("\n=== Testing Item Removal ===")
    
    manager = ContextTriadManager()
    
    # Add items
    hot_id = manager.add_hot_context("Hot item")
    warm_id = manager.add_warm_context("Warm item")
    cold_id = manager.add_cold_context("Cold item")
    
    # Check initial state
    state = manager.get_state()
    assert len(state.hot_context) == 1
    assert len(state.warm_context) == 1
    assert len(state.cold_context) == 1
    
    # Remove items
    assert manager.remove_item(hot_id, ContextLayer.HOT)
    assert manager.remove_item(warm_id, ContextLayer.WARM)
    assert manager.remove_item(cold_id, ContextLayer.COLD)
    
    # Check final state
    state = manager.get_state()
    assert len(state.hot_context) == 0
    assert len(state.warm_context) == 0
    assert len(state.cold_context) == 0
    
    print("✓ Items successfully removed from all layers")


def test_hot_context_limit():
    """Test that hot context is limited to keep it fresh."""
    print("\n=== Testing Hot Context Auto-Limit ===")
    
    manager = ContextTriadManager()
    
    # Add many hot context items (more than limit)
    for i in range(60):
        manager.add_hot_context(f"Hot item {i}")
    
    state = manager.get_state()
    
    # Should be limited to 50 most recent items
    assert len(state.hot_context) <= 50
    print(f"✓ Hot context limited to {len(state.hot_context)} items (max 50)")


if __name__ == "__main__":
    print("============================================================")
    print("Context Triad Test Suite")
    print("============================================================")
    
    try:
        test_hot_context()
        test_warm_context()
        test_cold_context()
        test_full_context_triad()
        test_context_policies()
        test_priority_ordering()
        test_token_limits()
        test_item_removal()
        test_hot_context_limit()
        
        print("\n============================================================")
        print("✅ All Context Triad tests passed successfully!")
        print("============================================================")
    except AssertionError as e:
        print(f"\n❌ Test failed: {e}")
        raise
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        raise
