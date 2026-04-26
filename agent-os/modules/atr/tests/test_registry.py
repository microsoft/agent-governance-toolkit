# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for registry functionality."""

import pytest
from atr.registry import (
    Registry,
    ToolNotFoundError,
    ToolAlreadyExistsError,
)
from atr.schema import (
    ToolSpec,
    ToolMetadata,
    ParameterSpec,
    ParameterType,
    CostLevel,
    SideEffect,
)


def create_sample_tool(name: str = "test_tool") -> ToolSpec:
    """Helper to create a sample tool spec."""
    metadata = ToolMetadata(
        name=name,
        description=f"Test tool: {name}",
    )
    return ToolSpec(metadata=metadata, parameters=[])


def test_registry_initialization():
    """Test registry initialization."""
    registry = Registry()
    assert len(registry) == 0


def test_register_and_get_tool():
    """Test registering and retrieving a tool."""
    registry = Registry()
    tool_spec = create_sample_tool("scraper")
    
    registry.register_tool(tool_spec)
    
    retrieved = registry.get_tool("scraper")
    assert retrieved.metadata.name == "scraper"


def test_register_duplicate_tool_fails():
    """Test that registering duplicate tool raises error."""
    registry = Registry()
    tool_spec = create_sample_tool("duplicate")
    
    registry.register_tool(tool_spec)
    
    with pytest.raises(ToolAlreadyExistsError):
        registry.register_tool(tool_spec)


def test_register_duplicate_with_replace():
    """Test that replace=True allows overwriting."""
    registry = Registry()
    tool_spec1 = create_sample_tool("replaceable")
    tool_spec2 = create_sample_tool("replaceable")
    tool_spec2.metadata.description = "Updated description"
    
    registry.register_tool(tool_spec1)
    registry.register_tool(tool_spec2, replace=True)
    
    retrieved = registry.get_tool("replaceable")
    assert retrieved.metadata.description == "Updated description"


def test_get_nonexistent_tool_fails():
    """Test that getting nonexistent tool raises error."""
    registry = Registry()
    
    with pytest.raises(ToolNotFoundError):
        registry.get_tool("nonexistent")


def test_register_with_callable():
    """Test registering a tool with a callable function."""
    registry = Registry()
    
    def sample_func(x: int) -> int:
        return x * 2
    
    tool_spec = create_sample_tool("doubler")
    registry.register_tool(tool_spec, callable_func=sample_func)
    
    # Get the callable - registry returns it but doesn't execute
    retrieved_callable = registry.get_callable("doubler")
    assert retrieved_callable is sample_func
    
    # The Agent Runtime would execute it
    result = retrieved_callable(5)
    assert result == 10


def test_get_callable_without_function_fails():
    """Test that getting callable for tool without function raises error."""
    registry = Registry()
    tool_spec = create_sample_tool("no_callable")
    
    registry.register_tool(tool_spec)
    
    with pytest.raises(ValueError, match="has no callable function"):
        registry.get_callable("no_callable")


def test_list_tools():
    """Test listing all tools."""
    registry = Registry()
    
    registry.register_tool(create_sample_tool("tool1"))
    registry.register_tool(create_sample_tool("tool2"))
    registry.register_tool(create_sample_tool("tool3"))
    
    tools = registry.list_tools()
    assert len(tools) == 3
    assert any(t.metadata.name == "tool1" for t in tools)


def test_list_tools_by_tag():
    """Test filtering tools by tag."""
    registry = Registry()
    
    tool1 = create_sample_tool("web_tool")
    tool1.metadata.tags = ["web", "http"]
    
    tool2 = create_sample_tool("file_tool")
    tool2.metadata.tags = ["file", "io"]
    
    tool3 = create_sample_tool("web_tool2")
    tool3.metadata.tags = ["web", "scraping"]
    
    registry.register_tool(tool1)
    registry.register_tool(tool2)
    registry.register_tool(tool3)
    
    web_tools = registry.list_tools(tag="web")
    assert len(web_tools) == 2
    assert all("web" in t.metadata.tags for t in web_tools)


def test_list_tools_by_cost():
    """Test filtering tools by cost level."""
    registry = Registry()
    
    tool1 = create_sample_tool("cheap_tool")
    tool1.metadata.cost = CostLevel.LOW
    
    tool2 = create_sample_tool("expensive_tool")
    tool2.metadata.cost = CostLevel.HIGH
    
    tool3 = create_sample_tool("free_tool")
    tool3.metadata.cost = CostLevel.FREE
    
    registry.register_tool(tool1)
    registry.register_tool(tool2)
    registry.register_tool(tool3)
    
    low_cost_tools = registry.list_tools(cost=CostLevel.LOW)
    assert len(low_cost_tools) == 1
    assert low_cost_tools[0].metadata.name == "cheap_tool"


def test_list_tools_by_side_effect():
    """Test filtering tools by side effect."""
    registry = Registry()
    
    tool1 = create_sample_tool("reader")
    tool1.metadata.side_effects = [SideEffect.READ]
    
    tool2 = create_sample_tool("writer")
    tool2.metadata.side_effects = [SideEffect.WRITE]
    
    tool3 = create_sample_tool("networker")
    tool3.metadata.side_effects = [SideEffect.NETWORK, SideEffect.READ]
    
    registry.register_tool(tool1)
    registry.register_tool(tool2)
    registry.register_tool(tool3)
    
    read_tools = registry.list_tools(side_effect=SideEffect.READ)
    assert len(read_tools) == 2
    assert all(SideEffect.READ in t.metadata.side_effects for t in read_tools)


def test_search_tools_by_name():
    """Test searching tools by name."""
    registry = Registry()
    
    registry.register_tool(create_sample_tool("web_scraper"))
    registry.register_tool(create_sample_tool("file_reader"))
    registry.register_tool(create_sample_tool("web_crawler"))
    
    results = registry.search_tools("web")
    assert len(results) == 2
    assert all("web" in t.metadata.name for t in results)


def test_search_tools_by_description():
    """Test searching tools by description."""
    registry = Registry()
    
    tool1 = create_sample_tool("tool1")
    tool1.metadata.description = "Scrapes web pages"
    
    tool2 = create_sample_tool("tool2")
    tool2.metadata.description = "Reads local files"
    
    tool3 = create_sample_tool("tool3")
    tool3.metadata.description = "Web API client"
    
    registry.register_tool(tool1)
    registry.register_tool(tool2)
    registry.register_tool(tool3)
    
    results = registry.search_tools("web")
    assert len(results) == 2


def test_search_tools_by_tag():
    """Test searching tools by tag."""
    registry = Registry()
    
    tool1 = create_sample_tool("tool1")
    tool1.metadata.tags = ["database", "sql"]
    
    tool2 = create_sample_tool("tool2")
    tool2.metadata.tags = ["api", "rest"]
    
    registry.register_tool(tool1)
    registry.register_tool(tool2)
    
    results = registry.search_tools("database")
    assert len(results) == 1
    assert results[0].metadata.name == "tool1"


def test_unregister_tool():
    """Test unregistering a tool."""
    registry = Registry()
    tool_spec = create_sample_tool("to_remove")
    
    registry.register_tool(tool_spec)
    assert len(registry) == 1
    
    registry.unregister_tool("to_remove")
    assert len(registry) == 0


def test_unregister_nonexistent_tool_fails():
    """Test that unregistering nonexistent tool raises error."""
    registry = Registry()
    
    with pytest.raises(ToolNotFoundError):
        registry.unregister_tool("nonexistent")


def test_clear_registry():
    """Test clearing all tools from registry."""
    registry = Registry()
    
    registry.register_tool(create_sample_tool("tool1"))
    registry.register_tool(create_sample_tool("tool2"))
    registry.register_tool(create_sample_tool("tool3"))
    
    assert len(registry) == 3
    
    registry.clear()
    assert len(registry) == 0


def test_contains_operator():
    """Test 'in' operator for registry."""
    registry = Registry()
    tool_spec = create_sample_tool("exists")
    
    registry.register_tool(tool_spec)
    
    assert "exists" in registry
    assert "nonexistent" not in registry


def test_registry_does_not_execute_tools():
    """Test that registry stores but doesn't execute tools."""
    registry = Registry()
    
    # Track if function was called
    call_count = [0]
    
    def counting_func(x: int) -> int:
        call_count[0] += 1
        return x * 2
    
    tool_spec = create_sample_tool("counter")
    
    # Register the tool - should NOT execute it
    registry.register_tool(tool_spec, callable_func=counting_func)
    assert call_count[0] == 0, "Registry should not execute the tool on registration"
    
    # Get the tool - should NOT execute it
    retrieved = registry.get_tool("counter")
    assert call_count[0] == 0, "Registry should not execute the tool on retrieval"
    
    # Get the callable - should NOT execute it
    func = registry.get_callable("counter")
    assert call_count[0] == 0, "Registry should not execute the tool when getting callable"
    
    # Only when the Agent Runtime explicitly calls it
    result = func(5)
    assert call_count[0] == 1, "Function should only execute when explicitly called"
    assert result == 10
