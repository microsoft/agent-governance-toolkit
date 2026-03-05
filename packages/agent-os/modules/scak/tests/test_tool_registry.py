# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Tests for tool registry.
"""

import pytest
import asyncio
from src.interfaces.tool_registry import (
    ToolRegistry,
    ToolDefinition,
    ToolParameter,
    ToolType,
    tool,
    create_default_registry
)


class TestToolRegistry:
    """Test tool registry functionality."""
    
    def test_initialization(self):
        """Test registry initialization."""
        registry = ToolRegistry()
        
        assert len(registry.tools) == 0
        assert len(registry.executors) == 0
    
    def test_register_tool(self):
        """Test registering a tool."""
        registry = ToolRegistry()
        
        definition = ToolDefinition(
            name="test_tool",
            description="A test tool",
            tool_type=ToolType.TEXT,
            parameters=[],
            returns="string"
        )
        
        async def executor(**kwargs):
            return "test result"
        
        registry.register_tool(definition, executor)
        
        assert "test_tool" in registry.tools
        assert "test_tool" in registry.executors
    
    @pytest.mark.asyncio
    async def test_execute_tool(self):
        """Test tool execution."""
        registry = ToolRegistry()
        
        definition = ToolDefinition(
            name="greet",
            description="Greet someone",
            tool_type=ToolType.TEXT,
            parameters=[
                ToolParameter(name="name", type="string", description="Name", required=True)
            ],
            returns="greeting"
        )
        
        async def executor(name: str):
            return f"Hello, {name}!"
        
        registry.register_tool(definition, executor)
        
        result = await registry.execute_tool("greet", {"name": "Alice"})
        
        assert result["success"] is True
        assert result["result"] == "Hello, Alice!"
        assert "duration_ms" in result
    
    @pytest.mark.asyncio
    async def test_execute_nonexistent_tool(self):
        """Test executing non-existent tool."""
        registry = ToolRegistry()
        
        with pytest.raises(ValueError, match="Tool 'unknown' not found"):
            await registry.execute_tool("unknown", {})
    
    @pytest.mark.asyncio
    async def test_execute_tool_with_approval(self):
        """Test tool requiring approval."""
        registry = ToolRegistry()
        
        definition = ToolDefinition(
            name="restricted",
            description="Restricted tool",
            tool_type=ToolType.CODE,
            parameters=[],
            returns="result",
            requires_approval=True
        )
        
        async def executor():
            return "executed"
        
        registry.register_tool(definition, executor)
        
        # Should fail without approval callback
        with pytest.raises(RuntimeError, match="execution rejected"):
            await registry.execute_tool("restricted", {})
    
    @pytest.mark.asyncio
    async def test_execute_tool_with_approval_callback(self):
        """Test tool with approval callback."""
        registry = ToolRegistry()
        
        definition = ToolDefinition(
            name="restricted",
            description="Restricted tool",
            tool_type=ToolType.CODE,
            parameters=[],
            returns="result",
            requires_approval=True
        )
        
        async def executor():
            return "executed"
        
        async def approve_callback(params):
            return True  # Approve
        
        registry.register_tool(definition, executor)
        registry.register_approval_callback("restricted", approve_callback)
        
        result = await registry.execute_tool("restricted", {})
        assert result["success"] is True
    
    def test_get_tool_schema(self):
        """Test getting OpenAI-compatible schema."""
        registry = ToolRegistry()
        
        definition = ToolDefinition(
            name="search",
            description="Search the web",
            tool_type=ToolType.TEXT,
            parameters=[
                ToolParameter(name="query", type="string", description="Search query", required=True),
                ToolParameter(name="limit", type="integer", description="Result limit", required=False)
            ],
            returns="results"
        )
        
        async def executor(**kwargs):
            return []
        
        registry.register_tool(definition, executor)
        
        schema = registry.get_tool_schema("search")
        
        assert schema is not None
        assert schema["name"] == "search"
        assert "parameters" in schema
        assert "query" in schema["parameters"]["properties"]
        assert "limit" in schema["parameters"]["properties"]
        assert "query" in schema["parameters"]["required"]
    
    def test_list_tools(self):
        """Test listing tools."""
        registry = ToolRegistry()
        
        for i in range(3):
            definition = ToolDefinition(
                name=f"tool_{i}",
                description=f"Tool {i}",
                tool_type=ToolType.TEXT,
                parameters=[],
                returns="result"
            )
            registry.register_tool(definition, lambda: None)
        
        tools = registry.list_tools()
        assert len(tools) == 3
        assert "tool_0" in tools
    
    def test_get_tools_by_type(self):
        """Test filtering tools by type."""
        registry = ToolRegistry()
        
        registry.register_tool(
            ToolDefinition(name="t1", description="", tool_type=ToolType.TEXT, parameters=[], returns=""),
            lambda: None
        )
        registry.register_tool(
            ToolDefinition(name="t2", description="", tool_type=ToolType.VISION, parameters=[], returns=""),
            lambda: None
        )
        registry.register_tool(
            ToolDefinition(name="t3", description="", tool_type=ToolType.TEXT, parameters=[], returns=""),
            lambda: None
        )
        
        text_tools = registry.get_tools_by_type(ToolType.TEXT)
        vision_tools = registry.get_tools_by_type(ToolType.VISION)
        
        assert len(text_tools) == 2
        assert len(vision_tools) == 1


class TestToolDecorator:
    """Test tool decorator."""
    
    def test_decorator_basic(self):
        """Test basic decorator usage."""
        
        @tool("test_func", "Test function")
        async def test_func(arg1: str, arg2: int = 10) -> str:
            return f"{arg1}-{arg2}"
        
        assert hasattr(test_func, '_tool_definition')
        definition = test_func._tool_definition
        
        assert definition.name == "test_func"
        assert definition.description == "Test function"
        assert len(definition.parameters) == 2
    
    def test_decorator_with_multimodal(self):
        """Test decorator with multimodal inputs."""
        
        @tool(
            "vision_tool",
            "Process images",
            tool_type=ToolType.VISION,
            multimodal_inputs=["image"]
        )
        async def vision_tool(image_url: str) -> str:
            return "analyzed"
        
        definition = vision_tool._tool_definition
        
        assert definition.tool_type == ToolType.VISION
        assert "image" in definition.multimodal_inputs


class TestDefaultRegistry:
    """Test default registry creation."""
    
    def test_create_default_registry(self):
        """Test creating default registry with pre-registered tools."""
        registry = create_default_registry()
        
        tools = registry.list_tools()
        
        assert len(tools) > 0
        assert "web_search" in tools
        assert "analyze_image" in tools
    
    @pytest.mark.asyncio
    async def test_default_tool_execution(self):
        """Test executing default tools."""
        registry = create_default_registry()
        
        result = await registry.execute_tool(
            "web_search",
            {"query": "test", "max_results": 5}
        )
        
        assert result["success"] is True
        assert isinstance(result["result"], list)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
