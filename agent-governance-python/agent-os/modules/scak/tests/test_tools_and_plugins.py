# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Tests for OpenAPI tool discovery and plugin system.
"""

import pytest
import json
from pathlib import Path
from src.interfaces.openapi_tools import (
    OpenAPIParser,
    create_builtin_tools_library
)
from src.interfaces.tool_registry import ToolRegistry, ToolType


class TestOpenAPIParser:
    """Test OpenAPI specification parsing."""
    
    @pytest.fixture
    def parser(self):
        """Create parser instance."""
        return OpenAPIParser()
    
    def test_parse_valid_spec(self, parser):
        """Test parsing valid OpenAPI spec."""
        spec_yaml = """
openapi: 3.0.0
info:
  title: Test API
  version: 1.0.0
servers:
  - url: https://api.example.com
paths:
  /users:
    get:
      operationId: list_users
      summary: List all users
      responses:
        '200':
          description: Success
"""
        
        spec = parser.parse_spec(spec_yaml, format="yaml")
        
        assert spec["openapi"] == "3.0.0"
        assert spec["info"]["title"] == "Test API"
        assert spec["_base_url"] == "https://api.example.com"
    
    def test_parse_invalid_spec(self, parser):
        """Test parsing invalid spec raises error."""
        invalid_spec = "not valid yaml: ][]["
        
        with pytest.raises(ValueError):
            parser.parse_spec(invalid_spec, format="yaml")
    
    def test_extract_tools_from_spec(self, parser):
        """Test extracting tools from OpenAPI spec."""
        spec_yaml = """
openapi: 3.0.0
info:
  title: User API
  version: 1.0.0
servers:
  - url: https://api.example.com
paths:
  /users:
    get:
      operationId: list_users
      summary: List all users
      parameters:
        - name: limit
          in: query
          schema:
            type: integer
      responses:
        '200':
          description: List of users
  /users/{id}:
    get:
      operationId: get_user
      summary: Get user by ID
      parameters:
        - name: id
          in: path
          required: true
          schema:
            type: string
      responses:
        '200':
          description: User details
"""
        
        spec = parser.parse_spec(spec_yaml, format="yaml")
        tools = parser.extract_tools(spec, tool_prefix="user_api_")
        
        assert len(tools) == 2
        
        # Check first tool
        tool_names = [t.name for t in tools]
        assert "user_api_list_users" in tool_names or "user_api_get_user" in tool_names
        
        # Check parameters were extracted
        for tool in tools:
            assert tool.tool_type == ToolType.API
            assert len(tool.parameters) > 0
    
    def test_register_tools_from_spec(self, parser):
        """Test registering tools in registry."""
        spec_yaml = """
openapi: 3.0.0
info:
  title: Simple API
  version: 1.0.0
paths:
  /health:
    get:
      operationId: health_check
      summary: Health check
      responses:
        '200':
          description: OK
"""
        
        registry = ToolRegistry()
        count = parser.register_tools_from_spec(
            spec_yaml,
            registry,
            format="yaml",
            tool_prefix="api_"
        )
        
        assert count == 1
        assert len(registry.tools) == 1
        assert "api_health_check" in registry.tools


class TestBuiltinTools:
    """Test built-in tools library."""
    
    def test_create_builtin_library(self):
        """Test creating built-in tools library."""
        tools = create_builtin_tools_library()
        
        # Should have 60+ tools
        assert len(tools) >= 60
        
        # Check categories are represented
        tool_names = [t.name for t in tools]
        
        # Text processing
        assert any("text_" in name for name in tool_names)
        
        # Data manipulation
        assert any("data_" in name for name in tool_names)
        
        # File operations
        assert any("file_" in name for name in tool_names)
        
        # Web interaction
        assert any("web_" in name for name in tool_names)
        
        # Mathematics
        assert any("math_" in name for name in tool_names)
        
        # Time/Date
        assert any("time_" in name for name in tool_names)
    
    def test_builtin_tools_have_parameters(self):
        """Test built-in tools have proper parameters."""
        tools = create_builtin_tools_library()
        
        for tool in tools:
            assert tool.name
            assert tool.description
            assert tool.tool_type
            assert isinstance(tool.parameters, list)
            # Some tools have no parameters (like time_current)
            assert tool.returns


class TestPluginSystem:
    """Test plugin system (without actual plugin files)."""
    
    def test_plugin_metadata_validation(self):
        """Test plugin metadata model."""
        from src.interfaces.plugin_system import PluginMetadata
        
        metadata = PluginMetadata(
            plugin_id="test_plugin",
            name="Test Plugin",
            version="1.0.0",
            author="Test Author",
            description="A test plugin",
            provides_tools=["tool1", "tool2"]
        )
        
        assert metadata.plugin_id == "test_plugin"
        assert len(metadata.provides_tools) == 2
        assert metadata.sandboxed is True  # Default
    
    def test_plugin_initialization(self):
        """Test plugin initialization."""
        from src.interfaces.plugin_system import Plugin, PluginMetadata
        
        metadata = PluginMetadata(
            plugin_id="test",
            name="Test",
            version="1.0.0",
            author="Author",
            description="Description"
        )
        
        plugin = Plugin(metadata)
        
        assert plugin.metadata.plugin_id == "test"
        assert plugin.status.value == "inactive"
        assert len(plugin.registered_tools) == 0


class TestToolRegistry:
    """Test tool registry functionality."""
    
    @pytest.fixture
    def registry(self):
        """Create registry instance."""
        return ToolRegistry()
    
    @pytest.mark.asyncio
    async def test_register_and_execute_tool(self, registry):
        """Test registering and executing a tool."""
        from src.interfaces.tool_registry import ToolDefinition, ToolParameter
        
        # Define tool
        tool = ToolDefinition(
            name="test_add",
            description="Add two numbers",
            tool_type=ToolType.CODE,
            parameters=[
                ToolParameter(name="a", type="integer", description="First number", required=True),
                ToolParameter(name="b", type="integer", description="Second number", required=True)
            ],
            returns="Sum of a and b"
        )
        
        # Define executor
        def add_executor(a: int, b: int) -> int:
            return a + b
        
        # Register
        registry.register_tool(tool, add_executor)
        
        # Execute
        result = await registry.execute_tool("test_add", {"a": 5, "b": 3})
        
        assert result["success"] is True
        assert result["result"] == 8
    
    def test_get_tool_schema(self, registry):
        """Test getting OpenAI-compatible schema."""
        from src.interfaces.tool_registry import ToolDefinition, ToolParameter
        
        tool = ToolDefinition(
            name="test_tool",
            description="Test tool",
            tool_type=ToolType.TEXT,
            parameters=[
                ToolParameter(name="param1", type="string", description="Parameter 1", required=True)
            ],
            returns="Result"
        )
        
        registry.register_tool(tool, lambda param1: param1)
        
        schema = registry.get_tool_schema("test_tool")
        
        assert schema["name"] == "test_tool"
        assert schema["description"] == "Test tool"
        assert "parameters" in schema
        assert "param1" in schema["parameters"]["properties"]
    
    def test_list_tools(self, registry):
        """Test listing registered tools."""
        from src.interfaces.tool_registry import ToolDefinition
        
        for i in range(3):
            tool = ToolDefinition(
                name=f"tool_{i}",
                description=f"Tool {i}",
                tool_type=ToolType.TEXT,
                parameters=[],
                returns="Result"
            )
            registry.register_tool(tool, lambda: None)
        
        tools = registry.list_tools()
        
        assert len(tools) == 3
        assert "tool_0" in tools
        assert "tool_1" in tools
        assert "tool_2" in tools


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
