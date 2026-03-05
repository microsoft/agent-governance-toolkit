# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for schema definitions."""

import pytest
from atr.schema import (
    ToolSpec,
    ToolMetadata,
    ParameterSpec,
    ParameterType,
    SideEffect,
    CostLevel,
)


def test_parameter_spec_basic():
    """Test basic parameter specification."""
    param = ParameterSpec(
        name="url",
        type=ParameterType.STRING,
        description="The URL to process",
        required=True,
    )
    
    assert param.name == "url"
    assert param.type == ParameterType.STRING
    assert param.description == "The URL to process"
    assert param.required is True
    assert param.default is None


def test_parameter_spec_with_default():
    """Test parameter with default value."""
    param = ParameterSpec(
        name="timeout",
        type=ParameterType.INTEGER,
        description="Timeout in seconds",
        required=False,
        default=30,
    )
    
    assert param.required is False
    assert param.default == 30


def test_parameter_spec_default_on_required_fails():
    """Test that default on required parameter raises error."""
    with pytest.raises(ValueError, match="Cannot set default value for required parameter"):
        ParameterSpec(
            name="bad_param",
            type=ParameterType.STRING,
            description="Bad parameter",
            required=True,
            default="should fail",
        )


def test_tool_metadata():
    """Test tool metadata."""
    metadata = ToolMetadata(
        name="test_tool",
        description="A test tool",
        version="1.0.0",
        cost=CostLevel.LOW,
        side_effects=[SideEffect.READ, SideEffect.NETWORK],
        tags=["test", "example"],
    )
    
    assert metadata.name == "test_tool"
    assert metadata.cost == CostLevel.LOW
    assert SideEffect.READ in metadata.side_effects
    assert "test" in metadata.tags


def test_tool_spec_basic():
    """Test basic tool specification."""
    metadata = ToolMetadata(
        name="scraper",
        description="Web scraper tool",
    )
    
    param = ParameterSpec(
        name="url",
        type=ParameterType.STRING,
        description="URL to scrape",
        required=True,
    )
    
    spec = ToolSpec(
        metadata=metadata,
        parameters=[param],
    )
    
    assert spec.metadata.name == "scraper"
    assert len(spec.parameters) == 1
    assert spec.parameters[0].name == "url"


def test_tool_spec_to_openai_schema():
    """Test conversion to OpenAI function calling format."""
    metadata = ToolMetadata(
        name="calculator",
        description="Perform calculations",
    )
    
    params = [
        ParameterSpec(
            name="operation",
            type=ParameterType.STRING,
            description="The operation to perform",
            required=True,
            enum=["add", "subtract", "multiply", "divide"],
        ),
        ParameterSpec(
            name="a",
            type=ParameterType.NUMBER,
            description="First number",
            required=True,
        ),
        ParameterSpec(
            name="b",
            type=ParameterType.NUMBER,
            description="Second number",
            required=True,
        ),
    ]
    
    spec = ToolSpec(metadata=metadata, parameters=params)
    openai_schema = spec.to_openai_function_schema()
    
    assert openai_schema["name"] == "calculator"
    assert openai_schema["description"] == "Perform calculations"
    assert "parameters" in openai_schema
    assert openai_schema["parameters"]["type"] == "object"
    assert "operation" in openai_schema["parameters"]["properties"]
    assert "a" in openai_schema["parameters"]["properties"]
    assert "b" in openai_schema["parameters"]["properties"]
    assert set(openai_schema["parameters"]["required"]) == {"operation", "a", "b"}
    assert openai_schema["parameters"]["properties"]["operation"]["enum"] == ["add", "subtract", "multiply", "divide"]


def test_tool_spec_optional_parameters():
    """Test tool spec with optional parameters."""
    metadata = ToolMetadata(
        name="fetcher",
        description="Fetch data",
    )
    
    params = [
        ParameterSpec(
            name="url",
            type=ParameterType.STRING,
            description="URL to fetch",
            required=True,
        ),
        ParameterSpec(
            name="timeout",
            type=ParameterType.INTEGER,
            description="Timeout in seconds",
            required=False,
            default=30,
        ),
    ]
    
    spec = ToolSpec(metadata=metadata, parameters=params)
    openai_schema = spec.to_openai_function_schema()
    
    # Only required params should be in 'required' list
    assert openai_schema["parameters"]["required"] == ["url"]
    assert "timeout" in openai_schema["parameters"]["properties"]


def test_tool_spec_serialization():
    """Test that tool spec can be serialized to JSON."""
    metadata = ToolMetadata(
        name="test",
        description="Test tool",
    )
    
    spec = ToolSpec(metadata=metadata, parameters=[])
    
    # Should serialize without error (private attrs are auto-excluded)
    json_str = spec.model_dump_json()
    assert json_str is not None
