# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the @register decorator."""

import pytest
from atr.decorator import register, _python_type_to_parameter_type, _extract_parameters_from_function
from atr.schema import ParameterType, CostLevel, SideEffect
from atr.registry import Registry
from typing import Optional, List, Dict


def test_python_type_to_parameter_type():
    """Test conversion of Python types to ParameterType."""
    assert _python_type_to_parameter_type(str) == ParameterType.STRING
    assert _python_type_to_parameter_type(int) == ParameterType.INTEGER
    assert _python_type_to_parameter_type(float) == ParameterType.NUMBER
    assert _python_type_to_parameter_type(bool) == ParameterType.BOOLEAN
    assert _python_type_to_parameter_type(list) == ParameterType.ARRAY
    assert _python_type_to_parameter_type(dict) == ParameterType.OBJECT


def test_python_optional_type():
    """Test conversion of Optional types."""
    from typing import Optional
    
    # Optional[str] should still be STRING
    result = _python_type_to_parameter_type(Optional[str])
    assert result == ParameterType.STRING


def test_extract_parameters_basic():
    """Test extracting parameters from a function."""
    def sample_func(url: str, timeout: int = 30) -> str:
        """Sample function."""
        pass
    
    params = _extract_parameters_from_function(sample_func)
    
    assert len(params) == 2
    assert params[0].name == "url"
    assert params[0].type == ParameterType.STRING
    assert params[0].required is True
    
    assert params[1].name == "timeout"
    assert params[1].type == ParameterType.INTEGER
    assert params[1].required is False
    assert params[1].default == 30


def test_extract_parameters_without_type_hints_fails():
    """Test that functions without type hints raise an error."""
    def bad_func(url, timeout=30):
        """Function without type hints - should fail."""
        pass
    
    with pytest.raises(ValueError, match="must have a type hint"):
        _extract_parameters_from_function(bad_func)


def test_register_decorator_basic():
    """Test basic decorator usage."""
    registry = Registry()
    
    @register(name="test_tool", registry=registry)
    def my_tool(x: int) -> int:
        """A test tool."""
        return x * 2
    
    # Check tool was registered
    assert "test_tool" in registry
    
    # Check the function still works
    assert my_tool(5) == 10
    
    # Check we can get the tool spec
    tool_spec = registry.get_tool("test_tool")
    assert tool_spec.metadata.name == "test_tool"
    assert tool_spec.metadata.description == "A test tool."


def test_register_decorator_uses_function_name():
    """Test that decorator uses function name if no name provided."""
    registry = Registry()
    
    @register(registry=registry)
    def my_function(x: str) -> str:
        """My function."""
        return x.upper()
    
    assert "my_function" in registry


def test_register_decorator_with_metadata():
    """Test decorator with full metadata."""
    registry = Registry()
    
    @register(
        name="complex_tool",
        description="A complex tool",
        version="2.0.0",
        author="Test Author",
        cost="high",
        side_effects=["network", "write"],
        tags=["api", "database"],
        registry=registry,
    )
    def complex_func(url: str, data: dict) -> dict:
        """Process data."""
        return {"status": "ok"}
    
    tool_spec = registry.get_tool("complex_tool")
    
    assert tool_spec.metadata.name == "complex_tool"
    assert tool_spec.metadata.description == "A complex tool"
    assert tool_spec.metadata.version == "2.0.0"
    assert tool_spec.metadata.author == "Test Author"
    assert tool_spec.metadata.cost == CostLevel.HIGH
    assert SideEffect.NETWORK in tool_spec.metadata.side_effects
    assert SideEffect.WRITE in tool_spec.metadata.side_effects
    assert "api" in tool_spec.metadata.tags


def test_register_decorator_extracts_parameters():
    """Test that decorator correctly extracts parameters."""
    registry = Registry()
    
    @register(name="param_tool", registry=registry)
    def tool_with_params(
        required_str: str,
        optional_int: int = 10,
        required_bool: bool = True,
        optional_float: Optional[float] = None
    ) -> str:
        """Tool with various parameters."""
        return "ok"
    
    tool_spec = registry.get_tool("param_tool")
    params = tool_spec.parameters
    
    assert len(params) == 4
    
    # Check required_str
    assert params[0].name == "required_str"
    assert params[0].type == ParameterType.STRING
    assert params[0].required is True
    
    # Check optional_int
    assert params[1].name == "optional_int"
    assert params[1].type == ParameterType.INTEGER
    assert params[1].required is False
    assert params[1].default == 10
    
    # Check required_bool (has default but still in signature)
    assert params[2].name == "required_bool"
    assert params[2].type == ParameterType.BOOLEAN
    assert params[2].required is False
    assert params[2].default is True


def test_register_decorator_extracts_return_type():
    """Test that decorator extracts return type."""
    registry = Registry()
    
    @register(name="return_tool", registry=registry)
    def tool_with_return(x: int) -> str:
        """Returns a string."""
        return str(x)
    
    tool_spec = registry.get_tool("return_tool")
    
    assert tool_spec.returns is not None
    assert tool_spec.returns.type == ParameterType.STRING


def test_register_decorator_no_return_type():
    """Test decorator with function that has no return type."""
    registry = Registry()
    
    @register(name="no_return", registry=registry)
    def tool_no_return(x: int):
        """No return annotation."""
        print(x)
    
    tool_spec = registry.get_tool("no_return")
    assert tool_spec.returns is None


def test_register_decorator_preserves_function():
    """Test that decorator returns the original function unchanged."""
    registry = Registry()
    
    @register(name="unchanged", registry=registry)
    def original_func(x: int) -> int:
        """Original function."""
        return x + 1
    
    # Function should work exactly as before
    assert original_func(5) == 6
    assert original_func.__name__ == "original_func"
    assert original_func.__doc__ == "Original function."


def test_register_decorator_callable_is_stored():
    """Test that the callable is stored in the registry."""
    registry = Registry()
    
    @register(name="stored_func", registry=registry)
    def my_func(x: int) -> int:
        """My function."""
        return x * 3
    
    # Get the callable from registry
    retrieved_func = registry.get_callable("stored_func")
    
    # It should be the same function
    assert retrieved_func is my_func
    
    # And it should work
    assert retrieved_func(4) == 12


def test_register_decorator_no_magic_arguments():
    """Test that decorator enforces type hints (no magic arguments)."""
    registry = Registry()
    
    # This should fail because 'x' has no type hint
    with pytest.raises(ValueError, match="must have a type hint"):
        @register(name="magic_arg", registry=registry)
        def bad_func(x):  # No type hint!
            """Bad function."""
            return x


def test_register_decorator_with_complex_types():
    """Test decorator with complex type annotations."""
    registry = Registry()
    
    @register(name="complex_types", registry=registry)
    def complex_func(
        items: List[str],
        mapping: Dict[str, int],
        optional_list: Optional[List[int]] = None
    ) -> List[str]:
        """Function with complex types."""
        return items
    
    tool_spec = registry.get_tool("complex_types")
    params = tool_spec.parameters
    
    assert len(params) == 3
    assert params[0].name == "items"
    assert params[0].type == ParameterType.ARRAY
    assert params[1].name == "mapping"
    assert params[1].type == ParameterType.OBJECT


def test_register_decorator_does_not_execute():
    """Test that the decorator does NOT execute the function."""
    registry = Registry()
    
    call_count = [0]
    
    @register(name="not_executed", registry=registry)
    def counting_func(x: int) -> int:
        """Counts calls."""
        call_count[0] += 1
        return x
    
    # After decoration, function should not have been called
    assert call_count[0] == 0
    
    # Only when we explicitly call it
    counting_func(5)
    assert call_count[0] == 1


def test_register_decorator_with_global_registry():
    """Test decorator using the global registry."""
    import atr
    
    # Clear global registry first
    atr._global_registry.clear()
    
    @atr.register(name="global_tool")
    def global_func(x: str) -> str:
        """Uses global registry."""
        return x
    
    # Should be in global registry
    assert "global_tool" in atr._global_registry
    
    # Clean up
    atr._global_registry.clear()


def test_register_invalid_cost_defaults_to_free():
    """Test that invalid cost level defaults to FREE."""
    registry = Registry()
    
    @register(name="invalid_cost", cost="invalid", registry=registry)
    def func(x: int) -> int:
        """Function with invalid cost."""
        return x
    
    tool_spec = registry.get_tool("invalid_cost")
    assert tool_spec.metadata.cost == CostLevel.FREE


def test_register_invalid_side_effect_defaults_to_none():
    """Test that invalid side effects default to NONE."""
    registry = Registry()
    
    @register(name="invalid_se", side_effects=["invalid"], registry=registry)
    def func(x: int) -> int:
        """Function with invalid side effect."""
        return x
    
    tool_spec = registry.get_tool("invalid_se")
    assert SideEffect.NONE in tool_spec.metadata.side_effects
