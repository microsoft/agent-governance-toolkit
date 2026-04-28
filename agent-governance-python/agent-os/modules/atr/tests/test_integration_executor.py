# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Integration tests for executor with ATR registry."""

import pytest
import atr
from atr import DockerExecutor, LocalExecutor, ExecutorError


def test_execute_tool_with_local_executor():
    """Test execute_tool with LocalExecutor."""
    # Register a test tool
    @atr.register(name="test_add", tags=["math"])
    def add(a: int, b: int) -> int:
        """Add two numbers."""
        return a + b
    
    # Execute with default (local) executor
    result = atr.execute_tool("test_add", {"a": 10, "b": 5})
    assert result == 15
    
    # Clean up
    atr._global_registry.unregister_tool("test_add")


def test_execute_tool_with_explicit_local_executor():
    """Test execute_tool with explicit LocalExecutor."""
    # Register a test tool
    @atr.register(name="test_multiply", tags=["math"])
    def multiply(a: int, b: int) -> int:
        """Multiply two numbers."""
        return a * b
    
    executor = LocalExecutor()
    result = atr.execute_tool("test_multiply", {"a": 6, "b": 7}, executor=executor)
    assert result == 42
    
    # Clean up
    atr._global_registry.unregister_tool("test_multiply")


def test_execute_tool_with_docker_executor():
    """Test execute_tool with DockerExecutor."""
    try:
        executor = DockerExecutor(auto_pull=False)
    except (ImportError, ExecutorError) as e:
        pytest.skip(f"Docker not available: {str(e)}")
    
    # Register a test tool
    @atr.register(name="test_subtract", tags=["math"])
    def subtract(a: int, b: int) -> int:
        """Subtract two numbers."""
        return a - b
    
    result = atr.execute_tool("test_subtract", {"a": 20, "b": 8}, executor=executor, timeout=10)
    assert result == 12
    
    # Clean up
    atr._global_registry.unregister_tool("test_subtract")


def test_execute_tool_with_string_operations():
    """Test execute_tool with string operations."""
    try:
        executor = DockerExecutor(auto_pull=False)
    except (ImportError, ExecutorError) as e:
        pytest.skip(f"Docker not available: {str(e)}")
    
    @atr.register(name="test_upper", tags=["string"])
    def to_upper(text: str) -> str:
        """Convert text to uppercase."""
        return text.upper()
    
    result = atr.execute_tool("test_upper", {"text": "hello world"}, executor=executor, timeout=10)
    assert result == "HELLO WORLD"
    
    # Clean up
    atr._global_registry.unregister_tool("test_upper")


def test_execute_tool_with_list_operations():
    """Test execute_tool with list operations."""
    try:
        executor = DockerExecutor(auto_pull=False)
    except (ImportError, ExecutorError) as e:
        pytest.skip(f"Docker not available: {str(e)}")
    
    @atr.register(name="test_reverse", tags=["list"])
    def reverse_list(items: list) -> list:
        """Reverse a list."""
        return list(reversed(items))
    
    result = atr.execute_tool("test_reverse", {"items": [1, 2, 3, 4]}, executor=executor, timeout=10)
    assert result == [4, 3, 2, 1]
    
    # Clean up
    atr._global_registry.unregister_tool("test_reverse")


def test_execute_tool_error_handling():
    """Test execute_tool error handling."""
    @atr.register(name="test_error", tags=["test"])
    def error_func(x: int) -> int:
        """Function that raises an error."""
        raise ValueError("Intentional error")
    
    with pytest.raises(ExecutorError):
        atr.execute_tool("test_error", {"x": 1})
    
    # Clean up
    atr._global_registry.unregister_tool("test_error")


def test_execute_tool_nonexistent():
    """Test execute_tool with nonexistent tool."""
    with pytest.raises(atr.ToolNotFoundError):
        atr.execute_tool("nonexistent_tool", {})


def test_execute_tool_with_defaults():
    """Test execute_tool with default parameter values."""
    @atr.register(name="test_greet", tags=["string"])
    def greet(name: str = "World") -> str:
        """Greet someone."""
        return f"Hello, {name}!"
    
    # Test with default
    result1 = atr.execute_tool("test_greet")
    assert result1 == "Hello, World!"
    
    # Test with explicit value
    result2 = atr.execute_tool("test_greet", {"name": "Alice"})
    assert result2 == "Hello, Alice!"
    
    # Clean up
    atr._global_registry.unregister_tool("test_greet")


def test_execute_tool_sandboxed_vs_local():
    """Compare sandboxed and local execution results."""
    try:
        docker_executor = DockerExecutor(auto_pull=False)
    except (ImportError, ExecutorError) as e:
        pytest.skip(f"Docker not available: {str(e)}")
    
    @atr.register(name="test_calc", tags=["math"])
    def calculate(x: int, y: int) -> int:
        """Calculate x squared plus y."""
        return x * x + y
    
    # Execute locally
    local_executor = LocalExecutor()
    result_local = atr.execute_tool("test_calc", {"x": 5, "y": 3}, executor=local_executor)
    
    # Execute in Docker
    result_docker = atr.execute_tool("test_calc", {"x": 5, "y": 3}, executor=docker_executor, timeout=10)
    
    # Results should be the same
    assert result_local == result_docker == 28
    
    # Clean up
    atr._global_registry.unregister_tool("test_calc")


def test_execute_tool_complex_function():
    """Test execute_tool with a more complex function."""
    try:
        executor = DockerExecutor(auto_pull=False)
    except (ImportError, ExecutorError) as e:
        pytest.skip(f"Docker not available: {str(e)}")
    
    @atr.register(name="test_complex", tags=["data"])
    def process_data(numbers: list, multiplier: int = 2, add_value: int = 0) -> list:
        """Process a list of numbers."""
        return [n * multiplier + add_value for n in numbers]
    
    result = atr.execute_tool(
        "test_complex",
        {"numbers": [1, 2, 3, 4], "multiplier": 3, "add_value": 10},
        executor=executor,
        timeout=10
    )
    assert result == [13, 16, 19, 22]
    
    # Clean up
    atr._global_registry.unregister_tool("test_complex")
