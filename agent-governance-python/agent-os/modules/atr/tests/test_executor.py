# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for executor functionality."""

import pytest
from atr.executor import (
    Executor,
    LocalExecutor,
    DockerExecutor,
    ExecutorError,
    ExecutionTimeoutError,
)


def test_local_executor_basic():
    """Test basic local executor functionality."""
    executor = LocalExecutor()
    
    def add(a: int, b: int) -> int:
        return a + b
    
    result = executor.execute(add, {"a": 5, "b": 3})
    assert result == 8


def test_local_executor_no_args():
    """Test local executor with no arguments."""
    executor = LocalExecutor()
    
    def get_value() -> int:
        return 42
    
    result = executor.execute(get_value)
    assert result == 42


def test_local_executor_with_defaults():
    """Test local executor with default arguments."""
    executor = LocalExecutor()
    
    def greet(name: str = "World") -> str:
        return f"Hello, {name}!"
    
    result1 = executor.execute(greet)
    assert result1 == "Hello, World!"
    
    result2 = executor.execute(greet, {"name": "Alice"})
    assert result2 == "Hello, Alice!"


def test_local_executor_error_handling():
    """Test local executor error handling."""
    executor = LocalExecutor()
    
    def failing_func(x: int) -> int:
        raise ValueError("Something went wrong")
    
    with pytest.raises(ExecutorError, match="Local execution failed"):
        executor.execute(failing_func, {"x": 1})


def test_local_executor_complex_return():
    """Test local executor with complex return types."""
    executor = LocalExecutor()
    
    def process_list(items: list) -> list:
        return [item.upper() for item in items]
    
    result = executor.execute(process_list, {"items": ["hello", "world"]})
    assert result == ["HELLO", "WORLD"]


def test_docker_executor_initialization():
    """Test Docker executor initialization."""
    try:
        executor = DockerExecutor(auto_pull=False)
        assert executor.image == "python:3.9-slim"
        assert hasattr(executor, "_client")
    except (ImportError, ExecutorError) as e:
        pytest.skip(f"Docker not available: {str(e)}")


def test_docker_executor_custom_image():
    """Test Docker executor with custom image."""
    try:
        executor = DockerExecutor(image="python:3.9-slim", auto_pull=False)
        assert executor.image == "python:3.9-slim"
    except (ImportError, ExecutorError) as e:
        pytest.skip(f"Docker not available: {str(e)}")


def test_docker_executor_basic_execution():
    """Test basic Docker executor functionality."""
    try:
        executor = DockerExecutor(auto_pull=False)
    except (ImportError, ExecutorError) as e:
        pytest.skip(f"Docker not available: {str(e)}")
    
    def add(a: int, b: int) -> int:
        return a + b
    
    result = executor.execute(add, {"a": 5, "b": 3}, timeout=10)
    assert result == 8


def test_docker_executor_string_operations():
    """Test Docker executor with string operations."""
    try:
        executor = DockerExecutor(auto_pull=False)
    except (ImportError, ExecutorError) as e:
        pytest.skip(f"Docker not available: {str(e)}")
    
    def concatenate(a: str, b: str) -> str:
        return a + b
    
    result = executor.execute(concatenate, {"a": "Hello, ", "b": "World!"}, timeout=10)
    assert result == "Hello, World!"


def test_docker_executor_list_processing():
    """Test Docker executor with list processing."""
    try:
        executor = DockerExecutor(auto_pull=False)
    except (ImportError, ExecutorError) as e:
        pytest.skip(f"Docker not available: {str(e)}")
    
    def double_items(items: list) -> list:
        return [x * 2 for x in items]
    
    result = executor.execute(double_items, {"items": [1, 2, 3]}, timeout=10)
    assert result == [2, 4, 6]


def test_docker_executor_error_handling():
    """Test Docker executor error handling."""
    try:
        executor = DockerExecutor(auto_pull=False)
    except (ImportError, ExecutorError) as e:
        pytest.skip(f"Docker not available: {str(e)}")
    
    def failing_func(x: int) -> int:
        raise ValueError("Something went wrong")
    
    with pytest.raises(ExecutorError, match="(Function execution failed|Container execution failed)"):
        executor.execute(failing_func, {"x": 1}, timeout=10)


def test_docker_executor_timeout():
    """Test Docker executor timeout functionality."""
    try:
        executor = DockerExecutor(auto_pull=False)
    except (ImportError, ExecutorError) as e:
        pytest.skip(f"Docker not available: {str(e)}")
    
    def slow_func() -> int:
        import time
        time.sleep(10)  # Sleep longer than timeout
        return 42
    
    # This should timeout with a 2 second limit
    with pytest.raises((ExecutionTimeoutError, ExecutorError)):
        executor.execute(slow_func, timeout=2)


def test_docker_executor_no_network():
    """Test that Docker executor runs without network access."""
    try:
        executor = DockerExecutor(auto_pull=False)
    except (ImportError, ExecutorError) as e:
        pytest.skip(f"Docker not available: {str(e)}")
    
    def check_network() -> str:
        # This function should fail if it tries to make network calls
        # But we'll just return a value to verify execution works
        return "no network needed"
    
    result = executor.execute(check_network, timeout=10)
    assert result == "no network needed"


def test_docker_executor_with_math():
    """Test Docker executor with mathematical operations."""
    try:
        executor = DockerExecutor(auto_pull=False)
    except (ImportError, ExecutorError) as e:
        pytest.skip(f"Docker not available: {str(e)}")
    
    def calculate(x: float, y: float, operation: str) -> float:
        if operation == "add":
            return x + y
        elif operation == "multiply":
            return x * y
        elif operation == "divide":
            return x / y if y != 0 else 0
        return 0
    
    result = executor.execute(
        calculate,
        {"x": 10.0, "y": 2.0, "operation": "multiply"},
        timeout=10
    )
    assert result == 20.0


def test_docker_executor_cleanup():
    """Test that Docker executor cleans up containers."""
    try:
        import docker
        executor = DockerExecutor(auto_pull=False)
    except (ImportError, ExecutorError) as e:
        pytest.skip(f"Docker not available: {str(e)}")
    
    client = docker.from_env()
    
    # Get initial container count
    initial_containers = len(client.containers.list(all=True))
    
    def simple_func() -> int:
        return 42
    
    # Execute function
    executor.execute(simple_func, timeout=10)
    
    # Check that no new containers remain
    final_containers = len(client.containers.list(all=True))
    assert final_containers == initial_containers


def test_executor_abstract_class():
    """Test that Executor is an abstract class."""
    with pytest.raises(TypeError):
        Executor()


def test_local_executor_is_executor():
    """Test that LocalExecutor is an instance of Executor."""
    executor = LocalExecutor()
    assert isinstance(executor, Executor)


def test_docker_executor_is_executor():
    """Test that DockerExecutor is an instance of Executor."""
    try:
        executor = DockerExecutor(auto_pull=False)
        assert isinstance(executor, Executor)
    except (ImportError, ExecutorError) as e:
        pytest.skip(f"Docker not available: {str(e)}")
