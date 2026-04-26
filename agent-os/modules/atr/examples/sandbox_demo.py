# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Example demonstrating sandboxed execution with ATR.

This example shows how to use Docker-based sandboxed execution
to safely run untrusted code in isolated containers.
"""

import atr
from typing import List


# Register some example tools
@atr.register(name="safe_calculator", cost="free", tags=["math", "sandbox"])
def safe_calculate(operation: str, a: float, b: float) -> float:
    """Perform basic arithmetic operations in a sandboxed environment.
    
    Args:
        operation: The operation (add, subtract, multiply, divide)
        a: First number
        b: Second number
    """
    if operation == "add":
        return a + b
    elif operation == "subtract":
        return a - b
    elif operation == "multiply":
        return a * b
    elif operation == "divide":
        return a / b if b != 0 else 0
    return 0


@atr.register(name="text_processor", cost="low", tags=["text", "sandbox"])
def process_text(text: str, operation: str = "upper") -> str:
    """Process text with various operations.
    
    Args:
        text: The text to process
        operation: The operation (upper, lower, reverse, title)
    """
    if operation == "upper":
        return text.upper()
    elif operation == "lower":
        return text.lower()
    elif operation == "reverse":
        return text[::-1]
    elif operation == "title":
        return text.title()
    return text


@atr.register(name="list_analyzer", cost="low", tags=["data", "sandbox"])
def analyze_list(numbers: List[float]) -> dict:
    """Analyze a list of numbers and return statistics.
    
    Args:
        numbers: List of numbers to analyze
    """
    if not numbers:
        return {"count": 0, "sum": 0, "min": 0, "max": 0, "avg": 0}
    
    return {
        "count": len(numbers),
        "sum": sum(numbers),
        "min": min(numbers),
        "max": max(numbers),
        "avg": sum(numbers) / len(numbers),
    }


def main():
    """Demonstrate sandboxed execution."""
    print("=" * 70)
    print("ATR - Sandboxed Execution Demo")
    print("=" * 70)
    
    # Example 1: Local execution (NOT sandboxed - use only with trusted code)
    print("\n1. Local Execution (Not Sandboxed):")
    print("-" * 70)
    print("WARNING: Local execution runs code directly on the host machine.")
    print("Only use this with trusted code!")
    print()
    
    result = atr.execute_tool("safe_calculator", {
        "operation": "multiply",
        "a": 7,
        "b": 6
    })
    print(f"Calculator result (local): {result}")
    
    # Example 2: Docker sandboxed execution (SAFE for untrusted code)
    print("\n2. Docker Sandboxed Execution (Safe):")
    print("-" * 70)
    print("Docker execution runs code in isolated containers with:")
    print("  - No network access")
    print("  - Memory limits")
    print("  - Automatic cleanup")
    print("  - Complete isolation from host")
    print()
    
    try:
        # Create Docker executor
        docker_executor = atr.DockerExecutor(
            image="python:3.9-slim",
            auto_pull=True
        )
        print("✓ Docker executor initialized")
        
        # Execute calculator in Docker
        print("\nExecuting calculator in Docker container...")
        result = atr.execute_tool(
            "safe_calculator",
            {
                "operation": "add",
                "a": 42,
                "b": 8
            },
            executor=docker_executor,
            timeout=30
        )
        print(f"  Result: {result}")
        
        # Execute text processor in Docker
        print("\nExecuting text processor in Docker container...")
        result = atr.execute_tool(
            "text_processor",
            {
                "text": "hello world from docker",
                "operation": "title"
            },
            executor=docker_executor,
            timeout=30
        )
        print(f"  Result: {result}")
        
        # Execute list analyzer in Docker
        print("\nExecuting list analyzer in Docker container...")
        result = atr.execute_tool(
            "list_analyzer",
            {
                "numbers": [10, 20, 30, 40, 50]
            },
            executor=docker_executor,
            timeout=30
        )
        print(f"  Result: {result}")
        
        print("\n✓ All sandboxed executions completed successfully!")
        
    except ImportError:
        print("✗ Docker SDK not installed. Install with: pip install docker")
        print("  Skipping sandboxed execution examples.")
    except atr.ExecutorError as e:
        print(f"✗ Docker execution error: {e}")
        print("  Make sure Docker is installed and running.")
    
    # Example 3: Execution with timeout
    print("\n3. Execution with Timeout:")
    print("-" * 70)
    print("Timeouts prevent long-running or malicious code from hanging.")
    print()
    
    try:
        docker_executor = atr.DockerExecutor(auto_pull=True)
        
        # Quick execution with short timeout
        result = atr.execute_tool(
            "safe_calculator",
            {"operation": "divide", "a": 100, "b": 4},
            executor=docker_executor,
            timeout=10  # 10 second timeout
        )
        print(f"Quick calculation completed: {result}")
        
    except atr.ExecutionTimeoutError:
        print("✗ Execution exceeded timeout limit")
    except (ImportError, atr.ExecutorError) as e:
        print(f"Skipping timeout example: {e}")
    
    # Example 4: Comparison of execution modes
    print("\n4. Comparison of Execution Modes:")
    print("-" * 70)
    
    import textwrap
    comparison = textwrap.dedent("""
        | Feature              | Local Executor    | Docker Executor       |
        |---------------------|-------------------|-----------------------|
        | Speed               | Fast              | Slower (containerized)|
        | Security            | No isolation      | Full isolation        |
        | Network Access      | Full access       | Disabled              |
        | Resource Limits     | None              | Configurable          |
        | Cleanup             | N/A               | Automatic             |
        | Use Case            | Trusted code only | Untrusted code        |
    """)
    print(comparison)
    
    # Example 5: Best practices
    print("\n5. Best Practices:")
    print("-" * 70)
    
    import textwrap
    best_practices = textwrap.dedent("""
        1. Always use DockerExecutor for untrusted or agent-generated code
        2. Set appropriate timeouts to prevent hanging executions
        3. Use LocalExecutor only for trusted, pre-vetted code
        4. Monitor Docker resource usage in production
        5. Consider using custom Docker images with minimal dependencies
        6. Test your tools in Docker before deploying to production
    """)
    print(best_practices)
    
    print("\n" + "=" * 70)
    print("Demo complete!")
    print("=" * 70)


if __name__ == "__main__":
    main()
