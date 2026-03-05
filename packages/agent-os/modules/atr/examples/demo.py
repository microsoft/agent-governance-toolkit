# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Example usage of the ATR (Agent Tool Registry).

This example demonstrates how to register tools, discover them, and execute them.
"""

import atr
from typing import List


# Example 1: Simple web scraper tool
@atr.register(name="web_scraper", cost="low", tags=["web", "scraping"], side_effects=["network"])
def scrape_website(url: str, timeout: int = 30) -> str:
    """Scrape content from a website.
    
    Args:
        url: The URL to scrape
        timeout: Request timeout in seconds
    """
    # Simulated implementation
    return f"Content from {url} (timeout: {timeout}s)"


# Example 2: File reader with side effects
@atr.register(
    name="file_reader",
    cost="low",
    side_effects=["read", "filesystem"],
    tags=["file", "io"]
)
def read_file(path: str, encoding: str = "utf-8") -> str:
    """Read a file from disk."""
    # Simulated implementation
    return f"Content of {path} (encoding: {encoding})"


# Example 3: Calculator tool
@atr.register(name="calculator", tags=["math"])
def calculate(operation: str, a: float, b: float) -> float:
    """Perform basic arithmetic operations.
    
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


# Example 4: Complex types
@atr.register(name="list_processor", tags=["data"])
def process_items(items: List[str], reverse: bool = False) -> List[str]:
    """Process a list of items.
    
    Args:
        items: List of strings to process
        reverse: Whether to reverse the list
    """
    result = [item.upper() for item in items]
    if reverse:
        result.reverse()
    return result


def main():
    """Demonstrate ATR usage."""
    print("=" * 60)
    print("ATR - Agent Tool Registry Demo")
    print("=" * 60)
    
    # Discover tools
    print("\n1. Listing all registered tools:")
    print("-" * 60)
    all_tools = atr._global_registry.list_tools()
    for tool in all_tools:
        print(f"  - {tool.metadata.name}: {tool.metadata.description[:50]}...")
    
    # Search for tools
    print("\n2. Searching for 'web' tools:")
    print("-" * 60)
    web_tools = atr._global_registry.search_tools("web")
    for tool in web_tools:
        print(f"  - {tool.metadata.name}: {tool.metadata.description[:50]}...")
    
    # Filter by tags
    print("\n3. Filtering tools by tag 'file':")
    print("-" * 60)
    file_tools = atr._global_registry.list_tools(tag="file")
    for tool in file_tools:
        print(f"  - {tool.metadata.name}: {tool.metadata.description[:50]}...")
    
    # Get a specific tool
    print("\n4. Getting tool specification:")
    print("-" * 60)
    scraper_spec = atr._global_registry.get_tool("web_scraper")
    print(f"  Name: {scraper_spec.metadata.name}")
    print(f"  Description: {scraper_spec.metadata.description}")
    print(f"  Cost: {scraper_spec.metadata.cost}")
    print(f"  Side Effects: {scraper_spec.metadata.side_effects}")
    print(f"  Tags: {scraper_spec.metadata.tags}")
    print(f"  Parameters:")
    for param in scraper_spec.parameters:
        required = "required" if param.required else f"optional (default: {param.default})"
        print(f"    - {param.name} ({param.type.value}): {required}")
    
    # Convert to OpenAI format
    print("\n5. Converting to OpenAI function calling format:")
    print("-" * 60)
    openai_schema = scraper_spec.to_openai_function_schema()
    import json
    print(json.dumps(openai_schema, indent=2))
    
    # Execute a tool (this is what the Agent Runtime would do)
    print("\n6. Executing tools (Agent Runtime responsibility):")
    print("-" * 60)
    
    # Get the callable and execute
    scraper_func = atr._global_registry.get_callable("web_scraper")
    result = scraper_func(url="https://example.com", timeout=10)
    print(f"  Scraper result: {result}")
    
    calc_func = atr._global_registry.get_callable("calculator")
    result = calc_func("multiply", 7, 6)
    print(f"  Calculator result: {result}")
    
    processor_func = atr._global_registry.get_callable("list_processor")
    result = processor_func(["hello", "world"], reverse=True)
    print(f"  Processor result: {result}")
    
    print("\n" + "=" * 60)
    print("Demo complete!")
    print("=" * 60)


if __name__ == "__main__":
    main()
