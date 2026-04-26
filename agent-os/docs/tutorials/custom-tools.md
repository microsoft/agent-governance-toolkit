# Creating Custom Tools

> **Build safe, reusable tools for your agents.**

## Overview

Agent OS provides a collection of pre-built safe tools, but you can also create custom tools that follow the same security principles.

## Using Pre-Built Safe Tools

### Quick Start

```python
from atr.tools.safe import create_safe_toolkit

# Create a toolkit with standard tools
toolkit = create_safe_toolkit("standard")

# Available tools
http = toolkit["http"]       # HTTP client with rate limiting
files = toolkit["files"]     # File reader with sandboxing  
json = toolkit["json"]       # JSON/YAML parser
calc = toolkit["calculator"] # Safe math operations
dt = toolkit["datetime"]     # Timezone-aware datetime
text = toolkit["text"]       # Text processing

# Use a tool
result = await http.get("https://api.example.com/data")
```

### Toolkit Presets

```python
# Minimal - no I/O, just processing
toolkit = create_safe_toolkit("minimal")
# Includes: calculator, datetime, text

# Read-only - file access, no network
toolkit = create_safe_toolkit("readonly", config={
    "sandbox_paths": ["./data"],
    "allowed_extensions": [".txt", ".json", ".md"]
})
# Includes: files, json, calculator, datetime, text

# Network - HTTP only, no files
toolkit = create_safe_toolkit("network", config={
    "allowed_domains": ["api.github.com", "api.openai.com"],
    "rate_limit": 30
})
# Includes: http

# Restricted - all tools with tight limits
toolkit = create_safe_toolkit("restricted", config={
    "allowed_domains": ["api.internal.com"],
    "sandbox_paths": ["./safe-data"],
    "max_file_size": 100_000,
    "rate_limit": 10
})
```

### Individual Tool Usage

#### HTTP Client

```python
from atr.tools.safe import HttpClientTool

http = HttpClientTool(
    allowed_domains=["api.github.com", "httpbin.org"],
    rate_limit=30,          # requests per minute
    timeout=10.0,           # seconds
    max_response_size=1_000_000
)

# GET request
response = await http.get(
    "https://api.github.com/users/octocat",
    headers={"Accept": "application/json"}
)
print(response["body"])

# POST request
response = await http.post(
    "https://httpbin.org/post",
    json_body={"key": "value"}
)
```

#### File Reader

```python
from atr.tools.safe import FileReaderTool

reader = FileReaderTool(
    sandbox_paths=["./data", "./configs"],
    allowed_extensions=[".txt", ".json", ".yaml"],
    max_file_size=1_000_000
)

# Read file
result = reader.read_file("./data/config.json")
print(result["content"])

# List directory
result = reader.list_directory("./data", pattern="*.txt")
print(result["files"])

# Check if file exists
result = reader.exists("./data/test.txt")
```

#### Calculator

```python
from atr.tools.safe import CalculatorTool

calc = CalculatorTool(precision=10)

# Evaluate expression (safe - no eval())
result = calc.evaluate("2 + 2 * 3")  # 8

# With variables
result = calc.evaluate("x * 2 + y", {"x": 5, "y": 10})  # 20

# Math functions
result = calc.evaluate("sqrt(16) + sin(0)")  # 4.0

# Statistics
result = calc.statistics([1, 2, 3, 4, 5])
# {"mean": 3.0, "median": 3.0, "std_dev": 1.58...}
```

#### JSON Parser

```python
from atr.tools.safe import JsonParserTool

parser = JsonParserTool(max_size=1_000_000, max_depth=50)

# Parse JSON
result = parser.parse_json('{"key": "value"}')
print(result["data"])

# Parse YAML (safe_load)
result = parser.parse_yaml("key: value")

# Convert to JSON
result = parser.to_json({"key": "value"}, indent=2)

# Validate schema
result = parser.validate_schema(
    data={"name": "John", "age": 30},
    schema={"type": "object", "required": ["name"]}
)
```

#### DateTime

```python
from atr.tools.safe import DateTimeTool

dt = DateTimeTool(default_timezone="UTC")

# Get current time
now = dt.now()
print(now["iso"])  # 2024-01-15T10:30:00+00:00

# Parse date
result = dt.parse("2024-01-15")

# Format date
result = dt.format("2024-01-15T10:30:00Z", format="human")
# "January 15, 2024 at 10:30 AM"

# Add time
result = dt.add("2024-01-15T10:30:00Z", days=7, hours=2)

# Calculate difference
result = dt.diff("2024-01-15", "2024-01-20")
# {"days": 5, "total_hours": 120, ...}
```

#### Text Tool

```python
from atr.tools.safe import TextTool

text = TextTool(max_length=100_000)

# Split/join
result = text.split("hello world", " ")  # ["hello", "world"]
result = text.join(["a", "b", "c"], "-")  # "a-b-c"

# Replace
result = text.replace("hello world", "world", "universe")

# Analyze
result = text.analyze("Hello world! How are you?")
# {"words": 5, "sentences": 2, "characters": 25, ...}

# Safe regex
result = text.regex_find(r"\d+", "abc123def456")
# {"matches": ["123", "456"]}

# Hash
result = text.hash("my text", algorithm="sha256")
```

## Creating Custom Tools

### Basic Custom Tool

```python
from atr.decorator import tool

@tool(
    name="my_custom_tool",
    description="Does something useful",
    tags=["custom", "safe"]
)
def my_tool(input_data: str) -> dict:
    """
    Process input data safely.
    
    Args:
        input_data: Data to process
    
    Returns:
        Processed result
    """
    # Your logic here
    result = input_data.upper()
    
    return {
        "success": True,
        "result": result
    }
```

### Tool with Validation

```python
from atr.decorator import tool
from typing import Optional, List

@tool(
    name="data_processor",
    description="Process data with validation",
    tags=["data", "safe"]
)
def process_data(
    items: List[str],
    max_items: int = 100,
    filter_pattern: Optional[str] = None
) -> dict:
    """Process a list of items safely."""
    
    # Validate inputs
    if len(items) > max_items:
        return {
            "success": False,
            "error": f"Too many items: {len(items)}. Max: {max_items}"
        }
    
    # Process
    result = []
    for item in items:
        if filter_pattern and filter_pattern not in item:
            continue
        result.append(item.strip())
    
    return {
        "success": True,
        "result": result,
        "count": len(result)
    }
```

### Tool Class with State

```python
from atr.decorator import tool
from typing import Dict, Any

class DatabaseTool:
    """Safe database query tool."""
    
    def __init__(
        self,
        connection_string: str,
        allowed_tables: List[str],
        max_results: int = 1000
    ):
        self.connection_string = connection_string
        self.allowed_tables = set(allowed_tables)
        self.max_results = max_results
        self._connection = None
    
    def _validate_table(self, table: str):
        """Ensure table is in allowed list."""
        if table not in self.allowed_tables:
            raise ValueError(
                f"Table '{table}' not allowed. "
                f"Allowed: {', '.join(self.allowed_tables)}"
            )
    
    @tool(
        name="db_select",
        description="Run a safe SELECT query",
        tags=["database", "read", "safe"]
    )
    async def select(
        self,
        table: str,
        columns: List[str] = None,
        where: Dict[str, Any] = None,
        limit: int = 100
    ) -> Dict[str, Any]:
        """
        Run a SELECT query safely.
        
        Args:
            table: Table name (must be in allowed list)
            columns: Columns to select (default: all)
            where: WHERE conditions as dict
            limit: Max rows to return
        """
        # Validate
        self._validate_table(table)
        limit = min(limit, self.max_results)
        
        # Build query safely (no SQL injection)
        cols = ", ".join(columns) if columns else "*"
        query = f"SELECT {cols} FROM {table}"
        
        if where:
            conditions = " AND ".join(
                f"{k} = ?" for k in where.keys()
            )
            query += f" WHERE {conditions}"
        
        query += f" LIMIT {limit}"
        
        # Execute (using parameterized query)
        # ... actual database code ...
        
        return {
            "success": True,
            "query": query,
            "rows": [],  # results
            "count": 0
        }
```

### Async Tool

```python
from atr.decorator import tool
import asyncio

@tool(
    name="async_fetcher",
    description="Fetch data asynchronously",
    tags=["async", "network", "safe"]
)
async def fetch_multiple(urls: List[str], timeout: float = 10.0) -> dict:
    """Fetch multiple URLs concurrently."""
    
    import aiohttp
    
    async def fetch_one(session, url):
        try:
            async with session.get(url, timeout=timeout) as response:
                return {
                    "url": url,
                    "status": response.status,
                    "success": True
                }
        except Exception as e:
            return {
                "url": url,
                "error": str(e),
                "success": False
            }
    
    async with aiohttp.ClientSession() as session:
        tasks = [fetch_one(session, url) for url in urls]
        results = await asyncio.gather(*tasks)
    
    return {
        "success": True,
        "results": results,
        "total": len(results),
        "successful": sum(1 for r in results if r["success"])
    }
```

## Registering Tools with ATR

```python
from atr import ToolRegistry
from atr.tools.safe import create_safe_toolkit

# Create registry
registry = ToolRegistry()

# Register pre-built tools
toolkit = create_safe_toolkit("standard")
toolkit["register_all"](registry)

# Register custom tool
@tool(name="my_tool", description="My custom tool")
def my_tool(x: int) -> int:
    return x * 2

registry.register(my_tool)

# List registered tools
for tool in registry.list_tools():
    print(f"- {tool.name}: {tool.description}")
```

## Security Best Practices

### 1. Input Validation

```python
@tool(name="safe_tool")
def safe_tool(data: str, max_length: int = 1000) -> dict:
    # Always validate inputs
    if len(data) > max_length:
        return {"error": f"Input too long: {len(data)} > {max_length}"}
    
    # Sanitize
    data = data.strip()
    
    # Process
    return {"result": process(data)}
```

### 2. Output Limits

```python
@tool(name="list_tool")
def list_tool(items: list, max_items: int = 100) -> dict:
    # Limit output size
    result = items[:max_items]
    truncated = len(items) > max_items
    
    return {
        "result": result,
        "truncated": truncated,
        "total": len(items)
    }
```

### 3. Timeout Protection

```python
import asyncio

@tool(name="slow_tool")
async def slow_tool(data: str, timeout: float = 30.0) -> dict:
    try:
        result = await asyncio.wait_for(
            slow_operation(data),
            timeout=timeout
        )
        return {"success": True, "result": result}
    except asyncio.TimeoutError:
        return {"success": False, "error": "Operation timed out"}
```

### 4. Resource Limits

```python
@tool(name="memory_safe_tool")
def memory_safe_tool(data: list, max_memory_mb: int = 100) -> dict:
    import sys
    
    # Check memory usage
    size_bytes = sys.getsizeof(data)
    size_mb = size_bytes / (1024 * 1024)
    
    if size_mb > max_memory_mb:
        return {"error": f"Data too large: {size_mb:.1f}MB > {max_memory_mb}MB"}
    
    return {"result": process(data)}
```

## Next Steps

| Tutorial | Description |
|----------|-------------|
| [Multi-Agent Systems](./multi-agent.md) | Coordinate agent teams |
| [Observability](../observability.md) | Monitor tool usage |
| [ATR Reference](../packages/atr.md) | Full ATR documentation |

---

<div align="center">

**Ready to build multi-agent systems?**

[Multi-Agent Systems →](./multi-agent.md)

</div>
