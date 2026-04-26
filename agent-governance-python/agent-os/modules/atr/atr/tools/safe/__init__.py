# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Safe Tool Plugins for Agent Tool Registry (ATR).

This package provides pre-built, security-hardened tools that agents can use
safely without risk of unauthorized access or dangerous operations.

All tools in this package follow the principle of least privilege:
- Read-only operations where possible
- Sandboxed file access
- Rate limiting on network operations
- Input validation and sanitization
- No shell execution

Available Tools:
    - HttpClientTool: Safe HTTP requests with URL whitelisting
    - FileReaderTool: Read-only file access with path sandboxing
    - JsonParserTool: Safe JSON/YAML parsing
    - CalculatorTool: Safe mathematical operations
    - DateTimeTool: Timezone-aware datetime operations
    - TextTool: Safe text processing operations

Example:
    >>> from atr.tools.safe import HttpClientTool, FileReaderTool
    >>> 
    >>> # Create tools with restrictions
    >>> http = HttpClientTool(
    ...     allowed_domains=["api.example.com"],
    ...     rate_limit=10  # requests per minute
    ... )
    >>> 
    >>> reader = FileReaderTool(
    ...     sandbox_path="/data/safe",
    ...     max_file_size=1_000_000  # 1MB
    ... )
"""

from typing import List

__all__: List[str] = [
    "HttpClientTool",
    "FileReaderTool", 
    "JsonParserTool",
    "CalculatorTool",
    "DateTimeTool",
    "TextTool",
    "create_safe_toolkit",
]


def __getattr__(name: str):
    """Lazy import tools."""
    if name == "HttpClientTool":
        from atr.tools.safe.http_client import HttpClientTool
        return HttpClientTool
    elif name == "FileReaderTool":
        from atr.tools.safe.file_reader import FileReaderTool
        return FileReaderTool
    elif name == "JsonParserTool":
        from atr.tools.safe.json_parser import JsonParserTool
        return JsonParserTool
    elif name == "CalculatorTool":
        from atr.tools.safe.calculator import CalculatorTool
        return CalculatorTool
    elif name == "DateTimeTool":
        from atr.tools.safe.datetime_tool import DateTimeTool
        return DateTimeTool
    elif name == "TextTool":
        from atr.tools.safe.text_tool import TextTool
        return TextTool
    elif name == "create_safe_toolkit":
        from atr.tools.safe.toolkit import create_safe_toolkit
        return create_safe_toolkit
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
