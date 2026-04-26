# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Safe Toolkit Factory.

Creates pre-configured collections of safe tools for common use cases.
"""

from typing import Dict, List, Optional, Any

from atr.tools.safe.http_client import HttpClientTool
from atr.tools.safe.file_reader import FileReaderTool
from atr.tools.safe.json_parser import JsonParserTool
from atr.tools.safe.calculator import CalculatorTool
from atr.tools.safe.datetime_tool import DateTimeTool
from atr.tools.safe.text_tool import TextTool


def create_safe_toolkit(
    preset: str = "standard",
    config: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Create a pre-configured toolkit of safe tools.
    
    Presets:
        - "minimal": Only calculator, datetime, text (no I/O)
        - "standard": All tools with sensible defaults
        - "restricted": Standard but with more restrictions
        - "readonly": File reader + JSON parser + calculator
        - "network": HTTP client only
    
    Args:
        preset: Preset name
        config: Optional configuration overrides
    
    Returns:
        Dict with tool instances and registry helper
    
    Example:
        ```python
        # Create standard toolkit
        toolkit = create_safe_toolkit("standard")
        
        # Access tools
        http = toolkit["http"]
        files = toolkit["files"]
        
        # Register all tools with ATR
        from atr import ToolRegistry
        registry = ToolRegistry()
        toolkit["register_all"](registry)
        ```
    """
    config = config or {}
    
    tools = {}
    
    if preset == "minimal":
        # No I/O tools - just processing
        tools["calculator"] = CalculatorTool(
            precision=config.get("precision", 15)
        )
        tools["datetime"] = DateTimeTool(
            default_timezone=config.get("timezone", "UTC")
        )
        tools["text"] = TextTool(
            max_length=config.get("max_text_length", 100000)
        )
    
    elif preset == "readonly":
        # File reading and processing
        tools["files"] = FileReaderTool(
            sandbox_paths=config.get("sandbox_paths"),
            allowed_extensions=config.get("allowed_extensions", [
                ".txt", ".json", ".yaml", ".yml", ".md", ".csv", ".xml"
            ]),
            max_file_size=config.get("max_file_size", 1_000_000)
        )
        tools["json"] = JsonParserTool(
            max_size=config.get("max_json_size", 1_000_000)
        )
        tools["calculator"] = CalculatorTool()
        tools["datetime"] = DateTimeTool()
        tools["text"] = TextTool()
    
    elif preset == "network":
        # HTTP only
        tools["http"] = HttpClientTool(
            allowed_domains=config.get("allowed_domains"),
            blocked_domains=config.get("blocked_domains"),
            rate_limit=config.get("rate_limit", 60),
            timeout=config.get("timeout", 30),
            max_response_size=config.get("max_response_size", 10_000_000)
        )
    
    elif preset == "restricted":
        # All tools with stricter limits
        tools["http"] = HttpClientTool(
            allowed_domains=config.get("allowed_domains", []),  # Must specify domains
            rate_limit=config.get("rate_limit", 10),  # Lower rate limit
            timeout=config.get("timeout", 10),
            max_response_size=config.get("max_response_size", 1_000_000)
        )
        tools["files"] = FileReaderTool(
            sandbox_paths=config.get("sandbox_paths", []),  # Must specify paths
            allowed_extensions=config.get("allowed_extensions", [".txt", ".json"]),
            max_file_size=config.get("max_file_size", 100_000),
            follow_symlinks=False
        )
        tools["json"] = JsonParserTool(
            max_size=config.get("max_json_size", 100_000),
            max_depth=config.get("max_depth", 20)
        )
        tools["calculator"] = CalculatorTool(precision=10)
        tools["datetime"] = DateTimeTool()
        tools["text"] = TextTool(max_length=10000)
    
    else:  # "standard" or default
        # All tools with sensible defaults
        tools["http"] = HttpClientTool(
            allowed_domains=config.get("allowed_domains"),
            blocked_domains=config.get("blocked_domains"),
            rate_limit=config.get("rate_limit", 60),
            timeout=config.get("timeout", 30),
            max_response_size=config.get("max_response_size", 10_000_000)
        )
        tools["files"] = FileReaderTool(
            sandbox_paths=config.get("sandbox_paths"),
            allowed_extensions=config.get("allowed_extensions"),
            max_file_size=config.get("max_file_size", 10_000_000)
        )
        tools["json"] = JsonParserTool(
            max_size=config.get("max_json_size", 10_000_000)
        )
        tools["calculator"] = CalculatorTool(
            precision=config.get("precision", 15)
        )
        tools["datetime"] = DateTimeTool(
            default_timezone=config.get("timezone", "UTC")
        )
        tools["text"] = TextTool(
            max_length=config.get("max_text_length", 1_000_000)
        )
    
    # Helper function to register all tools
    def register_all(registry):
        """Register all tools with an ATR registry."""
        for name, tool in tools.items():
            if name.startswith("_"):
                continue
            # Register tool methods
            for method_name in dir(tool):
                if method_name.startswith("_"):
                    continue
                method = getattr(tool, method_name)
                if callable(method) and hasattr(method, "_tool_metadata"):
                    registry.register(method)
    
    tools["register_all"] = register_all
    tools["_preset"] = preset
    tools["_config"] = config
    
    return tools


def list_presets() -> Dict[str, str]:
    """List available toolkit presets."""
    return {
        "minimal": "Calculator, datetime, text - no I/O operations",
        "standard": "All tools with sensible defaults",
        "restricted": "All tools with stricter security limits",
        "readonly": "File reader, JSON parser, calculator - no network",
        "network": "HTTP client only - no file access"
    }
