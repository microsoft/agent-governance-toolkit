# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Safe JSON/YAML Parser Tool.

Provides safe parsing of JSON and YAML with:
- Size limits to prevent memory exhaustion
- Depth limits to prevent stack overflow
- Safe YAML loading (no arbitrary code execution)
- Schema validation support
"""

import json
from typing import Any, Dict, List, Optional, Union

from atr.decorator import tool


class JsonParserTool:
    """
    Safe JSON and YAML parser.
    
    Features:
    - Input size limits
    - Nesting depth limits
    - Safe YAML loading (yaml.safe_load)
    - Schema validation (optional)
    - Pretty printing
    
    Example:
        ```python
        parser = JsonParserTool(
            max_size=1_000_000,  # 1MB
            max_depth=50
        )
        
        # Parse JSON
        data = parser.parse_json('{"key": "value"}')
        
        # Parse YAML  
        data = parser.parse_yaml("key: value")
        
        # Validate schema
        parser.validate(data, schema={"type": "object"})
        ```
    """
    
    def __init__(
        self,
        max_size: int = 10_000_000,  # 10MB
        max_depth: int = 100,
        max_keys: int = 10000
    ):
        """
        Initialize parser tool.
        
        Args:
            max_size: Maximum input size in characters
            max_depth: Maximum nesting depth
            max_keys: Maximum number of keys in objects
        """
        self.max_size = max_size
        self.max_depth = max_depth
        self.max_keys = max_keys
    
    def _check_size(self, data: str, name: str = "input"):
        """Check input size."""
        if len(data) > self.max_size:
            raise ValueError(
                f"{name} too large: {len(data)} chars. Maximum: {self.max_size}"
            )
    
    def _check_depth(self, obj: Any, current_depth: int = 0):
        """Check nesting depth recursively."""
        if current_depth > self.max_depth:
            raise ValueError(f"Nesting too deep. Maximum depth: {self.max_depth}")
        
        if isinstance(obj, dict):
            if len(obj) > self.max_keys:
                raise ValueError(f"Too many keys: {len(obj)}. Maximum: {self.max_keys}")
            for value in obj.values():
                self._check_depth(value, current_depth + 1)
        elif isinstance(obj, list):
            for item in obj:
                self._check_depth(item, current_depth + 1)
    
    @tool(
        name="parse_json",
        description="Safely parse a JSON string into a Python object",
        tags=["json", "parse", "safe"]
    )
    def parse_json(self, data: str) -> Dict[str, Any]:
        """
        Parse JSON string.
        
        Args:
            data: JSON string to parse
        
        Returns:
            Dict with parsed data and metadata
        """
        self._check_size(data, "JSON")
        
        try:
            parsed = json.loads(data)
        except json.JSONDecodeError as e:
            return {
                "success": False,
                "error": f"Invalid JSON: {e.msg} at line {e.lineno}, column {e.colno}",
                "data": None
            }
        
        # Check depth
        try:
            self._check_depth(parsed)
        except ValueError as e:
            return {
                "success": False,
                "error": str(e),
                "data": None
            }
        
        return {
            "success": True,
            "data": parsed,
            "type": type(parsed).__name__
        }
    
    @tool(
        name="parse_yaml",
        description="Safely parse a YAML string into a Python object",
        tags=["yaml", "parse", "safe"]
    )
    def parse_yaml(self, data: str) -> Dict[str, Any]:
        """
        Parse YAML string safely.
        
        Uses yaml.safe_load to prevent arbitrary code execution.
        
        Args:
            data: YAML string to parse
        
        Returns:
            Dict with parsed data and metadata
        """
        try:
            import yaml
        except ImportError:
            return {
                "success": False,
                "error": "PyYAML not installed. Install with: pip install pyyaml",
                "data": None
            }
        
        self._check_size(data, "YAML")
        
        try:
            # Always use safe_load to prevent code execution
            parsed = yaml.safe_load(data)
        except yaml.YAMLError as e:
            return {
                "success": False,
                "error": f"Invalid YAML: {e}",
                "data": None
            }
        
        # Check depth
        try:
            self._check_depth(parsed)
        except ValueError as e:
            return {
                "success": False,
                "error": str(e),
                "data": None
            }
        
        return {
            "success": True,
            "data": parsed,
            "type": type(parsed).__name__ if parsed is not None else "null"
        }
    
    @tool(
        name="to_json",
        description="Convert a Python object to a JSON string",
        tags=["json", "serialize", "safe"]
    )
    def to_json(
        self,
        data: Any,
        indent: Optional[int] = 2,
        sort_keys: bool = False
    ) -> Dict[str, Any]:
        """
        Convert object to JSON string.
        
        Args:
            data: Object to serialize
            indent: Indentation level (None for compact)
            sort_keys: Whether to sort dictionary keys
        
        Returns:
            Dict with JSON string
        """
        try:
            result = json.dumps(data, indent=indent, sort_keys=sort_keys, ensure_ascii=False)
            
            if len(result) > self.max_size:
                return {
                    "success": False,
                    "error": f"Output too large: {len(result)} chars",
                    "json": None
                }
            
            return {
                "success": True,
                "json": result,
                "size": len(result)
            }
        except (TypeError, ValueError) as e:
            return {
                "success": False,
                "error": f"Cannot serialize: {e}",
                "json": None
            }
    
    @tool(
        name="to_yaml",
        description="Convert a Python object to a YAML string",
        tags=["yaml", "serialize", "safe"]
    )
    def to_yaml(
        self,
        data: Any,
        default_flow_style: bool = False
    ) -> Dict[str, Any]:
        """
        Convert object to YAML string.
        
        Args:
            data: Object to serialize
            default_flow_style: Use flow style (compact) formatting
        
        Returns:
            Dict with YAML string
        """
        try:
            import yaml
        except ImportError:
            return {
                "success": False,
                "error": "PyYAML not installed. Install with: pip install pyyaml",
                "yaml": None
            }
        
        try:
            result = yaml.safe_dump(
                data,
                default_flow_style=default_flow_style,
                allow_unicode=True
            )
            
            if len(result) > self.max_size:
                return {
                    "success": False,
                    "error": f"Output too large: {len(result)} chars",
                    "yaml": None
                }
            
            return {
                "success": True,
                "yaml": result,
                "size": len(result)
            }
        except yaml.YAMLError as e:
            return {
                "success": False,
                "error": f"Cannot serialize: {e}",
                "yaml": None
            }
    
    @tool(
        name="validate_json_schema",
        description="Validate data against a JSON schema",
        tags=["json", "validate", "schema", "safe"]
    )
    def validate_schema(
        self,
        data: Any,
        schema: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Validate data against JSON schema.
        
        Args:
            data: Data to validate
            schema: JSON schema
        
        Returns:
            Dict with validation result
        """
        try:
            import jsonschema
        except ImportError:
            return {
                "valid": False,
                "error": "jsonschema not installed. Install with: pip install jsonschema"
            }
        
        try:
            jsonschema.validate(instance=data, schema=schema)
            return {
                "valid": True,
                "error": None
            }
        except jsonschema.ValidationError as e:
            return {
                "valid": False,
                "error": e.message,
                "path": list(e.absolute_path)
            }
        except jsonschema.SchemaError as e:
            return {
                "valid": False,
                "error": f"Invalid schema: {e.message}"
            }
    
    @tool(
        name="json_query",
        description="Query JSON data using JSONPath or simple dot notation",
        tags=["json", "query", "safe"]
    )
    def query(
        self,
        data: Any,
        path: str
    ) -> Dict[str, Any]:
        """
        Query JSON data using dot notation.
        
        Args:
            data: JSON data to query
            path: Dot-notation path (e.g., "users.0.name")
        
        Returns:
            Dict with query result
        """
        parts = path.split(".")
        current = data
        
        try:
            for part in parts:
                if not part:
                    continue
                
                if isinstance(current, dict):
                    current = current[part]
                elif isinstance(current, list):
                    idx = int(part)
                    current = current[idx]
                else:
                    raise KeyError(f"Cannot access '{part}' on {type(current).__name__}")
            
            return {
                "success": True,
                "value": current,
                "path": path
            }
        except (KeyError, IndexError, ValueError) as e:
            return {
                "success": False,
                "error": f"Path not found: {e}",
                "value": None
            }
