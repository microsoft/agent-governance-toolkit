# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Tool Registry - Dynamic Tool Management and Discovery

The Tool Registry enables dynamic registration and discovery of tools for agents,
supporting extensibility beyond the hardcoded ActionType enum. This addresses
the need for flexible tool ecosystems similar to LangChain's 100+ integrations.

Research Foundations:
    - Plugin architecture patterns for extensible systems
    - Service registry patterns from microservices architecture
    - Tool abstraction inspired by "Multimodal Agents: A Survey" (arXiv:2404.12390)
    - Dynamic capability discovery for agent systems

See docs/RESEARCH_FOUNDATION.md for complete references.
"""

from typing import Any, Dict, List, Optional, Callable, Set
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
import hashlib
import inspect
import logging
import textwrap
import uuid

logger = logging.getLogger(__name__)


class ToolType(Enum):
    """Categories of tools available to agents"""
    TEXT = "text"
    VISION = "vision"
    AUDIO = "audio"
    CODE = "code"
    DATABASE = "database"
    API = "api"
    FILE_SYSTEM = "file_system"
    WORKFLOW = "workflow"
    SEARCH = "search"
    CUSTOM = "custom"


@dataclass
class ToolSchema:
    """JSON Schema definition for tool parameters"""
    type: str = "object"
    properties: Dict[str, Any] = field(default_factory=dict)
    required: List[str] = field(default_factory=list)
    description: str = ""


@dataclass
class Tool:
    """
    A tool that can be used by agents.
    
    Attributes:
        tool_id: Unique identifier for the tool
        name: Human-readable name
        description: What the tool does
        tool_type: Category of the tool
        handler: Function that executes the tool
        parameter_schema: JSON schema for parameters
        requires_approval: Whether tool execution requires human approval
        risk_level: Risk score (0.0-1.0, higher = more risky)
        content_hash: SHA-256 hash of the tool handler's source code at
            registration time.  Used to detect tampering or aliasing.
        metadata: Additional tool metadata
    """
    tool_id: str
    name: str
    description: str
    tool_type: ToolType
    handler: Callable
    parameter_schema: ToolSchema
    requires_approval: bool = False
    risk_level: float = 0.0
    content_hash: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.now)


class ToolRegistry:
    """
    Central registry for dynamic tool management.
    
    Features:
    - Register tools dynamically at runtime
    - Discover available tools by type or capability
    - Validate tool parameters against schemas
    - Support for multi-modal tools (text, vision, audio)
    - Integration point for external tool providers
    
    Usage:
        registry = ToolRegistry()
        
        # Register a tool
        registry.register_tool(
            name="web_search",
            description="Search the web for information",
            tool_type=ToolType.SEARCH,
            handler=search_handler,
            parameter_schema=search_schema
        )
        
        # Discover tools
        tools = registry.get_tools_by_type(ToolType.SEARCH)
        
        # Execute a tool
        result = registry.execute_tool("web_search", {"query": "AI safety"})
    """
    
    def __init__(self):
        self._tools: Dict[str, Tool] = {}
        self._tools_by_type: Dict[ToolType, Set[str]] = {}
        self._tools_by_name: Dict[str, str] = {}  # name -> tool_id mapping
        self._integrity_violations: List[Dict[str, Any]] = []

    @staticmethod
    def _compute_handler_hash(handler: Callable) -> str:
        """Compute a SHA-256 content hash of a callable's source code.

        Returns an empty string if source is unavailable (e.g. built-in
        or C-extension functions).  Callers should treat an empty hash
        as "unverifiable" rather than silently trusting the handler.
        """
        try:
            source = textwrap.dedent(inspect.getsource(handler))
            return hashlib.sha256(source.encode("utf-8")).hexdigest()
        except (OSError, TypeError):
            logger.warning(
                "Cannot compute source hash for handler %r — "
                "source unavailable (built-in or C-extension)",
                getattr(handler, "__qualname__", handler),
            )
        return ""
        
    def register_tool(
        self,
        name: str,
        description: str,
        tool_type: ToolType,
        handler: Callable,
        parameter_schema: Optional[ToolSchema] = None,
        requires_approval: bool = False,
        risk_level: float = 0.0,
        metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Register a new tool in the registry.
        
        Args:
            name: Tool name (must be unique)
            description: What the tool does
            tool_type: Category of the tool
            handler: Function to execute the tool
            parameter_schema: JSON schema for parameters (auto-generated if None)
            requires_approval: Whether execution requires approval
            risk_level: Risk score 0.0-1.0
            metadata: Additional metadata
            
        Returns:
            tool_id: Unique identifier for the registered tool
            
        Raises:
            ValueError: If tool name already exists
        """
        if name in self._tools_by_name:
            raise ValueError(f"Tool '{name}' already registered")
            
        tool_id = str(uuid.uuid4())
        
        # Auto-generate schema from function signature if not provided
        if parameter_schema is None:
            parameter_schema = self._generate_schema_from_handler(handler)
        
        # Compute content hash for integrity verification
        content_hash = self._compute_handler_hash(handler)
        
        tool = Tool(
            tool_id=tool_id,
            name=name,
            description=description,
            tool_type=tool_type,
            handler=handler,
            parameter_schema=parameter_schema,
            requires_approval=requires_approval,
            risk_level=risk_level,
            content_hash=content_hash,
            metadata=metadata or {}
        )
        
        self._tools[tool_id] = tool
        self._tools_by_name[name] = tool_id
        
        if tool_type not in self._tools_by_type:
            self._tools_by_type[tool_type] = set()
        self._tools_by_type[tool_type].add(tool_id)
        
        return tool_id
    
    def unregister_tool(self, tool_id_or_name: str) -> bool:
        """
        Remove a tool from the registry.
        
        Args:
            tool_id_or_name: Tool ID or name
            
        Returns:
            True if tool was removed, False if not found
        """
        tool_id = self._resolve_tool_id(tool_id_or_name)
        if not tool_id:
            return False
            
        tool = self._tools.get(tool_id)
        if not tool:
            return False
            
        del self._tools[tool_id]
        del self._tools_by_name[tool.name]
        self._tools_by_type[tool.tool_type].discard(tool_id)
        
        return True
    
    def get_tool(self, tool_id_or_name: str) -> Optional[Tool]:
        """Get a tool by ID or name"""
        tool_id = self._resolve_tool_id(tool_id_or_name)
        return self._tools.get(tool_id) if tool_id else None
    
    def get_tools_by_type(self, tool_type: ToolType) -> List[Tool]:
        """Get all tools of a specific type"""
        tool_ids = self._tools_by_type.get(tool_type, set())
        return [self._tools[tid] for tid in tool_ids]
    
    def get_all_tools(self) -> List[Tool]:
        """Get all registered tools"""
        return list(self._tools.values())
    
    def execute_tool(
        self,
        tool_id_or_name: str,
        parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Execute a registered tool.
        
        Args:
            tool_id_or_name: Tool ID or name
            parameters: Tool parameters
            
        Returns:
            Result dictionary with 'success', 'result', or 'error' keys
        """
        tool = self.get_tool(tool_id_or_name)
        if not tool:
            return {
                "success": False,
                "error": f"Tool '{tool_id_or_name}' not found"
            }
        
        # Verify tool integrity before execution
        integrity = self.verify_tool_integrity(tool.tool_id)
        if not integrity["verified"]:
            logger.warning(
                "Tool integrity check FAILED for '%s': %s",
                tool.name,
                integrity["reason"],
            )
            self._integrity_violations.append({
                "tool_id": tool.tool_id,
                "tool_name": tool.name,
                "reason": integrity["reason"],
                "timestamp": datetime.now().isoformat(),
            })
            return {
                "success": False,
                "error": f"Tool integrity verification failed: {integrity['reason']}",
                "tool_id": tool.tool_id,
                "tool_name": tool.name,
            }
        
        # Validate parameters against schema
        validation_result = self.validate_parameters(tool.tool_id, parameters)
        if not validation_result["valid"]:
            return {
                "success": False,
                "error": f"Invalid parameters: {validation_result['errors']}"
            }
        
        try:
            result = tool.handler(**parameters)
            return {
                "success": True,
                "result": result,
                "tool_id": tool.tool_id,
                "tool_name": tool.name
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "tool_id": tool.tool_id,
                "tool_name": tool.name
            }
    
    def validate_parameters(
        self,
        tool_id_or_name: str,
        parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Validate parameters against tool schema.
        
        Returns:
            {"valid": bool, "errors": List[str]}
        """
        tool = self.get_tool(tool_id_or_name)
        if not tool:
            return {"valid": False, "errors": ["Tool not found"]}
        
        errors = []
        schema = tool.parameter_schema
        
        # Check required parameters
        for required_param in schema.required:
            if required_param not in parameters:
                errors.append(f"Missing required parameter: {required_param}")
        
        # Type checking would go here (simplified for now)
        # In production, use jsonschema library for full validation
        
        return {
            "valid": len(errors) == 0,
            "errors": errors
        }
    
    def search_tools(self, query: str) -> List[Tool]:
        """
        Search tools by name or description.
        
        Args:
            query: Search string
            
        Returns:
            List of matching tools
        """
        query_lower = query.lower()
        matches = []
        
        for tool in self._tools.values():
            if (query_lower in tool.name.lower() or 
                query_lower in tool.description.lower()):
                matches.append(tool)
        
        return matches
    
    def verify_tool_integrity(self, tool_id_or_name: str) -> Dict[str, Any]:
        """Verify that a tool's handler has not been modified since registration.

        Compares the current SHA-256 hash of the handler's source code
        against the hash recorded at registration time.

        Returns:
            {"verified": bool, "reason": str, "registered_hash": str, "current_hash": str}
        """
        tool = self.get_tool(tool_id_or_name)
        if not tool:
            return {
                "verified": False,
                "reason": "Tool not found",
                "registered_hash": "",
                "current_hash": "",
            }

        if not tool.content_hash:
            return {
                "verified": False,
                "reason": "No content hash recorded at registration (built-in or C-extension)",
                "registered_hash": "",
                "current_hash": "",
            }

        current_hash = self._compute_handler_hash(tool.handler)
        if not current_hash:
            return {
                "verified": False,
                "reason": "Cannot compute current hash — source unavailable",
                "registered_hash": tool.content_hash,
                "current_hash": "",
            }

        verified = current_hash == tool.content_hash
        return {
            "verified": verified,
            "reason": "" if verified else "Handler source has been modified since registration",
            "registered_hash": tool.content_hash,
            "current_hash": current_hash,
        }

    def get_integrity_violations(self) -> List[Dict[str, Any]]:
        """Return all recorded integrity violations."""
        return list(self._integrity_violations)
    
    def _resolve_tool_id(self, tool_id_or_name: str) -> Optional[str]:
        """Resolve a tool name to its ID, or return ID if already an ID"""
        if tool_id_or_name in self._tools:
            return tool_id_or_name
        return self._tools_by_name.get(tool_id_or_name)
    
    def _generate_schema_from_handler(self, handler: Callable) -> ToolSchema:
        """Auto-generate a basic schema from function signature"""
        sig = inspect.signature(handler)
        properties = {}
        required = []
        
        for param_name, param in sig.parameters.items():
            if param_name == "self":
                continue
                
            properties[param_name] = {
                "type": "string",  # Default to string, would need type hints for better
                "description": f"Parameter {param_name}"
            }
            
            if param.default == inspect.Parameter.empty:
                required.append(param_name)
        
        return ToolSchema(
            type="object",
            properties=properties,
            required=required,
            description=handler.__doc__ or ""
        )


def create_standard_tool_registry() -> ToolRegistry:
    """
    Create a tool registry with standard built-in tools.
    
    Returns:
        ToolRegistry with common tools pre-registered
    """
    registry = ToolRegistry()
    
    # This would register standard tools
    # Intentionally left minimal to show the pattern
    
    return registry
