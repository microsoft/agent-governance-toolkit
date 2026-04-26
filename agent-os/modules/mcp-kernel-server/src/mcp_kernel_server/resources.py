# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
MCP Resources for Agent OS VFS.

Exposes the Agent Virtual File System as MCP resources,
allowing agents to read/write structured memory.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, Optional
from datetime import datetime, timezone
import json


@dataclass
class ResourceContent:
    """Content returned from VFS resource."""
    uri: str
    mime_type: str
    content: Any
    metadata: dict = field(default_factory=dict)


class VFSResource:
    """
    Agent Virtual File System as MCP Resource.
    
    Provides structured memory access through standard paths:
    - /vfs/{agent_id}/mem/working/* - Ephemeral working memory
    - /vfs/{agent_id}/mem/episodic/* - Experience logs
    - /vfs/{agent_id}/policy/* - Read-only policies
    
    Stateless Design:
    - All state stored in external backend (memory/redis/s3)
    - No session state maintained in server
    - Horizontally scalable
    """
    
    uri_template = "vfs://{agent_id}/{path}"
    
    # Backend storage (in production: Redis, S3, DynamoDB)
    _storage: Dict[str, Dict[str, Any]] = {}
    
    def __init__(self, config: Optional[dict] = None):
        self.config = config or {}
        self.backend = self.config.get("backend", "memory")
    
    def list_resources(self, agent_id: str) -> list:
        """List available resources for an agent."""
        return [
            {
                "uri": f"vfs://{agent_id}/mem/working",
                "name": "Working Memory",
                "description": "Ephemeral working memory for current task",
                "mimeType": "application/json"
            },
            {
                "uri": f"vfs://{agent_id}/mem/episodic",
                "name": "Episodic Memory", 
                "description": "Agent experience and history logs",
                "mimeType": "application/json"
            },
            {
                "uri": f"vfs://{agent_id}/policy",
                "name": "Policies",
                "description": "Agent policies and constraints (read-only)",
                "mimeType": "application/json"
            }
        ]
    
    async def read(self, uri: str) -> ResourceContent:
        """Read from VFS path."""
        agent_id, path = self._parse_uri(uri)
        
        # Initialize agent storage if needed
        if agent_id not in self._storage:
            self._storage[agent_id] = self._init_agent_storage(agent_id)
        
        # Navigate to path
        content = self._get_path(self._storage[agent_id], path)
        
        return ResourceContent(
            uri=uri,
            mime_type="application/json",
            content=content,
            metadata={
                "agent_id": agent_id,
                "path": path,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
        )
    
    async def write(self, uri: str, content: Any) -> ResourceContent:
        """Write to VFS path (if allowed)."""
        agent_id, path = self._parse_uri(uri)
        
        # Check write permissions
        if path.startswith("policy"):
            raise PermissionError(f"Cannot write to policy path: {path}")
        
        # Initialize agent storage if needed
        if agent_id not in self._storage:
            self._storage[agent_id] = self._init_agent_storage(agent_id)
        
        # Write to path
        self._set_path(self._storage[agent_id], path, content)
        
        return ResourceContent(
            uri=uri,
            mime_type="application/json",
            content={"status": "written", "path": path},
            metadata={
                "agent_id": agent_id,
                "path": path,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
        )
    
    def _parse_uri(self, uri: str) -> tuple:
        """Parse VFS URI into agent_id and path."""
        # Handle vfs://agent_id/path format
        if uri.startswith("vfs://"):
            uri = uri[6:]
        
        parts = uri.split("/", 1)
        agent_id = parts[0]
        path = parts[1] if len(parts) > 1 else ""
        
        return agent_id, path
    
    def _init_agent_storage(self, agent_id: str) -> dict:
        """Initialize storage structure for an agent."""
        return {
            "mem": {
                "working": {
                    "_meta": {"type": "working_memory", "ephemeral": True}
                },
                "episodic": {
                    "_meta": {"type": "episodic_memory"},
                    "sessions": []
                }
            },
            "policy": {
                "_meta": {"type": "policies", "read_only": True},
                "default": {
                    "name": "default",
                    "rules": [
                        {"action": "*", "effect": "allow"}
                    ]
                }
            }
        }
    
    def _get_path(self, storage: dict, path: str) -> Any:
        """Navigate storage to get value at path."""
        if not path:
            return storage
        
        current = storage
        for part in path.split("/"):
            if not part:
                continue
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                return None
        return current
    
    def _set_path(self, storage: dict, path: str, value: Any):
        """Navigate storage to set value at path."""
        parts = [p for p in path.split("/") if p]
        
        current = storage
        for part in parts[:-1]:
            if part not in current:
                current[part] = {}
            current = current[part]
        
        if parts:
            current[parts[-1]] = value


class VFSResourceTemplate:
    """
    MCP Resource Template for dynamic VFS paths.
    
    Allows clients to discover available resources dynamically.
    """
    
    uri_template = "vfs://{agent_id}/{path}"
    name = "Agent VFS"
    description = "Virtual File System for agent memory and policies"
    
    @staticmethod
    def get_templates() -> list:
        """Return MCP resource templates."""
        return [
            {
                "uriTemplate": "vfs://{agent_id}/mem/working/{key}",
                "name": "Working Memory Item",
                "description": "Read/write ephemeral working memory",
                "mimeType": "application/json"
            },
            {
                "uriTemplate": "vfs://{agent_id}/mem/episodic/{session_id}",
                "name": "Episodic Session",
                "description": "Read/write session history",
                "mimeType": "application/json"
            },
            {
                "uriTemplate": "vfs://{agent_id}/policy/{policy_name}",
                "name": "Policy",
                "description": "Read agent policy (read-only)",
                "mimeType": "application/json"
            }
        ]
