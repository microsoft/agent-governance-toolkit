# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
MCP Kernel Server - Main server implementation.

Exposes Agent OS primitives through Model Context Protocol:
- Tools: cmvk_verify, kernel_execute, iatp_sign, iatp_verify, iatp_reputation
- Resources: VFS filesystem, audit logs
- Prompts: Standard agent instructions

AAIF Compliance:
- Stateless: All context in request, no session state
- MCP June 2026: Full protocol compliance
- Claude Desktop: Zero-config integration via stdio

Usage:
    # Stdio mode (for Claude Desktop)
    mcp-kernel-server --stdio
    
    # HTTP mode (for development)
    mcp-kernel-server --http --port 8080
"""

import asyncio
import json
import logging
import sys
from typing import Any, Optional
from dataclasses import dataclass, asdict

from mcp_kernel_server.tools import (
    CMVKVerifyTool,
    KernelExecuteTool,
    IATPSignTool,
    IATPVerifyTool,
    IATPReputationTool,
    VerifyCodeSafetyTool,
    CMVKReviewCodeTool,
    GetAuditLogTool,
    ToolResult,
)
from mcp_kernel_server.resources import VFSResource, VFSResourceTemplate

logger = logging.getLogger(__name__)


@dataclass
class ServerConfig:
    """Server configuration."""
    host: str = "0.0.0.0"
    port: int = 8080
    policy_mode: str = "strict"
    cmvk_threshold: float = 0.85
    vfs_backend: str = "memory"


# =============================================================================
# MCP Prompts - Standard Agent Instructions
# =============================================================================

PROMPTS = {
    "governed_agent": {
        "name": "governed_agent",
        "description": "Instructions for operating as a governed agent under Agent OS",
        "arguments": [
            {
                "name": "agent_id",
                "description": "Unique identifier for this agent",
                "required": True
            },
            {
                "name": "policies",
                "description": "Comma-separated list of policies to enforce",
                "required": False
            }
        ],
        "template": """You are operating as a governed agent under Agent OS.

Agent ID: {agent_id}
Active Policies: {policies}

IMPORTANT RULES:
1. Before executing any action, use the kernel_execute tool
2. The kernel will check your action against active policies
3. If the kernel returns a SIGKILL, stop immediately
4. All actions are logged to the audit trail

Available Tools:
- kernel_execute: Execute actions with policy enforcement
- cmvk_verify: Verify claims across multiple models
- iatp_sign: Sign trust attestations for other agents
- iatp_verify: Verify trust relationships
- iatp_reputation: Query agent reputation network

Example usage:
```
Use kernel_execute with:
- action: "database_query"
- params: {"query": "SELECT * FROM users WHERE id = 1"}
- agent_id: "{agent_id}"
- policies: [{policies}]
```
"""
    },
    "verify_claim": {
        "name": "verify_claim",
        "description": "Instructions for verifying a claim using CMVK",
        "arguments": [
            {
                "name": "claim",
                "description": "The claim to verify",
                "required": True
            }
        ],
        "template": """Verify the following claim using CMVK verification:

Claim: {claim}

Use the cmvk_verify tool to check this claim across multiple AI models.
This helps detect hallucinations and ensures accuracy.

The tool will return:
- verified: Whether models agree on the claim
- confidence: Agreement score (0-1)
- drift_score: Measure of disagreement between models

If drift_score > 0.15, the models significantly disagree and the claim needs review.
"""
    },
    "safe_execution": {
        "name": "safe_execution",
        "description": "Template for executing actions safely through the kernel",
        "arguments": [
            {
                "name": "action",
                "description": "The action to execute",
                "required": True
            },
            {
                "name": "params",
                "description": "JSON parameters for the action",
                "required": True
            }
        ],
        "template": """Execute the following action through the Agent OS kernel:

Action: {action}
Parameters: {params}

Use kernel_execute tool with these values. The kernel will:
1. Check the action against active policies
2. Log the action to the audit trail
3. Execute if allowed, or return SIGKILL if blocked

If you receive a SIGKILL signal, do NOT retry the action.
Explain to the user why the action was blocked.
"""
    }
}


class KernelMCPServer:
    """
    MCP Server exposing Agent OS kernel primitives.
    
    Stateless Design (MCP June 2026 Standard):
    - No session state maintained
    - All context passed in each request
    - State externalized to backend storage
    - Horizontally scalable
    
    Tools (8 total):
    - verify_code_safety: Check code safety before execution
    - cmvk_verify: Cross-model claim verification
    - cmvk_review: Multi-model code review
    - kernel_execute: Governed action execution
    - iatp_sign: Trust attestation signing
    - iatp_verify: Trust relationship verification
    - iatp_reputation: Reputation query/slashing
    - get_audit_log: Retrieve audit trail
    
    Resources:
    - vfs://{agent_id}/mem/* - Agent memory
    - vfs://{agent_id}/policy/* - Agent policies
    - audit://{agent_id}/log - Audit trail (read-only)
    
    Prompts:
    - governed_agent: Standard governed agent instructions
    - verify_claim: CMVK verification template
    - safe_execution: Safe action execution template
    """
    
    SERVER_NAME = "agent-os-kernel"
    SERVER_VERSION = "1.2.0"
    PROTOCOL_VERSION = "2024-11-05"
    
    def __init__(self, config: Optional[ServerConfig] = None):
        self.config = config or ServerConfig()
        
        # Initialize tools (stateless)
        self.tools = {
            "verify_code_safety": VerifyCodeSafetyTool(),
            "cmvk_verify": CMVKVerifyTool({"threshold": self.config.cmvk_threshold}),
            "cmvk_review": CMVKReviewCodeTool(),
            "kernel_execute": KernelExecuteTool({"policy_mode": self.config.policy_mode}),
            "iatp_sign": IATPSignTool(),
            "iatp_verify": IATPVerifyTool(),
            "iatp_reputation": IATPReputationTool(),
            "get_audit_log": GetAuditLogTool(),
        }
        
        # Initialize resources (stateless with external backend)
        self.vfs = VFSResource({"backend": self.config.vfs_backend})
        
        # Prompts (static)
        self.prompts = PROMPTS
    
    # =========================================================================
    # MCP Protocol Handlers
    # =========================================================================
    
    async def handle_initialize(self, params: dict) -> dict:
        """Handle MCP initialize request."""
        return {
            "protocolVersion": self.PROTOCOL_VERSION,
            "capabilities": {
                "tools": {"listChanged": False},
                "resources": {"subscribe": False, "listChanged": False},
                "prompts": {"listChanged": False},
            },
            "serverInfo": {
                "name": self.SERVER_NAME,
                "version": self.SERVER_VERSION
            }
        }
    
    async def handle_list_tools(self) -> dict:
        """Handle MCP tools/list request."""
        return {
            "tools": [
                {
                    "name": tool.name,
                    "description": tool.description,
                    "inputSchema": tool.input_schema
                }
                for tool in self.tools.values()
            ]
        }
    
    async def handle_call_tool(self, name: str, arguments: dict) -> dict:
        """Handle MCP tools/call request."""
        if name not in self.tools:
            return {
                "isError": True,
                "content": [{"type": "text", "text": f"Unknown tool: {name}"}]
            }
        
        tool = self.tools[name]
        
        try:
            result = await tool.execute(arguments)
            
            if result.success:
                return {
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps(result.data, indent=2)
                        }
                    ],
                    "isError": False
                }
            else:
                return {
                    "content": [
                        {
                            "type": "text", 
                            "text": result.error or "Execution failed"
                        }
                    ],
                    "isError": True
                }
        except Exception as e:
            logger.exception(f"Tool execution failed: {name}")
            return {
                "isError": True,
                "content": [{"type": "text", "text": str(e)}]
            }
    
    async def handle_list_resources(self) -> dict:
        """Handle MCP resources/list request."""
        return {
            "resources": [
                {
                    "uri": "vfs://",
                    "name": "Agent VFS Root",
                    "description": "Virtual File System for agent memory",
                    "mimeType": "application/json"
                },
                {
                    "uri": "audit://",
                    "name": "Audit Log",
                    "description": "Immutable audit trail of agent actions",
                    "mimeType": "application/json"
                }
            ]
        }
    
    async def handle_list_resource_templates(self) -> dict:
        """Handle MCP resources/templates/list request."""
        templates = VFSResourceTemplate.get_templates()
        templates.append({
            "uriTemplate": "audit://{agent_id}/log",
            "name": "Agent Audit Log",
            "description": "Read-only audit trail for agent",
            "mimeType": "application/json"
        })
        return {"resourceTemplates": templates}
    
    async def handle_read_resource(self, uri: str) -> dict:
        """Handle MCP resources/read request."""
        try:
            if uri.startswith("audit://"):
                result = await self._read_audit(uri)
            else:
                result = await self.vfs.read(uri)
            
            return {
                "contents": [
                    {
                        "uri": result.uri,
                        "mimeType": result.mime_type,
                        "text": json.dumps(result.content, indent=2)
                    }
                ]
            }
        except Exception as e:
            logger.exception(f"Resource read failed: {uri}")
            return {
                "contents": [
                    {
                        "uri": uri,
                        "mimeType": "text/plain",
                        "text": f"Error: {str(e)}"
                    }
                ]
            }
    
    async def _read_audit(self, uri: str) -> Any:
        """Read from audit log."""
        from mcp_kernel_server.resources import ResourceContent
        
        # Parse audit://agent_id/log
        parts = uri.replace("audit://", "").split("/")
        agent_id = parts[0] if parts else "unknown"
        
        # Return audit entries (in production, from external store)
        return ResourceContent(
            uri=uri,
            mime_type="application/json",
            content={
                "agent_id": agent_id,
                "entries": [],  # Would be populated from audit backend
                "note": "Audit log is append-only and immutable"
            }
        )
    
    # =========================================================================
    # MCP Prompts Handlers
    # =========================================================================
    
    async def handle_list_prompts(self) -> dict:
        """Handle MCP prompts/list request."""
        return {
            "prompts": [
                {
                    "name": p["name"],
                    "description": p["description"],
                    "arguments": p.get("arguments", [])
                }
                for p in self.prompts.values()
            ]
        }
    
    async def handle_get_prompt(self, name: str, arguments: dict) -> dict:
        """Handle MCP prompts/get request."""
        if name not in self.prompts:
            return {
                "isError": True,
                "description": f"Unknown prompt: {name}"
            }
        
        prompt = self.prompts[name]
        
        # Fill in template with arguments
        template = prompt["template"]
        for arg in prompt.get("arguments", []):
            arg_name = arg["name"]
            arg_value = arguments.get(arg_name, "")
            template = template.replace(f"{{{arg_name}}}", str(arg_value))
        
        return {
            "description": prompt["description"],
            "messages": [
                {
                    "role": "user",
                    "content": {
                        "type": "text",
                        "text": template
                    }
                }
            ]
        }
    
    # =========================================================================
    # Stdio Transport (for Claude Desktop)
    # =========================================================================
    
    async def run_stdio(self):
        """
        Run server in stdio mode for Claude Desktop integration.
        
        Protocol: JSON-RPC 2.0 over stdin/stdout
        Each message is newline-delimited JSON
        """
        logger.info("Starting MCP Kernel Server in stdio mode")
        
        reader = asyncio.StreamReader()
        protocol = asyncio.StreamReaderProtocol(reader)
        await asyncio.get_event_loop().connect_read_pipe(lambda: protocol, sys.stdin)
        
        writer_transport, writer_protocol = await asyncio.get_event_loop().connect_write_pipe(
            asyncio.streams.FlowControlMixin, sys.stdout
        )
        writer = asyncio.StreamWriter(writer_transport, writer_protocol, reader, asyncio.get_event_loop())
        
        while True:
            try:
                line = await reader.readline()
                if not line:
                    break
                
                request = json.loads(line.decode())
                response = await self._handle_jsonrpc(request)
                
                writer.write((json.dumps(response) + "\n").encode())
                await writer.drain()
                
            except Exception as e:
                logger.exception("Stdio handler error")
                error_response = {
                    "jsonrpc": "2.0",
                    "error": {"code": -32603, "message": str(e)},
                    "id": None
                }
                writer.write((json.dumps(error_response) + "\n").encode())
                await writer.drain()
    
    async def _handle_jsonrpc(self, request: dict) -> dict:
        """Handle JSON-RPC request."""
        method = request.get("method", "")
        params = request.get("params", {})
        request_id = request.get("id")
        
        try:
            if method == "initialize":
                result = await self.handle_initialize(params)
            elif method == "tools/list":
                result = await self.handle_list_tools()
            elif method == "tools/call":
                result = await self.handle_call_tool(params.get("name"), params.get("arguments", {}))
            elif method == "resources/list":
                result = await self.handle_list_resources()
            elif method == "resources/templates/list":
                result = await self.handle_list_resource_templates()
            elif method == "resources/read":
                result = await self.handle_read_resource(params.get("uri", ""))
            elif method == "prompts/list":
                result = await self.handle_list_prompts()
            elif method == "prompts/get":
                result = await self.handle_get_prompt(params.get("name"), params.get("arguments", {}))
            else:
                return {
                    "jsonrpc": "2.0",
                    "error": {"code": -32601, "message": f"Unknown method: {method}"},
                    "id": request_id
                }
            
            return {
                "jsonrpc": "2.0",
                "result": result,
                "id": request_id
            }
            
        except Exception as e:
            logger.exception(f"Method {method} failed")
            return {
                "jsonrpc": "2.0",
                "error": {"code": -32603, "message": str(e)},
                "id": request_id
            }
    
    # =========================================================================
    # Server Lifecycle
    # =========================================================================
    
    async def start(self):
        """Start the MCP server."""
        logger.info(f"Starting MCP Kernel Server on {self.config.host}:{self.config.port}")
    
    async def stop(self):
        """Stop the MCP server."""
        logger.info("Stopping MCP Kernel Server")


# =========================================================================
# Stateless Execution Helper (for direct integration)
# =========================================================================

async def stateless_execute(
    action: str,
    params: dict,
    context: dict,
    config: Optional[dict] = None
) -> dict:
    """
    Execute an action through the kernel statelessly.
    
    This is the core stateless API for June 2026 MCP compliance:
    - All context passed in request
    - No session state maintained
    - Can run on any server instance
    
    Args:
        action: Action to execute (e.g., "database_query")
        params: Action parameters
        context: Full execution context including:
            - agent_id: Identifier for the agent
            - policies: List of policy names to enforce
            - history: Previous interactions (optional)
            - state: External state reference (optional)
        config: Optional server configuration
    
    Returns:
        Execution result with success status and data
    """
    server = KernelMCPServer(ServerConfig(**(config or {})))
    
    tool_args = {
        "action": action,
        "params": params,
        "agent_id": context.get("agent_id", "anonymous"),
        "policies": context.get("policies", []),
        "context": context
    }
    
    result = await server.tools["kernel_execute"].execute(tool_args)
    
    return {
        "success": result.success,
        "data": result.data,
        "error": result.error,
        "metadata": result.metadata
    }
