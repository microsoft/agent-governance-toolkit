# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
MCP Kernel Server - Expose Agent OS primitives through Model Context Protocol.

This package provides:
- CMVK verification as MCP tool
- IATP trust signing as MCP tool  
- VFS filesystem as MCP resource
- Governed execution as MCP tool
"""

from mcp_kernel_server.server import KernelMCPServer
from mcp_kernel_server.tools import (
    CMVKVerifyTool,
    KernelExecuteTool,
    IATPSignTool,
)
from mcp_kernel_server.resources import VFSResource

__version__ = "3.1.0"
__all__ = [
    "KernelMCPServer",
    "CMVKVerifyTool",
    "KernelExecuteTool", 
    "IATPSignTool",
    "VFSResource",
]
