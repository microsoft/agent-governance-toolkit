# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Virtual File System module for Context-as-a-Service.

Provides a lightweight in-memory file system that maintains project state
shared across multiple SDLC agents, allowing agents to see each other's edits.
"""

from caas.vfs.filesystem import VirtualFileSystem

__all__ = [
    "VirtualFileSystem",
]
