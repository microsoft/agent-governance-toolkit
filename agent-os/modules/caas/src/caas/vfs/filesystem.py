# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Virtual File System implementation.

A lightweight in-memory file system that maintains project state and allows
multiple agents to share and see each other's file edits.
"""

import json
from datetime import datetime, timezone
from pathlib import Path as PathLib
from typing import Dict, List, Optional, Set

from caas.models import (
    FileNode,
    FileType,
    FileEdit,
    VFSState,
    FileResponse,
    FileListResponse,
)


class VirtualFileSystem:
    """
    Lightweight in-memory virtual file system for SDLC agents.
    
    Features:
    - In-memory file storage with dict-based tree structure
    - Version history tracking for all file edits
    - Multi-agent support with agent ID tracking
    - CRUD operations: create, read, update, delete
    - Directory support with recursive operations
    
    Example:
        >>> vfs = VirtualFileSystem()
        >>> vfs.create_file("/project/main.py", "print('hello')", "agent-1")
        >>> content = vfs.read_file("/project/main.py")
        >>> vfs.update_file("/project/main.py", "print('world')", "agent-2")
        >>> history = vfs.get_file_history("/project/main.py")
    """
    
    def __init__(self, root_path: str = "/", storage_path: Optional[str] = None):
        """
        Initialize the virtual file system.
        
        Args:
            root_path: Root path for the file system (default: "/")
            storage_path: Optional path for persistent storage
        """
        self.root_path = root_path
        self.storage_path = storage_path
        self.files: Dict[str, FileNode] = {}
        
        # Create root directory
        self._ensure_directory("/")
        
        # Load from disk if storage path exists
        if self.storage_path:
            self._load_from_disk()
    
    def _normalize_path(self, path: str) -> str:
        """Normalize a file path."""
        # Remove duplicate slashes and ensure leading slash
        normalized = "/" + path.strip("/")
        # Normalize to remove .. and . components
        parts = []
        for part in normalized.split("/"):
            if part == "..":
                if parts:
                    parts.pop()
            elif part and part != ".":
                parts.append(part)
        
        result = "/" + "/".join(parts) if parts else "/"
        return result
    
    def _ensure_directory(self, path: str):
        """Ensure a directory exists in the file system."""
        normalized = self._normalize_path(path)
        
        if normalized not in self.files:
            now = datetime.now(timezone.utc).isoformat()
            self.files[normalized] = FileNode(
                path=normalized,
                file_type=FileType.DIRECTORY,
                content="",
                created_by="system",
                created_at=now,
                modified_by="system",
                modified_at=now,
            )
    
    def _ensure_parent_directories(self, path: str):
        """Ensure all parent directories exist for a given path."""
        normalized = self._normalize_path(path)
        parts = normalized.strip("/").split("/")
        
        # Create each parent directory
        for i in range(len(parts)):
            if i == 0:
                parent_path = "/"
            else:
                parent_path = "/" + "/".join(parts[:i])
            self._ensure_directory(parent_path)
    
    def create_file(
        self,
        path: str,
        content: str,
        agent_id: str,
        metadata: Optional[Dict] = None,
    ) -> FileNode:
        """
        Create a new file in the file system.
        
        Args:
            path: Path where to create the file
            content: Initial content of the file
            agent_id: ID of the agent creating the file
            metadata: Optional metadata for the file
            
        Returns:
            The created FileNode
            
        Raises:
            ValueError: If file already exists or path is invalid
        """
        normalized = self._normalize_path(path)
        
        if normalized in self.files:
            raise ValueError(f"File already exists: {normalized}")
        
        # Ensure parent directories exist
        self._ensure_parent_directories(normalized)
        
        now = datetime.now(timezone.utc).isoformat()
        
        # Create initial edit record
        initial_edit = FileEdit(
            agent_id=agent_id,
            timestamp=now,
            content=content,
            message="Initial creation",
        )
        
        # Create file node
        file_node = FileNode(
            path=normalized,
            file_type=FileType.FILE,
            content=content,
            metadata=metadata or {},
            created_by=agent_id,
            created_at=now,
            modified_by=agent_id,
            modified_at=now,
            edit_history=[initial_edit],
        )
        
        self.files[normalized] = file_node
        
        if self.storage_path:
            self._save_to_disk()
        
        return file_node
    
    def read_file(self, path: str) -> str:
        """
        Read the content of a file.
        
        Args:
            path: Path of the file to read
            
        Returns:
            The file content
            
        Raises:
            FileNotFoundError: If file doesn't exist
            ValueError: If path is a directory
        """
        normalized = self._normalize_path(path)
        
        if normalized not in self.files:
            raise FileNotFoundError(f"File not found: {normalized}")
        
        file_node = self.files[normalized]
        
        if file_node.file_type == FileType.DIRECTORY:
            raise ValueError(f"Cannot read directory: {normalized}")
        
        return file_node.content
    
    def update_file(
        self,
        path: str,
        content: str,
        agent_id: str,
        message: Optional[str] = None,
    ) -> FileNode:
        """
        Update an existing file.
        
        Args:
            path: Path of the file to update
            content: New content
            agent_id: ID of the agent updating the file
            message: Optional commit-like message
            
        Returns:
            The updated FileNode
            
        Raises:
            FileNotFoundError: If file doesn't exist
            ValueError: If path is a directory
        """
        normalized = self._normalize_path(path)
        
        if normalized not in self.files:
            raise FileNotFoundError(f"File not found: {normalized}")
        
        file_node = self.files[normalized]
        
        if file_node.file_type == FileType.DIRECTORY:
            raise ValueError(f"Cannot update directory: {normalized}")
        
        now = datetime.now(timezone.utc).isoformat()
        
        # Create edit record
        edit = FileEdit(
            agent_id=agent_id,
            timestamp=now,
            content=content,
            message=message,
        )
        
        # Update file node
        file_node.content = content
        file_node.modified_by = agent_id
        file_node.modified_at = now
        file_node.edit_history.append(edit)
        
        if self.storage_path:
            self._save_to_disk()
        
        return file_node
    
    def delete_file(self, path: str, agent_id: str) -> bool:
        """
        Delete a file from the file system.
        
        Args:
            path: Path of the file to delete
            agent_id: ID of the agent deleting the file
            
        Returns:
            True if deleted successfully
            
        Raises:
            FileNotFoundError: If file doesn't exist
        """
        normalized = self._normalize_path(path)
        
        if normalized not in self.files:
            raise FileNotFoundError(f"File not found: {normalized}")
        
        file_node = self.files[normalized]
        
        # If it's a directory, check if it's empty
        if file_node.file_type == FileType.DIRECTORY:
            children = self._get_children(normalized)
            if children:
                raise ValueError(
                    f"Cannot delete non-empty directory: {normalized}. "
                    f"Contains {len(children)} items."
                )
        
        del self.files[normalized]
        
        if self.storage_path:
            self._save_to_disk()
        
        return True
    
    def _get_children(self, directory_path: str) -> List[str]:
        """Get all immediate children of a directory."""
        normalized = self._normalize_path(directory_path)
        children = []
        
        for path in self.files.keys():
            if path == normalized:
                continue
            
            # Check if this path is a child of the directory
            if path.startswith(normalized + "/"):
                relative = path[len(normalized) + 1:]
                # Only immediate children (no subdirectories)
                if "/" not in relative:
                    children.append(path)
        
        return children
    
    def list_files(
        self,
        directory_path: str = "/",
        recursive: bool = False,
    ) -> FileListResponse:
        """
        List files in a directory.
        
        Args:
            directory_path: Path of the directory to list
            recursive: Whether to list recursively
            
        Returns:
            FileListResponse with list of files
            
        Raises:
            FileNotFoundError: If directory doesn't exist
            ValueError: If path is not a directory
        """
        normalized = self._normalize_path(directory_path)
        
        if normalized not in self.files:
            raise FileNotFoundError(f"Directory not found: {normalized}")
        
        dir_node = self.files[normalized]
        if dir_node.file_type != FileType.DIRECTORY:
            raise ValueError(f"Not a directory: {normalized}")
        
        files: List[FileResponse] = []
        
        for path, file_node in self.files.items():
            if path == normalized:
                continue
            
            # Check if this file is in the requested directory
            if recursive:
                # Include all descendants
                is_descendant = path.startswith(normalized + "/")
            else:
                # Include only immediate children
                is_descendant = path.startswith(normalized + "/")
                if is_descendant:
                    relative = path[len(normalized) + 1:]
                    is_descendant = "/" not in relative
            
            if is_descendant:
                files.append(
                    FileResponse(
                        path=file_node.path,
                        file_type=file_node.file_type,
                        content=file_node.content,
                        metadata=file_node.metadata,
                        created_by=file_node.created_by,
                        created_at=file_node.created_at,
                        modified_by=file_node.modified_by,
                        modified_at=file_node.modified_at,
                        edit_count=len(file_node.edit_history),
                    )
                )
        
        return FileListResponse(files=files, total_count=len(files))
    
    def get_file_info(self, path: str) -> FileResponse:
        """
        Get information about a file without reading its content.
        
        Args:
            path: Path of the file
            
        Returns:
            FileResponse with file information
            
        Raises:
            FileNotFoundError: If file doesn't exist
        """
        normalized = self._normalize_path(path)
        
        if normalized not in self.files:
            raise FileNotFoundError(f"File not found: {normalized}")
        
        file_node = self.files[normalized]
        
        return FileResponse(
            path=file_node.path,
            file_type=file_node.file_type,
            content=file_node.content,
            metadata=file_node.metadata,
            created_by=file_node.created_by,
            created_at=file_node.created_at,
            modified_by=file_node.modified_by,
            modified_at=file_node.modified_at,
            edit_count=len(file_node.edit_history),
        )
    
    def get_file_history(self, path: str) -> List[FileEdit]:
        """
        Get the edit history of a file.
        
        Args:
            path: Path of the file
            
        Returns:
            List of FileEdit objects
            
        Raises:
            FileNotFoundError: If file doesn't exist
        """
        normalized = self._normalize_path(path)
        
        if normalized not in self.files:
            raise FileNotFoundError(f"File not found: {normalized}")
        
        file_node = self.files[normalized]
        return file_node.edit_history
    
    def get_state(self) -> VFSState:
        """
        Get the complete file system state.
        
        Returns:
            VFSState object representing the entire file system
        """
        return VFSState(files=self.files, root_path=self.root_path)
    
    def _save_to_disk(self):
        """Save the file system state to disk."""
        if not self.storage_path:
            return
        
        storage_file = PathLib(self.storage_path)
        storage_file.parent.mkdir(parents=True, exist_ok=True)
        
        state = self.get_state()
        with open(storage_file, "w") as f:
            f.write(state.model_dump_json(indent=2))
    
    def _load_from_disk(self):
        """Load the file system state from disk."""
        if not self.storage_path:
            return
        
        storage_file = PathLib(self.storage_path)
        if not storage_file.exists():
            return
        
        with open(storage_file, "r") as f:
            data = json.load(f)
            state = VFSState(**data)
            self.files = state.files
            self.root_path = state.root_path
