# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Agent Virtual File System (VFS) - POSIX-style memory abstraction for agents.

This module provides a virtual file system interface for agent memory,
inspired by POSIX VFS but designed for AI agent state management.

Instead of high-level "Semantic Memory" or "Vector Store" abstractions,
this provides a standard POSIX-like interface that can mount ANY backend.

Mount Points:
    /mem/working    - Working memory (current context, scratchpad)
    /mem/episodic   - Episodic memory (past interactions, experiences)
    /mem/semantic   - Semantic memory (facts, knowledge)
    /mem/procedural - Procedural memory (learned skills, patterns)
    /state          - Agent state (checkpoints, snapshots)
    /tools          - Tool interfaces (mounted dynamically)
    /policy         - Policy files (read-only from user-space)

Design Philosophy:
    - Everything is a file (UNIX philosophy)
    - Backends are drivers (Pinecone, Weaviate, Redis = mount points)
    - Kernel controls mount permissions
    - User-space agents see unified interface
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import IntFlag, auto
from pathlib import PurePosixPath
from typing import (
    Any, Dict, List, Optional, Union, Iterator, BinaryIO, TextIO, Callable
)
import io
import json
import logging
import hashlib

logger = logging.getLogger(__name__)


class FileMode(IntFlag):
    """File permission modes (POSIX-style)."""
    NONE = 0
    READ = auto()       # r
    WRITE = auto()      # w
    EXECUTE = auto()    # x (for tools/procedures)
    APPEND = auto()     # a
    
    # Common combinations
    RO = READ
    RW = READ | WRITE
    RWX = READ | WRITE | EXECUTE


class FileType(IntFlag):
    """File types in the VFS."""
    REGULAR = auto()    # Regular data file
    DIRECTORY = auto()  # Directory
    SYMLINK = auto()    # Symbolic link
    DEVICE = auto()     # Device file (backend connection)
    SOCKET = auto()     # IPC socket
    FIFO = auto()       # Named pipe


@dataclass
class INode:
    """
    Index node - metadata for a VFS entry.
    
    Inspired by UNIX inodes but adapted for agent memory.
    """
    path: str
    file_type: FileType
    mode: FileMode
    size: int = 0
    created: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    modified: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    accessed: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    owner: str = "agent"
    group: str = "agents"
    
    # Extended attributes (agent-specific)
    embedding_dim: Optional[int] = None  # For vector entries
    content_hash: Optional[str] = None
    ttl_seconds: Optional[int] = None  # Time-to-live
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "type": self.file_type.name,
            "mode": self.mode.value,
            "size": self.size,
            "created": self.created.isoformat(),
            "modified": self.modified.isoformat(),
            "owner": self.owner,
            "metadata": self.metadata,
        }


@dataclass
class FileDescriptor:
    """Open file descriptor."""
    fd: int
    path: str
    mode: FileMode
    position: int = 0
    inode: Optional[INode] = None


class VFSBackend(ABC):
    """
    Abstract backend driver for VFS mount points.
    
    Implement this to add support for different storage backends:
    - MemoryBackend: In-memory storage (default)
    - RedisBackend: Redis-based persistent storage
    - VectorBackend: Vector database (Pinecone, Weaviate, etc.)
    - SQLBackend: SQL database storage
    """
    
    @abstractmethod
    def read(self, path: str) -> bytes:
        """Read file contents."""
        pass
    
    @abstractmethod
    def write(self, path: str, data: bytes, mode: FileMode = FileMode.WRITE) -> int:
        """Write data to file. Returns bytes written."""
        pass
    
    @abstractmethod
    def delete(self, path: str) -> bool:
        """Delete a file."""
        pass
    
    @abstractmethod
    def exists(self, path: str) -> bool:
        """Check if path exists."""
        pass
    
    @abstractmethod
    def list_dir(self, path: str) -> List[str]:
        """List directory contents."""
        pass
    
    @abstractmethod
    def stat(self, path: str) -> Optional[INode]:
        """Get file metadata."""
        pass
    
    @abstractmethod
    def mkdir(self, path: str) -> bool:
        """Create directory."""
        pass


class MemoryBackend(VFSBackend):
    """
    In-memory VFS backend.
    
    Simple implementation for working memory and testing.
    Data is lost on agent restart (ephemeral by design).
    """
    
    def __init__(self):
        self._files: Dict[str, bytes] = {}
        self._inodes: Dict[str, INode] = {}
        self._dirs: set = {"/"}
    
    def read(self, path: str) -> bytes:
        if path not in self._files:
            raise FileNotFoundError(f"No such file: {path}")
        
        # Update access time
        if path in self._inodes:
            self._inodes[path].accessed = datetime.now(timezone.utc)
        
        return self._files[path]
    
    def write(self, path: str, data: bytes, mode: FileMode = FileMode.WRITE) -> int:
        # Ensure parent directory exists - auto-create if needed
        parent = str(PurePosixPath(path).parent)
        if parent not in self._dirs and parent != path:
            # Auto-create parent directories (like mkdir -p)
            self._mkdir_p(parent)
        
        if mode & FileMode.APPEND and path in self._files:
            self._files[path] += data
        else:
            self._files[path] = data
        
        # Update or create inode
        now = datetime.now(timezone.utc)
        if path in self._inodes:
            self._inodes[path].modified = now
            self._inodes[path].size = len(self._files[path])
            self._inodes[path].content_hash = hashlib.sha256(self._files[path]).hexdigest()[:16]
        else:
            self._inodes[path] = INode(
                path=path,
                file_type=FileType.REGULAR,
                mode=FileMode.RW,
                size=len(data),
                content_hash=hashlib.sha256(data).hexdigest()[:16],
            )
        
        return len(data)
    
    def delete(self, path: str) -> bool:
        if path in self._files:
            del self._files[path]
            if path in self._inodes:
                del self._inodes[path]
            return True
        return False
    
    def exists(self, path: str) -> bool:
        return path in self._files or path in self._dirs
    
    def list_dir(self, path: str) -> List[str]:
        if path not in self._dirs:
            raise NotADirectoryError(f"Not a directory: {path}")
        
        # Find all entries under this directory
        prefix = path.rstrip("/") + "/"
        entries = set()
        
        for p in list(self._files.keys()) + list(self._dirs):
            if p.startswith(prefix):
                # Get the immediate child
                remainder = p[len(prefix):]
                if remainder:
                    child = remainder.split("/")[0]
                    entries.add(child)
        
        return sorted(entries)
    
    def stat(self, path: str) -> Optional[INode]:
        if path in self._inodes:
            return self._inodes[path]
        if path in self._dirs:
            return INode(
                path=path,
                file_type=FileType.DIRECTORY,
                mode=FileMode.RWX,
            )
        return None
    
    def mkdir(self, path: str) -> bool:
        if path in self._dirs:
            return False
        self._dirs.add(path)
        return True
    
    def _mkdir_p(self, path: str) -> None:
        """Create directory and all parent directories (like mkdir -p)."""
        parts = path.strip("/").split("/")
        current = ""
        for part in parts:
            current = current + "/" + part
            if current not in self._dirs:
                self._dirs.add(current)


@dataclass
class MountPoint:
    """A mounted filesystem."""
    path: str
    backend: VFSBackend
    mode: FileMode = FileMode.RW
    read_only: bool = False
    description: str = ""


class AgentVFS:
    """
    Agent Virtual File System.
    
    Provides a unified POSIX-like interface for agent memory,
    with support for multiple backends mounted at different paths.
    
    Example:
        vfs = AgentVFS(agent_id="agent-001")
        
        # Mount backends
        vfs.mount("/mem/working", MemoryBackend())
        vfs.mount("/mem/episodic", RedisBackend(host="localhost"))
        vfs.mount("/mem/semantic", VectorBackend(client=pinecone_client))
        
        # Use like a filesystem
        vfs.write("/mem/working/scratchpad.txt", b"Current task: ...")
        vfs.write("/mem/episodic/2024-01-26/interaction-001.json", data)
        
        # Read back
        data = vfs.read("/mem/working/scratchpad.txt")
    """
    
    # Standard mount points for agents
    STANDARD_MOUNTS = {
        "/mem/working": "Working memory (ephemeral context)",
        "/mem/episodic": "Episodic memory (experiences)",
        "/mem/semantic": "Semantic memory (facts)",
        "/mem/procedural": "Procedural memory (skills)",
        "/state": "Agent state (checkpoints)",
        "/tools": "Tool interfaces",
        "/policy": "Policy files (read-only)",
        "/ipc": "Inter-process communication",
    }
    
    def __init__(self, agent_id: str):
        self.agent_id = agent_id
        self._mounts: Dict[str, MountPoint] = {}
        self._fd_counter = 0
        self._open_files: Dict[int, FileDescriptor] = {}
        
        # Create standard mount points with default memory backend
        self._init_standard_mounts()
    
    def _init_standard_mounts(self) -> None:
        """Initialize standard mount points with memory backend."""
        default_backend = MemoryBackend()
        
        for path, description in self.STANDARD_MOUNTS.items():
            read_only = path == "/policy"  # Policy is read-only from user-space
            self._mounts[path] = MountPoint(
                path=path,
                backend=default_backend,
                mode=FileMode.RO if read_only else FileMode.RW,
                read_only=read_only,
                description=description,
            )
            # Create the directory
            default_backend.mkdir(path)
    
    def mount(
        self,
        path: str,
        backend: VFSBackend,
        mode: FileMode = FileMode.RW,
        read_only: bool = False,
    ) -> None:
        """
        Mount a backend at the specified path.
        
        Args:
            path: Mount point (e.g., "/mem/semantic")
            backend: VFS backend implementation
            mode: Access mode
            read_only: If True, writes are rejected
        """
        logger.info(f"[VFS] Mounting {backend.__class__.__name__} at {path}")
        
        self._mounts[path] = MountPoint(
            path=path,
            backend=backend,
            mode=mode,
            read_only=read_only,
        )
        
        # Ensure mount point directory exists
        backend.mkdir(path)
    
    def unmount(self, path: str) -> bool:
        """Unmount a filesystem."""
        if path in self._mounts:
            logger.info(f"[VFS] Unmounting {path}")
            del self._mounts[path]
            return True
        return False
    
    def _resolve_mount(self, path: str) -> tuple[MountPoint, str]:
        """
        Resolve a path to its mount point and relative path.
        
        Returns (mount_point, relative_path)
        """
        # Find the longest matching mount point
        best_match = None
        best_len = 0
        
        for mount_path in self._mounts:
            if path.startswith(mount_path) and len(mount_path) > best_len:
                best_match = mount_path
                best_len = len(mount_path)
        
        if not best_match:
            raise FileNotFoundError(f"No mount point for path: {path}")
        
        mount = self._mounts[best_match]
        return mount, path
    
    # ========== File Operations ==========
    
    def read(self, path: str) -> bytes:
        """Read file contents."""
        mount, full_path = self._resolve_mount(path)
        return mount.backend.read(full_path)
    
    def read_text(self, path: str, encoding: str = "utf-8") -> str:
        """Read file as text."""
        return self.read(path).decode(encoding)
    
    def read_json(self, path: str) -> Any:
        """Read and parse JSON file."""
        return json.loads(self.read_text(path))
    
    def write(self, path: str, data: Union[bytes, str], mode: FileMode = FileMode.WRITE) -> int:
        """Write data to file."""
        mount, full_path = self._resolve_mount(path)
        
        if mount.read_only:
            raise PermissionError(f"Mount point is read-only: {mount.path}")
        
        if isinstance(data, str):
            data = data.encode("utf-8")
        
        return mount.backend.write(full_path, data, mode)
    
    def write_json(self, path: str, data: Any, indent: int = 2) -> int:
        """Write data as JSON."""
        return self.write(path, json.dumps(data, indent=indent, default=str))
    
    def append(self, path: str, data: Union[bytes, str]) -> int:
        """Append data to file."""
        return self.write(path, data, FileMode.APPEND)
    
    def delete(self, path: str) -> bool:
        """Delete a file."""
        mount, full_path = self._resolve_mount(path)
        
        if mount.read_only:
            raise PermissionError(f"Mount point is read-only: {mount.path}")
        
        return mount.backend.delete(full_path)
    
    def exists(self, path: str) -> bool:
        """Check if path exists."""
        try:
            mount, full_path = self._resolve_mount(path)
            return mount.backend.exists(full_path)
        except FileNotFoundError:
            return False
    
    def stat(self, path: str) -> Optional[INode]:
        """Get file metadata."""
        mount, full_path = self._resolve_mount(path)
        return mount.backend.stat(full_path)
    
    def ls(self, path: str = "/") -> List[str]:
        """List directory contents."""
        mount, full_path = self._resolve_mount(path)
        return mount.backend.list_dir(full_path)
    
    def mkdir(self, path: str) -> bool:
        """Create directory."""
        mount, full_path = self._resolve_mount(path)
        
        if mount.read_only:
            raise PermissionError(f"Mount point is read-only: {mount.path}")
        
        return mount.backend.mkdir(full_path)
    
    # ========== File Descriptor Operations (POSIX-style) ==========
    
    def open(self, path: str, mode: FileMode = FileMode.READ) -> int:
        """
        Open a file and return a file descriptor.
        
        This provides a more traditional POSIX-style interface.
        """
        mount, full_path = self._resolve_mount(path)
        
        if mode & FileMode.WRITE and mount.read_only:
            raise PermissionError(f"Cannot open for writing: {path}")
        
        inode = mount.backend.stat(full_path)
        
        self._fd_counter += 1
        fd = self._fd_counter
        
        self._open_files[fd] = FileDescriptor(
            fd=fd,
            path=full_path,
            mode=mode,
            inode=inode,
        )
        
        return fd
    
    def close(self, fd: int) -> None:
        """Close a file descriptor."""
        if fd in self._open_files:
            del self._open_files[fd]
    
    def fd_read(self, fd: int, size: int = -1) -> bytes:
        """Read from file descriptor."""
        if fd not in self._open_files:
            raise ValueError(f"Invalid file descriptor: {fd}")
        
        desc = self._open_files[fd]
        data = self.read(desc.path)
        
        if size < 0:
            return data[desc.position:]
        
        result = data[desc.position:desc.position + size]
        desc.position += len(result)
        return result
    
    def fd_write(self, fd: int, data: bytes) -> int:
        """Write to file descriptor."""
        if fd not in self._open_files:
            raise ValueError(f"Invalid file descriptor: {fd}")
        
        desc = self._open_files[fd]
        if not (desc.mode & FileMode.WRITE):
            raise PermissionError("File not opened for writing")
        
        return self.write(desc.path, data)
    
    # ========== Memory-Specific Operations ==========
    
    def save_checkpoint(self, checkpoint_id: str, state: Dict[str, Any]) -> str:
        """Save agent state checkpoint."""
        path = f"/state/checkpoints/{checkpoint_id}.json"
        self.write_json(path, {
            "checkpoint_id": checkpoint_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "agent_id": self.agent_id,
            "state": state,
        })
        logger.info(f"[VFS] Saved checkpoint: {checkpoint_id}")
        return path
    
    def load_checkpoint(self, checkpoint_id: str) -> Dict[str, Any]:
        """Load agent state from checkpoint."""
        path = f"/state/checkpoints/{checkpoint_id}.json"
        data = self.read_json(path)
        logger.info(f"[VFS] Loaded checkpoint: {checkpoint_id}")
        return data.get("state", {})
    
    def log_episodic(self, event: Dict[str, Any], event_id: Optional[str] = None) -> str:
        """Log an episodic memory event."""
        if not event_id:
            event_id = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-%f")
        
        path = f"/mem/episodic/{event_id}.json"
        self.write_json(path, {
            "event_id": event_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": event,
        })
        return path
    
    def get_working_memory(self) -> Dict[str, Any]:
        """Get all working memory contents."""
        result = {}
        for name in self.ls("/mem/working"):
            path = f"/mem/working/{name}"
            try:
                if name.endswith(".json"):
                    result[name] = self.read_json(path)
                else:
                    result[name] = self.read_text(path)
            except Exception:
                result[name] = f"<binary: {self.stat(path).size if self.stat(path) else '?'} bytes>"
        return result
    
    def clear_working_memory(self) -> int:
        """Clear working memory. Returns number of files deleted."""
        count = 0
        for name in self.ls("/mem/working"):
            if self.delete(f"/mem/working/{name}"):
                count += 1
        return count
    
    def get_mount_info(self) -> List[Dict[str, Any]]:
        """Get information about all mount points."""
        return [
            {
                "path": mp.path,
                "backend": mp.backend.__class__.__name__,
                "mode": mp.mode.name,
                "read_only": mp.read_only,
                "description": mp.description or self.STANDARD_MOUNTS.get(mp.path, ""),
            }
            for mp in self._mounts.values()
        ]


# ========== Backend Implementations ==========

class VectorBackend(VFSBackend):
    """
    Vector database backend stub.
    
    This is a placeholder for vector store integration.
    Implement with actual Pinecone/Weaviate/Qdrant client.
    """
    
    def __init__(self, client: Any = None, namespace: str = "default"):
        self.client = client
        self.namespace = namespace
        self._fallback = MemoryBackend()  # Fallback for non-vector operations
        logger.info(f"[VectorBackend] Initialized with namespace: {namespace}")
    
    def read(self, path: str) -> bytes:
        # For vector stores, reading returns the stored document
        return self._fallback.read(path)
    
    def write(self, path: str, data: bytes, mode: FileMode = FileMode.WRITE) -> int:
        # For vector stores, this would upsert to the index
        # Actual implementation would embed and store
        return self._fallback.write(path, data, mode)
    
    def delete(self, path: str) -> bool:
        return self._fallback.delete(path)
    
    def exists(self, path: str) -> bool:
        return self._fallback.exists(path)
    
    def list_dir(self, path: str) -> List[str]:
        return self._fallback.list_dir(path)
    
    def stat(self, path: str) -> Optional[INode]:
        return self._fallback.stat(path)
    
    def mkdir(self, path: str) -> bool:
        return self._fallback.mkdir(path)
    
    # Vector-specific methods
    def search(
        self,
        query_vector: List[float],
        top_k: int = 10,
        filter_dict: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Search for similar vectors.
        
        Override with actual vector search implementation.
        """
        logger.warning("[VectorBackend] search() not implemented - using stub")
        return []
    
    def embed_and_store(
        self,
        path: str,
        text: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Embed text and store in vector database.
        
        Override with actual embedding implementation.
        """
        logger.warning("[VectorBackend] embed_and_store() not implemented - using stub")
        return self._fallback.write(path, text.encode("utf-8"))


# ========== Convenience Functions ==========

def create_agent_vfs(
    agent_id: str,
    working_backend: Optional[VFSBackend] = None,
    episodic_backend: Optional[VFSBackend] = None,
    semantic_backend: Optional[VFSBackend] = None,
) -> AgentVFS:
    """
    Create an AgentVFS with optional custom backends.
    
    Args:
        agent_id: Unique agent identifier
        working_backend: Backend for /mem/working (default: MemoryBackend)
        episodic_backend: Backend for /mem/episodic (default: MemoryBackend)
        semantic_backend: Backend for /mem/semantic (default: MemoryBackend)
    
    Returns:
        Configured AgentVFS instance
    """
    vfs = AgentVFS(agent_id)
    
    if working_backend:
        vfs.mount("/mem/working", working_backend)
    
    if episodic_backend:
        vfs.mount("/mem/episodic", episodic_backend)
    
    if semantic_backend:
        vfs.mount("/mem/semantic", semantic_backend)
    
    return vfs
