# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Safe File Reader Tool.

Provides read-only file access with security controls:
- Path sandboxing (only read from allowed directories)
- No directory traversal (../ blocked)
- File size limits
- Extension filtering
- No symbolic link following outside sandbox
"""

import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from atr.decorator import tool


class FileReaderTool:
    """
    Safe file reader with path sandboxing.
    
    Features:
    - Read-only operations only
    - Sandbox path enforcement (can't read outside allowed dirs)
    - Directory traversal prevention
    - File size limits
    - Extension whitelisting
    - Symlink safety
    
    Example:
        ```python
        reader = FileReaderTool(
            sandbox_paths=["/data/docs", "/data/configs"],
            allowed_extensions=[".txt", ".json", ".yaml", ".md"],
            max_file_size=1_000_000  # 1MB
        )
        
        # Register with ATR
        registry.register(reader.read_file)
        registry.register(reader.list_directory)
        
        # Use from agent
        content = reader.read_file("/data/docs/readme.txt")
        ```
    """
    
    def __init__(
        self,
        sandbox_paths: Optional[List[str]] = None,
        allowed_extensions: Optional[List[str]] = None,
        blocked_extensions: Optional[List[str]] = None,
        max_file_size: int = 10_000_000,  # 10MB
        follow_symlinks: bool = False,
        encoding: str = "utf-8"
    ):
        """
        Initialize file reader tool.
        
        Args:
            sandbox_paths: List of allowed directory paths
            allowed_extensions: Whitelist of file extensions (e.g., [".txt", ".json"])
            blocked_extensions: Blacklist of extensions (e.g., [".exe", ".sh"])
            max_file_size: Maximum file size to read in bytes
            follow_symlinks: Whether to follow symbolic links
            encoding: Default file encoding
        """
        self.sandbox_paths: List[Path] = [
            Path(p).resolve() for p in (sandbox_paths or [os.getcwd()])
        ]
        self.allowed_extensions: Optional[Set[str]] = (
            set(ext.lower() for ext in allowed_extensions) if allowed_extensions else None
        )
        self.blocked_extensions: Set[str] = set(
            ext.lower() for ext in (blocked_extensions or [
                ".exe", ".dll", ".so", ".dylib",
                ".sh", ".bash", ".zsh", ".fish",
                ".bat", ".cmd", ".ps1",
                ".py", ".pyc", ".pyo",
                ".class", ".jar",
            ])
        )
        self.max_file_size = max_file_size
        self.follow_symlinks = follow_symlinks
        self.encoding = encoding
    
    def _validate_path(self, path: str) -> Path:
        """Validate path is within sandbox and safe to access."""
        # Convert to Path and resolve
        file_path = Path(path)
        
        # Don't resolve symlinks if not allowed
        if self.follow_symlinks:
            resolved = file_path.resolve()
        else:
            # Resolve parent but not the file itself if it's a symlink
            resolved = file_path.parent.resolve() / file_path.name
            if file_path.is_symlink():
                raise ValueError(f"Symbolic links not allowed: {path}")
        
        # Check for directory traversal attempts
        path_str = str(path)
        if ".." in path_str:
            raise ValueError(f"Directory traversal not allowed: {path}")
        
        # Check if within sandbox
        in_sandbox = False
        for sandbox in self.sandbox_paths:
            try:
                resolved.relative_to(sandbox)
                in_sandbox = True
                break
            except ValueError:
                continue
        
        if not in_sandbox:
            raise ValueError(
                f"Path '{path}' is outside allowed directories. "
                f"Allowed: {[str(p) for p in self.sandbox_paths]}"
            )
        
        return resolved
    
    def _validate_extension(self, path: Path):
        """Validate file extension."""
        ext = path.suffix.lower()
        
        # Check blocked extensions
        if ext in self.blocked_extensions:
            raise ValueError(f"File extension '{ext}' is blocked")
        
        # Check allowed extensions (if whitelist set)
        if self.allowed_extensions and ext not in self.allowed_extensions:
            raise ValueError(
                f"File extension '{ext}' not allowed. "
                f"Allowed: {', '.join(sorted(self.allowed_extensions))}"
            )
    
    @tool(
        name="read_file",
        description="Read the contents of a text file",
        tags=["file", "read", "safe"]
    )
    def read_file(
        self,
        path: str,
        encoding: Optional[str] = None,
        max_lines: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Read a file's contents.
        
        Args:
            path: Path to file (must be within sandbox)
            encoding: File encoding (default: utf-8)
            max_lines: Maximum number of lines to read
        
        Returns:
            Dict with content, size, and metadata
        """
        # Validate path
        file_path = self._validate_path(path)
        self._validate_extension(file_path)
        
        # Check file exists
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {path}")
        
        if not file_path.is_file():
            raise ValueError(f"Path is not a file: {path}")
        
        # Check file size
        file_size = file_path.stat().st_size
        if file_size > self.max_file_size:
            raise ValueError(
                f"File too large: {file_size} bytes. "
                f"Maximum: {self.max_file_size} bytes"
            )
        
        # Read file
        enc = encoding or self.encoding
        try:
            content = file_path.read_text(encoding=enc)
        except UnicodeDecodeError:
            raise ValueError(f"Unable to decode file with encoding '{enc}'")
        
        # Apply line limit
        if max_lines:
            lines = content.splitlines(keepends=True)
            if len(lines) > max_lines:
                content = "".join(lines[:max_lines])
                content += f"\n... [truncated, showing {max_lines} of {len(lines)} lines]"
        
        return {
            "content": content,
            "size": file_size,
            "path": str(file_path),
            "encoding": enc,
            "lines": content.count("\n") + 1
        }
    
    @tool(
        name="read_file_lines",
        description="Read specific lines from a file",
        tags=["file", "read", "safe"]
    )
    def read_lines(
        self,
        path: str,
        start_line: int = 1,
        end_line: Optional[int] = None,
        encoding: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Read specific lines from a file.
        
        Args:
            path: Path to file
            start_line: First line to read (1-indexed)
            end_line: Last line to read (inclusive, None for end of file)
            encoding: File encoding
        
        Returns:
            Dict with lines, content, and metadata
        """
        file_path = self._validate_path(path)
        self._validate_extension(file_path)
        
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {path}")
        
        if start_line < 1:
            raise ValueError("start_line must be >= 1")
        
        enc = encoding or self.encoding
        lines = file_path.read_text(encoding=enc).splitlines()
        
        # Adjust for 0-indexing
        start_idx = start_line - 1
        end_idx = end_line if end_line else len(lines)
        
        selected = lines[start_idx:end_idx]
        
        return {
            "lines": selected,
            "content": "\n".join(selected),
            "start_line": start_line,
            "end_line": min(end_idx, len(lines)),
            "total_lines": len(lines),
            "path": str(file_path)
        }
    
    @tool(
        name="list_directory",
        description="List files and directories in a path",
        tags=["file", "directory", "safe"]
    )
    def list_directory(
        self,
        path: str,
        pattern: str = "*",
        recursive: bool = False,
        include_hidden: bool = False
    ) -> Dict[str, Any]:
        """
        List directory contents.
        
        Args:
            path: Directory path
            pattern: Glob pattern (e.g., "*.txt")
            recursive: Whether to search recursively
            include_hidden: Include hidden files (starting with .)
        
        Returns:
            Dict with files, directories, and counts
        """
        dir_path = self._validate_path(path)
        
        if not dir_path.exists():
            raise FileNotFoundError(f"Directory not found: {path}")
        
        if not dir_path.is_dir():
            raise ValueError(f"Path is not a directory: {path}")
        
        # List contents
        if recursive:
            matches = list(dir_path.rglob(pattern))
        else:
            matches = list(dir_path.glob(pattern))
        
        files = []
        directories = []
        
        for item in matches:
            # Skip hidden files unless requested
            if not include_hidden and item.name.startswith("."):
                continue
            
            # Skip symlinks if not following
            if item.is_symlink() and not self.follow_symlinks:
                continue
            
            rel_path = str(item.relative_to(dir_path))
            
            if item.is_file():
                files.append({
                    "name": item.name,
                    "path": rel_path,
                    "size": item.stat().st_size,
                    "extension": item.suffix
                })
            elif item.is_dir():
                directories.append({
                    "name": item.name,
                    "path": rel_path
                })
        
        return {
            "path": str(dir_path),
            "files": files,
            "directories": directories,
            "file_count": len(files),
            "directory_count": len(directories)
        }
    
    @tool(
        name="file_exists",
        description="Check if a file or directory exists",
        tags=["file", "check", "safe"]
    )
    def exists(self, path: str) -> Dict[str, Any]:
        """
        Check if path exists.
        
        Args:
            path: Path to check
        
        Returns:
            Dict with exists, is_file, is_dir
        """
        try:
            file_path = self._validate_path(path)
            return {
                "exists": file_path.exists(),
                "is_file": file_path.is_file(),
                "is_directory": file_path.is_dir(),
                "path": str(file_path)
            }
        except ValueError:
            # Path outside sandbox
            return {
                "exists": False,
                "is_file": False,
                "is_directory": False,
                "path": path,
                "error": "Path outside allowed directories"
            }
    
    @tool(
        name="file_info",
        description="Get metadata about a file",
        tags=["file", "metadata", "safe"]
    )
    def file_info(self, path: str) -> Dict[str, Any]:
        """
        Get file metadata.
        
        Args:
            path: Path to file
        
        Returns:
            Dict with size, modified time, etc.
        """
        file_path = self._validate_path(path)
        
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {path}")
        
        stat = file_path.stat()
        
        return {
            "path": str(file_path),
            "name": file_path.name,
            "extension": file_path.suffix,
            "size": stat.st_size,
            "size_human": self._human_size(stat.st_size),
            "modified": stat.st_mtime,
            "created": stat.st_ctime,
            "is_file": file_path.is_file(),
            "is_directory": file_path.is_dir(),
            "is_symlink": file_path.is_symlink()
        }
    
    def _human_size(self, size: int) -> str:
        """Convert bytes to human readable string."""
        for unit in ["B", "KB", "MB", "GB"]:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} TB"
