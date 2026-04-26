# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Tests for Virtual File System functionality.
"""

import pytest
from datetime import datetime

from caas import VirtualFileSystem, FileType
from caas.models import FileNode, FileEdit


def test_vfs_initialization():
    """Test VFS initialization."""
    vfs = VirtualFileSystem()
    assert vfs.root_path == "/"
    assert "/" in vfs.files
    assert vfs.files["/"].file_type == FileType.DIRECTORY


def test_create_file():
    """Test file creation."""
    vfs = VirtualFileSystem()
    
    # Create a file
    file_node = vfs.create_file(
        path="/project/main.py",
        content="print('hello world')",
        agent_id="agent-1",
        metadata={"language": "python"}
    )
    
    assert file_node.path == "/project/main.py"
    assert file_node.content == "print('hello world')"
    assert file_node.file_type == FileType.FILE
    assert file_node.created_by == "agent-1"
    assert file_node.metadata["language"] == "python"
    assert len(file_node.edit_history) == 1
    
    # Verify parent directory was created
    assert "/project" in vfs.files
    assert vfs.files["/project"].file_type == FileType.DIRECTORY


def test_create_file_duplicate():
    """Test that creating a duplicate file raises an error."""
    vfs = VirtualFileSystem()
    
    vfs.create_file("/test.txt", "content", "agent-1")
    
    with pytest.raises(ValueError, match="File already exists"):
        vfs.create_file("/test.txt", "other content", "agent-1")


def test_read_file():
    """Test file reading."""
    vfs = VirtualFileSystem()
    
    vfs.create_file("/readme.md", "# Project", "agent-1")
    
    content = vfs.read_file("/readme.md")
    assert content == "# Project"


def test_read_file_not_found():
    """Test reading non-existent file."""
    vfs = VirtualFileSystem()
    
    with pytest.raises(FileNotFoundError):
        vfs.read_file("/nonexistent.txt")


def test_read_directory_error():
    """Test that reading a directory raises an error."""
    vfs = VirtualFileSystem()
    
    with pytest.raises(ValueError, match="Cannot read directory"):
        vfs.read_file("/")


def test_update_file():
    """Test file update."""
    vfs = VirtualFileSystem()
    
    # Create file
    vfs.create_file("/code.js", "var x = 1;", "agent-1")
    
    # Update file
    file_node = vfs.update_file(
        path="/code.js",
        content="const x = 1;",
        agent_id="agent-2",
        message="Use const instead of var"
    )
    
    assert file_node.content == "const x = 1;"
    assert file_node.modified_by == "agent-2"
    assert len(file_node.edit_history) == 2
    assert file_node.edit_history[1].message == "Use const instead of var"


def test_update_file_not_found():
    """Test updating non-existent file."""
    vfs = VirtualFileSystem()
    
    with pytest.raises(FileNotFoundError):
        vfs.update_file("/nonexistent.txt", "content", "agent-1")


def test_delete_file():
    """Test file deletion."""
    vfs = VirtualFileSystem()
    
    vfs.create_file("/temp.txt", "temporary", "agent-1")
    assert "/temp.txt" in vfs.files
    
    result = vfs.delete_file("/temp.txt", "agent-1")
    assert result is True
    assert "/temp.txt" not in vfs.files


def test_delete_file_not_found():
    """Test deleting non-existent file."""
    vfs = VirtualFileSystem()
    
    with pytest.raises(FileNotFoundError):
        vfs.delete_file("/nonexistent.txt", "agent-1")


def test_delete_non_empty_directory():
    """Test that deleting non-empty directory fails."""
    vfs = VirtualFileSystem()
    
    vfs.create_file("/project/file.txt", "content", "agent-1")
    
    with pytest.raises(ValueError, match="Cannot delete non-empty directory"):
        vfs.delete_file("/project", "agent-1")


def test_list_files():
    """Test file listing."""
    vfs = VirtualFileSystem()
    
    vfs.create_file("/project/main.py", "code", "agent-1")
    vfs.create_file("/project/utils.py", "utils", "agent-1")
    vfs.create_file("/project/tests/test_main.py", "tests", "agent-1")
    
    # List files in /project (non-recursive)
    result = vfs.list_files("/project", recursive=False)
    
    assert result.total_count == 3  # main.py, utils.py, tests/
    paths = [f.path for f in result.files]
    assert "/project/main.py" in paths
    assert "/project/utils.py" in paths
    assert "/project/tests" in paths


def test_list_files_recursive():
    """Test recursive file listing."""
    vfs = VirtualFileSystem()
    
    vfs.create_file("/project/main.py", "code", "agent-1")
    vfs.create_file("/project/src/utils.py", "utils", "agent-1")
    vfs.create_file("/project/src/lib/helpers.py", "helpers", "agent-1")
    
    # List files recursively
    result = vfs.list_files("/project", recursive=True)
    
    assert result.total_count >= 3
    paths = [f.path for f in result.files]
    assert "/project/main.py" in paths
    assert "/project/src/utils.py" in paths
    assert "/project/src/lib/helpers.py" in paths


def test_get_file_info():
    """Test getting file information."""
    vfs = VirtualFileSystem()
    
    vfs.create_file("/info.txt", "content", "agent-1")
    
    info = vfs.get_file_info("/info.txt")
    
    assert info.path == "/info.txt"
    assert info.file_type == FileType.FILE
    assert info.content == "content"
    assert info.created_by == "agent-1"
    assert info.edit_count == 1


def test_get_file_history():
    """Test getting file edit history."""
    vfs = VirtualFileSystem()
    
    # Create and update file multiple times
    vfs.create_file("/history.txt", "v1", "agent-1")
    vfs.update_file("/history.txt", "v2", "agent-1", "Update to v2")
    vfs.update_file("/history.txt", "v3", "agent-2", "Update to v3")
    
    history = vfs.get_file_history("/history.txt")
    
    assert len(history) == 3
    assert history[0].content == "v1"
    assert history[0].agent_id == "agent-1"
    assert history[1].content == "v2"
    assert history[1].message == "Update to v2"
    assert history[2].content == "v3"
    assert history[2].agent_id == "agent-2"


def test_multi_agent_collaboration():
    """Test multiple agents working on shared files."""
    vfs = VirtualFileSystem()
    
    # Agent 1 creates a file
    vfs.create_file("/shared/doc.md", "# Title\n", "agent-1")
    
    # Agent 2 reads and updates
    content = vfs.read_file("/shared/doc.md")
    assert content == "# Title\n"
    
    vfs.update_file("/shared/doc.md", "# Title\n\n## Section 1\n", "agent-2")
    
    # Agent 3 reads and updates
    content = vfs.read_file("/shared/doc.md")
    assert "Section 1" in content
    
    vfs.update_file(
        "/shared/doc.md",
        "# Title\n\n## Section 1\n\n## Section 2\n",
        "agent-3"
    )
    
    # Verify history shows all three agents
    history = vfs.get_file_history("/shared/doc.md")
    assert len(history) == 3
    assert history[0].agent_id == "agent-1"
    assert history[1].agent_id == "agent-2"
    assert history[2].agent_id == "agent-3"
    
    # Verify final content is visible to all agents
    final_content = vfs.read_file("/shared/doc.md")
    assert "Section 1" in final_content
    assert "Section 2" in final_content


def test_path_normalization():
    """Test that paths are normalized correctly."""
    vfs = VirtualFileSystem()
    
    # Create with various path formats
    vfs.create_file("project/file.txt", "content", "agent-1")
    vfs.create_file("/project//subdir///file2.txt", "content2", "agent-1")
    
    # All should be normalized
    assert "/project/file.txt" in vfs.files
    assert "/project/subdir/file2.txt" in vfs.files
    
    # Read with unnormalized paths
    content = vfs.read_file("project/file.txt")
    assert content == "content"
    
    content2 = vfs.read_file("//project//subdir/file2.txt")
    assert content2 == "content2"


def test_get_state():
    """Test getting VFS state."""
    vfs = VirtualFileSystem()
    
    vfs.create_file("/file1.txt", "content1", "agent-1")
    vfs.create_file("/file2.txt", "content2", "agent-2")
    
    state = vfs.get_state()
    
    assert state.root_path == "/"
    assert len(state.files) >= 3  # root + 2 files
    assert "/file1.txt" in state.files
    assert "/file2.txt" in state.files


def test_vfs_isolation():
    """Test that separate VFS instances are isolated."""
    vfs1 = VirtualFileSystem()
    vfs2 = VirtualFileSystem()
    
    vfs1.create_file("/vfs1.txt", "content1", "agent-1")
    vfs2.create_file("/vfs2.txt", "content2", "agent-2")
    
    # Each VFS should only see its own files
    assert "/vfs1.txt" in vfs1.files
    assert "/vfs1.txt" not in vfs2.files
    
    assert "/vfs2.txt" in vfs2.files
    assert "/vfs2.txt" not in vfs1.files


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
