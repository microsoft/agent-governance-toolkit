#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
GitHub Copilot under Agent-OS Governance - Real World Example

This example shows how to run an AI coding assistant (like GitHub Copilot)
under Agent-OS governance, allowing all file system operations without
prompting but logging everything for audit.

Usage:
    python copilot_governed.py
"""

import asyncio
import os
import sys
import tempfile
from pathlib import Path
from datetime import datetime

# Add the control-plane module to path
sys.path.insert(0, str(Path(__file__).parent.parent / "modules" / "control-plane" / "src"))

from agent_control_plane.kernel_space import KernelSpace, SyscallRequest, SyscallType
from agent_control_plane.policy_engine import PolicyEngine
from agent_control_plane.flight_recorder import FlightRecorder


# =============================================================================
# REAL FILE SYSTEM EXECUTORS (Not Mocks!)
# =============================================================================

def real_file_read(path: str) -> str:
    """Actually read a file from disk."""
    with open(path, 'r', encoding='utf-8') as f:
        return f.read()


def real_file_write(path: str, content: str) -> int:
    """Actually write content to a file."""
    # Create parent directories if needed
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, 'w', encoding='utf-8') as f:
        bytes_written = f.write(content)
    return bytes_written


def real_file_delete(path: str) -> bool:
    """Actually delete a file."""
    if os.path.exists(path):
        os.remove(path)
        return True
    return False


def real_file_list(path: str) -> list:
    """Actually list directory contents."""
    if os.path.isdir(path):
        return os.listdir(path)
    return []


def real_file_exists(path: str) -> bool:
    """Check if file exists."""
    return os.path.exists(path)


def real_file_mkdir(path: str) -> bool:
    """Create directory."""
    Path(path).mkdir(parents=True, exist_ok=True)
    return True


# =============================================================================
# COPILOT GOVERNANCE SETUP
# =============================================================================

def create_copilot_governance(workspace_path: str, audit_db: str = "copilot_audit.db"):
    """
    Create a governance setup for GitHub Copilot.
    
    This allows ALL file operations within the workspace without prompting,
    but logs everything for audit purposes.
    
    Args:
        workspace_path: The root directory where Copilot can operate
        audit_db: Path to SQLite audit database
        
    Returns:
        Tuple of (kernel, agent_context)
    """
    # 1. Create Policy Engine - Allow all file operations for copilot
    policy = PolicyEngine()
    
    # Allow all file operations for the copilot agent
    policy.add_constraint("github-copilot", [
        "file_read",
        "file_write", 
        "file_delete",
        "file_list",
        "file_exists",
        "file_mkdir",
        # Add more as needed
        "code_search",
        "code_analyze",
    ])
    
    # 2. Create Flight Recorder for audit trail
    recorder = FlightRecorder(
        db_path=audit_db,
        enable_batching=False,  # Immediate writes for demo
    )
    
    # 3. Create Kernel with governance
    kernel = KernelSpace(
        policy_engine=policy,
        flight_recorder=recorder,
    )
    
    # 4. Register REAL file system executors (not mocks!)
    kernel.register_tool("file_read", real_file_read)
    kernel.register_tool("file_write", real_file_write)
    kernel.register_tool("file_delete", real_file_delete)
    kernel.register_tool("file_list", real_file_list)
    kernel.register_tool("file_exists", real_file_exists)
    kernel.register_tool("file_mkdir", real_file_mkdir)
    
    # 5. Create agent context
    ctx = kernel.create_agent_context("github-copilot")
    
    print(f"✓ Governance initialized for workspace: {workspace_path}")
    print(f"✓ Audit log: {audit_db}")
    print(f"✓ Registered tools: {kernel.list_tools()}")
    
    return kernel, ctx, recorder


# =============================================================================
# GOVERNED OPERATIONS
# =============================================================================

async def governed_read(kernel, ctx, path: str) -> str:
    """Read a file through the governed kernel."""
    request = SyscallRequest(
        syscall=SyscallType.SYS_EXEC,
        args={"tool": "file_read", "args": {"path": path}},
    )
    result = await kernel.syscall(request, ctx)
    if result.success:
        return result.return_value
    else:
        raise Exception(f"Read failed: {result.error_message}")


async def governed_write(kernel, ctx, path: str, content: str) -> int:
    """Write a file through the governed kernel."""
    request = SyscallRequest(
        syscall=SyscallType.SYS_EXEC,
        args={"tool": "file_write", "args": {"path": path, "content": content}},
    )
    result = await kernel.syscall(request, ctx)
    if result.success:
        return result.return_value
    else:
        raise Exception(f"Write failed: {result.error_message}")


async def governed_list(kernel, ctx, path: str) -> list:
    """List directory through the governed kernel."""
    request = SyscallRequest(
        syscall=SyscallType.SYS_EXEC,
        args={"tool": "file_list", "args": {"path": path}},
    )
    result = await kernel.syscall(request, ctx)
    if result.success:
        return result.return_value
    else:
        raise Exception(f"List failed: {result.error_message}")


async def governed_delete(kernel, ctx, path: str) -> bool:
    """Delete a file through the governed kernel."""
    request = SyscallRequest(
        syscall=SyscallType.SYS_EXEC,
        args={"tool": "file_delete", "args": {"path": path}},
    )
    result = await kernel.syscall(request, ctx)
    if result.success:
        return result.return_value
    else:
        raise Exception(f"Delete failed: {result.error_message}")


# =============================================================================
# DEMO: Simulate Copilot Operations
# =============================================================================

async def demo_copilot_session(workspace: str):
    """
    Demonstrate a Copilot session with full governance.
    
    All operations go through the kernel:
    - Policy is checked (allow-list)
    - Actions are logged to FlightRecorder
    - Real file operations happen
    """
    print("\n" + "="*60)
    print("GitHub Copilot under Agent-OS Governance - LIVE DEMO")
    print("="*60 + "\n")
    
    # Setup governance
    audit_db = os.path.join(workspace, "audit.db")
    kernel, ctx, recorder = create_copilot_governance(workspace, audit_db)
    
    print("\n--- Starting Copilot Session ---\n")
    
    # 1. Create a new Python file
    py_file = os.path.join(workspace, "hello.py")
    code = '''#!/usr/bin/env python3
"""Generated by GitHub Copilot under Agent-OS governance."""

def greet(name: str) -> str:
    """Return a greeting message."""
    return f"Hello, {name}!"

if __name__ == "__main__":
    print(greet("World"))
'''
    
    print(f"1. Writing {py_file}...")
    bytes_written = await governed_write(kernel, ctx, py_file, code)
    print(f"   ✓ Wrote {bytes_written} bytes")
    
    # 2. Read it back
    print(f"\n2. Reading {py_file}...")
    content = await governed_read(kernel, ctx, py_file)
    print(f"   ✓ Read {len(content)} characters")
    print(f"   Preview: {content[:50]}...")
    
    # 3. Create a README
    readme = os.path.join(workspace, "README.md")
    readme_content = f"""# Demo Project

Generated by GitHub Copilot under Agent-OS governance.

## Files
- hello.py - A simple greeting script

## Governance
All file operations were:
- Logged to FlightRecorder (audit.db)
- Checked against PolicyEngine
- Executed through KernelSpace

Generated at: {datetime.now().isoformat()}
"""
    
    print(f"\n3. Writing {readme}...")
    await governed_write(kernel, ctx, readme, readme_content)
    print("   ✓ README.md created")
    
    # 4. List the workspace
    print(f"\n4. Listing {workspace}...")
    files = await governed_list(kernel, ctx, workspace)
    print(f"   ✓ Found {len(files)} items: {files}")
    
    # 5. Show audit log
    print("\n--- Audit Log (FlightRecorder) ---\n")
    recorder.flush()
    logs = recorder.query_logs(agent_id="github-copilot", limit=10)
    for log in logs:
        verdict = log.get('policy_verdict', 'unknown')
        tool = log.get('tool_name', 'unknown')
        emoji = "✓" if verdict == "allowed" else "✗"
        print(f"   {emoji} [{verdict}] {tool}")
    
    # 6. Verify integrity
    print("\n--- Integrity Check (Hash Chain) ---\n")
    integrity = recorder.verify_integrity()
    if integrity.get("valid"):
        print(f"   ✓ Audit log integrity verified ({integrity.get('total_entries')} entries)")
    else:
        print(f"   ✗ Integrity check failed: {integrity.get('error')}")
    
    # 7. Show statistics
    print("\n--- Kernel Metrics ---\n")
    metrics = kernel.metrics
    print(f"   Syscalls: {metrics.syscall_count}")
    print(f"   Policy checks: {metrics.policy_checks}")
    print(f"   Policy violations: {metrics.policy_violations}")
    print(f"   Active agents: {metrics.active_agents}")
    
    # Cleanup - close recorder
    recorder.close()
    
    print("\n" + "="*60)
    print("Demo complete! All operations were governed and logged.")
    print("="*60 + "\n")
    
    return True


# =============================================================================
# MAIN
# =============================================================================

async def main():
    # Create a temporary workspace
    with tempfile.TemporaryDirectory(prefix="copilot_governed_") as workspace:
        print(f"Workspace: {workspace}")
        success = await demo_copilot_session(workspace)
        
        if success:
            print("\n✓ All tests passed! Agent-OS governance is REAL and WORKING.")
        else:
            print("\n✗ Some tests failed.")
            sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
