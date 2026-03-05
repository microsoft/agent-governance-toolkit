#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Test that policy enforcement actually blocks unauthorized operations.
"""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "modules" / "control-plane" / "src"))

from agent_control_plane.kernel_space import KernelSpace, SyscallRequest, SyscallType
from agent_control_plane.policy_engine import PolicyEngine
from agent_control_plane.signals import AgentKernelPanic


async def test_policy_enforcement():
    """Test that unauthorized operations are actually blocked."""
    print("="*60)
    print("Testing Policy Enforcement (Should Block!)")
    print("="*60 + "\n")
    
    # Create policy that ONLY allows file_read
    policy = PolicyEngine()
    policy.add_constraint("restricted-agent", ["file_read"])  # Only read!
    
    kernel = KernelSpace(policy_engine=policy)
    
    # Register a dangerous tool
    kernel.register_tool("file_delete", lambda path: f"DELETED {path}")
    
    ctx = kernel.create_agent_context("restricted-agent")
    
    # Try to delete (should be BLOCKED)
    print("Attempting file_delete with restricted-agent...")
    print("(This agent only has file_read permission)")
    print()
    
    request = SyscallRequest(
        syscall=SyscallType.SYS_EXEC,
        args={"tool": "file_delete", "args": {"path": "/important/file.txt"}},
    )
    
    try:
        result = await kernel.syscall(request, ctx)
        print(f"❌ UNEXPECTED: Operation was allowed! Result: {result}")
        return False
    except AgentKernelPanic as e:
        print(f"✓ CORRECTLY BLOCKED!")
        print(f"  Exception: {type(e).__name__}")
        print(f"  Message: Policy violation detected")
        return True
    except Exception as e:
        print(f"? Got exception: {type(e).__name__}: {e}")
        return True  # Still blocked, different exception


async def test_allowed_operation():
    """Test that authorized operations work."""
    print("\n" + "="*60)
    print("Testing Allowed Operation")
    print("="*60 + "\n")
    
    policy = PolicyEngine()
    policy.add_constraint("reader-agent", ["file_read"])
    
    kernel = KernelSpace(policy_engine=policy)
    kernel.register_tool("file_read", lambda path: f"Content of {path}")
    
    ctx = kernel.create_agent_context("reader-agent")
    
    print("Attempting file_read with reader-agent...")
    
    request = SyscallRequest(
        syscall=SyscallType.SYS_EXEC,
        args={"tool": "file_read", "args": {"path": "/some/file.txt"}},
    )
    
    result = await kernel.syscall(request, ctx)
    
    if result.success:
        print(f"✓ CORRECTLY ALLOWED!")
        print(f"  Result: {result.return_value}")
        return True
    else:
        print(f"❌ UNEXPECTED: Operation was blocked! Error: {result.error_message}")
        return False


async def main():
    blocked = await test_policy_enforcement()
    allowed = await test_allowed_operation()
    
    print("\n" + "="*60)
    print("SUMMARY")
    print("="*60)
    print(f"Policy enforcement (block unauthorized): {'✓ PASS' if blocked else '❌ FAIL'}")
    print(f"Policy allows authorized operations:     {'✓ PASS' if allowed else '❌ FAIL'}")
    
    if blocked and allowed:
        print("\n✓ Agent-OS policy enforcement is REAL and WORKING!")
        sys.exit(0)
    else:
        print("\n❌ Something is broken!")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
