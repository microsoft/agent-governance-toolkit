# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Integration tests for KernelSpace with PolicyEngine and FlightRecorder.

These tests verify that:
1. PolicyEngine is properly wired to KernelSpace._check_policy()
2. FlightRecorder logs all actions
3. _sys_exec() actually executes tools
4. Policy violations are blocked and logged
"""

import asyncio
import pytest
import tempfile
import os
import sys
from datetime import datetime

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from agent_control_plane.kernel_space import (
    KernelSpace, SyscallRequest, SyscallType, ProtectionRing,
)
from agent_control_plane.policy_engine import PolicyEngine
from agent_control_plane.flight_recorder import FlightRecorder


class TestKernelSpaceIntegration:
    """Integration tests for KernelSpace with all kernel components."""
    
    @pytest.fixture
    def temp_db(self):
        """Create a temporary database for flight recorder."""
        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        yield path
        try:
            os.unlink(path)
        except PermissionError:
            pass  # File may still be in use on Windows
    
    @pytest.fixture
    def flight_recorder(self, temp_db):
        """Create a FlightRecorder instance."""
        recorder = FlightRecorder(db_path=temp_db, enable_batching=False)
        yield recorder
        recorder.close()
    
    @pytest.fixture
    def policy_engine(self):
        """Create a PolicyEngine with test policies."""
        engine = PolicyEngine()
        
        # Add constraints allowing specific tools for test-agent
        # For SYS_EXEC, the actual tool name is checked (not "code_execute")
        # For other syscalls like SYS_CHECKPOLICY, the mapped name is checked
        engine.add_constraint("test-agent", [
            "file_read", "file_write",  # For SYS_READ/SYS_WRITE syscalls
            "echo", "async_echo", "test_tool",  # Specific tools for SYS_EXEC
            "nonexistent_tool",  # For testing unregistered tool error
            "syscall_sys_checkpolicy",  # For SYS_CHECKPOLICY syscall
        ])
        
        return engine
    
    @pytest.fixture
    def kernel_with_policy(self, policy_engine, flight_recorder):
        """Create a KernelSpace with policy engine and flight recorder."""
        return KernelSpace(
            policy_engine=policy_engine,
            flight_recorder=flight_recorder,
        )
    
    @pytest.fixture
    def kernel_without_policy(self):
        """Create a KernelSpace without policy engine (permissive mode)."""
        return KernelSpace()
    
    @pytest.mark.asyncio
    async def test_policy_engine_wired_to_check_policy(self, kernel_with_policy):
        """Verify PolicyEngine is properly wired to _check_policy."""
        ctx = kernel_with_policy.create_agent_context("test-agent")
        
        # Create a request that should be allowed (file_read is in the allow-list)
        allowed_request = SyscallRequest(
            syscall=SyscallType.SYS_READ,
            args={"path": "/home/user/data.txt"},
        )
        
        allowed, error = await kernel_with_policy._check_policy(allowed_request, ctx)
        assert allowed is True
        assert error is None
        
        # Verify metrics increased
        assert kernel_with_policy.metrics.policy_checks >= 1
    
    @pytest.mark.asyncio
    async def test_sys_checkpolicy_uses_policy_engine(self, kernel_with_policy):
        """Verify SYS_CHECKPOLICY syscall uses the policy engine."""
        ctx = kernel_with_policy.create_agent_context("test-agent")
        
        # Check if an allowed action is permitted
        request = SyscallRequest(
            syscall=SyscallType.SYS_CHECKPOLICY,
            args={
                "action": "file_read",
                "target": "/home/user/notes.txt",
                "args": {"path": "/home/user/notes.txt"},
            },
        )
        
        result = await kernel_with_policy.syscall(request, ctx)
        assert result.success is True
        assert "allowed" in result.return_value
    
    @pytest.mark.asyncio
    async def test_sys_exec_executes_registered_tool(self, kernel_with_policy):
        """Verify SYS_EXEC actually executes registered tools."""
        ctx = kernel_with_policy.create_agent_context("test-agent")
        
        # Register a simple tool
        def echo_tool(message: str) -> str:
            return f"Echo: {message}"
        
        kernel_with_policy.register_tool("echo", echo_tool)
        
        # Execute the tool
        request = SyscallRequest(
            syscall=SyscallType.SYS_EXEC,
            args={
                "tool": "echo",
                "args": {"message": "Hello, World!"},
            },
        )
        
        result = await kernel_with_policy.syscall(request, ctx)
        assert result.success is True
        assert result.return_value == "Echo: Hello, World!"
        assert result.execution_time_ms > 0
    
    @pytest.mark.asyncio
    async def test_sys_exec_blocks_unregistered_tool(self, kernel_with_policy):
        """Verify SYS_EXEC returns error for unregistered tools."""
        ctx = kernel_with_policy.create_agent_context("test-agent")
        
        request = SyscallRequest(
            syscall=SyscallType.SYS_EXEC,
            args={
                "tool": "nonexistent_tool",
                "args": {},
            },
        )
        
        result = await kernel_with_policy.syscall(request, ctx)
        assert result.success is False
        assert result.error_code == -404
        assert "not registered" in result.error_message
    
    @pytest.mark.asyncio
    async def test_sys_exec_with_async_tool(self, kernel_with_policy):
        """Verify SYS_EXEC handles async tools correctly."""
        ctx = kernel_with_policy.create_agent_context("test-agent")
        
        # Register an async tool
        async def async_echo(message: str, delay: float = 0.01) -> str:
            await asyncio.sleep(delay)
            return f"Async Echo: {message}"
        
        kernel_with_policy.register_tool("async_echo", async_echo)
        
        request = SyscallRequest(
            syscall=SyscallType.SYS_EXEC,
            args={
                "tool": "async_echo",
                "args": {"message": "Async World!", "delay": 0.01},
            },
        )
        
        result = await kernel_with_policy.syscall(request, ctx)
        assert result.success is True
        assert result.return_value == "Async Echo: Async World!"
        assert result.execution_time_ms >= 10  # At least 10ms due to delay
    
    @pytest.mark.asyncio
    async def test_flight_recorder_logs_all_actions(self, kernel_with_policy, flight_recorder):
        """Verify FlightRecorder logs all tool executions."""
        ctx = kernel_with_policy.create_agent_context("test-agent")
        
        # Register a tool
        def test_tool(value: int) -> int:
            return value * 2
        
        kernel_with_policy.register_tool("test_tool", test_tool)
        
        # Execute the tool
        request = SyscallRequest(
            syscall=SyscallType.SYS_EXEC,
            args={
                "tool": "test_tool",
                "args": {"value": 21},
            },
        )
        
        await kernel_with_policy.syscall(request, ctx)
        
        # Check flight recorder
        flight_recorder.flush()
        logs = flight_recorder.query_logs(agent_id="test-agent")
        
        assert len(logs) > 0
        assert logs[0]["tool_name"] == "test_tool"
        assert logs[0]["policy_verdict"] == "allowed"
    
    @pytest.mark.asyncio
    async def test_tool_execution_error_logged(self, kernel_with_policy, flight_recorder):
        """Verify tool execution errors are logged to flight recorder."""
        ctx = kernel_with_policy.create_agent_context("test-agent")
        
        # Register a tool that raises an error
        def failing_tool() -> None:
            raise ValueError("Something went wrong!")
        
        kernel_with_policy.register_tool("failing_tool", failing_tool)
        
        # Add failing_tool to allowed list
        kernel_with_policy._policy_engine.add_constraint("test-agent", [
            "file_read", "file_write", "echo", "async_echo", "test_tool", "failing_tool"
        ])
        
        request = SyscallRequest(
            syscall=SyscallType.SYS_EXEC,
            args={"tool": "failing_tool", "args": {}},
        )
        
        result = await kernel_with_policy.syscall(request, ctx)
        
        assert result.success is False
        assert result.error_code == -500
        assert "ValueError" in result.error_message
        
        # Check flight recorder
        flight_recorder.flush()
        logs = flight_recorder.query_logs(agent_id="test-agent", policy_verdict="error")
        
        assert len(logs) > 0
        assert "Something went wrong" in logs[0]["violation_reason"]
    
    @pytest.mark.asyncio
    async def test_kernel_metrics_track_policy_checks(self, kernel_with_policy):
        """Verify kernel metrics track policy checks and violations."""
        ctx = kernel_with_policy.create_agent_context("metrics-agent")
        
        # Add allowed tools for metrics-agent
        kernel_with_policy._policy_engine.add_constraint("metrics-agent", ["file_read"])
        
        initial_checks = kernel_with_policy.metrics.policy_checks
        
        # Make several syscalls
        for i in range(5):
            request = SyscallRequest(
                syscall=SyscallType.SYS_READ,
                args={"path": f"/data/file{i}.txt"},
            )
            await kernel_with_policy.syscall(request, ctx)
        
        # Verify metrics increased
        assert kernel_with_policy.metrics.policy_checks > initial_checks
    
    @pytest.mark.asyncio
    async def test_permissive_mode_without_policy_engine(self, kernel_without_policy):
        """Verify kernel allows all actions when no policy engine is set."""
        ctx = kernel_without_policy.create_agent_context("permissive-agent")
        
        # Register a tool
        def any_tool(data: str) -> str:
            return f"Processed: {data}"
        
        kernel_without_policy.register_tool("any_tool", any_tool)
        
        # Should execute without policy check
        request = SyscallRequest(
            syscall=SyscallType.SYS_EXEC,
            args={"tool": "any_tool", "args": {"data": "test"}},
        )
        
        result = await kernel_without_policy.syscall(request, ctx)
        assert result.success is True
        assert result.return_value == "Processed: test"
    
    @pytest.mark.asyncio
    async def test_list_and_unregister_tools(self, kernel_with_policy):
        """Verify tool registration, listing, and unregistration."""
        # Register multiple tools
        kernel_with_policy.register_tool("tool_a", lambda: "A")
        kernel_with_policy.register_tool("tool_b", lambda: "B")
        kernel_with_policy.register_tool("tool_c", lambda: "C")
        
        tools = kernel_with_policy.list_tools()
        assert "tool_a" in tools
        assert "tool_b" in tools
        assert "tool_c" in tools
        
        # Unregister one
        result = kernel_with_policy.unregister_tool("tool_b")
        assert result is True
        
        tools = kernel_with_policy.list_tools()
        assert "tool_b" not in tools
        assert "tool_a" in tools
        
        # Try to unregister non-existent
        result = kernel_with_policy.unregister_tool("nonexistent")
        assert result is False
    
    @pytest.mark.asyncio
    async def test_policy_blocks_unauthorized_tool(self, kernel_with_policy):
        """Verify policy blocks tools not in allow-list."""
        from agent_control_plane.signals import AgentKernelPanic
        
        ctx = kernel_with_policy.create_agent_context("restricted-agent")
        
        # restricted-agent has no allowed tools by default
        
        # Register a tool
        kernel_with_policy.register_tool("dangerous_tool", lambda: "danger")
        
        request = SyscallRequest(
            syscall=SyscallType.SYS_EXEC,
            args={"tool": "dangerous_tool", "args": {}},
        )
        
        # Policy violation triggers kernel panic (agent termination)
        with pytest.raises(AgentKernelPanic):
            await kernel_with_policy.syscall(request, ctx)


class TestKernelSpaceWithRealPolicies:
    """Tests with realistic policy configurations."""
    
    @pytest.fixture
    def secure_policy_engine(self):
        """Create a policy engine with realistic security policies."""
        engine = PolicyEngine()
        
        # Add constraints allowing specific tools for secure-agent
        engine.add_constraint("secure-agent", [
            "file_read", "file_write", 
            "syscall_sys_checkpolicy"  # Need to allow checkpolicy syscall
        ])
        
        return engine
    
    @pytest.fixture
    def secure_kernel(self, secure_policy_engine):
        """Create a secure kernel with policy engine."""
        return KernelSpace(policy_engine=secure_policy_engine)
    
    @pytest.mark.asyncio
    async def test_file_read_within_workspace_allowed(self, secure_kernel):
        """Verify file reads are allowed for permitted agent."""
        ctx = secure_kernel.create_agent_context("secure-agent")
        
        request = SyscallRequest(
            syscall=SyscallType.SYS_CHECKPOLICY,
            args={
                "action": "file_read",
                "args": {"path": "/workspace/data/config.json"},
            },
        )
        
        result = await secure_kernel.syscall(request, ctx)
        assert result.success is True
        assert result.return_value["allowed"] is True
    
    @pytest.mark.asyncio
    async def test_unauthorized_tool_blocked(self, secure_kernel):
        """Verify unauthorized tools are blocked by policy."""
        from agent_control_plane.signals import AgentKernelPanic
        
        ctx = secure_kernel.create_agent_context("attacker-agent")
        
        # attacker-agent has no permissions - will trigger kernel panic
        request = SyscallRequest(
            syscall=SyscallType.SYS_CHECKPOLICY,
            args={
                "action": "code_execute",
                "args": {"command": "rm -rf /"},
            },
        )
        
        # Policy violation triggers kernel panic (agent termination)
        with pytest.raises(AgentKernelPanic):
            await secure_kernel.syscall(request, ctx)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
