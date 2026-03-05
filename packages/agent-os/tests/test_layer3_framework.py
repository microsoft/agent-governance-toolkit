# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Test Layer 3: Framework (Control Plane) package.
"""

import pytest


# Check if control plane submodules are installed
try:
    from agent_control_plane import signals
    HAS_SIGNALS = True
except (ImportError, ModuleNotFoundError):
    HAS_SIGNALS = False

try:
    from agent_control_plane import vfs
    HAS_VFS = True
except (ImportError, ModuleNotFoundError):
    HAS_VFS = False

try:
    from agent_control_plane import kernel_space
    HAS_KERNEL_SPACE = True
except (ImportError, ModuleNotFoundError):
    HAS_KERNEL_SPACE = False


@pytest.mark.skipif(not HAS_SIGNALS, reason="agent_control_plane.signals not available")
class TestSignals:
    """Test POSIX-style signal handling."""
    
    def test_import_signals(self):
        """Test importing signal module."""
        from agent_control_plane.signals import (
            AgentSignal,
            SignalDispatcher,
            SignalInfo,
            AgentKernelPanic,
        )
        assert AgentSignal is not None
        assert SignalDispatcher is not None
    
    def test_signal_values(self):
        """Test signal enum values."""
        from agent_control_plane.signals import AgentSignal
        
        assert AgentSignal.SIGSTOP.value == 1
        assert AgentSignal.SIGCONT.value == 2
        assert AgentSignal.SIGINT.value == 3
        assert AgentSignal.SIGKILL.value == 4
        assert AgentSignal.SIGTERM.value == 5
        assert AgentSignal.SIGPOLICY.value == 8
    
    def test_create_signal_dispatcher(self):
        """Test creating a signal dispatcher."""
        from agent_control_plane.signals import SignalDispatcher, AgentSignal
        
        dispatcher = SignalDispatcher(agent_id="test-agent")
        
        assert dispatcher.agent_id == "test-agent"
        assert dispatcher.is_running is True
        assert dispatcher.is_stopped is False
        assert dispatcher.is_terminated is False
    
    def test_sigstop_pauses_agent(self):
        """Test SIGSTOP pauses an agent."""
        from agent_control_plane.signals import SignalDispatcher, AgentSignal
        
        dispatcher = SignalDispatcher(agent_id="test-agent")
        dispatcher.signal(AgentSignal.SIGSTOP, source="test", reason="test pause")
        
        assert dispatcher.is_stopped is True
        assert dispatcher.is_running is False
    
    def test_sigcont_resumes_agent(self):
        """Test SIGCONT resumes a stopped agent."""
        from agent_control_plane.signals import SignalDispatcher, AgentSignal
        
        dispatcher = SignalDispatcher(agent_id="test-agent")
        dispatcher.signal(AgentSignal.SIGSTOP)
        assert dispatcher.is_stopped is True
        
        dispatcher.signal(AgentSignal.SIGCONT)
        assert dispatcher.is_stopped is False
        assert dispatcher.is_running is True
    
    def test_sigkill_terminates_agent(self):
        """Test SIGKILL terminates an agent."""
        from agent_control_plane.signals import (
            SignalDispatcher, AgentSignal, AgentKernelPanic
        )
        
        dispatcher = SignalDispatcher(agent_id="test-agent")
        
        # SIGKILL should set terminated state
        # Note: The exception is caught internally in handler failure
        dispatcher.signal(AgentSignal.SIGKILL, reason="test termination")
        
        # Agent should be terminated after SIGKILL
        assert dispatcher.is_terminated is True
    
    def test_signal_history(self):
        """Test signal history is recorded."""
        from agent_control_plane.signals import SignalDispatcher, AgentSignal
        
        dispatcher = SignalDispatcher(agent_id="test-agent")
        dispatcher.signal(AgentSignal.SIGSTOP)
        dispatcher.signal(AgentSignal.SIGCONT)
        
        history = dispatcher.get_signal_history()
        assert len(history) == 2
        assert history[0]["signal"] == "SIGSTOP"
        assert history[1]["signal"] == "SIGCONT"


@pytest.mark.skipif(not HAS_VFS, reason="agent_control_plane.vfs not available")
class TestVFS:
    """Test Agent Virtual File System."""
    
    def test_import_vfs(self):
        """Test importing VFS module."""
        from agent_control_plane.vfs import (
            AgentVFS,
            VFSBackend,
            MemoryBackend,
            FileMode,
        )
        assert AgentVFS is not None
        assert MemoryBackend is not None
    
    def test_create_agent_vfs(self):
        """Test creating an AgentVFS."""
        from agent_control_plane.vfs import AgentVFS
        
        vfs = AgentVFS(agent_id="test-agent")
        
        assert vfs.agent_id == "test-agent"
        # Should have standard mount points
        mounts = vfs.get_mount_info()
        paths = [m["path"] for m in mounts]
        assert "/mem/working" in paths
        assert "/mem/episodic" in paths
        assert "/state" in paths
        assert "/policy" in paths
    
    def test_vfs_write_read(self):
        """Test writing and reading from VFS."""
        from agent_control_plane.vfs import AgentVFS
        
        vfs = AgentVFS(agent_id="test-agent")
        
        # Write data
        vfs.write("/mem/working/test.txt", "Hello World")
        
        # Read back
        data = vfs.read_text("/mem/working/test.txt")
        assert data == "Hello World"
    
    def test_vfs_json(self):
        """Test JSON operations."""
        from agent_control_plane.vfs import AgentVFS
        
        vfs = AgentVFS(agent_id="test-agent")
        
        # Write JSON
        vfs.write_json("/mem/working/config.json", {"key": "value", "count": 42})
        
        # Read JSON
        data = vfs.read_json("/mem/working/config.json")
        assert data["key"] == "value"
        assert data["count"] == 42
    
    def test_vfs_checkpoint(self):
        """Test checkpoint functionality."""
        from agent_control_plane.vfs import AgentVFS
        
        vfs = AgentVFS(agent_id="test-agent")
        
        # Save checkpoint
        state = {"step": 5, "context": "test"}
        path = vfs.save_checkpoint("checkpoint-001", state)
        
        assert "/state/checkpoints/" in path
        
        # Load checkpoint
        loaded = vfs.load_checkpoint("checkpoint-001")
        assert loaded["step"] == 5
        assert loaded["context"] == "test"
    
    def test_policy_is_readonly(self):
        """Test /policy is read-only from user space."""
        from agent_control_plane.vfs import AgentVFS
        
        vfs = AgentVFS(agent_id="test-agent")
        
        # Writing to /policy should fail
        with pytest.raises(PermissionError):
            vfs.write("/policy/rules.txt", "should fail")


@pytest.mark.skipif(not HAS_KERNEL_SPACE, reason="agent_control_plane.kernel_space not available")
class TestKernelSpace:
    """Test Kernel/User Space separation."""
    
    def test_import_kernel_space(self):
        """Test importing kernel space module."""
        from agent_control_plane.kernel_space import (
            KernelSpace,
            AgentContext,
            ProtectionRing,
            SyscallType,
            KernelState,
        )
        assert KernelSpace is not None
        assert ProtectionRing is not None
    
    def test_protection_rings(self):
        """Test protection ring values."""
        from agent_control_plane.kernel_space import ProtectionRing
        
        assert ProtectionRing.RING_0_KERNEL.value == 0
        assert ProtectionRing.RING_3_USER.value == 3
    
    def test_syscall_types(self):
        """Test syscall types."""
        from agent_control_plane.kernel_space import SyscallType
        
        assert hasattr(SyscallType, 'SYS_READ')
        assert hasattr(SyscallType, 'SYS_WRITE')
        assert hasattr(SyscallType, 'SYS_EXEC')
        assert hasattr(SyscallType, 'SYS_SIGNAL')
    
    def test_create_kernel(self):
        """Test creating a kernel."""
        from agent_control_plane.kernel_space import KernelSpace, KernelState
        
        kernel = KernelSpace()
        
        assert kernel.state == KernelState.RUNNING
    
    def test_create_agent_context(self):
        """Test creating an agent context."""
        from agent_control_plane.kernel_space import (
            KernelSpace, ProtectionRing
        )
        
        kernel = KernelSpace()
        ctx = kernel.create_agent_context("test-agent")
        
        assert ctx.agent_id == "test-agent"
        assert ctx.ring == ProtectionRing.RING_3_USER
    
    @pytest.mark.asyncio
    async def test_syscall_read_write(self):
        """Test syscall read/write operations."""
        from agent_control_plane.kernel_space import KernelSpace
        
        kernel = KernelSpace()
        ctx = kernel.create_agent_context("test-agent")
        
        # Write via syscall
        await ctx.write("/mem/working/data.txt", "test data")
        
        # Read via syscall
        data = await ctx.read("/mem/working/data.txt")
        assert data == b"test data"


class TestControlPlane:
    """Test main Control Plane interface."""
    
    def test_import_control_plane(self):
        """Test importing control plane."""
        from agent_control_plane import (
            AgentControlPlane,
            PolicyEngine,
            ExecutionEngine,
        )
        assert AgentControlPlane is not None
        assert PolicyEngine is not None
    
    def test_create_control_plane(self):
        """Test creating a control plane instance."""
        from agent_control_plane import AgentControlPlane
        
        cp = AgentControlPlane()
        assert cp is not None
