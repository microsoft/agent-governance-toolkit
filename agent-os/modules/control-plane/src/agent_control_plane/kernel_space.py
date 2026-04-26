# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""
Kernel Space - Protected core that survives agent crashes.

This module implements the kernel/user space separation for Agent OS.
The kernel space contains critical infrastructure that MUST survive
even when user-space agents crash or hallucinate.

Kernel Space Components:
    - Policy Engine (enforcement)
    - Flight Recorder (audit)
    - Signal Dispatcher (control)
    - VFS Mount Manager (memory)
    - IPC Router (communication)

User Space Components:
    - LLM Generation
    - Tool Execution
    - Agent Logic
    - Custom Handlers

Design Philosophy:
    - Kernel survives agent crashes (isolation)
    - Policy violations trigger kernel panic (0% tolerance)
    - All agent actions pass through kernel syscalls
    - Kernel state is checkpointed independently

Comparison with AIOS:
    AIOS focuses on EFFICIENCY (GPU throughput, scheduling)
    We focus on SAFETY (isolation, policy enforcement, audit)
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, auto
from typing import Any, Callable, Dict, List, Optional, Tuple, TypeVar, Generic, Union
import asyncio
import logging
import traceback
from contextlib import asynccontextmanager

# Import kernel components
from .signals import (
    SignalDispatcher, AgentSignal, SignalInfo, AgentKernelPanic,
    policy_violation, kill_agent, pause_agent
)
from .vfs import AgentVFS, create_agent_vfs

logger = logging.getLogger(__name__)


class ProtectionRing(Enum):
    """
    Protection rings (inspired by x86 architecture).
    
    Ring 0: Kernel - Most privileged (policy, audit, signals)
    Ring 1: Drivers - Backend drivers (VFS backends, tool executors)
    Ring 2: Services - System services (monitoring, health checks)
    Ring 3: User - Agent code (least privileged)
    """
    RING_0_KERNEL = 0
    RING_1_DRIVERS = 1
    RING_2_SERVICES = 2
    RING_3_USER = 3


class SyscallType(Enum):
    """
    System calls that user space can make into kernel.
    
    All agent actions must go through syscalls.
    """
    # Process control
    SYS_FORK = auto()      # Spawn child agent
    SYS_EXIT = auto()      # Terminate self
    SYS_WAIT = auto()      # Wait for child
    SYS_EXEC = auto()      # Execute tool
    
    # File operations (VFS)
    SYS_OPEN = auto()
    SYS_CLOSE = auto()
    SYS_READ = auto()
    SYS_WRITE = auto()
    SYS_STAT = auto()
    
    # Memory operations
    SYS_MMAP = auto()      # Map memory region
    SYS_MUNMAP = auto()    # Unmap memory region
    SYS_BRK = auto()       # Extend heap (context window)
    
    # IPC operations
    SYS_PIPE = auto()      # Create pipe
    SYS_SEND = auto()      # Send message
    SYS_RECV = auto()      # Receive message
    
    # Signal operations
    SYS_SIGNAL = auto()    # Send signal
    SYS_SIGACTION = auto() # Set signal handler
    SYS_SIGPROCMASK = auto()  # Block signals
    
    # Policy operations (read-only from user space)
    SYS_GETPOLICY = auto() # Get policy for action
    SYS_CHECKPOLICY = auto() # Check if action allowed


@dataclass
class SyscallRequest:
    """A system call request from user space."""
    syscall: SyscallType
    args: Dict[str, Any]
    caller_ring: ProtectionRing = ProtectionRing.RING_3_USER
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    trace_id: Optional[str] = None


@dataclass
class SyscallResult:
    """Result of a system call."""
    success: bool
    return_value: Any = None
    error_code: Optional[int] = None
    error_message: Optional[str] = None
    execution_time_ms: float = 0.0


class KernelState(Enum):
    """Kernel operating state."""
    BOOTING = auto()
    RUNNING = auto()
    DEGRADED = auto()  # Some components failed
    PANIC = auto()     # Unrecoverable error
    SHUTDOWN = auto()


@dataclass
class KernelMetrics:
    """Kernel performance metrics."""
    syscall_count: int = 0
    policy_checks: int = 0
    policy_violations: int = 0
    agent_crashes: int = 0
    kernel_panics: int = 0
    uptime_seconds: float = 0.0
    active_agents: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "syscall_count": self.syscall_count,
            "policy_checks": self.policy_checks,
            "policy_violations": self.policy_violations,
            "agent_crashes": int,
            "kernel_panics": self.kernel_panics,
            "uptime_seconds": self.uptime_seconds,
            "active_agents": self.active_agents,
        }


class KernelSpace:
    """The Kernel Space — protected core of Agent OS.

    KernelSpace implements Ring 0, the most privileged execution layer in the
    Agent OS architecture. Inspired by operating system kernel design, it
    provides strict isolation between the trusted kernel and untrusted agent
    (user-space) code.

    Responsibilities:
        - **Policy enforcement**: All agent actions pass through kernel
          syscalls where policies are checked before execution.
        - **Flight recording**: Every syscall is logged to the
          ``FlightRecorder`` for forensic audit and compliance.
        - **Signal management**: Agents communicate through POSIX-style
          signals (``SIGTERM``, ``SIGKILL``, ``SIGPAUSE``, etc.).
        - **VFS management**: Each agent gets an isolated virtual filesystem.
        - **Tool execution**: Tools are registered in the kernel and executed
          through the ``SYS_EXEC`` syscall with full policy governance.

    The kernel SURVIVES agent crashes. If an agent hallucinates, throws an
    exception, or violates policy, the kernel remains stable and can recover
    or terminate the agent.

    Args:
        policy_engine: Optional policy engine for syscall authorization.
            When ``None``, the kernel runs in permissive mode (all syscalls
            allowed).
        flight_recorder: Optional ``FlightRecorder`` instance for audit
            logging. When ``None``, audit logging is disabled.

    Example:
        Basic kernel lifecycle::

            kernel = KernelSpace()

            # Register an agent in user space
            agent_ctx = kernel.create_agent_context("agent-001")

            # Agent makes syscalls through the kernel
            result = await kernel.syscall(SyscallRequest(
                syscall=SyscallType.SYS_WRITE,
                args={"path": "/mem/working/notes.txt", "data": "Hello"},
            ), agent_ctx)

        Using the context manager for automatic isolation::

            async with user_space_execution(kernel, "agent-001") as ctx:
                await ctx.write("/mem/working/task.txt", "Hello World")
    """
    
    def __init__(
        self,
        policy_engine: Optional[Any] = None,
        flight_recorder: Optional[Any] = None,
    ):
        self._state = KernelState.BOOTING
        self._metrics = KernelMetrics()
        self._start_time = datetime.now(timezone.utc)
        
        # Kernel components (Ring 0)
        self._policy_engine = policy_engine
        self._flight_recorder = flight_recorder
        
        # Agent registry
        self._agents: Dict[str, "AgentContext"] = {}
        self._signal_dispatchers: Dict[str, SignalDispatcher] = {}
        self._vfs_instances: Dict[str, AgentVFS] = {}
        
        # Tool registry - maps tool names to callable executors
        self._tool_registry: Dict[str, Callable[..., Any]] = {}
        
        # Syscall handlers
        self._syscall_handlers: Dict[SyscallType, Callable] = {}
        self._init_syscall_handlers()
        
        # Boot complete
        self._state = KernelState.RUNNING
        logger.info("[Kernel] Booted successfully")
    
    def _init_syscall_handlers(self) -> None:
        """Initialize syscall handlers."""
        # File operations
        self._syscall_handlers[SyscallType.SYS_READ] = self._sys_read
        self._syscall_handlers[SyscallType.SYS_WRITE] = self._sys_write
        self._syscall_handlers[SyscallType.SYS_OPEN] = self._sys_open
        self._syscall_handlers[SyscallType.SYS_CLOSE] = self._sys_close
        
        # Signal operations
        self._syscall_handlers[SyscallType.SYS_SIGNAL] = self._sys_signal
        
        # Policy operations
        self._syscall_handlers[SyscallType.SYS_CHECKPOLICY] = self._sys_checkpolicy
        
        # Process operations
        self._syscall_handlers[SyscallType.SYS_EXIT] = self._sys_exit
        self._syscall_handlers[SyscallType.SYS_EXEC] = self._sys_exec
    
    @property
    def state(self) -> KernelState:
        return self._state
    
    @property
    def metrics(self) -> KernelMetrics:
        self._metrics.uptime_seconds = (
            datetime.now(timezone.utc) - self._start_time
        ).total_seconds()
        self._metrics.active_agents = len(self._agents)
        return self._metrics
    
    def create_agent_context(self, agent_id: str) -> "AgentContext":
        """Create a context for an agent in user space.

        Allocates all kernel resources the agent needs — a signal
        dispatcher, VFS instance, and policy context — and registers the
        agent in the kernel's internal registry.

        Args:
            agent_id: Unique string identifier for the agent. Must not
                already be registered with this kernel.

        Returns:
            An ``AgentContext`` bound to this kernel at
            ``ProtectionRing.RING_3_USER``.

        Raises:
            ValueError: If an agent with the given ``agent_id`` is already
                registered.
        """
        if agent_id in self._agents:
            raise ValueError(f"Agent {agent_id} already registered")
        
        # Create kernel resources for this agent
        signal_dispatcher = SignalDispatcher(agent_id)
        vfs = create_agent_vfs(agent_id)
        
        self._signal_dispatchers[agent_id] = signal_dispatcher
        self._vfs_instances[agent_id] = vfs
        
        # Create agent context
        ctx = AgentContext(
            agent_id=agent_id,
            kernel=self,
            ring=ProtectionRing.RING_3_USER,
        )
        
        self._agents[agent_id] = ctx
        
        logger.info(f"[Kernel] Created context for agent: {agent_id}")
        return ctx
    
    def destroy_agent_context(self, agent_id: str) -> None:
        """Remove an agent and release all its kernel resources.

        Cleans up the agent's context, signal dispatcher, and VFS instance.
        No-op if the agent is not registered.

        Args:
            agent_id: Identifier of the agent to remove.
        """
        if agent_id in self._agents:
            del self._agents[agent_id]
        if agent_id in self._signal_dispatchers:
            del self._signal_dispatchers[agent_id]
        if agent_id in self._vfs_instances:
            del self._vfs_instances[agent_id]
        
        logger.info(f"[Kernel] Destroyed context for agent: {agent_id}")
    
    async def syscall(
        self,
        request: SyscallRequest,
        ctx: "AgentContext",
    ) -> SyscallResult:
        """Handle a system call from user space.

        All agent actions MUST go through this interface. The kernel
        enforces policy, logs the attempt to the flight recorder, checks
        agent liveness, and dispatches to the appropriate syscall handler.

        Args:
            request: The syscall request describing the operation and its
                arguments.
            ctx: The calling agent's context, used for identity and
                permission checks.

        Returns:
            A ``SyscallResult`` indicating success or failure.  On success,
            ``return_value`` contains the handler's output.  On failure,
            ``error_code`` and ``error_message`` describe what went wrong:

            - ``-1``: Agent has been terminated.
            - ``-2``: Policy violation (action blocked).
            - ``-3``: Unknown / unregistered syscall type.
            - ``-4``: Handler raised an unexpected exception.

        Raises:
            AgentKernelPanic: If a policy violation triggers a kernel
                panic (0% tolerance mode).
        """
        start_time = datetime.now(timezone.utc)
        self._metrics.syscall_count += 1
        
        # Log to flight recorder using start_trace API
        trace_id = None
        if self._flight_recorder:
            trace_id = self._flight_recorder.start_trace(
                agent_id=ctx.agent_id,
                tool_name=f"syscall_{request.syscall.name}",
                tool_args=request.args,
            )
        
        # Check if agent is in valid state
        dispatcher = self._signal_dispatchers.get(ctx.agent_id)
        if dispatcher and dispatcher.is_terminated:
            return SyscallResult(
                success=False,
                error_code=-1,
                error_message="Agent has been terminated",
            )
        
        # Policy check (if policy engine available)
        if self._policy_engine:
            self._metrics.policy_checks += 1
            try:
                allowed, policy_error = await self._check_policy(request, ctx)
                if not allowed:
                    self._metrics.policy_violations += 1
                    
                    # Build actionable error message
                    error_msg = f"Policy '{request.syscall.name}' blocked: {policy_error or 'Access denied'}"
                    
                    # This is a policy violation - trigger signal
                    if dispatcher:
                        policy_violation(
                            dispatcher,
                            policy_name="syscall_policy",
                            details=f"Syscall {request.syscall.name} not allowed",
                            context={"args": request.args},
                        )
                    
                    return SyscallResult(
                        success=False,
                        error_code=-2,
                        error_message=error_msg,
                    )
            except AgentKernelPanic as e:
                # Re-raise kernel panics
                self._metrics.kernel_panics += 1
                raise
        
        # Execute the syscall
        handler = self._syscall_handlers.get(request.syscall)
        if not handler:
            return SyscallResult(
                success=False,
                error_code=-3,
                error_message=f"Unknown syscall: {request.syscall.name}",
            )
        
        try:
            result = await handler(request, ctx)
            execution_time = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000
            result.execution_time_ms = execution_time
            return result
        except AgentKernelPanic:
            raise
        except Exception as e:
            logger.error(f"[Kernel] Syscall {request.syscall.name} failed: {e}")
            self._metrics.agent_crashes += 1
            return SyscallResult(
                success=False,
                error_code=-4,
                error_message=str(e),
            )
    
    async def _check_policy(
        self,
        request: SyscallRequest,
        ctx: "AgentContext",
    ) -> Tuple[bool, Optional[str]]:
        """
        Check if syscall is allowed by policy.
        
        Returns:
            Tuple of (allowed, error_message). If allowed is True, error_message is None.
            If allowed is False, error_message contains actionable details.
        """
        self._metrics.policy_checks += 1
        
        # If no policy engine, allow (permissive mode)
        if not self._policy_engine:
            logger.debug(f"[Kernel] No policy engine - allowing {request.syscall.name}")
            return (True, None)
        
        # For SYS_EXEC, check the actual tool name (not "code_execute")
        # This avoids double-checking at both syscall and tool level
        if request.syscall == SyscallType.SYS_EXEC:
            tool_name = request.args.get("tool", "unknown_tool")
        else:
            # Map syscall to tool_name for policy check
            tool_name = self._syscall_to_tool_name(request.syscall)
        
        # Build args from syscall request
        tool_args = request.args.copy()
        tool_args["_syscall"] = request.syscall.name
        tool_args["_ring"] = request.caller_ring.name
        
        # Check violation using policy engine (positional args: agent_role, tool_name, args)
        violation = self._policy_engine.check_violation(
            ctx.agent_id,  # agent_role
            tool_name,     # tool_name
            tool_args,     # args
        )
        
        if violation:
            self._metrics.policy_violations += 1
            logger.warning(f"[Kernel] Policy violation for {ctx.agent_id}: {violation}")
            
            # Record to flight recorder
            if self._flight_recorder:
                trace_id = self._flight_recorder.start_trace(
                    agent_id=ctx.agent_id,
                    tool_name=tool_name,
                    tool_args=tool_args,
                )
                self._flight_recorder.log_violation(trace_id, violation)
            
            return (False, violation)
        
        return (True, None)
    
    def _syscall_to_tool_name(self, syscall: SyscallType) -> str:
        """Map syscall type to a tool name for policy engine."""
        mapping = {
            SyscallType.SYS_READ: "file_read",
            SyscallType.SYS_WRITE: "file_write",
            SyscallType.SYS_EXEC: "code_execute",
            SyscallType.SYS_OPEN: "file_open",
            SyscallType.SYS_CLOSE: "file_close",
            SyscallType.SYS_FORK: "agent_spawn",
            SyscallType.SYS_EXIT: "agent_exit",
            SyscallType.SYS_SIGNAL: "signal_send",
            SyscallType.SYS_SEND: "ipc_send",
            SyscallType.SYS_RECV: "ipc_recv",
            SyscallType.SYS_MMAP: "memory_map",
            SyscallType.SYS_MUNMAP: "memory_unmap",
        }
        return mapping.get(syscall, f"syscall_{syscall.name.lower()}")
    
    # ========== Syscall Implementations ==========
    
    async def _sys_read(
        self,
        request: SyscallRequest,
        ctx: "AgentContext",
    ) -> SyscallResult:
        """SYS_READ: Read from VFS."""
        path = request.args.get("path")
        if not path:
            return SyscallResult(success=False, error_code=1, error_message="No path specified")
        
        vfs = self._vfs_instances.get(ctx.agent_id)
        if not vfs:
            return SyscallResult(success=False, error_code=2, error_message="No VFS for agent")
        
        try:
            data = vfs.read(path)
            return SyscallResult(success=True, return_value=data)
        except Exception as e:
            return SyscallResult(success=False, error_code=3, error_message=str(e))
    
    async def _sys_write(
        self,
        request: SyscallRequest,
        ctx: "AgentContext",
    ) -> SyscallResult:
        """SYS_WRITE: Write to VFS."""
        path = request.args.get("path")
        data = request.args.get("data")
        
        if not path or data is None:
            return SyscallResult(success=False, error_code=1, error_message="Missing path or data")
        
        vfs = self._vfs_instances.get(ctx.agent_id)
        if not vfs:
            return SyscallResult(success=False, error_code=2, error_message="No VFS for agent")
        
        try:
            bytes_written = vfs.write(path, data)
            return SyscallResult(success=True, return_value=bytes_written)
        except Exception as e:
            return SyscallResult(success=False, error_code=3, error_message=str(e))
    
    async def _sys_open(
        self,
        request: SyscallRequest,
        ctx: "AgentContext",
    ) -> SyscallResult:
        """SYS_OPEN: Open a file descriptor."""
        path = request.args.get("path")
        mode = request.args.get("mode", "r")
        
        vfs = self._vfs_instances.get(ctx.agent_id)
        if not vfs:
            return SyscallResult(success=False, error_code=2, error_message="No VFS for agent")
        
        try:
            from .vfs import FileMode
            file_mode = FileMode.READ if "r" in mode else FileMode.WRITE
            fd = vfs.open(path, file_mode)
            return SyscallResult(success=True, return_value=fd)
        except Exception as e:
            return SyscallResult(success=False, error_code=3, error_message=str(e))
    
    async def _sys_close(
        self,
        request: SyscallRequest,
        ctx: "AgentContext",
    ) -> SyscallResult:
        """SYS_CLOSE: Close a file descriptor."""
        fd = request.args.get("fd")
        
        vfs = self._vfs_instances.get(ctx.agent_id)
        if not vfs:
            return SyscallResult(success=False, error_code=2, error_message="No VFS for agent")
        
        try:
            vfs.close(fd)
            return SyscallResult(success=True)
        except Exception as e:
            return SyscallResult(success=False, error_code=3, error_message=str(e))
    
    async def _sys_signal(
        self,
        request: SyscallRequest,
        ctx: "AgentContext",
    ) -> SyscallResult:
        """SYS_SIGNAL: Send a signal to an agent."""
        target_agent = request.args.get("target", ctx.agent_id)
        signal_num = request.args.get("signal")
        reason = request.args.get("reason", "")
        
        dispatcher = self._signal_dispatchers.get(target_agent)
        if not dispatcher:
            return SyscallResult(success=False, error_code=1, error_message="Target agent not found")
        
        try:
            signal = AgentSignal(signal_num)
            dispatcher.signal(signal, source=ctx.agent_id, reason=reason)
            return SyscallResult(success=True)
        except Exception as e:
            return SyscallResult(success=False, error_code=2, error_message=str(e))
    
    async def _sys_checkpolicy(
        self,
        request: SyscallRequest,
        ctx: "AgentContext",
    ) -> SyscallResult:
        """SYS_CHECKPOLICY: Check if an action is allowed before attempting it."""
        action = request.args.get("action")
        target = request.args.get("target")
        tool_args = request.args.get("args", {})
        
        if not action:
            return SyscallResult(
                success=False,
                error_code=1,
                error_message="No action specified",
            )
        
        # If no policy engine, allow all
        if not self._policy_engine:
            return SyscallResult(success=True, return_value={"allowed": True})
        
        # Check violation using policy engine (positional args)
        args_to_check = {**tool_args, "target": target} if target else tool_args
        violation = self._policy_engine.check_violation(
            ctx.agent_id,   # agent_role
            action,         # tool_name
            args_to_check,  # args
        )
        
        if violation:
            return SyscallResult(
                success=True,  # The check succeeded, but action would be denied
                return_value={
                    "allowed": False,
                    "reason": violation,
                    "action": action,
                    "agent_id": ctx.agent_id,
                },
            )
        
        return SyscallResult(
            success=True,
            return_value={
                "allowed": True,
                "action": action,
                "agent_id": ctx.agent_id,
            },
        )
    
    async def _sys_exit(
        self,
        request: SyscallRequest,
        ctx: "AgentContext",
    ) -> SyscallResult:
        """SYS_EXIT: Agent requests termination."""
        exit_code = request.args.get("code", 0)
        
        logger.info(f"[Kernel] Agent {ctx.agent_id} exiting with code {exit_code}")
        
        # Clean up agent
        self.destroy_agent_context(ctx.agent_id)
        
        return SyscallResult(success=True, return_value=exit_code)
    
    async def _sys_exec(
        self,
        request: SyscallRequest,
        ctx: "AgentContext",
    ) -> SyscallResult:
        """
        SYS_EXEC: Execute a tool through the kernel.
        
        This is the critical choke point - ALL tool execution goes through here.
        The kernel:
        1. Checks policy
        2. Records to flight recorder
        3. Executes the tool
        4. Returns result or error
        """
        tool_name = request.args.get("tool")
        tool_args = request.args.get("args", {})
        input_prompt = request.args.get("input_prompt")
        
        if not tool_name:
            return SyscallResult(
                success=False,
                error_code=1,
                error_message="No tool specified",
            )
        
        # Start trace in flight recorder
        trace_id = None
        if self._flight_recorder:
            trace_id = self._flight_recorder.start_trace(
                agent_id=ctx.agent_id,
                tool_name=tool_name,
                tool_args=tool_args,
                input_prompt=input_prompt,
            )
        
        # NOTE: Policy check already happened at syscall level in syscall()
        # We skip the double-check here for efficiency
        
        # Look up tool in registry
        executor = self._tool_registry.get(tool_name)
        if not executor:
            error_msg = f"Tool '{tool_name}' not registered in kernel"
            if self._flight_recorder and trace_id:
                self._flight_recorder.log_error(trace_id, error_msg)
            
            return SyscallResult(
                success=False,
                error_code=-404,
                error_message=error_msg,
            )
        
        # Execute the tool
        start_time = datetime.now(timezone.utc)
        try:
            # Check if executor is async
            if asyncio.iscoroutinefunction(executor):
                result = await executor(**tool_args)
            else:
                result = executor(**tool_args)
            
            execution_time_ms = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000
            
            if self._flight_recorder and trace_id:
                self._flight_recorder.log_success(trace_id, result, execution_time_ms)
            
            logger.info(f"[Kernel] ALLOWED: {ctx.agent_id} executed {tool_name}")
            
            return SyscallResult(
                success=True,
                return_value=result,
                execution_time_ms=execution_time_ms,
            )
            
        except Exception as e:
            execution_time_ms = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000
            error_msg = f"{type(e).__name__}: {str(e)}"
            
            if self._flight_recorder and trace_id:
                self._flight_recorder.log_error(trace_id, error_msg)
            
            logger.error(f"[Kernel] Tool execution failed: {error_msg}")
            
            return SyscallResult(
                success=False,
                error_code=-500,
                error_message=error_msg,
                execution_time_ms=execution_time_ms,
            )
    
    def register_tool(
        self,
        tool_name: str,
        executor: Callable[..., Any],
        description: Optional[str] = None,
    ) -> None:
        """Register a tool in the kernel's tool registry.

        Registered tools can be invoked by agents via the ``SYS_EXEC``
        syscall. The kernel wraps every invocation with policy checks and
        flight-recorder logging.

        Args:
            tool_name: Unique name for the tool (e.g. ``"read_file"``,
                ``"web_search"``). If a tool with this name is already
                registered, it is silently overwritten.
            executor: A callable (sync or async) that implements the tool.
                Arguments are passed as keyword arguments from the syscall's
                ``args["args"]`` dictionary.
            description: Optional human-readable description, recorded in
                the audit log for compliance.
        """
        self._tool_registry[tool_name] = executor
        logger.info(f"[Kernel] Registered tool: {tool_name}")
    
    def unregister_tool(self, tool_name: str) -> bool:
        """Unregister a tool from the kernel.

        Args:
            tool_name: Name of the tool to remove.

        Returns:
            ``True`` if the tool was found and removed, ``False`` if no
            tool with that name was registered.
        """
        if tool_name in self._tool_registry:
            del self._tool_registry[tool_name]
            logger.info(f"[Kernel] Unregistered tool: {tool_name}")
            return True
        return False
    
    def list_tools(self) -> List[str]:
        """List all registered tool names.

        Returns:
            A list of tool name strings currently in the registry.
        """
        return list(self._tool_registry.keys())
    
    # ========== Kernel Control ==========
    
    def panic(self, reason: str) -> None:
        """Trigger a kernel panic.

        This is a catastrophic, unrecoverable failure that halts all agent
        processing. The panic is recorded in the flight recorder, kernel
        state transitions to ``KernelState.PANIC``, and an
        ``AgentKernelPanic`` exception is raised.

        Args:
            reason: Human-readable description of why the panic occurred.

        Raises:
            AgentKernelPanic: Always raised to unwind the call stack.
        """
        self._state = KernelState.PANIC
        self._metrics.kernel_panics += 1
        
        logger.critical(f"[KERNEL PANIC] {reason}")
        
        # Record to flight recorder using error API
        if self._flight_recorder:
            trace_id = self._flight_recorder.start_trace(
                agent_id="kernel",
                tool_name="kernel_panic",
                tool_args={"reason": reason, "metrics": self._metrics.to_dict()},
            )
            self._flight_recorder.log_error(trace_id, f"KERNEL PANIC: {reason}")
        
        raise AgentKernelPanic(
            agent_id="kernel",
            signal=SignalInfo(signal=AgentSignal.SIGKILL, reason=reason),
            message=f"Kernel panic: {reason}",
        )
    
    def shutdown(self) -> None:
        """Perform a graceful kernel shutdown.

        Sends ``SIGTERM`` to every registered agent, then destroys all
        agent contexts and transitions the kernel to
        ``KernelState.SHUTDOWN``.
        """
        logger.info("[Kernel] Initiating shutdown")
        self._state = KernelState.SHUTDOWN
        
        # Send SIGTERM to all agents
        for agent_id, dispatcher in self._signal_dispatchers.items():
            try:
                dispatcher.signal(
                    AgentSignal.SIGTERM,
                    source="kernel",
                    reason="Kernel shutdown",
                )
            except Exception:
                pass
        
        # Clean up all agents
        for agent_id in list(self._agents.keys()):
            self.destroy_agent_context(agent_id)
        
        logger.info("[Kernel] Shutdown complete")


@dataclass
class AgentContext:
    """
    Context for an agent running in user space.
    
    This is the agent's view of the kernel - it can only
    interact with the kernel through syscalls.
    """
    agent_id: str
    kernel: KernelSpace
    ring: ProtectionRing = ProtectionRing.RING_3_USER
    
    # Runtime state
    pid: int = field(default_factory=lambda: id(object()))
    created: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    async def syscall(self, syscall_type: SyscallType, **kwargs) -> SyscallResult:
        """Make a system call to the kernel."""
        request = SyscallRequest(
            syscall=syscall_type,
            args=kwargs,
            caller_ring=self.ring,
        )
        return await self.kernel.syscall(request, self)
    
    # ========== Convenience Methods ==========
    
    async def read(self, path: str) -> bytes:
        """Read from VFS."""
        result = await self.syscall(SyscallType.SYS_READ, path=path)
        if not result.success:
            raise IOError(result.error_message)
        return result.return_value
    
    async def write(self, path: str, data: Union[bytes, str]) -> int:
        """Write to VFS."""
        result = await self.syscall(SyscallType.SYS_WRITE, path=path, data=data)
        if not result.success:
            raise IOError(result.error_message)
        return result.return_value
    
    async def exit(self, code: int = 0) -> None:
        """Request termination."""
        await self.syscall(SyscallType.SYS_EXIT, code=code)
    
    async def signal(
        self,
        target: str,
        signal: AgentSignal,
        reason: str = "",
    ) -> bool:
        """Send a signal to another agent."""
        result = await self.syscall(
            SyscallType.SYS_SIGNAL,
            target=target,
            signal=signal.value,
            reason=reason,
        )
        return result.success
    
    async def check_policy(self, action: str, target: str) -> bool:
        """Check if an action is allowed."""
        result = await self.syscall(
            SyscallType.SYS_CHECKPOLICY,
            action=action,
            target=target,
        )
        return result.return_value if result.success else False


@asynccontextmanager
async def user_space_execution(kernel: KernelSpace, agent_id: str):
    """
    Context manager for user-space agent execution.
    
    This provides isolation - if the agent crashes, the kernel survives.
    
    Example:
        kernel = KernelSpace()
        
        async with user_space_execution(kernel, "agent-001") as ctx:
            # Agent code runs here - isolated from kernel
            await ctx.write("/mem/working/task.txt", "Hello World")
            
            # If this raises, kernel catches it
            result = await some_llm_call()
    """
    ctx = kernel.create_agent_context(agent_id)
    
    try:
        yield ctx
    except AgentKernelPanic:
        # Kernel panics propagate up
        raise
    except Exception as e:
        # User space crashes are contained
        logger.error(f"[UserSpace] Agent {agent_id} crashed: {e}")
        logger.debug(traceback.format_exc())
        
        # Record crash
        kernel._metrics.agent_crashes += 1
        
        # Signal the agent (if still exists)
        dispatcher = kernel._signal_dispatchers.get(agent_id)
        if dispatcher:
            try:
                dispatcher.signal(
                    AgentSignal.SIGKILL,
                    source="kernel",
                    reason=f"Agent crash: {e}",
                )
            except AgentKernelPanic:
                pass
    finally:
        # Clean up
        kernel.destroy_agent_context(agent_id)


# ========== Factory Functions ==========

def create_kernel(
    policy_engine: Optional[Any] = None,
    flight_recorder: Optional[Any] = None,
) -> KernelSpace:
    """Create a new kernel instance."""
    return KernelSpace(
        policy_engine=policy_engine,
        flight_recorder=flight_recorder,
    )
