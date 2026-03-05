# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# Community Edition — basic YAML policy enforcement
"""
Kernel Space - Basic wrapper delegating to policy engine.

Keeps ProtectionRing enum and KernelSpace class but without actual
ring-based isolation.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, auto
from typing import Any, Callable, Dict, List, Optional, Tuple, Union
import asyncio
import logging
import traceback
from contextlib import asynccontextmanager

from .signals import (
    SignalDispatcher, AgentSignal, SignalInfo, AgentKernelPanic,
    policy_violation, kill_agent, pause_agent
)
from .vfs import AgentVFS, create_agent_vfs

logger = logging.getLogger(__name__)


class ProtectionRing(Enum):
    """Protection rings (kept for API compatibility)."""
    RING_0_KERNEL = 0
    RING_1_DRIVERS = 1
    RING_2_SERVICES = 2
    RING_3_USER = 3


class SyscallType(Enum):
    """System calls that user space can make into kernel."""
    SYS_FORK = auto()
    SYS_EXIT = auto()
    SYS_WAIT = auto()
    SYS_EXEC = auto()
    SYS_OPEN = auto()
    SYS_CLOSE = auto()
    SYS_READ = auto()
    SYS_WRITE = auto()
    SYS_STAT = auto()
    SYS_MMAP = auto()
    SYS_MUNMAP = auto()
    SYS_BRK = auto()
    SYS_PIPE = auto()
    SYS_SEND = auto()
    SYS_RECV = auto()
    SYS_SIGNAL = auto()
    SYS_SIGACTION = auto()
    SYS_SIGPROCMASK = auto()
    SYS_GETPOLICY = auto()
    SYS_CHECKPOLICY = auto()


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
    DEGRADED = auto()
    PANIC = auto()
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
            "agent_crashes": self.agent_crashes,
            "kernel_panics": self.kernel_panics,
            "uptime_seconds": self.uptime_seconds,
            "active_agents": self.active_agents,
        }


class KernelSpace:
    """Basic KernelSpace — delegates policy checks to the policy engine."""

    def __init__(
        self,
        policy_engine: Optional[Any] = None,
        flight_recorder: Optional[Any] = None,
    ):
        self._state = KernelState.BOOTING
        self._metrics = KernelMetrics()
        self._start_time = datetime.now(timezone.utc)

        self._policy_engine = policy_engine
        self._flight_recorder = flight_recorder

        self._agents: Dict[str, "AgentContext"] = {}
        self._signal_dispatchers: Dict[str, SignalDispatcher] = {}
        self._vfs_instances: Dict[str, AgentVFS] = {}
        self._tool_registry: Dict[str, Callable[..., Any]] = {}

        self._syscall_handlers: Dict[SyscallType, Callable] = {}
        self._init_syscall_handlers()

        self._state = KernelState.RUNNING
        logger.info("[Kernel] Booted successfully")

    def _init_syscall_handlers(self) -> None:
        self._syscall_handlers[SyscallType.SYS_READ] = self._sys_read
        self._syscall_handlers[SyscallType.SYS_WRITE] = self._sys_write
        self._syscall_handlers[SyscallType.SYS_OPEN] = self._sys_open
        self._syscall_handlers[SyscallType.SYS_CLOSE] = self._sys_close
        self._syscall_handlers[SyscallType.SYS_SIGNAL] = self._sys_signal
        self._syscall_handlers[SyscallType.SYS_CHECKPOLICY] = self._sys_checkpolicy
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

    # -- agent management --

    def create_agent_context(self, agent_id: str) -> "AgentContext":
        if agent_id in self._agents:
            raise ValueError(f"Agent {agent_id} already registered")
        signal_dispatcher = SignalDispatcher(agent_id)
        vfs = create_agent_vfs(agent_id)
        self._signal_dispatchers[agent_id] = signal_dispatcher
        self._vfs_instances[agent_id] = vfs
        ctx = AgentContext(agent_id=agent_id, kernel=self, ring=ProtectionRing.RING_3_USER)
        self._agents[agent_id] = ctx
        logger.info(f"[Kernel] Created context for agent: {agent_id}")
        return ctx

    def destroy_agent_context(self, agent_id: str) -> None:
        self._agents.pop(agent_id, None)
        self._signal_dispatchers.pop(agent_id, None)
        self._vfs_instances.pop(agent_id, None)
        logger.info(f"[Kernel] Destroyed context for agent: {agent_id}")

    # -- syscall dispatch --

    async def syscall(self, request: SyscallRequest, ctx: "AgentContext") -> SyscallResult:
        start_time = datetime.now(timezone.utc)
        self._metrics.syscall_count += 1

        if self._flight_recorder:
            self._flight_recorder.start_trace(
                agent_id=ctx.agent_id,
                tool_name=f"syscall_{request.syscall.name}",
                tool_args=request.args,
            )

        dispatcher = self._signal_dispatchers.get(ctx.agent_id)
        if dispatcher and dispatcher.is_terminated:
            return SyscallResult(success=False, error_code=-1, error_message="Agent has been terminated")

        if self._policy_engine:
            self._metrics.policy_checks += 1
            try:
                allowed, policy_error = await self._check_policy(request, ctx)
                if not allowed:
                    self._metrics.policy_violations += 1
                    error_msg = f"Policy '{request.syscall.name}' blocked: {policy_error or 'Access denied'}"
                    if dispatcher:
                        policy_violation(dispatcher, policy_name="syscall_policy",
                                         details=f"Syscall {request.syscall.name} not allowed",
                                         context={"args": request.args})
                    return SyscallResult(success=False, error_code=-2, error_message=error_msg)
            except AgentKernelPanic:
                self._metrics.kernel_panics += 1
                raise

        handler = self._syscall_handlers.get(request.syscall)
        if not handler:
            return SyscallResult(success=False, error_code=-3,
                                 error_message=f"Unknown syscall: {request.syscall.name}")
        try:
            result = await handler(request, ctx)
            result.execution_time_ms = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000
            return result
        except AgentKernelPanic:
            raise
        except Exception as e:
            logger.error(f"[Kernel] Syscall {request.syscall.name} failed: {e}")
            self._metrics.agent_crashes += 1
            return SyscallResult(success=False, error_code=-4, error_message=str(e))

    async def _check_policy(self, request: SyscallRequest, ctx: "AgentContext") -> Tuple[bool, Optional[str]]:
        if not self._policy_engine:
            return (True, None)

        if request.syscall == SyscallType.SYS_EXEC:
            tool_name = request.args.get("tool", "unknown_tool")
        else:
            tool_name = self._syscall_to_tool_name(request.syscall)

        tool_args = request.args.copy()
        tool_args["_syscall"] = request.syscall.name
        tool_args["_ring"] = request.caller_ring.name

        violation = self._policy_engine.check_violation(ctx.agent_id, tool_name, tool_args)
        if violation:
            self._metrics.policy_violations += 1
            if self._flight_recorder:
                trace_id = self._flight_recorder.start_trace(
                    agent_id=ctx.agent_id, tool_name=tool_name, tool_args=tool_args)
                self._flight_recorder.log_violation(trace_id, violation)
            return (False, violation)
        return (True, None)

    def _syscall_to_tool_name(self, syscall: SyscallType) -> str:
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

    # -- syscall implementations --

    async def _sys_read(self, request: SyscallRequest, ctx: "AgentContext") -> SyscallResult:
        path = request.args.get("path")
        if not path:
            return SyscallResult(success=False, error_code=1, error_message="No path specified")
        vfs = self._vfs_instances.get(ctx.agent_id)
        if not vfs:
            return SyscallResult(success=False, error_code=2, error_message="No VFS for agent")
        try:
            return SyscallResult(success=True, return_value=vfs.read(path))
        except Exception as e:
            return SyscallResult(success=False, error_code=3, error_message=str(e))

    async def _sys_write(self, request: SyscallRequest, ctx: "AgentContext") -> SyscallResult:
        path = request.args.get("path")
        data = request.args.get("data")
        if not path or data is None:
            return SyscallResult(success=False, error_code=1, error_message="Missing path or data")
        vfs = self._vfs_instances.get(ctx.agent_id)
        if not vfs:
            return SyscallResult(success=False, error_code=2, error_message="No VFS for agent")
        try:
            return SyscallResult(success=True, return_value=vfs.write(path, data))
        except Exception as e:
            return SyscallResult(success=False, error_code=3, error_message=str(e))

    async def _sys_open(self, request: SyscallRequest, ctx: "AgentContext") -> SyscallResult:
        path = request.args.get("path")
        mode = request.args.get("mode", "r")
        vfs = self._vfs_instances.get(ctx.agent_id)
        if not vfs:
            return SyscallResult(success=False, error_code=2, error_message="No VFS for agent")
        try:
            from .vfs import FileMode
            file_mode = FileMode.READ if "r" in mode else FileMode.WRITE
            return SyscallResult(success=True, return_value=vfs.open(path, file_mode))
        except Exception as e:
            return SyscallResult(success=False, error_code=3, error_message=str(e))

    async def _sys_close(self, request: SyscallRequest, ctx: "AgentContext") -> SyscallResult:
        fd = request.args.get("fd")
        vfs = self._vfs_instances.get(ctx.agent_id)
        if not vfs:
            return SyscallResult(success=False, error_code=2, error_message="No VFS for agent")
        try:
            vfs.close(fd)
            return SyscallResult(success=True)
        except Exception as e:
            return SyscallResult(success=False, error_code=3, error_message=str(e))

    async def _sys_signal(self, request: SyscallRequest, ctx: "AgentContext") -> SyscallResult:
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

    async def _sys_checkpolicy(self, request: SyscallRequest, ctx: "AgentContext") -> SyscallResult:
        action = request.args.get("action")
        target = request.args.get("target")
        tool_args = request.args.get("args", {})
        if not action:
            return SyscallResult(success=False, error_code=1, error_message="No action specified")
        if not self._policy_engine:
            return SyscallResult(success=True, return_value={"allowed": True})
        args_to_check = {**tool_args, "target": target} if target else tool_args
        violation = self._policy_engine.check_violation(ctx.agent_id, action, args_to_check)
        if violation:
            return SyscallResult(success=True, return_value={
                "allowed": False, "reason": violation, "action": action, "agent_id": ctx.agent_id})
        return SyscallResult(success=True, return_value={
            "allowed": True, "action": action, "agent_id": ctx.agent_id})

    async def _sys_exit(self, request: SyscallRequest, ctx: "AgentContext") -> SyscallResult:
        exit_code = request.args.get("code", 0)
        logger.info(f"[Kernel] Agent {ctx.agent_id} exiting with code {exit_code}")
        self.destroy_agent_context(ctx.agent_id)
        return SyscallResult(success=True, return_value=exit_code)

    async def _sys_exec(self, request: SyscallRequest, ctx: "AgentContext") -> SyscallResult:
        tool_name = request.args.get("tool")
        tool_args = request.args.get("args", {})
        input_prompt = request.args.get("input_prompt")
        if not tool_name:
            return SyscallResult(success=False, error_code=1, error_message="No tool specified")

        trace_id = None
        if self._flight_recorder:
            trace_id = self._flight_recorder.start_trace(
                agent_id=ctx.agent_id, tool_name=tool_name,
                tool_args=tool_args, input_prompt=input_prompt)

        executor = self._tool_registry.get(tool_name)
        if not executor:
            error_msg = f"Tool '{tool_name}' not registered in kernel"
            if self._flight_recorder and trace_id:
                self._flight_recorder.log_error(trace_id, error_msg)
            return SyscallResult(success=False, error_code=-404, error_message=error_msg)

        start = datetime.now(timezone.utc)
        try:
            if asyncio.iscoroutinefunction(executor):
                result = await executor(**tool_args)
            else:
                result = executor(**tool_args)
            elapsed = (datetime.now(timezone.utc) - start).total_seconds() * 1000
            if self._flight_recorder and trace_id:
                self._flight_recorder.log_success(trace_id, result, elapsed)
            return SyscallResult(success=True, return_value=result, execution_time_ms=elapsed)
        except Exception as e:
            elapsed = (datetime.now(timezone.utc) - start).total_seconds() * 1000
            error_msg = f"{type(e).__name__}: {str(e)}"
            if self._flight_recorder and trace_id:
                self._flight_recorder.log_error(trace_id, error_msg)
            return SyscallResult(success=False, error_code=-500, error_message=error_msg, execution_time_ms=elapsed)

    # -- tool registry --

    def register_tool(self, tool_name: str, executor: Callable[..., Any], description: Optional[str] = None) -> None:
        self._tool_registry[tool_name] = executor
        logger.info(f"[Kernel] Registered tool: {tool_name}")

    def unregister_tool(self, tool_name: str) -> bool:
        if tool_name in self._tool_registry:
            del self._tool_registry[tool_name]
            return True
        return False

    def list_tools(self) -> List[str]:
        return list(self._tool_registry.keys())

    # -- kernel control --

    def panic(self, reason: str) -> None:
        self._state = KernelState.PANIC
        self._metrics.kernel_panics += 1
        logger.critical(f"[KERNEL PANIC] {reason}")
        if self._flight_recorder:
            trace_id = self._flight_recorder.start_trace(
                agent_id="kernel", tool_name="kernel_panic",
                tool_args={"reason": reason, "metrics": self._metrics.to_dict()})
            self._flight_recorder.log_error(trace_id, f"KERNEL PANIC: {reason}")
        raise AgentKernelPanic(
            agent_id="kernel",
            signal=SignalInfo(signal=AgentSignal.SIGKILL, reason=reason),
            message=f"Kernel panic: {reason}",
        )

    def shutdown(self) -> None:
        logger.info("[Kernel] Initiating shutdown")
        self._state = KernelState.SHUTDOWN
        for agent_id, dispatcher in self._signal_dispatchers.items():
            try:
                dispatcher.signal(AgentSignal.SIGTERM, source="kernel", reason="Kernel shutdown")
            except Exception:
                pass
        for agent_id in list(self._agents.keys()):
            self.destroy_agent_context(agent_id)
        logger.info("[Kernel] Shutdown complete")


@dataclass
class AgentContext:
    """Context for an agent running in user space."""
    agent_id: str
    kernel: KernelSpace
    ring: ProtectionRing = ProtectionRing.RING_3_USER
    pid: int = field(default_factory=lambda: id(object()))
    created: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    async def syscall(self, syscall_type: SyscallType, **kwargs) -> SyscallResult:
        request = SyscallRequest(syscall=syscall_type, args=kwargs, caller_ring=self.ring)
        return await self.kernel.syscall(request, self)

    async def read(self, path: str) -> bytes:
        result = await self.syscall(SyscallType.SYS_READ, path=path)
        if not result.success:
            raise IOError(result.error_message)
        return result.return_value

    async def write(self, path: str, data: Union[bytes, str]) -> int:
        result = await self.syscall(SyscallType.SYS_WRITE, path=path, data=data)
        if not result.success:
            raise IOError(result.error_message)
        return result.return_value

    async def exit(self, code: int = 0) -> None:
        await self.syscall(SyscallType.SYS_EXIT, code=code)

    async def signal(self, target: str, signal: AgentSignal, reason: str = "") -> bool:
        result = await self.syscall(SyscallType.SYS_SIGNAL, target=target, signal=signal.value, reason=reason)
        return result.success

    async def check_policy(self, action: str, target: str) -> bool:
        result = await self.syscall(SyscallType.SYS_CHECKPOLICY, action=action, target=target)
        return result.return_value if result.success else False


@asynccontextmanager
async def user_space_execution(kernel: KernelSpace, agent_id: str):
    """Context manager for user-space agent execution with isolation."""
    ctx = kernel.create_agent_context(agent_id)
    try:
        yield ctx
    except AgentKernelPanic:
        raise
    except Exception as e:
        logger.error(f"[UserSpace] Agent {agent_id} crashed: {e}")
        logger.debug(traceback.format_exc())
        kernel._metrics.agent_crashes += 1
        dispatcher = kernel._signal_dispatchers.get(agent_id)
        if dispatcher:
            try:
                dispatcher.signal(AgentSignal.SIGKILL, source="kernel", reason=f"Agent crash: {e}")
            except AgentKernelPanic:
                pass
    finally:
        kernel.destroy_agent_context(agent_id)


def create_kernel(
    policy_engine: Optional[Any] = None,
    flight_recorder: Optional[Any] = None,
) -> KernelSpace:
    """Create a new kernel instance."""
    return KernelSpace(policy_engine=policy_engine, flight_recorder=flight_recorder)