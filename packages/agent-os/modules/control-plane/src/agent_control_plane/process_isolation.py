# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Process-Level Agent Isolation

Provides real OS-level process isolation for agent execution, addressing
the limitation that in-process SIGKILL (AgentKernelPanic) is catchable
by a broad ``except BaseException`` in Python.

This module runs agents in separate processes where ``os.kill(SIGKILL)``
is truly non-catchable by agent code.

Architecture::

    +-------------------------------------------+
    |  Supervisor Process (Kernel Space)        |
    |  - ProcessIsolationManager                |
    |  - IsolatedSignalDispatcher               |
    |                                           |
    |  +------------+  +------------+           |
    |  | Agent A    |  | Agent B    |           |
    |  | (Process)  |  | (Process)  |           |
    |  +------------+  +------------+           |
    +-------------------------------------------+

Isolation Levels:
    COOPERATIVE  -- In-process, exception-based (current behaviour)
    PROCESS      -- Separate process via multiprocessing.Process
    SUBPROCESS   -- Separate process via subprocess.Popen

Security Model:
    - In-process signals  = cooperative path (can be caught)
    - Process-level kill  = enforcement path (non-catchable)

See Also:
    signals.py -- In-process cooperative signal handling
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import multiprocessing
import os
import signal as _signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

from .signals import AgentKernelPanic, AgentSignal, SignalDispatcher, SignalInfo

logger = logging.getLogger(__name__)


# ================================================================
# Enums
# ================================================================


class IsolationLevel(str, Enum):
    """Level of process isolation for agent execution."""

    COOPERATIVE = "cooperative"  # In-process, exception-based (current behaviour)
    PROCESS = "process"          # Separate process via multiprocessing
    SUBPROCESS = "subprocess"    # Separate process via subprocess.Popen


class AgentProcessState(str, Enum):
    """Lifecycle state of an isolated agent process."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    TERMINATED = "terminated"
    FAILED = "failed"


# ================================================================
# Result dataclass
# ================================================================


@dataclass
class AgentProcessResult:
    """Result from an isolated agent process."""

    agent_id: str
    state: AgentProcessState
    return_value: Any = None
    error: Optional[str] = None
    exit_code: Optional[int] = None
    duration_seconds: float = 0.0
    terminated_by_signal: bool = False


# ================================================================
# Worker function (module top-level so multiprocessing can pickle it)
# ================================================================


def _agent_worker(
    target: Callable,
    args: tuple,
    kwargs: dict,
    result_queue: multiprocessing.Queue,
) -> None:
    """Execute *target* inside the child process, sending the outcome via *result_queue*."""
    start = time.monotonic()
    try:
        rv = target(*args, **(kwargs or {}))
        result_queue.put({
            "state": "completed",
            "return_value": rv,
            "error": None,
            "exit_code": 0,
            "duration": time.monotonic() - start,
        })
    except SystemExit as exc:
        code = exc.code if isinstance(exc.code, int) else 1
        result_queue.put({
            "state": "failed",
            "return_value": None,
            "error": f"SystemExit({exc.code})",
            "exit_code": code,
            "duration": time.monotonic() - start,
        })
    except BaseException as exc:
        result_queue.put({
            "state": "failed",
            "return_value": None,
            "error": f"{type(exc).__name__}: {exc}",
            "exit_code": 1,
            "duration": time.monotonic() - start,
        })


# Bootstrap script executed inside a ``subprocess.Popen`` child.
# The parent sends: base64(hmac_key + b"|" + hmac_sig + b"|" + json_payload)
# The child verifies the HMAC before deserializing.
# The JSON payload contains {"module": "...", "qualname": "...", "args": [...], "kwargs": {...}}
# and the target function is resolved via importlib, avoiding pickle deserialization.
_SUBPROCESS_BOOTSTRAP = """\
import base64, hashlib, hmac, importlib, json, sys, time
raw = base64.b64decode(sys.stdin.buffer.read())
parts = raw.split(b"|", 2)
if len(parts) != 3:
    json.dump({"state": "failed", "error": "Invalid bootstrap payload format", "exit_code": 1, "duration": 0}, sys.stdout)
    sys.exit(1)
_key, _expected_sig, _payload = parts
_actual_sig = hmac.new(_key, _payload, hashlib.sha256).digest()
if not hmac.compare_digest(_actual_sig, _expected_sig):
    json.dump({"state": "failed", "error": "HMAC verification failed — payload tampered", "exit_code": 1, "duration": 0}, sys.stdout)
    sys.exit(1)
_data = json.loads(_payload)
_mod = importlib.import_module(_data["module"])
_obj = _mod
for _attr in _data["qualname"].split("."):
    _obj = getattr(_obj, _attr)
target = _obj
args = tuple(_data.get("args", ()))
kwargs = _data.get("kwargs", {})
_start = time.monotonic()
try:
    _rv = target(*args, **kwargs)
    json.dump({
        "state": "completed",
        "return_value": repr(_rv),
        "error": None,
        "exit_code": 0,
        "duration": time.monotonic() - _start,
    }, sys.stdout)
except SystemExit as _e:
    json.dump({
        "state": "failed",
        "error": f"SystemExit({_e.code})",
        "exit_code": getattr(_e, "code", 1),
        "duration": time.monotonic() - _start,
    }, sys.stdout)
except Exception as _e:
    json.dump({
        "state": "failed",
        "error": f"{type(_e).__name__}: {_e}",
        "exit_code": 1,
        "duration": time.monotonic() - _start,
    }, sys.stdout)
"""


# ================================================================
# AgentProcessHandle
# ================================================================


@dataclass
class AgentProcessHandle:
    """Handle to a running agent process.

    Provides real process-level control including non-catchable termination.
    """

    agent_id: str
    pid: Optional[int] = None
    state: AgentProcessState = AgentProcessState.PENDING
    isolation_level: IsolationLevel = IsolationLevel.PROCESS

    # ---- internal fields (hidden from repr) ----
    _process: Any = field(default=None, repr=False)
    _result_queue: Any = field(default=None, repr=False)
    _start_time: float = field(default=0.0, repr=False)
    _result: Optional[AgentProcessResult] = field(default=None, repr=False)
    _killed: bool = field(default=False, repr=False)

    # --------------------------------------------------------------
    # Public API
    # --------------------------------------------------------------

    def terminate(self) -> bool:
        """Send SIGTERM (graceful shutdown request)."""
        if self._process is None or not self.is_alive():
            return False
        try:
            self._process.terminate()
            self.state = AgentProcessState.TERMINATED
            elapsed = time.monotonic() - self._start_time
            self._result = AgentProcessResult(
                agent_id=self.agent_id,
                state=AgentProcessState.TERMINATED,
                error="Terminated by SIGTERM",
                exit_code=-15 if os.name != "nt" else 1,
                duration_seconds=elapsed,
                terminated_by_signal=True,
            )
            logger.info(
                f"[ProcessIsolation] SIGTERM -> agent {self.agent_id} "
                f"(pid={self.pid})"
            )
            return True
        except (OSError, ProcessLookupError) as exc:
            logger.warning(
                f"[ProcessIsolation] terminate failed for "
                f"{self.agent_id}: {exc}"
            )
            return False

    def kill(self) -> bool:
        """Send real OS SIGKILL -- truly non-catchable.

        On Unix:    ``os.kill(pid, signal.SIGKILL)``
        On Windows: ``TerminateProcess`` via ``process.kill()``
        This is the real deal -- the OS scheduler handles it.
        """
        if self._process is None or not self.is_alive():
            return False

        # Flag early so a concurrent wait() sees it immediately.
        self._killed = True

        try:
            if os.name != "nt" and self.pid is not None:
                os.kill(self.pid, _signal.SIGKILL)
            else:
                # Windows: process.kill() calls TerminateProcess
                self._process.kill()

            # Wait briefly for the OS to reap the process.
            if self.isolation_level == IsolationLevel.PROCESS:
                self._process.join(timeout=5)
            elif self.isolation_level == IsolationLevel.SUBPROCESS:
                try:
                    self._process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    pass

            self.state = AgentProcessState.TERMINATED
            elapsed = time.monotonic() - self._start_time
            self._result = AgentProcessResult(
                agent_id=self.agent_id,
                state=AgentProcessState.TERMINATED,
                error="Killed by SIGKILL",
                exit_code=-9 if os.name != "nt" else 1,
                duration_seconds=elapsed,
                terminated_by_signal=True,
            )
            logger.critical(
                f"[ProcessIsolation] SIGKILL -> agent {self.agent_id} "
                f"(pid={self.pid})"
            )
            return True
        except (OSError, ProcessLookupError) as exc:
            logger.warning(
                f"[ProcessIsolation] kill failed for {self.agent_id}: {exc}"
            )
            return False

    def is_alive(self) -> bool:
        """Check whether the underlying OS process is still running."""
        if self._process is None:
            return False
        if self.isolation_level == IsolationLevel.PROCESS:
            return self._process.is_alive()
        if self.isolation_level == IsolationLevel.SUBPROCESS:
            return self._process.poll() is None
        return False

    def wait(self, timeout: Optional[float] = None) -> AgentProcessResult:
        """Block until the process finishes (or *timeout* expires) and return its result."""
        # Fast path -- already resolved.
        if self._result is not None and not self.is_alive():
            return self._result

        if self._process is None:
            return AgentProcessResult(
                agent_id=self.agent_id,
                state=AgentProcessState.FAILED,
                error="No process to wait on",
            )

        if self.isolation_level == IsolationLevel.PROCESS:
            return self._wait_process(timeout)

        if self.isolation_level == IsolationLevel.SUBPROCESS:
            return self._wait_subprocess(timeout)

        return AgentProcessResult(
            agent_id=self.agent_id,
            state=AgentProcessState.FAILED,
            error=f"Unsupported isolation level: {self.isolation_level}",
        )

    # --------------------------------------------------------------
    # Internal helpers
    # --------------------------------------------------------------

    def _wait_process(self, timeout: Optional[float]) -> AgentProcessResult:
        """Wait logic for ``IsolationLevel.PROCESS``."""
        self._process.join(timeout=timeout)

        if self._process.is_alive():
            # Timed out -- forcibly kill.
            self.kill()

        # Killed (by us, or by an external timeout timer)?
        if self._result is not None:
            return self._result

        return self._read_queue_result()

    def _wait_subprocess(self, timeout: Optional[float]) -> AgentProcessResult:
        """Wait logic for ``IsolationLevel.SUBPROCESS``."""
        try:
            stdout, stderr = self._process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.kill()
            if self._result is not None:
                return self._result
            elapsed = time.monotonic() - self._start_time
            self._result = AgentProcessResult(
                agent_id=self.agent_id,
                state=AgentProcessState.TERMINATED,
                error="Timed out",
                duration_seconds=elapsed,
                terminated_by_signal=True,
            )
            self.state = AgentProcessState.TERMINATED
            return self._result

        if self._result is not None:
            return self._result

        return self._parse_subprocess_output(stdout, stderr)

    def _read_queue_result(self) -> AgentProcessResult:
        """Read the result dict from the multiprocessing Queue."""
        # Killed by another thread (e.g. timeout timer)?
        if self._killed:
            if self._result is not None:
                return self._result
            elapsed = time.monotonic() - self._start_time
            self._result = AgentProcessResult(
                agent_id=self.agent_id,
                state=AgentProcessState.TERMINATED,
                error="Killed",
                exit_code=-9 if os.name != "nt" else 1,
                duration_seconds=elapsed,
                terminated_by_signal=True,
            )
            self.state = AgentProcessState.TERMINATED
            return self._result

        try:
            if self._result_queue is not None and not self._result_queue.empty():
                data = self._result_queue.get_nowait()
                state = (
                    AgentProcessState.COMPLETED
                    if data["state"] == "completed"
                    else AgentProcessState.FAILED
                )
                self._result = AgentProcessResult(
                    agent_id=self.agent_id,
                    state=state,
                    return_value=data.get("return_value"),
                    error=data.get("error"),
                    exit_code=data.get("exit_code"),
                    duration_seconds=data.get("duration", 0.0),
                )
            else:
                # Process exited without writing to the queue.
                elapsed = time.monotonic() - self._start_time
                exit_code = getattr(self._process, "exitcode", None)
                if exit_code is not None and exit_code < 0:
                    self._result = AgentProcessResult(
                        agent_id=self.agent_id,
                        state=AgentProcessState.TERMINATED,
                        error=f"Terminated by signal {-exit_code}",
                        exit_code=exit_code,
                        duration_seconds=elapsed,
                        terminated_by_signal=True,
                    )
                else:
                    self._result = AgentProcessResult(
                        agent_id=self.agent_id,
                        state=AgentProcessState.FAILED,
                        error=f"Process exited with code {exit_code}",
                        exit_code=exit_code,
                        duration_seconds=elapsed,
                    )
        except Exception as exc:  # noqa: BLE001
            elapsed = time.monotonic() - self._start_time
            self._result = AgentProcessResult(
                agent_id=self.agent_id,
                state=AgentProcessState.FAILED,
                error=str(exc),
                duration_seconds=elapsed,
            )

        self.state = self._result.state
        return self._result

    def _parse_subprocess_output(
        self, stdout: bytes, stderr: bytes,
    ) -> AgentProcessResult:
        """Parse JSON result from subprocess stdout."""
        exit_code = self._process.returncode
        elapsed = time.monotonic() - self._start_time

        try:
            data = json.loads(stdout.decode("utf-8", errors="replace"))
            state = (
                AgentProcessState.COMPLETED
                if data.get("state") == "completed"
                else AgentProcessState.FAILED
            )
            self._result = AgentProcessResult(
                agent_id=self.agent_id,
                state=state,
                return_value=data.get("return_value"),
                error=data.get("error"),
                exit_code=data.get("exit_code", exit_code),
                duration_seconds=data.get("duration", elapsed),
            )
        except (json.JSONDecodeError, UnicodeDecodeError):
            stderr_txt = (
                stderr.decode("utf-8", errors="replace") if stderr else ""
            )
            self._result = AgentProcessResult(
                agent_id=self.agent_id,
                state=(
                    AgentProcessState.COMPLETED
                    if exit_code == 0
                    else AgentProcessState.FAILED
                ),
                return_value=(
                    stdout.decode("utf-8", errors="replace") if stdout else None
                ),
                error=stderr_txt or None,
                exit_code=exit_code,
                duration_seconds=elapsed,
            )

        self.state = self._result.state
        return self._result


# ================================================================
# ProcessIsolationManager
# ================================================================


class ProcessIsolationManager:
    """Manages agent processes with real OS-level isolation.

    Unlike in-process ``AgentKernelPanic`` (which can be caught with
    ``try/except``), this runs agents in separate processes where
    ``os.kill(SIGKILL)`` is truly non-catchable by the agent.
    """

    def __init__(
        self,
        default_isolation: IsolationLevel = IsolationLevel.PROCESS,
    ) -> None:
        self._default_isolation = default_isolation
        self._handles: Dict[str, AgentProcessHandle] = {}
        self._lock = threading.Lock()
        self._counter = 0

    # ----------------------------------------------------------
    # Spawn
    # ----------------------------------------------------------

    def spawn(
        self,
        target: Callable,
        agent_id: Optional[str] = None,
        args: tuple = (),
        kwargs: Optional[dict] = None,
        isolation: Optional[IsolationLevel] = None,
        timeout: Optional[float] = None,
    ) -> AgentProcessHandle:
        """Spawn an agent function in an isolated process."""
        if agent_id is None:
            agent_id = self._next_id()

        level = isolation or self._default_isolation

        if level == IsolationLevel.COOPERATIVE:
            raise ValueError(
                "Cooperative isolation is in-process only. "
                "Use SignalDispatcher directly for cooperative mode."
            )

        if level == IsolationLevel.PROCESS:
            handle = self._spawn_multiprocessing(
                agent_id, target, args, kwargs,
            )
        elif level == IsolationLevel.SUBPROCESS:
            handle = self._spawn_subprocess(
                agent_id, target, args, kwargs,
            )
        else:
            raise ValueError(f"Unsupported isolation level: {level}")

        with self._lock:
            self._handles[agent_id] = handle

        # Optional watchdog timer.
        if timeout is not None:
            timer = threading.Timer(
                timeout, self._on_timeout, args=(agent_id,),
            )
            timer.daemon = True
            timer.start()

        logger.info(
            f"[ProcessIsolation] Spawned {agent_id} "
            f"(pid={handle.pid}, isolation={level.value})"
        )
        return handle

    # ----------------------------------------------------------
    # Kill / Terminate
    # ----------------------------------------------------------

    def kill(self, agent_id: str, reason: str = "") -> bool:
        """Send SIGKILL to agent process -- truly non-catchable."""
        handle = self.get_handle(agent_id)
        if handle is None:
            logger.warning(
                f"[ProcessIsolation] kill: unknown agent {agent_id}"
            )
            return False
        logger.info(f"[ProcessIsolation] kill({agent_id}): {reason}")
        return handle.kill()

    def terminate(self, agent_id: str, reason: str = "") -> bool:
        """Send SIGTERM for graceful shutdown."""
        handle = self.get_handle(agent_id)
        if handle is None:
            logger.warning(
                f"[ProcessIsolation] terminate: unknown agent {agent_id}"
            )
            return False
        logger.info(f"[ProcessIsolation] terminate({agent_id}): {reason}")
        return handle.terminate()

    def kill_all(self, reason: str = "") -> int:
        """Kill all running agents.  Returns count killed."""
        killed = 0
        with self._lock:
            handles = list(self._handles.values())
        for h in handles:
            if h.is_alive() and h.kill():
                killed += 1
        logger.info(
            f"[ProcessIsolation] kill_all: {killed} agents killed"
            + (f" -- {reason}" if reason else "")
        )
        return killed

    # ----------------------------------------------------------
    # Queries
    # ----------------------------------------------------------

    def get_handle(self, agent_id: str) -> Optional[AgentProcessHandle]:
        """Retrieve the handle for a specific agent."""
        with self._lock:
            return self._handles.get(agent_id)

    def list_agents(self) -> List[AgentProcessHandle]:
        """Return a snapshot of all tracked agent handles."""
        with self._lock:
            return list(self._handles.values())

    # ----------------------------------------------------------
    # Maintenance
    # ----------------------------------------------------------

    def cleanup(self) -> None:
        """Remove completed / terminated / failed processes from tracking."""
        with self._lock:
            remove = [
                aid
                for aid, h in self._handles.items()
                if not h.is_alive()
                and h.state
                in (
                    AgentProcessState.COMPLETED,
                    AgentProcessState.TERMINATED,
                    AgentProcessState.FAILED,
                )
            ]
            for aid in remove:
                del self._handles[aid]
        if remove:
            logger.debug(
                f"[ProcessIsolation] Cleaned up {len(remove)} processes"
            )

    # ----------------------------------------------------------
    # Internal helpers
    # ----------------------------------------------------------

    def _next_id(self) -> str:
        self._counter += 1
        return f"agent-{self._counter:04d}"

    def _spawn_multiprocessing(
        self,
        agent_id: str,
        target: Callable,
        args: tuple,
        kwargs: Optional[dict],
    ) -> AgentProcessHandle:
        q: multiprocessing.Queue = multiprocessing.Queue()
        p = multiprocessing.Process(
            target=_agent_worker,
            args=(target, args, kwargs or {}, q),
            daemon=True,
        )
        p.start()
        return AgentProcessHandle(
            agent_id=agent_id,
            pid=p.pid,
            state=AgentProcessState.RUNNING,
            isolation_level=IsolationLevel.PROCESS,
            _process=p,
            _result_queue=q,
            _start_time=time.monotonic(),
        )

    def _spawn_subprocess(
        self,
        agent_id: str,
        target: Callable,
        args: tuple,
        kwargs: Optional[dict],
    ) -> AgentProcessHandle:
        # Validate target is an importable function (not a lambda/closure)
        if not hasattr(target, '__module__') or not hasattr(target, '__qualname__'):
            raise ValueError(
                f"Target callable {target!r} must be a module-level function "
                "with __module__ and __qualname__ for subprocess isolation"
            )
        # Serialize as JSON with function reference instead of pickling callables
        payload = json.dumps({
            "module": target.__module__,
            "qualname": target.__qualname__,
            "args": list(args),
            "kwargs": kwargs or {},
        }).encode('utf-8')
        # Sign payload with HMAC to prevent tampering
        hmac_key = os.urandom(32)
        sig = hmac.new(hmac_key, payload, hashlib.sha256).digest()
        encoded = base64.b64encode(hmac_key + b"|" + sig + b"|" + payload)
        proc = subprocess.Popen(
            [sys.executable, "-c", _SUBPROCESS_BOOTSTRAP],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        proc.stdin.write(encoded)   # type: ignore[union-attr]
        proc.stdin.close()          # type: ignore[union-attr]
        return AgentProcessHandle(
            agent_id=agent_id,
            pid=proc.pid,
            state=AgentProcessState.RUNNING,
            isolation_level=IsolationLevel.SUBPROCESS,
            _process=proc,
            _start_time=time.monotonic(),
        )

    def _on_timeout(self, agent_id: str) -> None:
        handle = self.get_handle(agent_id)
        if handle is not None and handle.is_alive():
            logger.warning(
                f"[ProcessIsolation] Timeout -> killing {agent_id}"
            )
            handle.kill()


# ================================================================
# IsolatedSignalDispatcher
# ================================================================


class IsolatedSignalDispatcher(SignalDispatcher):
    """Signal dispatcher that uses real process isolation for SIGKILL.

    Extends :class:`SignalDispatcher` so that ``SIGKILL`` routes through
    :class:`ProcessIsolationManager` for a true OS-level kill, while all
    other signals continue to use the cooperative in-process path.
    """

    def __init__(
        self,
        agent_id: str,
        process_manager: Optional[ProcessIsolationManager] = None,
    ) -> None:
        super().__init__(agent_id)
        self._process_manager = process_manager or ProcessIsolationManager()

    def _handle_kill(self, info: SignalInfo) -> None:
        """Override: route SIGKILL through real process isolation."""
        handle = self._process_manager.get_handle(self.agent_id)
        if handle is not None and handle.is_alive():
            logger.critical(
                f"[IsolatedSignalDispatcher] SIGKILL -> os.kill for "
                f"{self.agent_id} (pid={handle.pid})"
            )
            handle.kill()
            self._is_terminated = True
            self._is_stopped = True
        else:
            # No isolated process -- fall back to cooperative exception.
            super()._handle_kill(info)


# ================================================================
# Factory
# ================================================================


def create_isolated_signal_dispatcher(
    agent_id: str,
    **kwargs: Any,
) -> IsolatedSignalDispatcher:
    """Factory function for creating isolated signal dispatchers."""
    return IsolatedSignalDispatcher(
        agent_id=agent_id,
        process_manager=kwargs.get("process_manager"),
    )
