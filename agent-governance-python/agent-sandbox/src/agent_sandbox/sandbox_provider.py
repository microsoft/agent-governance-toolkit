# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""SandboxProvider abstract base class and supporting data types.

Defines the backend-agnostic API for sandboxed agent execution.  Any
sandbox backend — Docker, Hyperlight micro-VMs, cloud sandbox services,
or custom providers — implements the three core lifecycle methods:

* ``create_session`` — provision a sandbox with optional policy-driven
  resource limits, tool proxy, and network rules.
* ``execute_code`` — evaluate policy allow/deny, then run code inside
  an existing session.
* ``destroy_session`` — tear down the sandbox and release resources.

Additional methods provide status tracking (``get_session_status``,
``get_execution_status``, ``cancel_execution``) and async variants
that delegate to sync via ``asyncio.to_thread`` by default.
"""

from __future__ import annotations

import asyncio
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class SessionStatus(str, Enum):
    """Lifecycle state of a sandbox session."""

    PROVISIONING = "provisioning"
    READY = "ready"
    EXECUTING = "executing"
    DESTROYING = "destroying"
    DESTROYED = "destroyed"
    FAILED = "failed"


class ExecutionStatus(str, Enum):
    """State of a single code execution within a session."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    FAILED = "failed"


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------


@dataclass
class SandboxConfig:
    """Configuration for a sandbox environment.

    Extends the minimal config with fields needed by session-based
    providers (``input_dir``, ``output_dir``, ``runtime``).
    """

    timeout_seconds: float = 60.0
    memory_mb: int = 512
    cpu_limit: float = 1.0
    network_enabled: bool = False
    read_only_fs: bool = True
    env_vars: dict[str, str] = field(default_factory=dict)
    input_dir: str | None = None
    output_dir: str | None = None
    runtime: str | None = None


@dataclass
class SandboxResult:
    """Result from a sandbox execution."""

    success: bool
    exit_code: int = 0
    stdout: str = ""
    stderr: str = ""
    duration_seconds: float = 0.0
    killed: bool = False
    kill_reason: str = ""


@dataclass
class SessionHandle:
    """Returned by ``create_session`` — identifies an active sandbox session."""

    agent_id: str
    session_id: str
    status: SessionStatus = SessionStatus.READY


@dataclass
class ExecutionHandle:
    """Returned by ``execute_code`` — wraps the result of a single execution."""

    execution_id: str
    agent_id: str
    session_id: str
    status: ExecutionStatus = ExecutionStatus.COMPLETED
    result: SandboxResult | None = None


# ---------------------------------------------------------------------------
# Abstract base class
# ---------------------------------------------------------------------------


class SandboxProvider(ABC):
    """Abstract base class for sandbox providers.

    Defines session-based lifecycle methods (``create_session``,
    ``execute_code``, ``destroy_session``), status tracking, and async
    variants that default to ``asyncio.to_thread`` delegation.
    """

    # --- Sync (required) ---------------------------------------------------

    @abstractmethod
    def create_session(
        self,
        agent_id: str,
        policy: Any | None = None,
        config: SandboxConfig | None = None,
    ) -> SessionHandle:
        """Provision a sandbox with optional policy-driven constraints."""

    @abstractmethod
    def execute_code(
        self,
        agent_id: str,
        session_id: str,
        code: str,
        *,
        context: dict[str, Any] | None = None,
    ) -> ExecutionHandle:
        """Evaluate policy allow/deny, then run code in a session."""

    @abstractmethod
    def destroy_session(self, agent_id: str, session_id: str) -> None:
        """Tear down the sandbox and release resources."""

    @abstractmethod
    def is_available(self) -> bool:
        """Check if this sandbox provider is available."""

    def run(
        self,
        agent_id: str,
        command: list[str],
        config: SandboxConfig | None = None,
    ) -> SandboxResult:
        """Run a raw command in the sandbox (low-level helper).

        Default raises :class:`NotImplementedError` so that a custom
        provider that forgets to override the method surfaces as a
        programming error instead of silently returning a failure
        result that callers might confuse with a normal command
        failure. Providers that intentionally do not support raw
        commands (e.g. Hyperlight, where the sandbox is wasm-only)
        should override and either raise the same error or return an
        explicit :class:`SandboxResult` documenting the reason.
        """
        raise NotImplementedError(
            f"{type(self).__name__}.run() is not implemented; this "
            "provider does not support raw command execution"
        )

    # --- Status tracking (defaults; cloud providers override) ---------------

    def get_session_status(self, agent_id: str, session_id: str) -> SessionStatus:
        """Return the current session lifecycle state."""
        return SessionStatus.DESTROYED

    def get_execution_status(
        self, agent_id: str, session_id: str, execution_id: str
    ) -> ExecutionHandle:
        """Poll execution state (useful for cloud providers)."""
        return ExecutionHandle(
            execution_id=execution_id,
            agent_id=agent_id,
            session_id=session_id,
            status=ExecutionStatus.COMPLETED,
        )

    def cancel_execution(
        self, agent_id: str, session_id: str, execution_id: str
    ) -> bool:
        """Cancel a running execution.  Returns ``True`` if cancelled."""
        return False

    # --- Async (default: delegates to sync via asyncio.to_thread) -----------

    async def create_session_async(
        self,
        agent_id: str,
        policy: Any | None = None,
        config: SandboxConfig | None = None,
    ) -> SessionHandle:
        return await asyncio.to_thread(self.create_session, agent_id, policy, config)

    async def execute_code_async(
        self,
        agent_id: str,
        session_id: str,
        code: str,
        *,
        context: dict[str, Any] | None = None,
    ) -> ExecutionHandle:
        return await asyncio.to_thread(
            self.execute_code, agent_id, session_id, code, context=context
        )

    async def destroy_session_async(self, agent_id: str, session_id: str) -> None:
        await asyncio.to_thread(self.destroy_session, agent_id, session_id)

    async def cancel_execution_async(
        self, agent_id: str, session_id: str, execution_id: str
    ) -> bool:
        return await asyncio.to_thread(
            self.cancel_execution, agent_id, session_id, execution_id
        )
