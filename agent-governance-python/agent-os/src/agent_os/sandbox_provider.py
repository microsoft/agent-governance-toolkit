# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Pluggable SandboxProvider for agent execution isolation.

Defines the interface for sandbox backends (Docker, subprocess, etc.)
that the toolkit can use to isolate agent execution.

Example::

    provider = SubprocessSandboxProvider()
    result = provider.run(
        agent_id="a1",
        command=["python", "agent_task.py"],
        config=SandboxConfig(timeout_seconds=30, memory_mb=512),
    )
"""

from __future__ import annotations

import logging
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# Default set of command basenames allowed by SubprocessSandboxProvider.
DEFAULT_COMMAND_ALLOWLIST: frozenset[str] = frozenset(
    {"python", "python3", "node", "npm", "go", "cargo", "dotnet"}
)

# Environment variables that must never be passed through to sandboxed processes.
_DANGEROUS_ENV_VARS: frozenset[str] = frozenset(
    {"LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "LD_LIBRARY_PATH", "DYLD_LIBRARY_PATH"}
)


@dataclass
class SandboxConfig:
    """Configuration for a sandbox environment."""

    timeout_seconds: float = 60.0
    memory_mb: int = 512
    cpu_limit: float = 1.0
    network_enabled: bool = False
    read_only_fs: bool = True
    env_vars: dict[str, str] = field(default_factory=dict)


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


class SandboxProvider(ABC):
    """Abstract base class for sandbox providers."""

    @abstractmethod
    def run(
        self,
        agent_id: str,
        command: list[str],
        config: SandboxConfig | None = None,
    ) -> SandboxResult:
        """Run a command in a sandboxed environment."""
        ...

    @abstractmethod
    def is_available(self) -> bool:
        """Check if this sandbox provider is available."""
        ...


class SubprocessSandboxProvider(SandboxProvider):
    """Basic subprocess sandbox (no container isolation).

    Provides timeout, output capture, and command allowlisting.
    For production, use DockerSandboxProvider or a custom implementation.

    Args:
        allowed_commands: Set of allowed command basenames.
            Defaults to ``DEFAULT_COMMAND_ALLOWLIST``.
    """

    def __init__(
        self,
        allowed_commands: frozenset[str] | set[str] | None = None,
    ) -> None:
        self._allowed = frozenset(allowed_commands) if allowed_commands else DEFAULT_COMMAND_ALLOWLIST

    @staticmethod
    def _basename(cmd: str) -> str:
        """Return the platform-agnostic basename without extension."""
        import os
        base = os.path.basename(cmd)
        # Strip .exe / .cmd / .bat on Windows
        for ext in (".exe", ".cmd", ".bat"):
            if base.lower().endswith(ext):
                base = base[: -len(ext)]
                break
        return base

    def run(
        self,
        agent_id: str,
        command: list[str],
        config: SandboxConfig | None = None,
    ) -> SandboxResult:
        if not command:
            return SandboxResult(
                success=False, exit_code=-1, stderr="Empty command"
            )

        basename = self._basename(command[0])
        if basename not in self._allowed:
            return SandboxResult(
                success=False,
                exit_code=-1,
                stderr=(
                    f"Command '{basename}' is not in the sandbox allowlist. "
                    f"Allowed: {sorted(self._allowed)}"
                ),
            )

        cfg = config or SandboxConfig()
        import time

        # Filter dangerous env vars
        env = None
        if cfg.env_vars:
            env = {
                k: v
                for k, v in cfg.env_vars.items()
                if k not in _DANGEROUS_ENV_VARS and k != "PATH"
            }

        start = time.time()
        try:
            result = subprocess.run(  # noqa: S603 — allowlisted subprocess in sandbox provider
                command,
                capture_output=True,
                text=True,
                timeout=cfg.timeout_seconds,
                env=env,
            )
            duration = time.time() - start
            return SandboxResult(
                success=result.returncode == 0,
                exit_code=result.returncode,
                stdout=result.stdout[:10000],
                stderr=result.stderr[:10000],
                duration_seconds=round(duration, 3),
            )
        except subprocess.TimeoutExpired:
            duration = time.time() - start
            return SandboxResult(
                success=False,
                exit_code=-1,
                stderr=f"Timeout after {cfg.timeout_seconds}s",
                duration_seconds=round(duration, 3),
                killed=True,
                kill_reason="timeout",
            )
        except Exception as exc:
            duration = time.time() - start
            return SandboxResult(
                success=False,
                exit_code=-1,
                stderr=str(exc),
                duration_seconds=round(duration, 3),
            )

    def is_available(self) -> bool:
        return True


class NoOpSandboxProvider(SandboxProvider):
    """No-op sandbox for testing — runs nothing, always succeeds."""

    def run(
        self,
        agent_id: str,
        command: list[str],
        config: SandboxConfig | None = None,
    ) -> SandboxResult:
        return SandboxResult(success=True, stdout="no-op sandbox")

    def is_available(self) -> bool:
        return True
