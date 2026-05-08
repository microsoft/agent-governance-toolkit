# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Docker-based sandbox provider implementing the ``SandboxProvider`` ABC.

Each agent gets its own Docker container scoped to a session.  Containers
are hardened by default: all capabilities dropped, ``no-new-privileges``,
optional read-only root filesystem, non-root user, ``pids_limit=256``.

Policy-driven resource limits, tool proxies, and network proxies are set
up at session creation time when a ``PolicyDocument`` is passed.
"""

from __future__ import annotations

import logging
import os
import platform
import re
import shutil
import threading
import time
import uuid
from typing import Any, Callable

from agent_sandbox.isolation_runtime import IsolationRuntime
from agent_sandbox.sandbox_provider import (
    ExecutionHandle,
    ExecutionStatus,
    SandboxConfig,
    SandboxProvider,
    SandboxResult,
    SessionHandle,
    SessionStatus,
)
from agent_sandbox.docker_provider.state import SandboxCheckpoint, SandboxStateManager

logger = logging.getLogger(__name__)

# Protected system directories that must never be bind-mounted.
_PROTECTED_PATHS_UNIX = frozenset(
    {
        "/", "/etc", "/proc", "/sys", "/usr", "/var",
        "/boot", "/dev", "/sbin", "/bin", "/lib",
    }
)

# Windows system directories that must never be bind-mounted.  Compared
# case-insensitively against the realpath of the requested mount.
_PROTECTED_PATHS_WINDOWS = frozenset(
    p.lower()
    for p in (
        "C:\\Windows",
        "C:\\Program Files",
        "C:\\Program Files (x86)",
        "C:\\ProgramData",
        "C:\\System Volume Information",
    )
)

# Docker resource-name pattern (containers, image repos, tags).
# Must start with [a-zA-Z0-9] and may include _.- afterwards, max 128 chars.
_DOCKER_NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$")


def _validate_resource_name(value: str, label: str) -> None:
    """Validate *value* is safe to interpolate into a Docker resource name.

    Raises ``ValueError`` if *value* contains characters that could cause
    name collisions, Docker API errors, or shell-style injection when used
    as a container name, image repo, or image tag.
    """
    if not isinstance(value, str) or not _DOCKER_NAME_RE.match(value):
        raise ValueError(
            f"Invalid {label} '{value}': must match "
            f"[a-zA-Z0-9][a-zA-Z0-9_.-]{{0,127}}"
        )


# Environment variables that could break container hardening.
_BLOCKED_ENV_VARS = frozenset(
    {
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "LD_AUDIT",
        "LD_DEBUG",
        "LD_PROFILE",
        "LD_SHOW_AUXV",
        "LD_DYNAMIC_WEAK",
        "PYTHONSTARTUP",
        "PYTHONPATH",
    }
)


def _sanitize_env_vars(env_vars: dict[str, str]) -> dict[str, str]:
    """Remove dangerous env vars that could escape sandbox hardening."""
    blocked_found = [
        k for k in env_vars if k.upper() in _BLOCKED_ENV_VARS
    ]
    if blocked_found:
        logger.warning(
            "Blocked dangerous environment variables: %s",
            blocked_found,
        )
    return {
        k: v
        for k, v in env_vars.items()
        if k.upper() not in _BLOCKED_ENV_VARS
    }


def _is_protected_path(path: str) -> bool:
    """Check whether *path* is a system directory that must not be mounted."""
    system = platform.system()

    if system == "Windows":
        normalised = os.path.normpath(os.path.realpath(path))
        # Block drive roots like C:\, D:\
        if len(normalised) <= 3 and normalised.endswith((":\\", ":")):
            return True
        # Block well-known Windows system directories (case-insensitive).
        lowered = normalised.lower()
        for protected in _PROTECTED_PATHS_WINDOWS:
            if lowered == protected or lowered.startswith(protected + "\\"):
                return True
        return False

    # Unix-like: resolve symlinks then normalize
    import posixpath

    resolved = os.path.realpath(path)
    normalised = posixpath.normpath(resolved)
    return normalised in _PROTECTED_PATHS_UNIX


def _validate_mount_path(path: str, label: str) -> None:
    if _is_protected_path(path):
        raise ValueError(
            f"Cannot mount protected system directory '{path}' as {label}"
        )


def has_iptables() -> bool:
    """Return ``True`` if iptables is available on this host."""
    return shutil.which("iptables") is not None


def docker_config_from_policy(
    policy: Any, base: SandboxConfig
) -> SandboxConfig:
    """Extract sandbox-relevant fields from a policy into a config.

    Reads well-known policy attributes when present and merges them into
    *base*.  Unknown or missing attributes are silently ignored so the
    function works with any policy shape.
    """
    cfg = SandboxConfig(
        timeout_seconds=base.timeout_seconds,
        memory_mb=base.memory_mb,
        cpu_limit=base.cpu_limit,
        network_enabled=base.network_enabled,
        read_only_fs=base.read_only_fs,
        env_vars=dict(base.env_vars),
        input_dir=base.input_dir,
        output_dir=base.output_dir,
        runtime=base.runtime,
    )

    # Resource limits from policy defaults
    defaults = getattr(policy, "defaults", None)
    if defaults is not None:
        if hasattr(defaults, "max_memory_mb"):
            cfg.memory_mb = defaults.max_memory_mb
        if hasattr(defaults, "max_cpu"):
            cfg.cpu_limit = defaults.max_cpu

    # Sandbox mounts
    mounts = getattr(policy, "sandbox_mounts", None)
    if mounts is not None:
        if hasattr(mounts, "input_dir") and mounts.input_dir:
            cfg.input_dir = mounts.input_dir
        if hasattr(mounts, "output_dir") and mounts.output_dir:
            cfg.output_dir = mounts.output_dir

    # Network: enable if the policy specifies an allowlist
    if getattr(policy, "network_allowlist", None):
        cfg.network_enabled = True

    return cfg


class DockerSandboxProvider(SandboxProvider):
    """``SandboxProvider`` backed by hardened Docker containers.

    Parameters
    ----------
    image:
        Base Docker image (default ``python:3.11-slim``).
    docker_url:
        Docker daemon URL (default: auto-detect via env).
    runtime:
        OCI runtime to use (default ``IsolationRuntime.AUTO``).
    tools:
        Host-side tool callables keyed by name.  Passed to the
        ``ToolCallProxy`` when a policy has a ``tool_allowlist``.
    """

    def __init__(
        self,
        image: str = "python:3.11-slim",
        docker_url: str | None = None,
        runtime: IsolationRuntime = IsolationRuntime.AUTO,
        tools: dict[str, Callable[..., Any]] | None = None,
    ) -> None:
        self._image = image
        self._tools: dict[str, Callable[..., Any]] = tools or {}
        self._requested_runtime = runtime

        # Session state.  Guarded by ``_state_lock`` because async variants
        # call into sync methods via ``asyncio.to_thread`` and can race.
        self._state_lock = threading.RLock()
        self._containers: dict[tuple[str, str], Any] = {}
        self._evaluators: dict[tuple[str, str], Any] = {}
        self._session_configs: dict[tuple[str, str], SandboxConfig] = {}
        self._tool_proxy: Any | None = None
        self._network_proxy: Any | None = None
        self._state_manager: SandboxStateManager | None = None

        # Docker client
        self._client: Any | None = None
        self._available: bool = False
        self._runtime: IsolationRuntime = (
            IsolationRuntime.RUNC
            if runtime == IsolationRuntime.AUTO
            else runtime
        )

        try:
            import docker  # type: ignore[import-untyped]

            if docker_url:
                self._client = docker.DockerClient(base_url=docker_url)
            else:
                self._client = docker.from_env()

            self._client.ping()
            self._available = True

            # Auto-detect best runtime
            if runtime == IsolationRuntime.AUTO:
                self._runtime = self._detect_runtime()

            # Validate explicit runtime is installed
            if runtime not in (
                IsolationRuntime.AUTO,
                IsolationRuntime.RUNC,
            ):
                self._validate_runtime(runtime)

        except Exception as exc:
            logger.warning("Docker daemon not available: %s", exc)
            self._available = False

    # ------------------------------------------------------------------
    # Runtime detection
    # ------------------------------------------------------------------

    def _detect_runtime(self) -> IsolationRuntime:
        """Auto-detect the strongest available OCI runtime."""
        if self._client is None:
            return IsolationRuntime.RUNC
        try:
            info = self._client.info()
            runtimes = info.get("Runtimes", {})
            if "kata-runtime" in runtimes:
                return IsolationRuntime.KATA
            if "runsc" in runtimes:
                return IsolationRuntime.GVISOR
        except Exception as exc:
            logger.debug(
                "Failed to auto-detect Docker runtime; "
                "falling back to runc: %s",
                exc,
            )
        return IsolationRuntime.RUNC

    def _validate_runtime(self, runtime: IsolationRuntime) -> None:
        """Raise if the requested runtime is not installed."""
        if self._client is None:
            raise RuntimeError("Docker daemon is not available")
        try:
            info = self._client.info()
            runtimes = info.get("Runtimes", {})
            if runtime.value not in runtimes:
                raise RuntimeError(
                    f"OCI runtime '{runtime.value}' is not installed. "
                    f"Available runtimes: {list(runtimes.keys())}"
                )
        except RuntimeError:
            raise
        except Exception as exc:
            raise RuntimeError(
                f"Failed to query Docker runtimes: {exc}"
            ) from exc

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def runtime(self) -> IsolationRuntime:
        return self._runtime

    @property
    def kernel_isolated(self) -> bool:
        return self._runtime in (
            IsolationRuntime.GVISOR,
            IsolationRuntime.KATA,
        )

    # ------------------------------------------------------------------
    # Image management
    # ------------------------------------------------------------------

    def ensure_image(self, image: str | None = None) -> None:
        """Pull *image* if it is not already present locally.

        Authentication is resolved through Docker's standard credential
        chain (``docker login``, credential helpers, ``~/.docker/config.json``).
        For private registries, configure credentials via ``docker login``
        before creating the provider.

        Parameters
        ----------
        image:
            Image name to pull (defaults to the provider's configured image).
        """
        if self._client is None:
            raise RuntimeError("Docker daemon is not available")

        target = image or self._image
        try:
            self._client.images.get(target)
            logger.debug("Image '%s' already present locally", target)
            return
        except Exception:
            pass

        logger.info("Pulling image '%s' ...", target)

        # Split image:tag for the pull API
        if ":" in target and not target.startswith("sha256:"):
            repo, tag = target.rsplit(":", 1)
        else:
            repo, tag = target, "latest"

        self._client.images.pull(repo, tag=tag)
        logger.info("Pulled image '%s' successfully", target)

    # ------------------------------------------------------------------
    # SandboxProvider interface
    # ------------------------------------------------------------------

    def create_session(
        self,
        agent_id: str,
        policy: Any | None = None,
        config: SandboxConfig | None = None,
    ) -> SessionHandle:
        if not self._available:
            raise RuntimeError("Docker daemon is not available")

        # ``agent_id`` is interpolated into Docker container and image
        # names; reject anything outside the safe character set up front.
        _validate_resource_name(agent_id, "agent_id")

        session_id = uuid.uuid4().hex[:8]
        cfg = config or SandboxConfig()

        # 1. Extract policy constraints
        evaluator = None
        if policy is not None:
            cfg = docker_config_from_policy(policy, cfg)
            try:
                from agent_os.policies.evaluator import PolicyEvaluator

                evaluator = PolicyEvaluator(policies=[policy])
            except ImportError:
                logger.warning(
                    "agent-os-kernel not installed — "
                    "policy evaluation unavailable, session runs ungated"
                )
            except Exception as exc:
                raise RuntimeError(
                    f"Failed to initialize PolicyEvaluator: {exc}"
                ) from exc

        # 2. Create hardened container
        container = self._create_container(agent_id, session_id, cfg)
        with self._state_lock:
            self._containers[(agent_id, session_id)] = container
            self._session_configs[(agent_id, session_id)] = cfg
            if evaluator is not None:
                self._evaluators[(agent_id, session_id)] = evaluator

        return SessionHandle(
            agent_id=agent_id,
            session_id=session_id,
            status=SessionStatus.READY,
        )

    def execute_code(
        self,
        agent_id: str,
        session_id: str,
        code: str,
        *,
        context: dict[str, Any] | None = None,
    ) -> ExecutionHandle:
        key = (agent_id, session_id)
        with self._state_lock:
            if key not in self._containers:
                raise RuntimeError(
                    f"No active session for agent '{agent_id}' with "
                    f"session_id '{session_id}'. Call create_session() first."
                )
            evaluator = self._evaluators.get(key)
            session_cfg = self._session_configs.get(key)

        # Policy gate
        if evaluator is not None:
            eval_ctx: dict[str, Any] = {
                "agent_id": agent_id,
                "action": "execute",
                "code": code,
            }
            if context:
                eval_ctx.update(context)
            decision = evaluator.evaluate(eval_ctx)
            if not decision.allowed:
                raise PermissionError(
                    f"Policy denied: {decision.reason}"
                )

        # Run code with the session's configured timeout/env, not defaults.
        result = self.run(
            agent_id,
            ["python", "-c", code],
            config=session_cfg,
            session_id=session_id,
        )

        status = (
            ExecutionStatus.COMPLETED
            if result.success
            else ExecutionStatus.FAILED
        )
        return ExecutionHandle(
            execution_id=uuid.uuid4().hex[:8],
            agent_id=agent_id,
            session_id=session_id,
            status=status,
            result=result,
        )

    def destroy_session(self, agent_id: str, session_id: str) -> None:
        key = (agent_id, session_id)
        with self._state_lock:
            container = self._containers.pop(key, None)
            self._evaluators.pop(key, None)
            self._session_configs.pop(key, None)

        if container is not None:
            try:
                container.stop(timeout=5)
            except Exception as exc:
                logger.warning(
                    "Failed to stop container for agent '%s' "
                    "session '%s': %s",
                    agent_id,
                    session_id,
                    exc,
                )
            try:
                container.remove(force=True)
            except Exception as exc:
                logger.warning(
                    "Failed to remove container for agent '%s' "
                    "session '%s': %s",
                    agent_id,
                    session_id,
                    exc,
                )

    def is_available(self) -> bool:
        return self._available

    def get_session_status(
        self, agent_id: str, session_id: str
    ) -> SessionStatus:
        with self._state_lock:
            if (agent_id, session_id) in self._containers:
                return SessionStatus.READY
        return SessionStatus.DESTROYED

    # ------------------------------------------------------------------
    # Low-level run
    # ------------------------------------------------------------------

    def run(
        self,
        agent_id: str,
        command: list[str],
        config: SandboxConfig | None = None,
        *,
        session_id: str | None = None,
    ) -> SandboxResult:
        """Execute *command* inside the session's container."""
        # Find the container
        container = None
        with self._state_lock:
            if session_id is not None:
                container = self._containers.get((agent_id, session_id))
            else:
                for (aid, _sid), c in self._containers.items():
                    if aid == agent_id:
                        container = c
                        break

        if container is None:
            return SandboxResult(
                success=False,
                exit_code=-1,
                stderr=f"No container found for agent '{agent_id}'",
            )

        cfg = config or SandboxConfig()
        start = time.monotonic()
        timed_out = threading.Event()

        try:
            # Refresh container state
            container.reload()
            if container.status != "running":
                container.start()

            # Timeout watchdog: kills the exec process if it exceeds
            # the configured timeout.
            timer: threading.Timer | None = None
            if cfg.timeout_seconds and cfg.timeout_seconds > 0:
                def _on_timeout() -> None:
                    timed_out.set()
                    try:
                        container.kill()
                    except Exception as exc:
                        logger.warning(
                            "Failed to kill container on timeout for "
                            "agent '%s': %s",
                            agent_id,
                            exc,
                        )

                timer = threading.Timer(cfg.timeout_seconds, _on_timeout)
                timer.daemon = True
                timer.start()

            try:
                sanitized_env = (
                    _sanitize_env_vars(cfg.env_vars)
                    if cfg.env_vars
                    else {}
                )
                exec_result = container.exec_run(
                    cmd=command,
                    environment=sanitized_env,
                    workdir="/workspace",
                    demux=True,
                )
            finally:
                if timer is not None:
                    timer.cancel()

            killed = timed_out.is_set()
            kill_reason = (
                f"Execution exceeded timeout of "
                f"{cfg.timeout_seconds}s"
                if killed
                else ""
            )

            duration = time.monotonic() - start
            stdout_bytes, stderr_bytes = exec_result.output or (
                None,
                None,
            )
            stdout = (
                stdout_bytes.decode("utf-8", errors="replace")[:10000]
                if stdout_bytes
                else ""
            )
            stderr = (
                stderr_bytes.decode("utf-8", errors="replace")[:10000]
                if stderr_bytes
                else ""
            )
            # Both streams are truncated to prevent memory exhaustion
            # from adversarial output

            return SandboxResult(
                success=exec_result.exit_code == 0 and not killed,
                exit_code=exec_result.exit_code,
                stdout=stdout,
                stderr=stderr,
                duration_seconds=round(duration, 3),
                killed=killed,
                kill_reason=kill_reason,
            )

        except Exception as exc:
            duration = time.monotonic() - start
            return SandboxResult(
                success=False,
                exit_code=-1,
                stderr=str(exc),
                duration_seconds=round(duration, 3),
            )

    # ------------------------------------------------------------------
    # Container creation
    # ------------------------------------------------------------------

    def _create_container(
        self, agent_id: str, session_id: str, config: SandboxConfig
    ) -> Any:
        """Create a hardened Docker container for the session."""
        # Ensure the base image is available locally before creating
        self.ensure_image()

        # ``agent_id`` is already validated by ``create_session``; the
        # 8-char hex ``session_id`` is generated internally.  Re-validate
        # in case ``_create_container`` is reached via another path.
        _validate_resource_name(agent_id, "agent_id")
        container_name = f"agent-sandbox-{agent_id}-{session_id}"

        # Determine runtime
        runtime_value: str | None = None
        if config.runtime:
            runtime_value = config.runtime
        elif self._runtime != IsolationRuntime.RUNC:
            runtime_value = self._runtime.value

        # Build volume mounts
        volumes: dict[str, dict[str, str]] = {}
        if config.input_dir:
            _validate_mount_path(config.input_dir, "input_dir")
            volumes[config.input_dir] = {"bind": "/input", "mode": "ro"}
        if config.output_dir:
            _validate_mount_path(config.output_dir, "output_dir")
            volumes[config.output_dir] = {"bind": "/output", "mode": "rw"}

        # tmpfs mounts
        tmpfs: dict[str, str] = {
            "/workspace": "size=128m,uid=65534,gid=65534",
        }
        if config.read_only_fs:
            tmpfs["/tmp"] = "size=64m,uid=65534,gid=65534"

        run_kwargs: dict[str, Any] = {
            "image": self._image,
            "name": container_name,
            "command": ["sleep", "infinity"],
            "detach": True,
            "labels": {
                "agent-sandbox.managed": "true",
                "agent-sandbox.agent-id": agent_id,
            },
            "mem_limit": f"{config.memory_mb}m",
            # Disable swap by setting memswap_limit == mem_limit so that
            # the cgroup memory cap cannot be bypassed by spilling to swap.
            "memswap_limit": f"{config.memory_mb}m",
            "nano_cpus": int(config.cpu_limit * 1e9),
            "network_disabled": not config.network_enabled,
            "read_only": config.read_only_fs,
            "tmpfs": tmpfs,
            "security_opt": ["no-new-privileges"],
            "cap_drop": ["ALL"],
            "user": "65534:65534",
            "working_dir": "/workspace",
            "pids_limit": 256,
            # Resolve host.docker.internal on native Linux Docker
            # (Docker Desktop on macOS/Windows does this automatically)
            "extra_hosts": {"host.docker.internal": "host-gateway"},
        }

        if config.env_vars:
            run_kwargs["environment"] = _sanitize_env_vars(config.env_vars)
        if volumes:
            run_kwargs["volumes"] = volumes
        if runtime_value:
            run_kwargs["runtime"] = runtime_value

        container = self._client.containers.run(**run_kwargs)
        logger.info(
            "Created container '%s' for agent '%s' session '%s'",
            container_name,
            agent_id,
            session_id,
        )
        return container

    # ------------------------------------------------------------------
    # Checkpoint methods (Docker-specific, not on the ABC)
    # ------------------------------------------------------------------

    def _get_state_manager(self) -> SandboxStateManager:
        if self._state_manager is None:
            self._state_manager = SandboxStateManager(self)
        return self._state_manager

    def save_state(
        self, agent_id: str, session_id: str, name: str
    ) -> SandboxCheckpoint:
        """Snapshot the session's container via ``docker commit``."""
        _validate_resource_name(agent_id, "agent_id")
        _validate_resource_name(name, "checkpoint name")
        return self._get_state_manager().save(agent_id, session_id, name)

    def restore_state(
        self,
        agent_id: str,
        session_id: str,
        name: str,
        config: SandboxConfig | None = None,
    ) -> None:
        """Restore a checkpoint — destroy current, recreate from image."""
        _validate_resource_name(agent_id, "agent_id")
        _validate_resource_name(name, "checkpoint name")
        self._get_state_manager().restore(
            agent_id, session_id, name, config
        )

    def list_checkpoints(
        self, agent_id: str
    ) -> list[SandboxCheckpoint]:
        """List all checkpoint images for the agent."""
        _validate_resource_name(agent_id, "agent_id")
        return self._get_state_manager().list_checkpoints(agent_id)

    def delete_checkpoint(self, agent_id: str, name: str) -> None:
        """Remove a checkpoint image."""
        _validate_resource_name(agent_id, "agent_id")
        _validate_resource_name(name, "checkpoint name")
        self._get_state_manager().delete_checkpoint(agent_id, name)
