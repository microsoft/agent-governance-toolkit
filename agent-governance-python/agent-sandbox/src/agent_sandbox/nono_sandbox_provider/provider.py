# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""nono-backed implementation of :class:`SandboxProvider`.

`nono <https://github.com/always-further/nono>`_ is a capability-based
sandbox enforced by OS-native kernel primitives (Landlock on Linux,
Seatbelt on macOS).  Its Python bindings, ``nono-py``, expose the
one-shot :func:`nono_py.sandboxed_exec` primitive — fork, apply the
sandbox in the child, ``exec`` the command, capture stdio in the
unsandboxed parent — plus a filtering network proxy.  This provider drives
that library directly; there is no daemon, hypervisor, cloud account, or
external binary to install.

Session model
-------------
``sandboxed_exec`` is *one-shot*: it forks, sandboxes, runs the command,
and the child exits.  There is no long-lived guest the way a Docker
container or Hyperlight micro-VM persists across calls.

To satisfy the session-based :class:`SandboxProvider` contract, a
*session* is treated as a durable **bundle** — the resolved
:class:`NonoConfig`, the policy evaluator, a per-session workspace
directory, and an optional long-lived network proxy.  Each
:meth:`execute_code` (or :meth:`run`) call forks a fresh one-shot sandbox
using that bundle.  Consequently **guest state does not persist across
executions** except through the session's read-write ``output/``
directory, which is preserved on the host between invocations.  The proxy
is shared across executions and is shut down on :meth:`destroy_session`.

See ``docs/proposals/NONO-SANDBOX-PROVIDER.md`` for the design rationale.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import re
import shlex
import shutil
import sys
import tempfile
import threading
import time
import uuid
from pathlib import Path
from typing import Any

from agent_sandbox.code_scanner import enforce_no_subprocess_execution
from agent_sandbox.nono_sandbox_provider.config import (
    NonoConfig,
    default_system_paths,
    nono_config_from_policy,
)
from agent_sandbox.sandbox_provider import (
    ExecutionHandle,
    ExecutionStatus,
    SandboxConfig,
    SandboxProvider,
    SandboxResult,
    SessionHandle,
    SessionStatus,
)

logger = logging.getLogger(__name__)

# Lazy handle to the optional native extension. Imported at module load so
# the global exists, but the provider never requires it to import — only to
# construct/use. Tests replace this global with a fake module.
try:  # pragma: no cover - import guard exercised indirectly
    import nono_py as _nono_module
except ImportError:  # pragma: no cover - environment dependent
    _nono_module = None  # type: ignore[assignment]

# ``agent_id`` is interpolated into log lines and workspace directory
# names; reject anything outside the safe character set up front so a
# hostile agent_id cannot traverse paths or inject control characters.
_AGENT_ID_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$")

# Output truncation marker mirroring the other providers' convention.
_OUTPUT_TRUNCATED_MARKER = "\n[...output truncated at byte limit]\n"

# Default interpreter used to run code passed to ``execute_code``.
_DEFAULT_INTERPRETER = "python"

# Per-stream output cap (bytes) for captured stdout/stderr.
_OUTPUT_MAX_BYTES = 1_048_576  # 1 MiB

# nono's ``sandboxed_exec`` returns exit code 124 when it kills a child
# that exceeded ``timeout_secs`` (a -N exit code means killed by signal N).
_TIMEOUT_EXIT_CODE = 124

# Interpreters the static code scanner can vet. ``execute_code`` writes the
# submitted source to a ``.py`` script and scans it with
# ``enforce_no_subprocess_execution`` (a Python-AST scanner) before running
# ``<interpreter> <script>``. That scanner only understands Python, so any
# other interpreter would execute unscanned code — ``execute_code`` fails
# closed for those and steers callers to ``run()`` instead.
_PYTHON_INTERPRETER_RE = re.compile(
    r"^(?:py|python|pypy)\d*(?:\.\d+)?$", re.IGNORECASE
)


def _is_python_interpreter(interpreter: str) -> bool:
    """Return ``True`` if *interpreter* names a Python interpreter."""
    if not interpreter:
        return False
    try:
        first = shlex.split(interpreter)[0]
    except ValueError:
        return False
    name = Path(first).name
    if name.lower().endswith(".exe"):
        name = name[:-4]
    return bool(_PYTHON_INTERPRETER_RE.match(name))


def _validate_agent_id(value: str) -> None:
    if not isinstance(value, str) or not _AGENT_ID_RE.match(value):
        raise ValueError(
            f"Invalid agent_id '{value}': must match "
            r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}"
        )


def _decode(data: Any) -> str:
    """Decode ``sandboxed_exec`` stdout/stderr (bytes) to text."""
    if isinstance(data, bytes):
        return data.decode("utf-8", errors="replace")
    return str(data) if data is not None else ""


def _truncate(text: str, max_bytes: int) -> str:
    """Truncate *text* to *max_bytes* UTF-8 bytes, appending a marker."""
    encoded = text.encode("utf-8", errors="replace")
    if len(encoded) <= max_bytes:
        return text
    clipped = encoded[:max_bytes].decode("utf-8", errors="replace")
    return clipped + _OUTPUT_TRUNCATED_MARKER


class _Session:
    """Durable per-session bundle (see module docstring)."""

    __slots__ = ("config", "evaluator", "workspace", "interpreter", "proxy")

    def __init__(
        self,
        config: NonoConfig,
        evaluator: Any | None,
        workspace: Path,
        interpreter: str,
        proxy: Any | None,
    ) -> None:
        self.config = config
        self.evaluator = evaluator
        self.workspace = workspace
        self.interpreter = interpreter
        self.proxy = proxy


class NonoSandboxProvider(SandboxProvider):
    """``SandboxProvider`` backed by the ``nono-py`` capability sandbox.

    Parameters
    ----------
    interpreter:
        Command used to run code submitted to :meth:`execute_code`
        (default ``"python"``). The submitted code is written to a file
        in the session workspace and executed as ``<interpreter>
        <script>`` so no shell quoting of the code is required.
    include_system_paths:
        Grant read access to standard system directories (and the running
        interpreter's prefix) so a sandboxed interpreter can load.
        Defaults to ``True``. Set ``False`` for fully self-contained
        commands that need no system libraries.

    Notes
    -----
    A session must not be destroyed while one of its executions is in
    flight: :meth:`execute_code` / :meth:`run` release the internal lock
    before the (potentially long) ``sandboxed_exec`` call, so a concurrent
    :meth:`destroy_session` may remove the workspace or shut down the
    proxy mid-execution. Serialize execute/destroy per session if you
    drive a single session from multiple threads.
    """

    def __init__(
        self,
        *,
        interpreter: str = _DEFAULT_INTERPRETER,
        include_system_paths: bool = True,
    ) -> None:
        self._interpreter = interpreter
        self._include_system_paths = include_system_paths

        self._unavailable_reason = self._compute_unavailable_reason()
        self._available = not self._unavailable_reason
        if not self._available:
            logger.info(self._unavailable_reason)

        # RLock because async variants delegate to sync and teardown may
        # overlap with registry reads.
        self._state_lock = threading.RLock()
        self._sessions: dict[tuple[str, str], _Session] = {}

    # Availability

    @staticmethod
    def _compute_unavailable_reason() -> str:
        if _nono_module is None:
            return (
                "nono-py is not installed. Install it with "
                "'pip install agt-sandbox[nono]' (Linux/macOS only)."
            )
        try:
            if not _nono_module.is_supported():
                info = ""
                try:
                    info = _nono_module.support_info().details
                except Exception:  # pragma: no cover - defensive
                    pass
                return (
                    "nono sandboxing is not supported on this host"
                    + (f": {info}" if info else "")
                    + ". Requires Linux (kernel 5.13+, Landlock) or macOS."
                )
        except Exception as exc:  # pragma: no cover - defensive
            return f"nono availability probe failed: {exc}"
        return ""

    def is_available(self) -> bool:
        return self._available

    # SandboxProvider interface

    def create_session(
        self,
        agent_id: str,
        policy: Any | None = None,
        config: SandboxConfig | None = None,
    ) -> SessionHandle:
        if not self._available:
            raise RuntimeError(
                "nono unavailable: "
                + (self._unavailable_reason or "unknown reason")
            )
        _validate_agent_id(agent_id)

        session_id = uuid.uuid4().hex[:8]
        base_cfg = config or SandboxConfig()
        nono_cfg = NonoConfig.from_sandbox_config(
            base_cfg, include_system_paths=self._include_system_paths
        )

        evaluator = None
        if policy is not None:
            # nono has no in-sandbox tool-registration channel, so a
            # tool_allowlist cannot be enforced inside the sandbox.
            # Silently dropping a security control is the wrong default
            # (Hyperlight fails closed here), so refuse rather than run a
            # session that ignores the policy's allowlist.
            tool_allow = list(getattr(policy, "tool_allowlist", []) or [])
            if tool_allow:
                raise ValueError(
                    "nono does not support tool allowlisting — the sandbox "
                    "exposes no tool-registration channel, so a non-empty "
                    f"policy.tool_allowlist ({sorted(tool_allow)}) cannot be "
                    "enforced. Refusing to create a session that would "
                    "silently ignore it. Remove tool_allowlist from the "
                    "policy or use a provider that supports tools (e.g. "
                    "Hyperlight)."
                )
            nono_cfg = nono_config_from_policy(policy, base=nono_cfg)
            evaluator = self._build_evaluator(policy)

        # Per-session workspace: scripts go in ``scripts/`` (granted
        # read-only to the sandbox) and persistent output in ``output/``
        # (granted read-write). The output directory is what survives
        # across one-shot executions in the same session.
        workspace = Path(
            tempfile.mkdtemp(prefix=f"nono-{agent_id}-{session_id}-")
        )
        scripts_dir = workspace / "scripts"
        output_dir = workspace / "output"
        scripts_dir.mkdir(parents=True, exist_ok=True)
        output_dir.mkdir(parents=True, exist_ok=True)

        if str(scripts_dir) not in nono_cfg.readonly_paths:
            nono_cfg.readonly_paths.append(str(scripts_dir))
        if str(output_dir) not in nono_cfg.readwrite_paths:
            nono_cfg.readwrite_paths.append(str(output_dir))

        proxy = None
        if nono_cfg.allow_outbound:
            try:
                proxy = self._start_proxy(nono_cfg)
            except Exception as exc:
                shutil.rmtree(workspace, ignore_errors=True)
                raise RuntimeError(
                    f"Failed to start nono network proxy: {exc}"
                ) from exc

        session = _Session(
            config=nono_cfg,
            evaluator=evaluator,
            workspace=workspace,
            interpreter=self._interpreter,
            proxy=proxy,
        )
        with self._state_lock:
            self._sessions[(agent_id, session_id)] = session

        logger.info(
            "nono session created: agent=%s session=%s allow_outbound=%s "
            "hosts=%s",
            agent_id,
            session_id,
            nono_cfg.allow_outbound,
            nono_cfg.allowed_hosts or ("<unrestricted>" if proxy else "<none>"),
        )
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
            session = self._sessions.get(key)
        if session is None:
            raise RuntimeError(
                f"No active session for agent '{agent_id}' with "
                f"session_id '{session_id}'. Call create_session() first."
            )

        # ``execute_code`` writes a Python script and statically scans it.
        # The scanner only understands Python, so refuse to run any other
        # interpreter here rather than execute unscanned code (use run()
        # with an explicit command for non-Python languages).
        if not _is_python_interpreter(session.interpreter):
            raise ValueError(
                "execute_code only supports a Python interpreter; the "
                f"configured interpreter is '{session.interpreter}'. The "
                "static code scanner is Python-AST based and cannot vet "
                "non-Python code, so running it would give a false sense "
                "of safety. Use run() with an explicit command for other "
                "languages."
            )

        # Policy gate — runs entirely on the host before any sandbox is
        # forked, so a denied policy never reaches nono.
        if session.evaluator is not None:
            eval_ctx: dict[str, Any] = {
                "agent_id": agent_id,
                "action": "execute",
                "code": code,
            }
            if context:
                eval_ctx.update(context)
            decision = session.evaluator.evaluate(eval_ctx)
            if not getattr(decision, "allowed", False):
                reason = getattr(decision, "reason", "policy denied")
                raise PermissionError(f"Policy denied: {reason}")

        enforce_no_subprocess_execution(code)

        execution_id = uuid.uuid4().hex[:8]

        # Write the submitted code to a file in the read-only scripts
        # directory and run ``<interpreter> <script>``. Writing to a file
        # avoids any shell-quoting of the code into the command.
        script_path = session.workspace / "scripts" / f"{execution_id}.py"
        script_path.write_text(code, encoding="utf-8")

        command = [session.interpreter, str(script_path)]
        result = self._spawn(session, command, context=context)

        status = (
            ExecutionStatus.COMPLETED
            if result.success
            else ExecutionStatus.FAILED
        )
        return ExecutionHandle(
            execution_id=execution_id,
            agent_id=agent_id,
            session_id=session_id,
            status=status,
            result=result,
        )

    def run_once(
        self,
        agent_id: str,
        code: str,
        *,
        policy: Any | None = None,
        config: SandboxConfig | None = None,
        context: dict[str, Any] | None = None,
    ) -> ExecutionHandle:
        """Execute *code* in a fresh one-shot sandbox, no session to manage.

        Convenience wrapper that creates a session, runs the code, and
        destroys the session in a single call. Use this when you do not
        need cross-call state — every invocation is fully isolated and the
        workspace (including ``output/``) is removed afterwards.

        The same governance applies as :meth:`execute_code`: the host-side
        policy gate and the static code scan run before nono is invoked.

        For repeated executions that must share the persistent ``output/``
        directory, use :meth:`create_session` + :meth:`execute_code` and
        keep the ``session_id``.
        """
        handle = self.create_session(agent_id, policy=policy, config=config)
        try:
            return self.execute_code(
                handle.agent_id,
                handle.session_id,
                code,
                context=context,
            )
        finally:
            self.destroy_session(handle.agent_id, handle.session_id)

    async def run_once_async(
        self,
        agent_id: str,
        code: str,
        *,
        policy: Any | None = None,
        config: SandboxConfig | None = None,
        context: dict[str, Any] | None = None,
    ) -> ExecutionHandle:
        """Async variant of :meth:`run_once`."""
        return await asyncio.to_thread(
            self.run_once,
            agent_id,
            code,
            policy=policy,
            config=config,
            context=context,
        )

    def destroy_session(self, agent_id: str, session_id: str) -> None:
        key = (agent_id, session_id)
        with self._state_lock:
            session = self._sessions.pop(key, None)
        if session is None:
            return
        # Shut the long-lived proxy down before removing the workspace so
        # its background thread does not outlive the session.
        if session.proxy is not None:
            try:
                session.proxy.shutdown()
            except Exception as exc:  # pragma: no cover - defensive
                logger.warning(
                    "Failed to shut down nono proxy for %s/%s: %s",
                    agent_id,
                    session_id,
                    exc,
                )
        try:
            shutil.rmtree(session.workspace, ignore_errors=True)
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning(
                "Failed to remove nono workspace for %s/%s: %s",
                agent_id,
                session_id,
                exc,
            )
        logger.info(
            "nono session destroyed: agent=%s session=%s", agent_id, session_id
        )

    def get_session_status(
        self, agent_id: str, session_id: str
    ) -> SessionStatus:
        with self._state_lock:
            if (agent_id, session_id) in self._sessions:
                return SessionStatus.READY
        return SessionStatus.DESTROYED

    # Low-level run

    def run(
        self,
        agent_id: str,
        command: list[str],
        config: SandboxConfig | None = None,
        *,
        session_id: str | None = None,
    ) -> SandboxResult:
        """Fork a one-shot nono sandbox running *command*.

        When *session_id* is given (or a single session exists for
        *agent_id*), the session's resolved :class:`NonoConfig`,
        workspace, and proxy are reused. Otherwise an ephemeral config is
        built from *config* (or defaults) and a throwaway workspace (plus
        proxy, if egress is enabled) is created and cleaned up around the
        call.
        """
        if not self._available:
            return SandboxResult(
                success=False,
                exit_code=-1,
                stderr=self._unavailable_reason or "nono unavailable",
            )
        if not command:
            return SandboxResult(
                success=False, exit_code=-1, stderr="empty command"
            )

        session = self._find_session(agent_id, session_id)
        if session is not None:
            return self._spawn(session, command)

        # Ephemeral one-shot: build a transient session bundle.
        _validate_agent_id(agent_id)
        base_cfg = config or SandboxConfig()
        nono_cfg = NonoConfig.from_sandbox_config(
            base_cfg, include_system_paths=self._include_system_paths
        )
        workspace = Path(tempfile.mkdtemp(prefix=f"nono-{agent_id}-oneshot-"))
        proxy = None
        try:
            if nono_cfg.allow_outbound:
                proxy = self._start_proxy(nono_cfg)
            ephemeral = _Session(
                config=nono_cfg,
                evaluator=None,
                workspace=workspace,
                interpreter=self._interpreter,
                proxy=proxy,
            )
            return self._spawn(ephemeral, command)
        finally:
            if proxy is not None:
                try:
                    proxy.shutdown()
                except Exception:  # pragma: no cover - defensive
                    pass
            shutil.rmtree(workspace, ignore_errors=True)

    # Helpers

    def _find_session(
        self, agent_id: str, session_id: str | None
    ) -> _Session | None:
        with self._state_lock:
            if session_id is not None:
                return self._sessions.get((agent_id, session_id))
            for (aid, _sid), sess in self._sessions.items():
                if aid == agent_id:
                    return sess
        return None

    def _build_evaluator(self, policy: Any) -> Any | None:
        """Construct a policy evaluator, or ``None`` if unavailable."""
        try:
            from agent_os.policies.evaluator import PolicyEvaluator
        except ImportError:
            logger.warning(
                "agent-os-kernel not installed — policy evaluation "
                "unavailable, session runs ungated"
            )
            return None
        except Exception as exc:  # pragma: no cover - defensive
            raise RuntimeError(
                f"Failed to import PolicyEvaluator: {exc}"
            ) from exc
        try:
            return PolicyEvaluator(policies=[policy])
        except Exception as exc:
            raise RuntimeError(
                f"Failed to initialize PolicyEvaluator: {exc}"
            ) from exc

    def _start_proxy(self, cfg: NonoConfig) -> Any:
        """Start a nono filtering proxy for *cfg*'s egress policy."""
        nono = _nono_module
        assert nono is not None  # guarded by availability checks
        if cfg.allow_unrestricted_egress and not cfg.allowed_hosts:
            proxy_config = nono.ProxyConfig(allow_all_hosts=True)
        else:
            proxy_config = nono.ProxyConfig(allowed_hosts=list(cfg.allowed_hosts))
        return nono.start_proxy(proxy_config)

    @staticmethod
    def _resolve_command(command: list[str]) -> tuple[list[str], str | None]:
        """Resolve *command*'s program to an absolute path.

        ``sandboxed_exec`` runs the child with ``inherit_env=False``, so
        there is no ``PATH`` inside the sandbox to resolve a bare program
        name against. Resolution therefore happens here, in the
        unsandboxed parent: ``shutil.which`` finds the program on the host
        ``PATH``, and a bare Python interpreter that is not on ``PATH``
        (common on macOS, where ``python`` may be absent) falls back to
        the running interpreter. The program's directory is returned so
        the caller can grant the sandbox read access to it.
        """
        if not command:
            return command, None
        prog = command[0]
        candidate = Path(prog)
        if candidate.is_absolute():
            resolved = str(candidate)
        else:
            which = shutil.which(prog)
            if which:
                resolved = which
            elif _is_python_interpreter(prog):
                resolved = sys.executable
            else:
                # Leave unresolved; nono surfaces a clear "not found" error.
                return command, None
        try:
            parent = str(Path(resolved).resolve().parent)
        except (OSError, ValueError):  # pragma: no cover - defensive
            parent = None
        return [resolved, *command[1:]], parent

    def _build_caps(
        self, session: _Session, extra_read_dirs: list[str] | None = None
    ) -> Any:
        """Build the nono ``CapabilitySet`` for *session*.

        System paths are granted read-only and missing ones are skipped
        (they vary by host); explicitly requested mounts must exist and a
        missing one surfaces as a ``FileNotFoundError``. *extra_read_dirs*
        (e.g. the resolved interpreter's directory) are granted read-only,
        skipping any that are missing. Network is bound to the session
        proxy when egress is enabled, otherwise blocked.
        """
        nono = _nono_module
        assert nono is not None  # guarded by availability checks
        cfg = session.config
        caps = nono.CapabilitySet()
        mode = nono.AccessMode

        if cfg.include_system_paths:
            for sys_path in default_system_paths():
                with contextlib.suppress(FileNotFoundError):
                    caps.allow_path(sys_path, mode.READ)

        for sys_path in extra_read_dirs or []:
            with contextlib.suppress(FileNotFoundError):
                caps.allow_path(sys_path, mode.READ)

        for path in cfg.readonly_paths:
            caps.allow_path(path, mode.READ)
        for path in cfg.readwrite_paths:
            caps.allow_path(path, mode.READ_WRITE)

        if session.proxy is not None:
            caps.proxy_only(session.proxy)
        else:
            caps.block_network()
        return caps

    def _build_env(
        self, session: _Session, context: dict[str, Any] | None
    ) -> list[tuple[str, str]]:
        """Assemble the child's environment (no parent inheritance).

        The guest environment is the sanitised ``env_vars`` plus an
        optional ``NONO_CONTEXT`` JSON blob. When the session has a proxy,
        its env vars (``HTTP_PROXY`` etc.) are merged in via
        ``proxy.sandbox_env`` so the child routes egress through it.
        """
        extra: list[tuple[str, str]] = list(
            session.config.sanitized_env().items()
        )
        if context is not None:
            try:
                extra.append(("NONO_CONTEXT", json.dumps(context)))
            except (TypeError, ValueError):
                logger.warning(
                    "execution context is not JSON-serialisable; dropping"
                )
        if session.proxy is not None:
            return list(session.proxy.sandbox_env(extra))
        return extra

    def _spawn(
        self,
        session: _Session,
        command: list[str],
        *,
        context: dict[str, Any] | None = None,
    ) -> SandboxResult:
        """Build caps + env, fork the nono sandbox, and collect the result."""
        nono = _nono_module
        if nono is None:  # pragma: no cover - guarded earlier
            return SandboxResult(
                success=False, exit_code=-1, stderr="nono-py not installed"
            )

        start = time.monotonic()
        # Resolve the program to an absolute path in the unsandboxed parent
        # (the child has no PATH) and grant read access to its directory.
        command, prog_dir = self._resolve_command(command)
        extra_read_dirs = [prog_dir] if prog_dir else None
        try:
            caps = self._build_caps(session, extra_read_dirs=extra_read_dirs)
        except FileNotFoundError as exc:
            return SandboxResult(
                success=False,
                exit_code=-1,
                stderr=f"sandbox mount path unavailable: {exc}",
            )
        except Exception as exc:  # pragma: no cover - defensive
            return SandboxResult(
                success=False,
                exit_code=-1,
                stderr=f"failed to build nono capabilities: {exc}",
            )

        env_items = self._build_env(session, context)
        timeout = session.config.timeout_seconds
        # Run with the writable output directory as cwd so relative writes
        # land in the persistent workspace.
        cwd = str(session.workspace / "output")

        try:
            result = nono.sandboxed_exec(
                caps,
                command,
                cwd=cwd,
                timeout_secs=timeout,
                env=env_items,
                inherit_env=False,
            )
        except Exception as exc:
            return SandboxResult(
                success=False,
                exit_code=-1,
                stderr=f"nono sandboxed_exec failed: {exc}",
                duration_seconds=round(time.monotonic() - start, 3),
            )

        duration = time.monotonic() - start
        stdout = _decode(getattr(result, "stdout", b""))
        stderr = _decode(getattr(result, "stderr", b""))
        exit_code = int(getattr(result, "exit_code", -1))
        killed = exit_code == _TIMEOUT_EXIT_CODE
        kill_reason = (
            f"Execution exceeded nono timeout of {timeout}s" if killed else ""
        )
        return SandboxResult(
            success=(not killed and exit_code == 0),
            exit_code=exit_code,
            stdout=_truncate(stdout, _OUTPUT_MAX_BYTES),
            stderr=_truncate(stderr, _OUTPUT_MAX_BYTES),
            duration_seconds=round(duration, 3),
            killed=killed,
            kill_reason=kill_reason,
        )
