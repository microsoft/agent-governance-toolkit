# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""MXC-backed implementation of :class:`SandboxProvider`.

`MXC <https://github.com/microsoft/mxc>`_ (Microsoft eXecution Container)
runs untrusted code behind one of several OS-native or VM containment
backends, configured by a single JSON document and driven by a native
binary (``wxc-exec`` on Windows, ``lxc-exec`` on Linux, ``mxc-exec-mac``
on macOS).  MXC publishes no Python SDK, so this provider integrates by
spawning that binary as a subprocess and feeding it a config document
rendered from :class:`MxcConfig`.

Session model
-------------
MXC's stable native binary is *one-shot*: it provisions a sandbox, runs
the configured ``process.commandLine``, streams its stdio, and tears the
sandbox down on exit (provision → start → exec → stop → deprovision).
There is no long-lived, reusable guest the way a Docker container or a
Hyperlight micro-VM persists across calls.

To still satisfy the session-based :class:`SandboxProvider` contract,
this provider treats a *session* as a durable **bundle** — the resolved
:class:`MxcConfig`, the policy evaluator, and a per-session workspace
directory — rather than a running process.  Each :meth:`execute_code` (or
:meth:`run`) call spawns a fresh one-shot MXC sandbox using that bundle.
Consequently **guest state does not persist across executions in the same
session**: in-memory variables, interpreter state, and writes outside the
session's read-write workspace are discarded when each invocation exits.
Callers that need cross-call persistence should write to the session's
read-write output directory, which is preserved on the host between
executions.

(MXC does expose a stateful provision/exec/stop lifecycle through its
TypeScript SDK and the ``0.7.0-dev`` schema; wiring that path is left as a
future enhancement and is out of scope for this binary-driven provider.)
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import platform
import re
import shlex
import shutil
import subprocess
import tempfile
import threading
import time
import uuid
from pathlib import Path
from typing import Any

from agent_sandbox.code_scanner import enforce_no_subprocess_execution
from agent_sandbox.mxc_sandbox_provider.config import (
    MxcConfig,
    mxc_config_from_policy,
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

# Platform → default native binary name. Auto-detected on ``PATH`` when
# the caller does not pass an explicit ``binary_path``.
_PLATFORM_BINARIES: dict[str, tuple[str, ...]] = {
    "Windows": ("wxc-exec.exe", "wxc-exec"),
    "Linux": ("lxc-exec",),
    "Darwin": ("mxc-exec-mac",),
}

# Environment variable that overrides binary discovery.
_BINARY_ENV_VAR = "MXC_BINARY"

# ``agent_id`` is interpolated into log lines, workspace directory names,
# and config files; reject anything outside the safe character set up
# front so a hostile agent_id cannot traverse paths or inject control
# characters.
_AGENT_ID_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$")

# Output truncation marker mirroring the Docker provider's convention.
_OUTPUT_TRUNCATED_MARKER = "\n[...output truncated at byte limit]\n"

# Default interpreter used to run code passed to ``execute_code``.
_DEFAULT_INTERPRETER = "python"

# Grace period added to the subprocess timeout so MXC's own teardown can
# run before we hard-kill the process group.
_TEARDOWN_GRACE_SECONDS = 5.0

# Per-stream output cap (bytes) for captured stdout/stderr.
_OUTPUT_MAX_BYTES = 1_048_576  # 1 MiB

# OS-essential environment variables forwarded to the MXC *runner*
# process (wxc-exec / lxc-exec / mxc-exec-mac) so it can function — these
# go to the trusted, operator-installed binary, NOT into the sandboxed
# guest (the guest's environment is controlled separately by MXC via the
# config's ``env`` field). The runner needs them for things like its
# state file (Windows DACL fallback writes under LOCALAPPDATA) and
# temp-dir resolution. We forward an explicit allowlist rather than the
# whole environment so host secrets are never handed to the launcher.
_RUNNER_ENV_PASSTHROUGH: dict[str, tuple[str, ...]] = {
    "Windows": (
        "PATH",
        "SYSTEMROOT",
        "SYSTEMDRIVE",
        "WINDIR",
        "COMSPEC",
        "PATHEXT",
        "LOCALAPPDATA",
        "APPDATA",
        "USERPROFILE",
        "TEMP",
        "TMP",
        "NUMBER_OF_PROCESSORS",
        "PROCESSOR_ARCHITECTURE",
    ),
    "Linux": ("PATH", "HOME", "TMPDIR", "USER", "LANG", "LC_ALL"),
    "Darwin": ("PATH", "HOME", "TMPDIR", "USER", "LANG", "LC_ALL"),
}


def _runner_env() -> dict[str, str]:
    """Build the environment for the MXC *runner* process.

    Forwards **only** the OS-essential variables the trusted runner
    needs (per-platform allowlist). The parent's full environment is
    never inherited and — critically — no guest/policy environment is
    mixed in here: guest variables belong in the sandbox config's
    ``process.environment`` (see :meth:`MxcConfig.to_mxc_json`), not in
    the launcher's own process environment. Keeping them separate stops
    caller context (``MXC_CONTEXT``) or policy env from leaking into the
    trusted binary.
    """
    names = _RUNNER_ENV_PASSTHROUGH.get(platform.system(), ("PATH",))
    return {
        name: os.environ[name]
        for name in names
        if name in os.environ
    }


def _validate_agent_id(value: str) -> None:
    if not isinstance(value, str) or not _AGENT_ID_RE.match(value):
        raise ValueError(
            f"Invalid agent_id '{value}': must match "
            r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}"
        )


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


def _truncate(text: str, max_bytes: int) -> str:
    """Truncate *text* to *max_bytes* UTF-8 bytes, appending a marker."""
    encoded = text.encode("utf-8", errors="replace")
    if len(encoded) <= max_bytes:
        return text
    clipped = encoded[:max_bytes].decode("utf-8", errors="replace")
    return clipped + _OUTPUT_TRUNCATED_MARKER


class _Session:
    """Durable per-session bundle (see module docstring)."""

    __slots__ = ("config", "evaluator", "workspace", "interpreter")

    def __init__(
        self,
        config: MxcConfig,
        evaluator: Any | None,
        workspace: Path,
        interpreter: str,
    ) -> None:
        self.config = config
        self.evaluator = evaluator
        self.workspace = workspace
        self.interpreter = interpreter


class MxcSandboxProvider(SandboxProvider):
    """``SandboxProvider`` backed by the native MXC binary.

    Parameters
    ----------
    binary_path:
        Absolute path to the MXC native binary. When ``None``, the
        provider resolves it from the ``MXC_BINARY`` environment variable
        and then from ``PATH`` using the platform-appropriate name
        (``wxc-exec`` / ``lxc-exec`` / ``mxc-exec-mac``).
    backend:
        Default containment backend for sessions that do not override it
        via config/policy. ``None`` lets MXC pick the platform default.
    experimental:
        Pass MXC's ``--experimental`` flag. Forced on automatically when
        an experimental backend is selected.
    interpreter:
        Command used to run code submitted to :meth:`execute_code`
        (default ``"python"``). The submitted code is written to a file
        in the session workspace and executed as ``<interpreter>
        <script>`` so no shell quoting of the code is required.
    debug:
        Pass MXC's ``--debug`` flag for verbose diagnostics.
    """

    def __init__(
        self,
        binary_path: str | None = None,
        *,
        backend: str | None = None,
        experimental: bool = False,
        interpreter: str = _DEFAULT_INTERPRETER,
        debug: bool = False,
    ) -> None:
        self._backend = backend
        self._experimental = experimental
        self._interpreter = interpreter
        self._debug = debug

        # Validate the default backend eagerly via a throwaway config so
        # misconfiguration surfaces at construction, not first use.
        if backend is not None:
            MxcConfig(backend=backend)

        self._binary_path = self._resolve_binary(binary_path)
        self._available = self._binary_path is not None
        self._unavailable_reason = (
            ""
            if self._available
            else (
                "MXC native binary not found. Set MXC_BINARY, pass "
                "binary_path=..., or place "
                f"{self._expected_binary_names()} on PATH."
            )
        )
        if not self._available:
            logger.info(self._unavailable_reason)

        # Session bookkeeping. RLock because async variants delegate to
        # sync and teardown may overlap with registry reads.
        self._state_lock = threading.RLock()
        self._sessions: dict[tuple[str, str], _Session] = {}

    # ------------------------------------------------------------------
    # Binary discovery
    # ------------------------------------------------------------------

    @staticmethod
    def _expected_binary_names() -> tuple[str, ...]:
        return _PLATFORM_BINARIES.get(platform.system(), ())

    def _resolve_binary(self, binary_path: str | None) -> str | None:
        """Locate the MXC binary, returning an absolute path or ``None``."""
        if binary_path:
            candidate = Path(binary_path)
            if candidate.is_file() and os.access(candidate, os.X_OK):
                return str(candidate.resolve())
            logger.warning(
                "binary_path '%s' is not an executable file", binary_path
            )
            return None

        env_path = os.environ.get(_BINARY_ENV_VAR)
        if env_path:
            candidate = Path(env_path)
            if candidate.is_file() and os.access(candidate, os.X_OK):
                return str(candidate.resolve())
            logger.warning(
                "%s='%s' is not an executable file", _BINARY_ENV_VAR, env_path
            )

        for name in self._expected_binary_names():
            found = shutil.which(name)
            if found:
                return str(Path(found).resolve())
        return None

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def binary_path(self) -> str | None:
        return self._binary_path

    @property
    def backend(self) -> str | None:
        return self._backend

    # ------------------------------------------------------------------
    # SandboxProvider interface
    # ------------------------------------------------------------------

    def is_available(self) -> bool:
        return self._available

    def create_session(
        self,
        agent_id: str,
        policy: Any | None = None,
        config: SandboxConfig | None = None,
    ) -> SessionHandle:
        if not self._available:
            raise RuntimeError(
                "MXC unavailable: "
                + (self._unavailable_reason or "unknown reason")
            )
        _validate_agent_id(agent_id)

        session_id = uuid.uuid4().hex[:8]
        base_cfg = config or SandboxConfig()
        mxc_cfg = MxcConfig.from_sandbox_config(
            base_cfg, backend=self._backend, experimental=self._experimental
        )

        evaluator = None
        if policy is not None:
            # MXC's native binary has no tool-registration channel, so a
            # tool_allowlist cannot be enforced inside the sandbox.
            # Silently dropping a security control is the wrong default
            # (Hyperlight fails closed here), so refuse rather than run a
            # session that ignores the policy's allowlist.
            tool_allow = list(getattr(policy, "tool_allowlist", []) or [])
            if tool_allow:
                raise ValueError(
                    "MXC does not support tool allowlisting — the native "
                    "binary exposes no tool-registration channel, so a "
                    "non-empty policy.tool_allowlist "
                    f"({sorted(tool_allow)}) cannot be enforced. Refusing "
                    "to create a session that would silently ignore it. "
                    "Remove tool_allowlist from the policy or use a "
                    "provider that supports tools (e.g. Hyperlight)."
                )
            mxc_cfg = mxc_config_from_policy(policy, base=mxc_cfg)
            evaluator = self._build_evaluator(policy)

        # Per-session workspace: scripts go in ``scripts/`` (exposed
        # read-only to the sandbox) and persistent output in ``output/``
        # (exposed read-write). The output directory is what survives
        # across one-shot executions in the same session.
        workspace = Path(
            tempfile.mkdtemp(prefix=f"mxc-{agent_id}-{session_id}-")
        )
        (workspace / "scripts").mkdir(parents=True, exist_ok=True)
        output_dir = workspace / "output"
        output_dir.mkdir(parents=True, exist_ok=True)

        scripts_dir = str(workspace / "scripts")
        if scripts_dir not in mxc_cfg.readonly_paths:
            mxc_cfg.readonly_paths.append(scripts_dir)
        if str(output_dir) not in mxc_cfg.readwrite_paths:
            mxc_cfg.readwrite_paths.append(str(output_dir))

        session = _Session(
            config=mxc_cfg,
            evaluator=evaluator,
            workspace=workspace,
            interpreter=self._interpreter,
        )
        with self._state_lock:
            self._sessions[(agent_id, session_id)] = session

        logger.info(
            "MXC session created: agent=%s session=%s backend=%s "
            "allow_outbound=%s",
            agent_id,
            session_id,
            mxc_cfg.backend or "<platform-default>",
            mxc_cfg.allow_outbound,
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
        # spawned, so a denied policy never reaches MXC.
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
        # directory and run ``<interpreter> <script>``. Writing to a
        # file avoids any shell-quoting of the code into commandLine.
        script_path = session.workspace / "scripts" / f"{execution_id}.py"
        script_path.write_text(code, encoding="utf-8")

        command = [session.interpreter, str(script_path)]
        if context is not None:
            # Expose context to the guest via an environment variable it
            # can json.loads(), without mutating the submitted code.
            session = self._with_context_env(session, context)

        result = self._spawn(session, command)

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
        policy gate and the static code scan run before MXC is spawned.

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
        # MXC sandboxes are one-shot and already torn down after each
        # invocation, so there is no live process to stop — we only need
        # to remove the host-side workspace.
        try:
            shutil.rmtree(session.workspace, ignore_errors=True)
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning(
                "Failed to remove MXC workspace for %s/%s: %s",
                agent_id,
                session_id,
                exc,
            )
        logger.info(
            "MXC session destroyed: agent=%s session=%s", agent_id, session_id
        )

    def get_session_status(
        self, agent_id: str, session_id: str
    ) -> SessionStatus:
        with self._state_lock:
            if (agent_id, session_id) in self._sessions:
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
        """Spawn a one-shot MXC sandbox running *command*.

        When *session_id* is given (or a single session exists for
        *agent_id*), the session's resolved :class:`MxcConfig` and
        workspace are reused. Otherwise an ephemeral config is built
        from *config* (or defaults) and a throwaway workspace is created
        and cleaned up around the call.
        """
        if not self._available:
            return SandboxResult(
                success=False,
                exit_code=-1,
                stderr=self._unavailable_reason or "MXC unavailable",
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
        mxc_cfg = MxcConfig.from_sandbox_config(
            base_cfg, backend=self._backend, experimental=self._experimental
        )
        workspace = Path(tempfile.mkdtemp(prefix=f"mxc-{agent_id}-oneshot-"))
        try:
            ephemeral = _Session(
                config=mxc_cfg,
                evaluator=None,
                workspace=workspace,
                interpreter=self._interpreter,
            )
            return self._spawn(ephemeral, command)
        finally:
            shutil.rmtree(workspace, ignore_errors=True)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

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

    @staticmethod
    def _with_context_env(session: _Session, context: dict[str, Any]) -> _Session:
        """Return a shallow copy of *session* with ``MXC_CONTEXT`` set.

        The original session's config is not mutated; a copy carrying the
        serialised context in its environment is used for this single
        invocation.
        """
        cfg = session.config
        new_env = dict(cfg.env_vars)
        try:
            new_env["MXC_CONTEXT"] = json.dumps(context)
        except (TypeError, ValueError):
            logger.warning("execution context is not JSON-serialisable; dropping")
            return session
        new_cfg = MxcConfig(
            version=cfg.version,
            backend=cfg.backend,
            readonly_paths=list(cfg.readonly_paths),
            readwrite_paths=list(cfg.readwrite_paths),
            allow_outbound=cfg.allow_outbound,
            allowed_hosts=list(cfg.allowed_hosts),
            allow_unrestricted_egress=cfg.allow_unrestricted_egress,
            timeout_ms=cfg.timeout_ms,
            experimental=cfg.experimental,
            env_vars=new_env,
            extra_config=dict(cfg.extra_config),
        )
        return _Session(
            config=new_cfg,
            evaluator=session.evaluator,
            workspace=session.workspace,
            interpreter=session.interpreter,
        )

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

    def _build_argv(self, config_path: Path, cfg: MxcConfig) -> list[str]:
        """Assemble the native-binary argv for a one-shot invocation."""
        assert self._binary_path is not None  # guarded by _available
        argv = [self._binary_path]
        if cfg.needs_experimental:
            argv.append("--experimental")
        if self._debug:
            argv.append("--debug")
        argv.append(str(config_path))
        return argv

    def _spawn(self, session: _Session, command: list[str]) -> SandboxResult:
        """Render config, spawn the MXC binary, and collect the result."""
        cfg = session.config
        command_line = shlex.join(command)
        doc = cfg.to_mxc_json(command_line)

        config_path = session.workspace / f"config-{uuid.uuid4().hex[:8]}.json"
        config_path.write_text(json.dumps(doc), encoding="utf-8")

        argv = self._build_argv(config_path, cfg)
        # Hard timeout = MXC's own budget plus a grace period for its
        # provision/teardown so we only kill if MXC itself wedges.
        hard_timeout = cfg.timeout_ms / 1000.0 + _TEARDOWN_GRACE_SECONDS
        max_bytes = _OUTPUT_MAX_BYTES

        # Build the runner's environment: the OS-essential allowlist
        # only. This is the environment of the trusted MXC binary itself
        # (which needs e.g. LOCALAPPDATA on Windows for its state file),
        # NOT the sandboxed guest. The guest's environment is governed
        # separately and rendered into the config document's
        # ``process.environment`` by ``to_mxc_json`` (and sanitised
        # there). The parent's full environment is never inherited and
        # guest/policy env never reaches the launcher.
        child_env = _runner_env()

        start = time.monotonic()
        killed = False
        kill_reason = ""
        try:
            proc = subprocess.run(  # noqa: S603 - argv is fully constructed, no shell
                argv,
                capture_output=True,
                timeout=hard_timeout,
                check=False,
                env=child_env,
                cwd=str(session.workspace),
            )
            stdout = proc.stdout.decode("utf-8", errors="replace")
            stderr = proc.stderr.decode("utf-8", errors="replace")
            exit_code = proc.returncode
        except subprocess.TimeoutExpired as exc:
            killed = True
            kill_reason = (
                f"Execution exceeded MXC timeout of {cfg.timeout_ms}ms "
                f"(+{_TEARDOWN_GRACE_SECONDS}s grace)"
            )
            stdout = (
                exc.stdout.decode("utf-8", errors="replace")
                if isinstance(exc.stdout, bytes)
                else (exc.stdout or "")
            )
            stderr = (
                exc.stderr.decode("utf-8", errors="replace")
                if isinstance(exc.stderr, bytes)
                else (exc.stderr or "")
            )
            exit_code = -1
        except FileNotFoundError:
            return SandboxResult(
                success=False,
                exit_code=-1,
                stderr=f"MXC binary not found at '{self._binary_path}'",
            )
        finally:
            # The config file may carry mount layout; remove it eagerly.
            try:
                config_path.unlink(missing_ok=True)
            except OSError:  # pragma: no cover - defensive
                pass

        duration = time.monotonic() - start
        return SandboxResult(
            success=(not killed and exit_code == 0),
            exit_code=exit_code,
            stdout=_truncate(stdout, max_bytes),
            stderr=_truncate(stderr, max_bytes),
            duration_seconds=round(duration, 3),
            killed=killed,
            kill_reason=kill_reason,
        )
