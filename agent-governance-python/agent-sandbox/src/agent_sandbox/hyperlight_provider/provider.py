# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Hyperlight-backed implementation of :class:`SandboxProvider`.

Each call to :meth:`HyperLightSandboxProvider.create_session` constructs
exactly one upstream ``hyperlight_sandbox.Sandbox`` and stores it under
``(agent_id, session_id)``.  Subsequent ``execute_code`` calls on the
same session reuse the same sandbox — guest interpreter state, ``/output``
contents, and any in-memory variables persist across calls. Destroying
the session drops the sandbox; re-creating with the same id starts fresh.

Tool and network capabilities are bound at session-construction time:

* ``policy.tool_allowlist`` is iterated and ``Sandbox.register_tool`` is
  called once per allowlisted name found in ``self._tools``. Tools the
  provider knows about but the policy does not allow are simply not
  handed to the guest.
* ``policy.network_allowlist`` is iterated and ``Sandbox.allow_domain``
  is called once per entry. An empty / missing allowlist means the guest
  has zero network capability.

Because capabilities are session-scoped, mutating the policy mid-session
does **not** change what the guest can reach. To change the capability
set, destroy the session and create a new one.
"""

from __future__ import annotations

import asyncio
import importlib
import logging
import queue
import re
import threading
import time
import uuid
from concurrent.futures import Future
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable

from agent_sandbox.hyperlight_provider.config import (
    HyperlightConfig,
    hyperlight_config_from_policy,
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

# ``agent_id`` is interpolated into log lines and snapshot ids; reject
# anything outside the safe character set up front so a hostile agent_id
# cannot inject newlines or control characters.
_AGENT_ID_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$")


def _validate_agent_id(value: str) -> None:
    if not isinstance(value, str) or not _AGENT_ID_RE.match(value):
        raise ValueError(
            f"Invalid agent_id '{value}': must match "
            r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}"
        )


class HyperlightBackend(str, Enum):
    """Convenience enum for callers that prefer typed selectors over
    plain strings. Equivalent to passing the matching string to
    :class:`HyperlightConfig`.
    """

    WASM = "wasm"
    HYPERLIGHTJS = "hyperlightjs"
    NANVIX = "nanvix"


@dataclass
class SnapshotHandle:
    """Returned by :meth:`HyperLightSandboxProvider.snapshot_session`.

    Snapshots live in process memory; destroying the session drops them.
    """

    snapshot_id: str
    agent_id: str
    session_id: str


# ----------------------------------------------------------------------
# Per-session worker thread
# ----------------------------------------------------------------------
#
# Why this exists
# ---------------
# The upstream ``hyperlight_sandbox.Sandbox`` is implemented in Rust
# via PyO3 with ``#[pyclass(unsendable)]``: the underlying Wasmtime
# ``Store`` is ``!Send`` and panics at the PyO3 layer (a Rust
# ``PanicException``, which subclasses ``BaseException`` — *not*
# ``Exception``) the moment it is touched from any thread other than
# the one that constructed it.
#
# Naively wrapping ``Sandbox.run`` in ``asyncio.to_thread`` therefore
# guarantees a panic on the wasm backend, because the to_thread worker
# is by design a different thread from the event-loop thread that
# created the session.
#
# To honour the unsendable invariant transparently for callers, every
# session owns a dedicated OS thread — ``_SandboxWorker`` — that
# constructs the ``Sandbox``, runs all guest code, takes/restores
# snapshots, and ultimately drops the ``Sandbox`` exclusively from
# inside that one thread. Sync and async callers from any thread submit
# work via a queue and receive the result through a
# :class:`concurrent.futures.Future`; the async path then bridges that
# Future into the event loop with :func:`asyncio.wrap_future`.


class _SandboxWorker:
    """One OS thread per Hyperlight session.

    The thread is the *only* code path that ever touches the underlying
    ``Sandbox`` object. All public methods are safe to call from any
    thread (including the asyncio loop) and never block on the
    ``Sandbox`` itself — they marshal the work onto the worker thread
    via a queue and wait on a :class:`Future` for the outcome.

    The Sandbox is built lazily on the worker thread (not in
    ``__init__``) so that even ``create_session`` does not violate the
    unsendable invariant.
    """

    # Sentinel pushed onto the queue to ask the worker to exit.
    _SHUTDOWN = object()

    def __init__(self, name: str) -> None:
        self._name = name
        # Tasks waiting to run on the worker thread; each entry is
        # ``(callable, future)`` or the ``_SHUTDOWN`` sentinel.
        self._inbox: queue.Queue[Any] = queue.Queue()
        self._thread = threading.Thread(
            target=self._run,
            name=f"hyperlight-worker:{name}",
            daemon=True,
        )
        self._started = False
        self._stopped = False

    # -- public API --------------------------------------------------

    def start(self) -> None:
        """Start the worker thread. Idempotent."""
        if self._started:
            return
        self._started = True
        self._thread.start()

    def submit(
        self, fn: Callable[..., Any], *args: Any, **kwargs: Any
    ) -> Future:
        """Schedule ``fn(*args, **kwargs)`` on the worker thread.

        Returns a :class:`Future` that resolves with the return value
        or the exception raised by ``fn``. Safe to call from any
        thread, including the event-loop thread.
        """
        if not self._started:
            raise RuntimeError(
                f"sandbox worker '{self._name}' was never start()ed"
            )
        if self._stopped:
            raise RuntimeError(
                f"sandbox worker '{self._name}' has been stopped; "
                "create a new session"
            )
        fut: Future = Future()
        self._inbox.put((fn, args, kwargs, fut))
        return fut

    def submit_and_wait(
        self, fn: Callable[..., Any], *args: Any, **kwargs: Any
    ) -> Any:
        """Convenience: submit ``fn`` and block (sync) for its result."""
        return self.submit(fn, *args, **kwargs).result()

    def stop(self, *, join_timeout: float | None = 30.0) -> None:
        """Ask the worker to drain its queue and exit.

        Idempotent. Blocks up to ``join_timeout`` seconds for the
        thread to finish; if it's still running afterwards the daemon
        flag means it won't keep the interpreter alive.
        """
        if self._stopped:
            return
        self._stopped = True
        if not self._started:
            return
        self._inbox.put(self._SHUTDOWN)
        self._thread.join(timeout=join_timeout)

    @property
    def is_alive(self) -> bool:
        return self._started and self._thread.is_alive()

    # -- internals ---------------------------------------------------

    def _run(self) -> None:
        while True:
            item = self._inbox.get()
            if item is self._SHUTDOWN:
                return
            fn, args, kwargs, fut = item
            if not fut.set_running_or_notify_cancel():
                # Caller cancelled before we got to it.
                continue
            try:
                result = fn(*args, **kwargs)
            except (SystemExit, KeyboardInterrupt, GeneratorExit):
                # Never swallow control-flow exceptions — let them
                # propagate so the interpreter / event loop can shut
                # down cleanly.
                raise
            except BaseException as exc:  # noqa: BLE001 - PyO3 panics surface as BaseException
                fut.set_exception(exc)
            else:
                fut.set_result(result)


# ----------------------------------------------------------------------
# Provider
# ----------------------------------------------------------------------


class HyperLightSandboxProvider(SandboxProvider):
    """``SandboxProvider`` backed by ``hyperlight-sandbox``.

    Parameters
    ----------
    backend:
        Upstream backend selector. Defaults to ``"wasm"``.
    module:
        Guest module identifier, only meaningful for ``backend="wasm"``.
        Defaults to ``"python_guest"``.
    tools:
        Host-side tool callables keyed by name. Only the subset that
        appears in a session's ``policy.tool_allowlist`` is handed to
        that session's guest via ``Sandbox.register_tool``. Tools not
        listed in any policy are simply unused.
    sandbox_module:
        Optional override for the upstream module to import. The
        default ``"hyperlight_sandbox"`` matches the published PyPI
        package; tests inject a stub module here.
    """

    def __init__(
        self,
        backend: str | HyperlightBackend = "wasm",
        module: str | None = "python_guest",
        tools: dict[str, Callable[..., Any]] | None = None,
        *,
        sandbox_module: str = "hyperlight_sandbox",
    ) -> None:
        self._backend = (
            backend.value if isinstance(backend, HyperlightBackend) else backend
        )
        self._module = module
        self._tools: dict[str, Callable[..., Any]] = dict(tools or {})
        self._sandbox_module_name = sandbox_module

        # Session bookkeeping. Reentrant lock because async variants
        # delegate to sync via the worker, and registry mutations may
        # overlap with worker callbacks (e.g. _safe_drop on teardown).
        self._state_lock = threading.RLock()
        # Each session owns one OS thread that is the sole code path
        # touching its Sandbox — see _SandboxWorker docstring.
        self._workers: dict[tuple[str, str], _SandboxWorker] = {}
        # ``_sandboxes`` retains the same key shape but now stores the
        # Sandbox handle alongside the worker. The handle is *only*
        # safe to dereference from inside the worker thread; we keep
        # it in the registry so teardown and snapshot bookkeeping can
        # be looked up without going through the worker.
        self._sandboxes: dict[tuple[str, str], Any] = {}
        self._evaluators: dict[tuple[str, str], Any] = {}
        self._session_configs: dict[tuple[str, str], HyperlightConfig] = {}
        self._snapshots: dict[tuple[str, str, str], Any] = {}

        # Resolve the upstream SDK lazily but eagerly enough to set
        # ``_available`` correctly at __init__ time.
        self._sdk: Any | None = None
        self._available: bool = False
        self._unavailable_reason: str = ""
        try:
            self._sdk = importlib.import_module(self._sandbox_module_name)
        except Exception as exc:  # pragma: no cover - exercised by tests
            self._unavailable_reason = (
                f"hyperlight-sandbox SDK not importable: {exc}"
            )
            logger.info(self._unavailable_reason)
            return

        # Validate backend up front rather than at create_session time
        # so callers see configuration errors immediately.
        if self._backend not in {"wasm", "hyperlightjs", "nanvix"}:
            raise ValueError(
                f"Unknown Hyperlight backend '{self._backend}'. "
                "Expected one of: ['hyperlightjs', 'nanvix', 'wasm']"
            )

        # Probe hypervisor presence if upstream exposes the helper.
        # Older / newer SDK builds may not have it; absence is not
        # disqualifying — Sandbox() will error at session creation if
        # the hypervisor isn't reachable.
        present_fn = getattr(self._sdk, "is_hypervisor_present", None)
        if callable(present_fn):
            try:
                self._available = bool(present_fn())
                if not self._available:
                    self._unavailable_reason = (
                        "no hypervisor detected (KVM, mshv, or WHP)"
                    )
            except Exception as exc:  # defensive: upstream may raise
                self._unavailable_reason = (
                    f"hypervisor probe failed: {exc}"
                )
                self._available = False
        else:
            # No probe — assume available; create_session will surface
            # any real failure.
            self._available = True

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def backend(self) -> str:
        return self._backend

    @property
    def module(self) -> str | None:
        return self._module

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
                "hyperlight-sandbox unavailable: "
                + (self._unavailable_reason or "unknown reason")
                + ". Install the SDK and ensure a hypervisor "
                "(KVM / mshv / WHP) is reachable."
            )
        _validate_agent_id(agent_id)
        assert self._sdk is not None  # guarded by _available

        session_id = uuid.uuid4().hex[:8]
        base_cfg = config or SandboxConfig()
        hl_cfg = HyperlightConfig.from_sandbox_config(
            base_cfg, backend=self._backend, module=self._module
        )

        # Translate policy → config (resource caps, mount dirs).
        evaluator = None
        tool_allow: list[str] = []
        net_allow: list[str] = []
        if policy is not None:
            hl_cfg = hyperlight_config_from_policy(policy, base=hl_cfg)
            tool_allow = list(getattr(policy, "tool_allowlist", []) or [])
            net_allow = list(getattr(policy, "network_allowlist", []) or [])
            evaluator = self._build_evaluator(policy)

        # Resolve tool callables. Names listed in the allowlist that the
        # provider does not know about fail closed at session creation
        # time so a misconfigured policy never silently degrades.
        unknown_tools = [n for n in tool_allow if n not in self._tools]
        if unknown_tools:
            raise ValueError(
                "tool_allowlist references tools not registered with the "
                f"provider: {sorted(unknown_tools)}. Register them via "
                "the ``tools=`` constructor argument or remove them "
                "from the policy."
            )
        tools_to_register = {
            name: self._tools[name] for name in tool_allow
        }

        # Apply nanvix capability check before spinning up a worker.
        if hl_cfg.backend == "nanvix" and (tools_to_register or net_allow):
            raise ValueError(
                "backend='nanvix' does not support tools or network "
                "(this is an upstream limitation in hyperlight-sandbox "
                "v0.4.0). Use backend='wasm' for Python+tools or "
                "backend='hyperlightjs' for JS+tools."
            )

        # Spin up the per-session worker thread *before* constructing
        # the Sandbox so that the Sandbox is born on the thread that
        # will own it for the rest of its lifetime. This is the core
        # of the unsendable-invariant fix.
        worker = _SandboxWorker(name=f"{agent_id}/{session_id}")
        worker.start()

        def _bootstrap_sandbox() -> Any:
            sandbox = self._build_sandbox(hl_cfg)
            try:
                for name, fn in tools_to_register.items():
                    sandbox.register_tool(name, fn)
                for url in net_allow:
                    sandbox.allow_domain(url)
            except Exception:
                # Drop the half-configured sandbox before bubbling up.
                self._safe_drop(sandbox)
                raise
            return sandbox

        try:
            sandbox = worker.submit_and_wait(_bootstrap_sandbox)
        except Exception as exc:
            worker.stop(join_timeout=5.0)
            raise RuntimeError(
                f"Failed to build Hyperlight sandbox for "
                f"{agent_id}/{session_id}: {exc}"
            ) from exc

        with self._state_lock:
            self._workers[(agent_id, session_id)] = worker
            self._sandboxes[(agent_id, session_id)] = sandbox
            self._session_configs[(agent_id, session_id)] = hl_cfg
            if evaluator is not None:
                self._evaluators[(agent_id, session_id)] = evaluator

        logger.info(
            "Hyperlight session created: agent=%s session=%s backend=%s "
            "module=%s tools=%d allowed_domains=%d",
            agent_id,
            session_id,
            hl_cfg.backend,
            hl_cfg.module,
            len(tools_to_register),
            len(net_allow),
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
            worker = self._workers.get(key)
            sandbox = self._sandboxes.get(key)
            evaluator = self._evaluators.get(key)
            cfg = self._session_configs.get(key)

        if worker is None or sandbox is None:
            raise RuntimeError(
                f"No active session for agent '{agent_id}' with "
                f"session_id '{session_id}'. Call create_session() first."
            )

        # Policy gate — runs entirely on the host before any guest call,
        # so a denied policy never reaches the hypervisor.
        if evaluator is not None:
            eval_ctx: dict[str, Any] = {
                "agent_id": agent_id,
                "action": "execute",
                "code": code,
            }
            if context:
                eval_ctx.update(context)
            decision = evaluator.evaluate(eval_ctx)
            if not getattr(decision, "allowed", False):
                reason = getattr(decision, "reason", "policy denied")
                raise PermissionError(f"Policy denied: {reason}")

        execution_id = uuid.uuid4().hex[:8]
        timeout_s = (cfg.max_execution_time_ms / 1000.0) if cfg else 60.0

        run_kwargs: dict[str, Any] = {}
        if context is not None:
            # Pass context via globals so the guest can read it as
            # ``globals()["context"]`` without us mutating ``code``.
            run_kwargs["globals"] = {"context": dict(context)}

        # All Sandbox interaction happens inside the worker thread to
        # honour the unsendable invariant.
        def _do_run() -> tuple[Any, float]:
            inner_start = time.monotonic()
            try:
                rr = sandbox.run(code, **run_kwargs)
            except TypeError:
                rr = sandbox.run(code)
            return rr, time.monotonic() - inner_start

        start = time.monotonic()
        try:
            run_result, duration = worker.submit_and_wait(_do_run)
        except Exception as exc:
            duration = time.monotonic() - start
            return ExecutionHandle(
                execution_id=execution_id,
                agent_id=agent_id,
                session_id=session_id,
                status=ExecutionStatus.FAILED,
                result=SandboxResult(
                    success=False,
                    exit_code=1,
                    stderr=str(exc),
                    duration_seconds=round(duration, 3),
                ),
            )

        result = self._normalise_run_result(run_result, duration, timeout_s)
        status = (
            ExecutionStatus.COMPLETED if result.success else ExecutionStatus.FAILED
        )
        return ExecutionHandle(
            execution_id=execution_id,
            agent_id=agent_id,
            session_id=session_id,
            status=status,
            result=result,
        )

    def destroy_session(self, agent_id: str, session_id: str) -> None:
        key = (agent_id, session_id)
        with self._state_lock:
            worker = self._workers.pop(key, None)
            sandbox = self._sandboxes.pop(key, None)
            self._evaluators.pop(key, None)
            self._session_configs.pop(key, None)
            # Pop any snapshots associated with this session into a
            # separate list so we can drop them on the worker thread
            # below — snapshot objects share the unsendable invariant
            # with the Sandbox itself.
            session_snapshots: list[Any] = []
            remaining: dict[tuple[str, str, str], Any] = {}
            for k, v in self._snapshots.items():
                if k[0] == agent_id and k[1] == session_id:
                    session_snapshots.append(v)
                else:
                    remaining[k] = v
            self._snapshots = remaining
        if worker is not None and sandbox is not None:
            # The Sandbox's underlying Rust object is unsendable, so the
            # final ``__del__`` decref MUST happen on the worker thread
            # — otherwise the Python GC may reclaim it from whatever
            # thread was last to hold a reference and PyO3 raises an
            # unraisable ``RuntimeError`` at process exit.
            #
            # We wrap the sandbox (and any remaining session snapshots)
            # in a list and hand that list to the worker; the worker
            # clears the elements so the final decref happens inside
            # its own frame. We drop our local references *before*
            # submitting so the only live references belong to the
            # worker frame.
            box: list[Any] = [sandbox, *session_snapshots]
            sandbox = None  # noqa: F841 - explicit decref on caller side
            session_snapshots = []  # noqa: F841 - same
            del sandbox
            del session_snapshots

            def _drop_in_worker(items: list[Any]) -> None:
                # Index 0 is the Sandbox; the rest are snapshot handles.
                sb = items[0]
                items[0] = None
                self._safe_drop(sb)
                del sb
                # Snapshots have no documented teardown method; their
                # ``__del__`` is enough — we just need it to fire on
                # this thread.
                for i in range(1, len(items)):
                    items[i] = None

            try:
                worker.submit_and_wait(_drop_in_worker, box)
            except Exception as exc:
                logger.debug(
                    "Sandbox drop on worker raised: %s", exc
                )
            finally:
                # ``box`` is still bound in this frame but its elements
                # are now None; clearing it is belt-and-suspenders.
                for i in range(len(box)):
                    box[i] = None
                del box
        if worker is not None:
            worker.stop(join_timeout=10.0)

    def get_session_status(
        self, agent_id: str, session_id: str
    ) -> SessionStatus:
        with self._state_lock:
            if (agent_id, session_id) in self._workers:
                return SessionStatus.READY
        return SessionStatus.DESTROYED

    def cancel_execution(
        self, agent_id: str, session_id: str, execution_id: str
    ) -> bool:
        with self._state_lock:
            worker = self._workers.get((agent_id, session_id))
            sandbox = self._sandboxes.get((agent_id, session_id))
        if worker is None or sandbox is None:
            return False
        interrupt = getattr(sandbox, "interrupt", None)
        if not callable(interrupt):
            return False
        # ``interrupt`` is intended to be called from a *different*
        # thread than ``run`` — it signals the running guest. Even so,
        # we marshal it onto the worker for the wasm backend because
        # the unsendable check disallows even read-only access from
        # foreign threads. If the worker is currently blocked inside
        # ``sandbox.run``, the submit will queue behind it; for true
        # mid-execution interruption upstream needs to expose a
        # cross-thread-safe handle.
        try:
            worker.submit_and_wait(interrupt)
            return True
        except Exception as exc:
            logger.warning(
                "Sandbox.interrupt() failed for %s/%s: %s",
                agent_id,
                session_id,
                exc,
            )
            return False

    # ------------------------------------------------------------------
    # Provider-specific extensions (snapshots)
    # ------------------------------------------------------------------

    def snapshot_session(
        self, agent_id: str, session_id: str
    ) -> SnapshotHandle:
        """Capture a copy-on-write snapshot of the session's VM memory.

        Snapshots are kept in process memory and dropped when the
        session is destroyed. Not supported on ``backend="nanvix"``.
        """
        with self._state_lock:
            worker = self._workers.get((agent_id, session_id))
            sandbox = self._sandboxes.get((agent_id, session_id))
            cfg = self._session_configs.get((agent_id, session_id))
        if worker is None or sandbox is None:
            raise RuntimeError(
                f"No active session for agent '{agent_id}' with "
                f"session_id '{session_id}'."
            )
        if cfg is not None and cfg.backend == "nanvix":
            raise RuntimeError(
                "snapshot_session is not supported on backend='nanvix'"
            )
        snap_fn = getattr(sandbox, "snapshot", None)
        if not callable(snap_fn):
            raise RuntimeError(
                "Underlying Sandbox does not support snapshot()"
            )
        # Snapshot objects also wrap unsendable native state — capture
        # them on the worker thread.
        snap_obj = worker.submit_and_wait(snap_fn)
        snapshot_id = uuid.uuid4().hex[:12]
        with self._state_lock:
            self._snapshots[(agent_id, session_id, snapshot_id)] = snap_obj
        return SnapshotHandle(
            snapshot_id=snapshot_id,
            agent_id=agent_id,
            session_id=session_id,
        )

    def restore_snapshot(
        self, agent_id: str, session_id: str, snapshot_id: str
    ) -> None:
        """Restore the session's VM memory from a previous snapshot."""
        # Snapshots are single-use: ``pop`` drops our reference once we
        # hand the underlying object to the worker, otherwise long-lived
        # sessions accumulate snapshot objects in ``self._snapshots``
        # forever (the error message below documents this contract).
        with self._state_lock:
            worker = self._workers.get((agent_id, session_id))
            sandbox = self._sandboxes.get((agent_id, session_id))
            snap_obj = self._snapshots.pop(
                (agent_id, session_id, snapshot_id), None
            )
        if worker is None or sandbox is None:
            raise RuntimeError(
                f"No active session for agent '{agent_id}' with "
                f"session_id '{session_id}'."
            )
        if snap_obj is None:
            raise KeyError(
                f"Unknown snapshot '{snapshot_id}' for session "
                f"'{session_id}' (already restored & dropped, or never "
                "captured)."
            )
        restore_fn = getattr(sandbox, "restore", None)
        if not callable(restore_fn):
            raise RuntimeError(
                "Underlying Sandbox does not support restore()"
            )
        worker.submit_and_wait(restore_fn, snap_obj)

    # ------------------------------------------------------------------
    # Async overrides — bridge the worker's concurrent.futures.Future
    # into the asyncio event loop so the loop is never blocked while
    # the guest is running.
    # ------------------------------------------------------------------

    async def execute_code_async(
        self,
        agent_id: str,
        session_id: str,
        code: str,
        *,
        context: dict[str, Any] | None = None,
    ) -> ExecutionHandle:
        # Run the entire (otherwise sync) ``execute_code`` flow on a
        # background helper thread. ``execute_code`` itself blocks on
        # the per-session worker's Future via ``Future.result()``; we
        # wrap that single blocking call in ``asyncio.to_thread`` so
        # the event loop stays responsive. The unsendable invariant is
        # honoured because the per-session worker (not the to_thread
        # helper) is what actually touches the Sandbox.
        return await asyncio.to_thread(
            self.execute_code, agent_id, session_id, code, context=context
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _build_sandbox(self, cfg: HyperlightConfig) -> Any:
        """Construct the upstream Sandbox.

        We try the full kwarg form first; if upstream rejects an
        unknown keyword, fall back to the minimal positional form.
        """
        assert self._sdk is not None
        Sandbox = getattr(self._sdk, "Sandbox", None)
        if Sandbox is None:
            raise RuntimeError(
                f"{self._sandbox_module_name}.Sandbox is not exposed; "
                "is hyperlight-sandbox installed correctly?"
            )

        full_kwargs: dict[str, Any] = {
            "backend": cfg.backend,
            "max_execution_time_ms": cfg.max_execution_time_ms,
            "heap_size_bytes": cfg.heap_size_bytes,
            "stack_size_bytes": cfg.stack_size_bytes,
        }
        if cfg.backend == "wasm" and cfg.module is not None:
            full_kwargs["module"] = cfg.module
        if cfg.input_dir is not None:
            full_kwargs["input_dir"] = cfg.input_dir
        if cfg.output_dir is not None:
            full_kwargs["output_dir"] = cfg.output_dir
        if cfg.env_vars:
            full_kwargs["env"] = dict(cfg.env_vars)

        try:
            return Sandbox(**full_kwargs)
        except TypeError as exc:
            logger.debug(
                "Sandbox(**full_kwargs) rejected (%s); retrying minimal",
                exc,
            )
            minimal: dict[str, Any] = {"backend": cfg.backend}
            if cfg.backend == "wasm" and cfg.module is not None:
                minimal["module"] = cfg.module
            return Sandbox(**minimal)

    def _build_evaluator(self, policy: Any) -> Any | None:
        """Best-effort PolicyEvaluator construction — returns ``None``
        when ``agent-os-kernel`` isn't installed (the docker provider
        does the same)."""
        try:
            from agent_os.policies.evaluator import PolicyEvaluator
        except ImportError:
            logger.warning(
                "agent-os-kernel not installed — policy evaluation "
                "unavailable, session runs ungated"
            )
            return None
        try:
            return PolicyEvaluator(policies=[policy])
        except Exception as exc:
            raise RuntimeError(
                f"Failed to initialize PolicyEvaluator: {exc}"
            ) from exc

    @staticmethod
    def _normalise_run_result(
        run_result: Any, duration_s: float, timeout_s: float
    ) -> SandboxResult:
        """Map the upstream ``RunResult`` (or anything duck-compatible)
        into our :class:`SandboxResult`.
        """
        stdout = str(getattr(run_result, "stdout", "") or "")
        stderr = str(getattr(run_result, "stderr", "") or "")
        exit_code = int(getattr(run_result, "exit_code", 0) or 0)
        # Upstream may report duration in ms; prefer it when present.
        upstream_ms = getattr(run_result, "duration_ms", None)
        if isinstance(upstream_ms, (int, float)) and upstream_ms >= 0:
            duration = upstream_ms / 1000.0
        else:
            duration = duration_s

        # Timeout flag — host-side wallclock vs the configured timeout.
        killed = duration > timeout_s if timeout_s > 0 else False
        kill_reason = (
            f"Execution exceeded timeout of {timeout_s}s" if killed else ""
        )

        # Truncate to keep one adversarial print() from blowing memory.
        stdout = stdout[:10000]
        stderr = stderr[:10000]

        return SandboxResult(
            success=exit_code == 0 and not killed,
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            duration_seconds=round(duration, 3),
            killed=killed,
            kill_reason=kill_reason,
        )

    @staticmethod
    def _safe_drop(sandbox: Any) -> None:
        """Best-effort sandbox teardown.  Upstream typically releases
        the VM via ``__del__``; if a ``close``/``shutdown`` method is
        present we call it explicitly for determinism."""
        for name in ("close", "shutdown", "__exit__"):
            fn = getattr(sandbox, name, None)
            if not callable(fn):
                continue
            try:
                if name == "__exit__":
                    fn(None, None, None)
                else:
                    fn()
                return
            except Exception as exc:
                logger.debug(
                    "Sandbox.%s() raised during teardown: %s", name, exc
                )
