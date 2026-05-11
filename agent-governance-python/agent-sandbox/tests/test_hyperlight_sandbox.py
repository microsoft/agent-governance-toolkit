# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Unit tests for :mod:`agent_sandbox.hyperlight_provider`.

The upstream ``hyperlight-sandbox`` SDK is replaced with an in-memory
fake (see :class:`_FakeSandbox` and the ``fake_sdk`` fixture) so these
tests run without a hypervisor and without the real package installed.

Coverage targets:

* Configuration: :class:`HyperlightConfig`, ``hyperlight_config_from_policy``.
* Construction: SDK probe, backend validation, hypervisor-absence path.
* Lifecycle: create/execute/destroy, session reuse, status, cancel.
* Capabilities: ``register_tool`` / ``allow_domain`` calls match policy.
* Snapshots: capture, restore, error paths, nanvix unsupported.
* Async surface: ``execute_code_async``.
* Edge cases: bad agent_ids, tool not in registry, upstream SDK
  signatures that reject unknown kwargs, run-time exceptions.
"""

from __future__ import annotations

import asyncio
import sys
import types
from types import SimpleNamespace
from typing import Any

import pytest

from agent_sandbox.sandbox_provider import (
    ExecutionStatus,
    SandboxConfig,
    SessionStatus,
)


# =========================================================================
# Fake upstream SDK
# =========================================================================


class _FakeRunResult:
    def __init__(
        self,
        stdout: str = "",
        stderr: str = "",
        exit_code: int = 0,
        duration_ms: float | None = None,
    ) -> None:
        self.stdout = stdout
        self.stderr = stderr
        self.exit_code = exit_code
        self.duration_ms = duration_ms


class _FakeSandbox:
    """In-memory stand-in for ``hyperlight_sandbox.Sandbox``.

    Tracks every call (``register_tool``, ``allow_domain``, ``run``,
    ``snapshot``, ``restore``, ``interrupt``, ``close``) so tests can
    assert on the interaction.
    """

    # Class-level toggles flipped by individual tests.
    accept_full_kwargs: bool = True
    next_run_result: _FakeRunResult | None = None
    raise_on_register: bool = False
    raise_on_allow: bool = False
    raise_on_run: BaseException | None = None
    instances: list["_FakeSandbox"] = []

    def __init__(self, **kwargs: Any) -> None:
        if not _FakeSandbox.accept_full_kwargs:
            allowed = {"backend", "module"}
            unknown = set(kwargs) - allowed
            if unknown:
                raise TypeError(
                    f"Sandbox() got unexpected keyword arguments: {unknown}"
                )
        self.kwargs = kwargs
        self.tools: dict[str, Any] = {}
        self.allowed_domains: list[str] = []
        self.run_calls: list[tuple[str, dict[str, Any]]] = []
        self.snapshots: list[Any] = []
        self.interrupted = False
        self.closed = False
        _FakeSandbox.instances.append(self)

    def register_tool(self, name: str, fn: Any) -> None:
        if _FakeSandbox.raise_on_register:
            raise RuntimeError(f"register_tool boom: {name}")
        self.tools[name] = fn

    def allow_domain(self, url: str) -> None:
        if _FakeSandbox.raise_on_allow:
            raise RuntimeError(f"allow_domain boom: {url}")
        self.allowed_domains.append(url)

    def run(self, code: str, **kwargs: Any) -> _FakeRunResult:
        self.run_calls.append((code, dict(kwargs)))
        if _FakeSandbox.raise_on_run is not None:
            raise _FakeSandbox.raise_on_run
        return _FakeSandbox.next_run_result or _FakeRunResult(
            stdout=f"executed {len(code)} chars"
        )

    def snapshot(self) -> object:
        snap = object()
        self.snapshots.append(snap)
        return snap

    def restore(self, snap: Any) -> None:
        self.snapshots.append(("restored", snap))

    def interrupt(self) -> None:
        self.interrupted = True

    def close(self) -> None:
        self.closed = True


# =========================================================================
# Fixtures
# =========================================================================


@pytest.fixture
def fake_sdk(monkeypatch: pytest.MonkeyPatch) -> types.ModuleType:
    """Install a fake ``hyperlight_sandbox`` module in ``sys.modules``."""
    # Reset class-level state on the fake every test.
    _FakeSandbox.accept_full_kwargs = True
    _FakeSandbox.next_run_result = None
    _FakeSandbox.raise_on_register = False
    _FakeSandbox.raise_on_allow = False
    _FakeSandbox.raise_on_run = None
    _FakeSandbox.instances = []

    mod = types.ModuleType("hyperlight_sandbox")
    mod.Sandbox = _FakeSandbox  # type: ignore[attr-defined]
    mod.is_hypervisor_present = lambda: True  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "hyperlight_sandbox", mod)
    return mod


@pytest.fixture
def provider(fake_sdk):
    from agent_sandbox.hyperlight_provider import HyperLightSandboxProvider

    return HyperLightSandboxProvider(
        tools={
            "web_search": lambda q: f"results for {q}",
            "read_doc": lambda doc_id: f"doc {doc_id}",
            "delete_doc": lambda doc_id: None,  # NOT in any allowlist
        }
    )


def _make_policy(
    *,
    tool_allowlist: list[str] | None = None,
    network_allowlist: list[str] | None = None,
    max_memory_mb: int | None = None,
    timeout_seconds: float | None = None,
):
    """Build a duck-typed policy stand-in. PolicyEvaluator import will
    fail (agent-os-kernel not installed in this test env), so the
    provider runs without a host-side gate — exactly what we want for
    the capability-binding tests.
    """
    defaults = SimpleNamespace(
        max_memory_mb=max_memory_mb if max_memory_mb is not None else 256,
        timeout_seconds=(
            timeout_seconds if timeout_seconds is not None else 30
        ),
    )
    return SimpleNamespace(
        defaults=defaults,
        tool_allowlist=tool_allowlist or [],
        network_allowlist=network_allowlist or [],
    )


# =========================================================================
# 1. HyperlightConfig
# =========================================================================


class TestHyperlightConfig:
    def test_defaults(self):
        from agent_sandbox.hyperlight_provider import HyperlightConfig

        cfg = HyperlightConfig()
        assert cfg.backend == "wasm"
        assert cfg.module == "python_guest"
        assert cfg.heap_size_bytes == 64 * 1024 * 1024
        assert cfg.stack_size_bytes == 2 * 1024 * 1024
        assert cfg.max_execution_time_ms == 60_000

    @pytest.mark.parametrize(
        "backend", ["wasm", "hyperlightjs", "nanvix"]
    )
    def test_valid_backends(self, backend):
        from agent_sandbox.hyperlight_provider import HyperlightConfig

        assert HyperlightConfig(backend=backend).backend == backend

    def test_unknown_backend_rejected(self):
        from agent_sandbox.hyperlight_provider import HyperlightConfig

        with pytest.raises(ValueError, match="Unknown Hyperlight backend"):
            HyperlightConfig(backend="firecracker")

    @pytest.mark.parametrize(
        "field,value",
        [
            ("heap_size_bytes", 0),
            ("heap_size_bytes", -1),
            ("stack_size_bytes", 0),
            ("max_execution_time_ms", 0),
        ],
    )
    def test_non_positive_sizes_rejected(self, field, value):
        from agent_sandbox.hyperlight_provider import HyperlightConfig

        with pytest.raises(ValueError):
            HyperlightConfig(**{field: value})

    def test_from_sandbox_config_translates_resources(self):
        from agent_sandbox.hyperlight_provider import HyperlightConfig

        base = SandboxConfig(
            timeout_seconds=12.5,
            memory_mb=200,
            cpu_limit=4.0,
            input_dir="/host/in",
            output_dir="/host/out",
            env_vars={"X": "y"},
        )
        cfg = HyperlightConfig.from_sandbox_config(base)
        assert cfg.heap_size_bytes == 200 * 1024 * 1024
        assert cfg.max_execution_time_ms == 12_500
        assert cfg.input_dir == "/host/in"
        assert cfg.output_dir == "/host/out"
        assert cfg.env_vars == {"X": "y"}
        # cpu_limit deliberately not propagated (Hyperlight pins 1 vCPU).

    def test_from_sandbox_config_overrides(self):
        from agent_sandbox.hyperlight_provider import HyperlightConfig

        cfg = HyperlightConfig.from_sandbox_config(
            SandboxConfig(),
            backend="hyperlightjs",
            module=None,
        )
        assert cfg.backend == "hyperlightjs"
        assert cfg.module is None


class TestPolicyToConfig:
    def test_resource_caps_extracted(self):
        from agent_sandbox.hyperlight_provider import (
            hyperlight_config_from_policy,
        )

        policy = _make_policy(max_memory_mb=128, timeout_seconds=45)
        cfg = hyperlight_config_from_policy(policy)
        assert cfg.heap_size_bytes == 128 * 1024 * 1024
        assert cfg.max_execution_time_ms == 45_000

    def test_missing_defaults_keeps_base(self):
        from agent_sandbox.hyperlight_provider import (
            HyperlightConfig,
            hyperlight_config_from_policy,
        )

        policy = SimpleNamespace()  # no defaults attr
        base = HyperlightConfig(heap_size_bytes=999_999)
        cfg = hyperlight_config_from_policy(policy, base=base)
        assert cfg.heap_size_bytes == 999_999

    def test_sandbox_mounts_picked_up(self):
        from agent_sandbox.hyperlight_provider import (
            hyperlight_config_from_policy,
        )

        policy = SimpleNamespace(
            defaults=SimpleNamespace(),
            sandbox_mounts=SimpleNamespace(
                input_dir="/in", output_dir="/out"
            ),
        )
        cfg = hyperlight_config_from_policy(policy)
        assert cfg.input_dir == "/in"
        assert cfg.output_dir == "/out"

    def test_invalid_defaults_ignored(self):
        from agent_sandbox.hyperlight_provider import (
            hyperlight_config_from_policy,
        )

        policy = SimpleNamespace(
            defaults=SimpleNamespace(
                max_memory_mb=-5, timeout_seconds="bogus"
            )
        )
        cfg = hyperlight_config_from_policy(policy)
        # Falls back to defaults, no crash.
        assert cfg.heap_size_bytes == 64 * 1024 * 1024
        assert cfg.max_execution_time_ms == 60_000


# =========================================================================
# 2. Construction & SDK probe
# =========================================================================


class TestProviderConstruction:
    def test_available_when_sdk_imports_and_hypervisor_present(
        self, fake_sdk
    ):
        from agent_sandbox.hyperlight_provider import HyperLightSandboxProvider

        p = HyperLightSandboxProvider()
        assert p.is_available() is True
        assert p.backend == "wasm"
        assert p.module == "python_guest"

    def test_unavailable_when_sdk_missing(self, monkeypatch):
        # Ensure the module is genuinely not importable.
        monkeypatch.setitem(sys.modules, "hyperlight_sandbox", None)
        from agent_sandbox.hyperlight_provider import HyperLightSandboxProvider

        p = HyperLightSandboxProvider()
        assert p.is_available() is False

    def test_unavailable_when_no_hypervisor(self, monkeypatch, fake_sdk):
        fake_sdk.is_hypervisor_present = lambda: False  # type: ignore[attr-defined]
        from agent_sandbox.hyperlight_provider import HyperLightSandboxProvider

        p = HyperLightSandboxProvider()
        assert p.is_available() is False

    def test_hypervisor_probe_exception_is_unavailable(
        self, monkeypatch, fake_sdk
    ):
        def boom() -> bool:
            raise RuntimeError("no /dev/kvm")

        fake_sdk.is_hypervisor_present = boom  # type: ignore[attr-defined]
        from agent_sandbox.hyperlight_provider import HyperLightSandboxProvider

        p = HyperLightSandboxProvider()
        assert p.is_available() is False

    def test_no_probe_function_assumes_available(self, monkeypatch, fake_sdk):
        # Older SDK builds may omit the probe entirely.
        delattr(fake_sdk, "is_hypervisor_present")
        from agent_sandbox.hyperlight_provider import HyperLightSandboxProvider

        p = HyperLightSandboxProvider()
        assert p.is_available() is True

    def test_unknown_backend_rejected_at_construction(self, fake_sdk):
        from agent_sandbox.hyperlight_provider import HyperLightSandboxProvider

        with pytest.raises(ValueError, match="Unknown Hyperlight backend"):
            HyperLightSandboxProvider(backend="firecracker")

    def test_backend_enum_accepted(self, fake_sdk):
        from agent_sandbox.hyperlight_provider import (
            HyperlightBackend,
            HyperLightSandboxProvider,
        )

        p = HyperLightSandboxProvider(backend=HyperlightBackend.HYPERLIGHTJS)
        assert p.backend == "hyperlightjs"

    def test_create_session_when_unavailable_raises(self, monkeypatch):
        monkeypatch.setitem(sys.modules, "hyperlight_sandbox", None)
        from agent_sandbox.hyperlight_provider import HyperLightSandboxProvider

        p = HyperLightSandboxProvider()
        with pytest.raises(RuntimeError, match="hyperlight-sandbox unavailable"):
            p.create_session("agent-1")


# =========================================================================
# 3. Lifecycle
# =========================================================================


class TestSessionLifecycle:
    def test_create_returns_ready_handle(self, provider):
        handle = provider.create_session("agent-1")
        assert handle.agent_id == "agent-1"
        assert handle.status == SessionStatus.READY
        assert len(handle.session_id) == 8

    def test_session_id_is_unique(self, provider):
        ids = {provider.create_session("agent-1").session_id for _ in range(10)}
        assert len(ids) == 10

    def test_get_session_status_ready_then_destroyed(self, provider):
        h = provider.create_session("agent-1")
        assert (
            provider.get_session_status("agent-1", h.session_id)
            == SessionStatus.READY
        )
        provider.destroy_session("agent-1", h.session_id)
        assert (
            provider.get_session_status("agent-1", h.session_id)
            == SessionStatus.DESTROYED
        )

    def test_destroy_unknown_session_is_noop(self, provider):
        # No raise.
        provider.destroy_session("agent-1", "deadbeef")

    def test_invalid_agent_id_rejected(self, provider):
        with pytest.raises(ValueError, match="Invalid agent_id"):
            provider.create_session("hostile\nname")

    def test_each_session_uses_a_fresh_sandbox(self, provider):
        a = provider.create_session("agent-1")
        b = provider.create_session("agent-1")
        assert a.session_id != b.session_id
        # Two distinct underlying _FakeSandbox instances.
        assert len(_FakeSandbox.instances) == 2

    def test_same_session_reuses_same_sandbox(self, provider):
        h = provider.create_session("agent-1")
        provider.execute_code("agent-1", h.session_id, "print(1)")
        provider.execute_code("agent-1", h.session_id, "print(2)")
        # One sandbox, two run() calls on it.
        assert len(_FakeSandbox.instances) == 1
        assert len(_FakeSandbox.instances[0].run_calls) == 2


# =========================================================================
# 4. Capability binding (the central security claim)
# =========================================================================


class TestCapabilityBinding:
    def test_no_policy_means_no_tools_no_domains(self, provider):
        provider.create_session("agent-1")
        sb = _FakeSandbox.instances[-1]
        assert sb.tools == {}
        assert sb.allowed_domains == []

    def test_tool_allowlist_registers_only_allowed(self, provider):
        policy = _make_policy(tool_allowlist=["web_search", "read_doc"])
        provider.create_session("agent-1", policy=policy)
        sb = _FakeSandbox.instances[-1]
        assert set(sb.tools) == {"web_search", "read_doc"}
        assert "delete_doc" not in sb.tools

    def test_unknown_tool_in_allowlist_fails_closed(self, provider):
        policy = _make_policy(tool_allowlist=["web_search", "ghost_tool"])
        with pytest.raises(ValueError, match="not registered with the provider"):
            provider.create_session("agent-1", policy=policy)
        # No sandbox should remain registered after the failed creation.
        assert provider.get_session_status("agent-1", "any") == (
            SessionStatus.DESTROYED
        )

    def test_network_allowlist_calls_allow_domain(self, provider):
        policy = _make_policy(
            network_allowlist=["https://api.arxiv.org", "https://pypi.org"]
        )
        provider.create_session("agent-1", policy=policy)
        sb = _FakeSandbox.instances[-1]
        assert sb.allowed_domains == [
            "https://api.arxiv.org",
            "https://pypi.org",
        ]

    def test_empty_network_allowlist_means_no_domains(self, provider):
        policy = _make_policy(network_allowlist=[])
        provider.create_session("agent-1", policy=policy)
        sb = _FakeSandbox.instances[-1]
        assert sb.allowed_domains == []

    def test_register_tool_failure_tears_down_sandbox(self, provider):
        _FakeSandbox.raise_on_register = True
        policy = _make_policy(tool_allowlist=["web_search"])
        with pytest.raises(RuntimeError, match="register_tool"):
            provider.create_session("agent-1", policy=policy)
        # The transient sandbox should have been closed.
        assert _FakeSandbox.instances[-1].closed is True

    def test_allow_domain_failure_tears_down_sandbox(self, provider):
        _FakeSandbox.raise_on_allow = True
        policy = _make_policy(network_allowlist=["https://x.test"])
        with pytest.raises(RuntimeError, match="allow_domain"):
            provider.create_session("agent-1", policy=policy)
        assert _FakeSandbox.instances[-1].closed is True

    def test_nanvix_rejects_tools_or_network(self, fake_sdk):
        from agent_sandbox.hyperlight_provider import HyperLightSandboxProvider

        p = HyperLightSandboxProvider(
            backend="nanvix",
            module=None,
            tools={"x": lambda: None},
        )
        with pytest.raises(ValueError, match="nanvix"):
            p.create_session(
                "agent-1", policy=_make_policy(tool_allowlist=["x"])
            )
        with pytest.raises(ValueError, match="nanvix"):
            p.create_session(
                "agent-1",
                policy=_make_policy(network_allowlist=["https://x.test"]),
            )


# =========================================================================
# 5. execute_code
# =========================================================================


class TestExecuteCode:
    def test_execute_returns_completed_handle(self, provider):
        h = provider.create_session("agent-1")
        _FakeSandbox.next_run_result = _FakeRunResult(
            stdout="hello", duration_ms=12
        )
        eh = provider.execute_code("agent-1", h.session_id, "print('hi')")
        assert eh.status == ExecutionStatus.COMPLETED
        assert eh.result is not None
        assert eh.result.stdout == "hello"
        assert eh.result.success is True
        assert eh.result.exit_code == 0

    def test_execute_failure_maps_to_failed(self, provider):
        h = provider.create_session("agent-1")
        _FakeSandbox.next_run_result = _FakeRunResult(
            stdout="", stderr="boom", exit_code=2
        )
        eh = provider.execute_code("agent-1", h.session_id, "raise SystemExit(2)")
        assert eh.status == ExecutionStatus.FAILED
        assert eh.result.exit_code == 2
        assert "boom" in eh.result.stderr

    def test_execute_without_session_raises(self, provider):
        with pytest.raises(RuntimeError, match="No active session"):
            provider.execute_code("agent-1", "missing", "print(1)")

    def test_run_exception_returns_failed_handle_not_raise(self, provider):
        h = provider.create_session("agent-1")
        _FakeSandbox.raise_on_run = RuntimeError("guest panic")
        eh = provider.execute_code("agent-1", h.session_id, "1/0")
        assert eh.status == ExecutionStatus.FAILED
        assert eh.result.success is False
        assert "guest panic" in eh.result.stderr

    def test_context_passed_via_globals(self, provider):
        h = provider.create_session("agent-1")
        provider.execute_code(
            "agent-1", h.session_id, "x=1", context={"k": "v"}
        )
        sb = _FakeSandbox.instances[-1]
        code, kwargs = sb.run_calls[-1]
        assert code == "x=1"
        assert kwargs.get("globals") == {"context": {"k": "v"}}

    def test_run_falls_back_when_globals_kwarg_unsupported(
        self, provider, monkeypatch
    ):
        h = provider.create_session("agent-1")

        # Make sandbox.run reject ``globals`` once, then succeed.
        sb = _FakeSandbox.instances[-1]
        original_run = sb.run
        calls: list[tuple[str, dict[str, Any]]] = []

        def picky_run(code: str, **kwargs: Any) -> _FakeRunResult:
            calls.append((code, dict(kwargs)))
            if "globals" in kwargs:
                raise TypeError("unexpected keyword argument 'globals'")
            return original_run(code)

        monkeypatch.setattr(sb, "run", picky_run)
        eh = provider.execute_code(
            "agent-1", h.session_id, "x=1", context={"k": "v"}
        )
        assert eh.status == ExecutionStatus.COMPLETED
        # Two attempts: with globals (TypeError), then without.
        assert len(calls) == 2
        assert "globals" in calls[0][1]
        assert "globals" not in calls[1][1]

    def test_timeout_flag_set_when_duration_exceeds(
        self, provider, monkeypatch
    ):
        h = provider.create_session("agent-1")
        # Force the run result to report a duration over the 30s policy
        # default we used above. We didn't pass a policy, so timeout
        # comes from the SandboxConfig default (60s) → use a higher
        # duration to trigger the kill flag.
        _FakeSandbox.next_run_result = _FakeRunResult(
            stdout="late", duration_ms=120_000
        )
        eh = provider.execute_code("agent-1", h.session_id, "sleep(120)")
        assert eh.result.killed is True
        assert "exceeded timeout" in eh.result.kill_reason
        assert eh.result.success is False

    def test_stdout_truncation(self, provider):
        h = provider.create_session("agent-1")
        _FakeSandbox.next_run_result = _FakeRunResult(stdout="A" * 50_000)
        eh = provider.execute_code("agent-1", h.session_id, "print('A' * 50000)")
        assert len(eh.result.stdout) == 10_000


# =========================================================================
# 6. Snapshots
# =========================================================================


class TestSnapshots:
    def test_snapshot_then_restore(self, provider):
        h = provider.create_session("agent-1")
        snap = provider.snapshot_session("agent-1", h.session_id)
        assert snap.agent_id == "agent-1"
        assert snap.session_id == h.session_id
        assert isinstance(snap.snapshot_id, str) and len(snap.snapshot_id) == 12
        # restore should not raise
        provider.restore_snapshot("agent-1", h.session_id, snap.snapshot_id)

    def test_snapshot_unknown_session_raises(self, provider):
        with pytest.raises(RuntimeError, match="No active session"):
            provider.snapshot_session("agent-1", "missing")

    def test_restore_unknown_snapshot_raises(self, provider):
        h = provider.create_session("agent-1")
        with pytest.raises(KeyError, match="Unknown snapshot"):
            provider.restore_snapshot("agent-1", h.session_id, "nope")

    def test_destroy_drops_snapshots(self, provider):
        h = provider.create_session("agent-1")
        snap = provider.snapshot_session("agent-1", h.session_id)
        provider.destroy_session("agent-1", h.session_id)
        # Recreate same agent_id with a new session: the old snapshot
        # id must no longer be reachable.
        h2 = provider.create_session("agent-1")
        with pytest.raises(KeyError):
            provider.restore_snapshot(
                "agent-1", h2.session_id, snap.snapshot_id
            )

    def test_nanvix_snapshot_unsupported(self, fake_sdk):
        from agent_sandbox.hyperlight_provider import HyperLightSandboxProvider

        p = HyperLightSandboxProvider(backend="nanvix", module=None)
        h = p.create_session("agent-1")
        with pytest.raises(RuntimeError, match="nanvix"):
            p.snapshot_session("agent-1", h.session_id)


# =========================================================================
# 7. Cancel & cleanup
# =========================================================================


class TestCancelAndCleanup:
    def test_cancel_calls_interrupt(self, provider):
        h = provider.create_session("agent-1")
        ok = provider.cancel_execution("agent-1", h.session_id, "anything")
        assert ok is True
        assert _FakeSandbox.instances[-1].interrupted is True

    def test_cancel_unknown_session_returns_false(self, provider):
        assert (
            provider.cancel_execution("agent-1", "missing", "exec") is False
        )

    def test_cancel_swallows_interrupt_errors(self, provider, monkeypatch):
        h = provider.create_session("agent-1")
        sb = _FakeSandbox.instances[-1]

        def bad():
            raise RuntimeError("nope")

        monkeypatch.setattr(sb, "interrupt", bad)
        assert (
            provider.cancel_execution("agent-1", h.session_id, "x") is False
        )

    def test_destroy_calls_close(self, provider):
        h = provider.create_session("agent-1")
        provider.destroy_session("agent-1", h.session_id)
        assert _FakeSandbox.instances[-1].closed is True


# =========================================================================
# 8. Async surface
# =========================================================================


class TestAsync:
    def test_execute_code_async(self, provider):
        h = provider.create_session("agent-1")
        _FakeSandbox.next_run_result = _FakeRunResult(stdout="async-ok")

        eh = asyncio.run(
            provider.execute_code_async("agent-1", h.session_id, "x=1")
        )
        assert eh.status == ExecutionStatus.COMPLETED
        assert eh.result.stdout == "async-ok"

    def test_create_destroy_async(self, provider):
        async def run():
            h = await provider.create_session_async("agent-1")
            assert h.status == SessionStatus.READY
            await provider.destroy_session_async("agent-1", h.session_id)
            return provider.get_session_status("agent-1", h.session_id)

        assert asyncio.run(run()) == SessionStatus.DESTROYED


# =========================================================================
# 9. Upstream signature compatibility
# =========================================================================


class TestUpstreamSignatureCompat:
    def test_falls_back_to_minimal_kwargs_on_typeerror(self, provider):
        # First create should still succeed even when upstream rejects
        # the full kwarg form.
        _FakeSandbox.accept_full_kwargs = False
        h = provider.create_session("agent-1")
        assert h.status == SessionStatus.READY
        sb = _FakeSandbox.instances[-1]
        # Minimal form: only backend (+ module for wasm) survives.
        assert set(sb.kwargs.keys()) <= {"backend", "module"}

    def test_missing_sandbox_class_raises(self, fake_sdk):
        delattr(fake_sdk, "Sandbox")
        from agent_sandbox.hyperlight_provider import HyperLightSandboxProvider

        p = HyperLightSandboxProvider()
        with pytest.raises(RuntimeError, match="Sandbox is not exposed"):
            p.create_session("agent-1")


# =========================================================================
# 10. Top-level package re-exports
# =========================================================================


class TestPackageReexports:
    def test_top_level_exports_hyperlight(self):
        import agent_sandbox

        assert agent_sandbox.HyperLightSandboxProvider is not None
        assert agent_sandbox.HyperlightConfig is not None
        assert agent_sandbox.SnapshotHandle is not None
        assert "HyperLightSandboxProvider" in agent_sandbox.__all__
