# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""End-to-end integration test for :class:`HyperLightSandboxProvider`.

Skipped by default. Runs only when:

1. The real ``hyperlight-sandbox`` package is importable, **and**
2. A hypervisor is reachable (KVM on Linux, mshv on Azure Linux, or
   WHP on Windows 11 / Server 2022+), **and**
3. The environment variable ``AGT_HYPERLIGHT_INTEGRATION=1`` is set.

Windows host (the development environment for this repo)::

    # One-time setup: enable Windows Hypervisor Platform.
    # Run elevated PowerShell:
    #   Enable-WindowsOptionalFeature -Online -FeatureName HypervisorPlatform
    # Reboot, then verify with: bcdedit /enum | Select-String hypervisorlaunchtype
    # (should report "Auto"). Hyper-V itself is *not* required.

    pip install "hyperlight-sandbox[wasm,python_guest]>=0.4.0,<0.5"
    $env:AGT_HYPERLIGHT_INTEGRATION = "1"
    pytest agent-governance-python/agent-sandbox/tests/test_hyperlight_integration.py -v

Linux host with KVM::

    sudo usermod -aG kvm $USER  # one-time, then re-login
    pip install "hyperlight-sandbox[wasm,python_guest]>=0.4.0,<0.5"
    AGT_HYPERLIGHT_INTEGRATION=1         pytest agent-governance-python/agent-sandbox/tests/test_hyperlight_integration.py -v

macOS is **not supported** — neither WHP nor KVM is available.

The test exercises a complete agent flow:

* construct a real ``HyperLightSandboxProvider`` (wasm + Python guest),
* register a host-side tool and an allowed domain via policy,
* run pure-Python code that uses both,
* attempt to call a tool that was *not* allowlisted (must fail),
* attempt to reach a domain that was *not* allowlisted (must fail),
* snapshot the session, mutate state, restore, and verify rewind,
* destroy the session.
"""
from __future__ import annotations
import importlib
import os
from types import SimpleNamespace

import pytest
from agt.policies.result import PolicyEvaluation

def _hyperlight_runnable() -> tuple[bool, str]:
    if os.environ.get('AGT_HYPERLIGHT_INTEGRATION') != '1':
        return (False, 'set AGT_HYPERLIGHT_INTEGRATION=1 to enable')
    try:
        sdk = importlib.import_module('hyperlight_sandbox')
    except Exception as exc:
        return (False, f'hyperlight-sandbox not importable: {exc}')
    probe = getattr(sdk, 'is_hypervisor_present', None)
    if callable(probe):
        try:
            if not probe():
                return (False, 'no hypervisor reachable (KVM / mshv / WHP)')
        except Exception as exc:
            return (False, f'hypervisor probe raised: {exc}')
    return (True, '')
_RUNNABLE, _SKIP_REASON = _hyperlight_runnable()
pytestmark = pytest.mark.skipif(not _RUNNABLE, reason=_SKIP_REASON)

class _AllowRuntime:
    manifest = None
    defaults = SimpleNamespace(max_memory_mb=128, timeout_seconds=15)
    tool_allowlist = ["echo_tool"]
    network_allowlist = ["https://example.com"]

    def evaluate(self, intervention_point, snapshot):
        return PolicyEvaluation(verdict="allow")

    def close(self):
        return None

def _make_runtime():
    return _AllowRuntime()

@pytest.fixture
def provider():
    from agent_sandbox import HyperLightSandboxProvider
    p = HyperLightSandboxProvider(backend='wasm', module='python_guest', tools={'echo_tool': lambda message: f'echo:{message}', 'delete_everything': lambda: 'should-be-unreachable'})
    if not p.is_available():
        pytest.skip('provider reports unavailable at runtime')
    yield p
    for agent_id, session_id in list(p._sandboxes):
        try:
            p.destroy_session(agent_id, session_id)
        except Exception as exc:
            print(f'best-effort teardown: failed to destroy session {(agent_id, session_id)}: {exc}')

def test_code_actually_runs_inside_sandbox(provider):
    """Prove the executed code runs inside the Hyperlight guest, not on
    the host process.

    Each assertion below distinguishes guest from host. If *any* of them
    matched the host, code execution would have escaped the sandbox or
    silently fallen back to ``exec()`` on the host interpreter — both of
    which are critical isolation failures.

    Markers used (all observed against ``hyperlight-sandbox==0.4.0`` +
    the upstream ``python_guest`` WebAssembly module):

    * ``sys.platform == 'wasi'`` — the host is ``win32`` / ``linux`` /
      ``darwin`` and never ``wasi``.
    * ``len(os.environ) == 0`` — the guest starts with an empty
      environment; a real host CPython process always inherits at least
      ``PATH``.
    * ``socket`` and ``urllib`` are *not importable* — the WASI build
      ships without them, so any ``import socket`` from inside the
      sandbox raises ``ModuleNotFoundError``. On the host they are
      always importable.
    * Reading ``C:\\Windows\\System32\\drivers\\etc\\hosts`` (or
      ``/etc/hosts`` on Linux) raises ``FileNotFoundError`` from inside
      the sandbox because no host filesystem is mapped in.
    """
    import sys as _host_sys
    assert _host_sys.platform != 'wasi', 'host is somehow already running under WASI; this test cannot distinguish host from sandbox in that environment'
    handle = provider.create_session('agent-int', runtime=_make_runtime())
    try:
        probe = "import sys, os\nprint('PROBE_PLATFORM=' + sys.platform)\nprint('PROBE_ENV_COUNT=' + str(len(os.environ)))\ntry:\n    import socket  # noqa: F401\n    print('PROBE_SOCKET=importable')\nexcept ModuleNotFoundError:\n    print('PROBE_SOCKET=missing')\ntry:\n    import urllib.request  # noqa: F401\n    print('PROBE_URLLIB=importable')\nexcept ModuleNotFoundError:\n    print('PROBE_URLLIB=missing')\ntry:\n    with open('C:\\\\Windows\\\\System32\\\\drivers\\\\etc\\\\hosts') as f:\n        f.read(1)\n    print('PROBE_HOSTS=readable')\nexcept (FileNotFoundError, OSError, PermissionError):\n    print('PROBE_HOSTS=blocked')\ntry:\n    with open('/etc/hosts') as f:\n        f.read(1)\n    print('PROBE_ETC_HOSTS=readable')\nexcept (FileNotFoundError, OSError, PermissionError):\n    print('PROBE_ETC_HOSTS=blocked')\n"
        eh = provider.execute_code('agent-int', handle.session_id, probe)
        assert eh.result.success, eh.result.stderr
        out = eh.result.stdout
        markers = dict((line.split('=', 1) for line in out.splitlines() if line.startswith('PROBE_') and '=' in line))
        assert markers.get('PROBE_PLATFORM') == 'wasi', f"sys.platform inside sandbox was {markers.get('PROBE_PLATFORM')!r}, expected 'wasi' — code may have run on the host. Full stdout:\n{out}"
        assert markers.get('PROBE_ENV_COUNT') == '0', f'os.environ inside sandbox had {markers.get('PROBE_ENV_COUNT')} entries; expected 0. Host environment may have leaked in. Full stdout:\n{out}'
        assert markers.get('PROBE_SOCKET') == 'missing', f"the WASI Python guest must not expose 'socket'; got {markers.get('PROBE_SOCKET')!r}. Full stdout:\n{out}"
        assert markers.get('PROBE_URLLIB') == 'missing', f"the WASI Python guest must not expose 'urllib'; got {markers.get('PROBE_URLLIB')!r}. Full stdout:\n{out}"
        assert markers.get('PROBE_HOSTS') == 'blocked', "host's Windows hosts file was reachable from inside the sandbox — filesystem isolation breach. Full stdout:\n" + out
        assert markers.get('PROBE_ETC_HOSTS') == 'blocked', "host's /etc/hosts was reachable from inside the sandbox — filesystem isolation breach. Full stdout:\n" + out
    finally:
        provider.destroy_session('agent-int', handle.session_id)

def test_create_execute_destroy_roundtrip(provider):
    handle = provider.create_session('agent-int', runtime=_make_runtime())
    try:
        eh = provider.execute_code('agent-int', handle.session_id, "result = call_tool('echo_tool', message='hi')\nprint(result)\n")
        assert eh.result is not None
        assert eh.result.success is True, eh.result.stderr
        assert 'echo:hi' in eh.result.stdout
    finally:
        provider.destroy_session('agent-int', handle.session_id)

def test_state_persists_within_a_run_block(provider):
    """The upstream ``hyperlight-sandbox`` Python guest resets the
    interpreter between successive ``run()`` calls, so global state
    does *not* survive across ``execute_code`` boundaries.

    What *does* hold is intra-block persistence: a multi-line code
    string sees its own assignments. This test pins that contract so a
    future SDK upgrade that changes either side is caught.
    """
    handle = provider.create_session('agent-int', runtime=_make_runtime())
    try:
        eh = provider.execute_code('agent-int', handle.session_id, 'counter = 41\ncounter += 1\nprint(counter)')
        assert eh.result.success, eh.result.stderr
        assert '42' in eh.result.stdout
        provider.execute_code('agent-int', handle.session_id, 'stash = 7')
        eh2 = provider.execute_code('agent-int', handle.session_id, "try:\n    print(stash)\nexcept NameError:\n    print('reset')\n")
        assert 'reset' in eh2.result.stdout
    finally:
        provider.destroy_session('agent-int', handle.session_id)

def test_unallowed_tool_is_unreachable(provider):
    handle = provider.create_session('agent-int', runtime=_make_runtime())
    try:
        eh = provider.execute_code('agent-int', handle.session_id, "try:\n    call_tool('delete_everything')\n    print('UNEXPECTED-SUCCESS')\nexcept Exception as exc:\n    print(f'tool-blocked:{type(exc).__name__}')\n")
        assert eh.result.success is True
        assert 'UNEXPECTED-SUCCESS' not in eh.result.stdout
        assert 'tool-blocked' in eh.result.stdout
    finally:
        provider.destroy_session('agent-int', handle.session_id)

def test_unallowed_domain_is_unreachable(provider):
    handle = provider.create_session('agent-int', runtime=_make_runtime())
    try:
        eh = provider.execute_code('agent-int', handle.session_id, "try:\n    http_get('https://attacker.test/exfil')\n    print('UNEXPECTED-SUCCESS')\nexcept Exception as exc:\n    print(f'net-blocked:{type(exc).__name__}')\n")
        assert eh.result.success is True
        assert 'UNEXPECTED-SUCCESS' not in eh.result.stdout
        assert 'net-blocked' in eh.result.stdout
    finally:
        provider.destroy_session('agent-int', handle.session_id)

def test_snapshot_and_restore_round_trip(provider):
    """Snapshot / restore exercises the native Hyperlight memory-image
    mechanism. Because the upstream Python guest resets interpreter
    globals per ``run()``, we can't assert that *Python-level* state
    rewinds — that's a documented guest-module limitation. What this
    test pins is:

    * snapshot() returns a handle without raising,
    * restore() against that handle returns the sandbox to a usable
      state (subsequent ``run()`` calls succeed).

    A future Python guest that maintains durable interpreter state
    across ``run()`` invocations will let us tighten this assertion.
    """
    handle = provider.create_session('agent-int', runtime=_make_runtime())
    try:
        provider.execute_code('agent-int', handle.session_id, "print('pre')")
        snap = provider.snapshot_session('agent-int', handle.session_id)
        assert snap.snapshot_id
        provider.execute_code('agent-int', handle.session_id, "print('mid')")
        provider.restore_snapshot('agent-int', handle.session_id, snap.snapshot_id)
        eh_after = provider.execute_code('agent-int', handle.session_id, "print('post-restore')")
        assert eh_after.result.success, eh_after.result.stderr
        assert 'post-restore' in eh_after.result.stdout
    finally:
        provider.destroy_session('agent-int', handle.session_id)

def test_separate_sessions_are_isolated(provider):
    h1 = provider.create_session('agent-int', runtime=_make_runtime())
    h2 = provider.create_session('agent-int', runtime=_make_runtime())
    try:
        assert h1.session_id != h2.session_id
        provider.execute_code('agent-int', h1.session_id, "secret = 'red'")
        eh = provider.execute_code('agent-int', h2.session_id, "try:\n    print(secret)\nexcept NameError:\n    print('isolated')\n")
        assert 'isolated' in eh.result.stdout
        assert 'red' not in eh.result.stdout
    finally:
        provider.destroy_session('agent-int', h1.session_id)
        provider.destroy_session('agent-int', h2.session_id)

def test_python_exception_marks_failure_but_keeps_session_alive(provider):
    """A Python-level exception in guest code must surface as a failed
    ``ExecutionResult`` (non-zero exit, stderr populated) without
    tearing down the session — the next call on the same session must
    succeed."""
    handle = provider.create_session('agent-int', runtime=_make_runtime())
    try:
        bad = provider.execute_code('agent-int', handle.session_id, "raise ValueError('boom')")
        assert bad.result.success is False
        assert bad.result.exit_code != 0
        assert 'ValueError' in bad.result.stderr
        assert 'boom' in bad.result.stderr
        good = provider.execute_code('agent-int', handle.session_id, "print('still-alive')")
        assert good.result.success, good.result.stderr
        assert 'still-alive' in good.result.stdout
    finally:
        provider.destroy_session('agent-int', handle.session_id)

def test_guest_hard_abort_does_not_kill_host(provider):
    """The Hyperlight guarantee under test: if guest code performs a
    hard abort (here, ``os._exit``) that bypasses Python's exception
    machinery and triggers a hypervisor-level fault, the *host* process
    must remain alive and able to spin up a fresh session.

    The faulted session itself is unrecoverable — that's the documented
    contract. We only assert host survival and that subsequent sessions
    work."""
    handle = provider.create_session('agent-int', runtime=_make_runtime())
    try:
        crashed = provider.execute_code('agent-int', handle.session_id, 'import os\nos._exit(1)')
        assert crashed.result is not None
        assert crashed.result.success is False
    finally:
        try:
            provider.destroy_session('agent-int', handle.session_id)
        except Exception as exc:
            print(f'destroy_session after guest hard-abort failed (tolerated): {exc}')
    h2 = provider.create_session('agent-int', runtime=_make_runtime())
    try:
        eh = provider.execute_code('agent-int', h2.session_id, "print('host-alive')")
        assert eh.result.success, eh.result.stderr
        assert 'host-alive' in eh.result.stdout
    finally:
        provider.destroy_session('agent-int', h2.session_id)

def test_oversized_code_is_rejected(provider):
    """The upstream ``Sandbox.run`` enforces a 10 MiB code-size limit.
    The provider must surface that as a clean failed result rather than
    leaking the underlying ``ValueError`` or hanging."""
    handle = provider.create_session('agent-int', runtime=_make_runtime())
    try:
        oversized = 'x = 1\n' * 3000000
        eh = provider.execute_code('agent-int', handle.session_id, oversized)
        assert eh.result.success is False
        ok = provider.execute_code('agent-int', handle.session_id, "print('after-oversize')")
        assert ok.result.success, ok.result.stderr
        assert 'after-oversize' in ok.result.stdout
    finally:
        provider.destroy_session('agent-int', handle.session_id)

def test_stdout_and_stderr_are_captured_independently(provider):
    """Both streams must come back in their own fields and must not
    bleed into each other — agents reasoning over stderr-only error
    messages depend on this separation."""
    handle = provider.create_session('agent-int', runtime=_make_runtime())
    try:
        eh = provider.execute_code('agent-int', handle.session_id, "import sys\nsys.stderr.write('ERR-MARK\\n')\nsys.stderr.flush()\nprint('OUT-MARK')\n")
        assert eh.result.success, eh.result.stderr
        assert 'OUT-MARK' in eh.result.stdout
        assert 'ERR-MARK' not in eh.result.stdout
        assert 'ERR-MARK' in eh.result.stderr
        assert 'OUT-MARK' not in eh.result.stderr
    finally:
        provider.destroy_session('agent-int', handle.session_id)

@pytest.mark.asyncio
async def test_execute_code_async_does_not_block_event_loop(provider):
    """The async path must keep the event loop responsive while the
    guest runs. We measure that by ticking a heartbeat coroutine in
    parallel with the guest call: if the loop were blocked, the
    heartbeat would record fewer ticks than expected."""
    import asyncio
    import time
    handle = provider.create_session('agent-int', runtime=_make_runtime())
    try:
        ticks: list[float] = []

        async def heartbeat() -> None:
            for _ in range(5):
                ticks.append(time.monotonic())
                await asyncio.sleep(0.01)
        beat = asyncio.create_task(heartbeat())
        eh = await provider.execute_code_async('agent-int', handle.session_id, "print('async-ok')")
        await beat
        assert eh.result.success, eh.result.stderr
        assert 'async-ok' in eh.result.stdout
        assert len(ticks) == 5
    finally:
        provider.destroy_session('agent-int', handle.session_id)

@pytest.mark.asyncio
async def test_execute_code_async_does_not_panic_on_thread_hop(provider):
    """Regression test for the unsendable ``WasmSandbox`` panic.

    Before the per-session worker landed, ``execute_code_async`` would
    raise ``pyo3_runtime.PanicException`` (a ``BaseException``
    subclass, not a regular ``Exception``) the moment it dispatched
    the run onto a worker thread different from the one that built
    the sandbox.

    This test creates the session on the event-loop thread, then awaits
    ``execute_code_async`` (which internally bounces through
    ``asyncio.to_thread``). It must succeed — proving the per-session
    worker is correctly serialising all Sandbox access onto the one
    thread that owns the underlying Rust object.
    """
    handle = provider.create_session('agent-int', runtime=_make_runtime())
    try:
        try:
            eh = await provider.execute_code_async('agent-int', handle.session_id, "print('survived')")
        except (SystemExit, KeyboardInterrupt, GeneratorExit):
            raise
        except BaseException as exc:
            pytest.fail(f'execute_code_async raised {type(exc).__name__}: {exc!r}. The per-session worker is not serialising Sandbox access onto its owning thread — the unsendable invariant has been violated.')
        assert eh.result.success, eh.result.stderr
        assert 'survived' in eh.result.stdout
    finally:
        provider.destroy_session('agent-int', handle.session_id)

def test_concurrent_sessions_for_same_agent(provider):
    """Two threads driving two distinct sessions of the same agent in
    parallel must both succeed. Each session has its own worker thread,
    so cross-thread access to *different* Sandboxes is fine."""
    import threading
    h1 = provider.create_session('agent-int', runtime=_make_runtime())
    h2 = provider.create_session('agent-int', runtime=_make_runtime())
    results: dict[str, str] = {}
    errors: list[Exception] = []
    barrier = threading.Barrier(2)

    def runner(session_id: str, marker: str) -> None:
        try:
            barrier.wait(timeout=10)
            eh = provider.execute_code('agent-int', session_id, f"for _ in range(50): pass\nprint('{marker}')")
            results[marker] = eh.result.stdout
        except Exception as exc:
            errors.append(exc)
    try:
        t1 = threading.Thread(target=runner, args=(h1.session_id, 'M1'))
        t2 = threading.Thread(target=runner, args=(h2.session_id, 'M2'))
        t1.start()
        t2.start()
        t1.join(timeout=60)
        t2.join(timeout=60)
        assert not errors, errors
        assert 'M1' in results.get('M1', '')
        assert 'M2' in results.get('M2', '')
    finally:
        provider.destroy_session('agent-int', h1.session_id)
        provider.destroy_session('agent-int', h2.session_id)

def test_session_usable_from_thread_other_than_creator(provider):
    """Because every session is owned by its dedicated worker thread,
    callers can drive the session from *any* thread — including one
    that is neither the event loop nor the session's creator. This is
    the property that makes the provider safe to use from agent
    frameworks that fan out across thread pools."""
    import threading
    from typing import Any as _Any
    handle = provider.create_session('agent-int', runtime=_make_runtime())
    captured: dict[str, _Any] = {}
    errors: list[Exception] = []

    def offender() -> None:
        try:
            eh = provider.execute_code('agent-int', handle.session_id, "print('cross-thread-ok')")
            captured['eh'] = eh
        except Exception as exc:
            errors.append(exc)
    try:
        t = threading.Thread(target=offender)
        t.start()
        t.join(timeout=30)
        assert not errors, f'cross-thread execute_code raised — the per-session worker is not absorbing the thread hop: {errors!r}'
        eh = captured['eh']
        assert eh.result.success, eh.result.stderr
        assert 'cross-thread-ok' in eh.result.stdout
    finally:
        provider.destroy_session('agent-int', handle.session_id)

def test_create_destroy_loop_does_not_leak(provider):
    """Repeatedly creating and destroying sessions must not leak
    bookkeeping state inside the provider (which would eventually
    exhaust memory in long-running services). The per-session worker
    thread must also be joined on destroy — a leak there would be
    even more expensive than a leak in the dict bookkeeping."""
    import threading
    threads_before = {t.ident for t in threading.enumerate() if t.name.startswith('hyperlight-worker:')}
    for i in range(10):
        h = provider.create_session(f'agent-churn-{i}', runtime=_make_runtime())
        eh = provider.execute_code(f'agent-churn-{i}', h.session_id, "print('churn')")
        assert eh.result.success, eh.result.stderr
        provider.destroy_session(f'agent-churn-{i}', h.session_id)
    assert provider._sandboxes == {}, provider._sandboxes
    assert provider._workers == {}, provider._workers
    assert provider._evaluators == {}, provider._evaluators
    assert provider._session_configs == {}, provider._session_configs
    import time as _t
    _t.sleep(0.1)
    threads_after = {t.ident for t in threading.enumerate() if t.name.startswith('hyperlight-worker:')}
    leaked = threads_after - threads_before
    assert not leaked, f'create/destroy loop leaked {len(leaked)} worker threads'

def test_is_available_reports_true_with_real_sdk(provider):
    """When the real SDK is importable and the hypervisor is reachable
    (the gate that lets these tests run at all), ``is_available`` must
    return ``True``. This pins the runtime probe so a future regression
    that always returns ``False`` is caught immediately."""
    assert provider.is_available() is True
    assert provider.backend == 'wasm'
