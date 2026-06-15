# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""End-to-end integration test for :class:`NonoSandboxProvider`.

Skipped by default. Runs only when:

1. ``nono-py`` is installed and ``nono_py.is_supported()`` reports the
   host can enforce a sandbox (Linux with Landlock, or macOS), **and**
2. the environment variable ``AGT_NONO_INTEGRATION=1`` is set.

Install the binding (Linux / macOS only) and enable the suite::

    pip install "agt-sandbox[nono]"
    export AGT_NONO_INTEGRATION=1
    pytest agent-governance-python/agent-sandbox/tests/test_nono_integration.py -v

The test exercises a complete flow against a real OS sandbox:

* construct a real ``NonoSandboxProvider``,
* create a session with policy-derived mounts,
* run pure-Python code and capture stdout,
* verify a non-zero exit surfaces as a failure (not a host crash),
* destroy the session and confirm the workspace is cleaned up.

Note: on macOS, Seatbelt forbids nested sandboxes, so this suite is also
skipped when it detects it is already running inside a sandbox.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from agent_sandbox.nono_sandbox_provider import NonoSandboxProvider
from agent_sandbox.sandbox_provider import (
    ExecutionStatus,
    SandboxConfig,
    SessionStatus,
)


def _nono_runnable() -> tuple[bool, str]:
    if os.environ.get("AGT_NONO_INTEGRATION") != "1":
        return False, "set AGT_NONO_INTEGRATION=1 to enable"
    try:
        import nono_py  # noqa: F401
    except ImportError:
        return False, "nono-py not installed (pip install agt-sandbox[nono])"
    if not NonoSandboxProvider().is_available():
        return False, "nono sandboxing not supported on this host"
    return True, ""


_runnable, _skip_reason = _nono_runnable()
pytestmark = pytest.mark.skipif(not _runnable, reason=_skip_reason)


@pytest.fixture
def provider() -> NonoSandboxProvider:
    return NonoSandboxProvider()


def test_end_to_end_execute(provider: NonoSandboxProvider) -> None:
    handle = provider.create_session(
        agent_id="nono-integration",
        config=SandboxConfig(timeout_seconds=20, network_enabled=False),
    )
    assert handle.status == SessionStatus.READY
    try:
        execution = provider.execute_code(
            handle.agent_id,
            handle.session_id,
            "print('hello from nono sandbox')",
        )
        assert execution.status == ExecutionStatus.COMPLETED
        assert execution.result.success is True
        assert "hello from nono sandbox" in execution.result.stdout
    finally:
        provider.destroy_session(handle.agent_id, handle.session_id)
        assert provider.get_session_status(
            handle.agent_id, handle.session_id
        ) == SessionStatus.DESTROYED


def test_nonzero_exit_surfaces_as_failure(provider: NonoSandboxProvider) -> None:
    handle = provider.create_session(agent_id="nono-integration-2")
    try:
        execution = provider.execute_code(
            handle.agent_id,
            handle.session_id,
            "import sys; sys.exit(3)",
        )
        assert execution.status == ExecutionStatus.FAILED
        assert execution.result.success is False
        assert execution.result.exit_code != 0
    finally:
        provider.destroy_session(handle.agent_id, handle.session_id)


def test_output_dir_persists_across_executions(
    provider: NonoSandboxProvider,
) -> None:
    handle = provider.create_session(agent_id="nono-integration-3")
    try:
        first = provider.execute_code(
            handle.agent_id,
            handle.session_id,
            "open('out.txt', 'w').write('persisted')",
        )
        assert first.result.success is True
        second = provider.execute_code(
            handle.agent_id,
            handle.session_id,
            "print(open('out.txt').read())",
        )
        assert second.result.success is True
        assert "persisted" in second.result.stdout
    finally:
        provider.destroy_session(handle.agent_id, handle.session_id)


def test_workspace_cleaned_up(provider: NonoSandboxProvider) -> None:
    handle = provider.create_session(agent_id="nono-integration-4")
    key = (handle.agent_id, handle.session_id)
    workspace = Path(provider._sessions[key].workspace)
    assert workspace.exists()
    provider.destroy_session(handle.agent_id, handle.session_id)
    assert not workspace.exists()
