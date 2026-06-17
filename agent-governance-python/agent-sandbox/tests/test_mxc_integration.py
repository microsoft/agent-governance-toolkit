# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""End-to-end integration test for :class:`MxcSandboxProvider`.

Skipped by default. Runs only when:

1. A real MXC native binary is discoverable (``MXC_BINARY`` env var or
   ``wxc-exec`` / ``lxc-exec`` / ``mxc-exec-mac`` on ``PATH``), **and**
2. The environment variable ``AGT_MXC_INTEGRATION=1`` is set.

MXC (https://github.com/microsoft/mxc) ships no Python SDK; build the
native binary from source per its README, then::

    # Linux (bubblewrap is the default backend)
    export MXC_BINARY=/path/to/lxc-exec
    export AGT_MXC_INTEGRATION=1
    pytest agent-governance-python/agent-sandbox/tests/test_mxc_integration.py -v

    # Windows
    $env:MXC_BINARY = "C:\\path\\to\\wxc-exec.exe"
    $env:AGT_MXC_INTEGRATION = "1"
    pytest agent-governance-python/agent-sandbox/tests/test_mxc_integration.py -v

The test exercises a complete flow against a real OS sandbox:

* construct a real ``MxcSandboxProvider``,
* create a session with policy-derived mounts,
* run pure-Python code and capture stdout,
* verify a non-zero exit surfaces as a failure (not a host crash),
* destroy the session and confirm the workspace is cleaned up.
"""

from __future__ import annotations

import os
import platform

import pytest

from agent_sandbox.mxc_sandbox_provider import MxcSandboxProvider
from agent_sandbox.sandbox_provider import (
    ExecutionStatus,
    SandboxConfig,
    SessionStatus,
)


def _default_backend() -> str | None:
    system = platform.system()
    if system == "Linux":
        return "bubblewrap"
    # Windows / macOS: let MXC pick the platform default.
    return None


def _mxc_runnable() -> tuple[bool, str]:
    if os.environ.get("AGT_MXC_INTEGRATION") != "1":
        return False, "set AGT_MXC_INTEGRATION=1 to enable"
    probe = MxcSandboxProvider(backend=_default_backend())
    if not probe.is_available():
        return False, "MXC binary not found (set MXC_BINARY or add to PATH)"
    return True, ""


_runnable, _skip_reason = _mxc_runnable()
pytestmark = pytest.mark.skipif(not _runnable, reason=_skip_reason)


@pytest.fixture
def provider() -> MxcSandboxProvider:
    return MxcSandboxProvider(backend=_default_backend())


def test_end_to_end_execute(provider: MxcSandboxProvider) -> None:
    handle = provider.create_session(
        agent_id="mxc-integration",
        config=SandboxConfig(timeout_seconds=20, network_enabled=False),
    )
    assert handle.status == SessionStatus.READY
    try:
        execution = provider.execute_code(
            handle.agent_id,
            handle.session_id,
            "print('hello from mxc sandbox')",
        )
        assert execution.status == ExecutionStatus.COMPLETED
        assert execution.result.success is True
        assert "hello from mxc sandbox" in execution.result.stdout
    finally:
        provider.destroy_session(handle.agent_id, handle.session_id)
        assert provider.get_session_status(
            handle.agent_id, handle.session_id
        ) == SessionStatus.DESTROYED


def test_nonzero_exit_surfaces_as_failure(provider: MxcSandboxProvider) -> None:
    handle = provider.create_session(agent_id="mxc-integration-2")
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


def test_workspace_cleaned_up(provider: MxcSandboxProvider) -> None:
    from pathlib import Path

    handle = provider.create_session(agent_id="mxc-integration-3")
    key = (handle.agent_id, handle.session_id)
    workspace = Path(provider._sessions[key].workspace)
    assert workspace.exists()
    provider.destroy_session(handle.agent_id, handle.session_id)
    assert not workspace.exists()
