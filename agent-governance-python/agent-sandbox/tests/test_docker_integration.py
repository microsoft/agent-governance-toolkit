# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Integration tests that run against a real Docker daemon.

These tests are skipped automatically when Docker Desktop is not running
or the ``docker`` SDK is not installed.  Run them explicitly with::

    pytest tests/test_docker_integration.py -v

Every test creates short-lived containers and cleans them up in teardown.
"""

from __future__ import annotations

import asyncio
import textwrap
import time

import pytest

from agent_sandbox.sandbox_provider import (
    ExecutionStatus,
    SandboxConfig,
    SandboxResult,
    SessionStatus,
)
from agent_sandbox.isolation_runtime import IsolationRuntime

# ---------------------------------------------------------------------------
# Skip the entire module if Docker is not reachable
# ---------------------------------------------------------------------------

try:
    import docker

    _client = docker.from_env()
    _client.ping()
    _docker_available = True
except Exception:
    _docker_available = False

pytestmark = pytest.mark.skipif(
    not _docker_available,
    reason="Docker daemon is not running or docker SDK is not installed",
)

# Use a slim Python image for fast pulls
_TEST_IMAGE = "python:3.11-slim"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def provider():
    """Yield a real DockerSandboxProvider and destroy all sessions on teardown."""
    from agent_sandbox.docker_sandbox_provider import DockerSandboxProvider

    p = DockerSandboxProvider(image=_TEST_IMAGE)
    sessions: list[tuple[str, str]] = []
    yield p, sessions

    # Cleanup — destroy any sessions the test created
    for agent_id, session_id in sessions:
        try:
            p.destroy_session(agent_id, session_id)
        except Exception:
            pass


def _create(provider_tuple, agent_id="test-agent", **kwargs):
    """Helper: create a session and register it for cleanup."""
    p, sessions = provider_tuple
    h = p.create_session(agent_id, **kwargs)
    sessions.append((h.agent_id, h.session_id))
    return h


# =========================================================================
# 1. Provider availability
# =========================================================================


class TestProviderAvailability:
    def test_is_available(self, provider):
        p, _ = provider
        assert p.is_available() is True

    def test_runtime_is_detected(self, provider):
        p, _ = provider
        assert isinstance(p.runtime, IsolationRuntime)


# =========================================================================
# 2. Session lifecycle
# =========================================================================


class TestSessionLifecycle:
    def test_create_and_destroy(self, provider):
        p, sessions = provider
        h = _create(provider)
        assert h.status == SessionStatus.READY
        assert p.get_session_status(h.agent_id, h.session_id) == SessionStatus.READY

        p.destroy_session(h.agent_id, h.session_id)
        sessions.clear()  # already cleaned up
        assert p.get_session_status(h.agent_id, h.session_id) == SessionStatus.DESTROYED

    def test_multiple_sessions(self, provider):
        h1 = _create(provider, agent_id="a1")
        h2 = _create(provider, agent_id="a2")
        assert h1.session_id != h2.session_id
        assert h1.agent_id != h2.agent_id


# =========================================================================
# 3. Code execution
# =========================================================================


class TestCodeExecution:
    def test_hello_world(self, provider):
        p, _ = provider
        h = _create(provider)
        eh = p.execute_code(h.agent_id, h.session_id, "print('hello')")
        assert eh.status == ExecutionStatus.COMPLETED
        assert eh.result.success is True
        assert "hello" in eh.result.stdout

    def test_multiline_code(self, provider):
        p, _ = provider
        h = _create(provider)
        code = textwrap.dedent("""\
            import sys
            for i in range(3):
                print(i)
            print('python', sys.version_info.major)
        """)
        eh = p.execute_code(h.agent_id, h.session_id, code)
        assert eh.result.success
        assert "0" in eh.result.stdout
        assert "1" in eh.result.stdout
        assert "2" in eh.result.stdout
        assert "python 3" in eh.result.stdout

    def test_stderr_captured(self, provider):
        p, _ = provider
        h = _create(provider)
        eh = p.execute_code(
            h.agent_id, h.session_id,
            "import sys; sys.stderr.write('oops\\n')",
        )
        assert eh.result.success
        assert "oops" in eh.result.stderr

    def test_exit_code_nonzero(self, provider):
        p, _ = provider
        h = _create(provider)
        eh = p.execute_code(h.agent_id, h.session_id, "raise SystemExit(42)")
        assert eh.status == ExecutionStatus.FAILED
        assert eh.result.success is False
        assert eh.result.exit_code == 42

    def test_syntax_error(self, provider):
        p, _ = provider
        h = _create(provider)
        eh = p.execute_code(h.agent_id, h.session_id, "def ~~~")
        assert eh.result.success is False
        assert eh.result.exit_code != 0

    def test_multiple_executions_same_session(self, provider):
        """State persists across executions in the same session."""
        p, _ = provider
        h = _create(provider)

        # First exec: write a file
        p.execute_code(
            h.agent_id, h.session_id,
            "open('/workspace/flag.txt', 'w').write('yes')",
        )

        # Second exec: read it back
        eh = p.execute_code(
            h.agent_id, h.session_id,
            "print(open('/workspace/flag.txt').read())",
        )
        assert eh.result.success
        assert "yes" in eh.result.stdout


# =========================================================================
# 4. Resource limits
# =========================================================================


class TestResourceLimits:
    def test_memory_limit_applied(self, provider):
        """Container should respect memory limit (256 MB)."""
        p, _ = provider
        cfg = SandboxConfig(memory_mb=256)
        h = _create(provider, config=cfg)

        # Read cgroup memory limit inside the container
        eh = p.execute_code(
            h.agent_id, h.session_id,
            textwrap.dedent("""\
                import os
                # Try cgroup v2 first, fall back to v1
                paths = [
                    '/sys/fs/cgroup/memory.max',
                    '/sys/fs/cgroup/memory/memory.limit_in_bytes',
                ]
                for path in paths:
                    if os.path.exists(path):
                        val = open(path).read().strip()
                        print(val)
                        break
                else:
                    print('no-cgroup')
            """),
        )
        stdout = eh.result.stdout.strip()
        if stdout != "no-cgroup":
            limit = int(stdout)
            # 256 MB = 268435456 bytes
            assert limit == 256 * 1024 * 1024

    def test_pids_limit(self, provider):
        """Containers should have a PID limit of 256."""
        p, _ = provider
        h = _create(provider)

        eh = p.execute_code(
            h.agent_id, h.session_id,
            textwrap.dedent("""\
                import os
                paths = [
                    '/sys/fs/cgroup/pids.max',
                    '/sys/fs/cgroup/pids/pids.max',
                ]
                for path in paths:
                    if os.path.exists(path):
                        print(open(path).read().strip())
                        break
                else:
                    print('no-pids-cgroup')
            """),
        )
        stdout = eh.result.stdout.strip()
        if stdout != "no-pids-cgroup":
            assert stdout == "256"


# =========================================================================
# 5. Container hardening
# =========================================================================


class TestContainerHardening:
    def test_non_root_user(self, provider):
        """Container runs as nobody (UID 65534)."""
        p, _ = provider
        h = _create(provider)
        eh = p.execute_code(
            h.agent_id, h.session_id,
            "import os; print(os.getuid())",
        )
        assert eh.result.success
        assert eh.result.stdout.strip() == "65534"

    def test_read_only_root_fs(self, provider):
        """Root filesystem should be read-only by default."""
        p, _ = provider
        h = _create(provider)
        eh = p.execute_code(
            h.agent_id, h.session_id,
            textwrap.dedent("""\
                try:
                    open('/root_test', 'w').write('x')
                    print('writable')
                except OSError:
                    print('readonly')
            """),
        )
        assert "readonly" in eh.result.stdout

    def test_workspace_is_writable(self, provider):
        """The /workspace tmpfs should be writable."""
        p, _ = provider
        h = _create(provider)
        eh = p.execute_code(
            h.agent_id, h.session_id,
            textwrap.dedent("""\
                with open('/workspace/test.txt', 'w') as f:
                    f.write('ok')
                print(open('/workspace/test.txt').read())
            """),
        )
        assert eh.result.success
        assert "ok" in eh.result.stdout

    def test_network_disabled_by_default(self, provider):
        """Default config disables networking."""
        p, _ = provider
        h = _create(provider)
        eh = p.execute_code(
            h.agent_id, h.session_id,
            textwrap.dedent("""\
                import socket
                try:
                    socket.create_connection(('1.1.1.1', 80), timeout=2)
                    print('connected')
                except (OSError, socket.timeout):
                    print('blocked')
            """),
        )
        assert "blocked" in eh.result.stdout

    def test_network_enabled(self, provider):
        """When network is explicitly enabled, DNS should work."""
        p, _ = provider
        cfg = SandboxConfig(network_enabled=True)
        h = _create(provider, config=cfg)
        eh = p.execute_code(
            h.agent_id, h.session_id,
            textwrap.dedent("""\
                import socket
                try:
                    addr = socket.getaddrinfo('dns.google', 443)
                    print('resolved', len(addr))
                except Exception as e:
                    print('fail', e)
            """),
        )
        assert "resolved" in eh.result.stdout

    def test_capabilities_dropped(self, provider):
        """All capabilities should be dropped."""
        p, _ = provider
        h = _create(provider)
        eh = p.execute_code(
            h.agent_id, h.session_id,
            textwrap.dedent("""\
                import os
                # /proc/self/status has CapEff line
                with open('/proc/self/status') as f:
                    for line in f:
                        if line.startswith('CapEff:'):
                            val = int(line.split(':')[1].strip(), 16)
                            print('caps', val)
                            break
            """),
        )
        assert eh.result.success
        # All caps dropped → effective capabilities = 0
        assert "caps 0" in eh.result.stdout


# =========================================================================
# 6. Environment variable sanitization
# =========================================================================


class TestEnvVarIntegration:
    def test_safe_env_var_visible(self, provider):
        p, _ = provider
        cfg = SandboxConfig(env_vars={"MY_APP_KEY": "hello123"})
        h = _create(provider, config=cfg)
        eh = p.execute_code(
            h.agent_id, h.session_id,
            "import os; print(os.environ.get('MY_APP_KEY', 'missing'))",
        )
        assert "hello123" in eh.result.stdout

    def test_ld_preload_blocked(self, provider):
        p, _ = provider
        cfg = SandboxConfig(
            env_vars={"LD_PRELOAD": "/evil.so", "SAFE_VAR": "ok"},
        )
        h = _create(provider, config=cfg)
        eh = p.execute_code(
            h.agent_id, h.session_id,
            textwrap.dedent("""\
                import os
                print('LD_PRELOAD', os.environ.get('LD_PRELOAD', 'absent'))
                print('SAFE_VAR', os.environ.get('SAFE_VAR', 'absent'))
            """),
        )
        assert "LD_PRELOAD absent" in eh.result.stdout
        assert "SAFE_VAR ok" in eh.result.stdout


# =========================================================================
# 7. Low-level run()
# =========================================================================


class TestRunCommand:
    def test_run_echo(self, provider):
        p, _ = provider
        h = _create(provider)
        r = p.run(h.agent_id, ["echo", "hi"], session_id=h.session_id)
        assert r.success
        assert "hi" in r.stdout

    def test_run_nonexistent_command(self, provider):
        p, _ = provider
        h = _create(provider)
        r = p.run(
            h.agent_id,
            ["nonexistent_binary_xyz"],
            session_id=h.session_id,
        )
        assert r.success is False

    def test_duration_measured(self, provider):
        p, _ = provider
        h = _create(provider)
        r = p.run(
            h.agent_id,
            ["python", "-c", "import time; time.sleep(0.2)"],
            session_id=h.session_id,
        )
        assert r.duration_seconds >= 0.1


# =========================================================================
# 8. Checkpointing (save / restore / list / delete)
# =========================================================================


class TestCheckpointing:
    def test_save_and_list(self, provider):
        p, _ = provider
        h = _create(provider)

        # Write something to workspace
        p.execute_code(
            h.agent_id, h.session_id,
            "open('/workspace/state.txt', 'w').write('v1')",
        )

        cp = p.save_state(h.agent_id, h.session_id, "snap1")
        assert cp.name == "snap1"
        assert cp.agent_id == h.agent_id

        checkpoints = p.list_checkpoints(h.agent_id)
        names = [c.name for c in checkpoints]
        assert "snap1" in names

        # Cleanup checkpoint image
        p.delete_checkpoint(h.agent_id, "snap1")
        after = p.list_checkpoints(h.agent_id)
        assert "snap1" not in [c.name for c in after]

    def test_restore_checkpoint(self, provider):
        p, sessions = provider
        # Use read_only_fs=False so /tmp is part of the container's writable
        # layer rather than a tmpfs overlay (tmpfs is NOT captured by
        # ``docker commit``).
        cfg = SandboxConfig(read_only_fs=False)
        h = _create(provider, config=cfg)

        # Write state to /tmp (writable layer, not tmpfs)
        p.execute_code(
            h.agent_id, h.session_id,
            "open('/tmp/data.txt', 'w').write('original')",
        )
        p.save_state(h.agent_id, h.session_id, "restore-test")

        # Overwrite state
        p.execute_code(
            h.agent_id, h.session_id,
            "open('/tmp/data.txt', 'w').write('modified')",
        )

        # Restore: should get back 'original'
        p.restore_state(
            h.agent_id, h.session_id, "restore-test",
            config=cfg,
        )

        eh = p.execute_code(
            h.agent_id, h.session_id,
            "print(open('/tmp/data.txt').read())",
        )
        assert "original" in eh.result.stdout

        # Cleanup
        p.delete_checkpoint(h.agent_id, "restore-test")


# =========================================================================
# 9. Async interface
# =========================================================================


class TestAsyncInterface:
    def test_async_lifecycle(self, provider):
        p, sessions = provider

        async def _run():
            h = await p.create_session_async("async-agent")
            sessions.append((h.agent_id, h.session_id))
            assert h.status == SessionStatus.READY

            eh = await p.execute_code_async(
                h.agent_id, h.session_id, "print(1+1)",
            )
            assert eh.result.success
            assert "2" in eh.result.stdout

            await p.destroy_session_async(h.agent_id, h.session_id)
            sessions.remove((h.agent_id, h.session_id))

        asyncio.run(_run())


# =========================================================================
# 10. Execute after destroy
# =========================================================================


class TestErrorPaths:
    def test_execute_after_destroy_raises(self, provider):
        p, sessions = provider
        h = _create(provider)
        p.destroy_session(h.agent_id, h.session_id)
        sessions.remove((h.agent_id, h.session_id))

        with pytest.raises(RuntimeError, match="No active session"):
            p.execute_code(h.agent_id, h.session_id, "pass")

    def test_run_no_container(self, provider):
        p, _ = provider
        r = p.run("nonexistent", ["echo", "x"])
        assert r.success is False
        assert "No container" in r.stderr
