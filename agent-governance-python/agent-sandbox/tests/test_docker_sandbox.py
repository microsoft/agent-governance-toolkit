# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Comprehensive tests for the agent-sandbox package.

Covers the SandboxProvider ABC, data types, enums, DockerSandboxProvider
(with mocked Docker), SandboxStateManager, IsolationRuntime, container
hardening, policy integration, async interface, multi-session isolation,
and edge cases.

All Docker interactions are mocked so tests run without a Docker daemon.
"""

from __future__ import annotations

import asyncio
import threading
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from agent_sandbox.sandbox_provider import (
    ExecutionHandle,
    ExecutionStatus,
    SandboxConfig,
    SandboxProvider,
    SandboxResult,
    SessionHandle,
    SessionStatus,
)
from agent_sandbox.isolation_runtime import IsolationRuntime
from agent_sandbox.docker_provider.provider import (
    DockerSandboxProvider,
    _BLOCKED_ENV_VARS,
    _is_protected_path,
    _sanitize_env_vars,
    _validate_mount_path,
    _validate_resource_name,
    docker_config_from_policy,
)
from agent_sandbox.docker_provider.state import SandboxCheckpoint


# =========================================================================
# Section 1: Data types & enums
# =========================================================================


class TestSessionStatus:
    def test_all_values(self):
        assert SessionStatus.PROVISIONING == "provisioning"
        assert SessionStatus.READY == "ready"
        assert SessionStatus.EXECUTING == "executing"
        assert SessionStatus.DESTROYING == "destroying"
        assert SessionStatus.DESTROYED == "destroyed"
        assert SessionStatus.FAILED == "failed"

    def test_is_string_enum(self):
        assert isinstance(SessionStatus.READY, str)


class TestExecutionStatus:
    def test_all_values(self):
        assert ExecutionStatus.PENDING == "pending"
        assert ExecutionStatus.RUNNING == "running"
        assert ExecutionStatus.COMPLETED == "completed"
        assert ExecutionStatus.CANCELLED == "cancelled"
        assert ExecutionStatus.FAILED == "failed"


class TestSandboxConfig:
    def test_defaults(self):
        cfg = SandboxConfig()
        assert cfg.timeout_seconds == 60.0
        assert cfg.memory_mb == 512
        assert cfg.cpu_limit == 1.0
        assert cfg.network_enabled is False
        assert cfg.read_only_fs is True
        assert cfg.env_vars == {}
        assert cfg.input_dir is None
        assert cfg.output_dir is None
        assert cfg.runtime is None

    def test_custom_values(self):
        cfg = SandboxConfig(
            timeout_seconds=30,
            memory_mb=1024,
            cpu_limit=2.0,
            network_enabled=True,
            read_only_fs=False,
            env_vars={"KEY": "VAL"},
            input_dir="/data/in",
            output_dir="/data/out",
            runtime="runsc",
        )
        assert cfg.memory_mb == 1024
        assert cfg.input_dir == "/data/in"
        assert cfg.runtime == "runsc"


class TestSandboxResult:
    def test_defaults(self):
        r = SandboxResult(success=True)
        assert r.exit_code == 0
        assert r.stdout == ""
        assert r.stderr == ""
        assert r.killed is False

    def test_failure_result(self):
        r = SandboxResult(
            success=False, exit_code=1, stderr="error",
            killed=True, kill_reason="oom",
        )
        assert not r.success
        assert r.kill_reason == "oom"


class TestSessionHandle:
    def test_creation(self):
        h = SessionHandle(agent_id="a1", session_id="s1")
        assert h.agent_id == "a1"
        assert h.session_id == "s1"
        assert h.status == SessionStatus.READY

    def test_custom_status(self):
        h = SessionHandle(
            agent_id="a1", session_id="s1",
            status=SessionStatus.FAILED,
        )
        assert h.status == SessionStatus.FAILED


class TestExecutionHandle:
    def test_creation(self):
        h = ExecutionHandle(
            execution_id="e1", agent_id="a1", session_id="s1",
        )
        assert h.execution_id == "e1"
        assert h.status == ExecutionStatus.COMPLETED
        assert h.result is None

    def test_with_result(self):
        r = SandboxResult(success=True, stdout="hello")
        h = ExecutionHandle(
            execution_id="e1", agent_id="a1", session_id="s1",
            result=r,
        )
        assert h.result.stdout == "hello"


class TestIsolationRuntime:
    def test_values(self):
        assert IsolationRuntime.RUNC == "runc"
        assert IsolationRuntime.GVISOR == "runsc"
        assert IsolationRuntime.KATA == "kata-runtime"
        assert IsolationRuntime.AUTO == "auto"

    def test_is_str_enum(self):
        assert isinstance(IsolationRuntime.RUNC, str)


class TestSandboxCheckpoint:
    def test_creation(self):
        cp = SandboxCheckpoint(
            agent_id="a1", name="cp1",
            image_tag="agent-sandbox-a1:cp1",
        )
        assert cp.agent_id == "a1"
        assert cp.name == "cp1"
        assert cp.image_tag == "agent-sandbox-a1:cp1"
        assert cp.created_at  # non-empty


# =========================================================================
# Section 2: SandboxProvider ABC
# =========================================================================


class TestSandboxProviderABC:
    def test_cannot_instantiate(self):
        with pytest.raises(TypeError):
            SandboxProvider()

    def test_default_get_session_status(self):
        """Default returns DESTROYED for unknown sessions."""

        class Minimal(SandboxProvider):
            def create_session(self, agent_id, policy=None, config=None):
                return SessionHandle(agent_id=agent_id, session_id="x")

            def execute_code(self, agent_id, session_id, code, *, context=None):
                return ExecutionHandle(
                    execution_id="x", agent_id=agent_id,
                    session_id=session_id,
                )

            def destroy_session(self, agent_id, session_id):
                pass

            def is_available(self):
                return True

        p = Minimal()
        assert p.get_session_status("a", "s") == SessionStatus.DESTROYED

    def test_default_cancel(self):
        class Minimal(SandboxProvider):
            def create_session(self, agent_id, policy=None, config=None):
                return SessionHandle(agent_id=agent_id, session_id="x")

            def execute_code(self, agent_id, session_id, code, *, context=None):
                return ExecutionHandle(
                    execution_id="x", agent_id=agent_id,
                    session_id=session_id,
                )

            def destroy_session(self, agent_id, session_id):
                pass

            def is_available(self):
                return True

        assert Minimal().cancel_execution("a", "s", "e") is False

    def test_default_run_raises(self):
        class Minimal(SandboxProvider):
            def create_session(self, agent_id, policy=None, config=None):
                return SessionHandle(agent_id=agent_id, session_id="x")

            def execute_code(self, agent_id, session_id, code, *, context=None):
                return ExecutionHandle(
                    execution_id="x", agent_id=agent_id,
                    session_id=session_id,
                )

            def destroy_session(self, agent_id, session_id):
                pass

            def is_available(self):
                return True

        # Default ``run()`` raises ``NotImplementedError`` so a custom
        # provider that forgets to override surfaces as a programming
        # error rather than silently returning a failure ``SandboxResult``.
        with pytest.raises(NotImplementedError, match="does not support"):
            Minimal().run("a", ["echo"])

    def test_async_delegates_to_sync(self):
        class Minimal(SandboxProvider):
            def create_session(self, agent_id, policy=None, config=None):
                return SessionHandle(agent_id=agent_id, session_id="abc")

            def execute_code(self, agent_id, session_id, code, *, context=None):
                return ExecutionHandle(
                    execution_id="x", agent_id=agent_id,
                    session_id=session_id,
                    result=SandboxResult(success=True, stdout=code),
                )

            def destroy_session(self, agent_id, session_id):
                pass

            def is_available(self):
                return True

        p = Minimal()
        h = asyncio.run(p.create_session_async("a1"))
        assert h.session_id == "abc"
        eh = asyncio.run(p.execute_code_async("a1", "abc", "hello"))
        assert eh.result.stdout == "hello"
        asyncio.run(p.destroy_session_async("a1", "abc"))
        r = asyncio.run(p.cancel_execution_async("a1", "abc", "e1"))
        assert r is False


# =========================================================================
# Section 3: Path validation helpers
# =========================================================================


class TestPathValidation:
    @pytest.mark.parametrize(
        "path",
        [
            "/", "/etc", "/proc", "/sys", "/usr", "/var",
            "/boot", "/dev", "/sbin", "/bin", "/lib",
        ],
    )
    @patch("os.path.realpath", side_effect=lambda p: p)
    @patch("agent_sandbox.docker_provider.provider.platform")
    def test_unix_protected_paths(self, mock_platform, _mock_realpath, path):
        mock_platform.system.return_value = "Linux"
        assert _is_protected_path(path) is True

    @patch("os.path.realpath", side_effect=lambda p: p)
    @patch("agent_sandbox.docker_provider.provider.platform")
    def test_unix_safe_path(self, mock_platform, _mock_realpath):
        mock_platform.system.return_value = "Linux"
        assert _is_protected_path("/home/user/data") is False

    @patch("os.path.realpath", side_effect=lambda p: p)
    @patch("agent_sandbox.docker_provider.provider.platform")
    def test_validate_mount_raises_for_protected(self, mock_platform, _mock_realpath):
        mock_platform.system.return_value = "Linux"
        with pytest.raises(ValueError, match="protected system directory"):
            _validate_mount_path("/etc", "input_dir")

    @patch("os.path.realpath", side_effect=lambda p: p)
    @patch("agent_sandbox.docker_provider.provider.platform")
    def test_validate_mount_safe(self, mock_platform, _mock_realpath):
        mock_platform.system.return_value = "Linux"
        _validate_mount_path("/home/user/data", "input_dir")  # no exception


# =========================================================================
# Section 4: docker_config_from_policy
# =========================================================================


class TestDockerConfigFromPolicy:
    def test_no_policy_attributes(self):
        policy = SimpleNamespace()
        base = SandboxConfig()
        cfg = docker_config_from_policy(policy, base)
        assert cfg.memory_mb == base.memory_mb
        assert cfg.network_enabled is False

    def test_network_allowlist_enables_network(self):
        policy = SimpleNamespace(network_allowlist=["api.example.com"])
        cfg = docker_config_from_policy(policy, SandboxConfig())
        assert cfg.network_enabled is True

    def test_no_network_allowlist(self):
        policy = SimpleNamespace(network_allowlist=None)
        cfg = docker_config_from_policy(policy, SandboxConfig())
        assert cfg.network_enabled is False

    def test_sandbox_mounts(self):
        mounts = SimpleNamespace(
            input_dir="/data/in", output_dir="/data/out",
        )
        policy = SimpleNamespace(sandbox_mounts=mounts)
        cfg = docker_config_from_policy(policy, SandboxConfig())
        assert cfg.input_dir == "/data/in"
        assert cfg.output_dir == "/data/out"

    def test_resource_limits_from_defaults(self):
        defaults = SimpleNamespace(max_memory_mb=2048, max_cpu=4.0)
        policy = SimpleNamespace(defaults=defaults)
        cfg = docker_config_from_policy(policy, SandboxConfig())
        assert cfg.memory_mb == 2048
        assert cfg.cpu_limit == 4.0

    def test_preserves_base_values(self):
        """Unrelated base config values are preserved."""
        base = SandboxConfig(
            timeout_seconds=120, read_only_fs=False,
            env_vars={"A": "1"},
        )
        policy = SimpleNamespace()
        cfg = docker_config_from_policy(policy, base)
        assert cfg.timeout_seconds == 120
        assert cfg.read_only_fs is False
        assert cfg.env_vars == {"A": "1"}


# =========================================================================
# Section 5: DockerSandboxProvider (mocked Docker)
# =========================================================================


def _make_mock_docker_client():
    """Create a mock Docker client with sensible defaults."""
    client = MagicMock()
    client.ping.return_value = True
    client.info.return_value = {"Runtimes": {"runc": {}}}
    return client


def _make_mock_container(agent_id="a1", session_id="s1"):
    """Create a mock container with exec_run support."""
    container = MagicMock()
    container.name = f"agent-sandbox-{agent_id}-{session_id}"
    container.status = "running"
    container.attrs = {
        "NetworkSettings": {"IPAddress": "172.17.0.2"},
    }
    container.exec_run.return_value = MagicMock(
        exit_code=0, output=(b"hello\n", b""),
    )
    container.labels = {
        "agent-sandbox.managed": "true",
        "agent-sandbox.agent-id": agent_id,
    }
    return container


@pytest.fixture
def docker_provider():
    """DockerSandboxProvider with a fully mocked Docker client."""
    with patch(
        "agent_sandbox.docker_provider.provider.DockerSandboxProvider.__init__",
        return_value=None,
    ):
        provider = DockerSandboxProvider.__new__(DockerSandboxProvider)
        provider._image = "python:3.11-slim"
        provider._tools = {}
        provider._requested_runtime = IsolationRuntime.AUTO
        provider._state_lock = threading.RLock()
        provider._containers = {}
        provider._evaluators = {}
        provider._session_configs = {}
        provider._exec_locks = {}
        provider._tool_proxy = None
        provider._network_proxy = None
        provider._state_manager = None
        provider._client = _make_mock_docker_client()
        provider._available = True
        provider._runtime = IsolationRuntime.RUNC

        def _create_container(agent_id, session_id, config, image=None):
            return _make_mock_container(agent_id, session_id)

        provider._create_container = MagicMock(
            side_effect=_create_container,
        )
        return provider


# -- create_session --------------------------------------------------------


class TestDockerCreateSession:
    def test_basic_create(self, docker_provider):
        h = docker_provider.create_session("a1")
        assert h.agent_id == "a1"
        assert len(h.session_id) == 8
        assert h.status == SessionStatus.READY
        assert (h.agent_id, h.session_id) in docker_provider._containers

    def test_unique_sessions(self, docker_provider):
        h1 = docker_provider.create_session("a1")
        h2 = docker_provider.create_session("a1")
        assert h1.session_id != h2.session_id

    def test_unavailable_raises(self, docker_provider):
        docker_provider._available = False
        with pytest.raises(RuntimeError, match="not available"):
            docker_provider.create_session("a1")

    def test_with_config(self, docker_provider):
        cfg = SandboxConfig(memory_mb=1024, cpu_limit=2.0)
        h = docker_provider.create_session("a1", config=cfg)
        assert h.status == SessionStatus.READY
        call_args = docker_provider._create_container.call_args
        assert call_args[0][2].memory_mb == 1024

    def test_with_policy_stores_evaluator(self, docker_provider):
        try:
            from agent_os.policies.schema import (
                PolicyDocument,
                PolicyRule,
                PolicyCondition,
                PolicyAction,
            )
        except ImportError:
            pytest.skip("agent-os-kernel not installed")

        doc = PolicyDocument(
            name="test",
            rules=[
                PolicyRule(
                    name="deny_dangerous",
                    condition=PolicyCondition(
                        field="action", operator="eq", value="delete",
                    ),
                    action=PolicyAction.DENY,
                    message="No deleting",
                )
            ],
        )
        h = docker_provider.create_session("a1", policy=doc)
        assert (h.agent_id, h.session_id) in docker_provider._evaluators

    def test_without_policy_no_evaluator(self, docker_provider):
        h = docker_provider.create_session("a1")
        assert ("a1", h.session_id) not in docker_provider._evaluators


# -- execute_code ----------------------------------------------------------


class TestDockerExecuteCode:
    def test_basic_execution(self, docker_provider):
        h = docker_provider.create_session("a1")
        eh = docker_provider.execute_code(
            "a1", h.session_id, "print('hello')",
        )
        assert eh.status == ExecutionStatus.COMPLETED
        assert eh.result.success
        assert "hello" in eh.result.stdout

    def test_without_session_raises(self, docker_provider):
        with pytest.raises(RuntimeError, match="No active session"):
            docker_provider.execute_code("a1", "nonexistent", "pass")

    def test_failure(self, docker_provider):
        h = docker_provider.create_session("a1")
        c = docker_provider._containers[(h.agent_id, h.session_id)]
        c.exec_run.return_value = MagicMock(
            exit_code=1, output=(b"", b"error\n"),
        )
        eh = docker_provider.execute_code("a1", h.session_id, "bad")
        assert eh.status == ExecutionStatus.FAILED
        assert "error" in eh.result.stderr

    def test_with_context(self, docker_provider):
        h = docker_provider.create_session("a1")
        eh = docker_provider.execute_code(
            "a1", h.session_id, "pass", context={"task": "test"},
        )
        assert eh.status == ExecutionStatus.COMPLETED

    def test_policy_deny(self, docker_provider):
        try:
            from agent_os.policies.schema import (
                PolicyDocument, PolicyRule,
                PolicyCondition, PolicyAction,
            )
        except ImportError:
            pytest.skip("agent-os-kernel not installed")

        doc = PolicyDocument(
            name="strict",
            rules=[
                PolicyRule(
                    name="deny_exec",
                    condition=PolicyCondition(
                        field="action", operator="eq", value="execute",
                    ),
                    action=PolicyAction.DENY,
                    message="All execution denied",
                )
            ],
        )
        h = docker_provider.create_session("a1", policy=doc)
        with pytest.raises(PermissionError, match="Policy denied"):
            docker_provider.execute_code(
                "a1", h.session_id, "print('hi')",
            )

    def test_policy_allow(self, docker_provider):
        try:
            from agent_os.policies.schema import (
                PolicyDocument, PolicyRule,
                PolicyCondition, PolicyAction,
            )
        except ImportError:
            pytest.skip("agent-os-kernel not installed")

        doc = PolicyDocument(
            name="permissive",
            rules=[
                PolicyRule(
                    name="allow_all",
                    condition=PolicyCondition(
                        field="action", operator="eq", value="execute",
                    ),
                    action=PolicyAction.ALLOW,
                    message="Allowed",
                )
            ],
        )
        h = docker_provider.create_session("a1", policy=doc)
        eh = docker_provider.execute_code(
            "a1", h.session_id, "print('hi')",
        )
        assert eh.status == ExecutionStatus.COMPLETED

    def test_execution_handle_fields(self, docker_provider):
        h = docker_provider.create_session("a1")
        eh = docker_provider.execute_code("a1", h.session_id, "pass")
        assert eh.agent_id == "a1"
        assert eh.session_id == h.session_id
        assert len(eh.execution_id) == 8
        assert eh.result is not None


# -- destroy_session -------------------------------------------------------


class TestDockerDestroySession:
    def test_basic_destroy(self, docker_provider):
        h = docker_provider.create_session("a1")
        c = docker_provider._containers[(h.agent_id, h.session_id)]
        docker_provider.destroy_session("a1", h.session_id)
        c.stop.assert_called_once_with(timeout=5)
        c.remove.assert_called_once_with(force=True)
        assert ("a1", h.session_id) not in docker_provider._containers

    def test_nonexistent_is_noop(self, docker_provider):
        docker_provider.destroy_session("a1", "nonexistent")

    def test_cleans_evaluator(self, docker_provider):
        try:
            from agent_os.policies.schema import PolicyDocument
        except ImportError:
            pytest.skip("agent-os-kernel not installed")

        doc = PolicyDocument(name="test")
        h = docker_provider.create_session("a1", policy=doc)
        assert (h.agent_id, h.session_id) in docker_provider._evaluators
        docker_provider.destroy_session("a1", h.session_id)
        assert ("a1", h.session_id) not in docker_provider._evaluators

    def test_tolerates_stop_error(self, docker_provider):
        h = docker_provider.create_session("a1")
        c = docker_provider._containers[(h.agent_id, h.session_id)]
        c.stop.side_effect = Exception("already stopped")
        docker_provider.destroy_session("a1", h.session_id)
        assert ("a1", h.session_id) not in docker_provider._containers

    def test_tolerates_remove_error(self, docker_provider):
        h = docker_provider.create_session("a1")
        c = docker_provider._containers[(h.agent_id, h.session_id)]
        c.remove.side_effect = Exception("already removed")
        docker_provider.destroy_session("a1", h.session_id)

    def test_idempotent(self, docker_provider):
        h = docker_provider.create_session("a1")
        docker_provider.destroy_session("a1", h.session_id)
        docker_provider.destroy_session("a1", h.session_id)

    def test_remove_failure_keeps_entry_for_retry(self, docker_provider):
        """Regression: previously the container was popped from the
        registry BEFORE stop()/remove() were called, so if both Docker
        calls failed there was no handle left to retry. Now the entry
        is retained when remove() fails, and a follow-up destroy_session
        can complete the cleanup once the underlying Docker issue
        clears.
        """
        h = docker_provider.create_session("a1")
        c = docker_provider._containers[(h.agent_id, h.session_id)]
        c.stop.side_effect = Exception("daemon unreachable")
        c.remove.side_effect = Exception("daemon unreachable")

        docker_provider.destroy_session("a1", h.session_id)

        # Entry must be retained so the caller can retry.
        assert ("a1", h.session_id) in docker_provider._containers

        # Once Docker comes back, retry succeeds and the entry is
        # finally removed.
        c.stop.side_effect = None
        c.remove.side_effect = None
        docker_provider.destroy_session("a1", h.session_id)
        assert ("a1", h.session_id) not in docker_provider._containers

    def test_remove_failure_keeps_evaluator_and_config(self, docker_provider):
        """When destroy_session fails to remove the container, it must
        also keep the evaluator and session config so a retry has the
        full per-session state to operate on.
        """
        try:
            from agent_os.policies.schema import PolicyDocument
        except ImportError:
            pytest.skip("agent-os-kernel not installed")

        doc = PolicyDocument(name="test")
        h = docker_provider.create_session("a1", policy=doc)
        c = docker_provider._containers[(h.agent_id, h.session_id)]
        c.stop.side_effect = Exception("daemon unreachable")
        c.remove.side_effect = Exception("daemon unreachable")

        docker_provider.destroy_session("a1", h.session_id)

        assert ("a1", h.session_id) in docker_provider._containers
        assert ("a1", h.session_id) in docker_provider._evaluators


# -- get_session_status ----------------------------------------------------


class TestDockerSessionStatus:
    def test_active(self, docker_provider):
        h = docker_provider.create_session("a1")
        assert (
            docker_provider.get_session_status("a1", h.session_id)
            == SessionStatus.READY
        )

    def test_destroyed(self, docker_provider):
        assert (
            docker_provider.get_session_status("a1", "missing")
            == SessionStatus.DESTROYED
        )


# -- run -------------------------------------------------------------------


class TestDockerRun:
    def test_no_container_returns_failure(self, docker_provider):
        r = docker_provider.run("a1", ["echo", "hi"])
        assert not r.success
        assert "No container found" in r.stderr

    def test_with_session_id(self, docker_provider):
        h = docker_provider.create_session("a1")
        r = docker_provider.run(
            "a1", ["python", "-c", "pass"],
            session_id=h.session_id,
        )
        assert r.success

    def test_restarts_stopped_container(self, docker_provider):
        h = docker_provider.create_session("a1")
        c = docker_provider._containers[(h.agent_id, h.session_id)]
        c.status = "exited"
        r = docker_provider.run(
            "a1", ["python", "-c", "pass"],
            session_id=h.session_id,
        )
        c.start.assert_called_once()
        assert r.success

    def test_handles_exception(self, docker_provider):
        h = docker_provider.create_session("a1")
        c = docker_provider._containers[(h.agent_id, h.session_id)]
        c.exec_run.side_effect = Exception("docker error")
        r = docker_provider.run(
            "a1", ["python", "-c", "pass"],
            session_id=h.session_id,
        )
        assert not r.success
        assert "docker error" in r.stderr

    def test_output_truncation(self, docker_provider):
        h = docker_provider.create_session("a1")
        c = docker_provider._containers[(h.agent_id, h.session_id)]
        c.exec_run.return_value = MagicMock(
            exit_code=0, output=(b"x" * 20000, b""),
        )
        cfg = SandboxConfig(output_max_bytes=10000)
        r = docker_provider.run(
            "a1", ["echo"], session_id=h.session_id, config=cfg,
        )
        assert len(r.stdout) == 10000

    def test_none_output_handled(self, docker_provider):
        h = docker_provider.create_session("a1")
        c = docker_provider._containers[(h.agent_id, h.session_id)]
        c.exec_run.return_value = MagicMock(
            exit_code=0, output=(None, None),
        )
        r = docker_provider.run(
            "a1", ["echo"], session_id=h.session_id,
        )
        assert r.success
        assert r.stdout == ""
        assert r.stderr == ""

    def test_legacy_lookup_by_agent_id(self, docker_provider):
        """Without session_id, finds any container for the agent."""
        docker_provider.create_session("a1")
        r = docker_provider.run("a1", ["python", "-c", "pass"])
        assert r.success


# -- properties ------------------------------------------------------------


class TestDockerProperties:
    def test_runtime(self, docker_provider):
        assert docker_provider.runtime == IsolationRuntime.RUNC

    def test_kernel_isolated_runc(self, docker_provider):
        assert docker_provider.kernel_isolated is False

    def test_kernel_isolated_gvisor(self, docker_provider):
        docker_provider._runtime = IsolationRuntime.GVISOR
        assert docker_provider.kernel_isolated is True

    def test_kernel_isolated_kata(self, docker_provider):
        docker_provider._runtime = IsolationRuntime.KATA
        assert docker_provider.kernel_isolated is True

    def test_is_available(self, docker_provider):
        assert docker_provider.is_available() is True

    def test_not_available(self, docker_provider):
        docker_provider._available = False
        assert docker_provider.is_available() is False


# =========================================================================
# Section 6: Container creation hardening
# =========================================================================


class TestContainerCreationHardening:
    def _make_raw_provider(self):
        with patch(
            "agent_sandbox.docker_provider.provider.DockerSandboxProvider.__init__",
            return_value=None,
        ):
            p = DockerSandboxProvider.__new__(DockerSandboxProvider)
            p._image = "python:3.11-slim"
            p._runtime = IsolationRuntime.RUNC
            mock_client = _make_mock_docker_client()
            mock_client.containers.run.return_value = _make_mock_container()
            p._client = mock_client
            return p, mock_client

    def test_hardening_flags(self):
        p, client = self._make_raw_provider()
        p._create_container("a1", "s1", SandboxConfig())
        kw = client.containers.run.call_args[1]
        assert kw["security_opt"] == [
            "no-new-privileges",
            "seccomp=default",
            "apparmor=docker-default",
        ]
        assert kw["cap_drop"] == ["ALL"]
        assert kw["read_only"] is True
        assert kw["user"] == "65534:65534"
        assert kw["working_dir"] == "/workspace"
        assert kw["pids_limit"] == 128
        assert kw["network_disabled"] is True
        assert kw["mem_limit"] == "512m"
        assert kw["detach"] is True
        assert kw["command"] == ["sleep", "infinity"]

    def test_tmpfs_mounts_readonly(self):
        p, client = self._make_raw_provider()
        p._create_container("a1", "s1", SandboxConfig(read_only_fs=True))
        kw = client.containers.run.call_args[1]
        assert "/workspace" in kw["tmpfs"]
        assert "/tmp" in kw["tmpfs"]

    def test_tmpfs_no_tmp_when_writable(self):
        p, client = self._make_raw_provider()
        p._create_container("a1", "s1", SandboxConfig(read_only_fs=False))
        kw = client.containers.run.call_args[1]
        assert "/workspace" in kw["tmpfs"]
        assert "/tmp" not in kw["tmpfs"]

    @patch("os.path.realpath", side_effect=lambda p: p)
    @patch("agent_sandbox.docker_provider.provider.platform")
    def test_volume_mounts(self, mock_platform, _mock_realpath):
        mock_platform.system.return_value = "Linux"
        p, client = self._make_raw_provider()
        cfg = SandboxConfig(input_dir="/data/in", output_dir="/data/out")
        p._create_container("a1", "s1", cfg)
        kw = client.containers.run.call_args[1]
        assert "/data/in" in kw["volumes"]
        assert kw["volumes"]["/data/in"]["mode"] == "ro"
        assert kw["volumes"]["/data/out"]["mode"] == "rw"

    @patch("os.path.realpath", side_effect=lambda p: p)
    @patch("agent_sandbox.docker_provider.provider.platform")
    def test_protected_input_dir_raises(self, mock_platform, _mock_realpath):
        mock_platform.system.return_value = "Linux"
        p, _ = self._make_raw_provider()
        with pytest.raises(ValueError, match="protected system directory"):
            p._create_container(
                "a1", "s1", SandboxConfig(input_dir="/etc"),
            )

    def test_runtime_gvisor(self):
        p, client = self._make_raw_provider()
        p._runtime = IsolationRuntime.GVISOR
        p._create_container("a1", "s1", SandboxConfig())
        kw = client.containers.run.call_args[1]
        assert kw["runtime"] == "runsc"

    def test_config_runtime_overrides(self):
        p, client = self._make_raw_provider()
        p._create_container(
            "a1", "s1", SandboxConfig(runtime="kata-runtime"),
        )
        kw = client.containers.run.call_args[1]
        assert kw["runtime"] == "kata-runtime"

    def test_network_enabled(self):
        p, client = self._make_raw_provider()
        p._create_container(
            "a1", "s1", SandboxConfig(network_enabled=True),
        )
        kw = client.containers.run.call_args[1]
        assert kw["network_disabled"] is False

    def test_container_name_format(self):
        p, client = self._make_raw_provider()
        p._create_container("research-agent", "abc12345", SandboxConfig())
        kw = client.containers.run.call_args[1]
        assert kw["name"] == "agent-sandbox-research-agent-abc12345"

    def test_labels(self):
        p, client = self._make_raw_provider()
        p._create_container("a1", "s1", SandboxConfig())
        kw = client.containers.run.call_args[1]
        assert kw["labels"]["agent-sandbox.managed"] == "true"
        assert kw["labels"]["agent-sandbox.agent-id"] == "a1"

    def test_nano_cpus_calculation(self):
        p, client = self._make_raw_provider()
        p._create_container("a1", "s1", SandboxConfig(cpu_limit=2.5))
        kw = client.containers.run.call_args[1]
        assert kw["nano_cpus"] == 2_500_000_000


# =========================================================================
# Section 7: Runtime detection
# =========================================================================


class TestRuntimeDetection:
    def test_detect_kata(self, docker_provider):
        docker_provider._client.info.return_value = {
            "Runtimes": {"runc": {}, "kata-runtime": {}},
        }
        assert docker_provider._detect_runtime() == IsolationRuntime.KATA

    def test_detect_gvisor(self, docker_provider):
        docker_provider._client.info.return_value = {
            "Runtimes": {"runc": {}, "runsc": {}},
        }
        assert docker_provider._detect_runtime() == IsolationRuntime.GVISOR

    def test_detect_fallback_runc(self, docker_provider):
        docker_provider._client.info.return_value = {
            "Runtimes": {"runc": {}},
        }
        assert docker_provider._detect_runtime() == IsolationRuntime.RUNC

    def test_detect_no_client(self, docker_provider):
        docker_provider._client = None
        assert docker_provider._detect_runtime() == IsolationRuntime.RUNC

    def test_detect_exception(self, docker_provider):
        docker_provider._client.info.side_effect = Exception("oops")
        assert docker_provider._detect_runtime() == IsolationRuntime.RUNC

    def test_detect_prefers_kata_over_gvisor(self, docker_provider):
        docker_provider._client.info.return_value = {
            "Runtimes": {"runc": {}, "runsc": {}, "kata-runtime": {}},
        }
        assert docker_provider._detect_runtime() == IsolationRuntime.KATA

    def test_validate_installed(self, docker_provider):
        docker_provider._client.info.return_value = {
            "Runtimes": {"runc": {}, "runsc": {}},
        }
        docker_provider._validate_runtime(IsolationRuntime.GVISOR)

    def test_validate_not_installed(self, docker_provider):
        docker_provider._client.info.return_value = {
            "Runtimes": {"runc": {}},
        }
        with pytest.raises(RuntimeError, match="not installed"):
            docker_provider._validate_runtime(IsolationRuntime.GVISOR)

    def test_validate_no_client(self, docker_provider):
        docker_provider._client = None
        with pytest.raises(RuntimeError, match="not available"):
            docker_provider._validate_runtime(IsolationRuntime.GVISOR)


# =========================================================================
# Section 8: SandboxStateManager
# =========================================================================


class TestSandboxStateManager:
    @pytest.fixture
    def provider_with_session(self, docker_provider):
        h = docker_provider.create_session("a1")
        return docker_provider, h

    def test_save_checkpoint(self, provider_with_session):
        provider, h = provider_with_session
        cp = provider.save_state("a1", h.session_id, "cp1")
        assert cp.agent_id == "a1"
        assert cp.name == "cp1"
        assert cp.image_tag == "agent-sandbox-a1:cp1"
        c = provider._containers[(h.agent_id, h.session_id)]
        c.commit.assert_called_once()
        kw = c.commit.call_args[1]
        assert kw["repository"] == "agent-sandbox-a1"
        assert kw["tag"] == "cp1"

    def test_save_no_container_raises(self, docker_provider):
        with pytest.raises(RuntimeError, match="No active container"):
            docker_provider.save_state("a1", "nonexistent", "cp1")

    def test_list_checkpoints(self, docker_provider):
        mock_img = MagicMock()
        mock_img.tags = ["agent-sandbox-a1:cp1", "agent-sandbox-a1:cp2"]
        mock_img.labels = {
            "agent-sandbox.created-at": "2026-04-20T00:00:00+00:00",
        }
        docker_provider._client.images.list.return_value = [mock_img]
        cps = docker_provider.list_checkpoints("a1")
        assert len(cps) == 2
        assert cps[0].name == "cp1"
        assert cps[1].name == "cp2"

    def test_list_checkpoints_empty(self, docker_provider):
        docker_provider._client.images.list.return_value = []
        assert docker_provider.list_checkpoints("a1") == []

    def test_list_checkpoints_exception(self, docker_provider):
        docker_provider._client.images.list.side_effect = Exception("err")
        assert docker_provider.list_checkpoints("a1") == []

    def test_delete_checkpoint(self, docker_provider):
        docker_provider.delete_checkpoint("a1", "cp1")
        docker_provider._client.images.remove.assert_called_once_with(
            image="agent-sandbox-a1:cp1", force=True,
        )

    def test_delete_checkpoint_error(self, docker_provider):
        docker_provider._client.images.remove.side_effect = Exception(
            "not found",
        )
        with pytest.raises(RuntimeError, match="Failed to delete"):
            docker_provider.delete_checkpoint("a1", "cp1")

    def test_restore_checkpoint(self, provider_with_session):
        provider, h = provider_with_session
        provider._client.images.get.return_value = MagicMock()
        provider.restore_state("a1", h.session_id, "cp1")
        assert ("a1", h.session_id) in provider._containers

    def test_restore_nonexistent_raises(self, provider_with_session):
        provider, h = provider_with_session
        provider._client.images.get.side_effect = Exception("not found")
        with pytest.raises(RuntimeError, match="not found"):
            provider.restore_state("a1", h.session_id, "missing")

    def test_restore_does_not_mutate_provider_image(self, provider_with_session):
        """Regression: restore previously swapped self._image to the
        checkpoint tag for the duration of _create_container, restoring
        in finally. Two concurrent restores could interleave and one
        would create a container from the OTHER restore's image. The
        fix removes the global mutation entirely; image is passed
        explicitly to _create_container.
        """
        provider, h = provider_with_session
        provider._client.images.get.return_value = MagicMock()
        original_image = provider._image

        provider.restore_state("a1", h.session_id, "cp1")

        # The provider's base image must not have been mutated by
        # restore — its only side effect should be the per-session
        # container slot pointing at a freshly-created container.
        assert provider._image == original_image

    def test_restore_passes_checkpoint_image_to_create_container(
        self, provider_with_session,
    ):
        """The checkpoint image tag must be passed to _create_container
        as an explicit ``image=`` argument so concurrent restores
        cannot race on a shared mutable attribute.
        """
        provider, h = provider_with_session
        provider._client.images.get.return_value = MagicMock()

        provider.restore_state("a1", h.session_id, "cp1")

        last_call = provider._create_container.call_args
        assert last_call.kwargs.get("image") == "agent-sandbox-a1:cp1"


# =========================================================================
# Section 9: Multi-session isolation
# =========================================================================


class TestMultiSessionIsolation:
    def test_separate_containers(self, docker_provider):
        h1 = docker_provider.create_session("a1")
        h2 = docker_provider.create_session("a2")
        assert h1.session_id != h2.session_id
        c1 = docker_provider._containers[("a1", h1.session_id)]
        c2 = docker_provider._containers[("a2", h2.session_id)]
        assert c1 is not c2

    def test_destroy_one_preserves_other(self, docker_provider):
        h1 = docker_provider.create_session("a1")
        h2 = docker_provider.create_session("a2")
        docker_provider.destroy_session("a1", h1.session_id)
        assert ("a1", h1.session_id) not in docker_provider._containers
        assert ("a2", h2.session_id) in docker_provider._containers

    def test_same_agent_multiple_sessions(self, docker_provider):
        h1 = docker_provider.create_session("a1")
        h2 = docker_provider.create_session("a1")
        assert h1.session_id != h2.session_id
        assert ("a1", h1.session_id) in docker_provider._containers
        assert ("a1", h2.session_id) in docker_provider._containers


# =========================================================================
# Section 10: Async interface (DockerSandboxProvider)
# =========================================================================


class TestDockerProviderAsync:
    def test_create_session_async(self, docker_provider):
        h = asyncio.run(docker_provider.create_session_async("a1"))
        assert h.agent_id == "a1"
        assert h.status == SessionStatus.READY

    def test_execute_code_async(self, docker_provider):
        h = asyncio.run(docker_provider.create_session_async("a1"))
        eh = asyncio.run(
            docker_provider.execute_code_async(
                "a1", h.session_id, "pass",
            )
        )
        assert eh.status == ExecutionStatus.COMPLETED

    def test_destroy_session_async(self, docker_provider):
        h = asyncio.run(docker_provider.create_session_async("a1"))
        asyncio.run(
            docker_provider.destroy_session_async("a1", h.session_id)
        )
        assert ("a1", h.session_id) not in docker_provider._containers

    def test_cancel_execution_async(self, docker_provider):
        r = asyncio.run(
            docker_provider.cancel_execution_async("a1", "s", "e")
        )
        assert r is False


# =========================================================================
# Section 11: Edge cases & error handling
# =========================================================================


class TestEdgeCases:
    def test_exec_run_exception(self, docker_provider):
        h = docker_provider.create_session("a1")
        c = docker_provider._containers[(h.agent_id, h.session_id)]
        c.exec_run.side_effect = Exception("OOM killed")
        eh = docker_provider.execute_code("a1", h.session_id, "pass")
        assert eh.status == ExecutionStatus.FAILED
        assert "OOM killed" in eh.result.stderr

    def test_empty_code(self, docker_provider):
        h = docker_provider.create_session("a1")
        eh = docker_provider.execute_code("a1", h.session_id, "")
        assert eh.status == ExecutionStatus.COMPLETED

    def test_destroy_twice(self, docker_provider):
        h = docker_provider.create_session("a1")
        docker_provider.destroy_session("a1", h.session_id)
        docker_provider.destroy_session("a1", h.session_id)

    def test_different_configs(self, docker_provider):
        cfg1 = SandboxConfig(memory_mb=256)
        cfg2 = SandboxConfig(memory_mb=1024, cpu_limit=4.0)
        docker_provider.create_session("a1", config=cfg1)
        docker_provider.create_session("a2", config=cfg2)
        calls = docker_provider._create_container.call_args_list
        assert calls[0][0][2].memory_mb == 256
        assert calls[1][0][2].memory_mb == 1024

    def test_duration_measured(self, docker_provider):
        h = docker_provider.create_session("a1")
        eh = docker_provider.execute_code("a1", h.session_id, "pass")
        assert eh.result.duration_seconds >= 0

    def test_full_lifecycle(self, docker_provider):
        """End-to-end: create → execute → checkpoint → destroy."""
        h = docker_provider.create_session("a1")
        eh = docker_provider.execute_code(
            "a1", h.session_id, "print('step1')",
        )
        assert eh.result.success

        cp = docker_provider.save_state("a1", h.session_id, "step1")
        assert cp.name == "step1"

        docker_provider.destroy_session("a1", h.session_id)
        assert ("a1", h.session_id) not in docker_provider._containers

    def test_package_import(self):
        """Verify top-level package exports work."""
        from agent_sandbox import (
            DockerSandboxProvider,
            ExecutionHandle,
            ExecutionStatus,
            IsolationRuntime,
            SandboxCheckpoint,
            SandboxConfig,
            SandboxProvider,
            SandboxResult,
            SandboxStateManager,
            SessionHandle,
            SessionStatus,
        )

        assert SandboxProvider is not None
        assert DockerSandboxProvider is not None


# =========================================================================
# Section 12: Container env_vars and extra_hosts
# =========================================================================


class TestContainerEnvVarsAndHosts:
    """Verify env_vars are passed to containers.run() and extra_hosts is set."""

    def _make_raw_provider(self):
        with patch(
            "agent_sandbox.docker_provider.provider.DockerSandboxProvider.__init__",
            return_value=None,
        ):
            p = DockerSandboxProvider.__new__(DockerSandboxProvider)
            p._image = "python:3.11-slim"
            p._runtime = IsolationRuntime.RUNC
            mock_client = _make_mock_docker_client()
            mock_client.containers.run.return_value = _make_mock_container()
            p._client = mock_client
            return p, mock_client

    def test_env_vars_passed_to_container(self):
        p, client = self._make_raw_provider()
        cfg = SandboxConfig(
            env_vars={"HTTP_PROXY": "http://host:9101", "FOO": "bar"},
        )
        p._create_container("a1", "s1", cfg)
        kw = client.containers.run.call_args[1]
        assert kw["environment"] == {
            "HTTP_PROXY": "http://host:9101",
            "FOO": "bar",
        }

    def test_empty_env_vars_not_passed(self):
        p, client = self._make_raw_provider()
        p._create_container("a1", "s1", SandboxConfig())
        kw = client.containers.run.call_args[1]
        assert "environment" not in kw

    def test_extra_hosts_always_set(self):
        p, client = self._make_raw_provider()
        p._create_container("a1", "s1", SandboxConfig())
        kw = client.containers.run.call_args[1]
        assert kw["extra_hosts"] == {
            "host.docker.internal": "host-gateway",
        }

    def test_env_vars_are_defensive_copy(self):
        """Mutating config.env_vars after creation must not affect container."""
        p, client = self._make_raw_provider()
        env = {"KEY": "val"}
        cfg = SandboxConfig(env_vars=env)
        p._create_container("a1", "s1", cfg)
        kw = client.containers.run.call_args[1]
        env["INJECTED"] = "bad"
        assert "INJECTED" not in kw["environment"]


# =========================================================================
# Section 13: Restore preserves policy evaluator
# =========================================================================


class TestRestorePreservesEvaluator:
    """restore_state must re-attach the PolicyEvaluator after destroy+recreate."""

    def test_evaluator_preserved_across_restore(self, docker_provider):
        h = docker_provider.create_session("a1")
        # Manually inject a fake evaluator
        fake_evaluator = MagicMock()
        docker_provider._evaluators[("a1", h.session_id)] = fake_evaluator

        docker_provider._client.images.get.return_value = MagicMock()
        docker_provider.restore_state("a1", h.session_id, "cp1")

        # The evaluator must be re-attached after restore
        assert ("a1", h.session_id) in docker_provider._evaluators
        assert docker_provider._evaluators[("a1", h.session_id)] is fake_evaluator

    def test_no_evaluator_stays_none_after_restore(self, docker_provider):
        h = docker_provider.create_session("a1")
        assert ("a1", h.session_id) not in docker_provider._evaluators

        docker_provider._client.images.get.return_value = MagicMock()
        docker_provider.restore_state("a1", h.session_id, "cp1")

        assert ("a1", h.session_id) not in docker_provider._evaluators


# =========================================================================
# Section 14: get_execution_status default
# =========================================================================


class TestGetExecutionStatus:
    """ABC default and DockerSandboxProvider behavior."""

    def test_abc_default_returns_completed(self):
        class Minimal(SandboxProvider):
            def create_session(self, agent_id, policy=None, config=None):
                return SessionHandle(agent_id=agent_id, session_id="x")

            def execute_code(self, agent_id, session_id, code, *, context=None):
                return ExecutionHandle(
                    execution_id="x", agent_id=agent_id,
                    session_id=session_id,
                )

            def destroy_session(self, agent_id, session_id):
                pass

            def is_available(self):
                return True

        p = Minimal()
        eh = p.get_execution_status("a1", "s1", "e1")
        assert eh.execution_id == "e1"
        assert eh.status == ExecutionStatus.COMPLETED

    def test_docker_provider_inherits_default(self, docker_provider):
        eh = docker_provider.get_execution_status("a1", "s1", "e1")
        assert eh.execution_id == "e1"
        assert eh.status == ExecutionStatus.COMPLETED


# =========================================================================
# Section 15: stderr truncation
# =========================================================================


class TestOutputTruncation:
    """Both stdout and stderr are capped to output_max_bytes."""

    def test_stderr_truncated(self, docker_provider):
        h = docker_provider.create_session("a1")
        c = docker_provider._containers[(h.agent_id, h.session_id)]
        c.exec_run.return_value = MagicMock(
            exit_code=1, output=(b"", b"e" * 20000),
        )
        cfg = SandboxConfig(output_max_bytes=10000)
        r = docker_provider.run(
            "a1", ["bad"], session_id=h.session_id, config=cfg,
        )
        assert len(r.stderr) == 10000

    def test_both_truncated(self, docker_provider):
        h = docker_provider.create_session("a1")
        c = docker_provider._containers[(h.agent_id, h.session_id)]
        c.exec_run.return_value = MagicMock(
            exit_code=0, output=(b"o" * 20000, b"e" * 20000),
        )
        cfg = SandboxConfig(output_max_bytes=10000)
        r = docker_provider.run(
            "a1", ["cmd"], session_id=h.session_id, config=cfg,
        )
        assert len(r.stdout) == 10000
        assert len(r.stderr) == 10000

    def test_default_cap_allows_normal_output(self, docker_provider):
        """Default output_max_bytes (1 MiB) doesn't truncate normal output."""
        h = docker_provider.create_session("a1")
        c = docker_provider._containers[(h.agent_id, h.session_id)]
        c.exec_run.return_value = MagicMock(
            exit_code=0, output=(b"x" * 500, b"y" * 300),
        )
        r = docker_provider.run(
            "a1", ["echo"], session_id=h.session_id,
        )
        assert len(r.stdout) == 500
        assert len(r.stderr) == 300


class TestStreamCappedConsumer:
    """Unit tests for _consume_stream_capped and _cap_output_bytes."""

    def test_stream_under_cap(self):
        from agent_sandbox.docker_provider.provider import _consume_stream_capped
        stream = iter([(b"hello", b"world"), (b" more", None)])
        stdout, stderr, truncated = _consume_stream_capped(stream, 1024)
        assert stdout == b"hello more"
        assert stderr == b"world"
        assert not truncated

    def test_stream_over_cap(self):
        from agent_sandbox.docker_provider.provider import (
            _consume_stream_capped,
            _OUTPUT_TRUNCATED_MARKER,
        )
        stream = iter([(b"a" * 100, b"b" * 100), (b"a" * 100, b"b" * 100)])
        stdout, stderr, truncated = _consume_stream_capped(stream, 50)
        marker = _OUTPUT_TRUNCATED_MARKER.encode()
        assert stdout == b"a" * 50 + marker
        assert stderr == b"b" * 50 + marker
        assert truncated

    def test_stream_empty(self):
        from agent_sandbox.docker_provider.provider import _consume_stream_capped
        stream = iter([])
        stdout, stderr, truncated = _consume_stream_capped(stream, 1024)
        assert stdout is None
        assert stderr is None
        assert not truncated

    def test_cap_output_bytes_under_limit(self):
        from agent_sandbox.docker_provider.provider import _cap_output_bytes
        stdout, stderr, truncated = _cap_output_bytes(
            (b"hello", b"world"), 1024,
        )
        assert stdout == b"hello"
        assert stderr == b"world"
        assert not truncated

    def test_cap_output_bytes_over_limit(self):
        from agent_sandbox.docker_provider.provider import (
            _cap_output_bytes,
            _OUTPUT_TRUNCATED_MARKER,
        )
        stdout, stderr, truncated = _cap_output_bytes(
            (b"x" * 2000, b"y" * 2000), 1000,
        )
        marker = _OUTPUT_TRUNCATED_MARKER.encode()
        assert stdout == b"x" * 1000 + marker
        assert stderr == b"y" * 1000 + marker
        assert truncated

    def test_cap_output_bytes_none_input(self):
        from agent_sandbox.docker_provider.provider import _cap_output_bytes
        stdout, stderr, truncated = _cap_output_bytes(None, 1024)
        assert stdout is None
        assert stderr is None
        assert not truncated


# =========================================================================
# Section 16: docker_config_from_policy edge cases
# =========================================================================


class TestDockerConfigFromPolicyAdvanced:
    """Additional policy extraction tests from the design doc."""

    def test_empty_network_allowlist_keeps_network_disabled(self):
        policy = SimpleNamespace(network_allowlist=[])
        cfg = docker_config_from_policy(policy, SandboxConfig())
        assert cfg.network_enabled is False

    def test_mounts_with_only_input(self):
        mounts = SimpleNamespace(input_dir="/data/in", output_dir=None)
        policy = SimpleNamespace(sandbox_mounts=mounts)
        cfg = docker_config_from_policy(policy, SandboxConfig())
        assert cfg.input_dir == "/data/in"
        assert cfg.output_dir is None

    def test_mounts_with_only_output(self):
        mounts = SimpleNamespace(input_dir=None, output_dir="/data/out")
        policy = SimpleNamespace(sandbox_mounts=mounts)
        cfg = docker_config_from_policy(policy, SandboxConfig())
        assert cfg.input_dir is None
        assert cfg.output_dir == "/data/out"

    def test_partial_defaults_only_memory(self):
        defaults = SimpleNamespace(max_memory_mb=4096)
        policy = SimpleNamespace(defaults=defaults)
        cfg = docker_config_from_policy(policy, SandboxConfig())
        assert cfg.memory_mb == 4096
        assert cfg.cpu_limit == 1.0  # unchanged

    def test_partial_defaults_only_cpu(self):
        defaults = SimpleNamespace(max_cpu=8.0)
        policy = SimpleNamespace(defaults=defaults)
        cfg = docker_config_from_policy(policy, SandboxConfig())
        assert cfg.memory_mb == 512  # unchanged
        assert cfg.cpu_limit == 8.0

    def test_base_env_vars_not_mutated(self):
        """Ensure docker_config_from_policy makes a copy of env_vars."""
        base = SandboxConfig(env_vars={"A": "1"})
        policy = SimpleNamespace()
        cfg = docker_config_from_policy(policy, base)
        cfg.env_vars["B"] = "2"
        assert "B" not in base.env_vars


# =========================================================================
# Section 17: Session lifecycle — context manager pattern
# =========================================================================


class TestSessionLifecyclePattern:
    """Test patterns from the design doc's session lifecycle section."""

    def test_create_execute_checkpoint_restore_destroy(self, docker_provider):
        """Full lifecycle: create → execute → save → restore → execute → destroy."""
        h = docker_provider.create_session("a1")

        # Execute
        eh1 = docker_provider.execute_code("a1", h.session_id, "pass")
        assert eh1.result.success

        # Checkpoint
        cp = docker_provider.save_state("a1", h.session_id, "mid")
        assert cp.name == "mid"

        # Restore
        docker_provider._client.images.get.return_value = MagicMock()
        docker_provider.restore_state("a1", h.session_id, "mid")
        assert ("a1", h.session_id) in docker_provider._containers

        # Execute again after restore
        eh2 = docker_provider.execute_code("a1", h.session_id, "pass")
        assert eh2.result.success

        # Destroy
        docker_provider.destroy_session("a1", h.session_id)
        assert ("a1", h.session_id) not in docker_provider._containers

    def test_execute_after_destroy_raises(self, docker_provider):
        h = docker_provider.create_session("a1")
        docker_provider.destroy_session("a1", h.session_id)
        with pytest.raises(RuntimeError, match="No active session"):
            docker_provider.execute_code("a1", h.session_id, "pass")

    def test_save_state_after_destroy_raises(self, docker_provider):
        h = docker_provider.create_session("a1")
        docker_provider.destroy_session("a1", h.session_id)
        with pytest.raises(RuntimeError, match="No active container"):
            docker_provider.save_state("a1", h.session_id, "cp1")

    def test_concurrent_agents_isolated(self, docker_provider):
        """Two agents with different configs don't interfere."""
        h1 = docker_provider.create_session(
            "agent-a", config=SandboxConfig(memory_mb=256),
        )
        h2 = docker_provider.create_session(
            "agent-b", config=SandboxConfig(memory_mb=1024),
        )

        # Execute on both
        eh1 = docker_provider.execute_code("agent-a", h1.session_id, "a")
        eh2 = docker_provider.execute_code("agent-b", h2.session_id, "b")
        assert eh1.result.success
        assert eh2.result.success

        # Destroy one — other remains
        docker_provider.destroy_session("agent-a", h1.session_id)
        assert docker_provider.get_session_status(
            "agent-a", h1.session_id
        ) == SessionStatus.DESTROYED
        assert docker_provider.get_session_status(
            "agent-b", h2.session_id
        ) == SessionStatus.READY


# =========================================================================
# Section 18: Windows path protection
# =========================================================================


class TestWindowsPathProtection:
    @patch("agent_sandbox.docker_provider.provider.platform")
    def test_drive_root_blocked(self, mock_platform):
        mock_platform.system.return_value = "Windows"
        assert _is_protected_path("C:\\") is True

    @patch("agent_sandbox.docker_provider.provider.platform")
    def test_drive_letter_only_blocked(self, mock_platform):
        mock_platform.system.return_value = "Windows"
        assert _is_protected_path("D:") is True

    @patch("agent_sandbox.docker_provider.provider.platform")
    def test_windows_safe_path(self, mock_platform):
        mock_platform.system.return_value = "Windows"
        assert _is_protected_path("C:\\Users\\agent\\data") is False


# =========================================================================
# Section 19: Environment variable sanitization
# =========================================================================


class TestEnvVarSanitization:
    """Verify _sanitize_env_vars blocks dangerous environment variables."""

    def test_blocks_ld_preload(self):
        env = {"LD_PRELOAD": "/evil.so", "APP_KEY": "val"}
        result = _sanitize_env_vars(env)
        assert "LD_PRELOAD" not in result
        assert result["APP_KEY"] == "val"

    def test_blocks_ld_library_path(self):
        env = {"LD_LIBRARY_PATH": "/evil", "SAFE": "1"}
        result = _sanitize_env_vars(env)
        assert "LD_LIBRARY_PATH" not in result
        assert result["SAFE"] == "1"

    def test_blocks_pythonstartup(self):
        env = {"PYTHONSTARTUP": "/evil.py"}
        result = _sanitize_env_vars(env)
        assert len(result) == 0

    def test_blocks_pythonpath(self):
        env = {"PYTHONPATH": "/evil"}
        result = _sanitize_env_vars(env)
        assert len(result) == 0

    def test_blocks_all_ld_variants(self):
        env = {
            "LD_AUDIT": "/x",
            "LD_DEBUG": "all",
            "LD_PROFILE": "x",
            "LD_SHOW_AUXV": "1",
            "LD_DYNAMIC_WEAK": "1",
        }
        result = _sanitize_env_vars(env)
        assert len(result) == 0

    def test_case_insensitive_blocking(self):
        env = {"ld_preload": "/evil.so"}
        result = _sanitize_env_vars(env)
        assert "ld_preload" not in result

    def test_safe_vars_pass_through(self):
        env = {"HTTP_PROXY": "http://proxy:8080", "APP_MODE": "prod"}
        result = _sanitize_env_vars(env)
        assert result == env

    def test_empty_env(self):
        assert _sanitize_env_vars({}) == {}

    def test_blocked_vars_constant_complete(self):
        """Ensure all known dangerous vars are in the blocklist."""
        expected = {
            # glibc dynamic linker
            "LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT",
            "LD_DEBUG", "LD_PROFILE", "LD_SHOW_AUXV",
            "LD_DYNAMIC_WEAK",
            # POSIX shell startup hooks
            "BASH_ENV", "ENV",
            # Python
            "PYTHONSTARTUP", "PYTHONPATH", "PYTHONHOME",
            # Node.js
            "NODE_OPTIONS",
            # Ruby
            "RUBYOPT",
            # Perl
            "PERL5LIB", "PERL5OPT",
            # Java
            "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS",
        }
        assert _BLOCKED_ENV_VARS == expected

    def test_sanitized_env_in_container(self):
        """Verify _create_container applies sanitization."""
        with patch(
            "agent_sandbox.docker_provider.provider."
            "DockerSandboxProvider.__init__",
            return_value=None,
        ):
            p = DockerSandboxProvider.__new__(DockerSandboxProvider)
            p._image = "python:3.11-slim"
            p._runtime = IsolationRuntime.RUNC
            mock_client = _make_mock_docker_client()
            mock_client.containers.run.return_value = _make_mock_container()
            p._client = mock_client

        cfg = SandboxConfig(
            env_vars={"LD_PRELOAD": "/evil.so", "APP_KEY": "safe"},
        )
        p._create_container("a1", "s1", cfg)
        kw = mock_client.containers.run.call_args[1]
        assert "LD_PRELOAD" not in kw["environment"]
        assert kw["environment"]["APP_KEY"] == "safe"


# =========================================================================
# Section 20: Fail-closed policy enforcement
# =========================================================================


class TestFailClosedPolicy:
    """Policy enforcement must fail closed on non-ImportError exceptions."""

    def test_policy_import_error_warns_only(self, docker_provider):
        """ImportError (SDK not installed) results in warning, not failure."""
        with patch(
            "agent_sandbox.docker_provider.provider.docker_config_from_policy",
            return_value=SandboxConfig(),
        ):
            with patch.dict(
                "sys.modules",
                {"agent_os": None, "agent_os.policies": None,
                 "agent_os.policies.evaluator": None},
            ):
                h = docker_provider.create_session(
                    "a1", policy=SimpleNamespace(),
                )
                assert h.status == SessionStatus.READY

    def test_policy_other_error_raises(self, docker_provider):
        """Non-ImportError exceptions must propagate (fail closed)."""
        with patch(
            "agent_sandbox.docker_provider.provider.docker_config_from_policy",
            return_value=SandboxConfig(),
        ):
            with patch(
                "builtins.__import__",
                side_effect=RuntimeError("policy engine broken"),
            ):
                with pytest.raises(RuntimeError, match="Failed to initialize"):
                    docker_provider.create_session(
                        "a1", policy=SimpleNamespace(),
                    )


# =========================================================================
# Section 21: Symlink resolution in path validation
# =========================================================================


class TestSymlinkResolution:
    """_is_protected_path must resolve symlinks before checking."""

    @patch("agent_sandbox.docker_provider.provider.platform")
    @patch("os.path.realpath")
    def test_symlink_to_etc_blocked(self, mock_realpath, mock_platform):
        mock_platform.system.return_value = "Linux"
        mock_realpath.return_value = "/etc"
        assert _is_protected_path("/tmp/sneaky-link") is True

    @patch("agent_sandbox.docker_provider.provider.platform")
    @patch("os.path.realpath")
    def test_symlink_to_proc_blocked(self, mock_realpath, mock_platform):
        mock_platform.system.return_value = "Linux"
        mock_realpath.return_value = "/proc"
        assert _is_protected_path("/tmp/proc-link") is True

    @patch("agent_sandbox.docker_provider.provider.platform")
    @patch("os.path.realpath")
    def test_symlink_to_safe_path_allowed(self, mock_realpath, mock_platform):
        mock_platform.system.return_value = "Linux"
        mock_realpath.return_value = "/home/agent/data"
        assert _is_protected_path("/tmp/safe-link") is False

    @patch("agent_sandbox.docker_provider.provider.platform")
    @patch("os.path.realpath")
    def test_validate_mount_path_symlink_blocked(
        self, mock_realpath, mock_platform,
    ):
        mock_platform.system.return_value = "Linux"
        mock_realpath.return_value = "/usr"
        with pytest.raises(ValueError, match="protected system directory"):
            _validate_mount_path("/tmp/usr-link", "input_dir")


# =========================================================================
# Section 22: Timeout watchdog
# =========================================================================


class TestTimeoutWatchdog:
    """Verify timeout_seconds is enforced via a watchdog thread."""

    def test_timeout_kills_exec_process_not_container(self, docker_provider):
        """When an exec exceeds its timeout, only the offending exec
        process is killed — NOT the entire container. This preserves
        guest state from prior execute_code calls in the same session.
        """
        import time as _time

        h = docker_provider.create_session("a1")
        c = docker_provider._containers[(h.agent_id, h.session_id)]

        # Drive the timeout path through the low-level API. Simulate
        # exec_start blocking longer than the configured timeout.
        api = docker_provider._client.api
        api.exec_create.return_value = {"Id": "exec-abc"}

        def slow_exec_start(exec_id, stream=False, demux=True):
            if stream:
                def _gen():
                    _time.sleep(0.5)
                    yield (None, b"killed")
                return _gen()
            _time.sleep(0.5)
            return (None, b"killed")

        api.exec_start.side_effect = slow_exec_start
        api.exec_inspect.return_value = {"Pid": 4242, "ExitCode": 137}

        cfg = SandboxConfig(timeout_seconds=0.1)
        r = docker_provider.run(
            "a1", ["python", "-c", "pass"],
            config=cfg,
            session_id=h.session_id,
        )

        assert r.killed is True
        # Container.kill must NOT have been called — that would have
        # destroyed every previous execute_code call's state.
        assert not c.kill.called
        # Instead, the specific PID was sent SIGKILL via exec_run.
        kill_calls = [
            call for call in c.exec_run.call_args_list
            if call.args and call.args[0] == ["kill", "-9", "4242"]
        ]
        assert kill_calls, (
            f"Expected ``container.exec_run(['kill', '-9', '4242'])`` "
            f"call; got exec_run calls: {c.exec_run.call_args_list}"
        )

    def test_concurrent_runs_serialise_per_container(self, docker_provider):
        """Concurrent run() calls against the same session must
        serialise so a timeout in one cannot disrupt another in
        flight.
        """
        import threading
        import time as _time

        h = docker_provider.create_session("a1")
        c = docker_provider._containers[(h.agent_id, h.session_id)]

        in_progress = 0
        max_in_progress = 0
        lock = threading.Lock()

        def tracked_exec(*args, **kwargs):
            nonlocal in_progress, max_in_progress
            with lock:
                in_progress += 1
                max_in_progress = max(max_in_progress, in_progress)
            _time.sleep(0.05)
            with lock:
                in_progress -= 1
            return MagicMock(exit_code=0, output=(b"ok", b""))

        c.exec_run.side_effect = tracked_exec

        threads = [
            threading.Thread(
                target=docker_provider.run,
                args=("a1", ["echo"]),
                kwargs={"session_id": h.session_id, "config": SandboxConfig()},
            )
            for _ in range(4)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # The exec lock is per-(agent, session); only one exec at a
        # time should ever be in flight against this container.
        assert max_in_progress == 1


# ============================================================================
# Resource name sanitization (imran-siddique review)
# ============================================================================


class TestResourceNameValidation:
    """``_validate_resource_name`` rejects unsafe Docker name fragments."""

    @pytest.mark.parametrize(
        "name",
        [
            "agent1",
            "agent-001",
            "Agent_42",
            "a.b.c",
            "X",
        ],
    )
    def test_valid_names_pass(self, name):
        _validate_resource_name(name, "agent_id")  # no exception

    @pytest.mark.parametrize(
        "name",
        [
            "",
            "_starts-with-underscore",
            "-starts-with-dash",
            ".starts-with-dot",
            "has space",
            "has/slash",
            "has\\backslash",
            "has:colon",
            "has;semicolon",
            "has$shell",
            "x" * 200,
        ],
    )
    def test_invalid_names_rejected(self, name):
        with pytest.raises(ValueError, match="Invalid agent_id"):
            _validate_resource_name(name, "agent_id")

    def test_create_session_rejects_bad_agent_id(self, docker_provider):
        with pytest.raises(ValueError, match="Invalid agent_id"):
            docker_provider.create_session("bad agent/../../etc")

    def test_save_state_rejects_bad_checkpoint_name(self, docker_provider):
        h = docker_provider.create_session("a1")
        with pytest.raises(ValueError, match="checkpoint name"):
            docker_provider.save_state(
                "a1", h.session_id, "../etc/passwd"
            )

    def test_delete_checkpoint_rejects_bad_name(self, docker_provider):
        with pytest.raises(ValueError, match="checkpoint name"):
            docker_provider.delete_checkpoint("a1", "name with space")


# ============================================================================
# memswap_limit + Windows protected paths (imran-siddique review)
# ============================================================================


class TestMemswapLimit:
    """``_create_container`` sets memswap_limit == mem_limit so swap cannot
    bypass the cgroup memory cap."""

    def test_memswap_equals_mem_limit(self):
        from unittest.mock import MagicMock

        provider = DockerSandboxProvider.__new__(DockerSandboxProvider)
        provider._image = "python:3.11-slim"
        provider._client = MagicMock()
        provider._runtime = IsolationRuntime.RUNC
        provider.ensure_image = MagicMock()

        provider._create_container("a1", "s1", SandboxConfig(memory_mb=256))

        kwargs = provider._client.containers.run.call_args.kwargs
        assert kwargs["mem_limit"] == "256m"
        assert kwargs["memswap_limit"] == "256m"


class TestWindowsProtectedPathsExtended:
    """Windows protection covers system dirs, not just drive roots."""

    @pytest.mark.parametrize(
        "path",
        [
            "C:\\Windows",
            "C:\\Windows\\System32",
            "C:\\Program Files",
            "C:\\Program Files (x86)\\Foo",
            "C:\\ProgramData\\Bar",
            "c:\\windows\\system32",  # case-insensitive
        ],
    )
    def test_windows_system_dirs_blocked(self, path, monkeypatch):
        monkeypatch.setattr("platform.system", lambda: "Windows")
        monkeypatch.setattr("os.path.realpath", lambda p: p)
        assert _is_protected_path(path) is True

    def test_windows_user_dirs_allowed(self, monkeypatch):
        monkeypatch.setattr("platform.system", lambda: "Windows")
        monkeypatch.setattr("os.path.realpath", lambda p: p)
        assert _is_protected_path("C:\\Users\\agent\\workspace") is False


# ============================================================================
# Session config propagation to execute_code (imran-siddique review)
# ============================================================================


class TestSessionConfigPropagation:
    """``execute_code`` must use the session''s SandboxConfig (timeout, env),
    not a fresh default ``SandboxConfig()``."""

    def test_execute_code_uses_session_timeout(self, docker_provider):
        cfg = SandboxConfig(timeout_seconds=7.0, memory_mb=256)
        h = docker_provider.create_session("a1", config=cfg)

        captured = {}
        original_run = docker_provider.run

        def spy_run(agent_id, command, config=None, *, session_id=None):
            captured["config"] = config
            return original_run(
                agent_id, command, config=config, session_id=session_id
            )

        docker_provider.run = spy_run
        docker_provider.execute_code("a1", h.session_id, "print(1)")

        assert captured["config"] is not None
        assert captured["config"].timeout_seconds == 7.0
        assert captured["config"].memory_mb == 256

    def test_destroy_clears_session_config(self, docker_provider):
        cfg = SandboxConfig(timeout_seconds=5.0)
        h = docker_provider.create_session("a1", config=cfg)
        assert (h.agent_id, h.session_id) in docker_provider._session_configs

        docker_provider.destroy_session(h.agent_id, h.session_id)
        assert (h.agent_id, h.session_id) not in docker_provider._session_configs


# ============================================================================
# Thread safety on shared state (imran-siddique review)
# ============================================================================


class TestThreadSafety:
    """Concurrent create/destroy must not corrupt the internal dicts."""

    def test_concurrent_create_destroy(self, docker_provider):
        import threading as _t

        errors: list[Exception] = []

        def worker(i):
            try:
                for _ in range(20):
                    h = docker_provider.create_session(f"agent{i}")
                    docker_provider.get_session_status(
                        h.agent_id, h.session_id
                    )
                    docker_provider.destroy_session(
                        h.agent_id, h.session_id
                    )
            except Exception as e:
                errors.append(e)

        threads = [_t.Thread(target=worker, args=(i,)) for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == []
        assert docker_provider._containers == {}
        assert docker_provider._evaluators == {}
        assert docker_provider._session_configs == {}


class TestHardeningAdditions:
    """Regression coverage for the audit-driven hardening changes."""

    def test_security_opt_includes_seccomp_and_apparmor(self):
        from agent_sandbox.docker_provider.provider import DockerSandboxProvider

        with patch(
            "agent_sandbox.docker_provider.provider.DockerSandboxProvider.__init__",
            return_value=None,
        ):
            p = DockerSandboxProvider.__new__(DockerSandboxProvider)
            p._image = "python:3.11-slim"
            p._runtime = IsolationRuntime.RUNC
            client = MagicMock()
            client.images.get.return_value = MagicMock()
            client.containers.run.return_value = MagicMock()
            p._client = client

        p._create_container("a1", "s1", SandboxConfig())
        kw = client.containers.run.call_args[1]
        assert "seccomp=default" in kw["security_opt"]
        assert "apparmor=docker-default" in kw["security_opt"]

    def test_pids_limit_tightened_to_128(self):
        from agent_sandbox.docker_provider.provider import DockerSandboxProvider

        with patch(
            "agent_sandbox.docker_provider.provider.DockerSandboxProvider.__init__",
            return_value=None,
        ):
            p = DockerSandboxProvider.__new__(DockerSandboxProvider)
            p._image = "python:3.11-slim"
            p._runtime = IsolationRuntime.RUNC
            client = MagicMock()
            client.images.get.return_value = MagicMock()
            client.containers.run.return_value = MagicMock()
            p._client = client

        p._create_container("a1", "s1", SandboxConfig())
        kw = client.containers.run.call_args[1]
        assert kw["pids_limit"] == 128

    def test_blocked_envs_new_loaders(self):
        env = {
            "BASH_ENV": "/x",
            "PYTHONHOME": "/x",
            "NODE_OPTIONS": "--inspect",
            "RUBYOPT": "-rmal",
            "PERL5LIB": "/x",
            "JAVA_TOOL_OPTIONS": "-javaagent:/x",
            "_JAVA_OPTIONS": "-X",
            "APP_SAFE": "ok",
        }
        result = _sanitize_env_vars(env)
        for k in ("BASH_ENV", "PYTHONHOME", "NODE_OPTIONS", "RUBYOPT",
                  "PERL5LIB", "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS"):
            assert k not in result, f"{k} must be blocked"
        assert result["APP_SAFE"] == "ok"

    def test_users_root_blocked_but_subdir_allowed(self, monkeypatch):
        monkeypatch.setattr("platform.system", lambda: "Windows")
        monkeypatch.setattr("os.path.realpath", lambda p: p)
        assert _is_protected_path("C:\\Users") is True
        # Existing maintainer design: a specific user's working subdir is fine.
        assert _is_protected_path("C:\\Users\\agent\\workspace") is False

    def test_ensure_image_warns_when_unpinned(self, caplog):
        from agent_sandbox.docker_provider.provider import DockerSandboxProvider

        with patch(
            "agent_sandbox.docker_provider.provider.DockerSandboxProvider.__init__",
            return_value=None,
        ):
            p = DockerSandboxProvider.__new__(DockerSandboxProvider)
            p._image = "python"
            client = MagicMock()
            # First call: images.get raises -> need to pull.
            client.images.get.side_effect = Exception("not present")
            client.images.pull.return_value = MagicMock()
            p._client = client

        with caplog.at_level("WARNING", logger="agent_sandbox.docker_provider.provider"):
            p.ensure_image()

        warnings = [r for r in caplog.records if r.levelname == "WARNING"]
        assert any("digest" in r.getMessage() for r in warnings)
        # And: pull was actually attempted with ('python', tag='latest')
        client.images.pull.assert_called_once_with("python", tag="latest")

    def test_ensure_image_no_warning_when_tagged(self, caplog):
        from agent_sandbox.docker_provider.provider import DockerSandboxProvider

        with patch(
            "agent_sandbox.docker_provider.provider.DockerSandboxProvider.__init__",
            return_value=None,
        ):
            p = DockerSandboxProvider.__new__(DockerSandboxProvider)
            p._image = "python:3.11-slim"
            client = MagicMock()
            client.images.get.side_effect = Exception("not present")
            client.images.pull.return_value = MagicMock()
            p._client = client

        with caplog.at_level("WARNING", logger="agent_sandbox.docker_provider.provider"):
            p.ensure_image()

        assert not any(
            "digest" in r.getMessage() for r in caplog.records
            if r.levelname == "WARNING"
        )

    def test_ensure_image_digest_uses_no_tag(self):
        from agent_sandbox.docker_provider.provider import DockerSandboxProvider

        with patch(
            "agent_sandbox.docker_provider.provider.DockerSandboxProvider.__init__",
            return_value=None,
        ):
            p = DockerSandboxProvider.__new__(DockerSandboxProvider)
            p._image = "python@sha256:abc123"
            client = MagicMock()
            client.images.get.side_effect = Exception("not present")
            client.images.pull.return_value = MagicMock()
            p._client = client

        p.ensure_image()
        # Digest-pinned images must NOT have a tag passed; Docker SDK requires
        # the digest reference to be the full repo argument with no tag.
        client.images.pull.assert_called_once_with("python@sha256:abc123")
