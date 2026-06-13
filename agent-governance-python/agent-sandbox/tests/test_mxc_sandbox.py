# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Unit tests for :mod:`agent_sandbox.mxc_sandbox_provider`.

The native MXC binary is never actually invoked: binary discovery is
satisfied with a real executable path (``sys.executable``) and the
``subprocess.run`` call inside the provider is monkeypatched with a fake
that records the argv / config and returns canned output. This keeps the
suite hermetic — no MXC install, no OS sandbox, no network.

Coverage targets:

* Config: :class:`MxcConfig` validation, ``to_mxc_json``,
  ``from_sandbox_config``, ``backend_requires_experimental``.
* Policy translation: ``mxc_config_from_policy``, ``policy_to_mxc_json``,
  ``policy_yaml_to_mxc_json`` (including the ``sandbox_mounts`` block).
* Construction: binary discovery (explicit path, ``MXC_BINARY`` env,
  PATH), ``is_available``, bad backend.
* Lifecycle: create/execute/destroy, session reuse, status, raw ``run``.
* Spawn behaviour: argv construction (``--experimental`` / ``--debug``),
  env isolation, timeout → killed result, output truncation, missing
  binary.
* Guards: invalid agent_id, code-scanner enforcement, policy deny gate.
"""

from __future__ import annotations

import json
import subprocess
import sys
from types import SimpleNamespace
from typing import Any

import pytest

from agent_sandbox.code_scanner import SandboxCodeViolation
from agent_sandbox.mxc_sandbox_provider import (
    MxcConfig,
    MxcSandboxProvider,
    backend_requires_experimental,
    mxc_config_from_policy,
    policy_to_mxc_json,
    policy_yaml_to_mxc_json,
)
from agent_sandbox.mxc_sandbox_provider import provider as provider_mod
from agent_sandbox.sandbox_provider import (
    ExecutionStatus,
    SandboxConfig,
    SessionStatus,
)

# A real, executable file so binary discovery succeeds without MXC.
REAL_BINARY = sys.executable


# =========================================================================
# Fake subprocess.run
# =========================================================================


class _FakeCompleted:
    def __init__(self, stdout: bytes, stderr: bytes, returncode: int) -> None:
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


class _FakeRun:
    """Records the last invocation and returns a canned result.

    Reads the config file the provider wrote so tests can assert on the
    rendered MXC JSON document.
    """

    def __init__(
        self,
        stdout: bytes = b"ok",
        stderr: bytes = b"",
        returncode: int = 0,
        raise_exc: BaseException | None = None,
    ) -> None:
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode
        self.raise_exc = raise_exc
        self.argv: list[str] | None = None
        self.env: dict[str, str] | None = None
        self.cwd: str | None = None
        self.config_doc: dict[str, Any] | None = None

    def __call__(self, argv, **kwargs):  # noqa: ANN001 - test stub
        self.argv = list(argv)
        self.env = kwargs.get("env")
        self.cwd = kwargs.get("cwd")
        # The last argv element is the config path; capture its contents.
        config_path = argv[-1]
        try:
            with open(config_path, encoding="utf-8") as fh:
                self.config_doc = json.load(fh)
        except OSError:
            self.config_doc = None
        if self.raise_exc is not None:
            raise self.raise_exc
        return _FakeCompleted(self.stdout, self.stderr, self.returncode)


@pytest.fixture
def fake_run(monkeypatch):
    """Patch ``subprocess.run`` inside the provider module."""
    runner = _FakeRun()
    monkeypatch.setattr(provider_mod.subprocess, "run", runner)
    return runner


@pytest.fixture
def provider(monkeypatch):
    """A provider whose binary discovery is satisfied by a real exe."""
    monkeypatch.delenv("MXC_BINARY", raising=False)
    return MxcSandboxProvider(binary_path=REAL_BINARY, backend="bubblewrap")


# =========================================================================
# MxcConfig
# =========================================================================


class TestMxcConfig:
    def test_defaults_and_render(self):
        cfg = MxcConfig()
        doc = cfg.to_mxc_json("python x.py")
        assert doc["version"] == "0.6.0-alpha"
        assert doc["process"]["commandLine"] == "python x.py"
        assert doc["network"]["allowOutbound"] is False
        assert doc["filesystem"]["readonlyPaths"] == []
        # No backend → key omitted (let MXC pick the platform default).
        assert "backend" not in doc

    def test_allowed_hosts_only_when_outbound(self):
        cfg = MxcConfig(allow_outbound=True, allowed_hosts=["a.com", "b.com"])
        doc = cfg.to_mxc_json("cmd")
        assert doc["network"]["allowedHosts"] == ["a.com", "b.com"]

        # allowed_hosts present but outbound off → no allowedHosts emitted.
        cfg2 = MxcConfig(allow_outbound=False, allowed_hosts=["a.com"])
        assert "allowedHosts" not in cfg2.to_mxc_json("cmd")["network"]

    def test_unknown_backend_rejected(self):
        with pytest.raises(ValueError, match="Unknown MXC backend"):
            MxcConfig(backend="not-a-backend")

    def test_nonpositive_timeout_rejected(self):
        with pytest.raises(ValueError, match="timeout_ms must be positive"):
            MxcConfig(timeout_ms=0)

    def test_experimental_backend_forces_flag(self):
        cfg = MxcConfig(backend="hyperlight")
        assert cfg.experimental is True
        assert cfg.needs_experimental is True

    def test_stable_backend_no_experimental(self):
        cfg = MxcConfig(backend="bubblewrap")
        assert cfg.experimental is False
        assert cfg.needs_experimental is False

    def test_env_vars_rendered(self):
        cfg = MxcConfig(env_vars={"FOO": "bar"})
        doc = cfg.to_mxc_json("cmd")
        assert doc["process"]["environment"] == {"FOO": "bar"}

    def test_extra_config_deep_merged(self):
        cfg = MxcConfig(extra_config={"ui": {"allowWindows": True}})
        doc = cfg.to_mxc_json("cmd")
        assert doc["ui"]["allowWindows"] is True

    def test_from_sandbox_config(self):
        sc = SandboxConfig(
            timeout_seconds=10,
            network_enabled=True,
            input_dir="/in",
            output_dir="/out",
            env_vars={"K": "V"},
        )
        cfg = MxcConfig.from_sandbox_config(sc, backend="lxc")
        assert cfg.backend == "lxc"
        assert cfg.timeout_ms == 10_000
        assert cfg.allow_outbound is True
        assert cfg.readonly_paths == ["/in"]
        assert cfg.readwrite_paths == ["/out"]
        assert cfg.env_vars == {"K": "V"}


def test_backend_requires_experimental():
    assert backend_requires_experimental("hyperlight") is True
    assert backend_requires_experimental("bubblewrap") is False
    assert backend_requires_experimental(None) is False


# =========================================================================
# Policy translation
# =========================================================================


def _force_unix_paths(monkeypatch):
    """Make protected-path checks evaluate Unix paths on any host OS.

    ``is_protected_path`` only consults the Unix protected set when the
    platform is not Windows, so on a Windows dev box ``/etc`` would not
    be flagged. Force the Unix branch and an identity ``realpath`` so the
    fail-closed mount checks are exercised deterministically everywhere.
    """
    import agent_sandbox._hardening as hardening

    monkeypatch.setattr(hardening, "platform", SimpleNamespace(system=lambda: "Linux"))
    monkeypatch.setattr(hardening.os.path, "realpath", lambda p: p)


def _policy(**kw):
    """Build a duck-typed policy object for mxc_config_from_policy."""
    defaults = SimpleNamespace(
        timeout_seconds=kw.get("timeout_seconds"),
        max_memory_mb=kw.get("max_memory_mb"),
        max_cpu=kw.get("max_cpu"),
        network_default=kw.get("network_default"),
    )
    mounts = None
    if "input_dir" in kw or "output_dir" in kw:
        mounts = SimpleNamespace(
            input_dir=kw.get("input_dir"),
            output_dir=kw.get("output_dir"),
        )
    return SimpleNamespace(
        defaults=defaults,
        sandbox_mounts=mounts,
        network_allowlist=kw.get("network_allowlist"),
        tool_allowlist=kw.get("tool_allowlist"),
    )


class TestPolicyTranslation:
    def test_mounts_and_egress(self):
        policy = _policy(
            timeout_seconds=45,
            input_dir="/data/in",
            output_dir="/data/out",
            network_allowlist=["pypi.org", "*.github.com"],
        )
        cfg = mxc_config_from_policy(policy)
        assert cfg.timeout_ms == 45_000
        assert "/data/in" in cfg.readonly_paths
        assert "/data/out" in cfg.readwrite_paths
        assert cfg.allow_outbound is True
        assert cfg.allowed_hosts == ["pypi.org", "*.github.com"]

    def test_no_network_allowlist_keeps_egress_off(self):
        cfg = mxc_config_from_policy(_policy(timeout_seconds=5))
        assert cfg.allow_outbound is False

    def test_policy_to_mxc_json(self):
        doc = policy_to_mxc_json(
            _policy(input_dir="/in", network_allowlist=["x.com"]),
            "python run.py",
        )
        assert doc["filesystem"]["readonlyPaths"] == ["/in"]
        assert doc["network"]["allowedHosts"] == ["x.com"]
        assert doc["process"]["commandLine"] == "python run.py"

    def test_policy_yaml_to_mxc_json(self, tmp_path):
        yaml_text = (
            'version: "1.0"\n'
            "name: demo\n"
            "defaults:\n"
            "  timeout_seconds: 30\n"
            "  max_memory_mb: 512\n"
            "network_allowlist:\n"
            "  - pypi.org\n"
            "tool_allowlist:\n"
            "  - read_doc\n"
            "sandbox_mounts:\n"
            "  input_dir: /data/user-pdf\n"
            "  output_dir: /data/agent-out\n"
        )
        path = tmp_path / "policy.yaml"
        path.write_text(yaml_text, encoding="utf-8")

        doc = policy_yaml_to_mxc_json(str(path), "python /scripts/run.py")
        assert doc["timeoutMs"] == 30_000
        assert doc["filesystem"]["readonlyPaths"] == ["/data/user-pdf"]
        assert doc["filesystem"]["readwritePaths"] == ["/data/agent-out"]
        assert doc["network"]["allowOutbound"] is True
        assert doc["network"]["allowedHosts"] == ["pypi.org"]
        # tool_allowlist / CPU / memory are intentionally NOT in MXC JSON.
        assert "tools" not in doc
        assert "maxMemoryMb" not in doc

    def test_policy_yaml_non_mapping_rejected(self, tmp_path):
        path = tmp_path / "bad.yaml"
        path.write_text("- just\n- a list\n", encoding="utf-8")
        with pytest.raises(ValueError, match="must be a mapping"):
            policy_yaml_to_mxc_json(str(path), "cmd")


# =========================================================================
# Construction / binary discovery
# =========================================================================


class TestConstruction:
    def test_explicit_binary_available(self, monkeypatch):
        monkeypatch.delenv("MXC_BINARY", raising=False)
        p = MxcSandboxProvider(binary_path=REAL_BINARY)
        assert p.is_available() is True
        assert p.binary_path is not None

    def test_missing_binary_unavailable(self, monkeypatch):
        monkeypatch.delenv("MXC_BINARY", raising=False)
        p = MxcSandboxProvider(binary_path="/no/such/mxc-binary-xyz")
        assert p.is_available() is False

    def test_env_var_discovery(self, monkeypatch):
        monkeypatch.setenv("MXC_BINARY", REAL_BINARY)
        p = MxcSandboxProvider()
        assert p.is_available() is True

    def test_bad_backend_rejected_at_construction(self):
        with pytest.raises(ValueError, match="Unknown MXC backend"):
            MxcSandboxProvider(backend="nope", binary_path=REAL_BINARY)


# =========================================================================
# Lifecycle
# =========================================================================


class TestLifecycle:
    def test_create_execute_destroy(self, provider, fake_run):
        fake_run.stdout = b"hello from sandbox"
        handle = provider.create_session("agent-1")
        assert handle.status == SessionStatus.READY
        assert provider.get_session_status(handle.agent_id, handle.session_id) == (
            SessionStatus.READY
        )

        execution = provider.execute_code(
            handle.agent_id, handle.session_id, "print('hi')"
        )
        assert execution.status == ExecutionStatus.COMPLETED
        assert execution.result.success is True
        assert "hello from sandbox" in execution.result.stdout

        provider.destroy_session(handle.agent_id, handle.session_id)
        assert provider.get_session_status(
            handle.agent_id, handle.session_id
        ) == SessionStatus.DESTROYED

    def test_execute_without_session_raises(self, provider):
        with pytest.raises(RuntimeError, match="No active session"):
            provider.execute_code("agent-1", "nope", "print(1)")

    def test_destroy_unknown_session_is_noop(self, provider):
        provider.destroy_session("agent-1", "missing")  # no raise

    def test_invalid_agent_id_rejected(self, provider):
        with pytest.raises(ValueError, match="Invalid agent_id"):
            provider.create_session("bad id with spaces!")

    def test_unavailable_provider_raises_on_create(self):
        p = MxcSandboxProvider(binary_path="/no/such/binary")
        with pytest.raises(RuntimeError, match="MXC unavailable"):
            p.create_session("agent-1")

    def test_nonzero_exit_is_failure(self, provider, fake_run):
        fake_run.returncode = 1
        fake_run.stderr = b"boom"
        handle = provider.create_session("agent-1")
        execution = provider.execute_code(
            handle.agent_id, handle.session_id, "print(1)"
        )
        assert execution.status == ExecutionStatus.FAILED
        assert execution.result.success is False
        assert "boom" in execution.result.stderr

    def test_run_once_executes_and_cleans_up(self, provider, fake_run):
        fake_run.stdout = b"one-shot output"
        execution = provider.run_once("agent-1", "print('hi')")
        assert execution.status == ExecutionStatus.COMPLETED
        assert "one-shot output" in execution.result.stdout
        # No session should remain after run_once.
        assert provider._sessions == {}

    def test_run_once_cleans_up_on_failure(self, provider, fake_run):
        fake_run.returncode = 2
        execution = provider.run_once("agent-1", "print('hi')")
        assert execution.result.success is False
        # Session is still destroyed even when the run fails.
        assert provider._sessions == {}

    def test_run_once_destroys_session_on_guard_violation(self, provider, fake_run):
        with pytest.raises(SandboxCodeViolation):
            provider.run_once(
                "agent-1", "import subprocess; subprocess.run(['ls'])"
            )
        # The finally clause must clean up even when execute_code raised.
        assert provider._sessions == {}


# =========================================================================
# Spawn behaviour
# =========================================================================


class TestSpawn:
    def test_config_rendered_with_session_mounts(self, provider, fake_run):
        handle = provider.create_session("agent-1")
        provider.execute_code(handle.agent_id, handle.session_id, "print(1)")
        doc = fake_run.config_doc
        # Session workspace adds scripts (ro) + output (rw) mounts.
        assert any(
            p.endswith("scripts") for p in doc["filesystem"]["readonlyPaths"]
        )
        assert any(
            p.endswith("output") for p in doc["filesystem"]["readwritePaths"]
        )

    def test_experimental_flag_in_argv(self, monkeypatch, fake_run):
        monkeypatch.delenv("MXC_BINARY", raising=False)
        p = MxcSandboxProvider(binary_path=REAL_BINARY, backend="hyperlight")
        handle = p.create_session("agent-1")
        p.execute_code(handle.agent_id, handle.session_id, "print(1)")
        assert "--experimental" in fake_run.argv

    def test_debug_flag_in_argv(self, monkeypatch, fake_run):
        monkeypatch.delenv("MXC_BINARY", raising=False)
        p = MxcSandboxProvider(
            binary_path=REAL_BINARY, backend="bubblewrap", debug=True
        )
        handle = p.create_session("agent-1")
        p.execute_code(handle.agent_id, handle.session_id, "print(1)")
        assert "--debug" in fake_run.argv

    def test_env_is_not_inherited_wholesale(self, monkeypatch, provider, fake_run):
        monkeypatch.setenv("HOST_SECRET", "leaky")
        handle = provider.create_session("agent-1")
        provider.execute_code(handle.agent_id, handle.session_id, "print(1)")
        assert "HOST_SECRET" not in (fake_run.env or {})
        # PATH is still forwarded so the interpreter resolves.
        assert "PATH" in (fake_run.env or {})

    def test_timeout_marks_killed(self, monkeypatch, provider, fake_run):
        fake_run.raise_exc = subprocess.TimeoutExpired(cmd="mxc", timeout=1)
        handle = provider.create_session("agent-1")
        execution = provider.execute_code(
            handle.agent_id, handle.session_id, "print(1)"
        )
        assert execution.result.killed is True
        assert execution.result.success is False
        assert "timeout" in execution.result.kill_reason.lower()

    def test_missing_binary_at_spawn(self, monkeypatch, provider, fake_run):
        fake_run.raise_exc = FileNotFoundError()
        handle = provider.create_session("agent-1")
        execution = provider.execute_code(
            handle.agent_id, handle.session_id, "print(1)"
        )
        assert execution.result.success is False
        assert "not found" in execution.result.stderr.lower()

    def test_output_truncated(self, provider, fake_run):
        fake_run.stdout = b"x" * 2_000_000  # > 1 MiB cap
        handle = provider.create_session("agent-1")
        execution = provider.execute_code(
            handle.agent_id, handle.session_id, "print(1)"
        )
        assert "truncated" in execution.result.stdout


# =========================================================================
# Raw run
# =========================================================================


class TestRawRun:
    def test_run_with_session(self, provider, fake_run):
        fake_run.stdout = b"ran"
        handle = provider.create_session("agent-1")
        result = provider.run(
            handle.agent_id, ["echo", "hi"], session_id=handle.session_id
        )
        assert result.success is True
        assert "ran" in result.stdout

    def test_run_ephemeral_without_session(self, provider, fake_run):
        fake_run.stdout = b"oneshot"
        result = provider.run("agent-1", ["echo", "hi"])
        assert result.success is True

    def test_run_empty_command(self, provider):
        result = provider.run("agent-1", [])
        assert result.success is False

    def test_run_unavailable_provider(self):
        p = MxcSandboxProvider(binary_path="/no/such/binary")
        result = p.run("agent-1", ["echo", "hi"])
        assert result.success is False


# =========================================================================
# Guards
# =========================================================================


class TestGuards:
    def test_code_scanner_blocks_subprocess(self, provider, fake_run):
        handle = provider.create_session("agent-1")
        with pytest.raises(SandboxCodeViolation):
            provider.execute_code(
                handle.agent_id,
                handle.session_id,
                "import subprocess; subprocess.run(['ls'])",
            )

    def test_policy_deny_blocks_execution(self, provider, fake_run):
        class _DenyEvaluator:
            def evaluate(self, ctx):
                return SimpleNamespace(allowed=False, reason="nope")

        handle = provider.create_session("agent-1")
        # Inject a denying evaluator into the live session.
        key = (handle.agent_id, handle.session_id)
        provider._sessions[key].evaluator = _DenyEvaluator()
        with pytest.raises(PermissionError, match="Policy denied"):
            provider.execute_code(handle.agent_id, handle.session_id, "print(1)")


# =========================================================================
# Fail-closed hardening (review gaps)
# =========================================================================


class TestFailClosedHardening:
    def test_extra_config_cannot_flip_allow_outbound(self):
        """extra_config must never weaken the modelled network egress."""
        cfg = MxcConfig(
            allow_outbound=False,
            extra_config={"network": {"allowOutbound": True}},
        )
        doc = cfg.to_mxc_json("cmd")
        assert doc["network"]["allowOutbound"] is False

    def test_extra_config_cannot_widen_allowed_hosts(self):
        cfg = MxcConfig(
            allow_outbound=True,
            allowed_hosts=["safe.example"],
            extra_config={
                "network": {"allowedHosts": ["evil.example", "*"]}
            },
        )
        doc = cfg.to_mxc_json("cmd")
        assert doc["network"]["allowedHosts"] == ["safe.example"]

    def test_extra_config_cannot_swap_mounts_or_timeout(self):
        cfg = MxcConfig(
            readonly_paths=["/safe/ro"],
            readwrite_paths=["/safe/rw"],
            timeout_ms=1_000,
            extra_config={
                "filesystem": {
                    "readonlyPaths": ["/etc"],
                    "readwritePaths": ["/"],
                },
                "timeoutMs": 999_999,
            },
        )
        doc = cfg.to_mxc_json("cmd")
        assert doc["filesystem"]["readonlyPaths"] == ["/safe/ro"]
        assert doc["filesystem"]["readwritePaths"] == ["/safe/rw"]
        assert doc["timeoutMs"] == 1_000

    def test_extra_config_unrelated_keys_preserved(self):
        cfg = MxcConfig(extra_config={"ui": {"allowWindows": True}})
        doc = cfg.to_mxc_json("cmd")
        assert doc["ui"]["allowWindows"] is True

    def test_guest_env_dangerous_vars_stripped(self):
        cfg = MxcConfig(
            env_vars={
                "SAFE": "ok",
                "LD_PRELOAD": "/tmp/evil.so",
                "PYTHONSTARTUP": "/tmp/x.py",
                "NODE_OPTIONS": "--require /tmp/x",
            }
        )
        doc = cfg.to_mxc_json("cmd")
        env = doc["process"]["environment"]
        assert env == {"SAFE": "ok"}

    def test_tool_allowlist_fails_closed(self, provider, fake_run):
        policy = _policy(tool_allowlist=["read_doc"])
        with pytest.raises(ValueError, match="tool allowlisting"):
            provider.create_session("agent-1", policy=policy)

    def test_empty_tool_allowlist_is_allowed(self, provider, fake_run):
        policy = _policy(tool_allowlist=[])
        handle = provider.create_session("agent-1", policy=policy)
        assert handle.status == SessionStatus.READY

    def test_protected_mount_path_rejected_input(self, monkeypatch):
        _force_unix_paths(monkeypatch)
        with pytest.raises(ValueError, match="protected system directory"):
            MxcConfig.from_sandbox_config(
                SandboxConfig(input_dir="/etc")
            )

    def test_protected_mount_path_rejected_output(self, monkeypatch):
        _force_unix_paths(monkeypatch)
        with pytest.raises(ValueError, match="protected system directory"):
            MxcConfig.from_sandbox_config(
                SandboxConfig(output_dir="/")
            )

    def test_protected_mount_path_rejected_from_policy(self, monkeypatch):
        _force_unix_paths(monkeypatch)
        with pytest.raises(ValueError, match="protected system directory"):
            mxc_config_from_policy(_policy(input_dir="/usr"))

    def test_outbound_without_hosts_rejected(self):
        with pytest.raises(ValueError, match="without a host allowlist"):
            MxcConfig(allow_outbound=True)

    def test_outbound_unrestricted_requires_explicit_opt_in(self):
        cfg = MxcConfig(allow_outbound=True, allow_unrestricted_egress=True)
        doc = cfg.to_mxc_json("cmd")
        assert doc["network"]["allowOutbound"] is True
        assert "allowedHosts" not in doc["network"]

    def test_network_default_allow_enables_unrestricted_egress(self):
        cfg = mxc_config_from_policy(_policy(network_default="allow"))
        assert cfg.allow_outbound is True
        assert cfg.allow_unrestricted_egress is True
        assert cfg.allowed_hosts == []

    def test_network_default_deny_keeps_egress_off(self):
        cfg = mxc_config_from_policy(_policy(network_default="deny"))
        assert cfg.allow_outbound is False

    def test_network_allowlist_takes_precedence_over_default(self):
        cfg = mxc_config_from_policy(
            _policy(network_default="allow", network_allowlist=["pypi.org"])
        )
        assert cfg.allow_outbound is True
        assert cfg.allowed_hosts == ["pypi.org"]
        # Restricted egress, not unrestricted.
        assert cfg.allow_unrestricted_egress is False

    def test_context_and_policy_env_do_not_leak_into_runner(
        self, provider, fake_run
    ):
        """MXC_CONTEXT / guest env stay in the config doc, not the runner."""
        handle = provider.create_session("agent-1")
        # Seed a guest env var on the live session.
        key = (handle.agent_id, handle.session_id)
        provider._sessions[key].config.env_vars["GUEST_SECRET"] = "shh"
        provider.execute_code(
            handle.agent_id,
            handle.session_id,
            "print(1)",
            context={"task": "demo"},
        )
        # The trusted runner's environment must not carry guest/context env.
        assert "GUEST_SECRET" not in (fake_run.env or {})
        assert "MXC_CONTEXT" not in (fake_run.env or {})
        # ...but the guest config document does carry them.
        guest_env = fake_run.config_doc["process"]["environment"]
        assert guest_env.get("GUEST_SECRET") == "shh"
        assert "MXC_CONTEXT" in guest_env

    def test_execute_code_non_python_interpreter_fails_closed(
        self, monkeypatch, fake_run
    ):
        monkeypatch.delenv("MXC_BINARY", raising=False)
        p = MxcSandboxProvider(
            binary_path=REAL_BINARY, backend="bubblewrap", interpreter="node"
        )
        handle = p.create_session("agent-1")
        with pytest.raises(ValueError, match="only supports a Python"):
            p.execute_code(handle.agent_id, handle.session_id, "print(1)")

